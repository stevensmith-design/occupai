"""Tests for occupai_scan. Run: make test  (or: python3 -m unittest discover -s tests -v)."""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

import fixture_setup  # noqa: E402
from occupai_scan import config as cfgmod  # noqa: E402
from occupai_scan import tracker as trk  # noqa: E402
from occupai_scan.common import SCRIPT_VERSION  # noqa: E402
from occupai_scan.deps import pypi_audit  # noqa: E402
from occupai_scan.hygiene import count_secrets  # noqa: E402
from occupai_scan.match import effective_pin, in_range  # noqa: E402
from occupai_scan.safefs import Policy  # noqa: E402

DEMO_CHECKS = os.path.join(REPO, "examples", "demo", "library", "checks.json")
ALL_UNITS = ["agent-lab", "bad-deps", "ci-demo", "clean-app", "fire-app", "forked-tool", "indicator-repo",
             "old-node", "py-api", "reports-sql", "supa-app", "ui-kit", "web-shop"]


# Hermetic runs: an empty HOME and no $OCCUPAI_CONFIG, so a real ~/.occupai config never leaks into tests.
# The cwd is a temp folder too, so the kit's own occupai.config.yaml isn't picked up either.
TEST_HOME = tempfile.mkdtemp(prefix="occupai-home-")
TEST_ENV = {**os.environ, "OCCUPAI_CONFIG": "", "OCCUPAI_SKIP_KIT_DATA": "1", "HOME": TEST_HOME, "PYTHONPATH": REPO}


def run(*args, check=True):
    r = subprocess.run([sys.executable, "-m", "occupai_scan", *args], cwd=TEST_HOME, capture_output=True, text=True,
                       env=TEST_ENV)
    if check and r.returncode != 0:
        raise AssertionError(f"exit {r.returncode}: {r.stdout}{r.stderr}")
    return r.stdout


def read(path):
    with open(path) as f:
        return f.read()


def run_json(*args):
    return json.loads(run(*args))


class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="occupai-test-")
        cls.root = os.path.join(cls.tmp, "projects")
        cls.keys = fixture_setup.build(cls.root)
        cls.state_dir = os.path.join(cls.tmp, "state")
        os.makedirs(cls.state_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)


def flat(hygiene_out):
    rows = set()
    for unit, r in hygiene_out["results"].items():
        for check, v in r.items():
            if check == "ownership":
                continue
            for f in v.get("findings", []):
                detail = f.get("file") or f.get("variable")
                extra = f.get("pattern") or f.get("table") or f.get("package") or f.get("action") or ""
                rows.add((unit, check, f["type"], detail, extra, f["severity"]))
    return rows


class TestFindings(FixtureCase):
    EXPECTED = {
        ("web-shop", "secrets", "sensitive-file-committed", ".env", "", "high"),
        ("web-shop", "secrets", "key-pattern", "src/lib/ai.ts", "anthropic-key", "high"),
        ("forked-tool", "secrets", "sensitive-file-committed", ".npmrc", "", "medium"),
        ("supa-app", "db", "supabase-table-without-rls", "supabase/migrations/0001_init.sql", "profiles", "high"),
        ("fire-app", "db", "firebase-open-rule", "firestore.rules", "", "high"),
        ("ci-demo", "gha", "action-not-pinned-to-sha", ".github/workflows/triage.yml", "some-org/label-action@v2", "medium"),
        ("ci-demo", "gha", "no-top-level-permissions", ".github/workflows/triage.yml", "", "medium"),
        ("ci-demo", "gha", "script-injection-risk", ".github/workflows/triage.yml", "", "high"),
        ("agent-lab", "ai", "mcp-server-unpinned", ".mcp.json", "@example/mcp-files-server", "medium"),
        ("agent-lab", "ai", "agent-broad-allow", ".claude/settings.json", "", "medium"),
        ("agent-lab", "ai", "hidden-unicode-in-agent-instructions", "CLAUDE.md", "", "high"),
        ("agent-lab", "ai", "ai-key-exposed-to-browser", "NEXT_PUBLIC_OPENAI_API_KEY", "", "high"),
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.out = run_json("hygiene", "--root", cls.root, "--owners", "example-owner")
        cls.rows = flat(cls.out)

    def test_exact_findings(self):
        self.assertEqual(self.rows, self.EXPECTED)

    def test_must_not_flag(self):
        files = {(r[0], r[3]) for r in self.rows}
        for unit, f in [("web-shop", "public/inline.html"),       # key inside a base64 data URI
                        ("web-shop", "scripts/detect.ts"),        # detector regex line
                        ("web-shop", ".env.example"),             # example env file
                        ("agent-lab", "AGENTS.md"),               # emoji ZWJ
                        ("ci-demo", ".github/workflows/safe.yml"),  # env: pattern, pinned, permissions
                        ("web-shop", "test-data/planted/keys.ts")]:  # nested ignore marker
            self.assertNotIn((unit, f), files)
        for unit in ("reports-sql", "ui-kit", "clean-app", "bad-deps", "old-node", "py-api", "indicator-repo"):
            self.assertNotIn(unit, self.out["summary"], f"{unit} should have no hygiene findings")

    def test_injection_points_at_run_line(self):
        f = [x for x in self.out["results"]["ci-demo"]["gha"]["findings"] if x["type"] == "script-injection-risk"]
        self.assertEqual([x["line"] for x in f], [11])

    def test_ownership(self):
        self.assertEqual(self.out["third_party_clones"], {"forked-tool": "someone-else"})
        self.assertEqual(self.out["results"]["web-shop"]["ownership"], "mine")
        self.assertEqual(self.out["owner_unconfirmed"], [])

    def test_unknown_owner_without_config(self):
        out = run_json("hygiene", "--root", self.root, "--only", "web-shop")
        self.assertEqual(out["owner_unconfirmed"], ["web-shop"])

    def test_noise_filters_directly(self):
        k = self.keys["FAKE_ANTHROPIC_KEY"]
        self.assertEqual(count_secrets(f'key = "{k}"'), {"anthropic-key": 1})
        self.assertEqual(count_secrets(f'const re = new RegExp("{k}")'), {})
        self.assertEqual(count_secrets(f'<img src="data:image/png;base64,{self.keys["FAKE_AWS_KEY"]}">'), {})
        self.assertEqual(count_secrets("ANTHROPIC_API_KEY=sk-ant-your-key-here-000000000000000"), {})
        self.assertEqual(count_secrets("DATABASE_URL=postgres://user:pass@localhost/db"), {})


class TestMatch(FixtureCase):
    def test_replay_checks(self):
        out = run_json("match", "--root", self.root, "--checks", DEMO_CHECKS)
        self.assertEqual(out["demo-next-cache-leak"]["affected"], ["web-shop"])
        self.assertEqual(out["demo-fake-interview-npm"]["affected"], ["bad-deps"])  # not ui-kit (occupai-demo-animate)
        self.assertEqual(out["demo-node-security-release"]["affected"], ["old-node"])  # clean-app pins "24": fine
        self.assertEqual(out["demo-ci-stealer"]["affected"], ["indicator-repo"])
        self.assertNotIn("demo-paas-breach", out)  # account-scoped: not replayed per project
        kinds = {e["kind"] for e in out["demo-ci-stealer"]["projects"]["indicator-repo"]["evidence"]}
        self.assertEqual(kinds, {"git-branch", "git-commit"})
        self.assertEqual(out["demo-next-cache-leak"]["projects"]["ui-kit"]["status"], "not-affected")

    def test_versions_exact_names(self):
        out = run_json("versions", "--root", self.root, "--packages", "occupai-demo-anim,next")
        self.assertEqual(out["bad-deps/package-lock.json"], {"occupai-demo-anim": ["1.0.2"]})
        self.assertEqual(out["ui-kit/package-lock.json"], {"next": ["16.4.5"]})
        self.assertEqual(out["web-shop/package-lock.json"], {"next": ["16.2.1"]})


class TestNoSecretLeak(FixtureCase):
    def test_no_secret_value_in_any_output(self):
        state = os.path.join(self.state_dir, "leak-state.json")
        outputs = [run("projects", "--root", self.root),
                   run("changed", "--root", self.root, "--state", state),
                   run("hygiene", "--root", self.root, "--state", state, "--all"),
                   run("versions", "--root", self.root, "--packages", "next"),
                   run("match", "--root", self.root, "--checks", DEMO_CHECKS)]
        hy = os.path.join(self.state_dir, "leak-hygiene.json")
        with open(hy, "w") as f:
            f.write(outputs[2])
        outputs.append(run("save-state", "--root", self.root, "--state", state, "--hygiene", hy))
        with open(state) as f:
            outputs.append(f.read())
        blob = "\n".join(outputs)
        for name, value in self.keys.items():
            body = value.split("-")[-1].split("_")[-1]
            for i in range(0, len(body) - 12):
                self.assertNotIn(body[i:i + 12], blob, f"part of {name} leaked into output")


class TestChangeDetection(FixtureCase):
    def hygiene(self, state, *extra):
        return run_json("hygiene", "--root", self.root, "--state", state, *extra)

    def save(self, state, out):
        hy = state + ".hygiene.json"
        with open(hy, "w") as f:
            json.dump(out, f)
        run("save-state", "--root", self.root, "--state", state, "--hygiene", hy)

    def test_unchanged_reused_and_edited_rechecked(self):
        state = os.path.join(self.state_dir, "cd-state.json")
        first = self.hygiene(state)
        self.assertEqual(sorted(first["checked"]), ALL_UNITS)
        self.save(state, first)
        second = self.hygiene(state)
        self.assertEqual(second["checked"], [])
        self.assertEqual(second["reused_unchanged"], ALL_UNITS)
        self.assertEqual(flat(second), flat(first))
        # edit one git project and one plain folder
        with open(os.path.join(self.root, "clean-app", "notes.md"), "w") as f:
            f.write("edited\n")
        time.sleep(1.1)  # plain folders fingerprint by mtime (seconds)
        with open(os.path.join(self.root, "reports-sql", "schema.sql"), "a") as f:
            f.write("-- edited\n")
        changed = run_json("changed", "--root", self.root, "--state", state)
        self.assertEqual(sorted(changed["changed"]), ["clean-app", "reports-sql"])
        third = self.hygiene(state)
        self.assertEqual(sorted(third["checked"]), ["clean-app", "reports-sql"])

    def test_version_bump_invalidates_cache(self):
        state = os.path.join(self.state_dir, "vb-state.json")
        self.save(state, self.hygiene(state))
        with open(state) as f:
            s = json.load(f)
        self.assertEqual(s["script_version"], SCRIPT_VERSION)
        s["script_version"] = "0.0.0-older"
        with open(state, "w") as f:
            json.dump(s, f)
        out = self.hygiene(state)
        self.assertTrue(out["cache_invalidated"])
        self.assertEqual(sorted(out["checked"]), ALL_UNITS)


class TestResume(FixtureCase):
    def test_resume_across_budget_limits(self):
        prog = os.path.join(self.state_dir, "progress.json")
        calls, out = 0, None
        while calls < 50:
            calls += 1
            out = run_json("hygiene", "--root", self.root, "--resume", prog, "--budget", "0")
            if out.get("status") != "partial":
                break
            self.assertEqual(out["done"], calls)
        self.assertEqual(calls, len(ALL_UNITS))  # budget 0 = exactly one project per call
        full = run_json("hygiene", "--root", self.root)
        self.assertEqual(flat(out), flat(full))
        # a finished progress file starts a fresh run next time
        again = run_json("hygiene", "--root", self.root, "--resume", prog, "--budget", "0")
        self.assertEqual(again.get("status"), "partial")


class TestIgnoreMarker(FixtureCase):
    def test_marked_folders_are_skipped(self):
        units = run_json("projects", "--root", self.root)
        self.assertNotIn("ignored-stuff", units)
        self.assertEqual(sorted(units), ALL_UNITS)

    def test_marked_root_is_empty(self):
        # The committed fixtures folder itself carries the marker: scanning its parent finds nothing in it.
        units = run_json("projects", "--root", os.path.join(REPO, "tests"))
        self.assertNotIn("fixtures", units)

    def test_whole_project_marker(self):
        p = os.path.join(self.root, "web-shop")
        marker = os.path.join(p, ".occupai-ignore")
        open(marker, "w").close()
        try:
            # An ignore-marked project is not in the scan: --only says so instead of checking nothing.
            self.assertIn("no project named web-shop", run("hygiene", "--root", self.root, "--only", "web-shop",
                                                           check=False))
            self.assertEqual(run_json("hygiene", "--root", self.root)["summary"].get("web-shop"), None)
        finally:
            os.remove(marker)


class TestUnits(unittest.TestCase):
    def test_ranges(self):
        r = ">=15.0.0 <15.5.29 || >=16.0.0 <16.4.5"
        self.assertTrue(in_range("16.2.1", r))
        self.assertTrue(in_range("15.5.14", r))
        self.assertFalse(in_range("16.4.5", r))
        self.assertFalse(in_range("14.2.0", r))
        self.assertTrue(in_range("19.3.0", ">=19.2.0 <19.2.9 || 19.3.0"))
        self.assertFalse(in_range("19.3.1", ">=19.2.0 <19.2.9 || 19.3.0"))
        self.assertTrue(in_range("20.5.0", ">=20.0.0 <21.0.0"))

    def test_effective_pins(self):
        node = "<22.0.0 || >=22.0.0 <22.23.5 || >=24.0.0 <24.22.3"
        self.assertTrue(in_range(effective_pin("20"), node))          # EOL major
        self.assertTrue(in_range(effective_pin("v22.19.0"), node))    # exact, below fix
        self.assertFalse(in_range(effective_pin("22"), node))         # major-only: gets patches
        self.assertFalse(in_range(effective_pin("24.22.3"), node))

    def test_pypi_pinned_only(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "requirements.txt"), "w") as f:
                f.write("requests==2.0.0\nflask>=3.1\n# comment\n")
            seen = []

            class Resp(io.BytesIO):
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            def opener(req, timeout):
                seen.append(req.full_url)
                return Resp(json.dumps({"vulnerabilities": [{"id": "PYSEC-0000-1", "aliases": [], "fixed_in": ["2.1.0"]}]}).encode())

            out = pypi_audit(Policy(tmp), os.path.join(tmp, "requirements.txt"), opener=opener)
            self.assertEqual(seen, ["https://pypi.org/pypi/requests/2.0.0/json"])
            self.assertEqual(out["unsupported"], [{"line": 2, "reason": "unpinned"}])
            self.assertEqual(out["status"], "ok")
            self.assertEqual(out["vulns"]["requests==2.0.0"][0]["id"], "PYSEC-0000-1")
        finally:
            shutil.rmtree(tmp)

    def test_config_files_parse(self):
        for name in ("occupai.config.yaml", "occupai.config.example.yaml", "examples/demo/occupai.config.yaml"):
            cfg = cfgmod.load(os.path.join(REPO, name))
            self.assertIn("projects_root", cfg)
            self.assertIsInstance(cfg["exclusions"], list)
            self.assertIsInstance(cfg["my_owners"], list)
            self.assertIn("path", cfg["storage"])
        ex = cfgmod.load(os.path.join(REPO, "occupai.config.example.yaml"))
        for group in ("campaigns_and_supply_chain", "official", "stack_vendors", "news"):
            self.assertTrue(ex["news_sources"][group], group)
            self.assertIn("url", ex["news_sources"][group][0])
        self.assertEqual(set(ex["schedule"]), {"briefing", "scan", "full_day"})

    def test_yaml_subset(self):
        data = cfgmod.parse_yaml(
            "a: 1\nb: 'x # not a comment'  # comment\nc:\n  - one\n  - two\nd:\n  e: [p, q]\n"
            "f:\n  - name: n1\n    url: https://example.com/a\n  - name: n2\n    url: https://example.com/b\n")
        self.assertEqual(data, {"a": 1, "b": "x # not a comment", "c": ["one", "two"], "d": {"e": ["p", "q"]},
                                "f": [{"name": "n1", "url": "https://example.com/a"},
                                      {"name": "n2", "url": "https://example.com/b"}]})

    def test_checks_match_schema(self):
        with open(os.path.join(REPO, "schema", "checks.schema.json")) as f:
            schema = json.load(f)
        item_req = schema["properties"]["checks"]["items"]["required"]
        for path in (DEMO_CHECKS, os.path.join(REPO, "templates", "checks.json")):
            with open(path) as f:
                data = json.load(f)
            for k in schema["required"]:
                self.assertIn(k, data, path)
            for c in data["checks"]:
                for k in item_req:
                    self.assertIn(k, c, f"{path}: {c.get('id')} lacks {k}")


class TestTracker(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(REPO, "templates", "actioned.md")) as f:
            self.before, self.rows, self.after = trk.parse(f.read())

    def test_template_round_trip(self):
        text = trk.render(self.before, self.rows, self.after)
        b, r, a = trk.parse(text)
        self.assertEqual(r, self.rows)

    def test_mark_and_auto_close_rules(self):
        rows = []
        trk.add(rows, "x-1", "Item one", "2026-11-16")
        trk.add(rows, "x-2", "Item two", "2026-11-16")
        trk.add(rows, "x-3", "Item | with pipe", "2026-11-16")
        self.assertEqual(trk.auto_close(rows, "x-1", "not-affected", "2026-11-17", "no lockfile has it", complete=True), ("open", "not-affected"))
        self.assertTrue(rows[0]["Note"].startswith("auto: full run 2026-11-17"))
        trk.mark(rows, "x-2", "watching", "2026-11-17")
        self.assertIsNone(trk.auto_close(rows, "x-2", "done", "2026-11-18", "fixed", complete=True))  # user parked it
        trk.mark(rows, "x-1", "open", "2026-11-18", "I disagree")  # user reopened after an auto-close
        self.assertIsNone(trk.auto_close(rows, "x-1", "not-affected", "2026-11-19", "still clean", complete=True))
        with self.assertRaises(ValueError):
            trk.mark(rows, "x-3", "fixed?", "2026-11-18")
        b, r, a = trk.parse(trk.render("# T", rows, ""))
        self.assertEqual(r[2]["Item"], "Item | with pipe")

    def test_cli_mark(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "actioned.md")
            shutil.copy(os.path.join(REPO, "templates", "actioned.md"), path)
            run("tracker", "add", "demo-1", "Demo item", "--tracker", path, "--date", "2026-11-16")
            out = run_json("tracker", "mark", "demo-1", "done", "--tracker", path, "--date", "2026-11-17")
            self.assertEqual(out["row"]["Status"], "done")
            bad = subprocess.run([sys.executable, "-m", "occupai_scan", "tracker", "mark", "nope", "done", "--tracker", path],
                                 cwd=TEST_HOME, capture_output=True, text=True, env=TEST_ENV)
            self.assertEqual(bad.returncode, 2)
        finally:
            shutil.rmtree(tmp)


class TestSafety(unittest.TestCase):
    def test_audit_never_runs_in_repo(self):
        src = read(os.path.join(REPO, "occupai_scan", "deps.py"))
        self.assertIn("--package-lock-only", src)
        self.assertIn("--ignore-scripts", src)
        self.assertNotIn("pip-audit", src.replace("Never pip-audit -r", ""))
        for bad in ('"install"', '"ci"', "'install'", "os.remove", "os.unlink"):
            for mod in ("cli.py", "hygiene.py", "match.py", "discovery.py", "deps.py"):
                self.assertNotIn(bad, read(os.path.join(REPO, "occupai_scan", mod)), f"{bad} in {mod}")

    def test_missing_root_changes_nothing(self):
        r = subprocess.run([sys.executable, "-m", "occupai_scan", "hygiene", "--root", "/nonexistent/occupai"],
                           cwd=TEST_HOME, capture_output=True, text=True, env=TEST_ENV)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not reachable", r.stdout)


class TestDemoAndOut(unittest.TestCase):
    def test_demo_runs_offline_and_leaks_nothing(self):
        tmp = tempfile.mkdtemp(prefix="occupai-demo-")
        try:
            r = subprocess.run([sys.executable, os.path.join(REPO, "examples", "demo", "run_demo.py"), "--out", tmp],
                               capture_output=True, text=True, env=TEST_ENV)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            storage = os.path.join(tmp, "storage")
            reports = os.listdir(os.path.join(storage, "briefings"))
            self.assertEqual(len(reports), 2)  # one run: news brief + project report
            _, rows, _ = trk.load(os.path.join(storage, "actioned.md"))
            status = {row["ID"]: row["Status"] for row in rows}
            self.assertEqual(status["demo-httpd-rce"], "not-affected")   # auto-closed with evidence
            self.assertEqual(status["demo-paas-breach"], "open")        # account-scoped: never auto-closed
            self.assertEqual(status["demo-node-security-release"], "open")
            self.assertIn("hygiene-secrets-web-shop", status)
            self.assertNotIn("hygiene-secrets-forked-tool", status)      # third-party clone: info only
            # the fixture keys from this demo run never reach storage
            proj = os.path.join(tmp, "projects")
            secret_bits = [read(os.path.join(proj, "web-shop", "src", "lib", "ai.ts")).split('"')[1][-20:],
                           read(os.path.join(proj, "web-shop", ".env")).split("=")[1].strip()[-20:]]
            for dp, _, fns in os.walk(storage):
                for fn in fns:
                    text = read(os.path.join(dp, fn))
                    for bit in secret_bits:
                        self.assertNotIn(bit, text, f"secret fragment found in {fn}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_out_flag_saves_full_json(self):
        tmp = tempfile.mkdtemp(prefix="occupai-out-")
        try:
            root = os.path.join(tmp, "p")
            fixture_setup.build(root)
            path = os.path.join(tmp, "state", "h.json")
            short = run_json("hygiene", "--root", root, "--out", path)
            self.assertEqual(short["saved"], path)
            self.assertNotIn("results", short)
            self.assertIn("web-shop", short["summary"])
            with open(path) as f:
                self.assertIn("results", json.load(f))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
