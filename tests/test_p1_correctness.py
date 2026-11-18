"""P1 acceptance tests: matching and discovery, fingerprints, resume and state promotion.

Offline, on synthetic fixture copies in a temp folder. npm is the fake script from the P0 tests;
PyPI is never contacted by `match` (pinned versions are read from requirements files).
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE, os.path.join(HERE, "helpers")]

import fixture_setup  # noqa: E402
from test_p0_safety import Env, git_fixture, opened_paths, realtmp  # noqa: E402
from occupai_scan.deps import lock_versions  # noqa: E402
from occupai_scan.safefs import WALK_DEPTH, Coverage, Policy  # noqa: E402
from occupai_scan.versions import RangeError, npm_in_range, pypi_in_range, validate_range  # noqa: E402

DEMO_CHECKS = os.path.join(REPO, "examples", "demo", "library", "checks.json")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text if isinstance(text, str) else json.dumps(text))


def checks_file(path, checks):
    write(path, {"checks": [{"title": c["id"], "scope": "project", **c} for c in checks]})
    return path


# ====================================================================== 5. ranges

NPM_CASES = [
    # (range, version, affected?)
    (">=16.0.0 <16.4.5", "16.0.0", True), (">=16.0.0 <16.4.5", "16.4.4", True),
    (">=16.0.0 <16.4.5", "16.4.5", False), (">=16.0.0 <16.4.5", "15.9.9", False),
    (">=16.0.0 <16.4.5", "16.4.5-canary.1", True),   # installed prereleases by precedence: before the fix
    (">=16.0.0 <16.4.5", "16.0.0-rc.1", False),      # ...and before the first affected release
    (">=16.0.0, <16.4.5", "16.2.0", True), (">16.0.0", "16.0.0", False), (">16.0.0", "16.0.1", True),
    ("<=16.0.0", "16.0.0", True), ("<=16.0.0", "16.0.1", False), ("=1.2.3", "1.2.3", True),
    ("1.2.3", "1.2.3", True), ("1.2.3", "1.2.4", False), ("v1.2.3", "1.2.3", True), ("1.2.3", "1.2.3+build.5", True),
    (">=19.2.0 <19.2.9 || 19.3.0", "19.3.0", True), (">=19.2.0 <19.2.9 || 19.3.0", "19.3.1", False),
    (">=19.2.0 <19.2.9 || 19.3.0", "19.2.8", True), (">= 1.2.3 < 2.0.0", "1.5.0", True),
    ("<22.0.0 || >=22.0.0 <22.23.5", "21.9.0", True), ("<22.0.0 || >=22.0.0 <22.23.5", "22.23.5", False),
]
# Unsupported on purpose (parity with the check library): unknown, never reinterpreted.
NPM_MALFORMED = ["", "   ", "latest", "1.2.3.4", ">=", ">=1.2.3 <", "^1.2.3", "~1.2.3", "~>1.2.3", "1.2.3 - 2.3.4",
                 "20.x", "1.2.*", "*", ">=16", "<1.2", ">=1.0.0-rc.1", ">=1 && <2", "=>1.0.0", "npm:foo@1", "||",
                 ">=1.0.0 ||", "file:../x", "> = 1.0.0", ">= >=1.0.0"]
PYPI_CASES = [
    (">=2.0,<2.32.4", "2.31.0", True), (">=2.0,<2.32.4", "2.32.4", False), (">=2.0,<2.32.4", "2.32.4rc1", True),
    (">=2.0, <2.32.4", "1.9", False), (">1.0", "1.0.post1", True),
    ("==2.0", "2.0.0", True), ("!=2.0,>=1", "2.0", False), ("!=2.0,>=1", "2.1", True),
    ("<1.0 || >=3.0,<3.1", "3.0.5", True), ("<1.0 || >=3.0,<3.1", "2.0", False), ("<2", "1!0.5", False),
]
PYPI_MALFORMED = ["", "~=1.0", "==1.*", "^1.0", "latest", ">=1.0 ||", "1.0", "=>1.0", "<1.0a1", ">=2.0.dev1"]


class TestRanges(unittest.TestCase):
    def test_npm_boundaries(self):
        for rng, v, want in NPM_CASES:
            with self.subTest(rng=rng, v=v):
                self.assertIs(npm_in_range(v, rng), want)

    def test_npm_malformed_is_rejected(self):
        for rng in NPM_MALFORMED:
            with self.subTest(rng=rng):
                self.assertIsNotNone(validate_range(rng))
                with self.assertRaises(RangeError):
                    npm_in_range("1.0.0", rng)

    def test_unparsed_versions_are_rejected(self):
        for v in ("latest", "1.2", "git+https://example.com/x.git", "file:../x", "?", "npm:next@1.0.0"):
            with self.subTest(v=v), self.assertRaises(RangeError):
                npm_in_range(v, ">=1.0.0")

    def test_pypi_boundaries(self):
        for rng, v, want in PYPI_CASES:
            with self.subTest(rng=rng, v=v):
                self.assertIs(pypi_in_range(v, rng), want)

    def test_pypi_malformed_is_rejected(self):
        for rng in PYPI_MALFORMED:
            with self.subTest(rng=rng):
                self.assertIsNotNone(validate_range(rng, "pypi"))


# ====================================================================== 5. lockfile formats

class TestLockfileFormats(unittest.TestCase):
    def setUp(self):
        self.root = realtmp("occupai-p1lock-")
        self.pol = Policy(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def versions(self, name, content):
        p = os.path.join(self.root, "p", name)
        write(p, content)
        cov = Coverage()
        return lock_versions(self.pol, p, ["next"], cov), cov.skipped

    def test_package_lock_v1_is_unsupported(self):
        got, skipped = self.versions("package-lock.json", {"lockfileVersion": 1, "dependencies": {
            "next": {"version": "15.0.0"}}})
        self.assertIsNone(got)
        self.assertEqual(skipped, [{"file": "p/package-lock.json", "reason": "unsupported-lockfile-v1"}])

    def test_package_lock_v2_v3(self):
        for v in (2, 3):
            with self.subTest(v=v):
                got, _ = self.versions("package-lock.json", {"lockfileVersion": v, "packages": {
                    "": {"name": "p"}, "node_modules/next-auth": {"version": "4.0.0"},
                    "node_modules/@scope/next": {"version": "9.9.9"},
                    "node_modules/a/node_modules/next": {"version": "15.0.0"},
                    "node_modules/my-next": {"name": "next", "version": "14.0.0"},
                    "node_modules/linked": {"resolved": "packages/linked", "link": True}}})
                self.assertEqual(got, {"next": ["14.0.0", "15.0.0"]})

    def test_unknown_package_lock_version_is_unsupported(self):
        got, skipped = self.versions("package-lock.json", {"lockfileVersion": 4, "packages": {}})
        self.assertIsNone(got)
        self.assertEqual(skipped, [{"file": "p/package-lock.json", "reason": "unsupported-lockfile-version"}])

    def test_pnpm(self):
        v9 = ("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      next:\n        specifier: ^16\n"
              "        version: 16.2.1\npackages:\n  next@16.2.1:\n    resolution: {integrity: x}\n"
              "  next-auth@4.0.0:\n    resolution: {integrity: x}\n  '@scope/next@1.0.0':\n    resolution: {}\n")
        self.assertEqual(self.versions("pnpm-lock.yaml", v9)[0], {"next": ["16.2.1"]})
        v6 = "lockfileVersion: '6.0'\npackages:\n  /next@15.1.0(react@18.2.0):\n    dev: false\n"
        self.assertEqual(self.versions("pnpm-lock.yaml", v6)[0], {"next": ["15.1.0"]})
        v5 = "lockfileVersion: 5.4\npackages:\n  /next/14.0.0_react@18.2.0:\n    dev: false\n"
        self.assertEqual(self.versions("pnpm-lock.yaml", v5)[0], {"next": ["14.0.0"]})
        got, skipped = self.versions("pnpm-lock.yaml", "lockfileVersion: 3\npackages:\n  /next/1.0.0:\n")
        self.assertIsNone(got)
        self.assertEqual(skipped[0]["reason"], "unsupported-lockfile-version")

    def test_yarn(self):
        classic = ('# yarn lockfile v1\n\n"next@^16.0.0", next@16.2.1:\n  version "16.2.1"\n\n'
                   'next-auth@^4:\n  version "4.0.0"\n\n"@scope/next@^1":\n  version "1.0.0"\n\n'
                   'my-next@npm:next@14.0.0:\n  version "14.0.0"\n')
        self.assertEqual(self.versions("yarn.lock", classic)[0], {"next": ["14.0.0", "16.2.1"]})
        berry = '__metadata:\n  version: 6\n\n"next@npm:16.2.1":\n  version: 16.2.1\n  resolution: "next@npm:16.2.1"\n'
        self.assertEqual(self.versions("yarn.lock", berry)[0], {"next": ["16.2.1"]})

    def test_bun(self):
        text = ('{"lockfileVersion": 1, "packages": {"next": ["next@16.2.1", "", {}, "sha"],'
                ' "next-auth": ["next-auth@4.0.0", "", {}, "sha"], "x/next": ["next@15.0.0", "", {}, "sha"]}}')
        self.assertEqual(self.versions("bun.lock", text)[0], {"next": ["15.0.0", "16.2.1"]})


# ====================================================================== 5. replay through the CLI

class TestReplay(unittest.TestCase):
    """Python replay, unsupported inputs, exact names, depth limit, exclusions: never clean by accident."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = realtmp("occupai-p1replay-")
        r = cls.root = os.path.join(cls.tmp, "projects")
        hashed = "Requests==2.31.0 \\\n    --hash=sha256:aaaa\nflask>=3\n"
        for name, files in {
            "py-hit": {"requirements.txt": hashed},
            "py-fixed": {"requirements.txt": "requests==2.32.4\n"},
            "py-similar": {"requirements.txt": "requests-oauthlib==1.0.0\n"},
            "py-unpinned": {"requirements.txt": "requests>=2\n"},
            "py-include": {"requirements.txt": "-r base.txt\n", "base.txt": "requests==2.0.0\n"},
            "py-poetry": {"poetry.lock": "[[package]]\nname = \"requests\"\nversion = \"2.0.0\"\n"},
            "py-pyproject": {"pyproject.toml": "[project]\nname = \"x\"\n"},
            "js-only": {"package.json": {"name": "js-only"}, "package-lock.json":
                        {"lockfileVersion": 3, "packages": {"": {}, "node_modules/next-auth": {"version": "4.0.0"}}}},
            "js-nolock": {"package.json": {"name": "js-nolock", "dependencies": {"next": "^16"}}},
            "js-gitdep": {"package.json": {"name": "g"}, "package-lock.json": {"lockfileVersion": 3, "packages": {
                "node_modules/next": {"version": "git+https://example.com/next.git"}}}},
            "js-v1": {"package.json": {"name": "v1"}, "package-lock.json": {"lockfileVersion": 1, "dependencies": {
                "next": {"version": "16.2.1"}}}},
            "pnpm-old": {"pnpm-lock.yaml": "lockfileVersion: 3\npackages:\n  /next/16.2.1:\n"},
            "node-lts": {".nvmrc": "lts/*\n"},
            "node-matrix": {".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - uses: actions/setup-node@v4\n"
                            "        with:\n          node-version: ${{ matrix.node }}\n"},
        }.items():
            for f, c in files.items():
                write(os.path.join(r, name, f), c)
        deep = os.path.join(r, "deep-proj", *[f"d{i}" for i in range(WALK_DEPTH + 2)])
        write(os.path.join(deep, "package-lock.json"),
              {"lockfileVersion": 3, "packages": {"node_modules/occupai-demo-anim": {"version": "1.0.2"}}})
        write(os.path.join(deep, "package.json"), {"name": "deep"})
        write(os.path.join(r, "deep-proj", "README.md"), "deep\n")
        cls.checks = checks_file(os.path.join(cls.tmp, "checks.json"), [
            {"id": "py-req", "match": {"packages": [{"name": "requests", "ecosystem": "pypi", "affected": "<2.32.4"}]}},
            {"id": "npm-next", "match": {"packages": [{"name": "next", "affected": ">=16.0.0 <16.4.5"}]}},
            {"id": "bad-range", "match": {"packages": [{"name": "next", "affected": "^16.0.0"}]}},
            {"id": "bad-pyrange", "match": {"packages": [{"name": "requests", "ecosystem": "pypi", "affected": "~=2.0"}]}},
            {"id": "evil", "match": {"malicious_packages": ["occupai-demo-anim"]}},
            {"id": "node-old", "match": {"runtimes": [{"name": "node", "affected": "<22.0.0"}]}},
        ])
        cls.e = Env(cls.tmp)
        cls.m = cls.e.json("match", "--root", r, "--checks", cls.checks)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def status(self, check, unit):
        return self.m[check]["projects"][unit]["status"]

    def test_pinned_python_requirements_replay(self):
        self.assertEqual(self.m["py-req"]["affected"], ["py-hit"])
        ev = self.m["py-req"]["projects"]["py-hit"]["evidence"][0]
        self.assertEqual((ev["file"], ev["version"], ev["ecosystem"]), ("py-hit/requirements.txt", "2.31.0", "pypi"))
        self.assertEqual(self.status("py-req", "py-fixed"), "not-affected")
        self.assertEqual(self.status("py-req", "py-similar"), "not-affected")  # exact (normalised) names only
        self.assertEqual(self.status("py-req", "js-only"), "not-affected")

    def test_python_inputs_that_cant_be_read_are_unknown(self):
        for unit, reason in (("py-unpinned", "unpinned-requirement"), ("py-include", "requirement-not-followed"),
                             ("py-poetry", "unsupported-python-lockfile"),
                             ("py-pyproject", "unsupported-python-manifest")):
            with self.subTest(unit=unit):
                self.assertEqual(self.status("py-req", unit), "unknown")
                self.assertIn(reason, {s["reason"] for s in self.m["py-req"]["projects"][unit]["skipped"]})

    def test_exact_npm_names(self):
        self.assertEqual(self.status("npm-next", "js-only"), "not-affected")  # next-auth is not next

    def test_unsupported_npm_inputs_are_unknown(self):
        for unit, reason in (("js-nolock", "no-lockfile"), ("js-gitdep", "unparsed-version"),
                             ("js-v1", "unsupported-lockfile-v1"),
                             ("pnpm-old", "unsupported-lockfile-version")):
            with self.subTest(unit=unit):
                self.assertEqual(self.status("npm-next", unit), "unknown")
                self.assertIn(reason, {s["reason"] for s in self.m["npm-next"]["projects"][unit]["skipped"]})

    def test_malformed_ranges_are_never_reinterpreted(self):
        for check in ("bad-range", "bad-pyrange"):
            with self.subTest(check=check):
                self.assertEqual(self.m[check]["affected"], [])
                self.assertFalse(self.m[check]["complete"])
                self.assertTrue(all(p["status"] == "unknown" for p in self.m[check]["projects"].values()))

    def test_unsupported_runtime_pins_are_unknown(self):
        self.assertEqual(self.status("node-old", "node-lts"), "unknown")
        self.assertEqual(self.status("node-old", "node-matrix"), "unknown")
        self.assertEqual(self.status("node-old", "py-hit"), "not-affected")

    def test_truncated_traversal_is_unknown_and_reported(self):
        self.assertEqual(self.status("evil", "deep-proj"), "unknown")
        self.assertIn("depth-limit", {s["reason"] for s in self.m["evil"]["projects"]["deep-proj"]["skipped"]})
        units = self.e.json("projects", "--root", self.root)
        self.assertIn(("deep-proj", "depth-limit"), {(o["path"], o["reason"]) for o in units["_omitted"]})
        hy = self.e.json("hygiene", "--root", self.root, "--only", "deep-proj")
        self.assertEqual(hy["status"], "incomplete")
        self.assertIn("depth-limit", {s["reason"] for s in hy["results"]["deep-proj"]["secrets"]["skipped"]})


class TestExcludedNestedPaths(unittest.TestCase):
    def test_excluded_nested_paths_are_never_read(self):
        tmp = realtmp("occupai-p1excl-")
        try:
            root = os.path.join(tmp, "projects")
            keys = fixture_setup.build(root, seed=31)
            v = os.path.join(root, "web-shop", "vendored")
            write(os.path.join(v, "keys.ts"), f"export const k = '{keys['FAKE_OPENAI_KEY']}'\n")
            write(os.path.join(v, "package.json"), {"name": "v", "dependencies": {"occupai-demo-anim": "1.0.2"}})
            write(os.path.join(v, "package-lock.json"), {"lockfileVersion": 3, "packages": {
                "node_modules/occupai-demo-anim": {"version": "1.0.2"}}})
            write(os.path.join(v, "requirements.txt"), "requests==2.0.0\n")
            write(os.path.join(v, "schema.sql"), "create table public.t(id int);\n")
            git_fixture(os.path.join(root, "web-shop"), "add", "-f", "vendored")
            git_fixture(os.path.join(root, "web-shop"), "commit", "-q", "-m", "vendored")
            e = Env(tmp)
            trace = os.path.join(tmp, "open.log")
            st = os.path.join(tmp, "storage", "state.json")
            checks = checks_file(os.path.join(tmp, "c.json"), [
                {"id": "evil", "match": {"malicious_packages": ["occupai-demo-anim"],
                                         "files": [{"glob": "vendored/*", "contains": "x"}]}}])
            outs = []
            for args in (["projects"], ["hygiene", "--all", "--state", st], ["match", "--checks", checks],
                         ["versions", "--packages", "occupai-demo-anim"], ["audit"]):
                outs.append(e.json(*args, "--root", root, "--exclude", "*/vendored", trace=trace))
            opened = opened_paths(trace)
            self.assertTrue(any(p.startswith(os.path.join(root, "web-shop") + os.sep) for p in opened))  # control
            self.assertEqual([p for p in opened if p.startswith(v + os.sep) or p == v], [])
            blob = json.dumps(outs)
            self.assertNotIn("vendored", blob)
            self.assertEqual(outs[2]["evil"]["projects"]["web-shop"]["status"], "not-affected")
            self.assertTrue(all("vendored" not in json.dumps(c) for c in e.npm_calls()))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestContainedSymlinks(unittest.TestCase):
    """File symlinks are followed only to a readable regular file inside the same project."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = realtmp("occupai-p1link-")
        r = cls.root = os.path.join(cls.tmp, "projects")
        keys = fixture_setup.build(r, seed=53)
        lab = os.path.join(r, "agent-lab")
        os.remove(os.path.join(lab, "CLAUDE.md"))
        write(os.path.join(lab, "AGENTS.md"), "# Agents\nBe careful.\u200b\n")  # one hidden character
        os.symlink("AGENTS.md", os.path.join(lab, "CLAUDE.md"))           # the common case: allowed
        os.symlink("CLAUDE.md", os.path.join(lab, "chain.md"))            # chain ending inside: allowed
        os.makedirs(os.path.join(lab, "big"))
        write(os.path.join(lab, "big", "huge.txt"), "x" * 1_200_000)
        write(os.path.join(lab, "notes", "private.ts"), f"const k = '{keys['FAKE_OPENAI_KEY']}'\n")
        write(os.path.join(lab, ".env"), f"K={keys['FAKE_AWS_KEY']}\n")
        for name, target in (("to-env.ts", ".env"),                                 # sensitive target
                             ("to-other.ts", "../web-shop/src/lib/ai.ts"),          # another project
                             ("to-excluded.ts", "notes/private.ts"),                # excluded target
                             ("to-huge.txt", "big/huge.txt"),                       # over the size limit
                             ("to-dir", "notes"),                                   # a folder
                             ("to-missing.ts", "nope.ts")):
            os.symlink(target, os.path.join(lab, name))
        git_fixture(lab, "add", "-A")
        git_fixture(lab, "commit", "-q", "-m", "links")
        cls.lab = lab
        cls.e = Env(cls.tmp)
        cls.trace = os.path.join(cls.tmp, "open.log")
        cls.hy = cls.e.json("hygiene", "--root", r, "--only", "agent-lab", "--exclude", "*/notes", trace=cls.trace)
        cls.opened = opened_paths(cls.trace)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_contained_link_is_read(self):
        ai = self.hy["results"]["agent-lab"]["ai"]
        # CLAUDE.md -> AGENTS.md is not a gap; the refused .ts links the AI check would read are
        skipped = {s["file"] for s in ai["skipped"]}
        self.assertNotIn("agent-lab/CLAUDE.md", skipped)
        self.assertEqual(skipped, {"agent-lab/to-env.ts", "agent-lab/to-other.ts", "agent-lab/to-missing.ts",
                                   "agent-lab/to-excluded.ts"})
        files = {f.get("file") for f in ai["findings"]}
        self.assertIn("CLAUDE.md", files)
        self.assertIn(os.path.join(self.lab, "AGENTS.md"), self.opened)

    def test_everything_else_is_refused_and_reported(self):
        sec = self.hy["results"]["agent-lab"]["secrets"]
        skipped = {s["file"]: s["reason"] for s in sec["skipped"]}
        for n in ("to-env.ts", "to-other.ts", "to-excluded.ts", "to-missing.ts"):
            self.assertEqual(skipped.get(f"agent-lab/{n}"), "symlink", n)
        self.assertEqual(skipped.get("agent-lab/to-huge.txt"), "too-large")
        self.assertNotIn("agent-lab/CLAUDE.md", skipped)
        self.assertNotIn("agent-lab/chain.md", skipped)
        for target in (".env", "notes/private.ts", "big/huge.txt"):
            self.assertNotIn(os.path.join(self.lab, target), self.opened, target)
        self.assertNotIn(os.path.join(self.root, "web-shop", "src", "lib", "ai.ts"), self.opened)
        blob = json.dumps(self.hy)
        self.assertNotIn("private.ts", blob)
        self.assertEqual(sec["status"], "incomplete")

    def test_unscoped_policy_still_refuses(self):
        cov = Coverage()
        self.assertIsNone(Policy(self.root).read_text(os.path.join(self.lab, "CLAUDE.md"), cov=cov))
        self.assertEqual(cov.skipped, [{"file": "agent-lab/CLAUDE.md", "reason": "symlink"}])
        self.assertIsNotNone(Policy(self.root).for_unit("agent-lab").read_text(os.path.join(self.lab, "CLAUDE.md")))


# ====================================================================== 6. fingerprints, resume, state

class StateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-p1state-")
        self.root = os.path.join(self.tmp, "projects")
        self.keys = fixture_setup.build(self.root, seed=41)
        self.st_dir = os.path.join(self.tmp, "storage")
        os.makedirs(self.st_dir)
        self.state = os.path.join(self.st_dir, "state.json")
        self.e = Env(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def run_(self, *args, e=None):
        return (e or self.e).json(*args, "--root", self.root)

    def hygiene_and_save(self, *extra):
        hy = os.path.join(self.st_dir, "hy.json")
        out = self.run_("hygiene", "--state", self.state, "--out", hy, *extra)
        self.run_("save-state", "--state", self.state, "--hygiene", hy, *extra)
        return out

    def checked(self, *extra):
        return self.run_("hygiene", "--state", self.state, *extra)["checked"]

    def saved(self):
        with open(self.state) as f:
            return json.load(f)


class TestFingerprints(StateCase):
    def test_same_second_edit_to_dirty_file(self):
        f = self.p("clean-app", "package.json")
        with open(f) as fh:
            orig = fh.read()
        write(f, orig.replace('"clean-app"', '"clean-apX"'))  # dirty, same size
        self.hygiene_and_save()
        st = os.stat(f)
        write(f, orig.replace('"clean-app"', '"clean-apY"'))  # same size again...
        os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))       # ...and the same mtime, to the nanosecond
        self.assertEqual(self.run_("changed", "--state", self.state)["changed"], ["clean-app"])
        self.assertEqual(self.checked(), ["clean-app"])

    def test_non_git_edit_behind_a_newer_file(self):
        later = self.p("reports-sql", "notes.txt")
        write(later, "x\n")
        future = os.stat(later).st_mtime_ns + 10_000 * 10**9
        os.utime(later, ns=(future, future))
        self.hygiene_and_save()
        f = self.p("reports-sql", "schema.sql")
        st = os.stat(f)
        with open(f, "a") as fh:
            fh.write("-- edited\n")
        os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertEqual(self.checked(), ["reports-sql"])

    def test_ignored_file_that_hygiene_reads(self):
        write(self.p("agent-lab", ".gitignore"), ".claude/settings.local.json\n")
        git_fixture(self.p("agent-lab"), "add", ".gitignore")
        git_fixture(self.p("agent-lab"), "commit", "-q", "-m", "ignore local settings")
        local = self.p("agent-lab", ".claude", "settings.local.json")
        write(local, {})
        self.hygiene_and_save()
        self.assertEqual(self.checked(), [])
        write(local, {"permissions": {"defaultMode": "bypassPermissions"}})
        out = self.run_("hygiene", "--state", self.state)
        self.assertEqual(out["checked"], ["agent-lab"])
        self.assertIn(("agent-permissions-bypassed", ".claude/settings.local.json"),
                      {(f["type"], f.get("file")) for f in out["results"]["agent-lab"]["ai"]["findings"]})

    def test_owner_and_configuration_changes(self):
        self.hygiene_and_save("--owners", "example-owner")
        out = self.run_("hygiene", "--state", self.state, "--owners", "someone-else")
        self.assertEqual(out["checked"], [])  # ownership is re-derived, not re-scanned
        self.assertEqual(out["results"]["forked-tool"]["ownership"], "mine")
        self.assertEqual(out["results"]["web-shop"]["ownership"], "third-party")
        self.assertIn("web-shop", out["third_party_clones"])
        out = self.run_("hygiene", "--state", self.state, "--exclude", "*/nothing-matches-this")
        self.assertEqual(len(out["checked"]), len(out["results"]))  # exclusions changed: everything again

    def test_scanner_version_change(self):
        self.hygiene_and_save()
        s = self.saved()
        s["script_version"] = "0.0.0-older"
        write(self.state, s)
        out = self.run_("hygiene", "--state", self.state)
        self.assertTrue(out["cache_invalidated"])
        self.assertEqual(len(out["checked"]), len(out["results"]))

    def test_odd_folder_names_are_reused(self):
        write(self.p("it's [odd]", "index.ts"), "export const a = 1\n")
        self.hygiene_and_save()
        self.assertEqual(self.checked(), [])


class TestResumeBinding(StateCase):
    def test_changed_inputs_invalidate_resumed_hygiene(self):
        prog = os.path.join(self.st_dir, "hy-progress.json")
        first = self.run_("hygiene", "--resume", prog, "--budget", "0")
        self.assertEqual(first["status"], "partial")  # agent-lab (first unit) is done
        write(self.p("agent-lab", ".claude", "settings.json"), {"permissions": {"defaultMode": "bypassPermissions"}})
        out = first
        for _ in range(40):
            out = self.run_("hygiene", "--resume", prog, "--budget", "0")
            if out.get("status") != "partial":
                break
        self.assertEqual(out["redone_changed_inputs"], ["agent-lab"])
        self.assertIn("agent-permissions-bypassed", {f["type"] for f in out["results"]["agent-lab"]["ai"]["findings"]})

    def test_changed_inputs_invalidate_resumed_audit(self):
        prog = os.path.join(self.st_dir, "au-progress.json")
        args = ("audit", "--only", "bad-deps,ui-kit", "--resume", prog, "--budget", "0")
        self.assertEqual(self.run_(*args)["status"], "partial")
        lock = self.p("bad-deps", "package-lock.json")
        with open(lock, "a") as f:
            f.write("\n")
        out = self.run_(*args)
        while out.get("status") == "partial":
            out = self.run_(*args)
        self.assertEqual(out["redone_changed_inputs"], ["bad-deps"])
        names = [c["name"] for c in self.e.npm_calls()]
        self.assertEqual(names.count("bad-deps"), 2)

    def test_progress_from_other_settings_is_not_reused(self):
        prog = os.path.join(self.st_dir, "hy-progress.json")
        self.run_("hygiene", "--resume", prog, "--budget", "0")
        out = self.run_("hygiene", "--resume", prog, "--budget", "0", "--exclude", "*/other")
        self.assertEqual(out["done"], 1)  # started over instead of continuing


class TestStatePromotion(StateCase):
    def audit_and_save(self, e, *extra):
        au = os.path.join(self.st_dir, "au.json")
        out = self.run_("audit", "--state", self.state, "--out", au, *extra, e=e)
        saved = self.run_("save-state", "--state", self.state, "--audit", au, *extra, e=e)
        return out, saved

    def test_new_project_only_audit_preserves_others(self):
        self.hygiene_and_save()
        self.audit_and_save(Env(self.tmp, npm_mode="vuln"))
        before = self.saved()
        old_keys = {u: p["audit"]["keys"] for u, p in before["projects"].items() if "audit" in p}
        self.assertTrue(old_keys["bad-deps"])
        write(self.p("new-app", "package.json"), {"name": "new-app"})
        write(self.p("new-app", "package-lock.json"), {"lockfileVersion": 3, "packages": {"": {}}})
        out, _ = self.audit_and_save(Env(self.tmp, npm_mode="clean"), "--only", "new-app")
        self.assertEqual(out["first_audit"], ["new-app"])
        self.assertEqual(out["new_since_last"], [])
        self.assertEqual(out["fixed_since_last"], [])
        hy = os.path.join(self.st_dir, "hy-new.json")
        self.run_("hygiene", "--state", self.state, "--only", "new-app", "--out", hy)
        self.run_("save-state", "--state", self.state, "--only", "new-app", "--hygiene", hy)
        after = self.saved()
        for u, keys in old_keys.items():
            self.assertEqual(after["projects"][u]["audit"]["keys"], keys, u)
            self.assertEqual(after["projects"][u]["hygiene"], before["projects"][u]["hygiene"], u)
        self.assertEqual(after["projects"]["new-app"]["audit"]["keys"], [])
        self.assertLessEqual(set(sum(old_keys.values(), [])), set(after["audit_keys"]))
        self.assertEqual(self.checked(), [])  # everyone, old and new, has a current baseline

    def test_partial_progress_and_foreign_documents_are_refused(self):
        prog = os.path.join(self.st_dir, "au-progress.json")
        self.run_("audit", "--only", "bad-deps,ui-kit", "--resume", prog, "--budget", "0")
        hy = os.path.join(self.st_dir, "hy.json")
        self.run_("hygiene", "--out", hy)
        with open(hy) as f:
            doc = json.load(f)
        partial = os.path.join(self.st_dir, "partial.json")
        write(partial, {**doc, "status": "partial"})
        other_cfg = os.path.join(self.st_dir, "hy-other.json")
        self.run_("hygiene", "--out", other_cfg, "--exclude", "*/other")
        older = os.path.join(self.st_dir, "hy-older.json")
        write(older, {**doc, "script_version": "0.0.0"})
        for flag, path in (("--audit", prog), ("--hygiene", partial), ("--hygiene", other_cfg),
                           ("--hygiene", older), ("--hygiene", prog)):
            with self.subTest(path=os.path.basename(path)):
                r = self.e.run("save-state", "--root", self.root, "--state", self.state, flag, path)
                self.assertNotEqual(r.returncode, 0)
                self.assertFalse(os.path.exists(self.state))

    def test_stale_results_are_not_promoted(self):
        vuln = Env(self.tmp, npm_mode="vuln")
        self.hygiene_and_save()
        self.audit_and_save(vuln, "--only", "bad-deps")
        keys = self.saved()["projects"]["bad-deps"]["audit"]["keys"]
        # new results, then the inputs change before save-state
        hy, au = os.path.join(self.st_dir, "hy2.json"), os.path.join(self.st_dir, "au2.json")
        self.run_("hygiene", "--state", self.state, "--all", "--out", hy)
        self.run_("audit", "--state", self.state, "--out", au, e=Env(self.tmp, npm_mode="clean"))
        write(self.p("web-shop", "src", "new.ts"), "export const b = 2\n")
        with open(self.p("bad-deps", "package-lock.json"), "a") as f:
            f.write("\n")
        saved = self.run_("save-state", "--state", self.state, "--hygiene", hy, "--audit", au)
        # bad-deps' hygiene is stale too: its lockfile is one of the files hygiene can read
        self.assertEqual(saved["not_saved_inputs_changed"], {"hygiene": ["bad-deps", "web-shop"], "audit": ["bad-deps"]})
        s = self.saved()["projects"]
        self.assertEqual(s["bad-deps"]["audit"]["keys"], keys)  # the old finding stands; not "fixed"
        self.assertTrue(s["bad-deps"]["audit"]["stale"])
        self.assertTrue(s["web-shop"]["recheck"])
        self.assertEqual(sorted(self.checked()), ["bad-deps", "web-shop"])


if __name__ == "__main__":
    unittest.main()
