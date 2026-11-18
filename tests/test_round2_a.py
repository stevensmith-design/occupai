"""Fix round 2, stage A: odd folder names, discovery depth, your decisions about projects, the stack
inventory and the briefing's "touches my stack?" lookup. Offline, synthetic projects in a temp folder.
"""
import json
import os
import re
import shutil
import sys
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE, os.path.join(HERE, "helpers")]

from test_p0_safety import Env, realtmp  # noqa: E402
from occupai_scan.common import clean  # noqa: E402
from occupai_scan.safefs import WALK_DEPTH  # noqa: E402


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if isinstance(text, str) else json.dumps(text))


def pkg(deps):
    return {"name": "x", "version": "1.0.0", "dependencies": deps}


def lock(deps):
    packages = {"": {"name": "x", "version": "1.0.0", "dependencies": deps}}
    packages.update({f"node_modules/{n}": {"version": v} for n, v in deps.items()})
    return {"name": "x", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-r2a-")
        self.root = os.path.join(self.tmp, "projects")
        self.storage = os.path.join(self.tmp, "storage")
        os.makedirs(self.root)
        self.cfg = os.path.join(self.tmp, "occupai.config.yaml")
        write(self.cfg, f"projects_root: {self.root}\nexclusions: []\nmy_owners: [example-owner]\n"
                        f"storage:\n  path: {self.storage}\n")
        self.e = Env(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def project(self, name, deps=None, files=()):
        d = os.path.join(self.root, name)
        write(os.path.join(d, "package.json"), pkg(deps or {"left-pad": "1.3.0"}))
        write(os.path.join(d, "package-lock.json"), lock(deps or {"left-pad": "1.3.0"}))
        for f in files:
            write(os.path.join(d, f), "x: 1\n")
        return d

    def scan(self, *args):
        return self.e.json(*args, "--config", self.cfg)

    def run_scan(self, *args):
        return self.e.run(*args, "--config", self.cfg)

    def full_run(self):
        st = os.path.join(self.storage, "state")
        self.scan("hygiene", "--out", os.path.join(st, "h.json"))
        return self.scan("save-state", "--hygiene", os.path.join(st, "h.json"))


class TestOddFolderNames(Case):
    """A folder named "R&D app" was printed as "R_D app"; feeding that name back silently matched nothing."""
    NAMES = ["R&D app", "Bob's \"quoted\" [v2]", "with space", unicodedata.normalize("NFD", "Café-ü")]

    def setUp(self):
        super().setUp()
        for n in self.NAMES:
            self.project(n)

    def test_full_cycle_keeps_raw_names(self):
        first = self.scan("changed")
        self.assertEqual(sorted(first["new"]), sorted(clean(n) for n in self.NAMES))
        self.full_run()
        with open(os.path.join(self.storage, "state", "scan-state.json"), encoding="utf-8") as f:
            self.assertEqual(sorted(json.load(f)["projects"]), sorted(self.NAMES))  # state keeps raw names
        again = self.scan("changed")
        self.assertEqual((again["new"], again["changed"], again["removed"]), ([], [], []))
        self.assertEqual(len(again["unchanged"]), len(self.NAMES))

    def test_printed_names_work_with_only(self):
        self.full_run()
        st = os.path.join(self.storage, "state")
        for n in self.NAMES + [unicodedata.normalize("NFC", self.NAMES[-1])]:
            for name in (n, clean(n)):
                with self.subTest(name=name):
                    out = os.path.join(st, "h-one.json")
                    hy = self.scan("hygiene", "--only", name, "--out", out)
                    self.assertEqual(len(hy["reused_unchanged"]) + len(hy["checked"]), 1)
                    self.assertEqual(self.scan("save-state", "--only", name, "--hygiene", out)["updated"], 1)

    def test_unknown_only_name_is_an_error_not_an_empty_run(self):
        r = self.run_scan("changed", "--only", "no-such-project")
        self.assertEqual(r.returncode, 2)
        self.assertIn("no project named no-such-project", json.loads(r.stdout)["error"])


class TestDiscoveryDepth(Case):
    def test_nested_client_projects_are_found(self):
        self.project("clients/client-a/2026/team/apps/portal/web")  # 7 levels down, no git
        nested = os.path.join(self.root, "Collections", "skills", "set-1", "group", "pack", "v2", "tool")
        write(os.path.join(nested, "requirements.txt"), "flask==3.0.0\n")
        os.makedirs(os.path.join(nested, ".git", "objects"))
        units = self.scan("projects")
        self.assertIn("clients/client-a/2026/team/apps/portal/web", units)
        self.assertIn("Collections/skills/set-1/group/pack/v2/tool", units)
        self.assertNotIn("_omitted", units)

    def test_what_is_still_cut_off_is_named(self):
        deep = os.path.join(self.root, "Archive-ish", *[f"d{i}" for i in range(WALK_DEPTH + 2)])
        write(os.path.join(deep, "package-lock.json"), lock({}))
        omitted = self.scan("changed")["omitted"]
        cut = [o for o in omitted if o["path"] == "Archive-ish"]
        self.assertEqual(cut[0]["reason"], "depth-limit")
        self.assertTrue(cut[0]["cut_at"].startswith("Archive-ish/d0/"))


class TestProjectDecisions(Case):
    CHECKS = {"checks": [{"id": "fake-pad-1", "title": "Fictional left-pad advisory", "scope": "project",
                          "match": {"packages": [{"name": "left-pad", "affected": "<2.0.0"}]}}]}

    def setUp(self):
        super().setUp()
        self.project("live-app", files=["bitrise.yml"])
        self.project("old-site", files=["netlify.toml"])
        self.project("client-copy")
        self.project("dont-touch")
        write(os.path.join(self.storage, "library", "checks.json"), self.CHECKS)

    def test_inactive_needs_the_deployment_answer(self):
        r = self.run_scan("project", "old-site", "inactive")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(json.loads(r.stdout)["ask"], "Is old-site still deployed anywhere?")
        self.assertFalse(os.path.exists(os.path.join(self.storage, "library", "project-status.json")))

    def test_one_decision_applies_to_every_check(self):
        self.full_run()
        self.scan("project", "old-site", "inactive", "--not-deployed")
        self.scan("project", "client-copy", "managed", "--note", "client team owns it")
        self.scan("project", "dont-touch", "skip")
        listed = self.scan("project", "list")["projects"]
        self.assertEqual(listed["old-site"]["status"], "inactive")
        self.assertIs(listed["old-site"]["deployed"], False)

        ch = self.scan("changed")
        self.assertNotIn("dont-touch", ch["removed"] + ch["unchanged"])
        self.assertEqual(ch["your_decisions"]["dont-touch"], "skip")

        m = self.scan("match")["fake-pad-1"]
        self.assertEqual(m["affected"], ["live-app"])
        self.assertEqual(m["silenced"], ["client-copy", "old-site"])

        st = os.path.join(self.storage, "state")
        hy = self.scan("hygiene", "--all", "--out", os.path.join(st, "h.json"))
        self.assertEqual(set(hy["silenced"]), {"client-copy", "old-site"})
        self.assertNotIn("dont-touch", hy["checked"])
        saved = self.scan("save-state", "--hygiene", os.path.join(st, "h.json"))
        self.assertEqual([t["tech"] for t in saved["new_in_stack"]], [])
        with open(saved["stack_file"], encoding="utf-8") as f:
            stack = f.read()
        self.assertIn("| Bitrise | live-app |", stack)
        self.assertNotIn("Netlify", stack)  # an inactive project's tech is not "your stack"

        self.scan("project", "old-site", "active")
        self.assertNotIn("old-site", self.scan("project", "list")["projects"])


class TestStackInventory(Case):
    def test_inventory_and_new_tech(self):
        self.project("mobile-app", deps={"next": "15.0.0", "mongoose": "8.0.0"}, files=["bitrise.yml"])
        write(os.path.join(self.root, "api", "requirements.txt"), "fastapi==0.110.0\n")
        write(os.path.join(self.root, "api", ".github", "workflows", "ci.yml"), "on: push\n")
        first = self.full_run()
        self.assertEqual(first["new_in_stack"], "first-run")
        with open(first["stack_file"], encoding="utf-8") as f:
            stack = f.read()
        for row in ("| Bitrise | mobile-app | news only |", "| MongoDB | mobile-app | news only |",
                    "| Next.js | mobile-app |", "| FastAPI | api |", "| GitHub Actions | api | checked |",
                    "| npm | mobile-app | audited |"):
            self.assertIn(row, stack)

        write(os.path.join(self.root, "api", "fly.toml"), "app = 'x'\n")
        second = self.full_run()
        self.assertEqual(second["new_in_stack"], [{"tech": "Fly.io", "projects": ["api"],
                                                   "checked_locally": "news only"}])

    def test_briefing_relevance_uses_the_inventory(self):
        """A breach at a CI provider nobody listed in `stack` must reach the project
        that has the provider's config file. The briefing reads stack.md; this is its lookup."""
        self.project("mobile-app", files=["codemagic.yaml"])
        self.project("web-app")
        with open(self.full_run()["stack_file"], encoding="utf-8") as f:
            rows = {m.group(1): m.group(2).split(", ")
                    for m in re.finditer(r"^\| ([^|(]+?)(?: \(new\))? \| ([^|]+) \|", f.read(), re.M)}
        news = {"id": "fictional-ci-breach", "title": "Fictional breach at a CI provider", "service": "Codemagic"}
        self.assertEqual(rows.get(news["service"]), ["mobile-app"])
        with open(os.path.join(REPO, "prompts", "run.md"), encoding="utf-8") as f:
            self.assertTrue("**Touches my stack?** yes / no / maybe, judged against stack.md" in f.read())


if __name__ == "__main__":
    unittest.main()
