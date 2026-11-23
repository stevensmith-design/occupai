"""Fix round 2, stage C: setup. Discovery before the first scan, scheduling from the chat only, one task
run once while the user is there, expectations, and the check-on-your-computer line. Offline, fixtures only.
"""
import json
import os
import re
import shutil
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE, os.path.join(HERE, "helpers")]

import fixture_setup  # noqa: E402
from test_p0_safety import Env, realtmp  # noqa: E402
from occupai_scan.discovery import looks_like_copy  # noqa: E402

SETUP = os.path.join(REPO, "SETUP.md")


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class TestDiscover(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = realtmp("occupai-r2c-")
        cls.root = os.path.join(cls.tmp, "projects")
        fixture_setup.build(cls.root, seed=71)
        for d in ("web-shop copy", "site-2024-03-01", "_to_delete/thing", "Archive/client-site", "bold-app",
                  "oldenburg-maps", "app (2)", "skip-me"):
            write(os.path.join(cls.root, d, "package-lock.json"), "{}\n")
        cls.e = Env(cls.tmp)
        st = os.path.join(cls.tmp, "storage")
        cls.cfg = os.path.join(st, "occupai.config.yaml")
        write(cls.cfg, f"version: 1\nprojects_root: {cls.root}\nstorage:\n  path: {st}\nexclusions:\n  - \"ui-kit\"\n")
        cls.e.json("project", "skip-me", "skip", "--config", cls.cfg)
        t0 = time.time()
        cls.d = cls.e.json("discover", "--config", cls.cfg)
        cls.secs = time.time() - t0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_projects_ill_watch(self):
        watch = {w["project"]: w for w in self.d["watch"]}
        for u in ("web-shop copy", "site-2024-03-01", "_to_delete/thing", "Archive/client-site", "app (2)"):
            self.assertFalse(watch[u]["watch"], u)
            self.assertTrue(watch[u]["why"].startswith(u.split("/")[0] + ":"), watch[u])
        for u in ("web-shop", "bold-app", "oldenburg-maps", "agent-lab"):
            self.assertTrue(watch[u]["watch"], u)
        self.assertNotIn("ui-kit", watch)  # excluded in the config
        self.assertNotIn("skip-me", watch)  # "don't touch" decision: never read
        self.assertEqual(self.d["skipped"], ["skip-me"])
        self.assertLess(self.secs, 5)

    def test_scanning_for_and_owners(self):
        tech = {t["tech"]: t for t in self.d["scanning_for"]}
        self.assertIn("web-shop", tech["Next.js"]["projects"])
        self.assertEqual(tech["GitHub Actions"]["checked_locally"], "checked")
        self.assertEqual(tech["Flask"]["checked_locally"], "news only")
        self.assertEqual(self.d["github_owners"], {"example-owner": 3, "someone-else": 1})
        self.assertIn(self.d["computer"], ("macOS", "Linux", "Windows"))

    def test_no_secret_or_key_file_is_opened(self):
        # the fixtures hold fake keys in .env files; discover reads names and manifests only
        keys = fixture_setup.make_keys(71)
        text = json.dumps(self.d)
        for v in keys.values():
            self.assertNotIn(v, text)

    def test_looks_like_copy(self):
        for name in ("backup", "my-site_BACKUP", "old", "site-old", "Copy of app", "archive", "_to_delete",
                     "app-20240301", "app 2024-03-01", "app (3)", "clients/acme/site.bak"):
            self.assertIsNotNone(looks_like_copy(name), name)
        for name in ("bold", "copywriter", "oldenburg", "archivist-ui", "web-shop", "app-2024", "v20"):
            self.assertIsNone(looks_like_copy(name), name)


class TestSetupDoc(unittest.TestCase):
    def setUp(self):
        self.setup = read("SETUP.md")

    def test_budget(self):
        self.assertLess(len(self.setup.split()), 950)

    def test_discovery_before_first_scan(self):
        s = self.setup
        self.assertLess(s.index("scan.py discover"), s.index("Run the first check now?"))
        for part in ("**Projects I'll watch:**", "**Scanning for:**", '"Anything to add or remove?"',
                     "GitHub usernames and organisations", "clients', employer's"):
            self.assertIn(part, s)

    def test_scheduling_in_the_chat_only(self):
        s = self.setup
        self.assertIn("Create **two** local scheduled tasks yourself", s)
        self.assertIn("**one message to paste into a new Claude Desktop chat**", s)
        self.assertEqual(len(re.findall(r"scheduled task", s)), 3)  # the tasks, the paste message, the first-run question
        for dev in ("Code tab", "Bash(", "Edit(", "settings.json", "Settings >", "Keep computer awake",
                    "Working folder", "Run now"):
            self.assertNotIn(dev, s)
        # the task prompt has one copy: SETUP.md; the developer guide points at it
        self.assertEqual(len([b for b in re.findall(r"```\n(.*?)```", s, re.S) if "Run OccupAI" in b]), 1)
        self.assertIn("step 6 of [SETUP.md]", read("docs", "setup", "claude-desktop.md"))
        self.assertNotIn("```\nRun OccupAI", read("docs", "setup", "claude-desktop.md"))

    def test_approve_once_and_expectations(self):
        s = self.setup
        self.assertIn("Run the first check now? (Recommended, about 10–20 minutes.)", s)
        self.assertIn("choose 'always allow'", s)
        self.assertIn("re-check every project (10–20 minutes)", s)
        self.assertIn("The next full run re-checks every project and can take 10–20 minutes", read("prompts", "howto.md"))
        self.assertIn('say "Checked <done> of <done+remaining> projects"', read("prompts", "run.md"))


class TestCheckOnYourComputer(unittest.TestCase):
    def test_section_and_os_commands(self):
        run, howto = read("prompts", "run.md"), read("prompts", "howto.md")
        self.assertIn("<your computer, account or dashboard>: action — why. <action line>\n<`computer` from `changed`>", run)
        self.assertNotIn("Mac check", run + howto)
        rule = howto[howto.index("## Check on your computer"):]
        for part in ('"paste this into Terminal"', '"paste this into PowerShell"', "py --version"):
            self.assertIn(part, rule)
        schema = json.loads(read("schema", "checks.schema.json"))
        machine = schema["properties"]["checks"]["items"]["properties"]["match"]["properties"]["machine"]
        self.assertEqual(set(machine["oneOf"][1]["properties"]), {"macos", "linux", "windows"})

    def test_changed_prints_the_computer(self):
        tmp = realtmp("occupai-r2c-os-")
        try:
            os.makedirs(os.path.join(tmp, "projects", "a"))
            out = Env(tmp).json("changed", "--root", os.path.join(tmp, "projects"))
            self.assertIn(out["computer"], ("macOS", "Linux", "Windows"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
