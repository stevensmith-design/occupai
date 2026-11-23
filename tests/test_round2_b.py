"""Fix round 2, stage B: one run with two modes, one report, action lines, graceful recovery, and key-like
files left outside projects. Offline; the demo stands in for the agent.
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE, os.path.join(HERE, "helpers")]

from test_p0_safety import Env, git_fixture, realtmp  # noqa: E402
from occupai_scan import config as cfgmod  # noqa: E402
from occupai_scan.hygiene import key_like  # noqa: E402

# Round 3: the private project report (the shareable news brief is a separate file).
SECTIONS = ["## To do", "## Needs you (outside what the scan can see)", "## Not checked", "## Appendix"]


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class TestKeysOutsideProjects(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-r2b-")
        self.root = os.path.join(self.tmp, "projects")
        r = self.root
        for f in ("private", "private.pub", "server.pem", "notes.txt", "only.pub"):
            write(os.path.join(r, f), "not a key\n")
        write(os.path.join(r, "Notes", "id_rsa"), "not a key\n")                      # non-project folder
        write(os.path.join(r, "clients", "acme", "deploy.key"), "not a key\n")       # container folder
        write(os.path.join(r, "clients", "acme", "site", "package-lock.json"), "{}\n")
        write(os.path.join(r, "clients", "acme", "site", "id_ed25519"), "not a key\n")  # inside a project
        repo = os.path.join(r, "app")
        write(os.path.join(repo, "id_rsa"), "not a key\n")                           # inside a repo
        git_fixture(repo, "init", "-q")
        write(os.path.join(r, "old-stuff", "backup.p12"), "not a key\n")            # excluded below
        for f in ("server.pem", "private"):
            os.chmod(os.path.join(r, f), 0)  # never opened: an unreadable file is still reported by name
        self.e = Env(self.tmp)

    def tearDown(self):
        for f in ("server.pem", "private"):
            os.chmod(os.path.join(self.root, f), 0o644)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_names_only_outside_projects(self):
        hy = self.e.json("hygiene", "--root", self.root, "--exclude", "old-stuff")
        found = {k["file"]: k["why"] for k in hy["keys_outside_projects"]}
        self.assertEqual(found, {"private": "ssh-key-pair", "server.pem": "key-file-name",
                                 "Notes/id_rsa": "key-file-name", "clients/acme/deploy.key": "key-file-name"})
        self.assertTrue(all(k["fix"] == "move to ~/.ssh or delete" and k["severity"] == "medium"
                            for k in hy["keys_outside_projects"]))
        self.assertEqual(self.e.json("hygiene", "--root", self.root, "--only", "app")["keys_outside_projects"], [])

    def test_key_like(self):
        self.assertEqual(key_like(["a", "a.pub", "b.pub", "id_rsa.pub", "c.key", "notes.md"]),
                         {"a": "ssh-key-pair", "c.key": "key-file-name"})


class TestOneRun(unittest.TestCase):
    def test_three_prompts_became_one(self):
        names = sorted(os.listdir(os.path.join(REPO, "prompts")))
        self.assertEqual(names, ["howto.md", "run.md"])
        for dp, dns, fns in os.walk(REPO):
            dns[:] = [d for d in dns if d not in (".git", "_reference", "build", "__pycache__", "fixtures")]
            for f in fns:
                if f.endswith((".md", ".py", ".yaml")) and f not in ("CHANGELOG.md", "test_round2_b.py"):
                    text = read(os.path.relpath(os.path.join(dp, f), REPO))
                    for old in ("prompts/briefing.md", "prompts/scan.md", "prompts/audit.md", "-local-check.md"):
                        self.assertNotIn(old, text, os.path.join(dp, f))

    def test_modes(self):
        run = read("prompts", "run.md")
        self.assertIn("**full** when today is `schedule.full_day` (default Monday)", run)
        self.assertIn("**daily** on every other day", run)
        self.assertIn('"scan only <project>" is a full run with `--only <project>`', run)
        self.assertIn("the briefing still does the news, says \"Projects not checked; the next run will catch up\"", run)
        full_block = next(b for b in re.findall(r"```\n(.*?)```", run, re.S) if "SCAN audit" in b)
        self.assertIn("SCAN hygiene", full_block)
        cfg = cfgmod.load(os.path.join(REPO, "occupai.config.example.yaml"))
        self.assertEqual(cfg["schedule"], {"briefing": "52 7 * * *", "scan": "12 8 * * *", "full_day": "monday"})

    def test_report_order(self):
        run = read("prompts", "run.md")
        pos = [run.index(s) for s in SECTIONS]
        self.assertEqual(pos, sorted(pos))
        self.assertIn("An action that fits two places appears once", run)

    def test_setup_and_guides_make_one_task(self):
        setup = read("SETUP.md")
        self.assertIn("Create **two** local scheduled tasks", setup)
        self.assertNotRegex(setup.lower(), r"three (scheduled )?tasks")
        self.assertIn("Delete the tasks in **Scheduled**", read("docs", "setup", "claude-desktop.md"))


class TestRecoveryAndActions(unittest.TestCase):
    def test_every_stop_ends_with_a_way_forward(self):
        howto = read("prompts", "howto.md")
        rule = howto[howto.index("## Every stop ends with a way forward (hard rule)"):]
        rule = rule[:rule.index("\n## ", 5)]
        for part in ("1. What happened, in one plain sentence.", "2. One step for the user, in plain words.",
                     "reply **try again** here and I'll continue from where I stopped",
                     "redo only the steps that didn't finish"):
            self.assertIn(part, rule)
        for stop in ("No folder access", "Permission prompt waiting", "Computer asleep", "Network blocked",
                     "npm or PyPI unreachable", "Python missing"):
            self.assertIn(f"**{stop}", rule)
        self.assertIn("end with the recovery step from howto.md", read("prompts", "run.md"))

    def test_action_lines(self):
        howto = read("prompts", "howto.md")
        self.assertIn("One-time global fix first", howto)
        self.assertIn("say 'how do I <action>?' for steps", howto)


class TestDemoReport(unittest.TestCase):
    def test_project_report_sections_each_action_once(self):
        tmp = realtmp("occupai-r2b-demo-")
        try:
            r = subprocess.run([sys.executable, os.path.join(REPO, "examples", "demo", "run_demo.py"), "--out", tmp],
                               capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            reports = sorted(os.listdir(os.path.join(tmp, "storage", "briefings")))
            today = datetime.date.today().isoformat()
            self.assertEqual(reports, [f"{today}-news.md", f"{today}-projects.md"])
            text = read(os.path.join(tmp, "storage", "briefings", f"{today}-projects.md"))
            pos = [text.index(s) for s in SECTIONS]
            self.assertEqual(pos, sorted(pos))
            ids = re.findall(r"^- \[ \] \*\*\[([^\]]+)\]\*\*", text, re.M)
            self.assertEqual(len(ids), len(set(ids)), "an action appears more than once")
            fixes = [ln for ln in text.splitlines() if ". Fix: open " in ln]
            self.assertTrue(fixes and all(re.search(r"Fix: open \S+ in Claude Code and say: fix \S+ — \S", ln)
                                          for ln in fixes))
            self.assertIn("`deploy_key` (ssh-key-pair): move to ~/.ssh or delete", text)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
