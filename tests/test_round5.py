"""Round 5: the kit outside the projects folder, the shareable-brief marker switch, and the briefing/scan
overlap guard."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE]

import fixture_setup  # noqa: E402
from test_p0_safety import Env, realtmp  # noqa: E402
from occupai_scan import config as cfgmod  # noqa: E402


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def copy_kit(dest):
    """A downloaded kit: what the ZIP holds that setup and the tasks use."""
    ign = shutil.ignore_patterns("__pycache__", "*.pyc")
    for d in ("occupai_scan", "templates", "prompts", "schema"):
        shutil.copytree(os.path.join(REPO, d), os.path.join(dest, d), ignore=ign)
    for f in ("scan.py", "occupai.config.example.yaml", "SETUP.md"):
        shutil.copy2(os.path.join(REPO, f), os.path.join(dest, f))


class TestKitOutsideTheProjectsFolder(unittest.TestCase):
    """The ZIP lands in ~/Downloads/occupai-main while the projects are in ~/Desktop. Setup must ask for
    access to the kit and attach it to both tasks; the task's device shell then sees it at $HOME/mnt."""

    def setUp(self):
        self.tmp = realtmp("occupai-r5-kit-")
        self.home = os.path.join(self.tmp, "home")
        self.projects = os.path.join(self.home, "Desktop")
        fixture_setup.build(self.projects, seed=91)
        self.kit = os.path.join(self.home, "Downloads", "occupai-main")
        copy_kit(self.kit)
        self.env = {**os.environ, "HOME": self.home, "OCCUPAI_CONFIG": "", "PYTHONPATH": ""}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sh(self, cmd):
        r = subprocess.run(["/bin/sh", "-c", cmd], env=self.env, capture_output=True, text=True, cwd=self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout

    def test_setup_flow_from_downloads(self):
        setup = read("SETUP.md")
        # step 3: the shell block, run with the downloaded kit
        block = next(b for b in re.findall(r"```\n(.*?)```", setup, re.S) if "mkdir -p KIT/data" in b)
        self.sh(block.replace("KIT/", self.kit + "/"))
        cfg = os.path.join(self.kit, "data", "occupai.config.yaml")
        y = read(cfg).replace("kit_path: ~/code/occupai", "kit_path: ~/Downloads/occupai-main")
        y = y.replace("projects_root: ~/projects", "projects_root: ~/Desktop")
        write(cfg, y)
        # step 5: discover, run from the downloaded kit, says the kit must be attached
        cmd = re.search(r"`(python3 KIT/scan\.py discover --config [^`]+)`", setup).group(1)
        kit = json.loads(self.sh(cmd.replace("KIT/", self.kit + "/")))["kit"]
        self.assertEqual((kit["found"], kit["inside_projects"], kit["attach_to_tasks"]), (True, False, True))
        self.assertEqual(kit["path"], os.path.realpath(self.kit))
        # the SETUP text asks for the kit in the access request and attaches it to both tasks
        self.assertIn("If KIT isn't inside the projects folder, add KIT to that request", setup)
        self.assertIn("Attach exactly the folders approved in step 3: `projects_root`, plus KIT if outside it.", setup)
        task = next(b for b in re.findall(r"```\n(.*?)```", setup, re.S) if "Run OccupAI" in b)
        self.assertIn("If a folder (projects, KIT) isn't at its usual path, it's at $HOME/mnt/<folder name>",
                      task)

    def test_kit_inside_the_projects_folder_needs_nothing_extra(self):
        inside = os.path.join(self.projects, "occupai")
        copy_kit(inside)
        cfg = os.path.join(self.tmp, "c.yaml")
        write(cfg, f"projects_root: {self.projects}\nkit_path: {inside}\nexclusions: [occupai]\n"
                   f"storage:\n  path: {self.tmp}/storage\n")
        kit = Env(self.tmp).json("discover", "--config", cfg)["kit"]
        self.assertEqual((kit["inside_projects"], kit["attach_to_tasks"]), (True, False))
        write(cfg, f"projects_root: {self.projects}\nkit_path: {self.tmp}/nowhere\nstorage:\n  path: {self.tmp}/s\n")
        self.assertFalse(Env(self.tmp).json("discover", "--config", cfg)["kit"]["found"])

    def test_device_shell_sees_the_attached_kit(self):
        # the task's shell: attached folders appear at $HOME/mnt/<name>; the real paths don't exist there
        shell_home = os.path.join(self.tmp, "shell-home")
        mnt = os.path.join(shell_home, "mnt")
        shutil.copytree(self.kit, os.path.join(mnt, "occupai-main"))
        os.makedirs(os.path.join(mnt, "Desktop", "app"))
        with mock.patch.dict(os.environ, {"HOME": shell_home}):
            self.assertEqual(cfgmod.mounted("~/Downloads/occupai-main"), os.path.join(mnt, "occupai-main"))
            self.assertEqual(cfgmod.mounted("~/Downloads/occupai-main/prompts/run.md"),
                             os.path.join(mnt, "occupai-main", "prompts", "run.md"))
        write(os.path.join(mnt, ".occupai", "occupai.config.yaml"),
              "projects_root: ~/Desktop\nkit_path: ~/Downloads/occupai-main\nstorage:\n  path: ~/.occupai\n")
        e = Env(self.tmp)
        e.home = shell_home
        e.env = {**e.env, "HOME": shell_home}
        kit = e.json("discover")["kit"]
        self.assertTrue(kit["found"])
        self.assertEqual(kit["path"], os.path.realpath(os.path.join(mnt, "occupai-main")))


class TestBriefingMarker(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-r5-marker-")
        os.makedirs(os.path.join(self.tmp, "projects", "a"))
        self.cfg = os.path.join(self.tmp, "storage", "occupai.config.yaml")
        write(self.cfg, f"projects_root: {self.tmp}/projects\nstorage:\n  path: {self.tmp}/storage\n")
        self.e = Env(self.tmp)
        self.marker = os.path.join(self.tmp, "storage", "state", "briefing-running")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def m(self, *args):
        return self.e.json("marker", *args, "--config", self.cfg)

    def test_start_check_done(self):
        self.assertFalse(self.m("check")["briefing_running"])  # no marker yet: no briefing ever ran
        self.assertEqual(self.m("start")["state"], "running")
        self.assertTrue(self.m("check")["briefing_running"])
        self.m("done")
        self.assertTrue(os.path.isfile(self.marker))  # overwritten, never deleted
        self.assertFalse(self.m("check")["briefing_running"])

    def test_stale_marker_does_not_block(self):
        write(self.marker, json.dumps({"state": "running", "at": time.time() - 31 * 60}))
        st = self.m("check")
        self.assertEqual((st["briefing_running"], st.get("stale")), (False, True))
        write(self.marker, "not json")
        self.assertFalse(self.m("check")["briefing_running"])

    def test_wait(self):
        t = time.time()
        self.assertFalse(self.m("wait")["briefing_running"])  # nothing running: returns at once
        self.assertLess(time.time() - t, 20)
        self.m("start")
        t = time.time()
        self.assertTrue(self.m("wait", "--budget", "1")["briefing_running"])  # still running after its budget
        self.assertLess(time.time() - t, 20)

    def test_never_writes_inside_the_projects(self):
        cfg = os.path.join(self.tmp, "bad.yaml")
        write(cfg, f"projects_root: {self.tmp}/projects\nstorage:\n  path: {self.tmp}/projects/a\n")
        r = self.e.run("marker", "start", "--config", cfg)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "projects", "a", "state")))


class TestPromptsRound5(unittest.TestCase):
    def test_overlap_guard(self):
        run = read("prompts", "run.md")
        self.assertIn("the briefing runs `SCAN marker start` first and `SCAN marker done` last", run)
        self.assertIn("The scan runs `SCAN marker wait` first", run)
        self.assertIn("The briefing is still running. Reply **try again** in a few minutes.", run)
        self.assertNotIn("marker", read("SETUP.md"))  # the scan prompt handles overlap; setup never waits itself

    def test_markers_follow_the_scorecard_switch(self):
        run = read("prompts", "run.md")
        news = run[run.index("YYYY-MM-DD-news.md`**"):run.index("YYYY-MM-DD-projects.md`**")]
        self.assertIn('Only if `news_scorecard` is on (default): affected items end with "→ see your to-do list"', news)
        self.assertIn("Off: nothing hints at which items affect the user.", news)
        self.assertIn('"→ see your to-do list"', read("occupai.config.example.yaml"))

    def test_script_only(self):
        run, howto = read("prompts", "run.md"), read("prompts", "howto.md")
        self.assertNotIn("one short read-only command", run)
        self.assertNotIn("one-off commands", howto)
        self.assertNotIn("STORAGE/howto.md", run)
        self.assertIn("never ad-hoc shell", run)

    def test_wording(self):
        self.assertIn("click **+** → **Add folder** and pick the occupai folder", read("README.md"))
        self.assertIn("delete both tasks in Scheduled, in Claude's sidebar", read("SETUP.md"))
        self.assertIn("delete both tasks in **Scheduled**, in Claude's sidebar", read("README.md"))


if __name__ == "__main__":
    unittest.main()
