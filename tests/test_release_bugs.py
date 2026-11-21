"""Post-release bug fixes (GitHub issues #2, #18, #19, #20): never imply clean when something wasn't
checked, skip generated build folders, and say (NEW) on an item's first day."""
import json
import os
import shutil
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE]

from test_p0_safety import Env, git_fixture, realtmp  # noqa: E402
from occupai_scan import deps  # noqa: E402
from occupai_scan.match import run_match  # noqa: E402
from occupai_scan.safefs import Policy  # noqa: E402


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/left-pad": {"version": "1.0.0"}}})


class TestNotReachable(unittest.TestCase):
    """#2: a project that shows up empty or unreadable (as a folder not attached to the task can) is
    `not_reachable`, never "unchanged", and no reader calls it clean."""

    def setUp(self):
        self.tmp = realtmp("occupai-reach-")
        self.root = os.path.join(self.tmp, "projects")
        self.state = os.path.join(self.tmp, "storage", "scan-state.json")
        app = os.path.join(self.root, "app")
        write(os.path.join(app, "package.json"), '{"name": "app", "dependencies": {"left-pad": "1.0.0"}}')
        write(os.path.join(app, "package-lock.json"), LOCK)
        git_fixture(app, "init", "-q")
        git_fixture(app, "add", ".")
        git_fixture(app, "commit", "-qm", "init")
        write(os.path.join(self.root, "notes", "readme.md"), "notes\n")
        self.e = Env(self.tmp)

    def tearDown(self):
        for dp, dns, fns in os.walk(self.tmp):
            for d in dns:
                os.chmod(os.path.join(dp, d), 0o755)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self, *args):
        return self.e.json(*args, "--root", self.root, "--state", self.state)

    def save_baseline(self):
        out = os.path.join(self.tmp, "storage", "h.json")
        self.scan("hygiene", "--out", out)
        self.scan("save-state", "--hygiene", out)

    def hide_app(self):
        """The folder is still listed but shows nothing, like a folder the task can't see into."""
        shutil.move(os.path.join(self.root, "app"), os.path.join(self.tmp, "app-real"))
        os.makedirs(os.path.join(self.root, "app"))

    def test_empty_folder_is_not_reachable_on_every_run(self):
        self.save_baseline()
        self.hide_app()
        out = os.path.join(self.tmp, "storage", "h2.json")
        for _ in range(2):  # the second run must not reuse a result as "unchanged"
            ch = self.scan("changed")
            self.assertEqual(ch["not_reachable"], {"app": "empty-folder"})
            for k in ("new", "changed", "unchanged"):
                self.assertNotIn("app", ch[k])
            self.assertIn("notes", ch["unchanged"])
            hy = self.scan("hygiene", "--out", out)
            self.assertEqual(hy["status"], "incomplete")
            self.assertNotIn("app", hy["reused_unchanged"])
            self.assertTrue(all(v == "incomplete" for v in hy["incomplete"]["app"].values()))
            self.scan("save-state", "--hygiene", out)

    def test_unreadable_folder_is_not_reachable(self):
        os.chmod(os.path.join(self.root, "notes"), 0)
        self.assertEqual(self.scan("changed")["not_reachable"], {"notes": "unreadable"})

    def test_match_and_audit_never_clean_on_an_empty_folder(self):
        self.hide_app()
        pol = Policy(self.root)
        check = {"id": "x", "title": "x", "scope": "project", "match": {"malicious_packages": ["evil-pkg"]}}
        res = run_match(pol, ["app", "notes"], [check])["x"]["projects"]
        self.assertEqual(res["app"]["status"], "unknown")
        self.assertEqual(res["app"]["skipped"], [{"file": "app", "reason": "empty-folder"}])
        self.assertEqual(res["notes"]["status"], "not-affected")
        r = deps.run_audit(pol, "app")
        self.assertEqual(r["status"], "incomplete")
        self.assertIn({"file": "app", "reason": "empty-folder"}, r["skipped"])

    def test_a_folder_with_only_finder_metadata_counts_as_empty(self):
        write(os.path.join(self.root, "blank", ".DS_Store"), "")
        self.assertEqual(Policy(self.root).unit_gap("blank"), "empty-folder")
        self.assertIsNone(Policy(self.root).unit_gap("notes"))

    def test_prompt_puts_it_under_not_checked(self):
        self.assertIn('- **`not_reachable`** (from `changed`): under "Not checked", "<project> isn\'t readable from'
                      ' this task: attach the projects folder to both tasks".', read("prompts", "run.md"))


if __name__ == "__main__":
    unittest.main()
