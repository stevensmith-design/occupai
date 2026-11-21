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


class TestUnauditedEcosystems(unittest.TestCase):
    """#19: a project using an ecosystem the audit doesn't cover is never "ok": each lockfile (or manifest
    without one) is listed as not covered, per folder."""

    def setUp(self):
        self.tmp = realtmp("occupai-eco-")
        self.root = os.path.join(self.tmp, "projects")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def audit(self, unit, files):
        for f in files:
            write(os.path.join(self.root, unit, f), "x\n")
        return deps.run_audit(Policy(self.root), unit)

    def test_flutter_project_lists_dart_and_cocoapods(self):
        r = self.audit("flut", ["pubspec.yaml", "pubspec.lock", "ios/Podfile", "ios/Podfile.lock",
                                "android/build.gradle.kts"])
        self.assertEqual(r["status"], "incomplete")
        self.assertEqual(sorted(r["not_covered"]), ["flut/android/build.gradle.kts: not-audited (Gradle)",
                                                    "flut/ios/Podfile.lock: not-audited (CocoaPods)",
                                                    "flut/pubspec.lock: not-audited (Dart)"])

    def test_manifest_without_lockfile_is_listed(self):
        for unit, f, eco in (("rb", "Gemfile", "Ruby"), ("go", "go.mod", "Go"), ("rs", "Cargo.toml", "Rust"),
                             ("php", "composer.json", "PHP"), ("sw", "Package.swift", "Swift")):
            with self.subTest(eco=eco):
                r = self.audit(unit, [f])
                self.assertEqual(r["not_covered"], [f"{unit}/{f}: not-audited ({eco})"])
                self.assertEqual(r["status"], "incomplete")

    def test_plain_folder_stays_ok(self):
        self.assertEqual(self.audit("docs", ["readme.md"])["status"], "ok")

    def test_ecosystem_files_are_audit_inputs(self):
        self.audit("go", ["go.mod"])
        pol = Policy(self.root)
        before = deps.audit_inputs(pol, "go")
        write(os.path.join(self.root, "go", "go.sum"), "y\n")
        self.assertNotEqual(before, deps.audit_inputs(pol, "go"))  # a new lockfile re-runs the audit

    def test_prompt_lists_not_covered(self):
        self.assertIn('with their `skipped` reasons, `not_covered` files (e.g. "Dart: not audited")',
                      read("prompts", "run.md"))


class TestGeneratedFolders(unittest.TestCase):
    """#18: build output and dependency checkouts (where a Flutter app's iOS build copies SDK example
    lockfiles) are never audited or matched, and the audit names the folders it left out."""

    def setUp(self):
        self.tmp = realtmp("occupai-gen-")
        self.root = os.path.join(self.tmp, "projects")
        for d in ("build/ios/SourcePackages/checkouts/sdk/example", "ios/SourcePackages/checkouts/sdk/example",
                  "ios/DerivedData/x", ".build/checkouts/y", "android/.gradle/z", "web"):
            write(os.path.join(self.root, "flut", d, "package-lock.json"), LOCK)
        self.pol = Policy(self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_only_the_real_lockfile_is_read(self):
        self.assertEqual([self.pol.rel(p) for p in deps.lockfiles_in(self.pol, "flut")], ["flut/web/package-lock.json"])

    def test_audit_names_the_skipped_folders(self):
        shutil.rmtree(os.path.join(self.root, "flut", "web"))  # no npm call needed
        r = deps.run_audit(self.pol, "flut")
        self.assertEqual(r["npm"], {})
        self.assertEqual(r["generated_skipped"], ["flut/.build", "flut/android/.gradle", "flut/build",
                                                  "flut/ios/DerivedData", "flut/ios/SourcePackages"])
        self.assertEqual(r["status"], "ok")  # skipped by design, not a gap

    def test_news_match_ignores_build_copies(self):
        shutil.rmtree(os.path.join(self.root, "flut", "web"))
        check = {"id": "x", "title": "x", "scope": "project",
                 "match": {"packages": [{"name": "left-pad", "affected": "<1.3.0"}]}}
        self.assertEqual(run_match(self.pol, ["flut"], [check])["x"]["projects"]["flut"]["status"], "not-affected")

    def test_prompt_names_them_under_not_checked(self):
        self.assertIn('one line naming `generated_skipped` folders (build output, never audited) to "Not checked"',
                      read("prompts", "run.md"))


if __name__ == "__main__":
    unittest.main()
