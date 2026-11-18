"""Round 6: Codex pre-release findings. Git drivers with any name, more private-key names, an explicit
config that doesn't exist, unknown match keys, per-manifest Python coverage, storage inside the kit
(fresh install with no ~/.occupai), an exclusive overlap guard and the range wording in the schema."""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE]

import fixture_setup  # noqa: E402
from test_p0_safety import Env, git_fixture, opened_paths, realtmp, snapshot  # noqa: E402
from test_round5 import copy_kit, read, write  # noqa: E402
from occupai_scan import config as cfgmod  # noqa: E402
from occupai_scan.deps import run_audit  # noqa: E402
from occupai_scan.match import run_match  # noqa: E402
from occupai_scan.safefs import Policy, is_sensitive  # noqa: E402


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-r6-")
        self.root = os.path.join(self.tmp, "projects")
        os.makedirs(self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.root, *parts)


# ====================================================================== 1. git drivers, any name

class TestGitDriverNames(Tmp):
    def test_driver_with_slash_in_name_never_runs(self):
        fixture_setup.build(self.root, seed=61)
        ws = self.p("web-shop")
        sentinel = os.path.join(self.tmp, "DRIVER-RAN")
        hook = os.path.join(self.tmp, "hook.sh")
        write(hook, f"#!/bin/sh\necho ran >> '{sentinel}'\ncat\n")
        os.chmod(hook, 0o755)
        write(os.path.join(ws, "NOTES.md"), "aa\n")
        write(os.path.join(ws, ".gitattributes"), "*.md filter=evil/name diff=evil/name\n")
        git_fixture(ws, "add", ".gitattributes", "NOTES.md")
        git_fixture(ws, "commit", "-q", "-m", "attrs")
        genv = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull}
        for k in ("filter.evil/name.clean", "filter.evil/name.process", "diff.evil/name.textconv"):
            subprocess.run(["git", "config", k, hook], cwd=ws, check=True, env=genv)
        write(os.path.join(ws, "NOTES.md"), "bb\n")  # dirty and racily clean: git re-hashes it via the filter
        st = os.stat(os.path.join(ws, ".git", "index"))
        os.utime(os.path.join(ws, "NOTES.md"), ns=(st.st_atime_ns, st.st_mtime_ns))
        before = snapshot(self.root)
        e = Env(self.tmp)
        state = os.path.join(self.tmp, "storage", "state.json")
        e.json("changed", "--state", state, "--root", self.root)
        e.json("hygiene", "--all", "--state", state, "--root", self.root)
        self.assertFalse(os.path.exists(sentinel), "a repository-defined driver with '/' in its name ran")
        self.assertEqual(snapshot(self.root), before)
        subprocess.run(["git", "status", "--porcelain"], cwd=ws, capture_output=True, stdin=subprocess.DEVNULL,
                       timeout=30, env=genv)
        self.assertTrue(os.path.exists(sentinel), "control failed: the planted driver never runs")


# ====================================================================== 2. private-key names

NEW_SENSITIVE = ("putty.ppk", "id_ecdsa", "id_ecdsa.pub", "id_dsa", "AuthKey_ABC123.p8", "client.ovpn",
                 ".netrc", "_netrc", ".git-credentials")


class TestMoreSensitiveNames(Tmp):
    def test_names_are_sensitive(self):
        for n in NEW_SENSITIVE:
            self.assertTrue(is_sensitive(n), n)
        for n in ("notes.asc", "README.md", "ppk-notes.txt"):
            self.assertFalse(is_sensitive(n), n)

    def test_never_opened_and_listed_in_the_rules(self):
        fixture_setup.build(self.root, seed=62)
        keys = self.p("cred-proj", "keys")
        for n in NEW_SENSITIVE:
            write(os.path.join(keys, n), "not a real key\n")
        trace = os.path.join(self.tmp, "open.log")
        e = Env(self.tmp)
        state = os.path.join(self.tmp, "storage", "state.json")
        e.json("hygiene", "--all", "--state", state, "--root", self.root, trace=trace)
        e.json("match", "--checks", os.path.join(REPO, "examples", "demo", "library", "checks.json"),
               "--root", self.root, trace=trace)
        opened = opened_paths(trace)
        self.assertIn(self.p("web-shop", "package.json"), opened)  # the hook does see reads
        for n in NEW_SENSITIVE:
            self.assertNotIn(os.path.join(keys, n), opened, n)
        for f in ("AGENTS.md", os.path.join("prompts", "howto.md")):
            for g in ("*.ppk", "id_ecdsa*", "id_dsa*"):
                self.assertIn(f"`{g}`", read(f), f)


# ====================================================================== 3. explicit config

class TestExplicitConfig(Tmp):
    def test_missing_explicit_config_never_falls_back(self):
        home = os.path.join(self.tmp, "home")
        write(os.path.join(home, ".occupai", "occupai.config.yaml"), f"projects_root: {self.root}\n")
        e = Env(self.tmp)
        r = e.run("projects", "--config", os.path.join(self.tmp, "nope.yaml"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("config not found", r.stdout + r.stderr)
        e.env["OCCUPAI_CONFIG"] = os.path.join(self.tmp, "nope-env.yaml")
        r = e.run("projects")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("config not found", r.stdout + r.stderr)


# ====================================================================== 4. unknown match keys

class TestUnknownMatchKeys(Tmp):
    def test_unknown_key_or_no_rule_is_unknown(self):
        write(self.p("app", "package.json"), json.dumps({"name": "a"}))
        checks = [{"id": "typo", "scope": "project", "match": {"package": [{"name": "next", "affected": "<1.0.0"}]}},
                  {"id": "gittypo", "scope": "project", "match": {"git": {"branch": ["evil"]}}},
                  {"id": "empty", "scope": "project", "match": {}},
                  {"id": "nomatch", "scope": "project"},
                  {"id": "emptylist", "scope": "project", "match": {"packages": []}},
                  {"id": "agent-only", "scope": "project+machine", "match": {"machine": "node -v"}},
                  {"id": "ok", "scope": "project", "match": {"files": [{"glob": "nothing-*.txt"}]}}]
        m = run_match(Policy(self.root), ["app"], checks)
        for cid in ("typo", "gittypo", "empty", "nomatch", "emptylist", "agent-only"):
            with self.subTest(check=cid):
                self.assertEqual(m[cid]["projects"]["app"]["status"], "unknown")
                self.assertFalse(m[cid]["complete"])
                self.assertTrue(m[cid]["projects"]["app"]["skipped"][0]["reason"])
        self.assertEqual(m["typo"]["projects"]["app"]["skipped"][0], {"file": "rule:package", "reason": "unsupported-rule"})
        self.assertEqual(m["ok"]["projects"]["app"]["status"], "not-affected")


# ====================================================================== 5. per-manifest Python coverage

class TestPythonCoveragePerManifest(Tmp):
    def test_other_folders_requirements_dont_cover_a_manifest(self):
        write(self.p("mono", "app", "pyproject.toml"), "[project]\nname = \"x\"\ndependencies = [\"requests\"]\n")
        write(self.p("mono", "tools", "requirements.txt"), "occupai-demo-py==1.0\n")
        write(self.p("ok", "pyproject.toml"), "[project]\nname = \"y\"\n")
        write(self.p("ok", "requirements.txt"), "occupai-demo-py==1.0\n")
        check = {"id": "py", "scope": "project",
                 "match": {"packages": [{"name": "requests", "ecosystem": "pypi", "affected": "<2.0.0"}]}}
        m = run_match(Policy(self.root), ["mono", "ok"], [check])["py"]["projects"]
        self.assertEqual(m["mono"]["status"], "unknown")
        self.assertIn({"file": "mono/app/pyproject.toml", "reason": "unsupported-python-manifest"}, m["mono"]["skipped"])
        self.assertEqual(m["ok"]["status"], "not-affected")
        r = run_audit(Policy(self.root), "mono", opener=lambda req, timeout=None: (_ for _ in ()).throw(OSError()))
        self.assertIn("mono/app/pyproject.toml: no-requirements-file", r["not_covered"])
        self.assertNotEqual(r["status"], "ok")


# ====================================================================== 6. storage inside the kit

class TestFreshInstallStorageInKit(unittest.TestCase):
    """A truly fresh install: no ~/.occupai, the kit in ~/Downloads. Setup must need no extra folder."""

    def setUp(self):
        self.tmp = realtmp("occupai-r6-kit-")
        self.home = os.path.join(self.tmp, "home")
        self.projects = os.path.join(self.home, "Desktop")
        fixture_setup.build(self.projects, seed=63)
        self.kit = os.path.join(self.home, "Downloads", "occupai-main")
        copy_kit(self.kit)
        self.env = {**os.environ, "HOME": self.home, "OCCUPAI_CONFIG": "", "PYTHONPATH": ""}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sh(self, cmd, cwd=None):
        r = subprocess.run(["/bin/sh", "-c", cmd], env=self.env, capture_output=True, text=True, cwd=cwd or self.home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout

    def setup_block(self):
        setup = read("SETUP.md")
        return next(b for b in re.findall(r"```\n(.*?)```", setup, re.S) if "mkdir -p KIT/data" in b)

    def run_setup(self):
        self.sh(self.setup_block().replace("KIT/", self.kit + "/"))
        cfg = os.path.join(self.kit, "data", "occupai.config.yaml")
        y = read(cfg).replace("kit_path: ~/code/occupai", "kit_path: ~/Downloads/occupai-main")
        write(cfg, y.replace("projects_root: ~/projects", "projects_root: ~/Desktop"))
        return cfg

    def test_setup_needs_no_storage_folder_access(self):
        setup = read("SETUP.md")
        self.assertNotIn("~/.occupai`, in one request", setup)
        self.assertNotIn("(⌘⇧. shows .occupai)", setup)
        cfg = self.run_setup()
        data = os.path.join(self.kit, "data")
        self.assertTrue(os.path.exists(os.path.join(data, ".occupai-ignore")))
        for f in ("actioned.md", "library/checks.json", "library/baseline.md", "library/changelog.md"):
            self.assertTrue(os.path.exists(os.path.join(data, f)), f)
        cmd = re.search(r"`(python3 KIT/scan\.py discover --config [^`]+)`", setup).group(1)
        self.assertEqual(cmd, "python3 KIT/scan.py discover --config KIT/data/occupai.config.yaml")
        self.sh(cmd.replace("KIT/", self.kit + "/"))
        # the task runs the script with no --config and from any folder: it finds KIT/data itself
        scan = os.path.join(self.kit, "scan.py")
        self.sh(f"python3 '{scan}' marker start")
        self.assertTrue(os.path.exists(os.path.join(data, "state", "briefing-running")))
        with open(os.path.join(data, "actioned.md"), "a", encoding="utf-8") as f:
            f.write("| demo-1 | Demo item | 2026-11-18 | open | 2026-11-18 | |\n")
        self.sh(f"python3 '{scan}' tracker mark demo-1 done --note 'fixed'")
        self.assertIn("demo-1", read(os.path.join(data, "actioned.md")))
        out = os.path.join(data, "state", "hy.json")
        self.sh(f"python3 '{scan}' hygiene --all --out '{out}'")
        self.assertFalse(os.path.exists(os.path.join(self.home, ".occupai")), "setup or a run created ~/.occupai")
        self.assertEqual(cfgmod.storage_path(cfgmod.load(cfg)), os.path.realpath(data))
        # the task prompt names KIT/data, never ~/.occupai
        task = next(b for b in re.findall(r"```\n(.*?)```", setup, re.S) if "Run OccupAI" in b)
        self.assertNotIn(".occupai", task)
        self.assertIn("STORAGE = KIT/data", task)
        self.assertIn("data/", read(".gitignore").splitlines())

    def test_kit_inside_projects_folder_never_scans_its_data(self):
        kit = os.path.join(self.projects, "occupai")
        copy_kit(kit)
        self.sh(self.setup_block().replace("KIT/", kit + "/"))
        write(os.path.join(kit, "data", "library", "leak.ts"), "const k = 'AKIA" + "Q" * 16 + "'\n")
        cfg = os.path.join(kit, "data", "occupai.config.yaml")
        write(cfg, read(cfg).replace("projects_root: ~/projects", "projects_root: ~/Desktop")
              .replace('  - "occupai"', '  - "nothing-here"'))  # not excluded by name: the marker must do it
        hy = json.loads(self.sh(f"python3 '{kit}/scan.py' hygiene --all --out '{kit}/data/state/hy.json'"))
        self.assertNotEqual(hy.get("status"), "error", hy)
        self.assertNotIn("leak.ts", read(os.path.join(kit, "data", "state", "hy.json")))

    def test_existing_dot_occupai_still_wins(self):
        old = os.path.join(self.home, ".occupai")
        write(os.path.join(old, "occupai.config.yaml"), "projects_root: ~/Desktop\n")
        self.run_setup()
        self.sh(f"python3 '{self.kit}/scan.py' marker start")
        self.assertTrue(os.path.exists(os.path.join(old, "state", "briefing-running")))
        self.assertFalse(os.path.exists(os.path.join(self.kit, "data", "state", "briefing-running")))
        self.assertIn("If `~/.occupai/occupai.config.yaml` exists", read("SETUP.md"))

    def test_update_note(self):
        s = read("SETUP.md")
        self.assertIn("git pull", s)
        self.assertIn("copy `data/` across", s)


# ====================================================================== 7, 8. overlap guard, schema

class TestOverlapAndSchema(unittest.TestCase):
    def test_overlap_guard_is_exclusive(self):
        run = read("prompts", "run.md")
        guard = next(ln for ln in run.splitlines() if "**Overlap guard:**" in ln)
        self.assertNotIn("then continue", guard)
        self.assertIn("write nothing and end with", guard)
        self.assertIn("The briefing is still running. Reply **try again** in a few minutes.", guard)

    def test_schema_describes_only_supported_ranges(self):
        with open(os.path.join(REPO, "schema", "checks.schema.json")) as f:
            s = json.load(f)
        m = s["properties"]["checks"]["items"]["properties"]["match"]
        d = m["properties"]["packages"]["items"]["properties"]["affected"]["description"]
        for bad in ("x-ranges", "^", "~", "hyphen"):
            self.assertNotIn(bad, d.split("unsupported")[0].split("Anything else")[0])
        self.assertIn("||", d)
        self.assertNotIn("Free-text keys are allowed", m["description"])


if __name__ == "__main__":
    unittest.main()
