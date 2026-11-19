"""Fix round 3 (fresh install test, 2026-11-18): two outputs (shareable news brief, private project report),
setup fixes, chat-created tasks that see folders at $HOME/mnt/<folder>, npm's CA bundle, the user's OS from
the config, and sub-folder decisions for the dependency audit. Offline, fixtures only."""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE, os.path.join(HERE, "helpers")]

import fixture_setup  # noqa: E402
from test_p0_safety import Env, realtmp  # noqa: E402
from occupai_scan import cli, deps  # noqa: E402
from occupai_scan import config as cfgmod  # noqa: E402


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class TestDeviceShellMounts(unittest.TestCase):
    """A task created from a chat sees the attached folders at $HOME/mnt/<folder name>; the config written
    at setup still says ~/Desktop and ~/.occupai. The script maps them and finds the config there."""

    def setUp(self):
        self.tmp = realtmp("occupai-r3-mnt-")
        self.e = Env(self.tmp)
        mnt = os.path.join(self.e.home, "mnt")
        self.root = os.path.join(mnt, "Desktop")
        fixture_setup.build(self.root, seed=83)
        write(os.path.join(mnt, ".occupai", "occupai.config.yaml"),
              "version: 1\nprojects_root: ~/Desktop\nstorage:\n  path: ~/.occupai\ncomputer: macOS\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_paths_map_to_the_mounts(self):
        out = self.e.json("changed")  # no --config: found at $HOME/mnt/.occupai
        self.assertIn("web-shop", out["new"])
        self.assertEqual(out["computer"], "macOS")
        st = os.path.join(self.e.home, "mnt", ".occupai", "state")
        os.makedirs(st)
        self.e.json("hygiene", "--only", "web-shop", "--out", os.path.join(st, "h.json"))
        self.assertTrue(os.path.isfile(os.path.join(st, "h.json")))
        self.assertFalse(os.path.exists(os.path.join(self.e.home, ".occupai")))

    def test_mounted_only_when_the_path_is_missing(self):
        with mock.patch.dict(os.environ, {"HOME": self.e.home}):
            real = os.path.join(self.e.home, "Desktop")
            self.assertEqual(cfgmod.mounted("~/Desktop/web-shop"), os.path.join(self.root, "web-shop"))
            self.assertEqual(cfgmod.mounted("/nowhere/else"), "/nowhere/else")
            self.assertEqual(cfgmod.mounted("~/Desktop/missing"), os.path.join(real, "missing"))
            os.makedirs(real)  # a real folder always wins over a mount
            self.assertEqual(cfgmod.mounted("~/Desktop"), real)


class TestComputerFromConfig(unittest.TestCase):
    def test_config_wins_over_the_sandbox(self):
        tmp = realtmp("occupai-r3-os-")
        try:
            os.makedirs(os.path.join(tmp, "projects", "a"))
            cfg = os.path.join(tmp, "storage", "occupai.config.yaml")
            for value, want in (("windows", "Windows"), ("Linux", "Linux"), ("Amiga", None), ("", None)):
                write(cfg, f"projects_root: {tmp}/projects\nstorage:\n  path: {tmp}/storage\ncomputer: \"{value}\"\n")
                got = Env(tmp).json("changed", "--config", cfg)["computer"]
                self.assertEqual(got, want or {"Darwin": "macOS"}.get(os.uname().sysname, os.uname().sysname))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestNpmCertificates(unittest.TestCase):
    def test_ca_bundle_passed_and_tls_never_off(self):
        tmp = realtmp("occupai-r3-ca-")
        try:
            bundle = os.path.join(tmp, "corp-ca.pem")
            write(bundle, "not a real certificate\n")
            clear = {k: "" for k in deps.CA_ENV}
            with mock.patch.dict(os.environ, {**clear, "SSL_CERT_FILE": bundle}), deps.Scratch() as s:
                env = s.env()
            self.assertEqual(env["NODE_EXTRA_CA_CERTS"], bundle)
            self.assertEqual(env["npm_config_strict_ssl"], "true")
            with mock.patch.dict(os.environ, clear), mock.patch.object(deps, "CA_FILES", ()), deps.Scratch() as s:
                env = s.env()
            self.assertFalse(env.get("NODE_EXTRA_CA_CERTS"))
            self.assertEqual(env["npm_config_strict_ssl"], "true")
            src = read("occupai_scan", "deps.py")
            self.assertNotRegex(src, r"strict.ssl\W+false|NODE_TLS_REJECT_UNAUTHORIZED")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSubFolderDecisions(unittest.TestCase):
    def vuln(self, *names):
        return {"status": "ok", "vulns": {n: {"severity": "high", "advisories": [f"GHSA-{n}"]} for n in names}}

    def test_split_and_mostly_in(self):
        r = {"status": "ok", "npm": {"app/package-lock.json": self.vuln("a"),
                                     "app/demos/x/package-lock.json": self.vuln("b", "c"),
                                     "app/demos/y/package-lock.json": self.vuln("d")},
             "pypi": {}, "not_covered": ["app/demos/z/yarn.lock"], "skipped": []}
        self.assertEqual(cli.mostly_in(r, "app"), "app/demos")
        view, quiet = cli.split_subs(r, "app", {"app/demos": "inactive"})
        self.assertEqual(list(view["npm"]), ["app/package-lock.json"])
        self.assertEqual(view["not_covered"], [])
        self.assertEqual(quiet, {"app/demos": 3})
        self.assertIsNone(cli.mostly_in(view, "app"))
        self.assertIs(cli.split_subs(r, "other", {"app/demos": "inactive"})[0], r)

    def test_project_command_accepts_a_real_sub_folder(self):
        tmp = realtmp("occupai-r3-sub-")
        try:
            root = os.path.join(tmp, "projects")
            fixture_setup.build(root, seed=89)
            os.makedirs(os.path.join(root, "web-shop", "demos"))
            cfg = os.path.join(tmp, "storage", "occupai.config.yaml")
            write(cfg, f"projects_root: {root}\nstorage:\n  path: {tmp}/storage\n")
            e = Env(tmp)
            asked = e.run("project", "web-shop/demos", "inactive", "--config", cfg)
            self.assertEqual(json.loads(asked.stdout)["ask"], "Is web-shop/demos still deployed anywhere?")
            saved = e.json("project", "web-shop/demos", "inactive", "--not-deployed", "--config", cfg)
            self.assertEqual(saved["project"], "web-shop/demos")
            for bad in (("web-shop/../ci-demo", "inactive", "--not-deployed"), ("web-shop/nope", "managed"),
                        ("web-shop/demos", "skip")):
                self.assertNotEqual(e.run("project", *bad, "--config", cfg).returncode, 0, bad)
            path = os.path.join(tmp, "storage", "library", "project-status.json")
            self.assertEqual(cli.sub_statuses(path, ["web-shop"]), {"web-shop/demos": "inactive"})
            self.assertEqual(cli.project_statuses(path, ["web-shop"]), {})  # the project itself stays active
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestDiscoverNamesOwners(unittest.TestCase):
    def test_owner_per_project(self):
        tmp = realtmp("occupai-r3-own-")
        try:
            root = os.path.join(tmp, "projects")
            fixture_setup.build(root, seed=97)
            d = Env(tmp).json("discover", "--root", root)
            owners = {w["project"]: w.get("owner") for w in d["watch"]}
            self.assertEqual(owners["forked-tool"], "someone-else")
            self.assertEqual(sum(d["github_owners"].values()), sum(1 for o in owners.values() if o))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestTwoOutputs(unittest.TestCase):
    def test_prompt(self):
        run = read("prompts", "run.md")
        for part in ("`STORAGE/briefings/YYYY-MM-DD-news.md`", "never project names, paths, owners or findings",
                     "`STORAGE/briefings/YYYY-MM-DD-projects.md`** (private)", "`news_scorecard`",
                     "N of your projects may be affected — see your project report.",
                     "- [ ] [ID] <project>: action — why.", "(NEW) / (REOPENED) / (still open since YYYY-MM-DD)",
                     "top 3 fixes", "`mostly_in`", "say '<project>/<folder> is inactive' to quiet it",
                     "Is <project> still active or deployed? Say '<project> is inactive' to quiet it.",
                     "scan: the Result line), up to 3 one-line actions or items, and the two file names."):
            self.assertIn(part, run)
        for marker in ("🔴 CRITICAL", "🟠 HIGH", "🟡 MEDIUM", "⚪ LOW"):
            self.assertIn(marker, run)
        self.assertTrue(cfgmod.load(os.path.join(REPO, "occupai.config.example.yaml"))["news_scorecard"])

    def test_demo_news_brief_names_no_project(self):
        tmp = realtmp("occupai-r3-demo-")
        try:
            r = subprocess.run([sys.executable, os.path.join(REPO, "examples", "demo", "run_demo.py"), "--out", tmp],
                               capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            today = datetime.date.today().isoformat()
            b = os.path.join(tmp, "storage", "briefings")
            self.assertEqual(sorted(os.listdir(b)), [f"{today}-news.md", f"{today}-projects.md"])
            news = read(b, f"{today}-news.md")
            for unit in os.listdir(os.path.join(tmp, "projects")):
                self.assertNotRegex(news, rf"\b{re.escape(unit)}\b", unit)
            self.assertNotIn(tmp, news)
            self.assertIn("may be affected — see your project report", news)
            projects = read(b, f"{today}-projects.md")
            self.assertLess(projects.index("## To do"), projects.index("## Appendix"))
            self.assertIn("still open", projects)  # the Result line keeps the count
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSetupRound3(unittest.TestCase):
    def setUp(self):
        self.s = read("SETUP.md")

    def test_questions(self):
        for part in ('"~/Desktop (Recommended)"', '"Show me the folders and I\'ll pick"', '"Let\'s talk it through"',
                     "`~/worktrees`", '"pick a time your computer is usually on"',
                     '"a client or employer org: watch it, but as someone else\'s (info)"',
                     "scan.py project <name> managed",
                     "New folders in <projects folder> are watched automatically until you tell me to skip them."):
            self.assertIn(part, self.s)
        self.assertNotIn("~/code", self.s)

    def test_folder_access(self):
        s = self.s
        self.assertIn("Stay on this chat for a moment: a pop-up will appear for each folder. Tick 'Don't ask again' and click Allow.", s)
        self.assertIn("This often happens if you switched away. Reply **ask again**", s)
        self.assertIn("suggest close matches for typos", s)
        order = [s.index(x) for x in ("Reply **ask again**", "+ → Add folder", "run setup from Claude Code")]
        self.assertEqual(order, sorted(order))
        self.assertLess(s.index("click Allow"), s.index("mkdir -p KIT/data"))

    def test_task_from_the_chat_with_folders_attached(self):
        s = self.s
        self.assertIn("Create **two** local scheduled tasks yourself, from this chat", s)
        self.assertIn("Attach exactly the folders approved in step 3: `projects_root`, plus KIT if outside it.", s)
        block = next(b for b in re.findall(r"```\n(.*?)```", s, re.S) if "Run OccupAI" in b)
        self.assertIn("$HOME/mnt/<folder name>", block)
        self.assertLess(s.index("one message to paste"), s.index("Last resort: Claude Code"))
        self.assertIn("`computer` (macOS, Windows or Linux", s)
        self.assertIn("$HOME/mnt/<folder name>", read("prompts", "howto.md"))


class TestTwoTasks(unittest.TestCase):
    """Round 3b: back to two automations. The briefing does the news, the library and a quick match;
    the scan does the projects and writes the one action list."""

    def test_modes(self):
        run = read("prompts", "run.md")
        for part in ("- **briefing** (daily): steps 1, 2 with the quick match, 4, and the news brief.",
                     '- **scan** (daily, after the briefing; also "scan now"): steps 1, 3, 4, and the project report.',
                     "`SCAN match --ids <today's new and updated check IDs>",
                     "Matches become tracker actions (step 4), never a second action list.",
                     'Only if `news_scorecard` is on (default): affected items end with "→ see your to-do list"',
                     "including the briefing's quick-match rows in the tracker",
                     '"N new items; X may affect your projects → see your to-do list (DATE-projects.md)"'):
            self.assertIn(part, run)
        news = run[run.index("YYYY-MM-DD-news.md`**"):run.index("YYYY-MM-DD-projects.md`**")]
        self.assertNotIn("- [ ]", news)  # only the project report has checkboxes
        every = next(b for b in re.findall(r"```\n(.*?)```", run, re.S) if "SCAN changed" in b)
        self.assertIn("SCAN hygiene --resume", every)  # daily scans check new and changed projects
        self.assertNotIn("SCAN audit", every)

    def test_setup_creates_both_tasks(self):
        s = read("SETUP.md")
        for part in ('"OccupAI briefing" daily at `schedule.briefing` (Mode: briefing)', '"OccupAI scan" 20 minutes later (Mode: scan)',
                     "`schedule.scan` (20 minutes later)", "Uninstall: delete both tasks"):
            self.assertIn(part, s)
        block = next(b for b in re.findall(r"```\n(.*?)```", s, re.S) if "Run OccupAI" in b)
        self.assertIn("Mode: <briefing|scan>", block)
        cfg = cfgmod.load(os.path.join(REPO, "occupai.config.example.yaml"))
        self.assertEqual(cfg["schedule"], {"briefing": "52 7 * * *", "scan": "12 8 * * *", "full_day": "monday"})


if __name__ == "__main__":
    unittest.main()
