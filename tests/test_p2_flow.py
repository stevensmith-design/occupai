"""P2 acceptance tests: the install path, the multi-day flow, and the live-system rules the prompts carry.

Offline: fixture copies in a temp folder, fake npm on PATH, no web access. An agent normally follows the
prompts; here the deterministic parts run for real (the scan script, the tracker rules) and a small
stand-in applies the prompt rules, as in `make demo`.
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
sys.path[:0] = [REPO, HERE, os.path.join(HERE, "helpers"), os.path.join(REPO, "examples", "demo")]

import fixture_setup  # noqa: E402
import run_demo  # noqa: E402
from test_p0_safety import Env, git_fixture, realtmp  # noqa: E402
from test_round5 import copy_kit  # noqa: E402
from occupai_scan import config as cfgmod  # noqa: E402
from occupai_scan import tracker as trk  # noqa: E402

DEMO_CHECKS = os.path.join(REPO, "examples", "demo", "library", "checks.json")
# Total agent-facing words: round 3 total (4599) plus ~150 for the second task (round 3b) plus ~120 for round 4's
# release fixes (folder-access wording, folder list, no helper task, news summary, accuracy line) plus ~110 for
# round 5 (kit access, overlap guard, scorecard switch) plus ~65 for round 7's two final-message templates
# (raised from 4985 rather than cut real rules), then 5100 for the scan message's "Scanned:" line and
# "Needs you" group (2026-11-23, after cutting the repeats that could go); SETUP.md under 950.
WORD_BUDGET = 5100
SETUP_BUDGET = 950
AGENT_FILES = [os.path.join("prompts", "run.md"), os.path.join("prompts", "howto.md"), "SETUP.md"]


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if isinstance(text, str) else json.dumps(text))


def code_blocks(text):
    return re.findall(r"```\n(.*?)```", text, re.S)


def set_key(yaml_text, key, value):
    """Replace a top-level `key: ...` line (and an indented list under it) with `key: value`."""
    lines, out, skip = yaml_text.splitlines(), [], False
    for ln in lines:
        if skip and (ln.startswith("  ") or not ln.strip()):
            continue
        skip = False
        if re.match(rf"^{re.escape(key)}:", ln):
            out.append(f"{key}: {value}")
            skip = not ln.split(":", 1)[1].split("#")[0].strip()
            continue
        out.append(ln)
    return "\n".join(out) + "\n"


# ====================================================================== install (SETUP.md)

class TestSetupFlow(unittest.TestCase):
    """A fresh user with unrelated fictional settings follows SETUP.md and ends with a valid config and
    a first report, with no personal defaults anywhere."""

    def test_fresh_setup_on_fictional_settings(self):
        tmp = realtmp("occupai-p2setup-")
        try:
            home = os.path.join(tmp, "home")
            os.makedirs(home)
            projects = os.path.join(home, "Werkstatt")  # fictional answer 1
            fixture_setup.build(projects, seed=61)
            setup = read(os.path.join(REPO, "SETUP.md"))
            self.assertLess(len(setup.split()), SETUP_BUDGET)
            # step 1: the Python check SETUP.md gives
            check = re.search(r"`(python3 -c [^`]+)`", setup).group(1)
            self.assertEqual(subprocess.run(check, shell=True, capture_output=True, text=True).stdout.strip(), "True")
            # step 3: run its shell block as written, with KIT filled in
            kit = os.path.join(home, "Downloads", "occupai")  # a downloaded copy: setup writes into KIT/data
            copy_kit(kit)
            block = next(b for b in code_blocks(setup) if "mkdir -p KIT/data" in b)
            env = {**os.environ, "HOME": home, "OCCUPAI_CONFIG": ""}
            r = subprocess.run(["/bin/sh", "-c", block.replace("KIT/", kit + "/")], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            storage = os.path.join(kit, "data")
            cfg_path = os.path.join(storage, "occupai.config.yaml")
            # running it again never overwrites the user's tracker
            write(os.path.join(storage, "actioned.md"), read(os.path.join(storage, "actioned.md")) + "<!-- mine -->\n")
            subprocess.run(["/bin/sh", "-c", block.replace("KIT/", kit + "/")], env=env, capture_output=True)
            self.assertIn("<!-- mine -->", read(os.path.join(storage, "actioned.md")))
            # step 4: only the keys SETUP.md names, with fictional answers
            y = read(cfg_path)
            for k, v in (("kit_path", kit), ("projects_root", "~/Werkstatt"), ("my_owners", "[example-owner]"),
                         ("timezone", "Pacific/Chatham")):
                y = set_key(y, k, v)
            y = y.replace('briefing: "52 7 * * *"', 'briefing: "10 7 * * *"').replace("push: true", "push: false")
            write(cfg_path, y)
            cfg = cfgmod.load(cfg_path)
            self.assertEqual((cfg["projects_root"], cfg["my_owners"], cfg["timezone"], cfg["notifications"]["push"]),
                             ("~/Werkstatt", ["example-owner"], "Pacific/Chatham", False))
            # re-running setup keeps an existing config: the block never overwrites it, and step 4 then
            # changes only the keys the new answers change (here the timezone)
            write(cfg_path, read(cfg_path) + "# my own note\n")
            mine = read(cfg_path)
            r = subprocess.run(["/bin/sh", "-c", block.replace("KIT/", kit + "/")], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(read(cfg_path), mine)
            write(cfg_path, set_key(mine, "timezone", "Atlantic/Reykjavik"))
            again = cfgmod.load(cfg_path)
            self.assertIn("# my own note", read(cfg_path))
            self.assertEqual((again["projects_root"], again["my_owners"], again["timezone"], again["notifications"]["push"]),
                             ("~/Werkstatt", ["example-owner"], "Atlantic/Reykjavik", False))
            self.assertEqual(again["schedule"], cfg["schedule"])
            # step 5: the discovery command SETUP.md gives lists what it will watch before the first scan;
            # a folder that looks like a copy starts unticked, and unticking it means adding it to exclusions
            os.makedirs(os.path.join(projects, "web-shop backup"))
            write(os.path.join(projects, "web-shop backup", "package-lock.json"), "{}\n")
            cmd = re.search(r"`(python3 KIT/scan\.py discover --config [^`]+)`", setup).group(1)

            def discover():
                r = subprocess.run(["/bin/sh", "-c", cmd.replace("KIT/", kit + "/")], env=env, capture_output=True,
                                   text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                return json.loads(r.stdout)
            d = discover()
            watch = {w["project"]: w["watch"] for w in d["watch"]}
            self.assertTrue(watch["web-shop"])
            self.assertFalse(watch["web-shop backup"])
            self.assertIn("Next.js", [t["tech"] for t in d["scanning_for"]])
            self.assertIn("example-owner", d["github_owners"])
            y = read(cfg_path).replace("exclusions:\n", 'exclusions:\n  - "web-shop backup"\n', 1)
            write(cfg_path, y)
            self.assertNotIn("web-shop backup", [w["project"] for w in discover()["watch"]])
            # step 5: the first run, using the commands in prompts/run.md, then its one report
            os.environ["HOME"], old_home = home, os.environ.get("HOME")
            try:
                today = datetime.date.today().isoformat()
                result, _ = run_demo.local_scan(storage, cfg_path, today, [])
            finally:
                os.environ["HOME"] = old_home
            report = os.path.join(storage, "briefings", f"{today}-projects.md")
            self.assertTrue(os.path.isfile(report))
            self.assertIn("Result:", read(report))
            self.assertTrue(os.path.isfile(os.path.join(storage, "state", "scan-state.json")))
            # no personal defaults: nothing points at the author's machine or layout
            for f in (cfg_path, os.path.join(REPO, "occupai.config.example.yaml"), os.path.join(REPO, "SETUP.md")):
                text = read(f).replace(kit, "KIT").replace(REPO, "KIT")  # kit_path legitimately points at the kit
                for bad in ("/Users/", "/home/"):
                    self.assertNotIn(bad, text, f"{os.path.basename(f)} has a personal path")
            example = cfgmod.load(os.path.join(REPO, "occupai.config.example.yaml"))
            self.assertEqual((example["timezone"], example["projects_root"]), ("UTC", "~/projects"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_scan_prompt_commands_run_as_written(self):
        """Both command blocks in prompts/run.md (every run, full runs) work against a config, offline."""
        tmp = realtmp("occupai-p2cmds-")
        try:
            root, st = os.path.join(tmp, "projects"), os.path.join(tmp, "storage", "state")
            fixture_setup.build(root, seed=67)
            os.makedirs(st)
            cfg = os.path.join(tmp, "storage", "occupai.config.yaml")
            write(cfg, f"version: 1\nprojects_root: {root}\nstorage:\n  path: {os.path.dirname(st)}\n")
            write(os.path.join(os.path.dirname(st), "library", "checks.json"), read(DEMO_CHECKS))
            e = Env(tmp)
            blocks = [b for b in code_blocks(read(os.path.join(REPO, "prompts", "run.md"))) if "SCAN " in b]
            self.assertEqual(len(blocks), 2)
            for line in "\n".join(blocks).splitlines():
                line = line.split("  #")[0].strip()
                if not line.startswith("SCAN ") or "<" in line:
                    continue
                args = line.replace("$ST", st).split()[1:]
                for _ in range(40):  # repeat while it prints "partial", as the prompt says
                    out = e.json(*args, "--config", cfg)
                    if out.get("status") != "partial":
                        break
            saved = e.json("save-state", "--hygiene", os.path.join(st, "hygiene-out.json"), "--config", cfg)
            self.assertEqual(saved["projects"], 13)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ====================================================================== the multi-day flow

class TestLifecycle(unittest.TestCase):
    """briefing -> scan -> audit -> tracker/library over several days, with the rules the prompts state."""

    def setUp(self):
        self.tmp = realtmp("occupai-p2flow-")
        self.root = os.path.join(self.tmp, "projects")
        fixture_setup.build(self.root, seed=71)
        self.storage = os.path.join(self.tmp, "storage")
        self.state = os.path.join(self.storage, "state", "scan-state.json")
        os.makedirs(os.path.dirname(self.state))
        lib = json.loads(read(DEMO_CHECKS))
        lib["checks"].append({"id": "demo-cli-tool", "title": "Fictional CLI tool flaw (also on your machine)",
                              "scope": "project+machine", "severity": "high",
                              "match": {"packages": [{"name": "occupai-demo-cli", "affected": "<2.0.0"}],
                                        "machine": "occupai-demo-cli --version"}})
        self.checks = os.path.join(self.storage, "library", "checks.json")
        write(self.checks, lib)
        self.items = {c["id"]: c["title"] for c in lib["checks"]}
        self.tracker = os.path.join(self.storage, "actioned.md")
        shutil.copy(os.path.join(REPO, "templates", "actioned.md"), self.tracker)
        self.e = Env(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_(self, *args, e=None):
        return (e or self.e).json(*args, "--root", self.root)

    def rows(self):
        return {r["ID"]: r for r in trk.load(self.tracker)[1]}

    def briefing(self, day, changes=None):
        """The briefing's tracker step: dedupe by ID, reopen only on material change."""
        before, rows, after = trk.load(self.tracker)
        trk.wake_snoozed(rows, day)
        done = {i: trk.upsert(rows, i, t, day, (changes or {}).get(i)) for i, t in self.items.items()}
        trk.save(self.tracker, before, rows, after)
        still_open = sorted(r["ID"] for r in rows if r["Status"] in ("open", "REOPENED"))
        quiet = not any(done.values())
        return done, still_open, quiet

    def scan(self, day, only=None):
        """The scan's tracker step: replay checks, close only with complete evidence and nothing manual."""
        extra = ["--only", only] if only else []
        m = self.run_("match", "--checks", self.checks, *extra)
        before, rows, after = trk.load(self.tracker)
        updates = []
        for cid, res in m.items():
            scope = next(c["scope"] for c in json.loads(read(self.checks))["checks"] if c["id"] == cid)
            if res["affected"]:
                change = f"new project {', '.join(res['affected'])}" if only else None
                if change and trk.upsert(rows, cid, self.items[cid], day, change) == "reopened":
                    updates.append((cid, "REOPENED"))
            elif not only:
                manual = "machine" in scope or "account" in scope
                if trk.auto_close(rows, cid, "not-affected", day, f"no match in {res['checked']} projects",
                                  complete=res["complete"], manual=manual):
                    updates.append((cid, "not-affected"))
        trk.save(self.tracker, before, rows, after)
        return m, updates

    def test_days(self):
        # ---- day 1: first briefing, first scan, first audit
        done, still_open, quiet = self.briefing("2026-11-16")
        self.assertEqual(set(done.values()), {"new"})
        m, updates = self.scan("2026-11-16")
        rows = self.rows()
        self.assertEqual(rows["demo-httpd-rce"]["Status"], "not-affected")  # clean everywhere: closed with evidence
        self.assertTrue(rows["demo-httpd-rce"]["Note"].startswith("auto: full run 2026-11-16"))
        self.assertEqual(rows["demo-cli-tool"]["Status"], "open")  # projects clean, machine check still needed
        self.assertEqual(rows["demo-next-cache-leak"]["Status"], "open")
        self.assertEqual(rows["demo-paas-breach"]["Status"], "open")  # account-scoped: never auto-closed
        au = os.path.join(self.storage, "state", "audit-out.json")
        vuln = Env(self.tmp, npm_mode="vuln")
        out = self.run_("audit", "--state", self.state, "--out", au, e=vuln)
        self.assertEqual(out["new_since_last"], "first-run")
        self.run_("save-state", "--state", self.state, "--audit", au, e=vuln)

        # ---- day 2: same news again -> nothing new, nothing duplicated, open actions kept (quiet day)
        n_rows = len(self.rows())
        done, still_open2, quiet = self.briefing("2026-11-17")
        self.assertTrue(quiet)
        self.assertEqual(len(self.rows()), n_rows)
        self.assertEqual(still_open2, still_open_after_day1 := sorted(
            i for i, r in self.rows().items() if r["Status"] in ("open", "REOPENED")))
        self.assertIn("demo-next-cache-leak", still_open_after_day1)
        # a material update reopens a closed item, once, saying what changed
        done, _, _ = self.briefing("2026-11-17", {"demo-httpd-rce": "exploitation started"})
        self.assertEqual(done["demo-httpd-rce"], "reopened")
        self.assertEqual(self.rows()["demo-httpd-rce"]["Note"], "REOPENED 2026-11-17: exploitation started")
        # the user closes it again by hand; the scan never touches a user row
        before, rows, after = trk.load(self.tracker)
        trk.mark(rows, "demo-httpd-rce", "done", "2026-11-17", "patched the proxy")
        trk.save(self.tracker, before, rows, after)

        # ---- day 3 (after a missed day): catch-up widens the window, nothing is invented
        self.assertEqual(trk.missed_runs("2026-11-17", "2026-11-19", weekdays_only=True), ["2026-11-18"])
        reports = os.listdir(self.storage)
        self.assertNotIn("2026-11-18.md", reports)
        # a new project brings back a closed item
        write(os.path.join(self.root, "edge-proxy", "httpd.conf"), "Listen 8080\n")
        write(os.path.join(self.root, "edge-proxy", "package.json"), {"name": "edge-proxy"})
        write(os.path.join(self.root, "edge-proxy", "package-lock.json"), {"lockfileVersion": 3, "packages": {"": {}}})
        changed = self.run_("changed", "--state", self.state)
        self.assertEqual(changed["new"], ["edge-proxy"])
        m, updates = self.scan("2026-11-19", only="edge-proxy")
        self.assertIn(("demo-httpd-rce", "REOPENED"), updates)
        row = self.rows()["demo-httpd-rce"]
        self.assertEqual((row["Status"], row["Note"]),  # the user's note stays; the update is added
                         ("REOPENED", "user: 2026-11-17 — patched the proxy · REOPENED 2026-11-19: new project edge-proxy"))
        # ...and gets its initial dependency audit, merged into the baseline
        au2 = os.path.join(self.storage, "state", "audit-new.json")
        out = self.run_("audit", "--only", "edge-proxy", "--state", self.state, "--out", au2)
        self.assertEqual(out["first_audit"], ["edge-proxy"])
        self.run_("save-state", "--only", "edge-proxy", "--state", self.state, "--audit", au2)
        saved = json.loads(read(self.state))["projects"]
        self.assertIn("edge-proxy", saved)
        self.assertTrue(saved["bad-deps"]["audit"]["keys"])  # other projects' findings kept

    def test_committed_secret_stays_open_until_rotation(self):
        p = os.path.join(self.root, "leaky-app")
        write(os.path.join(p, "src", "config.ts"), f"export const key = '{fixture_setup.make_keys(5)['FAKE_OPENAI_KEY']}'\n")
        git_fixture(p, "init", "-q", "-b", "main")
        git_fixture(p, "add", "-A")
        git_fixture(p, "commit", "-q", "-m", "init")
        hy = self.run_("hygiene", "--only", "leaky-app")
        found = hy["results"]["leaky-app"]["secrets"]["findings"]
        committed = any(f["type"] == "key-pattern" and f["tracked"] for f in found)
        self.assertTrue(committed)
        before, rows, after = trk.load(self.tracker)
        trk.add(rows, "hygiene-secrets-leaky-app", "secrets hygiene in leaky-app", "2026-11-16",
                note="local scan 2026-11-16: key-pattern (src/config.ts), committed")
        trk.save(self.tracker, before, rows, after)
        # the user removes the key from the code; it's still in git history and may still work
        write(os.path.join(p, "src", "config.ts"), "export const key = process.env.KEY\n")
        git_fixture(p, "commit", "-q", "-am", "remove key")
        hy = self.run_("hygiene", "--only", "leaky-app")
        self.assertEqual(hy["results"]["leaky-app"]["secrets"]["findings"], [])
        before, rows, after = trk.load(self.tracker)
        self.assertIsNone(trk.auto_close(rows, "hygiene-secrets-leaky-app", "done", "2026-11-17", "no findings",
                                         complete=True, manual=committed))
        self.assertEqual(rows[-1]["Status"], "open")
        # only the user's confirmation closes it
        trk.mark(rows, "hygiene-secrets-leaky-app", "done", "2026-11-17", "rotated the key")
        self.assertEqual(rows[-1]["Status"], "done")

    def test_snoozed_and_watching(self):
        before, rows, after = trk.load(self.tracker)
        trk.add(rows, "x-snooze", "A snoozed item", "2026-11-01", status="snoozed until 2026-11-20")
        trk.add(rows, "x-watch", "A watched item", "2026-11-01", status="watching")
        self.assertIsNone(trk.upsert(rows, "x-snooze", "A snoozed item", "2026-11-18", "new variant"))
        self.assertEqual(trk.upsert(rows, "x-watch", "A watched item", "2026-11-18", "exploited"), "updated")
        self.assertEqual(rows[-1]["Status"], "watching")
        self.assertIsNone(trk.auto_close(rows, "x-watch", "done", "2026-11-18", "x", complete=True))
        self.assertEqual(trk.wake_snoozed(rows, "2026-11-19"), [])
        self.assertEqual(trk.wake_snoozed(rows, "2026-11-20"), ["x-snooze"])


# ====================================================================== the prompts carry the live rules

LIVE_RULES = [
    # (behaviour, prompt file, phrase that must stay in it)
    ("every source group, omissions reported", "run.md", "Check **every group**"),
    ("omissions reported", "run.md", "say so under \"Sources checked\""),
    ("quotes verbatim from fetched pages", "run.md", "verbatim quote under 15 words from a page fetched"),
    ("never from snippets", "run.md", "Never quote or decide from search snippets alone"),
    ("dedupe by tracker ID", "run.md", "Reuse the tracker ID for known items"),
    ("done/not-affected silent unless reopened", "run.md", "don't report again unless REOPENED"),
    ("snoozed / watching semantics", "run.md", "`snoozed until DATE`: silent until then"),
    ("news step never closes", "run.md", "The news step never closes, snoozes or watches anything"),
    ("open actions persist, prioritised", "run.md", "(still open since YYYY-MM-DD)"),
    ("exact commands", "run.md", "exact commands, fixed versions"),
    ("quiet days short", "run.md", "**Quiet day:**"),
    ("library updated with every item", "run.md", "Add a check to checks.json for every new actionable item"),
    ("one-line fix actions with the why", "howto.md", "Fix: open <project> in Claude Code and say: fix <ID> — <one-line why>"),
    ("news matching covers every project", "howto.md", "Dependency and news checks cover every project, changed or not"),
    ("change-based hygiene", "howto.md", "re-checks only new or changed projects"),
    ("monthly full refresh", "run.md", "on the first full run of the month"),
    ("missed-run catch-up", "run.md", "**Catch-up:**"),
    ("catch-up never invents", "run.md", "Never invent a missed run's results"),
    ("new-project onboarding", "run.md", "\"REOPENED: new project <path>\""),
    ("project items close only on full evidence",
     "run.md", "closes only when every project in `status_by_project` is done or not-affected"),
    ("manual/machine/account/partial never auto-close", "run.md", "Never auto-close machine-only checks"),
    ("committed secrets need rotation", "run.md", "stays open until the user confirms rotation"),
    ("user rows untouched", "run.md", "rows with a `user:` note"),
    ("undo-friendly tracker updates", "run.md", "say \"reopen <ID>\" to undo"),
    ("third-party clones separated", "run.md", "Third-party clones go under \"Third-party clones\""),
    ("unknown ownership explicit", "run.md", "`owner_unconfirmed`"),
        ("audit covers every project in full runs", "run.md", "Full runs add"),
    ("audit failures never clean", "run.md", "never \"no vulnerabilities\""),
    ("baseline and changelog evolve with the library", "run.md", "add a matching check to checks.json, and add a changelog line"),
]


class TestPrompts(unittest.TestCase):
    def test_live_rules_are_in_the_prompts(self):
        for behaviour, f, phrase in LIVE_RULES:
            with self.subTest(behaviour=behaviour):
                self.assertIn(phrase, read(os.path.join(REPO, "prompts", f)))

    def test_prompt_token_budget(self):
        self.assertLessEqual(sum(len(read(os.path.join(REPO, f)).split()) for f in AGENT_FILES), WORD_BUDGET)

    def test_no_osv_route_left(self):
        for dp, dns, fns in os.walk(REPO):
            dns[:] = [d for d in dns if d not in (".git", "_reference", "build", "__pycache__", "fixtures")]
            for f in fns:
                if f.endswith((".py", ".md", ".yaml", ".json")) and f not in ("CHANGELOG.md", "test_p2_flow.py"):
                    text = read(os.path.join(dp, f))
                    if f == "README.md":
                        text = text.split("## Roadmap")[0].replace("Dependabot, Snyk or osv-scanner", "")
                    self.assertNotIn("osv", text.lower(), os.path.relpath(os.path.join(dp, f), REPO))


if __name__ == "__main__":
    unittest.main()
