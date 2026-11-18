"""Review-fix tests: each reproduces a case from the Codex re-review (2026-11-16) first.

Rule throughout: unknown or incomplete never becomes clean, not-affected or fixed. Offline: synthetic
projects in a temp folder, fake npm on PATH, a fake PyPI opener. Scheduling itself stays untested.
"""
import io
import json
import os
import re
import shutil
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path[:0] = [REPO, HERE, os.path.join(HERE, "helpers")]

import fixture_setup  # noqa: E402
from test_p0_safety import Env, realtmp  # noqa: E402
from occupai_scan import tracker as trk  # noqa: E402
from occupai_scan.common import write_json  # noqa: E402
from occupai_scan.deps import audit_keys, covered, lock_versions, pypi_audit, run_audit  # noqa: E402
from occupai_scan.hygiene import check_db  # noqa: E402
from occupai_scan.match import run_match  # noqa: E402
from occupai_scan.safefs import Coverage, Policy, check_destination  # noqa: E402


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if isinstance(text, str) else json.dumps(text))


def code_blocks(text):
    return re.findall(r"```\n(.*?)```", text, re.S)


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = realtmp("occupai-review-")
        self.root = os.path.join(self.tmp, "projects")
        os.makedirs(self.root)

    def tearDown(self):
        for dp, dns, fns in os.walk(self.tmp):
            for d in dns:
                try:
                    os.chmod(os.path.join(dp, d), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.root, *parts)


# ====================================================================== 1. temp-file symlink

class TestStateWriteSidecar(TmpCase):
    def test_predictable_tmp_symlink_cannot_redirect_the_write(self):
        target = self.p("web", "app.js")
        write(target, "original\n")
        state = os.path.join(self.tmp, "storage", "state.json")
        os.makedirs(os.path.dirname(state))
        os.symlink(target, state + ".tmp")  # planted next to an allowed destination
        check_destination(state, self.root)  # the destination itself is fine
        write_json(state, {"saved": True})
        self.assertEqual(read(target), "original\n")
        self.assertEqual(json.loads(read(state)), {"saved": True})
        self.assertTrue(os.path.islink(state + ".tmp"))  # left alone, never followed
        self.assertEqual(sorted(os.listdir(os.path.dirname(state))), ["state.json", "state.json.tmp"])

    def test_through_save_state(self):
        fixture_setup.build(self.root, seed=83)
        target = self.p("web-shop", "package.json")
        before = read(target)
        state = os.path.join(self.tmp, "storage", "state.json")
        os.makedirs(os.path.dirname(state))
        os.symlink(target, state + ".tmp")
        Env(self.tmp).json("save-state", "--root", self.root, "--state", state)
        self.assertEqual(read(target), before)
        self.assertIn("projects", json.loads(read(state)))


# ====================================================================== 2. unsupported pins never "fixed"

def opener_for(vulnerable):
    """Fake PyPI: name==version in `vulnerable` has one advisory, everything else none."""
    def opener(req, timeout=None):
        m = re.search(r"/pypi/([^/]+)/([^/]+)/json$", req.full_url)
        key = f"{m.group(1)}=={m.group(2)}"
        vulns = [{"id": "PYSEC-DEMO-1", "aliases": [], "fixed_in": ["2.0"]}] if key in vulnerable else []
        return io.BytesIO(json.dumps({"info": {}, "vulnerabilities": vulns}).encode())
    return opener


class TestPythonFixedNeedsCoverage(TmpCase):
    def audit(self, text, vulnerable=()):
        write(self.p("py", "requirements.txt"), text)
        res = pypi_audit(Policy(self.root), self.p("py", "requirements.txt"), opener_for(set(vulnerable)))
        return {"py": {"npm": {}, "pypi": {"py/requirements.txt": res}}}

    def test_pin_changed_to_unsupported_range_is_not_fixed(self):
        old = audit_keys(self.audit("occupai-demo-py==1.0\n", {"occupai-demo-py==1.0"}))
        self.assertEqual(len(old), 1)
        ok = covered(self.audit("occupai-demo-py>=1.0\n"))
        self.assertFalse(ok(next(iter(old))))

    def test_removed_behind_an_include_is_not_fixed(self):
        old = audit_keys(self.audit("occupai-demo-py==1.0\n", {"occupai-demo-py==1.0"}))
        ok = covered(self.audit("-r other.txt\n"))
        self.assertFalse(ok(next(iter(old))))

    def test_real_upgrade_and_removal_are_fixed(self):
        old = next(iter(audit_keys(self.audit("occupai-demo-py==1.0\nflask>=3\n", {"occupai-demo-py==1.0"}))))
        self.assertTrue(covered(self.audit("occupai-demo-py==2.0\nflask>=3\n"))(old))  # unrelated unpinned line
        self.assertTrue(covered(self.audit("flask>=3\n"))(old))

    def test_through_the_audit_delta(self):
        """fixed_since_last and the saved baseline, as the audit reports them."""
        old = audit_keys(self.audit("occupai-demo-py==1.0\n", {"occupai-demo-py==1.0"}))
        new = self.audit("occupai-demo-py>=1.0\n")
        ok = covered(new)
        fixed = [k for k in old - audit_keys(new) if ok(k)]
        kept = audit_keys(new) | {k for k in old if not ok(k)}
        self.assertEqual(fixed, [])
        self.assertEqual(kept, old)


# ====================================================================== 3. skipped inputs never clean

class TestSkippedInputsAreReported(TmpCase):
    def setUp(self):
        super().setUp()
        outside = os.path.join(self.tmp, "outside")
        write(os.path.join(outside, "firestore.rules"), "allow read, write: if true;\n")
        write(self.p("fb-app", "index.js"), "console.log(1)\n")
        os.symlink(os.path.join(outside, "firestore.rules"), self.p("fb-app", "firestore.rules"))
        self.pol = Policy(self.root).for_unit("fb-app")

    def test_refused_rules_symlink_makes_db_incomplete(self):
        r = check_db(self.pol, "fb-app")
        self.assertEqual(r["status"], "incomplete")
        self.assertIn({"file": "fb-app/firestore.rules", "reason": "symlink"}, r["skipped"])

    def test_refused_symlink_makes_file_rule_unknown(self):
        check = {"id": "fb-open", "scope": "project", "match": {"files": [{"glob": "firestore.rules"}]}}
        m = run_match(Policy(self.root), ["fb-app"], [check])["fb-open"]
        self.assertEqual(m["projects"]["fb-app"]["status"], "unknown")
        self.assertFalse(m["complete"])

    def test_symlinked_folder_makes_file_rule_unknown(self):
        os.symlink(os.path.join(self.tmp, "outside"), self.p("fb-app", "conf"))
        check = {"id": "fb-open", "scope": "project", "match": {"files": [{"glob": "conf/*"}]}}
        m = run_match(Policy(self.root), ["fb-app"], [check])["fb-open"]
        self.assertEqual(m["projects"]["fb-app"]["status"], "unknown")

    def test_unreadable_folder_is_reported(self):
        sub = self.p("fb-app", "rules")
        write(os.path.join(sub, "database.rules.json"), '{"rules": {".read": true}}')
        os.remove(self.p("fb-app", "firestore.rules"))
        os.chmod(sub, 0)
        if os.access(sub, os.R_OK):
            self.skipTest("running as root: can't make a folder unreadable")
        r = check_db(Policy(self.root).for_unit("fb-app"), "fb-app")
        self.assertEqual(r["status"], "incomplete")
        self.assertIn({"file": "fb-app/rules", "reason": "unreadable"}, r["skipped"])
        check = {"id": "fb-open", "scope": "project", "match": {"files": [{"glob": "rules/*.json"}]}}
        m = run_match(Policy(self.root), ["fb-app"], [check])["fb-open"]
        self.assertEqual(m["projects"]["fb-app"]["status"], "unknown")


# ====================================================================== 4. malformed and unsupported inputs

class TestMalformedInputsAreUnknown(TmpCase):
    def test_empty_pypi_response_is_not_checked(self):
        write(self.p("py", "requirements.txt"), "occupai-demo-py==1.0\n")
        res = pypi_audit(Policy(self.root), self.p("py", "requirements.txt"), lambda req, timeout=None: io.BytesIO(b"{}"))
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["checked"], [])
        self.assertEqual(res["failed"], {"occupai-demo-py==1.0": "invalid-response"})

    def test_corrupt_yarn_lock_is_unknown(self):
        write(self.p("yarn-app", "package.json"), {"name": "y", "dependencies": {"occupai-demo-anim": "1"}})
        write(self.p("yarn-app", "yarn.lock"), "this is not a lockfile\nat all\n")
        cov = Coverage()
        self.assertIsNone(lock_versions(Policy(self.root), self.p("yarn-app", "yarn.lock"), ["occupai-demo-anim"], cov))
        self.assertEqual(cov.skipped[0]["reason"], "unparseable-lockfile")
        check = {"id": "evil", "scope": "project", "match": {"malicious_packages": ["occupai-demo-anim"]}}
        m = run_match(Policy(self.root), ["yarn-app"], [check])["evil"]
        self.assertEqual(m["projects"]["yarn-app"]["status"], "unknown")

    def test_pyproject_only_project_is_not_covered(self):
        write(self.p("py-only", "pyproject.toml"), "[project]\nname = \"x\"\ndependencies = [\"requests\"]\n")
        r = run_audit(Policy(self.root), "py-only")
        self.assertEqual(r["status"], "incomplete")
        self.assertIn("py-only/pyproject.toml: no-requirements-file", r["not_covered"])

    def test_package_json_with_deps_but_no_lockfile_is_not_covered(self):
        write(self.p("js-nolock", "package.json"), {"name": "n", "dependencies": {"next": "16.2.1"}})
        write(self.p("js-nodeps", "package.json"), {"name": "d"})
        r = run_audit(Policy(self.root), "js-nolock")
        self.assertEqual(r["status"], "incomplete")
        self.assertIn("js-nolock/package.json: no-lockfile", r["not_covered"])
        self.assertEqual(run_audit(Policy(self.root), "js-nodeps")["status"], "ok")  # nothing to audit


# ====================================================================== 5. user protection survives updates

class TestTrackerProtection(unittest.TestCase):
    def test_user_reopen_then_material_update_then_auto_close(self):
        rows = []
        trk.add(rows, "demo-x", "Item", "2026-11-16")
        trk.auto_close(rows, "demo-x", "not-affected", "2026-11-16", "no match", complete=True)
        trk.mark(rows, "demo-x", "REOPENED", "2026-11-17", "still seeing it on staging")
        self.assertEqual(trk.upsert(rows, "demo-x", "Item", "2026-11-18", "new exploit variant"), "updated")
        self.assertIsNone(trk.auto_close(rows, "demo-x", "not-affected", "2026-11-19", "no match", complete=True))
        row = rows[0]
        self.assertEqual(row["Status"], "REOPENED")
        self.assertIn("user: 2026-11-17 — still seeing it on staging", row["Note"])
        self.assertIn("UPDATED 2026-11-18: new exploit variant", row["Note"])

    def test_automated_updates_never_delete_user_text(self):
        rows = []
        trk.add(rows, "demo-y", "Item", "2026-11-16")
        rows[0]["Note"] = "waiting on the vendor"  # typed into actioned.md by hand
        trk.upsert(rows, "demo-y", "Item", "2026-11-17", "first update")
        trk.upsert(rows, "demo-y", "Item", "2026-11-18", "second update")
        self.assertEqual(rows[0]["Note"], "waiting on the vendor · UPDATED 2026-11-18: second update")
        trk.auto_close(rows, "demo-y", "done", "2026-11-19", "0 critical/high", complete=True)
        self.assertEqual(rows[0]["Note"], "waiting on the vendor · auto: full run 2026-11-19 — 0 critical/high")
        # survives a save and load
        text = trk.render("", rows, "")
        self.assertEqual(trk.parse(text)[1][0]["Note"], rows[0]["Note"])


# ====================================================================== 6. setup scope

class TestSetupScope(unittest.TestCase):
    def test_setup_rehearses_each_task_and_scopes_mark_done(self):
        setup = read(os.path.join(REPO, "SETUP.md"))
        self.assertLess(len(setup.split()), 950)
        sched = setup.split("## 6.")[1].split("## 7.")[0]
        self.assertIn("run each once now", sched)
        self.assertIn("look up security news", sched)  # web access, approved once in the same run
        finish = setup.split("## 7.")[1]
        self.assertIn("in a chat on the OccupAI folder", finish)
        self.assertNotIn("any session", setup)

    def test_readme_says_stack_and_sources_are_examples(self):
        readme = read(os.path.join(REPO, "README.md"))
        self.assertTrue("an example list to edit" in readme, "README doesn't say the sources are examples")
        self.assertTrue("stack.md" in readme, "README doesn't say relevance comes from what the projects use")
        for f in ("README.md", os.path.join("docs", "setup", "claude-desktop.md")):
            self.assertFalse(re.search(r"mark <ID> done\"? in any session", read(os.path.join(REPO, f))), f)


# ====================================================================== 7 + 8. the weekly audit, end to end

class TestAuditEndToEnd(unittest.TestCase):
    """audit -> tracker -> baseline/checks/changelog over two weeks, using the full-run commands in
    prompts/run.md as written. The script parts run for real; a small stand-in applies the prompt's tracker and library
    rules, as in test_p2_flow. The scheduled tasks themselves are not tested."""

    def setUp(self):
        self.tmp = realtmp("occupai-review-audit-")
        self.root = os.path.join(self.tmp, "projects")
        fixture_setup.build(self.root, seed=89)
        self.storage = os.path.join(self.tmp, "storage")
        self.st = os.path.join(self.storage, "state")
        os.makedirs(self.st)
        self.cfg = os.path.join(self.storage, "occupai.config.yaml")
        write(self.cfg, f"version: 1\nprojects_root: {self.root}\nstorage:\n  path: {self.storage}\n")
        self.tracker = os.path.join(self.storage, "actioned.md")
        shutil.copy(os.path.join(REPO, "templates", "actioned.md"), self.tracker)
        self.lib = os.path.join(self.storage, "library")
        os.makedirs(self.lib)
        for f in ("checks.json", "baseline.md", "changelog.md"):
            shutil.copy(os.path.join(REPO, "templates", f), self.lib)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_prompt_block(self, e):
        """The full-run block in prompts/run.md, as written: each SCAN line repeated while partial."""
        block = next(b for b in code_blocks(read(os.path.join(REPO, "prompts", "run.md"))) if "SCAN audit" in b)
        outs = []
        for line in block.splitlines():
            line = line.split("  #")[0].strip()
            if not line.startswith("SCAN "):
                continue
            args = line.replace("$ST", self.st).split()[1:]
            for _ in range(40):
                out = e.json(*args, "--config", self.cfg)
                if out.get("status") != "partial":
                    break
            outs.append(out)
        return outs

    def week(self, day, npm_mode):
        e = Env(self.tmp, npm_mode=npm_mode)
        outs = self.run_prompt_block(e)
        audit_out, saved = next(o for o in outs if o.get("kind") == "audit"), outs[-1]
        self.assertIn("saved", saved)
        doc = json.loads(read(os.path.join(self.st, "audit-out.json")))
        before, rows, after = trk.load(self.tracker)
        ids = {r["ID"] for r in rows}
        checks = json.loads(read(os.path.join(self.lib, "checks.json")))
        baseline, changelog = read(os.path.join(self.lib, "baseline.md")), read(os.path.join(self.lib, "changelog.md"))
        for u, r in sorted(doc["results"].items()):
            vulns = {n: v for lf in r.get("npm", {}).values() for n, v in (lf.get("vulns") or {}).items()}
            ch = {n: v for n, v in vulns.items() if v.get("severity") in ("critical", "high")}
            rid = f"audit-{u}"
            if ch:
                c = sum(1 for v in ch.values() if v["severity"] == "critical")
                note = f"{c} critical / {len(ch) - c} high / 0 moderate: {', '.join(sorted(ch))}"
                if rid in ids:
                    trk.upsert(rows, rid, f"Dependency audit: {u}", day, note)
                else:
                    trk.add(rows, rid, f"Dependency audit: {u}", day, note=note)
                for n, v in ch.items():
                    cid = f"audit-min-{n}"
                    if v.get("direct") and not any(x["id"] == cid for x in checks["checks"]):
                        found = e.json("versions", "--packages", n, "--config", self.cfg)
                        top = max(x for f, pk in found.items() if not f.startswith("_") for x in pk.get(n, []))
                        checks["checks"].append({"id": cid, "title": f"{n} with critical/high advisories",
                                                 "scope": "project", "severity": v["severity"],
                                                 "match": {"packages": [{"name": n, "affected": f"<={top}"}]}})
                        baseline = baseline.replace("| starting rule |\n\nFor npm",
                                                    f"| starting rule |\n| {n} | above {top} (no fix published yet) "
                                                    f"| {cid}, {day} |\n\nFor npm", 1)
                        changelog += f"- **{day} (audit):** baseline minimum and check for {n} ({cid}).\n"
            elif rid in ids and r.get("status") == "ok":
                trk.auto_close(rows, rid, "done", day, "0 critical/high", complete=True, source="dependency audit")
        trk.save(self.tracker, before, rows, after)
        write(os.path.join(self.lib, "checks.json"), json.dumps(checks, indent=1))
        write(os.path.join(self.lib, "baseline.md"), baseline)
        write(os.path.join(self.lib, "changelog.md"), changelog)
        return audit_out, e

    def rows(self):
        return {r["ID"]: r for r in trk.load(self.tracker)[1]}

    def test_two_weeks(self):
        self.assertFalse(os.path.exists(os.path.join(self.st, "hygiene-out.json")))  # standalone first audit
        # ---- week 1: vulnerable lockfiles
        out, e = self.week("2026-11-16", "vuln")
        self.assertEqual(out["new_since_last"], "first-run")
        state = json.loads(read(os.path.join(self.st, "scan-state.json")))
        keys = state["projects"]["bad-deps"]["audit"]["keys"]
        self.assertTrue(any(k.startswith("bad-deps/package-lock.json|occupai-demo-anim|") for k in keys))
        row = self.rows()["audit-bad-deps"]
        self.assertEqual(row["Status"], "open")
        self.assertIn("1 critical / 0 high", row["Note"])
        checks = json.loads(read(os.path.join(self.lib, "checks.json")))["checks"]
        self.assertEqual([c["id"] for c in checks], ["audit-min-occupai-demo-anim"])
        self.assertIn("| occupai-demo-anim | above", read(os.path.join(self.lib, "baseline.md")))
        self.assertIn("(audit-min-occupai-demo-anim)", read(os.path.join(self.lib, "changelog.md")))
        # the new check works: replaying it finds the same project
        m = e.json("match", "--config", self.cfg)["audit-min-occupai-demo-anim"]
        self.assertIn("bad-deps", m["affected"])

        # ---- week 2: the user fixed it; one project the user reopened by hand stays theirs
        before, rows, after = trk.load(self.tracker)
        users = sorted(i for i in (r["ID"] for r in rows) if i != "audit-bad-deps")
        if users:
            trk.mark(rows, users[0], "REOPENED", "2026-11-20", "keeping this open until the next release")
        trk.save(self.tracker, before, rows, after)
        out, _ = self.week("2026-11-23", "clean")
        self.assertTrue(any(k.startswith("bad-deps/package-lock.json|occupai-demo-anim|") for k in out["fixed_since_last"]))
        self.assertEqual(out["carried_unverified"], [])
        row = self.rows()["audit-bad-deps"]
        self.assertEqual((row["Status"], row["Updated"]), ("done", "2026-11-23"))
        self.assertIn("auto: dependency audit 2026-11-23 — 0 critical/high", row["Note"])
        if users:
            self.assertEqual(self.rows()[users[0]]["Status"], "REOPENED")
        state = json.loads(read(os.path.join(self.st, "scan-state.json")))
        self.assertEqual(state["projects"]["bad-deps"]["audit"]["keys"], [])
        # the library keeps the rule: baseline and changelog only grow through logged changes
        self.assertEqual(read(os.path.join(self.lib, "changelog.md")).count("(audit)"), 1)


if __name__ == "__main__":
    unittest.main()
