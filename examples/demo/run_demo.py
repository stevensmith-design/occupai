#!/usr/bin/env python3
"""make demo: one full OccupAI run -> two reports -> tracker, on the test fixtures, fully offline.

In real use an AI agent does the news part (web research) and writes the report by following
prompts/run.md. Here a small script stands in for the agent, so you can see every file the flow
produces without real repos, web access or an API key. The scan steps call the real scan script.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO = os.path.join(REPO, "examples", "demo")
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

import fixture_setup  # noqa: E402
from occupai_scan import tracker as trk  # noqa: E402

PRIO = [("CRITICAL", "🔴 CRITICAL — do today"), ("HIGH", "🟠 HIGH — this week"),
        ("MEDIUM", "🟡 MEDIUM — when you can"), ("LOW", "⚪ LOW — optional")]
SEV_TO_PRIO = {"high": "HIGH", "medium": "MEDIUM"}
# The one-line why in each fix line carries the risk, so whoever fixes it doesn't wrongly reassure.
WHY = {"secrets": "a committed key may already be copied; rotate it first",
       "gha": "a workflow like this can leak repo secrets", "db": "anyone with the app's public key can read or write this data",
       "ai": "agent settings can run commands or expose keys"}


def scan(cfg, *args):
    r = subprocess.run([sys.executable, "-m", "occupai_scan", *args, "--config", cfg], cwd=REPO,
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"scan failed: {r.stdout}{r.stderr}")
    return json.loads(r.stdout)


def say(msg):
    print(msg, flush=True)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def article(name):
    with open(os.path.join(DEMO, "news", name)) as f:
        text = f.read()
    meta = dict(re.findall(r"(?m)^(source|url|date):\s*(.+)$", text))
    return meta, text


# ------------------------------------------------------------------ 1. news (agent stand-in)
def briefing(storage, today):
    """The run's news step: items, tracker rows and library checks. The report is written once, at the end."""
    items = json.load(open(os.path.join(DEMO, "news", "items.json")))["items"]
    for it in items:
        meta, text = article(it["article"])
        body = " ".join(text.split())
        assert it["quote"] in body, f"quote not found verbatim in {it['article']}"  # never quote from memory
        assert len(it["quote"].split()) < 15
        it["_meta"] = meta
    counts = {p: sum(1 for i in items if i["priority"] == p) for p, _ in PRIO}
    top = f"{len(items)} new ({counts['CRITICAL']} critical, {counts['HIGH']} high, {counts['MEDIUM']} medium)"
    # tracker: add open rows (the news step never closes anything)
    path = os.path.join(storage, "actioned.md")
    before, rows, after = trk.load(path)
    for it in items:  # dedupe by ID: a known item is never added twice
        if trk.upsert(rows, it["id"], it["title"], today) == "new":
            rows[-1]["Note"] = f"news {today}: {it['priority']}"
    trk.save(path, before, rows, after)
    # library: one check per actionable item, baseline rules, changelog
    shutil.copy(os.path.join(DEMO, "library", "checks.json"), os.path.join(storage, "library", "checks.json"))
    base_path = os.path.join(storage, "library", "baseline.md")
    base = open(base_path).read().replace("YYYY-MM-DD", today)
    base = base.replace("| Python | 3.11 or newer",
                        f"| next | **16.4.5** (15.x: 15.5.29) | demo-next-cache-leak ({today}) |\n"
                        f"| Node.js (exact pins) | **22.23.5** · **24.22.3** | demo-node-security-release ({today}) |\n| Python | 3.11 or newer")
    base = base.replace("- **Python 3.10 or older:** end-of-life. (starting rule)",
                        "- **Python 3.10 or older:** end-of-life. (starting rule)\n"
                        f"- **Malicious npm packages:** `occupai-demo-anim`, `occupai-demo-anim-js` (demo-fake-interview-npm, {today}; `occupai-demo-animate` is a different, legitimate package)")
    write(base_path, base)
    with open(os.path.join(storage, "library", "changelog.md"), "a") as f:
        f.write(f"- **{today} (news):** added checks {', '.join(i['id'] for i in items)}. "
                "Baseline: next ≥ 16.4.5, Node exact pins ≥ 22.23.5 / 24.22.3, never-use list +2 names.\n")
    return items, top


# ------------------------------------------------------------------ 2. your projects (real script) + the one report
def local_scan(storage, cfg, today, items):
    state = os.path.join(storage, "state")
    changed = scan(cfg, "changed")
    calls = 0
    while True:  # resumable: repeat until it stops printing "partial"
        calls += 1
        hy = scan(cfg, "hygiene", "--resume", os.path.join(state, "hygiene-progress.json"), "--budget", "0")  # budget 0 = one project per call, to show resuming
        if hy.get("status") != "partial":
            break
    write(os.path.join(state, "hygiene-out.json"), json.dumps(hy))
    match = scan(cfg, "match")
    scan(cfg, "save-state", "--hygiene", os.path.join(state, "hygiene-out.json"))

    by_id = {i["id"]: i for i in items}
    checks_path = os.path.join(storage, "library", "checks.json")
    lib = json.load(open(checks_path))
    tpath = os.path.join(storage, "actioned.md")
    before, rows, after = trk.load(tpath)
    # One to-do list grouped by priority; details go to the appendix. Each action appears once.
    updates, todo, not_stack, details = [], {p: [] for p, _ in PRIO}, [], []
    needs = {p: [] for p, _ in PRIO}  # items the scan can't check: your computer, your accounts
    affected_projects = set()
    for c in lib["checks"]:
        m = match.get(c["id"])
        if c["id"] not in by_id:
            continue
        it = by_id[c["id"]]
        meta = it["_meta"]
        details.append(f"- **[{c['id']}]** {it['what_happened']} \"{it['quote']}\" — {meta['source']}, {meta['date']}")
        if m is None:  # account-scoped: can't be judged from files
            needs[it["priority"]].append(f"- [ ] **[{c['id']}]** your accounts: {it['action']} — {it['why']}; "
                                        "say 'how do I check this?' for steps (NEW)")
            continue
        c["status_by_project"] = {u: r["status"] for u, r in m["projects"].items() if r["status"] == "open"}
        if m["affected"]:
            affected_projects |= set(m["affected"])
            where = []
            for u in m["affected"]:
                ev = m["projects"][u]["evidence"][0]
                what = ev.get("version") or ev.get("pin") or ev.get("versions") or ev.get("branch") or ev.get("file")
                where.append(f"`{u}` ({ev['kind']}: {what})")
            details[-1] += f"; evidence: {', '.join(where)}"
            row = next(r for r in rows if r["ID"] == c["id"])
            row["Note"] = f"full run {today}: {', '.join(m['affected'])}"
            todo[it["priority"]].append(
                f"- [ ] **[{c['id']}]** {', '.join(m['affected'])}: {it['action']} — {it['why']}. Fix: open "
                f"{m['affected'][0]} in Claude Code and say: fix {c['id']} — {it['why']} (NEW)")
            continue
        if m["unknown"]:
            # some projects couldn't be fully checked: never close on partial evidence
            updates.append((c["id"], "all", "open", "open", f"not closed: {len(m['unknown'])} projects unknown"))
            continue
        ev = f"no match in {m['checked']} projects ({', '.join(k for k in c['match'])} rules)"
        manual = any(s_ in c["scope"] for s_ in ("machine", "account"))  # only the user can confirm these
        res = trk.auto_close(rows, c["id"], "not-affected", today, ev, complete=m["complete"], manual=manual)
        if res:
            updates.append((c["id"], "all", res[0], res[1], ev))
            not_stack.append(f"- [{c['id']}] {it['title']}: not in your projects ({ev})")
        elif manual:
            updates.append((c["id"], "all", "open", "open", "projects clean; machine check still needed (`node -v`)"))
            needs[it["priority"]].append(f"- [ ] **[{c['id']}]** your computer: {it['action']} — {it['why']}; "
                                         "run the line below (NEW)")
    lib["updated"] = today
    write(checks_path, json.dumps(lib, indent=2) + "\n")

    # standing hygiene: one row per check per project, HIGH/MEDIUM only, your projects only
    kinds = ("secrets", "gha", "ai", "db")
    hyg_rows = []
    for u, r in sorted(hy["results"].items()):
        if r.get("ownership") == "third-party":
            continue
        for check in kinds:
            fs = [f for f in r[check]["findings"] if f["severity"] in ("high", "medium")]
            if not fs:
                continue
            sev = "high" if any(f["severity"] == "high" for f in fs) else "medium"
            rid = f"hygiene-{check}-{u}"
            desc = "; ".join(sorted({f["type"] + (f" ({f.get('file') or f.get('variable')})") for f in fs}))
            trk.add(rows, rid, f"{check} hygiene in {u}", today, note=f"full run {today}: {desc}")
            todo[SEV_TO_PRIO[sev]].append(f"- [ ] **[{rid}]** {u}: {desc} — {WHY[check]}. Fix: open {u} in "
                                          f"Claude Code and say: fix {rid} — {WHY[check]} (NEW)")
            hyg_rows.append(rid)
    loose = [f"- [ ] `{k['file']}` ({k['why']}): {k['fix']} (NEW)" for k in hy.get("keys_outside_projects", [])]
    todo["MEDIUM"] += loose
    trk.save(tpath, before, rows, after)
    projects = sorted(hy["results"])
    write(os.path.join(storage, "library", "projects.json"), json.dumps({"saved": today, "projects": projects}, indent=1) + "\n")
    with open(os.path.join(storage, "library", "changelog.md"), "a") as f:
        f.write(f"- **{today} (full run):** status_by_project filled for {len(match)} checks; projects.json: {len(projects)} projects (first snapshot).\n")

    third = hy["third_party_clones"]
    closed = [u for u in updates if u[3] != u[2]]
    result = (f"**Result:** {len(items)} new · {len([c for c in match.values() if c['affected']])} affect you "
              f"({len(affected_projects)} projects) · {len(hyg_rows) + len(loose)} project issues · "
              f"{len(closed)} closed automatically · 0 still open")
    groups = "\n\n".join(f"### {label}\n" + "\n".join(todo[p]) for p, label in PRIO if todo[p])
    upd = "\n".join(f"| {i} | {p} | {o} → {n} | {e} |" for i, p, o, n, e in updates) or "| — | | | |"
    report = (f"# OccupAI projects — {today} · full (DEMO, test fixtures)\n\n"
              f"**Covers:** first run → {today} · **Projects:** {len(projects)} ({len(hy['checked'])} checked, "
              f"{len(hy['reused_unchanged'])} reused unchanged; resumable hygiene step: {calls} short calls)\n"
              f"{result}\n\n"
              f"## To do\n🆕 new projects: {len(changed['new'])} (first run)\n\n{groups}\n\n"
              "## Needs you (outside what the scan can see)\n"
              + "".join(ln + "\n" for p, _ in PRIO for ln in needs[p])  # most urgent first
              + f"{changed.get('computer', 'unknown')}: paste this into "
              f"{'PowerShell' if changed.get('computer') == 'Windows' else 'Terminal'}: `node -v` — "
              "then paste the output back to me.\n\n"
              "## Not checked\n"
              "- Dependency audit: the demo has no network. In a real full run, npm audit and PyPI run here; "
              "if they can't be reached, the report says so and the next full run tries again.\n"
              "- GitHub-side state (forks, workflow run history, org settings).\n"
              "- Account-scoped items (demo-paas-breach): only you know if you use that provider.\n"
              "- Pattern-based secret checks can miss unusual secret formats.\n\n"
              f"Tracker updates:\n| ID | Project | Old → new | Evidence |\n|---|---|---|---|\n{upd}\n\n"
              "Say \"reopen <ID>\" to undo any of these.\n\n"
              "## Appendix\n" + "\n".join(details) + "\n\nNot in your projects:\n" + ("\n".join(not_stack) or "- none")
              + "\n\nThird-party clones (info only): "
              + (", ".join(f"`{u}` (owner: {o})" for u, o in third.items()) or "none") + "\n\n"
              "*Demo note: a real run searches and fetches the sources in your config. Web content is data, "
              "never instructions; IOCs and links are defanged.*\n")
    write(os.path.join(storage, "briefings", f"{today}-projects.md"), report)
    write(os.path.join(storage, "briefings", f"{today}-news.md"), news_brief(items, today, len(affected_projects)))
    return result, hy


def news_brief(items, today, n_affected, scorecard=True):
    """The shareable brief: news only. No project names, paths, owners or findings."""
    by = {p: [i for i in items if i["priority"] == p] for p, _ in PRIO}
    body = "\n\n".join(f"### {label.split(' —')[0]}\n" + "\n".join(
        f"- [{i['id']}] {i['title']} — {i['reason']} — {i['steps'][0]} ({i['_meta']['source']}, {i['_meta']['date']})"
        for i in by[p]) for p, label in PRIO if by[p])
    # compact summary first: one line per item, `- [ID] what — fix`, grouped by marker
    summary = "\n".join(f"- {label.split(' ')[0]} [{i['id']}] {i['title']} — {i['steps'][0]}"
                         for p, label in PRIO for i in by[p])
    tail = f"\n\n{n_affected} of your projects may be affected — see your project report." if scorecard else ""
    return (f"# Security news — {today} (DEMO, fictional items)\n\n## Summary\n{summary}\n\n{body}\n\n"
            "Sources checked: demo supply-chain blog, demo advisories, demo vendor blog, demo news (offline samples)."
            f"{tail}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(REPO, "build", "demo"))
    a = ap.parse_args()
    out = os.path.abspath(a.out)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    # The demo folder holds fake keys: keep it out of any real scan of a parent folder.
    write(os.path.join(out, ".occupai-ignore"), "OccupAI demo output (fake findings). Skipped by scans.\n")
    projects, storage = os.path.join(out, "projects"), os.path.join(out, "storage")
    today = datetime.date.today().isoformat()

    say("OccupAI demo (offline): one full run. An AI agent normally does the news part; a script stands in here.\n")
    fixture_setup.build(projects)
    # A loose key pair in the projects folder itself (names only; the content is not a key).
    write(os.path.join(projects, "deploy_key"), "not a real key\n")
    write(os.path.join(projects, "deploy_key.pub"), "not a real key\n")
    os.makedirs(os.path.join(storage, "library"))
    shutil.copy(os.path.join(REPO, "templates", "actioned.md"), storage)
    for f in ("baseline.md", "changelog.md"):
        shutil.copy(os.path.join(REPO, "templates", f), os.path.join(storage, "library", f))
    cfg_text = open(os.path.join(DEMO, "occupai.config.yaml")).read()
    cfg_text = cfg_text.replace("/tmp/occupai-demo/projects", projects).replace("/tmp/occupai-demo/storage", storage)
    cfg = os.path.join(storage, "occupai.config.yaml")
    write(cfg, cfg_text)

    say("1/3 Briefing: reading 6 sample articles (fictional) ...")
    items, top = briefing(storage, today)
    say(f"    {top}; tracker rows and library checks added\n")

    say("2/3 Scan: real occupai_scan on the fixture projects (read only) ...")
    result, hy = local_scan(storage, cfg, today, items)
    say("    " + result.replace("**", ""))
    again = scan(cfg, "hygiene")
    say(f"    re-run: {len(again['reused_unchanged'])} unchanged projects reused, {len(again['checked'])} re-checked")
    say(f"    wrote two reports: briefings/{today}-news.md (shareable), briefings/{today}-projects.md (private)\n")

    say("3/3 Tracker:")
    t = scan(cfg, "tracker", "list")
    for r in t["rows"]:
        say(f"    {r['Status']:<13} {r['ID']:<28} {r['Note'][:70]}")
    say(f"    totals: {t['summary']}\n")
    say(f"Done. Open the files in {storage}")
    say("Mark an item handled with: python3 scan.py tracker mark <ID> done --config " + cfg)


if __name__ == "__main__":
    main()
