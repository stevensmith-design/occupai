# OccupAI run (two tasks: briefing, then scan)

Read `KIT/prompts/howto.md` first: its rules apply to every step. SCAN = `python3 KIT/scan.py`; you read its short JSON summaries.

**Goal:** a shareable news brief, and one private to-do list readable in three minutes: each action once, in priority order, only there.

## 0. Mode (the task prompt names it; on request without one, do briefing, then scan)
- **briefing** (daily): steps 1, 2 with the quick match, 4, and the news brief.
- **scan** (daily, after the briefing; also "scan now"): steps 1, 3, 4, and the project report.
  - **full** when today is `schedule.full_day` (default Monday), on the first run, when the last full run is more than 8 days old, or when the user asks ("run a full scan"; "scan only <project>" is a full run with `--only <project>`).
  - **daily** on every other day: standing checks on new and changed projects plus a replay of every check.
- **Overlap guard:** the briefing runs `SCAN marker start` first and `SCAN marker done` last (also when it stops early). The scan runs `SCAN marker wait` first; while it prints `"briefing_running": true`, repeat it, up to 5 times; still true: write nothing and end with "The briefing is still running. Reply **try again** in a few minutes."

## 1. Read state (only what's needed)
- CONFIG: ROOT, `my_owners`, `news_sources`, `timezone`, STORAGE, `notifications`, `schedule`.
- `STORAGE/actioned.md`: every row. `done` / `not-affected`: don't report again unless REOPENED. `snoozed until DATE`: silent until then. `watching`: only material changes, marked UPDATED. `open`: stays in the actions.
- The latest report of this mode in `STORAGE/briefings/` (`DATE-news.md` or `DATE-projects.md`): the news window starts at its date (first run: the last 7 days). Reuse each open item's priority. Never read reports older than 14 days.
- `STORAGE/library/checks.json` (IDs, titles, fix lines) and `stack.md`; `baseline.md` only if an item changes it.
- **Catch-up:** if runs were missed, the window covers everything since the last report; say "Catch-up: covers <date> → today (missed: <dates>)". Never invent a missed run's results.
- If ROOT can't be reached (no folder access, computer asleep, no shell here): the briefing still does the news, says "Projects not checked; the next run will catch up", and skips the quick match; the scan stops. Both end with the recovery step from howto.md.

## 2. News (briefing)
Check **every group** in `news_sources`:
- Start from each source's index or changelog page sorted by date (one fetch each) and note what's new since the window start.
- Fetch the full article only for new items that could touch the stack or are CRITICAL/HIGH for anyone, plus updates on open and watching items. Prefer primary sources.
- Aim for about 15–25 fetches; more when something is critical. **Never quote or decide from search snippets alone.**
- If a source can't be fetched, say so under "Sources checked".

Per new item, or tracker item with a material change (REOPENED or UPDATED, saying what changed):
- **ID**: the CVE or a stable lowercase slug. Reuse the tracker ID for known items.
- **What happened** in two sentences, and one verbatim quote under 15 words from a page fetched in this run, with source and date (or "no quote: page not fetched").
- **Claims match the source:** attribution (country, group), victim and impact numbers, "actively exploited" and "malicious" only as the fetched source states them. If it doesn't say it, leave it out or write "the source doesn't attribute it".
- **Priority** with a reason: CRITICAL (actively exploited, mass compromise, malware in a popular package), HIGH (serious, fix available, likely exploited), MEDIUM / LOW.
- **Touches my stack?** yes / no / maybe, judged against stack.md (any listed tech), naming the projects. Before the first full run, use `stack` in CONFIG.
- **What to do:** exact commands, fixed versions, indicators and what to rotate. Defang every IOC.
- **Fixed version not found:** mark the check `unknown` and say so; never a rule matching every version. A framework that bundles vulnerable code with no confirmed fix gets one plain line: "<framework> X.Y fixes <other issue>; <CVE> may still apply until <framework> ships a fix", so two items never seem to contradict.

**Verify before saving the news brief:** check each 🔴 and 🟠 item's headline and fix line against its source (versions, package names, attribution, numbers, exploited status, dates); change anything unsupported to match the source, or remove it. A 🔴 item calling a package or release malicious: re-open its primary source once to confirm names and versions; if it can't be fetched, write "not re-confirmed" in the item.

**Quick match (briefing):** `SCAN match --ids <today's new and updated check IDs> --out <STORAGE>/state/match-briefing.json`. Matches become tracker actions (step 4), never a second action list.

## 3. Your projects (scan)
Repeat any command that prints `"status": "partial"`; if someone is watching (setup, a run on request), say "Checked <done> of <done+remaining> projects" each time. Every scan (hygiene re-checks only new and changed projects):
```
ST=<STORAGE>/state
SCAN changed
SCAN match --out $ST/match-out.json
SCAN hygiene --resume $ST/hygiene-progress.json --budget 100 --out $ST/hygiene-out.json
SCAN save-state --hygiene $ST/hygiene-out.json
```
For each **new** project in `changed`, also `SCAN audit --only <p> --out $ST/audit-new.json` and `SCAN save-state --only <p> --hygiene $ST/hygiene-out.json --audit $ST/audit-new.json`. Report "🆕 New project: <path>: N issues"; a match on a closed item sets it to REOPENED with "REOPENED: new project <path>".

Full runs add the audit, in place of the last two lines (use `--all` on hygiene on the first full run of the month, or when asked):
```
SCAN hygiene --resume $ST/hygiene-progress.json --budget 100 --out $ST/hygiene-out.json
SCAN route-check
SCAN audit --resume $ST/audit-progress.json --budget 100 --out $ST/audit-out.json
SCAN save-state --hygiene $ST/hygiene-out.json --audit $ST/audit-out.json
```
Projects in `not_saved_inputs_changed` are re-checked next run.

**What "clean" means.** Only `ok` (hygiene), `not-affected` (match) and `"status": "complete"` mean checked, nothing found. `incomplete`, `error` and `unknown` are "not fully checked": never report them as clean or close rows on them. List them under "Not checked" with their `skipped` reasons, `not_covered` files (e.g. "Dart: not audited") and any `omitted` folders (for depth-limit, name `cut_at`). `carried_findings` and `carried_unverified` still stand.

Reading the results:
- **News matches** (`match-out.json`): affected projects with evidence. A rule the script can't express is `unknown`, under "Not checked": never ad-hoc shell commands.
- **Hygiene:** before a first-time HIGH/CRITICAL finding, rule out false positives (placeholder, detector regex, public client config, fixture) without printing values. `keys_outside_projects`: one line each, naming files as files (not folders), "move to ~/.ssh or delete". Third-party clones go under "Third-party clones" as info; list `owner_unconfirmed` owners for the user to confirm. `silenced` projects: one line with counts.
- **Audit:** per project only counts of packages with their **own** advisory by severity, and the top 3 fixes (the appendix holds the full list); `via_dependency_only` ones are fixed by fixing the dependency. With `mostly_in`, add "Most are in <folder>: say '<project>/<folder> is inactive' to quiet it". A lockfile with `error` is not covered, never "no vulnerabilities". Copy `route-check` notes and one line naming `generated_skipped` folders (build output, never audited) to "Not checked". `new_since_last` / `fixed_since_last` give the weekly delta.
- **`not_reachable`** (from `changed`): under "Not checked", "<project> isn't readable from this task: attach the projects folder to both tasks".
- **Unknown status:** a project with critical/high items and no decision in `your_decisions` gets one line: "Is <project> still active or deployed? Say '<project> is inactive' to quiet it."
- **Stack:** `new_in_stack` from save-state becomes "New in your stack: <tech> (<projects>) — news watched; <checked_locally>".

## 4. Tracker and library
- News: add an `open` row for each new actionable item; set REOPENED on closed items with a material change; return snoozed rows whose date has passed to `open`. The news step never closes, snoozes or watches anything.
- Add a check to checks.json for every new actionable item (`KIT/schema/checks.schema.json`): `match` rules the scan can replay (`packages` with npm ranges or `"ecosystem": "pypi"`, `malicious_packages`, `runtimes`, `files`, `git`; machine-only checks in `match.machine`). Fill `status_by_project` from `match`.
- Auto-close only with clear-cut evidence, noted `auto: <run> YYYY-MM-DD — <evidence>`. A project-scoped item closes only when every project in `status_by_project` is done or not-affected. Never auto-close machine-only checks, GitHub-side or account state, manual actions, or anything from a partial result. Never touch snoozed or watching rows, or rows with a `user:` note, except to add findings.
- Hygiene rows `hygiene-<check>-<project>` (HIGH and MEDIUM, your projects only) and audit rows `audit-<project>` (open while it has any critical or high; note `C critical / H high: <names>`). They auto-close when fixed; a secret that was ever committed stays open until the user confirms rotation. Third-party clones get no rows.
- Audit baseline: for critical/high packages that are direct dependencies or in 2+ projects, raise the minimum in baseline.md, add a matching check to checks.json, and add a changelog line.
- Write projects.json. One changelog line per library change.

## 5. Two reports (briefing: news; scan: projects)
Markers in both: 🔴 CRITICAL — do today / 🟠 HIGH — this week / 🟡 MEDIUM — when you can / ⚪ LOW — optional.

**`STORAGE/briefings/YYYY-MM-DD-news.md`** (shareable, e.g. to Slack): never project names, paths, owners or findings.
```
# Security news — YYYY-MM-DD
## Summary
- 🔴 [ID] what — fix (one line per item, grouped 🔴 / 🟠 / 🟡 / ⚪)
### 🔴 CRITICAL (then 🟠 / 🟡 / ⚪)
- [ID] what it is — why it matters — general fix (source link)
Sources checked: one line per group (newest post date seen), honestly.
Verified: N items checked against sources, M corrected.
```
It never asks the user to act. Only if `news_scorecard` is on (default): affected items end with "→ see your to-do list", and the brief ends with "N of your projects may be affected — see your project report." Off: nothing hints at which items affect the user.

**`STORAGE/briefings/YYYY-MM-DD-projects.md`** (private):
```
# OccupAI projects — YYYY-MM-DD (Day) · daily | full
**Covers:** <start> → today [· Catch-up: ...] · **Projects:** N checked (C re-checked, R unchanged) · scan script v<x>
**Result:** <new items by priority> · <items that affect you, M projects> · <K closed> · <S still open>
## To do
### 🔴 CRITICAL — do today (then 🟠 / 🟡 / ⚪)
- [ ] [ID] <project>: action — why. <action line> (NEW) / (REOPENED) / (still open since YYYY-MM-DD)
## Check on your computer
<`computer` from `changed`>: one copy-paste line from open machine-scoped items, "paste the output back to me".
## Not checked
What, why, next step.
Tracker updates: | ID | Project | Old → new | Evidence | — say "reopen <ID>" to undo.
## Appendix
Per item: what happened · "quote" — source, date; affected and fixed versions; evidence; full audit lists.
```
In each group: news matches (including the briefing's quick-match rows in the tracker), then project findings (dependencies, secrets, workflows, agent settings, database rules, keys outside projects), then older open items. An action that fits two places appears once, in the first. On daily scans, add "Full refresh and audit: last full run <date>". Third-party clones and silenced projects: one info line each, in the appendix. Items the user marked done since the last report appear once, ticked, then drop off. **Quiet day:** if nothing is new, reopened or changed: the title, the Covers line, "Nothing new · K still open", and the last three sections. Then stop.

## 6. Finish
- Save both reports, tracker and library. If STORAGE can't be written, deliver them in your final message and say so.
- If `notifications.push` is on and your tool supports it: the final message, under `notifications.max_chars`. Skip it on quiet days unless `quiet_days` is true.
- Final message: copy this mode's template. Nothing else: no paragraphs, no other file names. If your tool can attach files in the chat (e.g. a file card), attach the report; otherwise give its path.
```
N new items · X may affect your projects → to-do list comes with the scan
🔴 [ID] headline (may affect: <project>)
🟠 [ID] headline
Report: briefings/DATE-news.md
```
Briefing: news only, no actions or fixes; up to ~10 headlines, most urgent first; "(may affect: …)" only where the quick match matched a project. Scorecard off: line 1 is "N new items", no "(may affect)".
```
<Result line>
🔴 [ID] <project or "your computer">: action — Fix: <step>
<check-on-your-computer line, if machine items are open>
To-do list: briefings/DATE-projects.md
```
Scan: every checkbox line of the to-do list, grouped by marker, up to ~12, then "N more in the to-do list". <step> is howto.md's action line ("open <project> in Claude Code and say: …" or "say 'how do I …?'").
