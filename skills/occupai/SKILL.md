---
name: occupai
description: Run or query OccupAI, a daily security check-in for people who build with AI. Use for "run", "briefing", "scan", "full", "scan only <project>", "status" or "mark <ID> <status>", or when the user asks about their security briefing, open security items, or wants to mark a security item as done, not affected, snoozed or watching.
argument-hint: run | briefing | scan | full | only <project> | status | mark <ID> <status>
---

# OccupAI

OccupAI is a small set of read-only agent automations: two daily tasks (a briefing: news, library and a quick match; then a scan: standing checks on changed projects, on full days a full refresh and dependency audit), an action tracker and a security library. This skill is the entry point for running one by hand or for checking and updating the tracker.

## Find the files
1. **Config:** `$OCCUPAI_CONFIG`, else `~/.occupai/occupai.config.yaml`, else `data/occupai.config.yaml` in the kit, else `occupai.config.yaml` in the current folder. If none exists, OccupAI isn't set up yet: follow `SETUP.md` in the kit (it asks the user a few questions first).
2. From the config: **KIT** = `kit_path` (the cloned kit), **STORAGE** = `storage.path` (default: the config's folder).
3. **SCAN** = `python3 KIT/scan.py`. It is read-only and uses the Python standard library only.

## Commands (first word of the arguments)

### `run`, `briefing`, `scan`, `full`, `only <project>`
Read `KIT/prompts/howto.md`, then follow `KIT/prompts/run.md`. `run` does the briefing, then the scan; `briefing` or `scan` does one (the scan picks daily or full); `full` forces a full scan; `only <project>` is a full run with `--only <project>`. Needs web search and a shell on the machine where the projects live.

### `status`
Read-only summary; don't run any scan.
1. Run `SCAN tracker list`.
2. Reply with: counts by status; every `open` and `REOPENED` row grouped by priority if the latest `*-projects.md` report gives one (🔴 / 🟠 / 🟡 / ⚪), one line each, as `[ID] item (since <date>) — note`; snoozed rows with their dates; the dates of the latest daily and full reports in `STORAGE/briefings/`, flagging any that look missed.

### `mark <ID> <status>`
Status is one of `open`, `done`, `not-affected`, `watching`, `snoozed until YYYY-MM-DD`. Accept natural wording ("not affected", "snooze until Dec 1") and convert it.
1. Run `SCAN tracker mark <ID> <status> --note "<short reason if the user gave one>"`. It writes a `user:` note, so the scan won't auto-change that row later.
2. If the ID doesn't exist, show the closest IDs from `SCAN tracker list` and stop.
3. If the user marks a machine-scoped item done (e.g. after checking `node -v`), also set `status_machine` in `STORAGE/library/checks.json` and add a line to `STORAGE/library/changelog.md`.
4. Confirm in one line: `[ID] old → new`.

## Rules
- Everything is read-only for the user's projects. Never install packages, run project code, or open `.env`, key or credential files. Never print secret values.
- Only write inside STORAGE.
- An AI does the research and can miss things. Say what wasn't covered rather than implying full coverage.
