# Setup: Claude Desktop (scheduled tasks)

The primary path: open the kit folder in Claude Desktop and say **"Set up OccupAI"**. Claude follows [SETUP.md](../../SETUP.md) entirely in the chat: three questions, the projects it will watch, two scheduled tasks (briefing, then scan) created from the chat with your projects folder and (if outside it) the kit folder attached (or one message to paste into a new chat), then a question whether to run the first check now: you start each task yourself in your scheduled tasks. **This page is the developer fallback**: the manual steps, permissions and app settings behind that.

OccupAI is modelled on a setup the author runs daily in Claude Desktop. Setup and both tasks were tested end to end from this kit on one Mac (November 2026); please report anything that doesn't match on yours.

> Facts below were checked against Anthropic's docs on 2026-11-16 ([desktop scheduled tasks](https://code.claude.com/docs/en/desktop-scheduled-tasks), [permissions](https://code.claude.com/docs/en/permissions)). Labels in the app may change.

## How it runs (default: everything local)
OccupAI is **two local scheduled tasks** on your computer, every day: the **briefing** (news, library, a quick match of new checks) at `schedule.briefing`, and the **scan** (standing checks on new and changed projects, every check replayed) at `schedule.scan`. On `schedule.full_day` (Mondays by default) the scan also refreshes every project and runs the dependency audit. Both read your projects folder and write to the kit's `data/` folder.
- Local tasks "only fire while the app is open and your computer is awake". To keep runs from being skipped, turn on **Keep computer awake** in **Settings > Desktop app**. The docs also describe one catch-up run for the most recently missed time (within seven days). The prompts widen their window after missed runs either way.
- Local scheduled tasks need Claude Desktop 1.1.5368 or later.
- A task created from a chat runs in a device shell that sees each attached folder at `$HOME/mnt/<folder name>`. The task prompt says so, and the scan script maps the config's paths to those mounts itself.
- The scan waits for a briefing that is still running (`scan.py marker`), so the two never write the tracker at once, e.g. when both catch up after the computer wakes.
- Each shell call may be short-lived, so long steps use `--resume … --budget 100`, and the agent repeats a command until it stops printing `"status": "partial"`.

## 1. Prepare (once)
1. Download or clone the kit, e.g. to `~/code/occupai`.
2. Follow steps 3 to 5 of [SETUP.md](../../SETUP.md) yourself: create `KIT/data`, copy the config and templates, edit the config, and check the project list with `python3 scan.py discover`.

## 2. Create the tasks
You shouldn't need this: setup creates both tasks from the chat. Last resort, if the chat can't: in the **Code** tab, click **Scheduled** → **New task**, or describe the task in any session and Claude creates it. Create two tasks: "OccupAI briefing" daily at `schedule.briefing` and "OccupAI scan" at `schedule.scan` (e.g. 07:52 and 08:12: a few minutes before the hour, because on-the-hour runs can be delayed), each with the prompt below and its `Mode:` line filled in. Set the working folder to your projects folder, and make sure it can also read the kit folder and write its `data/` folder.

The prompt is the block in step 6 of [SETUP.md](../../SETUP.md) (one copy, so the two never drift apart).

## 3. Permissions
Scheduled runs can't wait for you: a run that needs approval stalls until someone answers it. Scheduled tasks use your Claude Code settings, and allow rules in `~/.claude/settings.json` apply. Run each task once with **Run now** (briefing first) and approve only these, choosing "always allow":
- `Bash(python3 <KIT>/scan.py:*)` (project checks)
- `WebSearch` and `WebFetch` (news; a local task has to be allowed to use the web)
- editing files under the kit's `data/` folder (`Edit(KIT/data/**)`)

Never allow package managers (`npm`, `pnpm`, `yarn`, `bun`, `pip`) or edits in your projects folder. As a backstop, add deny rules for `.env` and key files (see the [permissions docs](https://code.claude.com/docs/en/permissions) for path patterns). The script never opens them anyway.

## 4. First run and tracking
The first run checks every project, so it takes longer; later runs reuse unchanged projects. Reports appear in `KIT/data/briefings/`. To mark an item, open the kit folder in Claude and say "mark <ID> done", or edit `KIT/data/actioned.md`. To do it from any session, copy `skills/occupai` (and optionally `skills/security-baseline`) into `~/.claude/skills/` and use `/occupai mark <ID> done`.

## Uninstall
Delete the tasks in **Scheduled** (each task's prompt lives in `~/.claude/scheduled-tasks/<task-name>/`), then delete the kit folder (your data is in its `data/` folder).

## Advanced: cloud run (untested)
A cloud task runs even when your computer is off, but it starts from a fresh clone of attached repos and can't see your files. The same prompt then does the news part only and says "projects not checked; the next run will catch up". It needs shared storage. Minimum interval: one hour.
- **Private git repo as STORAGE:** clone it to `~/.occupai` and attach it to the cloud task, which commits and pushes its report, tracker and library. A local run starts with `git -C ~/.occupai pull --ff-only` and ends by committing and pushing (allow `Bash(git -C ~/.occupai:*)`).
- **Claude Project:** see [../storage.md](../storage.md). It depends on Project features that may change.
