# Set up OccupAI (instructions for the AI agent)

Speak plainly: the user may not be technical. KIT is this file's folder (absolute path). Everything happens in this chat (step 6's first run aside): never send the user to app menus, settings or permission lists. The hard rules in `KIT/prompts/howto.md` apply; every stop ends with one step and "reply **try again**".

## 1. Check Python
Run `python3 -c "import sys; print(sys.version_info >= (3, 9))"`. If it's missing or prints `False`, say: "OccupAI needs Python 3.9 or newer. On a Mac, run `xcode-select --install` in Terminal, then reply **try again**."

## 2. Ask three questions
In one message, as multiple choice:
1. **Which folder holds your projects?** "~/Desktop (Recommended)" · "Show me the folders and I'll pick" · "Let's talk it through". Never suggest the home folder or copies of repos (e.g. `~/worktrees`).
2. **What time should it run each day?** Default 08:00. Hint: "pick a time your computer is usually on".
3. **Notifications?** Default: on.

"Show me the folders": its top-level folders as a numbered list, one per line, in two groups: **Projects** and **Looks like a backup or copy, skipped unless you pick it** (backup, archive, copy, old or dated names). Reply with numbers, names or "all suggested". Several folders: use their common parent and exclude the rest. Say: "New folders in <projects folder> are watched automatically until you tell me to skip them."

## 3. Folder access and the data folder
Check the projects folder exists (suggest close matches for typos). Say "Stay on this chat for a moment: a pop-up will appear for each folder. Tick 'Don't ask again' and click Allow.", then request access to it yourself. If KIT isn't inside the projects folder, add KIT to that request: the daily tasks need it too. Refused? "This often happens if you switched away. Reply **ask again**." Then: "Or add them with + → Add folder"; "Or run setup from Claude Code on this folder". Then:
```
mkdir -p KIT/data/briefings KIT/data/library KIT/data/state && touch KIT/data/.occupai-ignore
[ -e KIT/data/occupai.config.yaml ] || cp KIT/occupai.config.example.yaml KIT/data/occupai.config.yaml
[ -e KIT/data/actioned.md ] || cp KIT/templates/actioned.md KIT/data/
for f in checks.json baseline.md changelog.md; do [ -e KIT/data/library/$f ] || cp KIT/templates/$f KIT/data/library/; done
```
Nothing is overwritten. If `~/.occupai/occupai.config.yaml` exists (older install), use `~/.occupai` instead of `KIT/data`.

## 4. Write the config
In `KIT/data/occupai.config.yaml`, change only: `kit_path` (KIT), `projects_root` (1), `timezone` (IANA; on a Mac, after `zoneinfo/` in `readlink /etc/localtime`), `schedule.briefing` (2 as cron, a few minutes early: 07:52 for 08:00), `schedule.scan` (20 minutes later), `schedule.full_day: monday`, `notifications.push` (3), `computer` (macOS, Windows or Linux: the user's, not a sandbox; ask if unsure). If KIT is inside the projects folder, add it to `exclusions`.

## 5. Show what it will watch
Run `python3 KIT/scan.py discover --config KIT/data/occupai.config.yaml`. Show, in one message:
- **Projects I'll watch:** `[x] name` lines; `"watch": false` entries (backups, copies) as `[ ] name (why)`.
- **Scanning for:** each `scanning_for` tech with its projects.
- **Which GitHub usernames and organisations do you work in** (yours, clients', employer's)? List `github_owners`; per owner: "mine" · "a client or employer org: watch it, but as someone else's (info)" · "not mine".

`kit.attach_to_tasks` true: KIT needs access and attaching too. Ask **"Anything to add or remove?"** Add unticked or removed folders to `exclusions`, set `my_owners` (or `[]`), run `python3 KIT/scan.py project <name> managed` for each project whose `owner` is a client or employer org, and re-run `discover` until the user agrees.

## 6. Schedule two tasks
1. Create **two** local scheduled tasks yourself, from this chat, with the prompt below: "OccupAI briefing" daily at `schedule.briefing` (Mode: briefing) and "OccupAI scan" 20 minutes later (Mode: scan). Attach exactly the folders approved in step 3: `projects_root`, plus KIT if outside it. Never attach individual projects, even if only some are watched: exclusions handle that, and new projects are picked up automatically. Never start tasks or create helper or one-off tasks: Scheduled must show only these two. If you can't, give **one message to paste into a new Claude Desktop chat**: "Create local scheduled tasks <both, as above>, with this prompt: <prompt>." Last resort: Claude Code on the kit folder; other tools: `KIT/docs/setup/`.
2. End with one question: "Run the first check now? (Recommended, about 10–20 minutes.) Open OccupAI briefing in your scheduled tasks and run it now. When its notification arrives, run OccupAI scan the same way. Or skip it, and it runs tomorrow at <briefing time>." Add: "You'll be asked once to let OccupAI read your projects, save reports in the OccupAI folder and look up security news: choose 'always allow' so daily runs never get stuck."

```
Run OccupAI unattended. Mode: <briefing|scan>. Don't ask questions; decide, note it, finish.
KIT = <absolute path>. Config: KIT/data/occupai.config.yaml; STORAGE = KIT/data.
If a folder (projects, KIT) isn't at its usual path, it's at $HOME/mnt/<folder name>.
Read KIT/prompts/howto.md, then follow KIT/prompts/run.md.
Read only: never install, run project code, open .env or key files, or print secrets.
Check projects only with `python3 KIT/scan.py`. Write only in KIT/data.
```

## 7. Finish: tell the user
- To mark something handled, say "mark <ID> done" (or "not affected", "snooze until <date>") in a chat on the OccupAI folder.
- The briefing writes a shareable news brief; the scan, your private to-do list.
- Changing watched folders makes the next full run re-check every project (10–20 minutes).
- Keep the kit folder: `data/` holds your reports and tracker. To update: `git pull`, or copy `data/` across.
- Uninstall: delete both tasks in Scheduled, in Claude's sidebar, then the kit folder.
