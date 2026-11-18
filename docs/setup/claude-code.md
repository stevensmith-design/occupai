# Setup: Claude Code (CLI)

> **Status: untested end to end.** Flags and rule syntax were checked against the [CLI reference](https://code.claude.com/docs/en/cli-reference), [headless](https://code.claude.com/docs/en/headless) and [permissions](https://code.claude.com/docs/en/permissions) docs on 2026-11-16.

Easiest: run `claude` in the kit folder and say **"Set up OccupAI"** ([SETUP.md](../../SETUP.md)). Claude Code can't create local schedules itself, so step 6 of SETUP.md ends with the cron or launchd lines below.

## Skills (optional)
```
mkdir -p ~/.claude/skills
ln -s ~/code/occupai/skills/occupai ~/.claude/skills/occupai
ln -s ~/code/occupai/skills/security-baseline ~/.claude/skills/security-baseline
```
Then `/occupai status`, `/occupai mark <ID> done`, `/occupai run`, `/occupai full`.

## Headless runs
Unattended runs can't answer prompts. `--permission-mode dontAsk` denies anything not pre-allowed instead of waiting. Use `Edit(...)` rules for writes (there is no `Write(...)` rule).
```
KIT=$HOME/code/occupai
ALLOW="Read,Glob,Grep,Edit(~/.occupai/**),Bash(python3 $KIT/scan.py:*),WebSearch,WebFetch"
DENY="Bash(npm:*),Bash(pnpm:*),Bash(yarn:*),Bash(bun:*),Bash(pip:*),Bash(pip3:*),Bash(rm:*)"
cd ~/.occupai
claude -p "/occupai $1" --add-dir ~/projects --allowedTools "$ALLOW" --disallowedTools "$DENY" \
  --permission-mode dontAsk --output-format text > state/last-run.log 2>&1
```
Pass `briefing` or `scan` as the script's first argument; the scan picks daily or full mode itself. Without the skill, pass the prompt instead: `claude -p "$(cat $KIT/prompts/run.md)" …`, with `OCCUPAI_CONFIG=~/.occupai/occupai.config.yaml` set.

## Schedule
Put the lines above in a small script (e.g. `~/bin/occupai-run.sh`, with absolute paths for `claude` and `python3`) and run it twice, at your config's `schedule.briefing` and `schedule.scan`.
- **cron:** `crontab -e`, e.g. `52 7 * * *  ~/bin/occupai-run.sh briefing` and `12 8 * * *  ~/bin/occupai-run.sh scan`. cron doesn't run jobs missed while the computer slept.
- **launchd (macOS):** a LaunchAgent with `StartCalendarInterval` runs a missed job when the Mac wakes.

The prompts widen their window after missed runs either way.

## Uninstall
Remove the cron lines or LaunchAgents, the skill links, `~/.occupai` and the kit folder.

## Advanced: cloud run
`/schedule` creates a cloud task (needs a claude.ai subscription login; minimum interval one hour). It can't see local files, so it does the news part only and needs shared storage: see [Claude Desktop, Advanced](claude-desktop.md#advanced-cloud-run-untested).
