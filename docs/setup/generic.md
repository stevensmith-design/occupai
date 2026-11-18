# Setup: other agents (Cursor CLI, Gemini CLI, …)

Any agent that can read files, run a shell command and search the web can run OccupAI. **Status: untested.** The pattern is the same everywhere: **cron + the agent's CLI + a prompt file + the scan script.**

## What each run can and can't see
- A **cloud** agent usually has web search but no local files: it does the news part only, if STORAGE is somewhere it can reach (a repo or synced folder).
- A **local** agent has your files but may have a restricted network. Full runs start the audit with `python3 scan.py route-check`, which says whether npm and PyPI can be reached, and lists anything not covered.
- Each shell call may be a short-lived sandbox. Long steps are resumable: `--resume <file> --budget 100`, repeated until the output stops saying `"status": "partial"`.

## Steps
1. Ask your agent to "set up OccupAI" ([SETUP.md](../../SETUP.md)), or do steps 3 and 4 of SETUP.md yourself. Skills are optional; the prompts work without them.
2. Point your agent at the one prompt, e.g.:
   ```
   cd ~/code/occupai
   <agent-cli> --prompt-file prompts/run.md       # flag names differ per tool
   ```
   Tell it the mode ("Mode: briefing" or "Mode: scan"); it reads `prompts/howto.md` and the config, and the scan picks daily or full mode.
3. Restrict tools to the minimum (names differ per tool):
   - Web search and fetch; read files; shell limited to `python3 /path/to/occupai/scan.py`; write only in `~/.occupai`. No package managers, no `rm`.
   - If your agent can't restrict the shell, run it in a container or VM that mounts your projects **read-only** and `~/.occupai` read-write.
4. Schedule with cron or launchd ([examples](claude-code.md#schedule)), twice a day: briefing at `schedule.briefing`, scan at `schedule.scan`.

## Without an agent
The scan script also runs on its own, without any AI:
```
python3 scan.py hygiene --config ~/.occupai/occupai.config.yaml --out ~/.occupai/state/hygiene-out.json
python3 scan.py match   --config ~/.occupai/occupai.config.yaml
python3 scan.py audit   --config ~/.occupai/occupai.config.yaml --out ~/.occupai/state/audit-out.json
```
You get JSON instead of a report, and no news, but the read-only guarantees are the same.
