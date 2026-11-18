# Storage

Everything OccupAI remembers is plain files in one folder, STORAGE: `data/` inside the kit folder by default (gitignored, marked with `.occupai-ignore` so it's never scanned). An older install that already has `~/.occupai/occupai.config.yaml` keeps using `~/.occupai`; `storage.path` in the config overrides both. Keep this folder when you update the kit: use `git pull`, or copy `data/` across to the new copy.

```
KIT/data/
  occupai.config.yaml         your config
  actioned.md                 the tracker: one row per item, edited by you and the agents
  actioned-archive.md         closed rows older than 30 days (moved, never deleted)
  briefings/
    YYYY-MM-DD-news.md      shareable news brief, from the briefing (no project names, paths or findings)
    YYYY-MM-DD-projects.md  private to-do list, from the scan (daily, or full on Mondays)
  library/
    checks.json      every item as a reusable check (schema/checks.schema.json)
    baseline.md      rules new projects start from (read by the security-baseline skill)
    changelog.md     one line per library change
    projects.json    the last list of projects, for onboarding
    stack.md         what your projects use ("scanning for"), written by each full run
    project-status.json  your decisions: inactive, not mine, managed elsewhere, skip
  state/             machine-written: scan-state.json, progress and output files
```

Nothing is sent anywhere by the kit itself. The agent you run reads these files and writes reports into them. The scan's state holds fingerprints, file names and finding types, never secret values.

## Local mode (default)
`storage.mode: local`. The run reads and writes STORAGE directly. Works when it runs on the same machine as your projects: Claude Code, Codex, other CLIs, or a Claude Desktop local task.

To keep history, make STORAGE a git repo and commit from your own terminal now and then. Scheduled runs shouldn't commit: they can't answer prompts, and a stuck commit can stall a run.

## Advanced: shared mode for a cloud run
A cloud run can't see your disk, so it does the news part only and says the projects weren't checked. Put STORAGE in a **private** git repo that the cloud task can clone and push to, and that your machine pulls before each local run. See [Claude Desktop, Advanced](setup/claude-desktop.md#advanced-cloud-run-untested). Untested in v0.1.

## Advanced: Claude Projects mode (Claude Desktop, untested)
`storage.mode: claude-project`. Instead of a folder, the briefings, tracker and library live as files in a Claude Project:
- The project's instructions say: "Read howto.md first. Briefings go in `briefings/`, the tracker is `actioned.md`, the library is in `library/`."
- Upload `prompts/howto.md` and the templates as the project's starting files.
- Run OccupAI from a session in the project that has your projects folder connected. Keep `state/` on your machine (`KIT/data/state`): it's machine data, not something to sync.
- Keep a local mirror of `library/` (`KIT/data/library`) so the `security-baseline` skill can read `baseline.md` in any project.

The author's own setup, which this kit is modelled on, keeps its state this way. The kit's version of it is untested, and it relies on Project features (file access and file updates from tasks) that Anthropic's public docs don't spell out, and that may change. If in doubt, use local mode.
