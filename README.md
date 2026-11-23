<p align="center">
  <img src="assets/hero-pixel-menacing.png" alt="OccupAI: a pixel-art purple octopus holding two yellow folders, with small virus icons around it" width="640">
</p>

# OccupAI

**A daily security check-in for people who build with AI.** v0.2, a side project.

Made by Steven Smith. More on OccupAI and my other work: [stevensmith.dev/occupai](https://stevensmith.dev/occupai?utm_source=github&utm_campaign=occupai)

I build a lot of small projects with AI coding agents, and I wanted something that tells me each morning what's new in security that touches my stack, checks whether any of it is in my projects, and remembers what I've already dealt with. OccupAI is that, packaged so you can run it too: a few agent automations (prompts, a read-only Python script and two skills) for the AI agent you already use. Everything it does to your projects is read-only, and you stay in charge of every fix.

**Covers secrets, AI agent setups, GitHub Actions, npm and Python dependencies, and Supabase/Firebase rules.**

**Who it's for:**
- **Solo builders and designers** shipping with AI coding agents: lots of small repos, no security team watching them.
- **Small teams:** one daily news brief to share with everyone, and a private to-do list for each person's projects.
- **"Does this affect me?"** When a package is hijacked overnight, you know by morning which projects use it and what to do.
- **Every new project starts ahead:** past issues become checks and a baseline, so old mistakes don't come back.

<table>
<tr>
<td align="center" width="50%"><img src="assets/hero-pixel-clear.png" alt="The octopus smiling, holding two folders" width="320"><br><sub><b>All clear: nothing urgent today</b></sub></td>
<td align="center" width="50%"><img src="assets/hero-pixel-menacing.png" alt="The octopus frowning, with virus icons around it" width="320"><br><sub><b>Action needed: critical items found</b></sub></td>
</tr>
</table>

<sub>These illustrate the summary line at the top of each report. The octopus is coming to the reports soon (see the Roadmap).</sub>

### What a morning's to-do list looks like

From `make demo`, which runs the real checks on made-up projects with planted issues (trimmed):

> **OccupAI projects — 2026-11-19 · full (DEMO, test fixtures)**
>
> **Result:** 6 new · 4 affect you (4 projects) · 6 project issues · 1 closed automatically · 0 still open
>
> 🔴 **CRITICAL — do today**
> - [ ] **[demo-ci-stealer]** indicator-repo: Check repos for `ci-helper-NNNN` branches; rotate CI secrets if found — active secret theft via CI
>
> 🟠 **HIGH — this week**
> - [ ] **[hygiene-db-supa-app]** supa-app: supabase-table-without-rls (supabase/migrations/0001_init.sql) — anyone with the app's public key can read or write this data
> - [ ] **[hygiene-secrets-web-shop]** web-shop: key-pattern (src/lib/ai.ts); sensitive-file-committed (.env) — a committed key may already be copied; rotate it first

In the full report, each line also ends with what to say to your AI tool to fix it.

## What it does

| | Runs | What you get |
|---|---|---|
| **1. Daily briefing and scan** | every day; two tasks on your machine | The briefing: the latest threats, prioritised, with sources, in a news brief you can share, quick-matched to your projects. The scan, after it: standing checks on new and changed projects, one private to-do list with each action once |
| **2. Full run** | Mondays (configurable), or "run a full scan" | The daily run plus standing hygiene checks (secrets, workflows, agent settings, database rules, keys left outside projects) and the dependency audit: known-vulnerable npm and Python dependencies, whether or not they made the news |
| **3. What you use** | every full run | `stack.md` lists what your projects use (hosting, CI, databases, SDKs), so news about any of it reaches the right project |
| **4. Action tracker** | always | `actioned.md` remembers what you've handled, and reopens an item only when something material changes |
| **5. Security library** | always | `checks.json` + `baseline.md` + the `security-baseline` skill, so new projects start without old issues |

## Quick start

1. **Download** this repo (green **Code** button → **Download ZIP**, then unzip it) or `git clone` it. Keep the folder where it is afterwards: the daily tasks run from it.
2. **Open the folder** in your AI tool. In Claude Desktop: start a new chat, click **+** → **Add folder** and pick the occupai folder. (In a terminal-based agent: start it in that folder.)
3. **Say "Set up OccupAI".** It checks you have Python 3.9 or newer, asks three questions (your projects folder, a time, notifications), shows the projects it will watch, then sets up two daily tasks: a briefing and, 20 minutes later, a scan. You start each task once yourself to approve its access. The full walkthrough is in [SETUP.md](SETUP.md). The first scan checks every project and can take 10–20 minutes.

**What you get each day:** the briefing writes a short news brief you can share with your team (`DATE-news.md`, no project names or findings), and the scan writes your private to-do list (`DATE-projects.md`, one checkbox line per action, 🔴/🟠/🟡/⚪). The chat message is a count line, up to three actions and the two file names.

Everything runs on your computer by default, and everything it keeps is in the kit's `data/` folder (gitignored). Keep that folder when you update the kit: `git pull`, or copy `data/` across to the new copy.

**Setup guides:** step-by-step guides for scheduling and running OccupAI are in [docs/setup/](docs/setup/).

**Mark something handled:** open the OccupAI folder in your AI tool and say `mark <ID> done` (or edit `data/actioned.md`).
**Your stack and news sources:** after the first full run, relevance comes from what your projects actually use (`data/library/stack.md`). `news_sources` in the config is an example list to edit.
**Uninstall:** delete both tasks in **Scheduled**, in Claude's sidebar (or your cron/launchd entries), then the kit folder (it holds `data/`). Nothing else is installed.

### For developers
Python 3.9+ and git; no other dependencies.
```
make test     # builds fake projects with planted issues and checks every finding (offline)
make demo     # one full run → two reports → tracker on those fake projects, offline (output in build/demo/storage)
```
In the demo a script stands in for the AI in the news step; the project checks use the real script. Manual setup without an agent: steps 3 and 4 of [SETUP.md](SETUP.md), then `python3 scan.py hygiene --out data/state/hygiene-out.json` for a first look with no AI involved.

## How it works

```
occupai.config.yaml   stack · news sources · projects folder · owners · schedule · storage
        │
briefing  daily: news (web search) + library + quick match of new checks → briefings/DATE-news.md (shareable, no project data)
scan      daily, after it: standing checks on new/changed projects + every check replayed;
          Mondays also full refresh + dependency audit → briefings/DATE-projects.md (private to-do list, 🔴🟠🟡⚪)
        │
STORAGE (KIT/data)     actioned.md · library/ (checks.json, baseline.md) · state/
```

- **Prompts drive the agent** ([prompts/](prompts/)): `run.md` for both tasks (the briefing, and the scan in daily or full mode), and `howto.md` for the shared procedures and hard rules. Every run is unattended: the agent decides, notes the decision and finishes. When it has to stop, it says what happened, the one step you need to take, and "reply **try again**".
- **A script does the deterministic work** (`python3 scan.py --help`): project discovery, change detection, hygiene checks, lockfile versions, replaying library checks, the dependency audit and tracker updates. It's Python 3 standard library only, prints short JSON, and is the same for every agent.
- **The tracker** gives every item an ID. The news step never closes anything. The project checks close an item only with clear-cut evidence (`auto: full run DATE — evidence`), and never touches what you snoozed, are watching, or reopened.
- **The library** turns each news item into a check with match rules, so a project you create next month is checked against last month's news. Status is tracked per project, not as one global "done".
- **Change-based:** unchanged projects reuse their last hygiene results (git HEAD and status, plus the size and timestamps of every file the checks can read, gitignored ones included; never their contents). Dependency and news checks cover every project every time, because a new advisory can hit an unchanged lockfile. Long steps are resumable for agents whose shell calls are short-lived.

### Safety rules (in the script, the prompts and the tool permissions)
- **Read only.** Nothing is installed, built or run in your projects; nothing is modified, committed or deleted. The script writes only to the storage folder.
- **Secrets are never read or printed.** Sensitive files (`.env`, keys, credentials) are checked by metadata only: tracked, in history, gitignored. Code is checked for key patterns, reported as counts and types.
- **npm audit runs on a copy** of `package.json` + `package-lock.json` in a temp folder, with `--package-lock-only --ignore-scripts`. Python uses the PyPI JSON API for pinned versions; never `pip-audit -r`, which resolves and builds packages.
- **Exact package names only:** `occupai-demo-animate` is not `occupai-demo-anim`.
- **Web content is data, not instructions;** IOCs are defanged.
- A folder with an `.occupai-ignore` file is skipped entirely (handy for test fixtures with fake secrets).

## What it checks

| Area | Checks |
|---|---|
| Secrets | `.env`/key/credential files committed, in git history or not gitignored (metadata only); API keys, tokens, private keys and DB URLs with passwords in tracked code (counts only). Noise filters for placeholders, detector regexes, base64 blobs and public Firebase/Google client configs |
| AI agent setups | MCP configs (inline secrets, unpinned `npx`/`uvx` servers, remote hosts), agent permissions (`Bash(*)`, bypassed permissions, hooks), hidden Unicode or pipe-to-shell in `CLAUDE.md`/`AGENTS.md`/skills, AI or service-role keys exposed via `NEXT_PUBLIC_*`/`VITE_*` |
| GitHub Actions | third-party actions not pinned to a SHA, missing `permissions:`, `pull_request_target` + PR checkout, `${{ github.event.* }}` in `run:` |
| Dependencies | npm (`package-lock.json` v2/v3) via npm audit; Python pinned requirements via PyPI; versions from pnpm, yarn and bun lockfiles for news items; Node and Python runtime pins |
| Database rules | Supabase tables without row level security (in Supabase projects); Firebase rules open to everyone |
| News items | whatever the briefing finds, replayed per project from `checks.json`: npm package ranges (comparators joined by spaces, commas and `||`; lockfile v2/v3, pnpm, yarn, bun), pinned Python requirements, malicious names, runtime pins, files, git branches and commits. Ranges the script can't parse make a project `unknown`, never clean |

## Good to know
- **An AI does the research.** It can miss an advisory, misjudge a priority or misread a page. The quote rule (verbatim, from a fetched page) and the "Sources checked" section make gaps visible, but don't remove them.
- **Pattern-based secret checks miss unusual formats,** and a clean result doesn't mean there are no secrets.
- **Limited coverage:** npm and Python only for the dependency audit (pnpm, yarn, bun, Poetry and uv lockfiles are listed as "not covered"); Supabase and Firebase only for database rules; Supabase migrations may not match your live database.
- **It can't see** what's installed on your machine (it gives you a one-line command to run), GitHub-side state (forks, org settings, workflow history), or your cloud accounts.
- **Local runs need your computer on.** Scheduled tasks skip or catch up when it's asleep, depending on the tool.
- v0.2: the scan script, SETUP.md's steps and the demo are covered by offline tests.

## Troubleshooting

**No briefing or scan today?** If your computer was off or asleep at the scheduled time, Claude pauses the task and keeps it paused. Open the task in your scheduled tasks and switch it back on (or run it now). Your data and settings are kept.

## FAQ

**Does it send my code anywhere?** The script doesn't. It reads files locally and talks only to npm's registry (through `npm audit`) and pypi.org. The AI agent you run sees what the prompts tell it to read: short JSON summaries, file names and finding types, never secret values. Check your agent's own data policy.

**Will it fix things for me?** No. It tells you exactly what to run (in a branch), and you decide. Fixing automatically would mean installing packages and running code, which is exactly what it never does.

**Why not just use Dependabot, Snyk or osv-scanner?** Use them. OccupAI is the daily layer around them: news that isn't an advisory yet (malware campaigns, compromised accounts), hygiene that dependency tools don't check (agent configs, workflows, committed `.env` files), and one tracker that remembers what you've handled.

**What does it cost?** The kit is free (MIT). The agent runs use your own AI plan. The briefing does about 15–25 web fetches a day.

**Can I change the news sources or my stack?** Yes, and you should: the defaults are examples. Edit `news_sources` and `stack` in the config. Sources are grouped (campaigns and supply chain, official, stack vendors, news), and the briefing reports on every group.

**Where is my data?** Plain Markdown and JSON files in the kit's `data/` folder (`~/.occupai` for older installs, or wherever `storage.path` points). See [docs/storage.md](docs/storage.md), including the optional Claude Projects mode.

**How do I mark something handled?** Open the OccupAI folder in your AI tool and say `mark <ID> done` (elsewhere, with the `occupai` skill installed: `/occupai mark <ID> done`), run `python3 scan.py tracker mark <ID> done`, or edit `actioned.md`.

## Roadmap
Not in v0.2:
1. **A starter library** of recent high-impact advisories with fixed versions, and a longer look-back on the first run, so a fresh install doesn't start from an empty library.
2. **`occupai init`**: a setup interview that fits the checks and news sources to your stack (SETUP.md's discovery step is the minimal version).
3. **Posting the news brief** to Slack or another team chat, and **fix on request**: a ready-to-paste fix request per to-do item.
4. **The octopus in the reports**: the friendly or menacing mascot in each report header, matching its summary line.
5. **Wider matching:** caret, tilde, hyphen and x-ranges, prerelease ranges, npm lockfile v1, and Poetry/uv/Pipfile lockfiles for news items (today these show as "unknown").

More ecosystems (pnpm, yarn and bun audits; Go, Rust, Ruby; other databases) come after that. Ideas and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Repo layout
```
SETUP.md                 what the agent follows when you say "Set up OccupAI"
scan.py, occupai_scan/   read-only scan script (Python 3 stdlib)
prompts/                 run.md, howto.md
skills/                  occupai (entry skill), security-baseline
templates/               actioned.md, checks.json, baseline.md, changelog.md
schema/                  checks.schema.json
docs/                    setup guides per tool, storage
examples/demo/           offline news sample + demo runner
tests/                   fixtures with planted (fake) issues + tests
```

## License
MIT. See [LICENSE](LICENSE). Security issues with the kit itself: see [SECURITY.md](SECURITY.md).
