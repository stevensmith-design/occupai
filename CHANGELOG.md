# Changelog

## Unreleased
- **"Needs you" group:** in the to-do list and the scan's chat message, items the scan can't check itself (your computer, GitHub or other online accounts, live dashboards like Supabase) are grouped under "Needs you (outside what the scan can see)", after the project findings, which stay first and unlabelled. The section replaces "Check on your computer" and keeps its copy-paste line; Fix lines are unchanged.
- **README troubleshooting:** what to do when no briefing or scan arrived (Claude pauses a task the computer was off or asleep for; switch it back on or run it now).
- **Priority changes are explained:** an item or CVE reported earlier at another priority is marked UPDATED with the reason in a few words (e.g. "🔴 → 🟠: no exploitation reported; patch widely available"); with no reason, the earlier priority stays. Replaces "reuse each open item's priority".
- **Every CVE of a multi-CVE issue is listed:** when a source names a set of CVEs for one issue (e.g. five nginx CVEs in one write-up), the briefing item lists all of them, each with its affected configuration in a few words, only as the source states them. Paid for by cutting text `run.md` and `howto.md` repeated from each other.
- **First-day items say (NEW) (#20):** an item first reported in today's run is marked (NEW) in the to-do list; "(still open since <date>)" is only for items first reported on an earlier day.
- **Build output is skipped everywhere (#18):** Xcode `SourcePackages` and `DerivedData`, SwiftPM `.build`, `.gradle`, `.svelte-kit`, `.nuxt` and `.output` join the folders that are never read (`build`, `dist`, `.next`, `out`, `Pods`, `target` already were). Xcode and SwiftPM checkouts in these folders can hold other projects' example lockfiles. The audit lists the generated folders it skipped (`generated_skipped`), and the scan names them in one line under "Not checked".
- **Unaudited ecosystems are named (#19):** the audit lists every Dart, Ruby, Go, Rust, CocoaPods, PHP, Swift, Gradle, .NET or Elixir lockfile (or manifest, when there's no lockfile) as `not_covered`, per folder, so a project that uses one is never reported as fully checked. The scan puts them under "Not checked" (e.g. "Dart: not audited").
- **A project the task can't read is never "unchanged" (#2):** a project folder that is empty or can't be listed here (a folder not attached to the task can look like that) is `not_reachable` in `changed`, and hygiene, the audit and news matching report it as not checked instead of clean. The scan lists it under "Not checked" with "attach the projects folder to both tasks". Scanner version 0.1.8: saved results are re-checked once.
- **Release placeholders filled:** the checks schema `$id` points to the raw file on GitHub, and the Codex guide clones from github.com/stevensmith-design/occupai.
- **CI:** runs on `ubuntu-24.04`, because `ubuntu-latest` moved to 26.04 without Python 3.9 and every run failed; `fail-fast: false`, so one failing Python version no longer cancels the others.
- **Briefing accuracy (issue 23):** attribution (country, group), victim and impact numbers, "actively exploited" and "malicious" are stated only as the fetched source states them. Before saving the news brief, each 🔴 and 🟠 item's headline and fix line is checked against its source and corrected or removed; a 🔴 item that calls a package malicious re-opens its primary source once ("not re-confirmed" if it can't). The brief adds "Verified: N items checked against sources, M corrected" under "Sources checked". Paid for by cutting rules `howto.md` repeated from `run.md`.
- README: links to stevensmith.dev carry `utm_source=github` and the repo name, so visits from the repo can be counted.
- **README:** a "Made by" line linking to stevensmith.dev/occupai; a trimmed excerpt of the `make demo` to-do list under the pictures; Quick start step 3 cut to two sentences (SETUP.md keeps the detail); `mark <ID> done` in backticks, because GitHub dropped `<ID>` as an HTML tag.
- **Setup, from fresh-install test 3:** both tasks get exactly the folders approved in step 3 (the projects folder, plus the kit if it's outside it), never individual projects, which left every folder showing "needs approval". The agent no longer starts the tasks (agents can't use "Run now"): setup ends by asking whether to run the first check now and tells the user how to start the briefing, then the scan. Setup no longer waits on the briefing marker itself; the scan prompt already handles overlap.
- **Final chat message:** `run.md` gives one literal template per task, and "nothing else: no paragraphs, no other file names". The briefing's is news only: a count line, up to ~10 headlines (with "may affect: <project>" where the quick match found one) and the news report. The scan's puts the to-do list in the chat: the Result line, every checkbox line with its fix step (up to ~12, then "N more"), the check-on-your-computer line, and the to-do list file. Where the chat can attach files, the report is attached.

## 0.1.0 (2026-11-18): first public release
OccupAI is a daily security check-in for people who build with AI: a few read-only agent automations, a Python script (standard library only) and two skills.

- **Setup in one chat.** Open the kit folder in Claude Desktop and say "Set up OccupAI". It checks Python, asks three questions (projects folder, time, notifications), asks for folder access itself, shows the projects it will watch (backups and copies unticked) and what they use, asks which GitHub usernames and organisations you work in, then creates two scheduled tasks from the chat and runs each once while you're there. Everything it keeps is in the kit's `data/` folder (gitignored, never scanned), so setup needs no extra folder; an older install's `~/.occupai` is still used.
- **Two daily tasks.** The scan waits if the briefing is still running. The **briefing** reads security news from every source group, turns each actionable item into a reusable check, and quick-matches new checks against your projects. The **scan**, 20 minutes later, runs standing checks on new and changed projects and replays every check; once a week (Monday by default) it refreshes every project and runs the dependency audit.
- **Two reports.** `DATE-news.md`, a news brief you can share (a one-line-per-item summary grouped 🔴/🟠/🟡/⚪, then the details; no project names, paths or findings), and `DATE-projects.md`, your private to-do list: one checkbox line per action, each action once, then "Check on your computer", "Not checked" and an appendix. The chat message is a count line, up to three actions and the two file names.
- **What it checks:** secrets (metadata and counts only, never values), AI agent setups (MCP configs, permissions, instruction files), GitHub Actions, npm and Python dependencies, Supabase and Firebase rules, key files left outside projects, and runtime versions. It records what your projects use, so news about any of it reaches the right project.
- **Tracker and library:** `actioned.md` remembers what you've handled ("mark <ID> done", "not affected", "snooze until <date>"); your decisions about a project (inactive, not mine, managed by someone else, skip) apply to every check. The library replays past news against new projects.
- **Read only, always.** Nothing is installed, built or run in your projects, and nothing there is changed. Every stop ends with what happened, one step for you, and "reply **try again**".
- **Tested:** the scan script and setup steps offline (`make test`), the offline demo (`make demo`), and setup plus both tasks end to end in Claude Desktop on one Mac. **Untested:** the Claude Code, Codex and generic-agent guides, and cloud runs with shared storage.

Scanner version 0.1.6 (the script's own version; a change makes saved results be re-checked once).

## Development history (before 0.1.0)
The 0.1.x numbers below are scanner versions from the private build.

### Final pre-release fixes (round 5)
- **Kit outside the projects folder:** setup asks for access to the kit folder too and attaches it to both tasks (or the user moves the kit into the projects folder); `discover` reports `kit` (`found`, `inside_projects`, `attach_to_tasks`), and the task prompt's mount line covers the kit. Before this, a kit unzipped in Downloads made every scheduled run fail.
- **Shareable brief:** the per-item "→ see your to-do list" markers now follow `news_scorecard`, like the closing count; off means the brief gives no hint of which items affect you.
- **Briefing/scan overlap:** `scan.py marker start|done|check|wait` keeps a `state/briefing-running` marker (stale after 30 minutes, overwritten rather than deleted). The briefing sets it; the scan, and "start the scan" in setup, wait for it.
- **Script only:** projects are checked only through `scan.py`; what it can't express is "not checked". README says how to open a folder in Claude Desktop and where to delete the tasks.

### Release readiness (round 4)
- Setup: "stay on this chat" before the folder pop-ups, "ask again" after a refusal; long folder lists as a numbered list in two groups (projects, backups or copies); no helper or one-off tasks: after the first briefing, the user replies "start the scan"; schedule a few minutes before the chosen time (default 07:52 and 08:12).
- Reports: a compact summary at the top of the news brief; the chat message is a count line, up to three actions and the two file names; one plain line when a framework bundles vulnerable code with no confirmed fix; never a rule matching every version; key files named as files.
- Docs describe two tasks and two reports, and what is tested.

### 0.1.6 (unreleased): fix round 3b (two tasks)
- **Back to two automations:** `run.md` has two modes. **briefing** (daily): news from every group, library checks added or updated, and a quick match of today's new and updated checks against every project (`scan.py match --ids`); writes the shareable `DATE-news.md`. Matches go into the tracker as actions; the brief never asks the user to act ("→ see your to-do list"). **scan** (daily, after the briefing; "scan now" on demand): standing checks on new and changed projects plus a replay of every check, and on the full day a full refresh and the dependency audit; writes `DATE-projects.md`, the one action list.
- **Config:** `schedule.briefing` and `schedule.scan` (default 08:00 and 08:20) replace `schedule.run`.
- **Setup** creates two tasks from the chat, "OccupAI briefing" and "OccupAI scan" 20 minutes later, with the same folders attached and one shared prompt with a `Mode:` line; it runs both once, briefing first. Guides, README and the `occupai` skill (`run` = briefing then scan; `briefing`, `scan`) updated.
- Prompt words: total 4718 (budget 4749 = round 3's 4599 + ~150).
- Tests: two-task checks in `tests/test_round3.py`; 163 tests, ~138 s.

### 0.1.6 (unreleased): fix round 3 (fresh install test, 2026-11-18)
Scanner version 0.1.6: saved hygiene results are re-checked once.

- **Two outputs per run:** `briefings/YYYY-MM-DD-news.md`, a shareable news brief grouped 🔴/🟠/🟡/⚪ (`[ID] what — why it matters — general fix`, source link; never project names, paths, owners or findings; optional last line "N of your projects may be affected", config `news_scorecard`, default on), and `briefings/YYYY-MM-DD-projects.md`, a private checkbox to-do list grouped by priority (`- [ ] [ID] <project>: action — why` + fix line, (NEW) / (REOPENED) / (still open since DATE)), then Check on your computer, Not checked, tracker updates, and an appendix with the details. The chat message is the top 3 actions and the two file names.
- **Dependency audit in the report:** counts and the top 3 fixes per project. `audit` adds `mostly_in` when most of a project's vulnerable packages sit in one sub-folder, and `scan.py project <project>/<folder> inactive|not-mine|managed` quiets that sub-folder's dependency findings (listed under `silenced`, never new or fixed).
- **Unknown project status:** a project with critical/high items and no decision gets one line: "Is <project> still active or deployed?"
- **Setup:** folder question with "~/Desktop (Recommended)" · "Show me the folders and I'll pick" · "Let's talk it through"; time hint "pick a time your computer is usually on"; a "client or employer org" answer per GitHub owner that sets those projects to `managed` (`discover` now names each project's `owner`); folder access requested by the agent itself after saying what the pop-ups look like, with paths checked first and recovery options "ask again" → "+ → Add folder" → Claude Code; the task is created from the chat with the projects folder and `~/.occupai` attached (Code tab only as a last resort); new folders are watched until skipped.
- **Chat-created tasks:** their device shell sees attached folders at `$HOME/mnt/<folder name>`. The script finds the config there and maps configured paths that aren't present to those mounts; the task prompt carries one line saying so.
- **npm certificates:** the isolated npm audit gets a system CA bundle via `NODE_EXTRA_CA_CERTS` (from `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` or the usual system paths) and always `strict-ssl=true`; `route-check` prints `ca_bundle`.
- **Your computer's OS:** config `computer` (set at setup) wins over detection, so a run in a sandboxed shell no longer reports the sandbox's OS.
- Prompt words: total 4599 (budget 4605, held at the round 2 total); SETUP.md 814.
- Tests: `tests/test_round3.py`; round 2 report-shape tests updated to the two files.

### 0.1.5 (unreleased): fix round 2, stage C (setup)
- **Discovery before the first scan:** `scan.py discover` lists the projects it would watch, with folders that look like backups or copies (backup, archive, copy, old, `_to_delete`, a full date or `(2)` in the name) unticked with a reason; what they use ("scanning for", with what is checked locally vs news only); and the GitHub owners seen. Setup shows both lists, asks "anything to add or remove?" and asks which GitHub usernames and organisations the user works in (theirs, clients', employer's). Unticked folders go to `exclusions`.
- **Scheduling in the chat only:** the agent creates the one scheduled task itself, or gives one message to paste into a new Claude Desktop chat that creates it. Menus, permission strings and app settings moved out of SETUP.md into `docs/setup/claude-desktop.md` (the developer fallback), which now points at the single copy of the task prompt in SETUP.md.
- **Approve access once:** setup runs the task once while the user is there, after one line on what they'll be asked and why. It sets expectations ("The first scan checks every project and can take 10–20 minutes"), and the run reports "Checked N of M projects" while someone is watching. The same 10–20 minute note applies when exclusions change.
- **Check on your computer** replaces "Mac check": the copy-paste line is for this computer's OS (`changed` now prints `computer`: macOS, Linux or Windows; Terminal or PowerShell), and `match.machine` in checks.json may give one command per OS.
- Setup asks three questions instead of four (the GitHub question moved to the discovery step).
- Prompt words: SETUP.md 596; total 4605 (budget 6024).
- Tests: `tests/test_round2_c.py`; the simulated setup now runs the discovery step and an exclusion.

### 0.1.5 (unreleased): fix round 2, stage B (one task, one report)
- **One run, two modes:** `prompts/run.md` replaces `briefing.md`, `scan.md` and `audit.md`. Daily: news + a quick match of every check against every project + onboarding of new projects. Full (`schedule.full_day`, Monday by default; also the first run, after 8+ days without one, or on request): daily + standing hygiene checks (change-based, `--all` on the first full run of the month) + dependency audit. On demand: "run a full scan", "scan only <project>". If the projects can't be reached, the run still delivers the news and says "Projects not checked; the next run will catch up".
- **Config:** `schedule` is now `run` (cron, daily) and `full_day`. Setup and the guides create one scheduled task instead of three.
- **One report** per run (`briefings/YYYY-MM-DD.md`): New this time (prioritised, matched to projects) · Possible vulnerabilities in your projects · General security issues · Still open · Mac check · Not checked. Each action appears once.
- **Action lines** (howto): code fixes as "Fix: open <project> in Claude Code and say: fix <ID> — <one-line why>"; a one-time global fix first when one exists; non-code actions in one line plus "say 'how do I <action>?'".
- **Graceful recovery** (hard rule in howto): every stop ends with what happened, one step for the user, and "reply **try again**"; the run then redoes only what didn't finish. Catalogue: folder access, permission prompt, computer asleep, network, npm/PyPI, Python.
- **Keys outside projects:** hygiene reports key-like files directly in the projects folder or in folders that aren't projects (key file names such as `*.pem`, `id_rsa*`, and `NAME` next to `NAME.pub`), by name only, never opened: "move to ~/.ssh or delete" (`keys_outside_projects`).
- Automated tracker notes say `auto: full run DATE` (was `local scan`).
- The demo makes one full run and one report.
- Prompt words: 4506 (was 6014; budget 6024).
- Tests: `tests/test_round2_b.py`.

### 0.1.5 (unreleased): fix round 2, stage A (install test bugs and correctness)
Scanner version 0.1.5: saved hygiene results are re-checked once.

- **Odd folder names:** names the script prints are sanitised (`R&D app` → `R_D app`), and feeding one back with `--only` used to match nothing. `--only` now accepts the printed name, the raw name or either Unicode form, and an unknown name is an error instead of an empty run. Keys, state and paths keep the raw name. A refused project folder ends with a short error, not a traceback.
- **Discovery depth:** discovery now searches as deep as the checks read (12 levels; was 6), so projects nested in client or collection folders are found. What is still cut off is reported under `omitted` with `cut_at`, the first folder not searched.
- **Your decisions about projects:** `scan.py project NAME active|inactive|not-mine|managed|skip` stores one decision per project (`STORAGE/library/project-status.json`) that every command applies. `skip` projects are never read; the others are still checked but appear only under `silenced` (hygiene, match, audit), never as actions, tracker rows, new/fixed audit lines or in the stack. `inactive` needs `--not-deployed`: the command returns the question "Is <project> still deployed anywhere?" until the user answers.
- **Stack inventory:** hygiene records what each project uses from file names and dependency names only (CI and hosting configs, Docker, databases, frameworks, AI SDKs, agent configs). `save-state` writes `STORAGE/library/stack.md` ("Scanning for", with what is checked locally vs news only) and reports `new_in_stack`.
- **Briefing relevance** uses `stack.md` instead of the fixed `stack` list, naming the projects (the config list is the fallback before the first scan).
- Prompt words: total 6014 (was 6024).
- Tests: `tests/test_round2_a.py`.

### 0.1.3 (unreleased): install path and parity with the live system (P2)
Scanner version 0.1.3: saved hygiene results are re-checked once.

- **Parity trim** (v1 = what the live system does): version ranges support comparators (exact, `>=`, `>`, `<=`, `<`, `=`; PyPI also `==`, `!=`) with full versions, joined by spaces or commas, and `||`. `^`, `~`, hyphen and x-ranges, partial versions and prerelease versions inside a range are `unknown (unsupported-range)`. Installed prereleases still compare by precedence (`16.4.5-canary.1` is inside `<16.4.5`). npm lockfile v1 is `unknown (unsupported-lockfile-v1)`.
- **osv-scanner route removed** (`audit --method`, `osv_audit`, the route-check branch). The audit is npm audit + PyPI; `route-check` reports whether they can be reached. On the Roadmap.
- **Contained symlinks:** a file symlink is followed only when it resolves to a regular file inside the same project that is not sensitive, excluded, ignore-marked or over the size limit (`CLAUDE.md` → `AGENTS.md`). Folder symlinks and everything else are still refused and reported.
- **Install for non-technical users:** `SETUP.md`, the prompt an agent follows when you say "Set up OccupAI" (checks Python, asks at most four questions, creates `~/.occupai`, runs a first scan, schedules the runs, explains marking done and uninstalling). Pointers at the top of `AGENTS.md` and a new `CLAUDE.md`.
- **Everything local by default.** The Claude Desktop guide sets up three local scheduled tasks; the cloud briefing (git storage repo or Claude Project) moved to "Advanced". README quick start is for humans first; `make test` / `make demo` moved to "For developers"; uninstall steps added.
- **Platform guides** checked against the official docs (2026-11-16). Fixes: no `Write(...)` permission rule (use `Edit`); "Keep computer awake" is an app setting; local tasks need `WebSearch`/`WebFetch` allowed; `/schedule` needs a claude.ai login; `--ask-for-approval` and `--search` aren't listed for `codex exec`. Claude Code, Codex and generic guides are shorter and marked untested.
- **Python 3.9+** is the real minimum (tests pass on 3.9 and 3.13); README and CI now say so.
- **Tracker rules in code** (`tracker.py`): `upsert` (dedupe by ID; reopen only on a material change; snoozed stays silent), `wake_snoozed`, `missed_runs`, and `auto_close(..., manual=True)` for items only the user can confirm (machine/account checks, committed-secret rotation). The demo uses them.
- **Voice:** docs say the kit is modelled on a setup the author runs daily, not that the author runs this kit.
- Tests: `tests/test_p2_flow.py` (setup flow on fictional settings, the scan prompt's commands as written, a multi-day briefing → scan → audit → tracker scenario, committed-secret rotation, snoozed/watching, the live rules each prompt must keep, prompt word budgets).

### 0.1.2 (unreleased): correctness and safe state handling (P1)
Scanner version 0.1.2: saved hygiene results are re-checked once.

- **Version ranges** (`occupai_scan/versions.py`): npm ranges now support caret, tilde, x-ranges, hyphen ranges, partial comparators and `||`, with prereleases ordered by semver precedence. PyPI ranges use PEP 440 comparators. Anything else (tags, `~=`, malformed operators, unparseable versions such as git or file dependencies) makes the project `unknown`; it is never reinterpreted.
- **Lockfiles:** `package-lock.json` v1 (nested), v2 and v3, pnpm 5/6/7/9, yarn classic and berry, and `bun.lock` are read for versions. npm aliases count as the real package. Other lockfile versions and `bun.lockb` are reported as unsupported. A `package.json` with dependencies and no lockfile makes npm rules `unknown`.
- **Python replay:** `packages` rules with `"ecosystem": "pypi"` match pinned `name==version` lines in `requirements*.txt` (names normalised; hashes, continuations and markers handled). Unpinned targets, `-r`/URL/editable lines, Poetry/uv/Pipfile lockfiles and manifests without requirements make the project `unknown`.
- **Runtime pins:** `lts/*`, `${{ matrix.node }}` and other non-version pins are `unknown`, not skipped. Dockerfile tags like `node:22-alpine` are read.
- **Traversal:** every reader walks to the same depth (12 levels) and records `depth-limit` when it stops early; discovery lists top-level folders it couldn't fully search under `omitted`. Exclusion globs now also match parent folders, for every reader.
- **Fingerprints:** hygiene's fingerprint covers the size, mtime/ctime (ns) and inode of every file the checks can read, gitignored ones included, plus git HEAD, `git status` and `.git/config`. Contents are never read for it. Exclusions and the scanner version invalidate the cache; a change to `my_owners` updates ownership without a re-check.
- **Resume:** progress files are bound to the exclusions too. Results from earlier calls are kept only if the project's inputs are unchanged when the run finishes; otherwise they're redone (`redone_changed_inputs`).
- **State promotion:** hygiene and audit outputs record what produced them (root, configuration, scanner version, per-project input fingerprints). `save-state` refuses partial, progress or foreign files. It saves a project only if its inputs haven't changed since its check; otherwise the project is marked for re-checking and its previous findings are kept. `--only` updates just those projects, and audit baselines are kept per project. `audit` reports first-time projects in `first_audit`.
- Odd folder names (quotes, brackets) no longer force a re-check every run.
- Demo: the malicious-package example now uses invented names (`occupai-demo-anim`, `occupai-demo-anim-js`; `occupai-demo-animate` is the look-alike). Previously it named a real npm package.
- Tests: `tests/test_p1_correctness.py`.

### 0.1.1 (unreleased): safety and evidence boundaries (P0)
Scanner version 0.1.1: saved hygiene results from 0.1.0 are re-checked once.

- **Safe file access** (`occupai_scan/safefs.py`): every project read (text, JSON, lockfile hashing, the npm scratch copy) goes through one policy bound to the projects root. Symlinks are never followed (files, folders, top-level projects); paths can't leave the root; reads are size-bounded; exclusions and `.occupai-ignore` apply to every reader. Skipped inputs are reported with a reason instead of silently ignored.
- **Sensitive files:** the exception is now an explicit env-example shape only (`.env.example`, `.env.local.sample`, ...). `credentials.example.json`, `cert.example.pem` and `.env.defaults` are sensitive and never opened (this reverses the 0.1.0 history-check change).
- **Write destinations:** `--state`, `--resume`, `--out` and `--tracker` are refused inside a scanned project (allowed under an excluded or ignore-marked folder) and when they are symlinks. Unit lists in progress files are validated before use.
- **No credentials in output:** MCP URLs are reduced to validated host names; unsupported requirement lines are reported by line number and reason, not text; errors are fixed categories (`npm-error:E401`, `malformed-output`, `tls-verify-failed`, `exception:TypeError`...), never raw stderr or exception text; the GitHub origin owner is parsed strictly. Repository-derived strings are stripped of control/bidi characters and shell/Markdown syntax before output. Scan-written tracker notes are defanged.
- **Isolated subprocesses:** git runs with fsmonitor, hooks, pager, credential helpers and repo-defined filter/diff drivers disabled, no optional locks, and `safe.directory` set to the one repo instead of `*`. npm runs in a scratch folder with its own HOME, empty user/global config, cache and logs, a fixed registry (`audit.npm_registry`), scripts off, and none of the host's tokens, `NODE_OPTIONS` or `npm_config_*` variables.
- **Explicit uncertainty:** every hygiene check, lockfile, requirements file and project has a status (`ok` / `incomplete` / `error`; match: `open` / `not-affected` / `unknown`). Failed npm runs, malformed output, missing binaries, network/TLS failures and corrupt lockfiles are errors, never clean. `fixed_since_last` only counts files checked successfully; other previous findings are `carried_unverified` and kept in state. Incomplete hygiene results keep the last complete findings (`carried_findings`) and are re-checked next run. `tracker.auto_close` requires `complete=True`.
- Tests: `tests/test_p0_safety.py` (access-instrumented with a Python audit hook; fake npm on PATH; one real-npm test against a loopback registry with an fs trace).

### 0.1.0 (unreleased)
First public version, generalised from a private setup that has run daily since November 2026.

- Daily briefing, weekday local scan and weekly dependency audit as agent prompts (`prompts/`), with a shared how-to of procedures and hard rules.
- `occupai_scan`: the read-only scan script, refactored into a package (`python3 scan.py`). Subcommands: `projects`, `changed`, `hygiene`, `versions`, `match`, `route-check`, `audit`, `save-state`, `tracker`.
  - New: `match` replays checks.json rules (package ranges, malicious names, runtime pins, files, git indicators) per project.
  - New: `route-check` picks osv-scanner (if api.osv.dev is reachable and it's installed) or npm audit + PyPI. It reports TLS failures separately and checks npm with `npm ping`.
  - New: `audit --method osv-scanner` (untested: no environment with OSV access yet).
  - New: `--config` (`occupai.config.yaml`); exclusions and GitHub owners come from the config instead of being hard-coded; hygiene output lists third-party clones and unconfirmed owners.
  - New: `--out FILE` saves the full JSON and prints a short summary, so agents read less and permission rules stay simple.
  - New: `tracker list | mark | add` for `actioned.md`.
  - Fixed: a top-level folder with `.occupai-ignore` was still listed as a project, and a marker at a git repo's root didn't skip its files.
  - Fixed: `--budget 0` (or a slow first project) could stop a resumable run from making progress; each call now finishes at least one project.
  - Fixed: progress and output files are written even when the state folder doesn't exist yet.
  - Changed: MCP inline-secret counts use the same placeholder filters as code; history checks skip example files (e.g. `credentials.example.json`); project skills under `.agents/skills` are checked too.
- Action tracker, security library templates and `schema/checks.schema.json`.
- Skills: `occupai` (briefing | scan | audit | status | mark) and `security-baseline`.
- Setup guides for Claude Desktop, Claude Code, Codex (untested) and generic agents; storage modes, including Claude Projects.
- Tests with planted fixtures (`make test`) and an offline demo (`make demo`).
