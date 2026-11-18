# Security baseline for new projects

**Updated:** YYYY-MM-DD · Generated from `checks.json` by your OccupAI automations. Don't edit by hand; tell your agent instead, so the change is logged in `changelog.md`.

**Use it:** at project start, before choosing versions, and before any package install. Follow every rule. If a rule can't be met, stop and say so. The `security-baseline` skill reads this file.

Keep this file under ~100 lines. The newest rule per package replaces older ones. Every rule cites the check ID and date that set it. Drop rules that no longer matter.

## 1. Minimum safe versions

| Package / runtime | Minimum | Why |
|---|---|---|
| Node.js | 22 or 24 (current LTS lines; newest patch) | starting rule |
| Python | 3.11 or newer (newest patch of the line) | starting rule |

For npm, enforce minimums for transitive dependencies with `overrides` in package.json, e.g. `"overrides": { "<package>": ">=<minimum>" }`. Two cautions:
- When fixes ship per release line, one `>=` range can let a vulnerable version through (`>=19.2.9` also allows a vulnerable `19.3.0`). Pin to the patched version of the line you use, or don't add an override.
- Only override packages that actually appear in the lockfile. Frameworks that bundle their own copy of a package (for example Next.js and `react-server-dom-*`) need the framework upgraded instead.

Start from current scaffolds, not old templates. Run `npm audit` (or your ecosystem's equivalent) before the first commit, and don't commit with any critical or high finding.

## 2. Never use
- **Node 20 or older:** end-of-life, no security fixes. (starting rule)
- **Python 3.10 or older:** end-of-life. (starting rule)

## 3. Always do
- **Gitignore `.env*` (except `.env.example`) and `.claude/settings.local.json` in the first commit.** Reference secrets as environment variables; never paste them into agent permission prompts. (starting rule)
- **GitHub Actions:** top-level `permissions: contents: read`; pin third-party actions to a full commit SHA; pass `${{ github.event.* }}` values through `env:`, never straight into `run:`. (starting rule)
- **Pin GitHub Actions `node-version` to a major only** (e.g. `24`) so patch fixes arrive automatically. (starting rule)
- **MCP servers:** pin `npx`/`uvx` packages to a version; no secrets inline in MCP config files. (starting rule)
- **Set spend limits and usage alerts on every AI provider key.** (starting rule)
