---
name: security-baseline
description: Apply the OccupAI security baseline when starting a new project, scaffolding an app, cloning a project to work on, choosing package or runtime versions, or before any npm/pnpm/yarn/bun/pip install or a project's first commit.
---

# Security baseline

The rules live in a data file that the OccupAI automations update. This skill only says how to use them, so it doesn't go stale.

**Source of truth:** `STORAGE/library/baseline.md`, where STORAGE is `storage.path` in the OccupAI config (`$OCCUPAI_CONFIG`, else `~/.occupai/occupai.config.yaml`, else `data/occupai.config.yaml` in the kit; default STORAGE is the config's folder). Details for each rule are in `checks.json` in the same folder.

## When
- Starting or scaffolding a new project, or cloning one to work on
- Before choosing versions of a framework, runtime or package
- Before any `npm` / `pnpm` / `yarn` / `bun` / `pip` install, and before the first commit

## Steps
1. **Read** `STORAGE/library/baseline.md` in full. If it's missing or unreadable, stop and tell the user. Don't fall back to versions from memory.
2. **Versions:** for every package and runtime the project uses, choose a version at or above the baseline minimum. Start from current scaffolds, not old templates. If a template pins something below a minimum, upgrade it.
3. **Transitive minimums (npm):** add `overrides` in package.json for baseline packages the project actually has in its lockfile, following the two cautions in baseline.md (per-release-line fixes; bundled packages need the framework upgraded instead).
4. **Runtime pins:** `.nvmrc` / `.node-version` / `.python-version` at or above the minimum; GitHub Actions `node-version` as a major only (e.g. `24`). Never use a runtime on the never-use list.
5. **Never-use list:** don't add any package named there. If a dependency pulls one in, stop and tell the user.
6. **Always-do rules:** apply every one before the first commit (for example gitignore `.env*` and `.claude/settings.local.json`; GitHub Actions with `permissions: contents: read` and actions pinned to full SHAs).
7. **Before the first commit:** run `npm audit` (or the ecosystem's equivalent). Don't commit while there's any critical or high finding; fix it or tell the user.
8. **Report** in one short block: the baseline date used, the versions chosen against each minimum, overrides added, always-do rules applied, and the audit result.

## Notes
- Never edit `baseline.md` or `checks.json` from this skill; they're maintained by the automations. If a rule seems wrong or blocks the work, tell the user so they can change it (and log it in `changelog.md`).
- The baseline is a floor, not a pin: newer patch and minor versions are fine.
