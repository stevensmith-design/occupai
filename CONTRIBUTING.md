# Contributing

Thanks for looking. OccupAI is a small side project, so small focused changes are easiest to review.

## Ground rules
- **Python 3 standard library only** in `occupai_scan/`. No dependencies.
- **Read-only, always.** The script must never install, build or run project code, never write inside a scanned project, never open sensitive files, and never output secret values. PRs that weaken this won't be merged.
- **Tests with every check change.** Add a fixture under `tests/fixtures/` that should be flagged and one that must NOT be flagged, then assert both in `tests/test_scan.py`.
- **No real secrets anywhere.** Fixtures use `@@TOKEN@@` placeholders; `tests/fixture_setup.py` generates fake keys at test time. Files that our `.gitignore` hides (like `.env`) are created there too.
- **Bump `SCRIPT_VERSION`** in `occupai_scan/common.py` when check logic changes, so cached results are re-checked.
- **Follow the kit's own baseline** in examples and CI: no Node ≤ 20 or Python ≤ 3.10, actions pinned to full SHAs, `permissions: contents: read`. (One exception: CI also tests Python 3.9, the oldest version the kit runs on, because it's the `python3` macOS ships. Your projects shouldn't use it.)
- **Honest wording.** Docs and reports say what was and wasn't covered. Don't oversell.

## Before opening a PR
```
make test
make demo
```

## Good first contributions
- Audits for pnpm, yarn or bun lockfiles
- More ecosystems (Go, Rust, Ruby) in `match` and `audit`
- Testing and fixing the Codex or generic-agent setup guides
- New noise filters, each with a fixture that shows the false positive
