---
source: Demo supply-chain blog
url: https://example.com/demo/ci-secret-stealer
date: 2026-11-16
---
# CI secret stealer pushed through hijacked accounts (fictional)

Attackers with stolen GitHub accounts pushed branches named ci-helper-NNNN with a commit titled "chore: add ci helper". The workflow it adds dumps every secret the CI job can read, then deletes its own run. This campaign is active and spreading.
