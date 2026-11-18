# Security action tracker

Every OccupAI run reads this file before writing. Edit it yourself, or tell your agent ("mark <ID> done", "not affected by <ID>"). With the `occupai` skill: `/occupai mark <ID> <status>`.

## Statuses
- **open**: reported, not handled yet. The briefing shows a one-line reminder under "Still open", not the full item again.
- **done**: you checked or fixed it. The briefing stays silent unless the item should be **REOPENED** (see below).
- **not-affected**: doesn't apply to you. Treated like done.
- **snoozed until YYYY-MM-DD**: silent until that date, then back to open.
- **watching**: you're not acting yet; only material changes are reported.
- **REOPENED**: a done or not-affected item that came back because something material changed after you acted: new IOCs or a new attack variant, exploitation started, the scope widened to your stack, a fix turned out incomplete, or a new project brought the issue back. The report says what changed.

Only you set **snoozed** and **watching**. The briefing never closes anything.

Notes starting **"auto:"** were set by the local scan or the dependency audit from evidence in your projects. Change any of them back to open if you disagree; the scan won't close a row you reopened (notes starting **"user:"**).

Rows that have been done or not-affected for more than 30 days move to `actioned-archive.md` (same table, never deleted).

## Items
| ID | Item | First reported | Status | Updated | Note |
|---|---|---|---|---|---|
