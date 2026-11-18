"""The action tracker (actioned.md): a Markdown table the agent and the user both edit.

| ID | Item | First reported | Status | Updated | Note |

This module only touches the tracker file in the storage folder, never a project.
"""
import datetime
import re

from .common import clean, defang, write_text

COLUMNS = ["ID", "Item", "First reported", "Status", "Updated", "Note"]
STATUS_RX = re.compile(r"^(open|done|not-affected|watching|REOPENED|snoozed until \d{4}-\d{2}-\d{2})$")
CLOSED = ("done", "not-affected")
USER_ONLY = ("watching", "snoozed")

# Notes are segments joined by " · ". Automated segments have exactly these shapes; an automated update
# replaces the previous automated segment and keeps every other segment (the user's text) as it is.
SEP = " · "
AUTO_SEGMENT = re.compile(r"^(auto: .+ \d{4}-\d{2}-\d{2} — .*|(UPDATED|REOPENED) \d{4}-\d{2}-\d{2}: .*)$")


def _with_auto(note, auto):
    """note with its automated segment replaced by auto; user text is never removed."""
    kept = [s for s in (note or "").split(SEP) if s.strip() and not AUTO_SEGMENT.match(s.strip())]
    return SEP.join(kept + [auto])


def user_protected(row):
    """A row the user set or annotated by hand (`tracker mark` writes a "user:" segment). Automated runs
    never close it, also after later automated updates; only the user changes it."""
    return any(s.strip().lower().startswith("user:") for s in (row.get("Note") or "").split(SEP))


def _cells(line):
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", s)]


def parse(text):
    """-> (before, rows, after). rows are dicts keyed by COLUMNS."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if _cells(ln)[:2] == ["ID", "Item"]), None)
    if start is None:
        raise ValueError("tracker table not found (expected a header row starting '| ID | Item |')")
    end = start + 2
    rows = []
    while end < len(lines) and lines[end].strip().startswith("|"):
        c = _cells(lines[end])
        c += [""] * (len(COLUMNS) - len(c))
        rows.append(dict(zip(COLUMNS, c[: len(COLUMNS)])))
        end += 1
    return "\n".join(lines[:start]), rows, "\n".join(lines[end:])


def render(before, rows, after):
    def esc(v):
        return str(v).replace("|", "\\|")
    out = [before.rstrip("\n"), "", "| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)] if before else \
          ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    out += ["| " + " | ".join(esc(r.get(c, "")) for c in COLUMNS) + " |" for r in rows]
    text = "\n".join(out) + "\n"
    if after.strip():
        text += "\n" + after.strip("\n") + "\n"
    return text


def load(path):
    with open(path) as f:
        return parse(f.read())


def save(path, before, rows, after):
    write_text(path, render(before, rows, after))


def validate_status(status):
    if not STATUS_RX.match(status):
        raise ValueError(f"unknown status '{status}'. Use: open, done, not-affected, watching, "
                         "snoozed until YYYY-MM-DD, REOPENED")
    return status


def mark(rows, item_id, status, date, note=None):
    """User-initiated status change (any status allowed). Returns the changed row."""
    validate_status(status)
    for r in rows:
        if r["ID"] == item_id:
            r["Status"], r["Updated"] = status, date
            r["Note"] = f"user: {date} — {note}" if note else f"user: {date} — set to {status}"
            return r
    raise KeyError(f"no tracker row with ID '{item_id}'")


def add(rows, item_id, item, date, status="open", note=""):
    if any(r["ID"] == item_id for r in rows):
        raise KeyError(f"tracker row '{item_id}' already exists")
    row = {"ID": item_id, "Item": item, "First reported": date, "Status": validate_status(status),
           "Updated": date, "Note": note}
    rows.append(row)
    return row


def can_auto_close(row):
    """The scan may auto-close only plain open/REOPENED rows the user hasn't parked or reopened by hand."""
    st = row["Status"]
    if st.startswith(USER_ONLY) or st in CLOSED:
        return False
    return not user_protected(row)


def auto_close(rows, item_id, status, date, evidence, *, complete, manual=False, source="full run"):
    """Scan- or audit-initiated close with evidence. Returns (old, new) or None if the rules forbid it.
    complete must be True: a run with unknown, failed or skipped coverage never closes a row.
    manual=True blocks closing: the item still needs something only the user can confirm (a machine
    or account check, a manual action, rotating a secret that was committed)."""
    if status not in CLOSED:
        raise ValueError("auto-close only sets done or not-affected")
    if complete is not True or manual:
        return None
    for r in rows:
        if r["ID"] == item_id:
            if not can_auto_close(r):
                return None
            old = r["Status"]
            r["Status"], r["Updated"] = status, date
            r["Note"] = _with_auto(r["Note"], f"auto: {clean(source)} {date} — {defang(clean(evidence))}")
            return old, status
    return None


def upsert(rows, item_id, item, date, change=None):
    """The news step's dedupe rule. A known ID is never added twice. Returns what happened:
    'new' (added open), 'reopened' (done/not-affected + a material change), 'updated' (open, REOPENED
    or watching + a material change), or None (nothing to report: known item, nothing material)."""
    row = next((r for r in rows if r["ID"] == item_id), None)
    if row is None:
        add(rows, item_id, item, date)
        return "new"
    if not change or row["Status"].startswith("snoozed"):
        return None  # snoozed stays silent until its date (wake_snoozed)
    reopen = row["Status"] in CLOSED
    row["Status"] = "REOPENED" if reopen else row["Status"]
    row["Updated"] = date
    row["Note"] = _with_auto(row["Note"], f"{'REOPENED' if reopen else 'UPDATED'} {date}: {defang(clean(change))}")
    return "reopened" if reopen else "updated"


def wake_snoozed(rows, today):
    """Snoozed rows whose date has passed go back to open. Returns their IDs."""
    woke = []
    for r in rows:
        m = re.match(r"snoozed until (\d{4}-\d{2}-\d{2})$", r["Status"])
        if m and m.group(1) <= today:
            r["Status"], r["Updated"] = "open", today
            woke.append(r["ID"])
    return woke


def missed_runs(last, today, weekdays_only=False):
    """Scheduled dates strictly between the last report and today (catch-up). Nothing is invented for
    them: the next run widens its window to cover them instead."""
    d, end, out = datetime.date.fromisoformat(last) + datetime.timedelta(days=1), datetime.date.fromisoformat(today), []
    while d < end:
        if not weekdays_only or d.weekday() < 5:
            out.append(d.isoformat())
        d += datetime.timedelta(days=1)
    return out


def summary(rows):
    out = {}
    for r in rows:
        key = r["Status"].split(" ")[0]
        out[key] = out.get(key, 0) + 1
    return out
