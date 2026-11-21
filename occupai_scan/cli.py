"""occupai_scan: read-only local security scan helper (Python 3 stdlib only).

Does the repetitive, deterministic work so the AI agent only reads short JSON summaries.
Never installs packages, never runs project code, never writes inside scanned projects,
never prints or stores secret values.

Subcommands (all print JSON on stdout):
  projects     discover project units + fingerprints
  discover     setup preview: projects it would watch (backups/copies unticked), stack, GitHub owners
  changed      new / changed / unchanged / removed vs the last saved state
  hygiene      standing checks (secrets, db, gha, ai); reuses results for unchanged projects
  versions     installed versions of --packages from every lockfile
  match        replay checks.json rules against projects (news items, onboarding)
  route-check  can npm audit and PyPI be reached from here (status codes only)
  audit        dependency audit per project (scratch copies only) + new/fixed vs last state
  save-state   write fingerprints + results for next time
  tracker      list | mark ID STATUS [--note ...] | add ID "Item" (actioned.md in the storage folder)
  marker       start | done | check | wait: the briefing's "running" marker (STORAGE/state/briefing-running),
               so the scan doesn't start while the briefing is still writing the tracker and library
  project      list | NAME STATUS [--note ...]: your decision about a project, applied to every check
               (active | inactive --not-deployed | not-mine | managed | skip); stored in the storage folder.
               NAME may be <project>/<folder>: quiets that sub-folder's dependency audit findings

Settings come from occupai.config.yaml (--config, $OCCUPAI_CONFIG, ~/.occupai/, KIT/data/ or ./, in that
order; an explicit config that doesn't exist is an error). Flags override the config. In a device shell that sees attached
folders at $HOME/mnt/<folder name>, configured paths that aren't there map to those mounts. State lives
in the storage folder, outside the projects. Long steps are resumable: add --resume FILE --budget SECONDS and repeat the
same command until it stops printing "status": "partial".

Results say what was actually covered: every check, lockfile and project carries a status
(ok | incomplete | error, or open | not-affected | unknown for match). Only "ok" / "not-affected"
mean clean. Strings that come from repositories are untrusted data and are sanitised before output.
"""
import argparse
import datetime
import hashlib
import json
import os
import sys
import time
import unicodedata

from . import config as cfgmod
from . import tracker as trk
from .common import (LOCKFILES, SCRIPT_VERSION, clean, computer, load_json, resolve_units, same_name, scrub, write_json,
                     write_text)
from .deps import (DEFAULT_NPM_REGISTRY, audit_inputs, audit_keys, covered, lock_versions, route_check, run_audit,
                   valid_registry)
from .discovery import discover, fingerprint, lockfile_hashes, looks_like_copy, origin_owner, ownership
from .hygiene import CHECKS, check_statuses, is_complete, keys_outside_projects, run_hygiene, severity_counts
from .match import load_checks, run_match
from .safefs import WALK_DEPTH, Coverage, PathRefused, Policy, UnsafeDestination, check_destination
from .stack import coverage as stack_coverage, detect, inventory, render as render_stack

CMDS = ["projects", "discover", "changed", "hygiene", "versions", "match", "route-check", "audit", "save-state", "tracker",
        "project", "marker"]

MARKER_FRESH = 30 * 60  # a "running" marker older than this is stale (a briefing that stopped without "done")

# Your decisions about projects (STORAGE/library/project-status.json). skip: never read. The silenced
# ones are still checked (cheap, change-based) but never become actions, tracker rows or "your stack".
STATUSES = {"active": "checked and reported (the default)",
            "inactive": "not used and not deployed anywhere: checked, findings silenced",
            "not-mine": "someone else's code: checked, findings silenced",
            "managed": "someone else looks after it: checked, findings silenced",
            "skip": "don't touch: never read"}
SILENCED = ("inactive", "not-mine", "managed")


def build_parser():
    ap = argparse.ArgumentParser(prog="occupai_scan", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=CMDS)
    ap.add_argument("args", nargs="*", help="tracker: list | mark ID STATUS | add ID ITEM; project: list | NAME STATUS")
    ap.add_argument("--version", action="version", version=f"occupai_scan {SCRIPT_VERSION}")
    ap.add_argument("--config", help="path to occupai.config.yaml")
    ap.add_argument("--root", help="projects folder (default: projects_root from config)")
    ap.add_argument("--exclude", nargs="*", help="exclusion globs (default: exclusions from config)")
    ap.add_argument("--owners", help="comma-separated GitHub owners that are yours (default: my_owners)")
    ap.add_argument("--state", help="scan state JSON (default: <storage>/state/scan-state.json when a config is used)")
    ap.add_argument("--only", help="comma-separated project units")
    ap.add_argument("--all", action="store_true", help="hygiene: ignore cache, check every project")
    ap.add_argument("--packages", help="versions: comma-separated package names")
    ap.add_argument("--checks", help="match: checks.json (default: <storage>/library/checks.json)")
    ap.add_argument("--ids", help="match: comma-separated check IDs (default: all project-scoped checks)")
    ap.add_argument("--hygiene", help="save-state: hygiene JSON file")
    ap.add_argument("--audit", help="save-state: audit JSON file")
    ap.add_argument("--resume", help="hygiene/audit: progress file (resumable across short shell calls)")
    ap.add_argument("--budget", type=int, default=120, help="seconds per call when using --resume")
    ap.add_argument("--fresh", action="store_true", help="ignore any existing progress file and start over")
    ap.add_argument("--tracker", help="tracker: path to actioned.md (default: <storage>/actioned.md)")
    ap.add_argument("--note", help="tracker mark/add: note text")
    ap.add_argument("--date", help="tracker: date to record (default: today)")
    ap.add_argument("--not-deployed", action="store_true",
                    help="project NAME inactive: the user confirmed it isn't deployed anywhere")
    ap.add_argument("--out", help="write the full JSON to this file (in STORAGE) and print only a short summary")
    return ap


_OUT = {"path": None}


def brief(obj):
    """Short version of a result for the agent to read; the full JSON goes to --out."""
    if "results" in obj:
        return {k: v for k, v in obj.items() if k != "results"}
    if obj and all(isinstance(v, dict) and "affected" in v for v in obj.values()):  # match
        return {k: {"title": v["title"], "affected": v["affected"], "unknown": v.get("unknown", []),
                    "checked": v["checked"], **({"silenced": v["silenced"]} if v.get("silenced") else {})}
                for k, v in obj.items()}
    return obj


def out(obj, trusted=False):
    """Print (and with --out, save) a result. Repository-derived strings are sanitised; trusted=True
    only for the user's own tracker file."""
    obj = obj if trusted else scrub(obj)
    path = _OUT["path"]
    if path and obj.get("status") != "partial" and "error" not in obj:
        write_json(path, obj, indent=1)
        obj = {"saved": path, **brief(obj)}
    print(json.dumps(obj, indent=1, ensure_ascii=False))


def fail(msg, code=2):
    print(json.dumps({"error": msg}, indent=1))
    return code


def _dest(path, root, patterns, what):
    """Validated absolute destination for a file we write, or raise UnsafeDestination."""
    try:
        return check_destination(path, root, patterns)
    except UnsafeDestination as e:
        raise UnsafeDestination(f"refusing {what}: {e}")


def _valid_units(pol, units):
    if not isinstance(units, list):
        return False
    for u in units:
        try:
            pol.unit_path(u)
        except PathRefused:
            return False
    return True


def config_key(exclude):
    """Everything outside a project that changes what the scanner reads or concludes about it."""
    blob = json.dumps({"v": SCRIPT_VERSION, "depth": WALK_DEPTH, "exclude": sorted(exclude or [])}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def main(argv=None):
    try:
        return _main(argv)
    except PathRefused as e:  # e.g. a project folder renamed or removed during the run
        return fail(f"a project folder could not be read ({e.reason}): run the same command again")


def _main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        cfg = cfgmod.load(a.config)
    except cfgmod.ConfigError as e:
        return fail(str(e))
    storage = cfgmod.storage_path(cfg)
    has_cfg = "_path" in cfg
    audit_cfg = cfg.get("audit") if isinstance(cfg.get("audit"), dict) else {}
    registry = valid_registry(audit_cfg.get("npm_registry") or DEFAULT_NPM_REGISTRY)
    if not registry:
        return fail("audit.npm_registry must be an https URL")

    root = a.root or cfg.get("projects_root")
    root = os.path.realpath(cfgmod.mounted(root)) if root else None
    exclude = a.exclude if a.exclude is not None else list(cfg.get("exclusions") or [])
    try:
        _OUT["path"] = _dest(a.out, root, exclude, "--out") if a.out else None
    except UnsafeDestination as e:
        return fail(str(e))

    if a.cmd == "route-check":
        out(route_check(registry))
        return 0
    if a.cmd == "tracker":
        return cmd_tracker(a, storage, root, exclude)
    if a.cmd == "marker":
        return cmd_marker(a, storage, root, exclude)

    if not root:
        return fail("no projects folder: pass --root or set projects_root in occupai.config.yaml")
    if not os.path.isdir(root):
        # Stop and change nothing if the folder can't be reached (e.g. not connected or not mounted).
        return fail(f"projects folder not reachable: {root}")
    pol = Policy(root, exclude)
    ckey = config_key(exclude)
    owners = [o.strip() for o in a.owners.split(",")] if a.owners else list(cfg.get("my_owners") or [])
    state_path = a.state or (os.path.join(storage, "state", "scan-state.json") if has_cfg else None)
    try:
        if state_path:
            state_path = _dest(state_path, root, exclude, "--state")
        if a.resume:
            a.resume = _dest(a.resume, root, exclude, "--resume")
    except UnsafeDestination as e:
        return fail(str(e))

    # Discovery walks the whole root (slow on mounted folders); a resumable run reuses its unit list for 2 h.
    cached = load_json(a.resume, {}) if a.resume else {}
    cached = cached if isinstance(cached, dict) else {}
    # A finished or stale (> 2 h) progress file starts a fresh run. Overwrite, never delete:
    # deletion may be disabled where the state lives.
    if cached and (cached.get("complete") or time.time() - (cached.get("created") or 0) > 7200 or a.fresh
                   or cached.get("root") != root or cached.get("script_version") != SCRIPT_VERSION
                   or cached.get("config_key") != ckey or not _valid_units(pol, cached.get("units"))):
        cached = {}
        write_json(a.resume, {})
    if cached.get("units"):
        units, omitted = cached["units"], cached.get("omitted", [])
    else:
        units, omitted = discover(pol)
        if a.resume:
            write_json(a.resume, {"units": units, "omitted": omitted, "created": time.time(), "root": root,
                                  "script_version": SCRIPT_VERSION, "config_key": ckey})
    status_path = os.path.join(storage, "library", "project-status.json") if has_cfg else None
    if a.cmd == "project":
        return cmd_project(a, units, status_path, root, exclude)
    statuses = project_statuses(status_path, units)
    subs = sub_statuses(status_path, units)
    skipped = sorted(u for u, s in statuses.items() if s == "skip")
    silenced = {u: s for u, s in statuses.items() if s in SILENCED}
    units = [u for u in units if u not in skipped]
    if a.only:
        # Names as printed by the script (sanitised) or as typed (raw, either Unicode form) both work.
        units, unknown = resolve_units([x.strip() for x in a.only.split(",") if x.strip()], units)
        if unknown:
            return fail(f"--only: no project named {', '.join(clean(x) for x in unknown)} in this scan "
                        "(use the names `changed` prints; excluded, ignore-marked and skipped projects are left out)")
    state = load_json(state_path, {}) if state_path else {}
    state = state if isinstance(state, dict) else {}
    prev = state.get("projects", {}) if isinstance(state.get("projects"), dict) else {}

    if a.cmd == "projects":
        res = {u: fingerprint(pol, u) for u in units}
        if omitted:
            res["_omitted"] = omitted
        out(res)
    elif a.cmd == "discover":
        return cmd_discover(pol, units, omitted, skipped, silenced, exclude, cfg)
    elif a.cmd == "changed":
        gaps = {u: g for u in units if (g := pol.unit_gap(u))}
        seen = [u for u in units if u not in gaps]  # an empty or unreadable folder is never "unchanged"
        cur = {u: fingerprint(pol, u)["fp"] for u in units}
        out({"last_saved": state.get("saved_at"),
             "cache_valid": state.get("script_version") == SCRIPT_VERSION if state else None,
             "new": [u for u in seen if u not in prev],
             "changed": [u for u in seen if u in prev and prev[u].get("fp") != cur[u]],
             "unchanged": [u for u in seen if u in prev and prev[u].get("fp") == cur[u]],
             "not_reachable": gaps,
             "removed": [u for u in prev if u not in cur and u not in skipped],
             "omitted": omitted, "computer": computer(cfg), **_choices(statuses)})
    elif a.cmd == "hygiene":
        # Skipped projects stay unread; with --only, only that project is checked.
        loose = [] if a.only else keys_outside_projects(pol, units, skipped)
        return cmd_hygiene(a, pol, units, omitted, state, prev, owners, ckey, statuses, loose)
    elif a.cmd == "versions":
        names = [x.strip() for x in (a.packages or "").split(",") if x.strip()]
        res, cov = {}, Coverage()
        for u in units:
            upol = pol.for_unit(u)
            for dp, dns, fns in upol.walk(u, cov=cov, wanted=lambda a: os.path.basename(a) in LOCKFILES):
                for f in fns:
                    if f in LOCKFILES:
                        v = lock_versions(upol, os.path.join(dp, f), names, cov)
                        if v:
                            res[pol.rel(os.path.join(dp, f))] = v
        if cov.skipped:
            res["_skipped"] = cov.skipped  # lockfiles not read: their versions are unknown, not absent
        out(res)
    elif a.cmd == "match":
        path = a.checks or os.path.join(storage, "library", "checks.json")
        if not os.path.isfile(path):
            return fail(f"checks.json not found: {path}")
        ids = [x.strip() for x in a.ids.split(",")] if a.ids else None
        out(silence_matches(run_match(pol, units, load_checks(path), ids), silenced))
    elif a.cmd == "audit":
        return cmd_audit(a, pol, units, omitted, state, prev, registry, ckey, statuses, subs)
    elif a.cmd == "save-state":
        stack_path = os.path.join(storage, "library", "stack.md") if has_cfg else None
        try:
            stack_path = stack_path and _dest(stack_path, root, exclude, "stack.md")
        except UnsafeDestination as e:
            return fail(str(e))
        return cmd_save_state(a, pol, units, state, prev, state_path, ckey, statuses, stack_path)
    return 0


def cmd_discover(pol, units, omitted, skipped, silenced, exclude, cfg):
    """Setup preview, before the first scan: the projects it would watch (folders that look like backups or
    copies start unticked), what they use ("scanning for") and the GitHub owners seen. Names only: reads
    nothing beyond what the stack inventory reads (package.json, requirements*.txt) and git remotes."""
    watch, owners, uses = [], {}, {}
    for u in units:
        why = looks_like_copy(u)
        has_gh, owner = (False, None) if why else origin_owner(pol.unit_path(u))
        watch.append({"project": u, "watch": not why, **({"why": why} if why else {}),
                      **({"owner": owner} if owner else {}), **({"status": silenced[u]} if u in silenced else {})})
        if why:
            continue
        if owner:
            owners[owner] = owners.get(owner, 0) + 1
        elif has_gh:
            owners["(unrecognised GitHub remote)"] = owners.get("(unrecognised GitHub remote)", 0) + 1
        if u not in silenced:
            try:
                uses[u] = detect(pol.for_unit(u), u)
            except Exception:  # noqa: BLE001  best effort, as in hygiene
                uses[u] = []
    inv = inventory(uses)
    out({"root": pol.root, "computer": computer(cfg), "kit": kit_place(cfg, pol.root), "watch": watch,
         "scanning_for": [{"tech": t, "projects": ps, "checked_locally": stack_coverage(t)} for t, ps in inv.items()],
         "github_owners": dict(sorted(owners.items(), key=lambda kv: (-kv[1], kv[0].lower()))),
         "already_excluded": exclude, "skipped": skipped, "omitted": omitted,
         "next": "untick = add the folder to `exclusions` in the config; then run discover again"})
    return 0


def kit_place(cfg, root):
    """Where the kit is, for setup: a scheduled task sees only its attached folders, so a kit outside the
    projects folder must be attached too (or moved into it)."""
    kit = cfg.get("kit_path")
    if not kit:
        return {"found": False, "next": "set kit_path in the config"}
    p = os.path.realpath(cfgmod.mounted(kit))
    if not os.path.isfile(os.path.join(p, "scan.py")):
        return {"path": p, "found": False, "next": "kit_path doesn't point at the kit folder (no scan.py there)"}
    inside = p == root or p.startswith(root + os.sep)
    return {"path": p, "found": True, "inside_projects": inside, "attach_to_tasks": not inside}


def _resumable_loop(a, units, prog, work, t0):
    """Process units until done or out of budget (always at least one unit per call)."""
    did = 0
    for u in units:
        if u in prog["results"]:
            continue
        if a.resume and did and time.time() - t0 > a.budget:
            break
        work(u)
        did += 1
        if a.resume:
            write_json(a.resume, prog)
    return [u for u in units if u not in prog["results"]]


def _run_units(a, units, prog, work, current, field):
    """Run work(u) for every unit, resumably. Results saved by an earlier call are only kept if the
    unit's inputs still match (prog[field][u] == current(u)); otherwise they're redone. Checked once,
    when everything else is done, so an unchanged run pays nothing extra."""
    t0, fresh = time.time(), set()

    def w(u):
        work(u)
        fresh.add(u)

    while True:
        remaining = _resumable_loop(a, units, prog, w, t0)
        if remaining or not a.resume:
            return remaining
        stale = [u for u in units if u not in fresh and prog[field].get(u) != current(u)]
        if not stale:
            return []
        for u in stale:
            del prog["results"][u]
            for k in ("checked", "reused"):
                if u in prog.get(k, []):
                    prog[k].remove(u)
        prog.setdefault("redone_changed_inputs", []).extend(stale)


def _load_progress(a, pol, units, extra):
    """A progress file is reused only for the same root, units, options, config and scanner version."""
    prog = load_json(a.resume, {}) if a.resume else {}
    prog = prog if isinstance(prog, dict) else {}
    same = (prog.get("units") == units and prog.get("root") == pol.root and isinstance(prog.get("results"), dict)
            and prog.get("script_version") == SCRIPT_VERSION and all(prog.get(k) == v for k, v in extra.items())
            and set(prog["results"]) <= set(units) and all(isinstance(v, dict) for v in prog["results"].values())
            and isinstance(prog.get("inputs"), dict))
    if not same:
        prog = {"units": units, "results": {}, "inputs": {}, "created": prog.get("created", time.time()),
                "root": pol.root, "script_version": SCRIPT_VERSION, **extra}
    return prog


def _meta(kind, a, pol, units, ckey):
    """Binds a result document to what produced it; save-state refuses documents that don't match."""
    return {"kind": kind, "root": pol.root, "script_version": SCRIPT_VERSION, "config_key": ckey,
            "scope": units if a.only else "all"}


def _reusable(p, fp, ckey, same_version, a):
    return (same_version and not a.all and isinstance(p, dict) and isinstance(p.get("hygiene"), dict)
            and not p.get("recheck") and is_complete(p["hygiene"]) and p.get("fp") == fp
            and p.get("hygiene_key") == ckey)


def cmd_hygiene(a, pol, units, omitted, state, prev, owners, ckey, statuses, loose=()):
    prog = _load_progress(a, pol, units, {"all": a.all, "op": "hygiene", "config_key": ckey})
    prog.setdefault("checked", [])
    prog.setdefault("reused", [])
    same_version = bool(state) and state.get("script_version") == SCRIPT_VERSION

    def work(u):
        fp = fingerprint(pol, u)["fp"]  # taken before the checks run: an edit during the run shows next time
        p = prev.get(u)
        if _reusable(p, fp, ckey, same_version, a):
            r = dict(p["hygiene"])
            prog["reused"].append(u)
        else:
            r = run_hygiene(pol, u, owners)
            prog["checked"].append(u)
        prog["inputs"][u] = fp
        prog["results"][u] = r

    remaining = _run_units(a, units, prog, work, lambda u: fingerprint(pol, u)["fp"], "inputs")
    if remaining:
        out({"status": "partial", "done": len(prog["results"]), "remaining": len(remaining),
             "next": "run the same command again"})
        return 0
    if a.resume:
        prog["complete"] = True
        write_json(a.resume, prog)
    res = prog["results"]
    summary, third_party, unknown, incomplete, silenced = {}, {}, [], {}, {}
    for u, r in res.items():
        sec = r.get("secrets") if isinstance(r.get("secrets"), dict) else {}
        # Ownership follows the current my_owners setting, also for reused results.
        r["ownership"] = own = ownership(sec.get("origin_owner"), sec.get("github_remote"), owners)
        counts = severity_counts(r)
        if statuses.get(u) in SILENCED:  # your decision: counts only, no actions, no owner question
            silenced[u] = {"status": statuses[u], **counts}
            continue
        if own == "third-party":
            third_party[u] = sec.get("origin_owner")
        elif own == "unknown":
            unknown.append(u)
        if any(counts.values()):
            summary[u] = {**counts, "ownership": own}
        st = check_statuses(r)
        if not is_complete(r):
            # Not clean: say which checks didn't finish, and keep what the last complete run found.
            incomplete[u] = {k: v for k, v in st.items() if v != "ok"}
            old = (prev.get(u) or {}).get("hygiene") or {}
            for k in incomplete[u]:
                if k in r and findings_of_prev(old, k):
                    r[k]["carried_findings"] = findings_of_prev(old, k)
    out({**_meta("hygiene", a, pol, units, ckey),
         "status": "complete" if not incomplete and not omitted else "incomplete",
         "checked": prog["checked"], "reused_unchanged": sorted(prog["reused"]),
         "redone_changed_inputs": prog.get("redone_changed_inputs", []),
         "cache_invalidated": bool(state) and not same_version,
         "summary": summary, "incomplete": incomplete, "omitted": omitted,
         "third_party_clones": third_party, "owner_unconfirmed": sorted(unknown), "silenced": silenced,
         "keys_outside_projects": list(loose),
         **_choices(statuses, silenced_too=False), "results": res, "inputs": prog["inputs"]})
    return 0


def findings_of_prev(old, check):
    v = old.get(check)
    return v.get("findings", []) if isinstance(v, dict) else []


def _unit_of(path, units):
    """Longest unit that contains a root-relative path (for keys saved before per-project baselines)."""
    best = None
    for u in units:
        if (path == u or path.startswith(u + "/")) and (best is None or len(u) > len(best)):
            best = u
    return best


def prev_audit_keys(state, prev):
    """{unit: set(keys)} for units with an audit baseline. Older state files kept one global key list:
    it is split by project (every project in that state counts as having a baseline)."""
    out = {}
    for u, p in prev.items():
        if isinstance(p, dict) and isinstance(p.get("audit"), dict):
            out[u] = set(p["audit"].get("keys") or [])
    legacy = state.get("audit_keys")
    if isinstance(legacy, list) and not out:
        cleaned = {clean(u): u for u in prev}
        for u in prev:
            out[u] = set()
        for k in legacy:
            u = _unit_of(str(k).split("|", 1)[0], list(cleaned))
            if u is not None:
                out[cleaned[u]].add(k)
    return out


def nfc(s):
    return unicodedata.normalize("NFC", s)


def split_subs(r, u, subs):
    """(view, quiet): an audit result without the lockfiles in sub-folders the user silenced
    ("<project>/<folder> is inactive"), and {sub-folder: vulnerable package count} for those."""
    mine = [x for x in subs if nfc(x).startswith(nfc(u) + "/")]
    if not mine:
        return r, {}
    view, parts = {**r, "npm": {}, "pypi": {}}, {}
    for kind in ("npm", "pypi"):
        for lf, x in r.get(kind, {}).items():
            hit = next((m for m in mine if nfc(lf).startswith(nfc(m) + "/")), None)
            (parts.setdefault(hit, {"npm": {}, "pypi": {}})[kind] if hit else view[kind])[lf] = x
    view["not_covered"] = [x for x in r.get("not_covered", []) if not any(nfc(x).startswith(nfc(m) + "/") for m in mine)]
    return view, {m: len(audit_keys({u: p})) for m, p in parts.items()}


def mostly_in(view, u):
    """'<project>/<folder>' when most of a project's vulnerable packages sit in one sub-folder (3+ in all)."""
    by = {}
    for kind in ("npm", "pypi"):
        for lf, x in view.get(kind, {}).items():
            rest = lf[len(u) + 1:] if lf.startswith(u + "/") else lf
            seg = rest.split("/")[0] if "/" in rest else None
            by[seg] = by.get(seg, 0) + len(x.get("vulns") or {})
    total = sum(by.values())
    top = max((k for k in by if k), key=lambda k: by[k], default=None)
    return f"{u}/{top}" if top and total >= 3 and by[top] * 2 > total else None


def cmd_audit(a, pol, units, omitted, state, prev, registry, ckey, statuses, subs=None):
    prog = _load_progress(a, pol, units, {"op": "audit", "registry": registry, "config_key": ckey})

    def work(u):
        inputs = audit_inputs(pol, u)  # taken before the audit: a lockfile edited meanwhile shows as stale
        try:
            r = run_audit(pol, u, registry)
        except Exception as e:  # noqa: BLE001  one project never stops the others
            r = {"status": "error", "error": f"exception:{type(e).__name__}",
                 "npm": {}, "pypi": {}, "not_covered": [], "skipped": []}
        prog["inputs"][u] = inputs
        prog["results"][u] = r

    remaining = _run_units(a, units, prog, work, lambda u: audit_inputs(pol, u), "inputs")
    if remaining:
        out({"status": "partial", "done": len(prog["results"]), "remaining": len(remaining),
             "next": "run the same command again"})
        return 0
    res = prog["results"]
    if a.resume:
        prog["complete"] = True
        write_json(a.resume, prog)
    subs = subs or {}
    views, quiet_subs = {}, {}
    for u, r in res.items():
        views[u], q = split_subs(r, u, subs)
        quiet_subs.update({m: {"status": subs[m], "vulnerable_packages": n} for m, n in q.items()})
    base = prev_audit_keys(state, prev)
    if subs:  # findings in silenced sub-folders are neither new nor fixed
        base = {u: {k for k in ks if not any(k.startswith(clean(m) + "/") for m in subs)} for u, ks in base.items()}
    quiet = {u for u in res if statuses.get(u) in SILENCED}  # your decision: no actions, no new/fixed lines
    first_audit = sorted(u for u in res if u not in base and u not in quiet)
    prev_keys = set().union(*(base[u] for u in res if u in base and u not in quiet)) if base else set()
    cur_keys = audit_keys({u: views[u] for u in res if u in base and u not in quiet})
    ok = covered(res)
    summary, not_ok, silenced = {}, {}, dict(quiet_subs)
    for u, r in views.items():
        if u in quiet:
            silenced[u] = {"status": statuses[u], "vulnerable_packages": len(audit_keys({u: r}))}
            continue
        sev = {}
        for lf in r.get("npm", {}).values():
            for v in (lf.get("vulns") or {}).values():
                sev[v.get("severity") or "unknown"] = sev.get(v.get("severity") or "unknown", 0) + 1
        py = sum(1 for rf in r.get("pypi", {}).values() for vs in (rf.get("vulns") or {}).values() if any(v.get("id") for v in vs))
        errors = [{"file": lf, "error": x.get("error")} for kind in ("npm", "pypi")
                  for lf, x in r.get(kind, {}).items() if x.get("status") == "error" and x.get("error")]
        errors += [{"file": rf, "package": pkg, "error": cat} for rf, x in r.get("pypi", {}).items()
                   for pkg, cat in (x.get("failed") or {}).items()]
        unsupported = [{"file": rf, **u_} for rf, x in r.get("pypi", {}).items() for u_ in (x.get("unsupported") or [])]
        crit_high = sorted({n for lf in r.get("npm", {}).values() for n, v in (lf.get("vulns") or {}).items()
                            if v.get("severity") in ("critical", "high")})
        if r.get("status") != "ok":
            not_ok[u] = r.get("status")
        if sev or py or r.get("not_covered") or errors or unsupported or r.get("skipped") or r.get("status") != "ok":
            summary[u] = {"status": r.get("status"), "own_advisories_by_severity": sev, "pypi_vulnerable": py,
                          "critical_high_packages": crit_high, "not_covered": r.get("not_covered", []),
                          "unsupported_requirements": unsupported, "skipped": r.get("skipped", []), "errors": errors,
                          **({"mostly_in": mostly_in(r, u)} if mostly_in(r, u) else {})}
    out({**_meta("audit", a, pol, units, ckey),
         "status": "complete" if not not_ok and not omitted else "incomplete",
         "summary": summary, "incomplete": not_ok, "omitted": omitted, "silenced": silenced,
         "generated_skipped": {u: r["generated_skipped"] for u, r in views.items()
                               if r.get("generated_skipped") and u not in quiet},
         **_choices(statuses, silenced_too=False), "results": res, "first_audit": first_audit,
         "new_since_last": "first-run" if not base else sorted(cur_keys - prev_keys),
         "fixed_since_last": [] if not base else sorted(k for k in prev_keys - cur_keys if ok(k)),
         "carried_unverified": sorted(k for k in prev_keys - cur_keys if not ok(k)),
         "redone_changed_inputs": prog.get("redone_changed_inputs", []), "inputs": prog["inputs"]})
    return 0


def _load_doc(path, kind, pol, ckey):
    """A hygiene/audit result document, or an error message. Only a finished document produced for this
    root, configuration and scanner version can become the saved baseline."""
    doc = load_json(path, None)
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), dict):
        return None, f"--{kind} file is not a {kind} result"
    if doc.get("status") == "partial" or doc.get("kind") != kind:
        return None, f"--{kind} file is not a finished {kind} result (partial or progress file)"
    if doc.get("script_version") != SCRIPT_VERSION:
        return None, f"--{kind} file is from another scanner version: run {kind} again"
    if doc.get("root") != clean(pol.root) or doc.get("config_key") != ckey:
        return None, f"--{kind} file is for another projects folder or configuration"
    if not all(isinstance(v, dict) for v in doc["results"].values()) or not isinstance(doc.get("inputs"), dict):
        return None, f"--{kind} file has malformed results"
    return doc, None


def _by_unit(results, units):
    """Result lookup by unit. Saved documents carry sanitised unit names, so match on clean(u); two
    units that sanitise to the same name are ambiguous and get no result (re-checked next run)."""
    names = {}
    for u in units:
        names.setdefault(clean(u), []).append(u)
    return {us[0]: results[c] for c, us in names.items() if len(us) == 1 and c in results}


def cmd_save_state(a, pol, units, state, prev, state_path, ckey, statuses, stack_path):
    if not state_path:
        return fail("save-state needs --state or a config")
    hy_doc = au_doc = None
    if a.hygiene:
        hy_doc, err = _load_doc(a.hygiene, "hygiene", pol, ckey)
        if err:
            return fail(err)
    if a.audit:
        au_doc, err = _load_doc(a.audit, "audit", pol, ckey)
        if err:
            return fail(err)
    hy = _by_unit(hy_doc["results"], units) if hy_doc else {}
    hy_in = _by_unit(hy_doc["inputs"], units) if hy_doc else {}
    au = _by_unit(au_doc["results"], units) if au_doc else {}
    au_in = _by_unit(au_doc["inputs"], units) if au_doc else {}
    base = prev_audit_keys(state, prev)
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    # --only saves just those projects; every other project's saved results stay as they were.
    projects = {u: p for u, p in prev.items() if isinstance(p, dict)} if a.only else {}
    stale = {"hygiene": [], "audit": []}
    for u in units:
        cur = {**fingerprint(pol, u), "locks": lockfile_hashes(pol, u)}
        old = prev.get(u) if isinstance(prev.get(u), dict) else {}
        new = hy.get(u)
        if isinstance(new, dict) and set(CHECKS) <= set(new):
            is_stale = hy_in.get(u) != cur["fp"]  # inputs changed since the check ran
            if is_stale:
                stale["hygiene"].append(u)
            if is_complete(new) and not is_stale:
                cur["hygiene"] = new
            else:
                # Keep the last good result for checks that failed this time, and re-check next run.
                merged = dict(new)
                for k, v in check_statuses(new).items():
                    if v != "ok" and isinstance((old.get("hygiene") or {}).get(k), dict):
                        merged[k] = {**old["hygiene"][k], "carried": True}
                        merged[k].pop("carried_findings", None)
                cur["hygiene"] = merged
                cur["recheck"] = True
            cur["hygiene_key"] = ckey
        elif isinstance(old.get("hygiene"), dict) and old.get("fp") == cur["fp"]:
            cur["hygiene"] = old["hygiene"]
            cur["hygiene_key"] = old.get("hygiene_key")
            if old.get("recheck"):
                cur["recheck"] = True
        r = au.get(u)
        old_keys = base.get(u, set())
        if isinstance(r, dict) and "status" in r and au_in.get(u) == audit_inputs(pol, u):
            ok = covered({u: r})
            # Findings survive anything not checked successfully this run (failed files, errors).
            keys = audit_keys({u: r}) | {k for k in old_keys if not ok(k)}
            cur["audit"] = {"status": r["status"], "inputs": au_in[u], "checked_at": now, "keys": sorted(keys)}
        elif u in base:
            if isinstance(r, dict):
                stale["audit"].append(u)
            cur["audit"] = {**(old.get("audit") or {}), "keys": sorted(old_keys)}
            if isinstance(r, dict):
                cur["audit"]["stale"] = True  # lockfiles changed after the audit ran: audit again
        elif isinstance(r, dict):
            stale["audit"].append(u)
        projects[u] = cur
    new_state = {"saved_at": now, "script_version": SCRIPT_VERSION, "config_key": ckey, "projects": projects}
    keys = sorted({k for p in projects.values() for k in (p.get("audit") or {}).get("keys", [])})
    if keys or any("audit" in p for p in projects.values()):
        new_state["audit_keys"] = keys
    # "Scanning for": what your active projects use. Silenced and skipped projects don't count.
    inv = inventory({clean(u): ((p.get("hygiene") or {}).get("stack") or {}).get("uses") or []
                     for u, p in projects.items() if _status(statuses, u) == "active"})
    old_inv = state.get("stack") if isinstance(state.get("stack"), dict) else None
    new_tech = sorted(t for t in inv if old_inv is not None and t not in old_inv)
    new_state["stack"] = inv
    write_json(state_path, new_state, indent=1)
    if stack_path:
        write_text(stack_path, render_stack(inv, new_tech, now[:10]))
    out({"saved": state_path, "projects": len(projects), "updated": len(units),
         "not_saved_inputs_changed": {k: v for k, v in stale.items() if v},
         "stack_file": stack_path, "stack": len(inv),
         "new_in_stack": "first-run" if old_inv is None else
         [{"tech": t, "projects": inv[t], "checked_locally": stack_coverage(t)} for t in new_tech]})
    return 0


# ------------------------------------------------------------------ your decisions about projects

def _status(statuses, name):
    """Status for a unit name, also for names saved in an older state (either Unicode form)."""
    if name in statuses:
        return statuses[name]
    return next((s for u, s in statuses.items() if same_name(u, name)), "active")


def sub_statuses(path, units):
    """{"<project>/<folder>": status}: silencing decisions for sub-folders of discovered projects."""
    saved = load_json(path, {}) if path else {}
    saved = saved.get("projects") if isinstance(saved, dict) and isinstance(saved.get("projects"), dict) else {}
    return {n: v["status"] for n, v in saved.items() if isinstance(v, dict) and v.get("status") in SILENCED
            and any(nfc(n).startswith(nfc(u) + "/") for u in units)}


def _sub_folder(name, units, root):
    """'<project>/<folder>' for an existing, real sub-folder of a project, else None."""
    parts = name.strip("/").split("/")
    for i in range(len(parts) - 1, 0, -1):
        found, _ = resolve_units(["/".join(parts[:i])], units)
        rest = parts[i:]
        if found and not any(p in ("", ".", "..") for p in rest):
            path = os.path.join(root, found[0], *rest)
            if os.path.isdir(path) and not os.path.islink(path):
                return found[0] + "/" + "/".join(rest)
    return None


def project_statuses(path, units):
    """{unit: status} for the discovered units that have a decision (raw names, never sanitised)."""
    saved = load_json(path, {}) if path else {}
    saved = saved.get("projects") if isinstance(saved, dict) and isinstance(saved.get("projects"), dict) else {}
    out = {}
    for name, v in saved.items():
        s = v.get("status") if isinstance(v, dict) else None
        if s in STATUSES and s != "active":
            hit = [u for u in units if u == name] or [u for u in units if same_name(u, name)]
            if hit:
                out[hit[0]] = s
    return out


def _choices(statuses, silenced_too=True):
    """Short output field: projects you decided about (skip always; silenced ones where not listed)."""
    pick = {u: s for u, s in sorted(statuses.items()) if silenced_too or s == "skip"}
    return {"your_decisions": pick} if pick else {}


def silence_matches(res, silenced):
    """Your decisions apply to news matches too: silenced projects leave affected/unknown, so they
    never open or block a tracker row, and are listed once under "silenced"."""
    for v in res.values():
        hit = sorted(u for u in v["affected"] + v["unknown"] if u in silenced)
        if hit:
            v["affected"] = [u for u in v["affected"] if u not in silenced]
            v["unknown"] = [u for u in v["unknown"] if u not in silenced]
            v["complete"] = not v["unknown"]
            v["silenced"] = hit
    return res


def cmd_project(a, units, path, root, exclude):
    if not path:
        return fail("project needs a config (the decisions live in the storage folder)")
    try:
        path = _dest(path, root, exclude, "project-status.json")
    except UnsafeDestination as e:
        return fail(str(e))
    doc = load_json(path, {})
    doc = doc if isinstance(doc, dict) and isinstance(doc.get("projects"), dict) else {"projects": {}}
    if not a.args or a.args == ["list"]:
        out({"projects": {n: {**v, "found": any(same_name(u, n) for u in units)}
                          for n, v in doc["projects"].items() if isinstance(v, dict)}, "statuses": STATUSES})
        return 0
    if len(a.args) != 2 or a.args[1] not in STATUSES:
        return fail(f"usage: project list | project NAME STATUS [--note TEXT]; STATUS: {', '.join(STATUSES)}")
    found, _ = resolve_units([a.args[0]], units)
    sub = None if found else _sub_folder(a.args[0], units, root)
    if not found and not sub:
        return fail(f"no project named {clean(a.args[0])} in this scan (use the names `changed` prints)")
    u, status = (found[0] if found else sub), a.args[1]
    if sub and status == "skip":
        return fail("a sub-folder can't be skipped: add it to `exclusions` in the config instead")
    if status == "inactive" and not a.not_deployed:
        # A deployed app is still exposed: silencing needs an answer from the user, never a guess.
        out({"error": "ask the user first", "ask": f"Is {clean(u)} still deployed anywhere?",
             "next": "No: run again with --not-deployed. Yes: keep it active (it is still exposed)."})
        return 2
    for n in [n for n in doc["projects"] if same_name(n, u)]:
        del doc["projects"][n]
    if status != "active":
        doc["projects"][u] = {"status": status, "since": a.date or datetime.date.today().isoformat(),
                              **({"note": a.note} if a.note else {}),
                              **({"deployed": False} if status == "inactive" else {})}
    write_json(path, doc, indent=1)
    out({"saved": path, "project": u, "status": status, "meaning": STATUSES[status]})
    return 0


def cmd_marker(a, storage, root, exclude):
    """The briefing writes start at its beginning and done at its end (overwritten, never deleted: deletion
    may be blocked where the state lives). The scan runs check (or wait) first."""
    path = os.path.join(storage, "state", "briefing-running")
    try:
        path = _dest(path, root, exclude, "marker")
    except UnsafeDestination as e:
        return fail(str(e))
    action = (a.args or ["check"])[0]
    if action in ("start", "done"):
        now = time.time()
        write_json(path, {"state": "running" if action == "start" else "done", "at": now,
                          "at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))})
        out({"saved": path, "state": "running" if action == "start" else "done"})
        return 0
    if action not in ("check", "wait"):
        return fail("usage: marker start | done | check | wait")

    def status():
        m = load_json(path, {})
        m = m if isinstance(m, dict) else {}
        age = time.time() - float(m.get("at") or 0) if isinstance(m.get("at"), (int, float)) else None
        running = m.get("state") == "running" and age is not None and 0 <= age < MARKER_FRESH
        return {"briefing_running": running, **({"age_minutes": round(age / 60, 1)} if age is not None else {}),
                **({"stale": True} if m.get("state") == "running" and not running else {})}
    st, t0 = status(), time.time()
    if action == "wait":
        # Short polls inside one shell call; the prompt repeats `wait` a few times, then goes on with a note.
        while st["briefing_running"] and time.time() - t0 < min(a.budget, 140):
            time.sleep(min(10, max(0.05, min(a.budget, 140) - (time.time() - t0))))
            st = status()
    out(st)
    return 0


def cmd_tracker(a, storage, root, exclude):
    path = a.tracker or os.path.join(storage, "actioned.md")
    try:
        path = _dest(path, root, exclude, "--tracker")
    except UnsafeDestination as e:
        return fail(str(e))
    if not os.path.isfile(path):
        return fail(f"tracker not found: {path}")
    before, rows, after = trk.load(path)
    action = (a.args or ["list"])[0]
    today = a.date or datetime.date.today().isoformat()
    try:
        if action == "list":
            out({"summary": trk.summary(rows), "rows": rows}, trusted=True)
            return 0
        if action == "mark" and len(a.args) >= 3:
            row = trk.mark(rows, a.args[1], " ".join(a.args[2:]), today, a.note)
        elif action == "add" and len(a.args) >= 3:
            row = trk.add(rows, a.args[1], " ".join(a.args[2:]), today, note=a.note or "")
        else:
            out({"error": "usage: tracker list | mark ID STATUS [--note TEXT] | add ID ITEM [--note TEXT]"})
            return 2
    except (KeyError, ValueError) as e:
        out({"error": str(e).strip("'\"")})
        return 2
    trk.save(path, before, rows, after)
    out({"saved": path, "row": row}, trusted=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
