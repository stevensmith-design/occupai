"""Replay checks from checks.json against projects (news items, new-project onboarding).

Supported `match` rules (see schema/checks.schema.json and occupai_scan/versions.py for range syntax):
  packages            [{name, affected, ecosystem?}]  ecosystem "npm" (default): exact lockfile names,
                                          npm ranges (^ ~ x-ranges, hyphen, comparators, ||);
                                          "pypi": pinned name==version lines in requirements*.txt,
                                          PEP 440 comparators
  malicious_packages  [name]              exact npm lockfile names; any version except "0.0.1-security"
  runtimes            [{name, affected}]  node | python: .nvmrc, .node-version, .python-version,
                                          .tool-versions, workflow node-/python-version, Dockerfile FROM
  files               [{glob, contains?}] path glob relative to the project, optional regex on content
  git                 {branches: [regex], commit_messages: [text], since: YYYY-MM-DD}
Sensitive files are never opened, whatever a rule says. A project is not-affected only when every
input was read and understood; an unsupported range, version, pin, lockfile format or requirement,
or a folder cut off by the depth limit, makes it unknown.
"""
import fnmatch
import json
import os
import re

from .common import git, is_git, is_sensitive
from .deps import (PY_MANIFESTS, UNSUPPORTED_PY, is_requirements, uncovered_manifests, lock_versions, lockfiles_in,
                   requirement_lines)
from .safefs import MAX_TEXT, Coverage
from .versions import RangeError, effective_pin, npm_in_range, pypi_in_range, pypi_name, validate_range


def in_range(version, rng):
    """npm-style range test (kept for callers and tests). Raises RangeError if unsupported."""
    return npm_in_range(version, rng)


# ------------------------------------------------------------------ runtime pins

def runtime_pins(pol, unit, name, cov=None):
    """[(file, pin_string)] for node or python pins in a project. Reads config files only. Pins that
    aren't plain versions (lts/*, a matrix expression) are returned too: the caller reports unknown."""
    project = os.path.join(pol.root, unit)
    pins = []
    files = {"node": [".nvmrc", ".node-version"], "python": [".python-version"]}[name]
    for f in files:
        t = pol.read_text(os.path.join(project, f), MAX_TEXT, cov)
        first = [x.strip() for x in t.splitlines() if x.strip() and not x.strip().startswith("#")] if t else []
        if first:
            pins.append((f, first[0]))
    t = pol.read_text(os.path.join(project, ".tool-versions"), MAX_TEXT, cov)
    if t:
        key = {"node": ("nodejs", "node"), "python": ("python",)}[name]
        for line in t.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in key:
                pins.append((".tool-versions", parts[1]))
    def wanted(a):
        b, d = os.path.basename(a), os.path.relpath(os.path.dirname(a), project)
        return (d == os.path.join(".github", "workflows") and b.endswith((".yml", ".yaml"))) or \
            b == "Dockerfile" or b.startswith("Dockerfile.")

    for dp, dns, fns in pol.walk(unit, cov=cov, wanted=wanted):
        rel_dir = os.path.relpath(dp, project)
        for f in fns:
            if rel_dir == os.path.join(".github", "workflows") and f.endswith((".yml", ".yaml")):
                s = pol.read_text(os.path.join(dp, f), MAX_TEXT, cov)
                for m in re.finditer(rf"(?m){name}-version:\s*(.+?)\s*$", s or ""):
                    val = m.group(1).split(" #")[0].strip()
                    vals = val[1:-1].split(",") if val.startswith("[") and val.endswith("]") else [val]
                    for v in vals:
                        if v.strip().strip("'\""):
                            pins.append((f".github/workflows/{f}", v.strip().strip("'\"")))
            elif f == "Dockerfile" or f.startswith("Dockerfile."):
                s = pol.read_text(os.path.join(dp, f), MAX_TEXT, cov)
                for m in re.finditer(rf"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?(?:library/)?{name}:(\S+)", s or ""):
                    tag = m.group(1)
                    num = re.match(r"(\d+(?:\.\d+){0,2})(?:-|$)", tag)
                    pins.append((os.path.relpath(os.path.join(dp, f), project), num.group(1) if num else tag))
    return pins


# ------------------------------------------------------------------ one check, one project

RULE_KEYS = {"packages", "malicious_packages", "runtimes", "files", "git"}
AGENT_KEYS = {"machine", "account"}  # for the agent; not replayed per project
GIT_KEYS = {"branches", "commit_messages", "since"}


def _rule_list(rules, key, cov, kind=list):
    v = rules.get(key) or kind()
    if not isinstance(v, kind):
        cov.skip(f"rule:{key}", "unsupported-rule")
        return kind()
    return v


def _npm_evidence(pol, unit, rules, bad_names, cov):
    evidence = []
    names = [r["name"] for r in rules] + list(bad_names)
    locks = lockfiles_in(pol, unit, cov)
    lock_dirs = {os.path.dirname(lf) for lf in locks}
    for lf in locks:
        found = lock_versions(pol, lf, names, cov)
        if found is None:
            continue
        rel = pol.rel(lf)
        for r in rules:
            for v in found.get(r["name"], []):
                try:
                    hit = npm_in_range(v, r["affected"])
                except RangeError:
                    cov.skip(rel, "unparsed-version")  # e.g. a git/file dependency: version unknown
                    continue
                if hit:
                    evidence.append({"kind": "package", "file": rel, "package": r["name"], "version": v,
                                     "affected": r["affected"]})
        for n in bad_names:
            vs = [v for v in found.get(n, []) if v != "0.0.1-security"]
            if vs:
                evidence.append({"kind": "malicious-package", "file": rel, "package": n, "versions": vs})
    # A package.json with dependencies but no lockfile: installed versions (and transitive packages)
    # can't be known, so the project is unknown, not clean.
    for dp, dns, fns in pol.walk(unit, cov=cov, wanted=lambda a: os.path.basename(a) == "package.json"):
        if "package.json" in fns and not any(dp == d or dp.startswith(d + os.sep) for d in lock_dirs):
            j = pol.load_json(os.path.join(dp, "package.json"), MAX_TEXT, cov)
            if isinstance(j, dict) and any(isinstance(j.get(k), dict) and j[k] for k in
                                           ("dependencies", "devDependencies", "optionalDependencies")):
                cov.skip(pol.rel(os.path.join(dp, "package.json")), "no-lockfile")
    return evidence


def _pypi_evidence(pol, unit, rules, cov):
    evidence = []
    wanted = {pypi_name(r["name"]): r for r in rules}
    reqs, manifests, locks = [], [], []

    def py_input(a):
        b = os.path.basename(a)
        return is_requirements(b) or b in PY_MANIFESTS or b in UNSUPPORTED_PY

    for dp, dns, fns in pol.walk(unit, cov=cov, wanted=py_input):
        reqs += [os.path.join(dp, f) for f in fns if is_requirements(f)]
        manifests += [os.path.join(dp, f) for f in fns if f in PY_MANIFESTS]
        locks += [os.path.join(dp, f) for f in fns if f in UNSUPPORTED_PY]
    for rf in sorted(reqs):
        t = pol.read_text(rf, MAX_TEXT, cov)
        if t is None:
            continue
        rel = pol.rel(rf)
        for n, kind, name, ver in requirement_lines(t):
            norm = pypi_name(name) if name else None
            if kind == "pin" and norm in wanted:
                r = wanted[norm]
                try:
                    hit = pypi_in_range(ver, r["affected"])
                except RangeError:
                    cov.skip(rel, "unparsed-version")
                    continue
                if hit:
                    evidence.append({"kind": "package", "ecosystem": "pypi", "file": rel, "line": n,
                                     "package": r["name"], "version": ver, "affected": r["affected"]})
            elif kind in ("unpinned", "environment-marker") and norm in wanted:
                cov.skip(rel, "unpinned-requirement")
            elif kind in ("include-not-followed", "url-or-vcs", "editable", "option"):
                cov.skip(rel, "requirement-not-followed")  # could install any package
    for lf in locks:
        cov.skip(pol.rel(lf), "unsupported-python-lockfile")
    for mf in uncovered_manifests(manifests, reqs):
        cov.skip(pol.rel(mf), "unsupported-python-manifest")
    return evidence


def match_check(pol, unit, check, cov=None):
    """Evidence list for one check in one project. Anything that couldn't be read, parsed or run is
    noted on cov, so the caller reports 'unknown' instead of 'not-affected'."""
    cov = cov if cov is not None else Coverage()
    pol = pol.for_unit(unit)
    p = pol.unit_root
    rules = check.get("match") or {}
    if not isinstance(rules, dict):
        cov.skip("rule:match", "unsupported-rule")
        return []
    # An unknown key (a typo such as "package") or a check with no project rule at all is unknown,
    # never "not-affected, complete".
    for k in sorted(set(rules) - RULE_KEYS - AGENT_KEYS):
        cov.skip(f"rule:{k}", "unsupported-rule")
    g = rules.get("git") or {}
    for k in sorted(set(g) - GIT_KEYS) if isinstance(g, dict) else ["git"]:
        cov.skip(f"rule:git.{k}", "unsupported-rule")
    g = g if isinstance(g, dict) else {}
    ran = bool(g.get("branches") or g.get("commit_messages"))
    evidence = []
    npm_rules, py_rules = [], []
    for r in _rule_list(rules, "packages", cov):
        eco = r.get("ecosystem", "npm") if isinstance(r, dict) else None
        if not isinstance(r, dict) or not isinstance(r.get("name"), str) or eco not in ("npm", "pypi"):
            cov.skip("rule:packages", "unsupported-rule")
        elif validate_range(r.get("affected"), eco):
            cov.skip(f"rule:{r['name']}", "unsupported-range")  # never silently reinterpreted
        else:
            (py_rules if eco == "pypi" else npm_rules).append(r)
    bad_names = [n for n in _rule_list(rules, "malicious_packages", cov) if isinstance(n, str)]
    ran = ran or bool(npm_rules or bad_names or py_rules)
    if npm_rules or bad_names:
        evidence += _npm_evidence(pol, unit, npm_rules, bad_names, cov)
    if py_rules:
        evidence += _pypi_evidence(pol, unit, py_rules, cov)
    for r in _rule_list(rules, "runtimes", cov):
        if not isinstance(r, dict) or r.get("name") not in ("node", "python") or validate_range(r.get("affected")):
            cov.skip("rule:runtimes", "unsupported-range" if isinstance(r, dict) else "unsupported-rule")
            continue
        ran = True
        for f, v in runtime_pins(pol, unit, r["name"], cov):
            eff = effective_pin(v)
            if eff is None:
                cov.skip(f, "unsupported-pin")  # lts/*, latest, ${{ matrix.node }}: version unknown
            elif npm_in_range(eff, r["affected"]):
                evidence.append({"kind": "runtime-pin", "file": f, "runtime": r["name"], "pin": v, "affected": r["affected"]})
    for r in _rule_list(rules, "files", cov):
        try:
            rx = re.compile(r["contains"]) if r.get("contains") else None
            glob = r["glob"]
        except (re.error, KeyError, TypeError):
            cov.skip("rule:files", "unsupported-rule")
            continue
        ran = True
        for dp, dns, fns in pol.walk(unit, cov=cov, wanted=lambda a: fnmatch.fnmatch(os.path.relpath(a, p), glob)):
            for f in fns:
                rel = os.path.relpath(os.path.join(dp, f), p)
                if not fnmatch.fnmatch(rel, glob):
                    continue
                if rx is not None:
                    if is_sensitive(f):
                        continue  # never opened
                    t = pol.read_text(os.path.join(dp, f), MAX_TEXT, cov)
                    if t is None or not rx.search(t):
                        continue
                evidence.append({"kind": "file", "file": rel, "rule": glob})
    if ran is False:
        cov.skip("rule:match", "no-project-rule")
    if g and is_git(p):
        since = ["--since", g["since"]] if g.get("since") else []
        rc, br, _ = git(p, "for-each-ref", "--format=%(refname:short)", "refs/heads", "refs/remotes")
        if rc != 0:
            cov.skip(unit, "git-failed")
        for b in br.splitlines():
            short = b.split("/", 1)[1] if b.startswith("origin/") else b
            for rx in g.get("branches", []) or []:
                if re.fullmatch(rx, short):
                    evidence.append({"kind": "git-branch", "branch": b, "rule": rx})
        msgs = g.get("commit_messages", []) or []
        if msgs:
            rc, log, _ = git(p, "log", "--all", *since, "--format=%h %s", timeout=90)
            if rc != 0:
                cov.skip(unit, "git-failed")
            for line in log.splitlines():
                h, _, subj = line.partition(" ")
                if subj.strip() in msgs:
                    evidence.append({"kind": "git-commit", "commit": h, "message": subj.strip()})
    return evidence


def run_match(pol, units, checks, only_ids=None):
    """{check_id: {"projects": {unit: {"status": open|not-affected|unknown, "evidence": [...]}}, ...}}
    not-affected only when every input the rules need was read; otherwise unknown (never clean)."""
    out = {}
    for c in checks:
        if only_ids and c["id"] not in only_ids:
            continue
        if "project" not in str(c.get("scope", "project")):
            continue
        projects = {}
        for u in units:
            cov = Coverage()
            try:
                ev = match_check(pol, u, c, cov)
            except Exception as e:  # noqa: BLE001  one project never stops the others
                projects[u] = {"status": "unknown", "evidence": [], "error": f"exception:{type(e).__name__}",
                               "skipped": cov.skipped}
                continue
            status = "open" if ev else ("not-affected" if cov.complete else "unknown")
            projects[u] = {"status": status, "evidence": ev}
            if cov.skipped:
                projects[u]["skipped"] = cov.skipped
        affected = sorted(u for u, r in projects.items() if r["status"] == "open")
        unknown = sorted(u for u, r in projects.items() if r["status"] == "unknown")
        out[c["id"]] = {"title": c.get("title"), "affected": affected, "unknown": unknown, "checked": len(units),
                        "complete": not unknown, "projects": projects}
    return out


def load_checks(path):
    with open(path) as f:
        return json.load(f).get("checks", [])
