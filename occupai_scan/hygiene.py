"""Standing hygiene checks: secrets, database access rules, GitHub Actions, AI agent setup.

Never opens sensitive files, never prints or stores secret values (counts and pattern types only).
"""
import fnmatch
import os
import re

from urllib.parse import urlsplit

from .common import LOCKFILES, PRUNE, SENSITIVE_GLOBS, TEXT_EXT_SKIP, excluded, findings_of, git, is_git, is_sensitive
from .discovery import origin_owner, ownership
from .safefs import MAX_TEXT, Coverage, PathRefused
from .stack import detect

SECRET_PATTERNS = {
    "anthropic-key": r"sk-ant-[A-Za-z0-9_-]{20,}",
    "openai-key": r"sk-(?!ant-)(proj-)?[A-Za-z0-9_-]{32,}",
    "github-token": r"(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})",
    "npm-token": r"npm_[A-Za-z0-9]{30,}",
    "aws-access-key": r"AKIA[0-9A-Z]{16}",
    "google-api-key": r"AIza[0-9A-Za-z_-]{35}",
    "slack-token": r"xox[bpas]-[A-Za-z0-9-]{10,}",
    "supabase-secret": r"(sb_secret_[A-Za-z0-9_-]{20,}|sbp_[A-Za-z0-9]{30,})",
    "jwt": r"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}",
    "db-url-with-password": r"postgres(ql)?://[^\s:'\"@/]+:[^\s@'\"]{4,}@",
    "private-key-block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}
# Boundary guards: a key must not sit inside a longer base64/alnum run (avoids random hits in embedded images).
SECRET_RE = {k: re.compile(r"(?<![A-Za-z0-9+/_-])" + v + r"(?![A-Za-z0-9+/=_-])") for k, v in SECRET_PATTERNS.items()}
DATA_URI = re.compile(r"data:[a-z0-9.+-]+/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=\s]+", re.I)
LONG_B64 = re.compile(r"[A-Za-z0-9+/]{300,}={0,2}")

# Invisible/bidi characters used to hide instructions. Excludes U+200D (ZWJ) and U+FE0F, which emoji
# use legitimately; a BOM (U+FEFF) only counts when it's not the first character.
HIDDEN_UNICODE = re.compile("[​‌‎‏‪-‮⁠-⁤⁦-⁩"
                            "\U000e0000-\U000e007f]|(?<!^)﻿")

PLACEHOLDER = re.compile(r"(example|sample|placeholder|dummy|fake|changeme|your[_-]?|xxxx|<[^>]*>|\$\{|\{\{|user:pass|"
                         r"username:password|postgres:postgres|redacted|\*\*\*\*)", re.I)
REGEX_LINE = re.compile(r"(grep\s|regex|RegExp|re\.compile|\\[sdwbS]|\(\?[:!=<]|\[\^|pattern\s*[:=])")
PUBLIC_CONFIG_FILES = {"google-services.json", "GoogleService-Info.plist", "firebase_app_id_file.json",
                       "firebase.json", "firebaseConfig.js", "firebaseConfig.ts"}


def strip_blobs(text):
    """Remove embedded base64 (data: URIs, very long base64 runs) before pattern matching."""
    return LONG_B64.sub(" ", DATA_URI.sub(" ", text))


def count_secrets(text):
    """{pattern_type: count} for real-looking keys in text. Values are never returned."""
    text = strip_blobs(text)
    out = {}
    for name, rx in SECRET_RE.items():
        n = 0
        for m in rx.finditer(text):
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            line = text[start: end if end != -1 else len(text)]
            if PLACEHOLDER.search(m.group(0)) or REGEX_LINE.search(line):
                continue  # placeholder value or a detector pattern, not a secret
            n += 1
        if n:
            out[name] = n
    return out


def tracked_files(repo):
    rc, out, _ = git(repo, "ls-files", "-z", timeout=90)
    return [f for f in out.split("\0") if f] if rc == 0 else None


def _in_scope(pol, unit, rel, skip):
    """A unit-relative path the checks may consider: not pruned, excluded or under an ignore marker."""
    if any(rel.startswith(s) for s in skip) or any(part in PRUNE for part in rel.split("/")):
        return False
    return not excluded(f"{unit}/{rel}", pol.patterns)


def check_secrets(pol, unit):
    p = pol.unit_path(unit)
    cov = Coverage()
    findings = []
    in_git = is_git(p)
    files = tracked_files(p) if in_git else None
    walked = []
    for dp, dns, fns in pol.walk(unit, on_symlink=lambda rel: cov.skip(rel, "symlink"), cov=cov):
        walked += [os.path.relpath(os.path.join(dp, f), p) for f in fns]
    if files is None:  # non-git (or git failed): walk, but nothing is known to be "committed"
        if in_git:
            cov.skip(unit, "git-failed")
        files = walked
        committed = set()
    else:
        committed = set(files)
    skip = pol.ignored_prefixes(unit) if in_git else []
    files = [f for f in files if _in_scope(pol, unit, f, skip)]
    committed = {f for f in committed if _in_scope(pol, unit, f, skip)}
    # 1) sensitive files: metadata only (never opened)
    present = [f for f in walked if is_sensitive(os.path.basename(f))]
    for rel in sorted(set(present) | {f for f in committed if is_sensitive(os.path.basename(f))}):
        tracked = rel in committed
        ignored = None
        if in_git and not tracked:
            rc, _, _ = git(p, "check-ignore", "-q", "--", rel)
            ignored = True if rc == 0 else False if rc == 1 else None
            if ignored is None:
                cov.skip(rel, "git-failed")
        maybe_config = os.path.basename(rel) in (".npmrc", ".pypirc")
        if tracked:
            f = {"type": "sensitive-file-committed", "file": rel, "severity": "medium" if maybe_config else "high"}
            if maybe_config:
                f["note"] = "often only registry settings; check it has no _authToken/password (file not opened)"
            findings.append(f)
        elif in_git and ignored is False:
            findings.append({"type": "sensitive-file-not-gitignored", "file": rel, "severity": "medium"})
    if in_git:
        globs = [f":(glob)**/{g}" for g in SENSITIVE_GLOBS]
        rc, out, _ = git(p, "log", "--all", "--diff-filter=A", "--name-only", "--format=", "--", *globs, timeout=120)
        if rc != 0:
            cov.skip(unit, "git-history-failed")
        hist = sorted({ln for ln in out.splitlines() if ln})
        for rel in hist:
            if not _in_scope(pol, unit, rel, skip) or not is_sensitive(os.path.basename(rel)):
                continue
            if rel not in committed:
                mc = os.path.basename(rel) in (".npmrc", ".pypirc")
                findings.append({"type": "sensitive-file-in-history", "file": rel, "severity": "medium" if mc else "high"})
    # 2) key patterns in (tracked) text files: counts + type only, never values
    for rel in files:
        base = os.path.basename(rel)
        if is_sensitive(base) or base in LOCKFILES or rel.lower().endswith(TEXT_EXT_SKIP):
            continue
        text = pol.read_text(os.path.join(p, rel), MAX_TEXT, cov)
        if text is None:
            continue
        for name, n in count_secrets(text).items():
            sev = "high" if rel in committed else "medium"
            note = None
            if name == "google-api-key":
                # Browser/Firebase keys are public by design; the risk is a key without restrictions.
                if base in PUBLIC_CONFIG_FILES:
                    sev, note = "info", "client config file; key is public by design, check API restrictions"
                else:
                    sev, note = "medium", "often a public browser/Firebase key; check it's restricted (HTTP referrer/app)"
            f = {"type": "key-pattern", "pattern": name, "file": rel, "count": n, "tracked": rel in committed, "severity": sev}
            if note:
                f["note"] = note
            findings.append(f)
    has_gh, owner = origin_owner(p)
    return cov.result(findings=findings, github_remote=has_gh, origin_owner=owner)


def is_supabase_project(pol, unit, cov):
    if pol.is_safe_dir(os.path.join(unit, "supabase")):
        return True
    for dp, dns, fns in pol.walk(unit, cov=cov, wanted=lambda a: os.path.basename(a) == "package.json"):
        if "package.json" in fns:
            t = pol.read_text(os.path.join(dp, "package.json"), MAX_TEXT, cov)
            if t and "@supabase/" in t:
                return True
    return False


DB_RULE_FILES = ("firestore.rules", "storage.rules", "database.rules.json")
JS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".vue", ".svelte", ".astro")


def check_db(pol, unit):
    p = pol.unit_path(unit)
    cov = Coverage()
    findings = []
    supabase = is_supabase_project(pol, unit, cov)
    tables, rls, policies = {}, set(), set()
    ct = re.compile(r"create\s+table\s+(if\s+not\s+exists\s+)?((public|\"public\")\.)?\"?([a-z0-9_]+)\"?", re.I)
    en = re.compile(r"alter\s+table\s+(only\s+)?((public|\"public\")\.)?\"?([a-z0-9_]+)\"?\s+enable\s+row\s+level\s+security", re.I)
    po = re.compile(r"create\s+policy\s+.+?\s+on\s+((public|\"public\")\.)?\"?([a-z0-9_]+)\"?", re.I | re.S)

    def wanted(a):
        b = os.path.basename(a)
        return (b.endswith(".sql") and supabase) or b in DB_RULE_FILES

    for dp, dns, fns in pol.walk(unit, cov=cov, wanted=wanted):
        for f in fns:
            fp = os.path.join(dp, f)
            rel = os.path.relpath(fp, p)
            if f.endswith(".sql") and supabase:
                s = pol.read_text(fp, MAX_TEXT, cov)
                if s is None:
                    continue
                s = re.sub(r"--[^\n]*", "", re.sub(r"/\*.*?\*/", "", s, flags=re.S))  # strip SQL comments
                for m in ct.finditer(s):
                    tables.setdefault(m.group(4).lower(), rel)
                rls |= {m.group(4).lower() for m in en.finditer(s)}
                policies |= {m.group(3).lower() for m in po.finditer(s)}
            elif f in DB_RULE_FILES[:2]:
                s = pol.read_text(fp, MAX_TEXT, cov)
                if s and re.search(r"allow\s+(read|write|read,\s*write|write,\s*read)\s*(:\s*if\s+true)?\s*;", s):
                    findings.append({"type": "firebase-open-rule", "file": rel, "severity": "high"})
            elif f == "database.rules.json":
                s = pol.read_text(fp, MAX_TEXT, cov)
                if s and re.search(r'"\.(read|write)"\s*:\s*true', s):
                    findings.append({"type": "firebase-rtdb-open-rule", "file": rel, "severity": "high"})
    for t, rel in sorted(tables.items()):
        if t.startswith(("schema_migrations", "_prisma", "knex_")):
            continue
        if t not in rls:
            findings.append({"type": "supabase-table-without-rls", "table": t, "file": rel, "severity": "high"})
        elif t not in policies:
            findings.append({"type": "rls-enabled-no-policy", "table": t, "file": rel, "severity": "info"})
    return cov.result(findings=findings, supabase_project=supabase, sql_tables=len(tables))


def check_gha(pol, unit):
    cov = Coverage()
    wdir = os.path.join(unit, ".github", "workflows")
    findings = []
    try:
        p = pol.check_dir(wdir)
    except PathRefused as e:
        if e.reason == "symlink":
            cov.skip(f"{unit}/.github/workflows", "symlink")
        return cov.result(findings=[], workflows=0)
    wfs = sorted(f for f in os.listdir(p) if f.endswith((".yml", ".yaml")))
    for f in wfs:
        rel = f".github/workflows/{f}"
        s = pol.read_text(os.path.join(p, f), MAX_TEXT, cov)
        if s is None:
            continue
        for m in re.finditer(r"uses:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)", s):
            action, ref = m.group(1), m.group(2)
            if action.startswith("./") or re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            first_party = action.split("/")[0] in ("actions", "github")
            findings.append({"type": "action-not-pinned-to-sha", "file": rel, "action": f"{action}@{ref}",
                             "severity": "low" if first_party else "medium"})
        if not re.search(r"(?m)^permissions:", s):
            findings.append({"type": "no-top-level-permissions", "file": rel, "severity": "medium"})
        if re.search(r"permissions:\s*write-all", s):
            findings.append({"type": "permissions-write-all", "file": rel, "severity": "medium"})
        if "pull_request_target" in s and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", s):
            findings.append({"type": "pull-request-target-checkout", "file": rel, "severity": "high"})
        # Script injection: ${{ github.event.* }} directly inside a run: block (env: indirection is the safe pattern)
        lines = s.splitlines()
        i, hit = 0, False
        while i < len(lines) and not hit:
            m = re.match(r"^(\s*)(-\s+)?run:\s*(.*)$", lines[i])
            if m:
                indent = len(m.group(1)) + (len(m.group(2)) if m.group(2) else 0)
                block = [m.group(3)]
                j = i + 1
                if m.group(3).strip() in ("|", ">", "|-", ">-", "|+", ">+", ""):
                    while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
                        block.append(lines[j])
                        j += 1
                if re.search(r"\$\{\{\s*github\.event\.", "\n".join(block)):
                    findings.append({"type": "script-injection-risk", "file": rel, "line": i + 1, "severity": "high"})
                    hit = True
                i = j
            else:
                i += 1
    return cov.result(findings=findings, workflows=len(wfs))


MCP_FILES = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "claude_desktop_config.json",
             ".gemini/settings.json", ".codex/config.toml")
AGENT_PERM_FILES = (".claude/settings.json", ".claude/settings.local.json")
INSTRUCTION_FILES = ("CLAUDE.md", "AGENTS.md", ".cursorrules", "GEMINI.md", ".github/copilot-instructions.md")
BROWSER_AI_VAR = re.compile(r"\b((?:NEXT_PUBLIC|VITE|PUBLIC|EXPO_PUBLIC|REACT_APP)_[A-Z0-9_]*"
                            r"(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|COHERE|REPLICATE|ELEVENLABS|SERVICE_ROLE)[A-Z0-9_]*)\b")


_PKG = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*(@[A-Za-z0-9.^~<>=*+-]+)?$")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$")


def safe_host(url):
    """Validated hostname of a URL, never user info, port, path, query or fragment. None if invalid."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return None
    return host if host and len(host) <= 253 and _HOST.match(host) else None


def check_ai(pol, unit):
    p = pol.unit_path(unit)
    cov = Coverage()
    findings = []
    for rel in MCP_FILES:
        s = pol.read_text(os.path.join(p, rel), MAX_TEXT, cov)
        if s is None:
            continue
        n = sum(count_secrets(s).values())
        if n:
            findings.append({"type": "mcp-config-inline-secret", "file": rel, "count": n, "severity": "high"})
        for m in re.finditer(r"\"(npx|uvx|bunx|pnpm\s+dlx)\"[^\]]*?\"args\"\s*:\s*\[([^\]]*)\]|(npx|uvx|bunx)\s+(-y\s+)?([@\w./-]+)", s):
            pkgs = re.findall(r"\"(@?[\w./-]+(?:@[\w.^~<>=-]+)?)\"", m.group(2) or "") or [m.group(5) or ""]
            for pk in pkgs:
                if pk.startswith("-") or not pk:
                    continue
                _, _, ver = pk.rpartition("@") if pk.count("@") > (1 if pk.startswith("@") else 0) else (pk, "", "")
                if not ver or ver == "latest":
                    findings.append({"type": "mcp-server-unpinned", "file": rel,
                                     "package": pk if _PKG.match(pk) and len(pk) <= 214 else "invalid-name",
                                     "severity": "medium"})
                break
        hosts = set()
        for u in re.findall(r"https?://[^\s\"']+", s):
            h = safe_host(u)
            if h is None:
                hosts.add("invalid-host")
            elif h not in ("localhost", "127.0.0.1") and not h.endswith(".localhost"):
                hosts.add(h)
        for h in sorted(hosts):
            findings.append({"type": "mcp-remote-url", "file": rel, "host": h, "severity": "info"})
    for rel in AGENT_PERM_FILES:
        j = pol.load_json(os.path.join(p, rel), MAX_TEXT, cov)
        if j is None:
            continue
        perms = j.get("permissions", {}) if isinstance(j, dict) else {}
        allow = perms.get("allow", []) if isinstance(perms, dict) else []
        broad = [a for a in (allow if isinstance(allow, list) else []) if re.fullmatch(r"Bash\((\*|:\*)?\)|Bash|\*", str(a))]
        if broad:
            findings.append({"type": "agent-broad-allow", "file": rel, "rules": broad, "severity": "medium"})
        if isinstance(perms, dict) and perms.get("defaultMode") in ("bypassPermissions",):
            findings.append({"type": "agent-permissions-bypassed", "file": rel, "severity": "high"})
        if isinstance(j, dict) and j.get("hooks"):
            n = len(j["hooks"]) if isinstance(j["hooks"], (dict, list)) else 1
            findings.append({"type": "agent-hooks-present", "file": rel, "count": n, "severity": "info"})
    inst = list(INSTRUCTION_FILES)
    for skills_dir in (".claude/skills", ".agents/skills"):
        for dp, dns, fns in pol.walk(f"{unit}/{skills_dir}", cov=cov, wanted=lambda a: a.endswith(".md")):
            inst += [os.path.relpath(os.path.join(dp, f), p) for f in fns if f.endswith(".md")]
    for rel in inst:
        s = pol.read_text(os.path.join(p, rel), MAX_TEXT, cov)
        if s is None:
            continue
        h = len(HIDDEN_UNICODE.findall(s))
        if h:
            findings.append({"type": "hidden-unicode-in-agent-instructions", "file": rel, "count": h, "severity": "high"})
        if re.search(r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh", s):
            findings.append({"type": "pipe-to-shell-in-agent-instructions", "file": rel, "severity": "medium"})
    # AI keys exposed to the browser: variable NAMES only (never values; .env files are not opened)
    names = set()
    for dp, dns, fns in pol.walk(unit, cov=cov, wanted=lambda a: a.endswith(JS_EXT)):
        for f in fns:
            if not f.endswith(JS_EXT) or is_sensitive(f):
                continue
            t = pol.read_text(os.path.join(dp, f), MAX_TEXT, cov)
            if t:
                names |= set(BROWSER_AI_VAR.findall(t))
    for n in sorted(names):
        findings.append({"type": "ai-key-exposed-to-browser", "variable": n, "severity": "high"})
    return cov.result(findings=findings)


CHECKS = {"secrets": check_secrets, "db": check_db, "gha": check_gha, "ai": check_ai}


def run_hygiene(pol, unit, my_owners=()):
    """One project. Each check reports status ok | incomplete | error; one failure never stops the others."""
    r = {}
    try:
        pol = pol.for_unit(unit)  # contained file symlinks (CLAUDE.md -> AGENTS.md) become readable
    except PathRefused:
        pass  # each check reports the refusal itself
    for k, fn in CHECKS.items():
        try:
            r[k] = fn(pol, unit)
        except PathRefused as e:
            r[k] = {"status": "error", "error": f"unit-refused:{e.reason}", "findings": [], "skipped": []}
        except Exception as e:  # noqa: BLE001  never let one project break the run
            r[k] = {"status": "error", "error": f"exception:{type(e).__name__}", "findings": [], "skipped": []}
    try:
        r["stack"] = {"uses": detect(pol, unit)}  # not a check: never makes a result incomplete
    except Exception:  # noqa: BLE001
        r["stack"] = {"uses": []}
    sec = r.get("secrets", {})
    r["ownership"] = ownership(sec.get("origin_owner"), sec.get("github_remote"), list(my_owners))
    return r


# Key-like file names. Only names are looked at: these files are never opened.
KEY_NAMES = ("*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk", "*.p8", "id_rsa*", "id_ed25519*",
             "id_ecdsa*", "id_dsa*")


def key_like(fns):
    """{name: why} for key-like files in one folder: key file names, and NAME next to NAME.pub (an SSH
    key pair under any name, e.g. `private` + `private.pub`). Public halves (.pub) are not reported."""
    names = set(fns)
    out = {f: "key-file-name" for f in names if not f.endswith(".pub") and any(fnmatch.fnmatch(f, g) for g in KEY_NAMES)}
    out.update({f[:-4]: "ssh-key-pair" for f in names if f.endswith(".pub") and f[:-4] in names})
    return out


def keys_outside_projects(pol, units, skip=()):
    """Key-like files directly in the projects folder or in folders that aren't projects (no git repo,
    no lockfile): metadata only. Inside a project the secrets check covers them."""
    projects = {u for u in units if is_git(os.path.join(pol.root, u))
                or any(os.path.lexists(os.path.join(pol.root, u, f)) for f in LOCKFILES)} | set(skip)
    found = []
    for dp, dns, fns in pol.walk("."):
        rel = os.path.relpath(dp, pol.root)
        dns[:] = [d for d in dns if os.path.normpath(os.path.join(rel, d)) not in projects]
        for f, why in sorted(key_like(fns).items()):
            found.append({"type": "key-file-outside-projects", "file": os.path.normpath(os.path.join(rel, f)),
                          "why": why, "severity": "medium", "fix": "move to ~/.ssh or delete"})
    return found


def check_statuses(result):
    return {k: v.get("status", "error") for k, v in result.items() if k in CHECKS and isinstance(v, dict)}


def is_complete(result):
    st = check_statuses(result)
    return set(st) == set(CHECKS) and all(v == "ok" for v in st.values())


def severity_counts(result):
    fs = [f for k, v in result.items() if k in CHECKS for f in findings_of(v)]
    return {sev: sum(1 for f in fs if f.get("severity") == sev) for sev in ("high", "medium", "low", "info")}
