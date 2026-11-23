"""Shared constants and small helpers. Python 3 stdlib only."""
import json
import os
import platform
import re
import secrets
import subprocess
import unicodedata

from .safefs import (IGNORE_MARKER, PRUNE, SENSITIVE_GLOBS, Policy, excluded,  # noqa: F401  (re-exported)
                     is_sensitive)

# Bump when check logic changes: cached hygiene results saved by older versions are re-run.
SCRIPT_VERSION = "0.1.9"

# Only used when no config is given. Real exclusions live in occupai.config.yaml.
FALLBACK_EXCLUDE = ["*/.claude/worktrees/*"]
LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")

TEXT_EXT_SKIP = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".woff",
                 ".woff2", ".ttf", ".otf", ".mp4", ".mov", ".mp3", ".lock", ".svg", ".avif", ".psd",
                 ".sketch", ".fig", ".bin", ".exe", ".dylib", ".so", ".jar", ".map")

# Host variables a subprocess may inherit. Everything else (tokens, NODE_OPTIONS, npm_config_*,
# GIT_* overrides) is dropped.
ENV_PASS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SYSTEMROOT", "COMSPEC", "PATHEXT",
            "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
            "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR")


def base_env(**extra):
    env = {k: os.environ[k] for k in ENV_PASS if k in os.environ}
    env.update(extra)
    return env


def sh(args, cwd=None, timeout=60, env=None):
    """Run a command. Returns (rc, stdout, stderr, problem): problem is a safe category or None.
    stderr is for local decisions only; never put it in output."""
    try:
        r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env=env if env is not None else base_env(), stdin=subprocess.DEVNULL,
                           errors="replace")
        return r.returncode, r.stdout, r.stderr, None
    except subprocess.TimeoutExpired:
        return 124, "", "", "timeout"
    except FileNotFoundError:
        return 127, "", "", "binary-not-found"
    except OSError:
        return 126, "", "", "cannot-run"


# ------------------------------------------------------------------ git, hardened
# Repository config is untrusted: a repo found on disk can carry a .git/config that runs commands
# (core.fsmonitor, filter drivers, hooks). Every git call neutralises those, uses no pager or
# credential helper, takes no optional locks (never rewrites the index), and trusts exactly this
# repo rather than safe.directory=*.
GIT_FIXED = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false",
             "-c", "core.pager=cat", "-c", "credential.helper=", "-c", "diff.external=", "-c", "gc.auto=0",
             "-c", "maintenance.auto=false", "-c", "protocol.allow=never", "-c", "core.sshCommand=false",
             "-c", "core.askPass=false", "-c", "uploadpack.packObjectsHook=", "-c", "log.showSignature=false",
             "--no-pager", "--no-replace-objects"]
_git_drivers = {}


def _git_env(repo):
    return base_env(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1",
                    GIT_DIR=os.path.join(repo, ".git"), GIT_WORK_TREE=repo, GIT_CEILING_DIRECTORIES=os.path.dirname(repo),
                    HOME=os.environ.get("HOME", ""), GIT_ATTR_NOSYSTEM="1", GIT_NO_LAZY_FETCH="1")


def _driver_overrides(repo):
    """Disable every filter/diff/merge driver the repo's config defines (they run commands), whatever
    characters the driver name holds ("evil/name", spaces, "="). The overrides go in as GIT_CONFIG_KEY_n /
    GIT_CONFIG_VALUE_n environment pairs, so a name is never parsed as a `-c key=value` argument."""
    if repo in _git_drivers:
        return _git_drivers[repo]
    base = ["git", "-c", f"safe.directory={repo}", *GIT_FIXED, "config", "--null", "--name-only", "--includes",
            "--get-regexp", r"^(filter|diff|merge)\..*\.(clean|smudge|process|textconv|command|driver)$"]
    rc, out, _, _ = sh(base, cwd=repo, env=_git_env(repo), timeout=20)
    pairs = []
    for key in (out.split("\0") if rc == 0 else []):
        if not key:
            continue
        pairs.append((key, ""))
        if key.startswith("filter.") and key.endswith((".clean", ".process")):
            pairs.append((key.rsplit(".", 1)[0] + ".required", "false"))
    over = {"GIT_CONFIG_COUNT": str(len(pairs))}
    for i, (k, v) in enumerate(pairs):
        over[f"GIT_CONFIG_KEY_{i}"], over[f"GIT_CONFIG_VALUE_{i}"] = k, v
    _git_drivers[repo] = over
    return over


def git(repo, *args, timeout=60):
    """(rc, stdout, problem). Never returns stderr."""
    repo = os.path.realpath(repo)
    env = {**_git_env(repo), **_driver_overrides(repo)}
    cmd = ["git", "-c", f"safe.directory={repo}", *GIT_FIXED, *args]
    rc, out, _, problem = sh(cmd, cwd=repo, env=env, timeout=timeout)
    if problem is None and rc != 0:
        problem = f"git-exit-{rc}"
    return rc, out, problem


def is_git(path):
    """A real .git directory (not a symlink, not a gitdir: file pointing elsewhere)."""
    g = os.path.join(path, ".git")
    return os.path.isdir(g) and not os.path.islink(g)


# ------------------------------------------------------------------ state files (storage only)

def load_json(path, default):
    """Our own state/progress files in the storage folder. Never used for project files."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return default


def write_text(path, text):
    """Replace a storage file atomically. Callers validate the destination first (safefs.check_destination).
    The temp file gets a random name in the destination's folder and is created with O_EXCL (and
    O_NOFOLLOW): anything already at that name, a planted symlink included, is never opened or followed."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    for _ in range(20):
        tmp = os.path.join(d, f".{os.path.basename(path)}.{secrets.token_hex(8)}.tmp")
        try:
            fd = os.open(tmp, flags, 0o666)
            break
        except FileExistsError:
            continue
    else:
        raise FileExistsError("no free temporary name")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path, data, indent=None):
    """Write state/progress JSON (atomically, see write_text)."""
    write_text(path, json.dumps(data, indent=indent))


def findings_of(check_result):
    return check_result.get("findings", []) if isinstance(check_result, dict) else []


# ------------------------------------------------------------------ untrusted strings in output
# File names, branch names, package names and the like come from repositories, so they are data.
# Before anything reaches stdout or a saved result: control and invisible/bidi characters are
# removed, characters that let text act as shell or Markdown syntax are replaced, and length is capped.
_UNSAFE_CHARS = set("`$|;&<>\\[]{}\"'")
MAX_STR = 300


def clean(s, limit=MAX_STR):
    out = []
    for ch in str(s):
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Zl", "Zp", "Co", "Cs"):
            out.append("?" if ch not in "\n\r\t" else " ")
        elif ch in _UNSAFE_CHARS:
            out.append("_")
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= limit else s[: limit - 1] + "…"


# Lists of our own delta keys ("file|package|advisory|severity"): built from clean() parts already.
PREBUILT_KEYS = {"new_since_last", "fixed_since_last", "carried_unverified", "audit_keys"}


def same_name(a, b):
    """Folder names compare equal in NFC (macOS may store either form)."""
    return unicodedata.normalize("NFC", a) == unicodedata.normalize("NFC", b)


def resolve_units(wanted, units):
    """(found, unknown): project names as the user or agent typed them, mapped to the real unit names.
    Accepts the raw name or the sanitised name the script printed (e.g. "R_D app" for "R&D app"), in
    either Unicode form. A sanitised name shared by two projects is ambiguous and stays unknown."""
    found, unknown = [], []
    for w in wanted:
        hits = [u for u in units if u == w] or [u for u in units if same_name(u, w)] \
            or [u for u in units if same_name(clean(u), clean(w))]
        (found.append(hits[0]) if len(hits) == 1 else unknown.append(w))
    return found, unknown


def scrub(obj):
    if isinstance(obj, dict):
        return {clean(k): (v if k in PREBUILT_KEYS and isinstance(v, list) else scrub(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub(v) for v in obj]
    if isinstance(obj, str):
        return clean(obj)
    return obj


_URL = re.compile(r"\b(h)(ttps?)(://)", re.I)
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_DOMAIN = re.compile(r"\b((?:[a-z0-9-]+\.)+)(com|net|org|io|dev|app|ru|cn|xyz|top|info|biz|co|me|sh|site|online)\b", re.I)


def defang(text):
    """For human reports and tracker notes: hxxps://, 203.0.113[.]5, evil[.]com."""
    text = _URL.sub(lambda m: "hxxp" + m.group(2)[3:] + m.group(3), text)
    text = _IPV4.sub(r"\1.\2.\3[.]\4", text)
    return _DOMAIN.sub(lambda m: m.group(1)[:-1] + "[.]" + m.group(2), text)


OS_NAMES = ("macOS", "Windows", "Linux")


def computer(cfg=None):
    """The user's OS, for the copy-paste check line: macOS | Windows | Linux. `computer` in the config
    wins (set at setup): a run in a sandboxed shell would otherwise report the sandbox's OS."""
    set_ = str((cfg or {}).get("computer") or "").strip().lower()
    hit = next((n for n in OS_NAMES if n.lower() == set_), None)
    return hit or {"Darwin": "macOS"}.get(platform.system(), platform.system() or "unknown")
