"""The one way the scanner reads project files.

Every project read (text, JSON, lockfile hashing, the scratch copy for npm audit) goes through a
Policy bound to the scan root. A read is refused, without opening anything, when the path:
  - is outside the root, or reached through a symlink (any component, including the file itself);
  - is a sensitive file (secrets: metadata only), or sits under an excluded or ignore-marked folder;
  - is not a regular file (FIFOs, devices).
Reads are bounded: a file over the size limit is not read. Refused, too-large and unreadable inputs
are recorded on a Coverage object, so a check can say it was incomplete instead of looking clean.
Symlinks: folder symlinks are never followed. A file symlink is followed only when the Policy is
scoped to a project (for_unit) and the link resolves to a regular file inside that same project that
is not sensitive, excluded, ignore-marked or over the size limit (e.g. CLAUDE.md -> AGENTS.md). Every
other symlink is refused and recorded as "symlink".
"""
import copy
import errno
import fnmatch
import hashlib
import json
import os
import re
import stat

IGNORE_MARKER = ".occupai-ignore"
PRUNE = {"node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__", "Pods",
         ".dart_tool", ".turbo", ".vercel", "coverage", ".git", ".cache", "out", "target"}

# Sensitive files: NEVER opened. Metadata only (name, tracked, in history, gitignored).
SENSITIVE_GLOBS = [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
                   "*.ppk", "*.p8", "*.ovpn", "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
                   "credentials*.json", "service-account*.json", "*.kdbx", ".npmrc", ".pypirc", ".netrc", "_netrc",
                   ".git-credentials"]
# The only exception: env example files, by exact shape (.env.example, .env.local.sample, ...).
# A credentials or key file never becomes readable because its name contains "example".
# .env.defaults is not exempt: it is often loaded at runtime and can hold real values.
SENSITIVE_OK = re.compile(r"^\.env(\.[A-Za-z0-9_-]+)?\.(example|sample|template)$")

MAX_TEXT = 1_000_000          # source, config, SQL, workflow files
WALK_DEPTH = 12               # folder levels below a project that every reader walks; deeper is reported
MAX_LOCK = 50_000_000         # lockfiles and manifests can be large

# Reasons a requested input was not read. INTENTIONAL ones are policy, not gaps in coverage.
INTENTIONAL = {"sensitive", "excluded", "ignored", "missing"}


def is_sensitive(name):
    if SENSITIVE_OK.match(name):
        return False
    return any(fnmatch.fnmatch(name, g) for g in SENSITIVE_GLOBS)


def excluded(rel, patterns):
    """Exclusion globs match the root-relative path or any of its parent folders, so "*/vendor"
    excludes "app/vendor/x.js" whichever reader asks (walks, git file lists, history, destinations)."""
    if not patterns:
        return False
    parts = rel.split("/")
    prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    return any(fnmatch.fnmatch(x, p) for p in patterns for x in prefixes)


class Coverage:
    """Inputs a check wanted but did not read, with a safe reason category."""

    def __init__(self):
        self.skipped = []

    def skip(self, rel, reason):
        if reason not in INTENTIONAL and not any(s["file"] == rel for s in self.skipped):
            self.skipped.append({"file": rel, "reason": reason})

    @property
    def complete(self):
        return not self.skipped

    def result(self, **fields):
        status = fields.pop("status", None) or ("ok" if self.complete else "incomplete")
        return {"status": status, **fields, "skipped": list(self.skipped)}


class PathRefused(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class Policy:
    def __init__(self, root, patterns=()):
        self.root = os.path.realpath(root)
        self._alias = os.path.abspath(root)  # the same root as the caller spelled it (e.g. /var vs /private/var)
        self.patterns = list(patterns or [])
        self._dirs = {}
        self.unit_root = None

    def for_unit(self, unit):
        """The same policy scoped to one project: contained file symlinks become readable."""
        p = copy.copy(self)
        p.unit_root = self.unit_path(unit)
        return p

    # ---------------------------------------------------------------- paths
    def rel(self, path):
        return os.path.relpath(path, self.root)

    def _rel_parts(self, path):
        a = os.path.normpath(path if os.path.isabs(path) else os.path.join(self.root, path))
        if self._alias != self.root and (a == self._alias or a.startswith(self._alias + os.sep)):
            a = self.root + a[len(self._alias):]
        if a != self.root and not a.startswith(self.root + os.sep):
            raise PathRefused("outside-root")
        r = os.path.relpath(a, self.root)
        return a, ([] if r == "." else r.split(os.sep))

    def _dir_verdict(self, parts):
        """None if the directory root/parts... is safe to read from, else a reason. Cached."""
        key = tuple(parts)
        if key in self._dirs:
            return self._dirs[key]
        verdict = None
        if parts:
            verdict = self._dir_verdict(parts[:-1])
            if verdict is None:
                p = os.path.join(self.root, *parts)
                rel = "/".join(parts)
                try:
                    st = os.lstat(p)
                    if stat.S_ISLNK(st.st_mode):
                        verdict = "symlink"
                    elif not stat.S_ISDIR(st.st_mode):
                        verdict = "not-a-directory"
                    elif excluded(rel, self.patterns):
                        verdict = "excluded"
                    elif os.path.lexists(os.path.join(p, IGNORE_MARKER)):
                        verdict = "ignored"
                except (FileNotFoundError, NotADirectoryError):
                    verdict = "missing"
                except OSError:
                    verdict = "unreadable"
        self._dirs[key] = verdict
        return verdict

    def check_file(self, path):
        """(abs_path, rel, lstat) for a readable regular file, or raise PathRefused."""
        a, parts = self._rel_parts(path)
        if not parts:
            raise PathRefused("not-a-file")
        v = self._dir_verdict(parts[:-1])
        if v:
            raise PathRefused(v)
        rel = "/".join(parts)
        if is_sensitive(parts[-1]):
            raise PathRefused("sensitive")
        if excluded(rel, self.patterns):
            raise PathRefused("excluded")
        try:
            st = os.lstat(a)
        except FileNotFoundError:
            raise PathRefused("missing")
        except OSError:
            raise PathRefused("unreadable")
        if stat.S_ISLNK(st.st_mode):
            return self._contained_link(a, rel)
        if not stat.S_ISREG(st.st_mode):
            raise PathRefused("not-a-file")
        return a, rel, st

    def _contained_link(self, a, rel):
        """(target_abs, link_rel, target_lstat) for a file symlink that stays inside the scoped project
        and points at a file the policy would read directly; otherwise PathRefused('symlink')."""
        if not self.unit_root:
            raise PathRefused("symlink")
        try:
            t, tparts = self._rel_parts(os.path.realpath(a))
        except PathRefused:
            raise PathRefused("symlink")
        if not t.startswith(self.unit_root + os.sep) or not tparts or self._dir_verdict(tparts[:-1]) \
                or is_sensitive(tparts[-1]) or excluded("/".join(tparts), self.patterns):
            raise PathRefused("symlink")
        try:
            tst = os.lstat(t)
        except OSError:
            raise PathRefused("symlink")
        if not stat.S_ISREG(tst.st_mode):
            raise PathRefused("symlink")
        return t, rel, tst

    def _inside_unit(self, path):
        """A folder symlink into the same scoped project: its contents are walked (or excluded by policy)
        through the real path, so leaving the link out loses nothing."""
        if not self.unit_root:
            return False
        t = os.path.realpath(path)
        return t == self.unit_root or t.startswith(self.unit_root + os.sep)

    def _link_ok(self, path):
        try:
            self._contained_link(path, None)
            return True
        except PathRefused:
            return False

    def check_dir(self, path):
        """Absolute path of a safe directory inside the root (the root itself included), or raise."""
        a, parts = self._rel_parts(path)
        v = self._dir_verdict(parts)
        if v:
            raise PathRefused(v)
        return a

    def is_safe_dir(self, path):
        try:
            self.check_dir(path)
            return True
        except PathRefused:
            return False

    def unit_path(self, unit):
        """Validate a project unit name (from discovery, --only or a resume file)."""
        if not isinstance(unit, str) or not unit or unit.startswith(("/", "\\")) or "\\" in unit \
                or any(x in ("", ".", "..") for x in unit.split("/")):
            raise PathRefused("invalid-unit")
        return self.check_dir(unit)

    # ---------------------------------------------------------------- reads
    def read_bytes(self, path, limit=MAX_TEXT, cov=None):
        """File bytes, or None (and a Coverage note) if the policy refuses it or it can't be read."""
        try:
            a, rel, st = self.check_file(path)
        except PathRefused as e:
            if cov is not None:
                cov.skip(self._safe_rel(path), e.reason)
            return None
        if st.st_size > limit:
            if cov is not None:
                cov.skip(rel, "too-large")
            return None
        try:
            fd = os.open(a, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError as e:
            if cov is not None:
                cov.skip(rel, "symlink" if e.errno == errno.ELOOP else "unreadable")
            return None
        try:
            fst = os.fstat(fd)
            if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(fst.st_mode):
                if cov is not None:
                    cov.skip(rel, "changed-during-read")
                return None
            chunks, total = [], 0
            while True:
                b = os.read(fd, 1 << 20)
                if not b:
                    break
                total += len(b)
                if total > limit:
                    if cov is not None:
                        cov.skip(rel, "too-large")
                    return None
                chunks.append(b)
            return b"".join(chunks)
        except OSError:
            if cov is not None:
                cov.skip(rel, "unreadable")
            return None
        finally:
            os.close(fd)

    def read_text(self, path, limit=MAX_TEXT, cov=None):
        b = self.read_bytes(path, limit, cov)
        return None if b is None else b.decode("utf-8", errors="ignore")

    def load_json(self, path, limit=MAX_TEXT, cov=None):
        """Parsed JSON, or None. Invalid JSON is recorded as 'invalid-json'."""
        t = self.read_text(path, limit, cov)
        if t is None:
            return None
        try:
            return json.loads(t)
        except ValueError:
            if cov is not None:
                cov.skip(self._safe_rel(path), "invalid-json")
            return None

    def hash_file(self, path, limit=MAX_LOCK, cov=None):
        b = self.read_bytes(path, limit, cov)
        return None if b is None else hashlib.sha256(b).hexdigest()[:24]

    def copy_into(self, path, dest_dir, limit=MAX_LOCK, cov=None):
        """Copy one project file into scratch space through the policy. Returns True if copied."""
        b = self.read_bytes(path, limit, cov)
        if b is None:
            return False
        dest = os.path.join(dest_dir, os.path.basename(path))
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(b)
        return True

    def _safe_rel(self, path):
        try:
            return "/".join(self._rel_parts(path)[1]) or "."
        except PathRefused:
            return "outside-root"

    # ---------------------------------------------------------------- traversal
    def walk(self, start, maxdepth=WALK_DEPTH, prune=True, on_symlink=None, cov=None, wanted=None):
        """os.walk inside the root that never follows symlinks and honours exclusions and ignore markers.
        Yields (dirpath, dirnames, filenames); refused symlinks are left out. With cov, nothing a reader
        wanted disappears silently: folders cut off by maxdepth ('depth-limit'), folders that can't be
        listed ('unreadable') and a refused start folder are recorded. With wanted(abs_path) as well,
        refused file symlinks the reader wants and folder symlinks that leave the scoped project (they
        could hold anything) are recorded as 'symlink'. on_symlink(root_relative_path) is the older per-caller hook."""
        try:
            top = self.check_dir(start)
        except PathRefused as e:
            if cov is not None:
                cov.skip(self._safe_rel(start), e.reason)
            return

        def onerror(err):
            if cov is not None:
                cov.skip(self._safe_rel(err.filename or top), "unreadable")

        base = top.count(os.sep)
        for dp, dns, fns in os.walk(top, followlinks=False, onerror=onerror):
            rel = os.path.relpath(dp, self.root)
            if dp != top and (excluded(rel, self.patterns) or os.path.islink(dp)):
                dns[:] = []
                continue
            if IGNORE_MARKER in fns:
                dns[:] = []
                continue
            links = {n for n in fns if os.path.islink(os.path.join(dp, n))}
            kept = {n for n in links if not is_sensitive(n) and self._link_ok(os.path.join(dp, n))}
            if on_symlink:
                for n in dns + fns:
                    if (not prune or n not in PRUNE) and n not in kept and os.path.islink(os.path.join(dp, n)):
                        on_symlink(self.rel(os.path.join(dp, n)))
            if cov is not None and wanted is not None:
                for n in sorted(set(dns) | (links - kept)):
                    a = os.path.join(dp, n)
                    if (prune and n in PRUNE) or is_sensitive(n) or excluded(self.rel(a), self.patterns) \
                            or not os.path.islink(a):
                        continue  # policy, not a gap
                    if (n in dns and not self._inside_unit(a)) or (n not in dns and wanted(a)):
                        cov.skip(self.rel(a), "symlink")
            dns[:] = [d for d in dns if not (prune and d in PRUNE) and not os.path.islink(os.path.join(dp, d))
                      and not excluded(os.path.relpath(os.path.join(dp, d), self.root), self.patterns)]
            if dns and dp.count(os.sep) - base >= maxdepth:
                if cov is not None:
                    cov.skip(rel, "depth-limit")
                dns[:] = []
            fns[:] = [f for f in fns if f not in links or f in kept]
            yield dp, dns, fns

    def ignored_prefixes(self, unit):
        """Unit-relative dirs that carry the ignore marker ('' = the whole unit)."""
        out = []
        p = os.path.join(self.root, unit)
        for dp, dns, fns in os.walk(p, followlinks=False):
            dns[:] = [d for d in dns if d not in PRUNE]
            if IGNORE_MARKER in fns:
                rel = os.path.relpath(dp, p)
                out.append("" if rel == "." else rel.rstrip("/") + "/")
                dns[:] = []
        return out


# ---------------------------------------------------------------- write destinations

class UnsafeDestination(ValueError):
    pass


def check_destination(path, root, patterns=()):
    """Refuse a state/progress/output path that would land inside a scanned project.

    Allowed: anywhere outside the projects root, or inside it only under an excluded or
    ignore-marked folder (e.g. a storage folder that the config excludes from scanning).
    The destination itself must not be a symlink or a directory."""
    a = os.path.abspath(os.path.expanduser(path))
    if os.path.islink(a):
        raise UnsafeDestination("destination is a symlink")
    if os.path.isdir(a):
        raise UnsafeDestination("destination is a directory")
    parent = os.path.realpath(os.path.dirname(a))
    real = os.path.join(parent, os.path.basename(a))
    if not root:
        return a
    r = os.path.realpath(root)
    if real == r or not real.startswith(r + os.sep):
        return a
    pol = Policy(r, patterns)
    parts = os.path.relpath(real, r).split(os.sep)
    for i in range(1, len(parts)):
        rel = "/".join(parts[:i])
        if excluded(rel, pol.patterns) or os.path.lexists(os.path.join(r, *parts[:i], IGNORE_MARKER)):
            return a
    raise UnsafeDestination("destination is inside the scanned projects folder")
