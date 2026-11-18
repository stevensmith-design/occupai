"""Project discovery, fingerprints and ownership. All file access goes through safefs.Policy."""
import hashlib
import os
import re
import stat

from .common import IGNORE_MARKER, LOCKFILES, excluded, git, is_git
from .safefs import WALK_DEPTH, Coverage


def discover(pol, maxdepth=WALK_DEPTH):
    """(units, omitted). Units: git repo roots + lockfile dirs outside repos + top-level folders with
    neither. Omitted: top-level entries skipped for safety (symlinks, unreadable), and top-level folders
    whose deeper levels weren't searched for projects (depth-limit, with the first folder cut off), so
    reports can name them. Discovery searches as deep as the checks read (WALK_DEPTH): a top-level
    folder that holds no project is a unit itself and is walked that deep anyway, so this costs little
    and finds projects nested in client or collection folders."""
    root = pol.root
    repos, lockdirs = set(), set()
    cut = Coverage()
    for dp, dns, fns in pol.walk(".", maxdepth, cov=cut):
        if is_git(dp):
            repos.add(os.path.relpath(dp, root))
        if any(f in fns for f in LOCKFILES):
            lockdirs.add(os.path.relpath(dp, root))
    units = set(repos)
    for lockdir in lockdirs:
        if not any(lockdir == r or lockdir.startswith(r + "/") for r in repos):
            units.add(lockdir)
    omitted = []
    for t in sorted(os.listdir(root)):
        p = os.path.join(root, t)
        if t.startswith(".") or excluded(t, pol.patterns):
            continue
        try:
            st = os.lstat(p)
        except OSError:
            omitted.append({"path": t, "reason": "unreadable"})
            continue
        if stat.S_ISLNK(st.st_mode):
            if os.path.isdir(p):
                omitted.append({"path": t, "reason": "symlink"})
            continue
        if not stat.S_ISDIR(st.st_mode) or os.path.lexists(os.path.join(p, IGNORE_MARKER)):
            continue
        if not any(u == t or u.startswith(t + "/") for u in units):
            units.add(t)
    # Folders cut off by the depth limit may hold undiscovered projects, unless they're inside a repo
    # (the repo is the unit, and its own checks report their depth limit).
    deep = {}
    for c in cut.skipped:
        if c["reason"] == "depth-limit" and not any(c["file"] == r or c["file"].startswith(r + "/") for r in repos):
            deep.setdefault(c["file"].split("/")[0], []).append(c["file"])
    omitted += [{"path": t, "reason": "depth-limit", "cut_at": min(fs, key=lambda f: (len(f), f))}
                for t, fs in sorted(deep.items())]
    return sorted(u for u in units if u != "."), omitted


# Folder names that look like a backup or a copy (whole words only, so "bold" or "copywriter" don't count):
# setup lists these unticked. Dated copies: a full date in the name (2024-03-01, 20240301), "app (2)".
_COPY_WORDS = {"backup", "backups", "bak", "archive", "archived", "archives", "copy", "old", "to_delete",
               "todelete", "to-delete"}
_DATED = re.compile(r"(?<!\d)(19|20)\d\d[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])(?!\d)|\(\d+\)\s*$")


def looks_like_copy(rel):
    """A short reason when any folder in the project's path looks like a backup or copy, else None."""
    for part in rel.split("/"):
        low = part.lower()
        words = set(re.split(r"[^a-z0-9]+", low)) | {low.strip("_ ")}
        hit = next((w for w in ("to_delete", "to-delete", "todelete") if w in low), None) or \
            next((w for w in sorted(words & _COPY_WORDS)), None)
        if hit:
            return f"{part}: looks like a backup or copy"
        if _DATED.search(part):
            return f"{part}: looks like a dated copy"
    return None


def _meta(h, path, rel):
    """Metadata only (never opens the file): size, mtime and ctime in ns, inode. ctime changes on every
    write and can't be set back, so same-second edits and restored mtimes still count."""
    try:
        st = os.lstat(path)
        kind = "L" if stat.S_ISLNK(st.st_mode) else "F"
        h.update(f"{kind}\0{rel}\0{st.st_size}\0{st.st_mtime_ns}\0{st.st_ctime_ns}\0{st.st_ino}\n"
                 .encode("utf-8", "surrogateescape"))
    except OSError:
        h.update(f"-\0{rel}\n".encode("utf-8", "surrogateescape"))


def fingerprint(pol, unit):
    """A fingerprint of everything hygiene can read in a unit, gitignored files included: the metadata
    of every file the checks' walk visits (same depth, exclusions and ignore markers, symlinks as
    entries), plus for git repos HEAD, `git status` (deep or renamed changes) and .git/config
    (origin -> ownership). Content is never read for this."""
    pol = pol.for_unit(unit)
    p = pol.unit_root
    h = hashlib.sha256()
    out = {"kind": "dir"}
    if is_git(p):
        # One git call: porcelain v2 with --branch also gives HEAD ("# branch.oid <sha>").
        _, st, _ = git(p, "status", "--porcelain=v2", "--branch", "-z", "--untracked-files=all", timeout=90)
        h.update(st.encode("utf-8", "surrogateescape"))
        head, skip_next = "", False
        for entry in st.split("\0"):
            if skip_next:  # the original path of a rename
                skip_next = False
                continue
            fields = {"1": 8, "2": 9, "u": 10, "?": 1}.get(entry[:1])
            if entry.startswith("# branch.oid "):
                head = entry.split()[2]
            if fields is None:
                continue
            skip_next = entry[:1] == "2"
            f = entry.split(" ", fields)[-1]
            if f and not os.path.isabs(f) and ".." not in f.split("/"):
                _meta(h, os.path.join(p, f), f)
        _meta(h, os.path.join(p, ".git", "config"), ".git/config")
        out = {"kind": "git", "head": head[:12]}
    cut = []
    for dp, dns, fns in pol.walk(unit, on_symlink=lambda rel: cut.append("L:" + rel)):
        dns.sort()
        rel_dir = os.path.relpath(dp, p)
        for f in sorted(fns):
            _meta(h, os.path.join(dp, f), f if rel_dir == "." else f"{rel_dir}/{f}")
    h.update("\n".join(sorted(cut)).encode("utf-8", "surrogateescape"))
    out["fp"] = h.hexdigest()[:24]
    return out


def lockfile_hashes(pol, unit):
    pol = pol.for_unit(unit)
    out = {}
    for dp, dns, fns in pol.walk(unit):
        for f in fns:
            if f in LOCKFILES or (f.startswith("requirements") and f.endswith(".txt")):
                h = pol.hash_file(os.path.join(dp, f))
                if h:
                    out[pol.rel(os.path.join(dp, f))] = h
    return out


_OWNER = re.compile(r"^(?:https?://(?:[^/@]*@)?|ssh://(?:[^/@]*@)?|[^/@:]*@)?github\.com[:/]([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/[^/]+?(?:\.git)?/?$")


def origin_owner(project_path):
    """(has_github_remote, owner or None). Reads the remote URL locally and keeps only a validated
    owner name: user info, tokens and the rest of the URL never leave this function."""
    if not is_git(project_path):
        return False, None
    remote = git(project_path, "remote", "get-url", "origin")[1].strip()
    m = _OWNER.match(remote)
    if m:
        return True, m.group(1)
    return ("github.com" in remote), None


def ownership(owner, has_github, my_owners):
    """mine | third-party | unknown. Projects without a GitHub origin count as mine (local work)."""
    if not has_github:
        return "mine"
    if not my_owners or not owner:
        return "unknown"
    return "mine" if owner.lower() in {o.lower() for o in my_owners} else "third-party"
