"""Dependency checks: lockfile versions, npm audit (scratch copy), PyPI, route check.

Never installs anything and never runs project code. npm audit only ever sees a
copy of the lockfile in a fresh temporary directory, never the repo itself, and run with a
controlled environment: no user/global npm config, no inherited tokens, cache and logs in scratch.

Result contract (every lockfile / requirements file):
  {"status": "ok", ...}                       checked successfully (may or may not have findings)
  {"status": "error", "error": "<category>"}  not checked: never treat as clean
Error categories are fixed strings (npm-not-found, timeout, malformed-output, npm-error:E401,
corrupt-lockfile, input-refused:symlink, ...). Raw stderr, exception text and URLs never appear.
"""
import hashlib
import json
import os
import re
import shutil
import ssl
import tempfile
import urllib.error
import urllib.request

from .common import LOCKFILES, base_env, clean, sh
from .safefs import MAX_LOCK, MAX_TEXT, Coverage

USER_AGENT = "occupai-scan (read-only security check)"
DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org/"
UNSUPPORTED_LOCKS = ("pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
UNSUPPORTED_PY = ("poetry.lock", "uv.lock", "Pipfile.lock")
# Ecosystems the audit doesn't cover: (lockfile, manifest) -> name. A project using one is never "ok":
# each folder's lockfile (or its manifest, when there's no lockfile) is listed as not covered.
OTHER_ECOSYSTEMS = {"Dart": ("pubspec.lock", "pubspec.yaml"), "Ruby": ("Gemfile.lock", "Gemfile"),
                    "Go": ("go.sum", "go.mod"), "Rust": ("Cargo.lock", "Cargo.toml"),
                    "CocoaPods": ("Podfile.lock", "Podfile"), "PHP": ("composer.lock", "composer.json"),
                    "Swift": ("Package.resolved", "Package.swift"),
                    "Gradle": ("gradle.lockfile", "build.gradle", "build.gradle.kts"),
                    ".NET": ("packages.lock.json",), "Elixir": ("mix.lock", "mix.exs")}
OTHER_FILES = {f for names in OTHER_ECOSYSTEMS.values() for f in names}


def other_ecosystems(rel_dir, fns):
    """'<folder>/<file>: not-audited (<ecosystem>)' per unaudited ecosystem in one folder: its lockfile,
    or else its first manifest found."""
    out = []
    for eco, names in OTHER_ECOSYSTEMS.items():
        f = next((n for n in names if n in fns), None)
        if f:
            out.append(f"{rel_dir}/{f}: not-audited ({eco})")
    return out


# ------------------------------------------------------------------ lockfile reading
# Supported for version lookups (news matching, `versions`):
#   package-lock.json  lockfileVersion 2 and 3 ("packages"); v1 is reported as unsupported-lockfile-v1
#   pnpm-lock.yaml     lockfileVersion 5.x, 6.x, 7.x, 9.x
#   yarn.lock          classic (v1) and berry
#   bun.lock           text lockfile
# Anything else (other lockfile versions, binary bun.lockb) is reported as unsupported, never as empty.
# Names are exact: an npm alias ("foo": "npm:bar@1") counts as bar, the package actually installed.

_NAME = r"(?:@[a-z0-9][\w.~-]*/)?[a-z0-9~][\w.~-]*"


def _add(res, name, version, names):
    if name in names:
        res.setdefault(name, set()).add(str(version) if version is not None else "?")


def _package_lock(j, names, res):
    if j.get("lockfileVersion") in (2, 3) and isinstance(j.get("packages"), dict):
        for k, v in j["packages"].items():
            if "node_modules/" not in k or not isinstance(v, dict) or v.get("link"):
                continue  # the root, workspace folders and links (their target has its own entry)
            name = v.get("name") if isinstance(v.get("name"), str) else k.rsplit("node_modules/", 1)[1]
            _add(res, name, v.get("version"), names)
        return True
    return "unsupported-lockfile-v1" if j.get("lockfileVersion") == 1 or "packages" not in j else False


def _pnpm(t, names, res):
    m = re.search(r"(?m)^lockfileVersion:\s*['\"]?(\d+)", t)
    if not m or m.group(1) not in ("5", "6", "7", "9"):
        return False
    for n in names:
        e = re.escape(n)
        # 6.x/7.x "/name@1.2.3(peer):", 9.x "name@1.2.3:", 5.x "/name/1.2.3:"
        for mm in re.finditer(r"(?m)^\s+['\"]?/?" + e + r"@([^\s'\"():]+)", t):
            _add(res, n, mm.group(1), names)
        for mm in re.finditer(r"(?m)^\s+['\"]?/" + e + r"/([^\s'\"/():_]+)", t):
            _add(res, n, mm.group(1), names)
    return True


def _spec_name(spec):
    """'name@^1', '@s/n@npm:^1', 'alias@npm:real@^1' -> installed package name."""
    spec = spec.strip().strip("\"'")
    at = spec.find("@", 1)
    if at == -1:
        return None
    name, rng = spec[:at], spec[at + 1:]
    if rng.startswith("npm:"):
        m = re.match(r"npm:(" + _NAME + r")@", rng)
        if m:
            return m.group(1)
    return name


def _yarn(t, names, res):
    """Classic ('# yarn lockfile v1' header) or berry (__metadata entry). Anything else, or a top-level
    line that isn't an entry header, is not a lockfile this reader understood."""
    if not re.search(r"(?m)^# yarn lockfile v1\s*$", t) and not re.search(r"(?m)^__metadata:\s*$", t):
        return "unparseable-lockfile"
    current = []
    for line in t.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and not line.rstrip().endswith(":"):
            return "unparseable-lockfile"
        if not line[0].isspace():
            current = [x for x in (_spec_name(s) for s in line.rstrip().rstrip(":").split(",")) if x] \
                if line.rstrip().endswith(":") else []
            continue
        m = re.match(r"^\s+version:?\s+['\"]?([^'\"\s]+)", line)
        if m and current:
            for n in set(current):
                _add(res, n, m.group(1), names)
            current = []
    return True


def _bun(t, names, res):
    if not re.search(r"\"lockfileVersion\"\s*:\s*[01]\b", t):
        return False
    for n in names:
        for mm in re.finditer(r"\[\s*\"" + re.escape(n) + r"@([^\"]+)\"", t):
            _add(res, n, mm.group(1), names)
    return True


def lock_versions(pol, lock_path, names, cov=None):
    """{name: [versions]} for exact package names in one lockfile. Versions are raw strings ("?" when
    the lockfile names the package without a version). Returns None (and a Coverage note) when the
    lockfile can't be read, parsed, or is a version this reader doesn't support."""
    names = set(names)
    res = {}
    base = os.path.basename(lock_path)
    if base == "package-lock.json":
        j = pol.load_json(lock_path, MAX_LOCK, cov)
        if j is None:
            return None
        ok = _package_lock(j, names, res) if isinstance(j, dict) else False
    else:
        t = pol.read_text(lock_path, MAX_LOCK, cov)
        if t is None:
            return None
        ok = {"pnpm-lock.yaml": _pnpm, "yarn.lock": _yarn, "bun.lock": _bun}[base](t, names, res)
    if ok is not True:
        if cov is not None:
            cov.skip(pol.rel(lock_path), ok or "unsupported-lockfile-version")
        return None
    return {k: sorted(v) for k, v in res.items()}


def lockfiles_in(pol, unit, cov=None):
    out = []
    for dp, dns, fns in pol.walk(unit, cov=cov, wanted=lambda a: os.path.basename(a) in LOCKFILES + ("bun.lockb",)):
        out += [os.path.join(dp, f) for f in fns if f in LOCKFILES]
        if cov is not None and "bun.lockb" in fns and "bun.lock" not in fns:
            cov.skip(pol.rel(os.path.join(dp, "bun.lockb")), "unsupported-lockfile")
    return sorted(out)


# ------------------------------------------------------------------ requirements (pinned Python)

_REQ_PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)(\[[A-Za-z0-9_,.\s-]*\])?\s*==\s*([A-Za-z0-9_.+!-]+)$")
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)")
PY_MANIFESTS = ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile")


def is_requirements(name):
    return name.startswith("requirements") and name.endswith(".txt")


def uncovered_manifests(manifests, reqs):
    """Python manifests with no requirements file in their own folder. Coverage is per location: a
    requirements.txt in tools/ says nothing about what app/pyproject.toml installs."""
    have = {os.path.dirname(r) for r in reqs}
    return [m for m in manifests if os.path.dirname(m) not in have]


def requirement_lines(text):
    """Yield (line_no, kind, name, version) for each requirement: kind 'pin' (name==version, with any
    environment marker or --hash options set aside), or an unsupported reason (unpinned,
    include-not-followed, url-or-vcs, editable, custom-index, option). Continuation lines are joined."""
    logical, buf, start = [], "", None
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("#") and not buf:
            continue
        start = start or n
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        logical.append((start, buf + raw))
        buf, start = "", None
    if buf:
        logical.append((start, buf))
    for n, raw in logical:
        line = raw.split(" #")[0].split("\t#")[0].strip()
        line = re.sub(r"\s--hash[=\s]\S+", "", " " + line).strip()  # hashes don't change what is installed
        if not line:
            continue
        req = line.split(";", 1)[0].strip()
        m = _REQ_PIN.match(req)
        if m:
            yield n, "pin", m.group(1), m.group(3)
            continue
        nm = _REQ_NAME.match(line) if not line.startswith("-") and not re.match(r"^[A-Za-z0-9+.-]+://", line) else None
        yield n, _req_reason(line), nm.group(1) if nm else None, None


# ------------------------------------------------------------------ isolated npm

def valid_registry(url):
    """https registries only (plain http allowed for loopback test servers). None if invalid."""
    if not isinstance(url, str):
        return None
    if re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?", url) or \
            re.fullmatch(r"http://(127\.0\.0\.1|localhost)(:\d+)?(/[A-Za-z0-9._~/-]*)?", url):
        return url if url.endswith("/") else url + "/"
    return None


# System CA bundles, in the order tried. A sandbox that intercepts TLS usually names its own bundle in
# one of these variables; npm (Node) doesn't read them, so the audit hands the bundle to Node explicitly.
CA_ENV = ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
CA_FILES = ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem")


def ca_bundle():
    """Path of a CA bundle file to add to Node's trusted roots, or None. Adds trust; never removes checks."""
    for p in [os.environ.get(k) for k in CA_ENV] + list(CA_FILES):
        if p and os.path.isfile(p):
            return p
    return None


class Scratch:
    """A fresh temp dir with its own HOME, npm cache, logs and empty npm config files. Removed on exit."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="occupai-audit-")
        self.work = os.path.join(self.dir, "work")
        for d in ("work", "home", "cache", "logs", "prefix", "tmp"):
            os.makedirs(os.path.join(self.dir, d), mode=0o700)
        for f in ("userconfig", "globalconfig"):
            open(os.path.join(self.dir, f), "w").close()
        return self

    def env(self, registry=DEFAULT_NPM_REGISTRY):
        d = self.dir
        return base_env(
            HOME=os.path.join(d, "home"), USERPROFILE=os.path.join(d, "home"), TMPDIR=os.path.join(d, "tmp"),
            npm_config_userconfig=os.path.join(d, "userconfig"), npm_config_globalconfig=os.path.join(d, "globalconfig"),
            npm_config_prefix=os.path.join(d, "prefix"), npm_config_cache=os.path.join(d, "cache"),
            npm_config_logs_dir=os.path.join(d, "logs"), npm_config_registry=registry,
            npm_config_ignore_scripts="true", npm_config_update_notifier="false", npm_config_fund="false",
            npm_config_audit="true", npm_config_save="false", npm_config_workspaces="false",
            npm_config_loglevel="error", npm_config_strict_ssl="true", NO_UPDATE_NOTIFIER="1", CI="true",
            **({"NODE_EXTRA_CA_CERTS": ca_bundle()} if ca_bundle() else {}))

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)
        return False


def _npm_error_category(j):
    err = j.get("error")
    code = err.get("code") if isinstance(err, dict) else None
    return f"npm-error:{code}" if isinstance(code, str) and re.fullmatch(r"E[A-Z0-9_]{1,30}", code) else "npm-error"


def parse_npm_audit(out):
    """npm audit --json text -> result dict (status ok / error). Anything unexpected is an error."""
    try:
        j = json.loads(out)
    except ValueError:
        return {"status": "error", "error": "malformed-output"}
    if not isinstance(j, dict):
        return {"status": "error", "error": "malformed-output"}
    if "error" in j:
        return {"status": "error", "error": _npm_error_category(j)}
    vul, meta = j.get("vulnerabilities"), j.get("metadata")
    if not isinstance(vul, dict) or not isinstance(meta, dict) or not isinstance(meta.get("vulnerabilities"), dict):
        return {"status": "error", "error": "malformed-output"}
    vulns = {}
    for name, v in vul.items():
        if not isinstance(v, dict):
            return {"status": "error", "error": "malformed-output"}
        advis = [x for x in (v.get("via") or []) if isinstance(x, dict)]
        if not advis:
            continue  # flagged only through a dependency: fixed by fixing that dependency
        fa = v.get("fixAvailable")
        vulns[name] = {"severity": v.get("severity"),
                       "advisories": sorted({str(a.get("url", a.get("source", ""))).rsplit("/", 1)[-1] for a in advis}),
                       "range": v.get("range"),
                       "fix": fa if isinstance(fa, bool) or fa is None else
                       {"name": fa.get("name"), "version": fa.get("version"), "major": fa.get("isSemVerMajor")}
                       if isinstance(fa, dict) else None,
                       "direct": bool(v.get("isDirect", False))}
    via_only = sorted(n for n in vul if n not in vulns)
    return {"status": "ok", "vulns": vulns, "via_dependency_only": via_only, "counts": meta["vulnerabilities"]}


def npm_audit(pol, lock_path, registry=DEFAULT_NPM_REGISTRY):
    reg = valid_registry(registry)
    if not reg:
        return {"status": "error", "error": "invalid-registry"}
    d = os.path.dirname(lock_path)
    cov = Coverage()
    lock = pol.read_bytes(lock_path, MAX_LOCK, cov)
    pkg = pol.read_bytes(os.path.join(d, "package.json"), MAX_TEXT, cov)
    if lock is None or pkg is None:
        reason = cov.skipped[0]["reason"] if cov.skipped else "no-package-json"
        return {"status": "error", "error": f"input-refused:{reason}" if cov.skipped else "no-package-json"}
    try:
        lj = json.loads(lock.decode("utf-8", errors="strict"))
        json.loads(pkg.decode("utf-8", errors="strict"))
    except ValueError:
        return {"status": "error", "error": "corrupt-lockfile"}
    if not isinstance(lj, dict) or not isinstance(lj.get("lockfileVersion"), int):
        return {"status": "error", "error": "corrupt-lockfile"}
    with Scratch() as s:
        for name, data in (("package-lock.json", lock), ("package.json", pkg)):
            with open(os.path.join(s.work, name), "wb") as f:
                f.write(data)
        rc, out, _, problem = sh(["npm", "audit", "--package-lock-only", "--ignore-scripts", "--json",
                                  "--registry", reg], cwd=s.work, timeout=90, env=s.env(reg))
    if problem:
        return {"status": "error", "error": "npm-not-found" if problem == "binary-not-found" else problem}
    res = parse_npm_audit(out)
    if res["status"] == "ok" and rc not in (0, 1):
        return {"status": "error", "error": f"npm-exit-{rc}"}
    return res


# ------------------------------------------------------------------ PyPI

def _req_reason(line):
    if line.startswith(("-r", "--requirement", "-c", "--constraint")):
        return "include-not-followed"
    if line.startswith(("-i", "--index-url", "--extra-index-url", "-f", "--find-links")):
        return "custom-index"
    if line.startswith(("-e", "--editable")):
        return "editable"
    if line.startswith("-"):
        return "option"
    if re.match(r"^[A-Za-z0-9+.-]+://", line) or line.startswith("git+") or " @ " in line:
        return "url-or-vcs"
    if ";" in line:
        return "environment-marker"
    return "unpinned"


def _http_error_category(e):
    if isinstance(e, urllib.error.HTTPError):
        return f"http-{e.code}" if isinstance(e.code, int) else "http-error"
    reason = getattr(e, "reason", e)
    if isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(reason):
        return "tls-verify-failed"
    if isinstance(e, (TimeoutError,)) or "timed out" in str(reason):
        return "timeout"
    if isinstance(e, (urllib.error.URLError, OSError)):
        return "network"
    if isinstance(e, ValueError):
        return "invalid-response"
    return f"exception:{type(e).__name__}"


def pypi_audit(pol, req_path, opener=None):
    """Pinned name==version lines only, via the PyPI JSON API. Never pip-audit -r (it resolves and builds).
    Other lines are listed as unsupported by line number and reason, never by their text (they can hold
    index URLs with credentials)."""
    opener = opener or urllib.request.urlopen
    cov = Coverage()
    text = pol.read_text(req_path, MAX_TEXT, cov)
    if text is None:
        reason = cov.skipped[0]["reason"] if cov.skipped else "missing"
        return {"status": "error", "error": f"input-refused:{reason}"}
    vulns, checked, failed, unsupported = {}, [], {}, []
    unverified, opaque = set(), False
    for n, kind, name, ver in requirement_lines(text):
        if kind != "pin":
            unsupported.append({"line": n, "reason": kind})
            if name:
                unverified.add(_pyname(name))  # installed version unknown
            elif kind != "custom-index":
                opaque = True  # an include, editable or URL line can install anything
            continue
        key = f"{name}=={ver}"
        try:
            req = urllib.request.Request(f"https://pypi.org/pypi/{name}/{ver}/json", headers={"User-Agent": USER_AGENT})
            with opener(req, timeout=15) as r:
                data = json.load(r)
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise ValueError("shape")  # an empty or foreign answer is not "no vulnerabilities"
            v = data.get("vulnerabilities") or []
            checked.append(key)
            if v:
                vulns[key] = [{"id": x.get("id"), "aliases": x.get("aliases"), "fixed_in": x.get("fixed_in")}
                              for x in v if isinstance(x, dict)]
        except Exception as e:  # noqa: BLE001
            failed[key] = _http_error_category(e)
    status = "ok" if not failed else ("error" if not checked else "incomplete")
    return {"status": status, "vulns": vulns, "checked": checked, "failed": failed, "unsupported": unsupported,
            "unverified_names": sorted(unverified), "opaque": opaque}


def _pyname(name):
    return re.sub(r"[-_.]+", "-", name).lower()


# ------------------------------------------------------------------ one project

def run_audit(pol, unit, registry=DEFAULT_NPM_REGISTRY, opener=None):
    """Audit one project. status: ok (every supported file checked), incomplete (some files failed,
    were skipped or are unsupported), error (nothing could be checked)."""
    pol = pol.for_unit(unit)
    r = {"npm": {}, "pypi": {}, "not_covered": [], "skipped": []}
    cov, gen = Coverage(), []
    if pol.unit_gap(unit):
        cov.skip(unit, pol.unit_gap(unit))
    interesting = set(LOCKFILES) | {"package.json", "bun.lockb"} | set(UNSUPPORTED_PY) | \
        set(PY_MANIFESTS) | OTHER_FILES
    reqs, manifests, pkg_dirs, lock_dirs = [], [], [], []

    def wanted(a):
        b = os.path.basename(a)
        return b in interesting or is_requirements(b)

    for dp, dns, fns in pol.walk(unit, cov=cov, wanted=wanted, generated=gen):
        rel_dir = pol.rel(dp)
        reqs += [f"{rel_dir}/{f}" for f in fns if is_requirements(f)]
        manifests += [f"{rel_dir}/{f}" for f in fns if f in PY_MANIFESTS]
        if "package.json" in fns:
            pkg_dirs.append(dp)
        if any(f in fns for f in LOCKFILES + ("bun.lockb",)):
            lock_dirs.append(dp)

        def guarded(fn, *args):
            try:
                return fn(*args)
            except Exception as e:  # noqa: BLE001  one file never stops the project
                return {"status": "error", "error": f"exception:{type(e).__name__}"}

        if "package-lock.json" in fns:
            r["npm"][f"{rel_dir}/package-lock.json"] = guarded(npm_audit, pol, os.path.join(dp, "package-lock.json"), registry)
        else:
            for lf in UNSUPPORTED_LOCKS:
                if lf in fns:
                    r["not_covered"].append(f"{rel_dir}/{lf}")
        for f in fns:
            if is_requirements(f):
                r["pypi"][f"{rel_dir}/{f}"] = guarded(pypi_audit, pol, os.path.join(dp, f), opener)
            elif f in UNSUPPORTED_PY:
                r["not_covered"].append(f"{rel_dir}/{f}")
        r["not_covered"] += other_ecosystems(rel_dir, fns)
    # Dependencies the audit can't see are "not covered", never an empty clean result.
    for dp in pkg_dirs:
        if not any(dp == d or dp.startswith(d + os.sep) for d in lock_dirs):
            j = pol.load_json(os.path.join(dp, "package.json"), MAX_TEXT, cov)
            if isinstance(j, dict) and any(isinstance(j.get(k), dict) and j[k] for k in
                                           ("dependencies", "devDependencies", "optionalDependencies")):
                r["not_covered"].append(f"{pol.rel(dp)}/package.json: no-lockfile")
    r["not_covered"] += [f"{m}: no-requirements-file" for m in uncovered_manifests(manifests, reqs)]
    r["skipped"] = cov.skipped
    if gen:
        r["generated_skipped"] = sorted(gen)  # build output and dependency copies: never audited, by design
    results = [x for k in ("npm", "pypi") for x in r[k].values()]
    ok = [x for x in results if x.get("status") == "ok"]
    if results and not ok and all(x.get("status") == "error" for x in results):
        r["status"] = "error"
    elif len(ok) < len(results) or r["not_covered"] or r["skipped"] or \
            any(x.get("unsupported") for x in r["pypi"].values()):
        r["status"] = "incomplete"
    else:
        r["status"] = "ok"
    return r


AUDIT_INPUTS = set(LOCKFILES) | {"package.json", "bun.lockb"} | set(UNSUPPORTED_PY) | OTHER_FILES


def audit_inputs(pol, unit):
    """Fingerprint of the files an audit of this unit depends on (metadata only: path, size, mtime and
    ctime in ns, inode). A result computed for other inputs is stale and is not promoted or resumed."""
    h = hashlib.sha256()
    pol = pol.for_unit(unit)
    for dp, dns, fns in pol.walk(unit):
        for f in sorted(fns):
            if f in AUDIT_INPUTS or is_requirements(f):
                h.update(_meta(os.path.join(dp, f), pol.rel(os.path.join(dp, f))))
    return h.hexdigest()[:24]


def _meta(path, rel):
    try:
        st = os.lstat(path)
        return f"{rel}\0{st.st_size}\0{st.st_mtime_ns}\0{st.st_ctime_ns}\0{st.st_ino}\n".encode("utf-8", "replace")
    except OSError:
        return f"{rel}\0gone\n".encode("utf-8", "replace")


# ------------------------------------------------------------------ deltas

def _items(results):
    """(key, kind, file, package, ok_for_package) for every advisory, plus coverage per file."""
    for _, r in (results or {}).items():
        for lf, res in r.get("npm", {}).items():
            if res.get("status") == "ok":
                for pkg, v in (res.get("vulns") or {}).items():
                    for adv in v.get("advisories", []):
                        yield _key(lf, pkg, adv, v.get("severity"))
        for rf, res in r.get("pypi", {}).items():
            for pkg, vs in (res.get("vulns") or {}).items():
                for v in vs:
                    if v.get("id"):
                        yield _key(rf, pkg, v["id"], "pypi")


def _key(*parts):
    return "|".join(clean(p).replace("|", "_") for p in parts)


def audit_keys(results):
    """Set of 'file|package|advisory|severity' strings from successfully checked files only.
    Each part is sanitised, so the keys are safe to print as they are."""
    return set(_items(results))


def covered(results):
    """Predicate: was this previous key's file (and package, for PyPI) checked successfully this run?
    Keys for anything not covered (failed, skipped, other projects) are carried, never 'fixed'."""
    npm_ok, pypi = set(), {}
    for _, r in (results or {}).items():
        npm_ok |= {lf for lf, res in r.get("npm", {}).items() if res.get("status") == "ok"}
        for rf, res in r.get("pypi", {}).items():
            if res.get("status") in ("ok", "incomplete") and not res.get("opaque") and "unverified_names" in res:
                # names whose installed version this run doesn't know: failed lookups and unsupported lines
                pypi[rf] = {_pyname(k.split("==")[0]) for k in (res.get("failed") or {})} | set(res["unverified_names"])

    def ok(key):
        parts = key.split("|")
        if len(parts) < 4:
            return False
        f, pkg, kind = parts[0], parts[1], parts[-1]
        if kind == "pypi":
            # fixed only when the file was read, nothing in it could install anything else, and this
            # package is either checked at its new pin or gone from the file
            return f in pypi and _pyname(pkg.split("==")[0]) not in pypi[f]
        return f in npm_ok
    return ok


# ------------------------------------------------------------------ route check
ROUTE_HOSTS = {"npm": "https://registry.npmjs.org/",
               "pypi": "https://pypi.org/simple/", "github": "https://github.com/"}


def probe(url, timeout=8):
    """HTTP status code only (or an error category). Never reads or prints the body."""
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code  # an HTTP answer still means the host is reachable
    except Exception as e:  # noqa: BLE001
        cat = _http_error_category(e)
        return cat if cat == "tls-verify-failed" else f"unreachable: {cat}"


def route_check(registry=DEFAULT_NPM_REGISTRY):
    codes = {k: probe(u) for k, u in ROUTE_HOSTS.items()}
    reachable = {k: isinstance(c, int) for k, c in codes.items()}
    tools = {"npm": bool(shutil.which("npm"))}
    notes = []
    if tools["npm"] and not reachable["npm"]:
        # npm has its own TLS setup: ask npm itself (read-only ping of the registry), isolated like the audit.
        with Scratch() as s:
            rc, _, _, _ = sh(["npm", "ping", "--registry", registry], cwd=s.work, timeout=30, env=s.env(registry))
        reachable["npm"] = rc == 0
        codes["npm_ping"] = "ok" if rc == 0 else "failed"
    if "tls-verify-failed" in codes.values():
        notes.append("Python can't verify TLS certificates here (python.org builds on macOS: run 'Install "
                     "Certificates.command'). Don't turn verification off; PyPI checks are not covered until fixed")
    if not reachable["npm"] or not tools["npm"]:
        notes.append("npm audit unavailable: package-lock.json projects are not covered this run")
    if codes["pypi"] != "tls-verify-failed" and not reachable["pypi"]:
        notes.append("pypi.org unreachable: Python requirements are not covered this run")
    return {"status_codes": codes, "reachable": reachable, "tools": tools, "ca_bundle": ca_bundle(), "notes": notes}
