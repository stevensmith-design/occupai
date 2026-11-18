"""Version parsing and affected-range matching for checks.json rules (stdlib only).

Supported range syntax (the forms the check library uses):
  npm (packages, runtimes)  comparators >=, >, <=, <, = or a bare exact version, each with a full
                            x.y.z version, joined by spaces or commas (AND) and || (OR):
                            ">=15.0.0 <15.5.29 || >=16.0.0 <16.4.5 || 19.3.0"
  pypi                      PEP 440 versions with >=, >, <=, <, ==, != joined the same way
Anything else (^, ~, hyphen and x-ranges, partial or prerelease versions inside a range, tags such as
"latest", ~=, wildcards) raises RangeError: the project is reported unknown, never reinterpreted.

Installed versions may be prereleases: they are ordered by semver precedence, so 16.4.5-canary.1 is
inside "<16.4.5" (canary builds of an unfixed release are affected).
"""
import re


class RangeError(ValueError):
    """The range (or version) is not in the supported syntax."""


# ------------------------------------------------------------------ npm (semver)

_SEMVER = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                     r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
                     r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
_RANGE_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b,
        "<": lambda a, b: a < b, "=": lambda a, b: a == b, "==": lambda a, b: a == b, "!=": lambda a, b: a != b}


def _pre_key(pre):
    if not pre:
        return (1,)  # a release sorts after all of its prereleases
    return (0,) + tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split("."))


def semver_key(v):
    """Comparable key for a full semver version string (prereleases by precedence), or None."""
    m = _SEMVER.match(str(v).strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), _pre_key(m.group(4)))


def _parse(rng, ops, key):
    """'>=1.0.0 <2.0.0 || 3.0.0' -> [[(op, key), ...], ...]. Raises RangeError."""
    if not isinstance(rng, str) or not rng.strip():
        raise RangeError("empty-range")
    sets = []
    for part in rng.split("||"):
        part = re.sub(r"(>=|<=|==|!=|>|<|=)\s+(?=[0-9vV])", r"\1", part.strip())
        toks = [t for t in re.split(r"[\s,]+", part) if t]
        if not toks:
            raise RangeError("empty-set")
        comps = []
        for t in toks:
            m = re.fullmatch(r"(>=|<=|==|!=|>|<|=)?(.+)", t)
            op = m.group(1) or ("=" if "=" in ops else "")
            k = key(m.group(2))
            if op not in ops or k is None:
                raise RangeError("unsupported-range")
            comps.append((op, k))
        sets.append(comps)
    return sets


def _npm_range_key(s):
    m = _RANGE_VERSION.match(s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), (1,)) if m else None


def parse_npm_range(rng):
    return _parse(rng, (">=", "<=", ">", "<", "="), _npm_range_key)


def npm_in_range(version, rng):
    """True/False for a full semver version. Raises RangeError for an unsupported range or version."""
    v = semver_key(version)
    if v is None:
        raise RangeError("bad-version")
    return any(all(_OPS[op](v, k) for op, k in comps) for comps in parse_npm_range(rng))


# ------------------------------------------------------------------ PEP 440 (PyPI)

_PEP440 = re.compile(r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)"
                     r"(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?"
                     r"(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?"
                     r"(?:[-_.]?(dev)[-_.]?(\d*))?"
                     r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$", re.I)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def pep440_key(v):
    """Comparable key for a PEP 440 version (local labels ignored), or None."""
    m = _PEP440.match(str(v).strip())
    if not m:
        return None
    epoch = int(m.group(1) or 0)
    rel = [int(x) for x in m.group(2).split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    has_pre, has_post, has_dev = m.group(3) is not None, m.group(5) is not None or m.group(6) is not None, \
        m.group(8) is not None
    if has_pre:
        pre = (0, _PRE_RANK[m.group(3).lower()], int(m.group(4) or 0))
    elif has_dev and not has_post:
        pre = (-1,)  # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (1,)
    post = (0, int(m.group(5) or m.group(7) or 0)) if has_post else (-1,)
    dev = (0, int(m.group(9) or 0)) if has_dev else (1,)
    return (epoch, tuple(rel), pre, post, dev)


def _pypi_range_key(s):
    k = pep440_key(s)
    return k if k is not None and k[2] == (1,) and k[4] == (1,) else None  # no pre/dev releases in ranges


def parse_pypi_range(rng):
    return _parse(rng, (">=", "<=", ">", "<", "==", "!="), _pypi_range_key)


def pypi_in_range(version, rng):
    v = pep440_key(version)
    if v is None:
        raise RangeError("bad-version")
    return any(all(_OPS[op](v, k) for op, k in comps) for comps in parse_pypi_range(rng))


def pypi_name(name):
    """PEP 503 normalised project name."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def validate_range(rng, ecosystem="npm"):
    """None if the range is supported, else the RangeError reason."""
    try:
        (parse_pypi_range if ecosystem == "pypi" else parse_npm_range)(rng)
        return None
    except RangeError as e:
        return str(e)


# ------------------------------------------------------------------ runtime pins

def effective_pin(pin):
    """A runtime pin is itself a range: '22' or '22.x' gets every 22.x release, so it is judged by the
    top of its line; an exact pin is judged as it is. Returns a semver string, or None if the pin
    isn't a plain version (lts/*, latest, a matrix expression...): the caller reports unknown."""
    s = str(pin).strip()
    m = re.fullmatch(r"v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?", s)
    if not m:
        return None
    parts = [m.group(1), m.group(2), m.group(3)]
    nums = []
    for p in parts:
        if p is None or p in "xX*":
            break
        nums.append(int(p))
    if len(nums) == 3:
        return "%d.%d.%d" % tuple(nums)
    if len(nums) == 2:
        return "%d.%d.999999" % tuple(nums)
    return "%d.999999.999999" % nums[0]
