"""occupai.config.yaml loading (stdlib only).

Supports the YAML subset the config uses: nested maps, lists of scalars, lists of maps, inline
[a, b] lists, quoted strings, comments, booleans, numbers and null. JSON files also work.
"""
import json
import os
import re

from .common import FALLBACK_EXCLUDE

CONFIG_NAME = "occupai.config.yaml"
KIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the kit this script runs from
LEGACY = os.path.join("~", ".occupai")
DEFAULTS = {
    "version": 1,
    "projects_root": None,
    "exclusions": list(FALLBACK_EXCLUDE),
    "my_owners": [],
    "timezone": "UTC",
    "storage": {"path": None, "mode": "local"},  # None: see storage_path()
    "computer": None,         # the user's OS (macOS | Windows | Linux), set at setup; detected when empty
    "news_scorecard": True,   # the shareable news brief ends with "N of your projects may be affected"
}


class ConfigError(ValueError):
    pass


def _scalar(s):
    s = s.strip()
    if not s:
        return None
    if s[0] in "\"'":
        q = s[0]
        end = s.find(q, 1)
        if end == -1:
            raise ConfigError(f"unclosed quote: {s}")
        return s[1:end]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return [_scalar(x) for x in _split_inline(inner)] if inner else []
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        out = {}
        for part in _split_inline(inner):
            k, _, v = part.partition(":")
            out[k.strip()] = _scalar(v)
        return out
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    return s


def _split_inline(s):
    parts, depth, cur, q = [], 0, "", None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in "\"'":
            q = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _strip_comment(line):
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def parse_yaml(text):
    lines = []
    for raw in text.splitlines():
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ConfigError("tabs are not allowed for indentation")
        s = _strip_comment(raw)
        if s.strip() and s.strip() != "---":
            lines.append((len(s) - len(s.lstrip()), s.strip()))
    value, i = _block(lines, 0, 0)
    if i != len(lines):
        raise ConfigError(f"unexpected indentation near: {lines[i][1]}")
    return value if value is not None else {}


def _block(lines, i, indent):
    if i >= len(lines):
        return None, i
    if lines[i][1].startswith("- ") or lines[i][1] == "-":
        return _list(lines, i, lines[i][0])
    return _map(lines, i, lines[i][0])


def _map(lines, i, indent):
    out = {}
    while i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("- "):
        key, sep, rest = lines[i][1].partition(":")
        if not sep:
            raise ConfigError(f"expected 'key: value': {lines[i][1]}")
        key = key.strip().strip("\"'")
        i += 1
        if rest.strip():
            out[key] = _scalar(rest)
        elif i < len(lines) and (lines[i][0] > indent or (lines[i][0] == indent and lines[i][1].startswith("- "))):
            out[key], i = _block(lines, i, lines[i][0])
        else:
            out[key] = None
    return out, i


def _list(lines, i, indent):
    out = []
    while i < len(lines) and lines[i][0] == indent and (lines[i][1].startswith("- ") or lines[i][1] == "-"):
        item = lines[i][1][1:].strip()
        if not item:
            i += 1
            val, i = _block(lines, i, lines[i][0]) if i < len(lines) and lines[i][0] > indent else (None, i)
            out.append(val)
            continue
        if re.match(r"^[^\"'\[{][^:]*:(\s|$)", item):
            # a map inside a list item: "- name: x" + following keys indented to align with "name"
            sub_indent = indent + 2
            sub = [(sub_indent, item)]
            j = i + 1
            while j < len(lines) and lines[j][0] > indent:
                sub.append(lines[j])
                j += 1
            val, k = _map(sub, 0, sub_indent)
            if k != len(sub):
                # nested blocks under keys of this item
                val, k = _map_with_children(sub, sub_indent)
            out.append(val)
            i = j
        else:
            out.append(_scalar(item))
            i += 1
    return out, i


def _map_with_children(sub, indent):
    out, i = _map(sub, 0, indent)
    if i != len(sub):
        raise ConfigError(f"unexpected indentation near: {sub[i][1]}")
    return out, i


def load(path=None):
    """Load config from --config, else $OCCUPAI_CONFIG, else ~/.occupai/ (older installs), KIT/data/ or
    ./occupai.config.yaml. An explicit path (--config or $OCCUPAI_CONFIG) that doesn't exist is an error:
    it never falls back to another config."""
    explicit = path or os.environ.get("OCCUPAI_CONFIG")
    if explicit:
        found = mounted(explicit) if os.path.isfile(mounted(explicit)) else None
        if not found:
            raise ConfigError(f"config not found: {explicit}")
    else:
        kit_cfg = [] if os.environ.get("OCCUPAI_SKIP_KIT_DATA") else [os.path.join(KIT_DIR, "data", CONFIG_NAME)]
        candidates = [os.path.join(LEGACY, CONFIG_NAME), *kit_cfg, CONFIG_NAME]  # skip: hermetic tests
        found = next((mounted(c) for c in candidates if os.path.isfile(mounted(c))), None)
    cfg = json.loads(json.dumps(DEFAULTS))
    if found:
        with open(os.path.expanduser(found)) as f:
            text = f.read()
        data = json.loads(text) if found.endswith(".json") else parse_yaml(text)
        if not isinstance(data, dict):
            raise ConfigError("config must be a map at the top level")
        for k, v in data.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update({kk: vv for kk, vv in v.items() if vv is not None})
            elif v is not None:
                cfg[k] = v
        cfg["_path"] = os.path.abspath(os.path.expanduser(found))
    return cfg


def mounted(path):
    """The path as seen from here. A task created from a Claude Desktop chat runs in a device shell that
    sees each attached folder at $HOME/mnt/<folder name>. A configured path that doesn't exist here but
    sits inside an attached folder maps to that mount; anything else is returned unchanged."""
    p = os.path.abspath(os.path.expanduser(path))
    mnt = os.path.join(os.path.expanduser("~"), "mnt")
    if os.path.exists(p) or not os.path.isdir(mnt):
        return p
    a = p
    while os.path.dirname(a) != a:
        name = os.path.basename(a)
        if name not in ("", ".", "..") and os.path.isdir(os.path.join(mnt, name)):
            m = os.path.normpath(os.path.join(mnt, name, os.path.relpath(p, a)))
            return m if os.path.exists(m) else p
        a = os.path.dirname(a)
    return p


def storage_path(cfg):
    """storage.path if set; else the folder holding the config when that is KIT/data (the default since
    setup keeps everything in the kit); else ~/.occupai (older installs, and runs with no config)."""
    p = cfg.get("storage", {}).get("path")
    if p:
        return mounted(p)
    cp = cfg.get("_path")
    if cp and os.path.basename(os.path.dirname(cp)) == "data" and \
            os.path.isfile(os.path.join(os.path.dirname(os.path.dirname(cp)), "scan.py")):
        return os.path.dirname(cp)
    return mounted(LEGACY)
