"""Build the fixture projects in a temp folder: fake keys, generated files and git history.

Fake keys are generated here at test time and never committed. The committed fixtures only hold
@@TOKENS@@ that don't look like keys.
"""
import os
import random
import re
import shutil
import string
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
PLACEHOLDER = re.compile(r"(example|sample|placeholder|dummy|fake|changeme|your|xxxx|redacted)", re.I)

# Files that our own .gitignore would hide (.env*), or that are better made at test time.
GENERATED = {
    "web-shop/.env": "API_TOKEN=@@FAKE_GITHUB_TOKEN@@\n",
    "web-shop/.env.example": "ANTHROPIC_API_KEY=your-key-here\n",
    "forked-tool/.npmrc": "registry=https://registry.npmjs.org/\n",
}

# name -> git setup. Projects not listed stay plain folders.
GIT = {
    "web-shop": {"remote": "https://github.com/example-owner/web-shop.git"},
    "ui-kit": {"remote": "git@github.com:example-owner/ui-kit.git"},
    "supa-app": {},
    "ci-demo": {"remote": "https://github.com/example-owner/ci-demo.git"},
    "agent-lab": {},
    "clean-app": {"remote": "https://github.com/example-owner/clean-app.git"},
    "forked-tool": {"remote": "https://github.com/someone-else/forked-tool.git"},
    "indicator-repo": {"branches": ["ci-helper-4821"], "commits": ["chore: add ci helper"]},
}


def _rand(rng, n, alphabet):
    while True:
        s = "".join(rng.choice(alphabet) for _ in range(n))
        if not PLACEHOLDER.search(s):
            return s


def make_keys(seed=None):
    rng = random.Random(seed)
    alnum = string.ascii_letters + string.digits
    return {
        "FAKE_ANTHROPIC_KEY": "sk-ant-api03-" + _rand(rng, 40, alnum),
        "FAKE_ANTHROPIC_KEY_2": "sk-ant-api03-" + _rand(rng, 40, alnum),
        "FAKE_OPENAI_KEY": "sk-proj-" + _rand(rng, 48, alnum),
        "FAKE_AWS_KEY": "AKIA" + _rand(rng, 16, string.ascii_uppercase.replace("X", "") + string.digits),
        "FAKE_GITHUB_TOKEN": "ghp_" + _rand(rng, 36, alnum),
    }


SPECIAL = {"ZWSP": "​", "ZWJ_EMOJI": "\U0001F469‍\U0001F4BB"}


def _git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=env)


_CACHE = {}


def build(dest, seed=None):
    """Copy fixtures to dest (without the root ignore marker), fill tokens, create git repos.
    Returns the generated fake keys so tests can assert they never appear in output.
    With a seed, the result is built once per test process and copied (keys are deterministic)."""
    if seed is not None:
        if seed not in _CACHE:
            import atexit
            import tempfile
            cache = tempfile.mkdtemp(prefix=f"occupai-fixture-{seed}-")
            atexit.register(shutil.rmtree, cache, True)
            _CACHE[seed] = (os.path.join(cache, "p"), _build(os.path.join(cache, "p"), seed))
        src, keys = _CACHE[seed]
        shutil.copytree(src, dest, symlinks=True, dirs_exist_ok=True)
        return keys
    return _build(dest, seed)


def _build(dest, seed):
    keys = make_keys(seed)
    values = {**keys, **SPECIAL}
    shutil.copytree(FIXTURES, dest, dirs_exist_ok=True)
    os.remove(os.path.join(dest, ".occupai-ignore"))
    for rel, content in GENERATED.items():
        os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
        with open(os.path.join(dest, rel), "w") as f:
            f.write(content)
    for dp, _, fns in os.walk(dest):
        for fn in fns:
            fp = os.path.join(dp, fn)
            with open(fp, encoding="utf-8") as f:
                text = f.read()
            if "@@" in text:
                for k, v in values.items():
                    text = text.replace(f"@@{k}@@", v)
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(text)
    for name, g in GIT.items():
        p = os.path.join(dest, name)
        _git(p, "init", "-q", "-b", "main")
        _git(p, "add", "-A", "-f")
        _git(p, "commit", "-q", "-m", "initial")
        if g.get("remote"):
            _git(p, "remote", "add", "origin", g["remote"])
        for b in g.get("branches", []):
            _git(p, "branch", b)
        for msg in g.get("commits", []):
            _git(p, "commit", "-q", "--allow-empty", "-m", msg)
    return keys
