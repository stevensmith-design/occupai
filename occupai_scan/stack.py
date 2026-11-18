"""What each project uses ("scanning for"), from tell-tale file names and dependency names only.

The news step judges "touches my stack?" against this list, so a news item about a service the user
never listed (a CI provider, a host, a database) still reaches the projects that use it. Only
package.json and requirements*.txt are read, for dependency names; nothing else is opened.
"""
import os
import re

from .safefs import Coverage

# label -> what the kit checks locally for it; anything else is "news only".
COVERED = {"npm": "audited", "PyPI": "audited (pinned requirements)", "GitHub Actions": "checked",
           "Supabase": "checked", "Firebase": "checked", "MCP servers": "checked", "Claude Code": "checked",
           "AI agent instructions": "checked"}

FILES = {"bitrise.yml": "Bitrise", "codemagic.yaml": "Codemagic", ".gitlab-ci.yml": "GitLab CI",
         "vercel.json": "Vercel", "netlify.toml": "Netlify", "render.yaml": "Render", "fly.toml": "Fly.io",
         "railway.json": "Railway", "firebase.json": "Firebase", "Dockerfile": "Docker",
         "composer.json": "PHP (Composer)", "Gemfile": "Ruby (Bundler)", "go.mod": "Go modules",
         "Cargo.toml": "Rust (Cargo)", "pubspec.yaml": "Flutter/Dart", "package.json": "npm",
         "pyproject.toml": "PyPI", ".mcp.json": "MCP servers", "CLAUDE.md": "Claude Code",
         "AGENTS.md": "AI agent instructions"}
DIRS = {".circleci": "CircleCI", "supabase": "Supabase", ".claude": "Claude Code", ".cursor": "Cursor"}

NPM = {"next": "Next.js", "react": "React", "vue": "Vue", "nuxt": "Nuxt", "svelte": "Svelte",
       "@sveltejs/kit": "Svelte", "express": "Express", "electron": "Electron", "expo": "Expo",
       "react-native": "React Native", "firebase": "Firebase", "firebase-admin": "Firebase",
       "mongodb": "MongoDB", "mongoose": "MongoDB", "prisma": "Prisma", "@prisma/client": "Prisma",
       "pg": "PostgreSQL", "postgres": "PostgreSQL", "mysql": "MySQL", "mysql2": "MySQL", "redis": "Redis",
       "ioredis": "Redis", "stripe": "Stripe", "@anthropic-ai/sdk": "Anthropic SDK", "openai": "OpenAI SDK",
       "@modelcontextprotocol/sdk": "MCP SDK", "ai": "Vercel AI SDK", "langchain": "LangChain"}
NPM_SCOPES = {"@supabase/": "Supabase", "@langchain/": "LangChain", "@vercel/": "Vercel"}
PYPI = {"django": "Django", "flask": "Flask", "fastapi": "FastAPI", "anthropic": "Anthropic SDK",
        "openai": "OpenAI SDK", "sqlalchemy": "SQLAlchemy", "pymongo": "MongoDB", "psycopg2": "PostgreSQL",
        "psycopg2-binary": "PostgreSQL", "psycopg": "PostgreSQL", "supabase": "Supabase",
        "firebase-admin": "Firebase", "langchain": "LangChain", "mcp": "MCP SDK"}
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def coverage(label):
    return COVERED.get(label, "news only")


def detect(pol, unit):
    """Sorted labels for one project (best effort: unreadable manifests just add nothing)."""
    found, cov = set(), Coverage()
    for dp, dns, fns in pol.walk(unit):
        found |= {DIRS[d] for d in dns if d in DIRS}
        if os.path.basename(dp) == ".github" and "workflows" in dns:
            found.add("GitHub Actions")
        for f in fns:
            if f in FILES:
                found.add(FILES[f])
            elif f.startswith("Dockerfile."):
                found.add("Docker")
            elif f.startswith("requirements") and f.endswith(".txt"):
                found.add("PyPI")
                for line in (pol.read_text(os.path.join(dp, f), cov=cov) or "").splitlines():
                    m = _REQ_NAME.match(line)
                    if m and m.group(1).lower().replace("_", "-") in PYPI:
                        found.add(PYPI[m.group(1).lower().replace("_", "-")])
            if f == "package.json":
                pkg = pol.load_json(os.path.join(dp, f), cov=cov)
                for sect in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    deps = pkg.get(sect) if isinstance(pkg, dict) else None
                    for name in (deps if isinstance(deps, dict) else {}):
                        label = NPM.get(name) or next((v for k, v in NPM_SCOPES.items() if name.startswith(k)), None)
                        if label:
                            found.add(label)
    return sorted(found)


def inventory(projects):
    """{label: [projects]} from {project: [labels]}."""
    out = {}
    for u, labels in sorted(projects.items()):
        for label in labels:
            out.setdefault(label, []).append(u)
    return dict(sorted(out.items(), key=lambda kv: kv[0].lower()))


def render(inv, new, date):
    """STORAGE/library/stack.md: the short "scanning for" list the news step reads."""
    lines = ["# Scanning for", "",
             f"Written by the full run on {date} from file and dependency names. Every run matches news "
             "against this list (\"touches my stack?\") and names the projects.", "",
             "| Tech | Projects | Checked locally |", "|---|---|---|"]
    for label, units in inv.items():
        mark = " (new)" if label in new else ""
        lines.append(f"| {label}{mark} | {', '.join(units)} | {coverage(label)} |")
    return "\n".join(lines) + "\n"
