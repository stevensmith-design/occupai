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

# label -> its official security news page(s) as (name, url), or a list of them: the vendor's own site or the
# project's GitHub security advisories, never aggregators or blogs. Added to `news_sources.stack_vendors`.
_GH = "https://github.com/{}/security/advisories"
SOURCES = {
    "npm": ("Node.js security releases", "https://nodejs.org/en/blog/vulnerability"),
    "PyPI": ("Python security", "https://www.python.org/news/security/"),
    "Next.js": ("Next.js blog", "https://nextjs.org/blog"), "React": ("React blog", "https://react.dev/blog"),
    "Vercel": ("Vercel changelog", "https://vercel.com/changelog"),
    "Supabase": ("Supabase changelog", "https://supabase.com/changelog"),
    "Claude Code": ("Claude Code security advisories", _GH.format("anthropics/claude-code")),
    "MCP servers": ("MCP servers security advisories", _GH.format("modelcontextprotocol/servers")),
    "MCP SDK": [("MCP TypeScript SDK security advisories", _GH.format("modelcontextprotocol/typescript-sdk")),
                ("MCP Python SDK security advisories", _GH.format("modelcontextprotocol/python-sdk"))],
    "PHP (Composer)": ("PHP news", "https://www.php.net/"),
    "Ruby (Bundler)": ("Ruby security", "https://www.ruby-lang.org/en/security/"),
    "Go modules": ("Go vulnerability database", "https://pkg.go.dev/vuln/list"),
    "Rust (Cargo)": ("RustSec advisories", "https://rustsec.org/advisories/"),
    "Flutter/Dart": ("Flutter security advisories", _GH.format("flutter/flutter")),
    "Django": ("Django weblog (security releases)", "https://www.djangoproject.com/weblog/"),
    "Flask": ("Flask security advisories", _GH.format("pallets/flask")),
    "FastAPI": ("FastAPI security advisories", _GH.format("fastapi/fastapi")),
    "Docker": ("Docker security announcements", "https://docs.docker.com/security/security-announcements/"),
    "GitLab CI": ("GitLab releases", "https://about.gitlab.com/releases/categories/releases/"),
    "Firebase": ("Firebase release notes", "https://firebase.google.com/support/releases"),
    "Electron": ("Electron security advisories", _GH.format("electron/electron")),
    "Express": ("Express security updates", "https://expressjs.com/en/advanced/security-updates.html"),
    "Vue": ("Vue security advisories", _GH.format("vuejs/core")),
    "Nuxt": ("Nuxt security advisories", _GH.format("nuxt/nuxt")),
    "Svelte": ("SvelteKit security advisories", _GH.format("sveltejs/kit")),
    "React Native": ("React Native security advisories", _GH.format("facebook/react-native")),
    "PostgreSQL": ("PostgreSQL security", "https://www.postgresql.org/support/security/"),
    "MongoDB": ("MongoDB security alerts", "https://www.mongodb.com/resources/products/alerts"),
    "Redis": ("Redis security advisories", _GH.format("redis/redis")),
    "LangChain": ("LangChain security advisories", _GH.format("langchain-ai/langchain")),
    "Cursor": ("Cursor security advisories", _GH.format("cursor/cursor")),
}


def coverage(label):
    return COVERED.get(label, "news only")


def _norm(url):
    return str(url).strip().lower().rstrip("/").replace("://www.", "://")


def sources(label):
    src = SOURCES.get(label) or []
    return [src] if isinstance(src, tuple) else src


def sources_for(label, news_sources):
    """[{name, url}] of the label's official sources not yet in any group (empty when unmapped)."""
    groups = news_sources.values() if isinstance(news_sources, dict) else []
    have = {_norm(s.get("url")) for g in groups if isinstance(g, list) for s in g if isinstance(s, dict)}
    return [{"name": n, "url": u} for n, u in sources(label) if _norm(u) not in have]


def tech_row(label, projects, news_sources):
    """One "scanning for" entry; `add_source` only when there are official sources not yet watched."""
    row = {"tech": label, "projects": projects, "checked_locally": coverage(label)}
    src = sources_for(label, news_sources)
    return {**row, "add_source": src} if src else row


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
