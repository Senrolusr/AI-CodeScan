"""Static pre-discovery: tech-stack, directory structure, import graph, middleware map, security-critical files."""

from __future__ import annotations

import os
import re
from services.config import (
    MAX_FILE_SIZE
)

from services.code_parser_pkg.files import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

_DIR_ROLE_PATTERNS = {
    "controller": ["controller", "controllers", "handler", "handlers", "endpoint", "endpoints", "api", "apis"],
    "service": ["service", "services", "logic", "business", "usecase", "usecases", "interactor", "interactors"],
    "model": ["model", "models", "entity", "entities", "domain"],
    "middleware": ["middleware", "middlewares", "interceptor", "interceptors", "guard", "guards", "filter", "filters"],
    "config": ["config", "configuration", "settings", "conf"],
    "route": ["route", "routes", "router", "routers", "urls"],
    "auth": ["auth", "authentication", "security", "permission", "permissions"],
    "dao": ["dao", "repository", "repositories", "mapper", "mappers", "dal", "persistence"],
    "view": ["view", "views", "template", "templates", "page", "pages", "component", "components"],
    "util": ["util", "utils", "helper", "helpers", "common", "shared", "lib", "libs"],
    "test": ["test", "tests", "spec", "specs", "__tests__", "testing"],
    "migrate": ["migration", "migrations", "migrate", "db"],
}

_PROJECT_PATTERNS = {
    "mvc": {"controller", "model", "view"},
    "layered": {"controller", "service", "dao"},
    "clean": {"entity", "usecase", "interactor"},
    "django_mvt": {"view", "model", "template"},
}

_PY_IMPORT_RE = re.compile(r'^(?:from\s+(\S+)\s+)?import\s+([^\n#]+)', re.MULTILINE)

_JS_IMPORT_RE = re.compile(r'(?:import\s+.*?from\s+["\'](\.[^"\']+)["\']|require\s*\(\s*["\'](\.[^"\']+)["\']\))', re.MULTILINE)

_GO_IMPORT_RE = re.compile(r'import\s*\(([\s\S]*?)\)', re.MULTILINE)

_GO_SINGLE_IMPORT_RE = re.compile(r'import\s+"([^"]+)"', re.MULTILINE)

_JAVA_IMPORT_RE = re.compile(r'import\s+([\w.]+)\s*;', re.MULTILINE)

_AUTH_DECORATOR_PATTERNS = [
    re.compile(r'@(\w*(?:auth|login|token|jwt|bearer)\w*)\b', re.I),
    re.compile(r'@(?:pre_?authorize|secured|roles_allowed|has_role|has_authority|permit_all|deny_all)\b', re.I),
    re.compile(r'@require_(?:auth|login|permission|role|scopes)', re.I),
    re.compile(r'decorator\s*\(\s*["\']?(\w*(?:auth|login|jwt|token)\w*)', re.I),
    re.compile(r'@UseGuards\((\w+)\)', re.I),
]

_MIDDLEWARE_PATTERNS = [
    re.compile(r'app\.use\(\s*([/\w]*)\s*,?\s*(?:\w+)?\s*\)', re.I),
    re.compile(r'app\.add_middleware\(\s*(\w+)', re.I),
    re.compile(r'MIDDLEWARE\s*=\s*\[([^\]]+)\]', re.I),
    re.compile(r'(?:const|let|var)\s+\w+\s*=\s*require\(["\']([/\w]*(?:middleware|auth|session|cors|csrf|helmet)[/\w]*)["\']\)', re.I),
    re.compile(r'\.use\(\s*/[^,]+,\s*(\w+Middleware)', re.I),
    re.compile(r'func\s+(\w+Middleware)\s*\(', re.I),
]

_SECURITY_FILE_PATTERNS = {
    "auth_handler": [
        re.compile(r'(?:login|authenticate|signin|sign_in|do_login|handle_login|verify_token|check_auth|auth_check)', re.I),
    ],
    "auth_middleware": [
        re.compile(r'class\s+\w*(?:Auth|Jwt|Token|Session|Login)Middleware', re.I),
        re.compile(r'func\s+\w*(?:Auth|Jwt|Token|Session)Middleware', re.I),
        re.compile(r'(?:def|function)\s+\w*(?:auth|jwt|token|session)_(?:middleware|guard|check|verify)', re.I),
    ],
    "permission": [
        re.compile(r'(?:permission|authorize|can_access|check_permission|has_role|is_admin|require_role|rbac|acl)', re.I),
    ],
    "crypto": [
        re.compile(r'(?:encrypt|decrypt|hash|bcrypt|scrypt|argon|pbkdf|hmac|aes|rsa|private_key|public_key|certificate|ssl|tls)', re.I),
    ],
    "file_operation": [
        re.compile(r'(?:upload|download|readfile|writefile|file_get_contents|fopen|move_uploaded|send_file|serve_file|attachment)', re.I),
    ],
    "db_query": [
        re.compile(r'(?:raw_query|execute_query|cursor\.execute|\.raw\(|\.query\(|\.find\(|\.aggregate\()', re.I),
    ],
    "config_secret": [
        re.compile(r'(?:secret_key|private_key|api_key|password|token|credential|database_url|connection_string)', re.I),
    ],
}

_MUST_COVER_ROLES = {"auth", "middleware", "config", "route"}

def _build_tech_stack_profile(project_dir: str, file_tree: list) -> dict:
    """Structured tech stack detection from dependency/config files."""
    profile = {"language": [], "framework": [], "database": [], "orm": [], "auth_library": [], "template_engine": [], "message_queue": [], "build_tool": []}
    flat_files = _flatten_files(file_tree)
    filenames = {f["name"] for f in flat_files}

    pkg = _read_project_file(project_dir, "package.json")
    req = _read_project_file(project_dir, "requirements.txt")
    pyproj = _read_project_file(project_dir, "pyproject.toml")
    pom = _read_project_file(project_dir, "pom.xml")
    gomod = _read_project_file(project_dir, "go.mod")
    cargotoml = _read_project_file(project_dir, "Cargo.toml")
    gemfile = _read_project_file(project_dir, "Gemfile")
    composer = _read_project_file(project_dir, "composer.json")

    # Python
    py_content = "\n".join(filter(None, [req, pyproj])).lower()
    if py_content or any(f["path"].endswith(".py") for f in flat_files[:50]):
        profile["language"].append("Python")
        if "django" in py_content:
            profile["framework"].append("Django")
        if "flask" in py_content:
            profile["framework"].append("Flask")
        if "fastapi" in py_content:
            profile["framework"].append("FastAPI")
        if "tornado" in py_content:
            profile["framework"].append("Tornado")
        if "sqlalchemy" in py_content:
            profile["orm"].append("SQLAlchemy")
        if "django" in py_content and "orm" not in profile["orm"]:
            profile["orm"].append("Django ORM")
        if "mongoengine" in py_content:
            profile["orm"].append("MongoEngine")
        if "peewee" in py_content:
            profile["orm"].append("Peewee")
        if "psycopg" in py_content or "psycopg2" in py_content:
            profile["database"].append("PostgreSQL")
        if "pymysql" in py_content or "mysqlclient" in py_content:
            profile["database"].append("MySQL")
        if "sqlite" in py_content:
            profile["database"].append("SQLite")
        if "pymongo" in py_content:
            profile["database"].append("MongoDB")
        if "redis" in py_content:
            profile["database"].append("Redis")
        if "celery" in py_content:
            profile["message_queue"].append("Celery")
        if "rq" in py_content:
            profile["message_queue"].append("Redis Queue")
        if "jinja" in py_content:
            profile["template_engine"].append("Jinja2")
        if "pyjwt" in py_content or "python-jose" in py_content or "jose" in py_content:
            profile["auth_library"].append("JWT")
        if "flask-login" in py_content:
            profile["auth_library"].append("Flask-Login")
        if "passlib" in py_content or "bcrypt" in py_content:
            profile["auth_library"].append("Passlib")
        if "poetry" in (pyproj or "").lower():
            profile["build_tool"].append("Poetry")
        if "setuptools" in py_content:
            profile["build_tool"].append("Setuptools")

    # Node.js
    if pkg:
        pkg_lower = pkg.lower()
        profile["language"].append("JavaScript/TypeScript")
        if '"express"' in pkg_lower:
            profile["framework"].append("Express")
        if '"koa"' in pkg_lower:
            profile["framework"].append("Koa")
        if '"@nestjs/core"' in pkg_lower:
            profile["framework"].append("NestJS")
        if '"fastify"' in pkg_lower:
            profile["framework"].append("Fastify")
        if '"next"' in pkg_lower:
            profile["framework"].append("Next.js")
        if '"react"' in pkg_lower:
            profile["framework"].append("React")
        if '"vue"' in pkg_lower:
            profile["framework"].append("Vue")
        if '"mongoose"' in pkg_lower:
            profile["orm"].append("Mongoose")
        if '"prisma"' in pkg_lower or '"@prisma/client"' in pkg_lower:
            profile["orm"].append("Prisma")
        if '"sequelize"' in pkg_lower:
            profile["orm"].append("Sequelize")
        if '"typeorm"' in pkg_lower:
            profile["orm"].append("TypeORM")
        if '"pg"' in pkg_lower or '"postgresql"' in pkg_lower:
            profile["database"].append("PostgreSQL")
        if '"mysql"' in pkg_lower or '"mysql2"' in pkg_lower:
            profile["database"].append("MySQL")
        if '"mongodb"' in pkg_lower:
            profile["database"].append("MongoDB")
        if '"ioredis"' in pkg_lower or '"redis"' in pkg_lower:
            profile["database"].append("Redis")
        if '"jsonwebtoken"' in pkg_lower or '"jose"' in pkg_lower:
            profile["auth_library"].append("JWT")
        if '"passport"' in pkg_lower:
            profile["auth_library"].append("Passport")
        if '"bull"' in pkg_lower:
            profile["message_queue"].append("Bull")
        if '"amqplib"' in pkg_lower or '"rabbitmq"' in pkg_lower:
            profile["message_queue"].append("RabbitMQ")
        if '"ejs"' in pkg_lower:
            profile["template_engine"].append("EJS")
        if '"pug"' in pkg_lower:
            profile["template_engine"].append("Pug")
        if '"handlebars"' in pkg_lower:
            profile["template_engine"].append("Handlebars")
        if '"webpack"' in pkg_lower:
            profile["build_tool"].append("Webpack")
        if '"vite"' in pkg_lower:
            profile["build_tool"].append("Vite")

    # Go
    if gomod:
        profile["language"].append("Go")
        gomod_lower = gomod.lower()
        if "gin-gonic" in gomod_lower:
            profile["framework"].append("Gin")
        if "echo" in gomod_lower:
            profile["framework"].append("Echo")
        if "fiber" in gomod_lower:
            profile["framework"].append("Fiber")
        if "gorm" in gomod_lower:
            profile["orm"].append("GORM")
        if "postgres" in gomod_lower:
            profile["database"].append("PostgreSQL")
        if "mysql" in gomod_lower:
            profile["database"].append("MySQL")
        if "mongo" in gomod_lower:
            profile["database"].append("MongoDB")
        if "redis" in gomod_lower:
            profile["database"].append("Redis")

    # Java
    if pom:
        profile["language"].append("Java")
        pom_lower = pom.lower()
        if "spring-boot" in pom_lower:
            profile["framework"].append("Spring Boot")
        if "hibernate" in pom_lower:
            profile["orm"].append("Hibernate")
        if "mybatis" in pom_lower:
            profile["orm"].append("MyBatis")
        if "spring-security" in pom_lower:
            profile["auth_library"].append("Spring Security")
        if "shiro" in pom_lower:
            profile["auth_library"].append("Apache Shiro")
        if "thymeleaf" in pom_lower:
            profile["template_engine"].append("Thymeleaf")
        if "kafka" in pom_lower:
            profile["message_queue"].append("Kafka")
        if "rabbitmq" in pom_lower:
            profile["message_queue"].append("RabbitMQ")
        profile["build_tool"].append("Maven")

    # Ruby
    if gemfile:
        profile["language"].append("Ruby")
        gem_lower = gemfile.lower()
        if "rails" in gem_lower:
            profile["framework"].append("Rails")
        if "activerecord" in gem_lower:
            profile["orm"].append("ActiveRecord")
        if "devise" in gem_lower:
            profile["auth_library"].append("Devise")

    # PHP
    if composer:
        profile["language"].append("PHP")
        comp_lower = composer.lower()
        if "laravel" in comp_lower:
            profile["framework"].append("Laravel")
        if "symfony" in comp_lower:
            profile["framework"].append("Symfony")
        if "doctrine" in comp_lower:
            profile["orm"].append("Doctrine")

    # Rust
    if cargotoml:
        profile["language"].append("Rust")
        cargo_lower = cargotoml.lower()
        if "actix" in cargo_lower:
            profile["framework"].append("Actix")
        if "axum" in cargo_lower:
            profile["framework"].append("Axum")
        if "rocket" in cargo_lower:
            profile["framework"].append("Rocket")
        if "diesel" in cargo_lower:
            profile["orm"].append("Diesel")
        if "sqlx" in cargo_lower:
            profile["orm"].append("SQLx")

    # Deduplicate
    for key in profile:
        profile[key] = list(dict.fromkeys(profile[key]))

    return profile

def _classify_directory_structure(file_tree: list) -> dict:
    """Classify directory roles and detect project pattern."""
    dir_roles = {}
    all_dir_names = set()

    def _walk_tree(nodes, parent_path=""):
        for node in nodes:
            if node.get("type") != "directory":
                continue
            name_lower = node["name"].lower()
            rel_path = f"{parent_path}/{node['name']}" if parent_path else node["name"]
            all_dir_names.add(name_lower)
            role = _match_dir_role(name_lower)
            if role:
                dir_roles[rel_path] = {"role": role, "name": node["name"]}
            if "children" in node:
                _walk_tree(node["children"], rel_path)

    _walk_tree(file_tree)

    detected_roles = {info["role"] for info in dir_roles.values()}
    pattern = "unknown"
    best_overlap = 0
    for pname, required in _PROJECT_PATTERNS.items():
        overlap = len(detected_roles & required)
        if overlap >= len(required) * 0.5 and overlap > best_overlap:
            best_overlap = overlap
            pattern = pname

    return {"pattern": pattern, "directory_roles": dir_roles, "detected_roles": sorted(detected_roles)}

def _match_dir_role(name_lower: str) -> str | None:
    for role, patterns in _DIR_ROLE_PATTERNS.items():
        if name_lower in patterns:
            return role
    return None

def _build_import_graph(project_dir: str, file_tree: list) -> dict:
    """Build file-level import/dependency graph."""
    files = _flatten_files(file_tree)
    imports = {}   # file_path -> [imported_file_paths]
    file_hub_scores = {}  # file_path -> hub score (how many files import it)
    file_roles = {}  # file_path -> inferred role

    ext_map = {}
    for f in files:
        ext_map.setdefault(f.get("extension", ""), []).append(f)

    py_files = {f["path"].replace("\\", "/") for f in ext_map.get(".py", [])}
    py_modules = {}
    for fp in py_files:
        parts = fp.replace("/", ".").rsplit(".", 1)[0]
        py_modules[parts] = fp
        py_modules[parts.rsplit(".", 1)[-1]] = fp

    js_files = {f["path"].replace("\\", "/") for f in ext_map.get(".js", []) + ext_map.get(".ts", []) + ext_map.get(".jsx", []) + ext_map.get(".tsx", []) + ext_map.get(".mjs", [])}

    for f in files:
        fp = f["path"].replace("\\", "/")
        full_path = os.path.join(project_dir, fp)
        if f.get("size", 0) > MAX_FILE_SIZE:
            continue
        try:
            content = _read_source_text(full_path)
        except Exception:
            continue

        resolved = set()
        ext = f.get("extension", "").lower()

        if ext == ".py":
            for match in _PY_IMPORT_RE.finditer(content):
                mod = match.group(1) or match.group(2)
                if not mod:
                    continue
                mod = mod.split(",")[0].strip().split(" as ")[0].strip()
                if mod.startswith("."):
                    mod = mod.lstrip(".")
                    parent = "/".join(fp.split("/")[:-1])
                    candidate = f"{parent}/{mod}".replace("//", "/")
                    for candidate_fp in [f"{candidate}.py", f"{candidate}/__init__.py"]:
                        if candidate_fp in py_files:
                            resolved.add(candidate_fp)
                elif mod in py_modules:
                    resolved.add(py_modules[mod])
        elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs"}:
            for match in _JS_IMPORT_RE.finditer(content):
                rel = match.group(1) or match.group(2)
                if not rel:
                    continue
                parent = "/".join(fp.split("/")[:-1])
                candidate = _resolve_js_import(parent, rel, js_files)
                if candidate:
                    resolved.add(candidate)
        elif ext == ".go":
            # Go: resolve internal imports via directory matching
            all_go_dirs = set()
            for gf in files:
                gfp = gf.get("path", "").replace("\\", "/")
                if gfp.lower().endswith(".go"):
                    all_go_dirs.add("/".join(gfp.split("/")[:-1]))

            # Detect Go module name from go.mod
            go_module = ""
            gm_content = _read_project_file(project_dir, "go.mod")
            if gm_content:
                for gml in gm_content.split("\n"):
                    gml = gml.strip()
                    if gml.startswith("module "):
                        go_module = gml.split(None, 1)[-1].strip()
                        break

            for match in _GO_IMPORT_RE.finditer(content):
                block = match.group(1) or ""
                pkg_lines = [l.strip().strip('"').strip() for l in block.split("\n")]
                for match2 in _GO_SINGLE_IMPORT_RE.finditer(content):
                    pkg_lines.append(match2.group(1))
                for pkg_line in pkg_lines:
                    if not pkg_line or pkg_line.startswith("//") or pkg_line.startswith("_"):
                        continue
                    # Strip alias: "alias "path"" -> "path"
                    if '"' in pkg_line:
                        pkg_line = pkg_line[pkg_line.index('"') + 1:].rstrip('"').strip()
                    # Strip module prefix for internal packages
                    if go_module and pkg_line.startswith(go_module + "/"):
                        pkg_line = pkg_line[len(go_module) + 1:]
                    elif go_module and pkg_line == go_module:
                        pkg_line = ""
                    if not pkg_line:
                        continue
                    # Match to directory
                    pkg_lower = pkg_line.lower()
                    for go_dir in all_go_dirs:
                        if go_dir.lower() == pkg_lower or go_dir.lower().endswith("/" + pkg_lower):
                            for gf in files:
                                gfp = gf.get("path", "").replace("\\", "/")
                                if gfp.lower().startswith(go_dir.lower() + "/") and gfp.lower().endswith(".go") and gfp != fp:
                                    resolved.add(gfp)
                            break
        elif ext == ".java":
            for match in _JAVA_IMPORT_RE.finditer(content):
                pkg_class = match.group(1)
                if pkg_class:
                    candidate = "/".join(pkg_class.split(".")) + ".java"
                    if candidate in py_files or any(f.endswith(candidate) for f in py_files):
                        resolved.add(candidate)

        if resolved:
            imports[fp] = sorted(resolved)
            for target in resolved:
                file_hub_scores[target] = file_hub_scores.get(target, 0) + 1

    # Infer file roles from content keywords
    for f in files:
        fp = f["path"].replace("\\", "/")
        full_path = os.path.join(project_dir, fp)
        if f.get("size", 0) > MAX_FILE_SIZE:
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(4000).lower()
        except Exception:
            continue

        role = _infer_file_role(fp, head)
        if role:
            file_roles[fp] = role

    top_hubs = sorted(file_hub_scores.items(), key=lambda x: -x[1])[:40]

    return {
        "imports": imports,
        "hub_scores": {fp: score for fp, score in top_hubs},
        "file_roles": file_roles,
    }

def _resolve_js_import(parent: str, rel_path: str, js_files: set) -> str | None:
    """Resolve a JS relative import to a file path."""
    base = f"{parent}/{rel_path}".replace("//", "/")
    for suffix in ["", ".js", ".jsx", ".ts", ".tsx", ".mjs", "/index.js", "/index.ts"]:
        candidate = base + suffix
        if candidate in js_files:
            return candidate
    return None

def _first_match_group(match: re.Match[str] | None) -> str:
    """优先返回第一个捕获组；无捕获组时退回完整匹配文本。"""
    if not match:
        return ""
    if match.lastindex and match.lastindex >= 1:
        return str(match.group(1) or "")
    return str(match.group(0) or "")

def _build_middleware_map(project_dir: str, file_tree: list, code_chunks: list[dict]) -> dict:
    """Extract middleware registrations and auth decorator mappings."""
    files = _flatten_files(file_tree)
    middleware_chain = []
    auth_decorators = {}
    route_auth_map = {}

    for f in files:
        fp = f["path"].replace("\\", "/")
        full_path = os.path.join(project_dir, fp)
        if f.get("size", 0) > MAX_FILE_SIZE:
            continue
        try:
            content = _read_source_text(full_path)
        except Exception:
            continue

        # Detect middleware registrations
        for pattern in _MIDDLEWARE_PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1) or "anonymous"
                middleware_chain.append({"name": name, "file_path": fp})

        # Detect auth decorators
        for pattern in _AUTH_DECORATOR_PATTERNS:
            for match in pattern.finditer(content):
                deco_name = _first_match_group(match).lstrip("@")
                if deco_name not in auth_decorators:
                    auth_decorators[deco_name] = {"file_path": fp, "count": 0}
                auth_decorators[deco_name]["count"] += 1

    # Map auth decorators to routes via route file analysis
    for chunk in code_chunks:
        fp = str(chunk.get("file_path", "")).replace("\\", "/")
        content = str(chunk.get("content", "")[:8000])
        for pattern in _AUTH_DECORATOR_PATTERNS:
            for match in pattern.finditer(content):
                deco_name = _first_match_group(match).lstrip("@")
                # Find nearby route definitions
                route_match = re.search(r'(?:app|router|bp|blueprint|api)\.(get|post|put|delete|patch)\(\s*["\']([^"\']*)["\']', content[match.end():match.end() + 200])
                if not route_match:
                    route_match = re.search(r'@(get|post|put|delete|patch)\(\s*["\']([^"\']*)["\']', content[match.end():match.end() + 200])
                if route_match:
                    method = route_match.group(1).upper()
                    path = route_match.group(2)
                    route_auth_map[f"{method} {path}"] = deco_name

    return {
        "middleware_chain": middleware_chain[:30],
        "auth_decorators": {k: v for k, v in sorted(auth_decorators.items(), key=lambda x: -x[1]["count"])[:20]},
        "route_auth_map": route_auth_map,
    }

def _identify_security_critical_files(
    project_dir: str, file_tree: list, import_graph: dict, tech_profile: dict
) -> dict:
    """Identify files that must be covered for security audit completeness."""
    files = _flatten_files(file_tree)
    critical_files = {}  # file_path -> {"reasons": [...], "priority": int}
    file_roles = import_graph.get("file_roles", {})
    hub_scores = import_graph.get("hub_scores", {})

    for f in files:
        fp = f["path"].replace("\\", "/")
        full_path = os.path.join(project_dir, fp)
        if f.get("size", 0) > MAX_FILE_SIZE:
            continue
        try:
            content = _read_source_text(full_path)
        except Exception:
            continue

        reasons = []

        # Check by file role
        role = file_roles.get(fp, "")
        if role in _MUST_COVER_ROLES:
            reasons.append(f"role:{role}")

        # Check by security patterns
        content_lower = content[:16000].lower()
        for category, patterns in _SECURITY_FILE_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content_lower):
                    reasons.append(f"security:{category}")
                    break

        # Check by hub score (highly imported files)
        hub_score = hub_scores.get(fp, 0)
        if hub_score >= 3:
            reasons.append(f"hub:imported_by_{hub_score}")

        # Check for config files
        basename = os.path.basename(fp).lower()
        if basename in {
            "main.py", "app.py", "server.js", "index.js", "manage.py",
            "settings.py", "config.py", "config.yaml", "config.json",
            "application.yml", "application.properties", ".env",
            "package.json", "requirements.txt", "go.mod", "pom.xml",
        }:
            reasons.append("entry:config_or_entry")

        if reasons:
            priority = len(reasons) + (5 if any("auth" in r for r in reasons) else 0)
            critical_files[fp] = {"reasons": reasons, "priority": priority}

    # Sort by priority descending
    sorted_files = sorted(critical_files.items(), key=lambda x: (-x[1]["priority"], x[0]))
    return {
        "must_cover_files": [fp for fp, _ in sorted_files],
        "file_details": {fp: info for fp, info in sorted_files},
        "total_critical_count": len(sorted_files),
    }

def run_pre_discovery(project_dir: str, file_tree: list, code_chunks: list[dict], static_routes: list[dict]) -> dict:
    """Run all static pre-discovery analyses and return combined result."""
    tech_profile = _build_tech_stack_profile(project_dir, file_tree)
    dir_structure = _classify_directory_structure(file_tree)
    import_graph = _build_import_graph(project_dir, file_tree)
    middleware_map = _build_middleware_map(project_dir, file_tree, code_chunks)
    security_files = _identify_security_critical_files(project_dir, file_tree, import_graph, tech_profile)

    return {
        "tech_profile": tech_profile,
        "dir_structure": dir_structure,
        "import_graph": import_graph,
        "middleware_map": middleware_map,
        "security_files": security_files,
    }

def _detect_tech_stack(project_dir: str, file_tree: list) -> str:
    """Detect tech stack from project files."""
    detected = []
    flat_files = _flatten_files(file_tree)
    filenames = {f["name"] for f in flat_files}

    package_json = _read_project_file(project_dir, "package.json")
    requirements_txt = _read_project_file(project_dir, "requirements.txt")
    pyproject_toml = _read_project_file(project_dir, "pyproject.toml")
    pom_xml = _read_project_file(project_dir, "pom.xml")
    go_mod = _read_project_file(project_dir, "go.mod")

    if package_json:
        package_lower = package_json.lower()
        if "koa" in package_lower:
            detected.append("Node.js/Koa")
        if "express" in package_lower:
            detected.append("Node.js/Express")
        if "\"react\"" in package_lower:
            detected.append("React")
        if "\"vue\"" in package_lower:
            detected.append("Vue")

    python_manifest = "\n".join([requirements_txt, pyproject_toml]).lower()
    if "manage.py" in filenames or "django" in python_manifest:
        detected.append("Python/Django")
    if "flask" in python_manifest:
        detected.append("Python/Flask")
    if "fastapi" in python_manifest:
        detected.append("Python/FastAPI")
    if pom_xml:
        detected.append("Java/Spring")
    if go_mod:
        detected.append("Go")

    detected = list(dict.fromkeys(detected))

    if not detected:
        # Fallback: check by extension distribution
        ext_counts = {}
        for f in flat_files:
            ext = f.get("extension", "")
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

        if ext_counts.get(".py", 0) > 3:
            detected.append("Python")
        elif ext_counts.get(".js", 0) > 3 or ext_counts.get(".ts", 0) > 3:
            detected.append("Node.js")
        elif ext_counts.get(".java", 0) > 3:
            detected.append("Java")
        elif ext_counts.get(".go", 0) > 3:
            detected.append("Go")

    return ", ".join(detected) if detected else "Unknown"

__all__ = [
    '_DIR_ROLE_PATTERNS',
    '_PROJECT_PATTERNS',
    '_PY_IMPORT_RE',
    '_JS_IMPORT_RE',
    '_GO_IMPORT_RE',
    '_GO_SINGLE_IMPORT_RE',
    '_JAVA_IMPORT_RE',
    '_AUTH_DECORATOR_PATTERNS',
    '_MIDDLEWARE_PATTERNS',
    '_SECURITY_FILE_PATTERNS',
    '_MUST_COVER_ROLES',
    '_build_tech_stack_profile',
    '_classify_directory_structure',
    '_match_dir_role',
    '_build_import_graph',
    '_resolve_js_import',
    '_first_match_group',
    '_build_middleware_map',
    '_identify_security_critical_files',
    'run_pre_discovery',
    '_detect_tech_stack',
]
