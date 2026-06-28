"""Route extraction orchestration: content dispatch + project-level route assembly."""

from __future__ import annotations

import os
import re
from services.config import (
    MAX_FILE_SIZE
)

from services.code_parser_pkg._utils import *  # noqa: F401,F403
from services.code_parser_pkg._text import *  # noqa: F401,F403
from services.code_parser_pkg.files import *  # noqa: F401,F403
from services.code_parser_pkg.routes_extract import *  # noqa: F401,F403
from services.code_parser_pkg.routes_resolve import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

def extract_project_routes(project_dir: str, file_tree: list, include_stats: bool = False) -> list[dict] | tuple[list[dict], dict]:
    """Best-effort static route extraction for common web frameworks."""
    files = _flatten_files(file_tree)
    routes = []
    seen = set()
    stats = {"files_scanned": 0}
    file_contents: dict[str, str] = {}
    existing_py_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith(".py")
    }
    gin_prefixes = _build_gin_api_prefixes(project_dir, files)
    fastapi_prefixes = _build_fastapi_router_prefixes(project_dir, files)
    django_prefixes = _build_django_include_prefixes(project_dir, files)
    flask_prefixes = _build_flask_blueprint_prefixes(project_dir, files)
    js_router_prefixes = _build_js_router_prefixes(project_dir, files)
    nestjs_prefixes = _build_nestjs_module_prefixes(project_dir, files)

    for file_node in files:
        rel_path = file_node["path"]
        full_path = os.path.join(project_dir, rel_path)
        if file_node.get("size", 0) > MAX_FILE_SIZE:
            continue
        stats["files_scanned"] += 1

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue
        file_contents[rel_path] = content

        file_routes = _extract_routes_from_content(
            rel_path,
            content,
            prefix_override=(
                _resolve_prefix_for_path(rel_path, fastapi_prefixes)
                or _resolve_prefix_for_path(rel_path, django_prefixes)
                or _resolve_prefix_for_path(rel_path, flask_prefixes)
                or _resolve_prefix_for_path(rel_path, nestjs_prefixes)
                or js_router_prefixes.get(rel_path, "")
                or gin_prefixes.get(rel_path, "")
            ),
        )
        for route in file_routes:
            if rel_path.lower().endswith(".py"):
                route = _enrich_python_route_metadata(
                    route,
                    current_path=rel_path,
                    current_content=content,
                    file_contents=file_contents,
                    existing_paths=existing_py_paths,
                )
            key = (
                route.get("method", "UNKNOWN"),
                route.get("path", ""),
                route.get("handler", ""),
                route.get("file_path", rel_path),
            )
            if key in seen:
                continue
            seen.add(key)
            routes.append(route)

    if include_stats:
        return routes, stats
    return routes

def _extract_routes_from_content(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    effective_prefix = prefix_override
    fastapi_local_prefix = _extract_fastapi_local_prefix(content)
    flask_local_prefix = _extract_flask_local_prefix(content)
    if fastapi_local_prefix:
        effective_prefix = _join_route_paths(effective_prefix, fastapi_local_prefix)
    elif flask_local_prefix:
        effective_prefix = _join_route_paths(effective_prefix, flask_local_prefix)

    if file_path.lower().endswith(".go") or "gin." in content:
        routes.extend(_extract_gin_routes(file_path, content, prefix_override=prefix_override))
    if _looks_like_js_router_file(file_path, content):
        routes.extend(_extract_js_router_routes(file_path, content, prefix_override=prefix_override))
    if file_path.lower().endswith(".py") and ("Blueprint(" in content or ".route(" in content or "add_url_rule(" in content):
        routes.extend(_extract_flask_routes(file_path, content, prefix_override=effective_prefix))
    if file_path.lower().endswith((".ts", ".tsx", ".js")) and "@Controller" in content:
        routes.extend(_extract_nestjs_routes(file_path, content, prefix_override=prefix_override))
    if file_path.lower().endswith((".ts", ".tsx", ".js")) and "forRoutes(" in content:
        routes.extend(_extract_nestjs_forroutes_bindings(file_path, content, prefix_override=prefix_override))
    if file_path.lower().endswith(".java") or "@RequestMapping" in content or "@GetMapping" in content:
        routes.extend(_extract_spring_routes(file_path, content, prefix_override=prefix_override))

    # --- Additional framework patterns ---

    # JAX-RS (Java): @Path, @GET, @POST etc. on methods
    if file_path.lower().endswith(".java"):
        routes.extend(_extract_jaxrs_routes(file_path, content, prefix_override=prefix_override))

    # .NET/C#: [HttpGet], [Route], [ApiController] patterns
    if file_path.lower().endswith(".cs"):
        routes.extend(_extract_dotnet_routes(file_path, content, prefix_override=prefix_override))

    # Go: net/http, chi, echo, fiber, mux patterns
    if file_path.lower().endswith(".go"):
        routes.extend(_extract_go_stdlib_routes(file_path, content, prefix_override=prefix_override))

    # Ruby on Rails: routes.rb get/post/resources
    if file_path.lower().endswith(".rb") and "route" in content.lower():
        routes.extend(_extract_rails_routes(file_path, content, prefix_override=prefix_override))

    # Rust: actix_web #[route], rocket #[get], axum .route()
    if file_path.lower().endswith(".rs"):
        routes.extend(_extract_rust_routes(file_path, content, prefix_override=prefix_override))

    # PHP: Laravel Route::*, Symfony @Route annotation
    if file_path.lower().endswith(".php"):
        routes.extend(_extract_php_routes(file_path, content, prefix_override=prefix_override))

    # Python: FastAPI WebSocket, Tornado, aiohttp
    if file_path.lower().endswith(".py"):
        routes.extend(_extract_python_async_routes(file_path, content, prefix_override=effective_prefix))

    # DRF @action decorator on ViewSets
    if file_path.lower().endswith(".py") and "@action(" in content:
        routes.extend(_extract_drf_action_routes(file_path, content, prefix_override=effective_prefix))

    patterns = [
        (
            re.compile(
                r'@(?:\w+\.)?(get|post|put|delete|patch|options|head|route|websocket|ws)\(\s*["\']([^"\']*)["\']',
                re.I,
            ),
            "python_decorator",
        ),
        (
            re.compile(
                r'\b(?:app|router|bp|blueprint|api|server|service|app\.\w+)\.(get|post|put|delete|patch|options|head|all|use)\(\s*["\']([^"\']*)["\']',
                re.I,
            ),
            "js_style",
        ),
        (
            re.compile(
                r'path\(\s*["\']([^"\']*)["\']\s*,\s*([A-Za-z_][\w\.]*)',
                re.I,
            ),
            "django_path",
        ),
        (
            re.compile(
                r're_path\(\s*r?["\']([^"\']*)["\']\s*,\s*([A-Za-z_][\w\.]*)',
                re.I,
            ),
            "django_re_path",
        ),
        (
            re.compile(
                r'url\(\s*r?["\']([^"\']*)["\']\s*,\s*([A-Za-z_][\w\.]*)',
                re.I,
            ),
            "django_url",
        ),
        (
            re.compile(
                r'Route::(get|post|put|delete|patch|options|any)\(\s*["\']([^"\']+)["\']',
                re.I,
            ),
            "laravel",
        ),
    ]

    for pattern, kind in patterns:
        for match in pattern.finditer(content):
            if _is_comment_or_docstring_match(content, match.start()):
                continue
            if kind in {"python_decorator", "js_style", "laravel"}:
                method = match.group(1).upper()
                path = match.group(2)
                handler = _guess_handler_nearby(content, match.start())
            else:
                method = "ANY"
                path = match.group(1)
                handler = match.group(2)

            routes.append(
                {
                    "method": "ANY" if method == "ROUTE" else method,
                    "path": _join_route_paths(effective_prefix, path),
                    "handler": _normalize_handler_name(handler or "Unknown"),
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _merge_params(
                        _extract_route_params(path),
                        _extract_python_handler_params(content, _normalize_handler_name(handler or "Unknown")),
                    ),
                    "line_start": _line_number_from_offset(content, match.start()),
                    "source_kind": kind,
                    "notes": "Static route extraction",
                }
            )

    return routes

__all__ = [
    'extract_project_routes',
    '_extract_routes_from_content',
]
