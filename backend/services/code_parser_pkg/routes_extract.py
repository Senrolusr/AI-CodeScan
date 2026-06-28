"""Per-language route extractors (Flask/FastAPI/Spring/Gin/Django/NestJS/PHP/Rails/Rust/.NET/JAX-RS/JS)."""

from __future__ import annotations

import os
import re

from services.code_parser_pkg._utils import *  # noqa: F401,F403
from services.code_parser_pkg._text import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

def _extract_jaxrs_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract JAX-RS routes: class-level @Path + method-level @GET/@POST etc."""
    routes = []
    class_path = ""
    class_path_match = re.search(r'@Path\(\s*["\']([^"\']*)["\']', content)
    if class_path_match:
        class_path = class_path_match.group(1)

    method_map = {
        "@GET": "GET", "@POST": "POST", "@PUT": "PUT", "@DELETE": "DELETE",
        "@PATCH": "PATCH", "@HEAD": "HEAD", "@OPTIONS": "OPTIONS",
    }
    method_path_pattern = re.compile(
        r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\n\s*(?:@Path\(\s*["\']([^"\']*)["\']\s*\)\s*\n\s*)?(?:public|private|protected)\s+\S+\s+(\w+)\s*\(',
        re.I,
    )
    for match in method_path_pattern.finditer(content):
        annotation, sub_path, handler = match.group(1).upper(), match.group(2) or "", match.group(3)
        method = method_map.get(f"@{annotation}", "ANY")
        full_path = _join_route_paths(prefix_override, _join_route_paths(class_path, sub_path))
        routes.append({
            "method": method, "path": full_path, "handler": handler,
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (JAX-RS)",
        })
    return routes

def _extract_dotnet_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract ASP.NET Core routes: [Route], [HttpGet], [HttpPost] etc."""
    routes = []
    class_route = ""
    class_route_match = re.search(r'\[Route\(\s*@"?([^"\]\s]+)"?\s*\)\]', content)
    if not class_route_match:
        class_route_match = re.search(r'\[Route\(\s*["\']([^"\']+)["\']\s*\)\]', content)
    if class_route_match:
        class_route = class_route_match.group(1).replace("[controller]", "").replace("[action]", "")

    http_methods = ["HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch"]
    for method_attr in http_methods:
        pattern = re.compile(
            rf'\[{method_attr}(?:\(\s*(?:@"?([^"\]\s]+)"?|["\']([^"\']+)["\'])\s*\))?\]\s*(?:\[.*?\]\s*)*(?:public|private|protected)\s+\S+\s+(\w+)\s*\(',
            re.I,
        )
        for match in pattern.finditer(content):
            path = match.group(1) or match.group(2) or ""
            handler = match.group(3)
            method = method_attr.replace("Http", "").upper()
            full_path = _join_route_paths(prefix_override, _join_route_paths(class_route, path))
            routes.append({
                "method": method, "path": full_path, "handler": handler,
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (.NET)",
            })

    # [ApiController] + [Route("api/[controller]")] without method-level paths
    if "[ApiController]" in content and routes:
        pass  # already covered above
    return routes

def _extract_go_stdlib_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract Go stdlib net/http, chi, echo, fiber, gorilla/mux routes."""
    routes = []

    # chi r.Get / r.Post etc.
    chi_pattern = re.compile(r'(\w+)\.(Get|Post|Put|Delete|Patch|Head|Options|Connect|Trace|Handle|HandleFunc)\(\s*"([^"]+)"\s*,\s*(\w+(?:\.\w+)?)', re.I)
    chi_vars = set()
    for match in chi_pattern.finditer(content):
        var_name, method, path, handler = match.groups()
        chi_vars.add(var_name)
        http_method = method.upper() if method.lower() not in ("handle", "handlefunc") else "ANY"
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": http_method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Go chi)",
        })

    # echo e.GET / e.POST etc.
    echo_pattern = re.compile(r'(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*"([^"]+)"\s*,\s*(\w+(?:\.\w+)?)', re.I)
    for match in echo_pattern.finditer(content):
        _, method, path, handler = match.groups()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method.upper(), "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Go echo)",
        })

    # fiber app.Get / app.Post etc.
    fiber_pattern = re.compile(r'(\w+)\.(Get|Post|Put|Delete|Patch|Head|Options|All|Use)\(\s*"([^"]+)"\s*,\s*(\w+(?:\.\w+)?)', re.I)
    for match in fiber_pattern.finditer(content):
        _, method, path, handler = match.groups()
        if "Use" in method:
            continue
        http_method = "ANY" if method.lower() == "all" else method.upper()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": http_method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Go fiber)",
        })

    # stdlib http.HandleFunc / http.Handle
    stdlib_pattern = re.compile(r'http\.HandleFunc\(\s*"([^"]+)"\s*,\s*(\w+(?:\.\w+)?)', re.I)
    for match in stdlib_pattern.finditer(content):
        path, handler = match.groups()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": "ANY", "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Go net/http)",
        })

    return routes

def _extract_rails_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract Ruby on Rails routes from routes.rb."""
    routes = []
    # Rails: get '/path', to: 'controller#action'
    rails_pattern = re.compile(
        r"(?:get|post|put|delete|patch)\s+['\"]([^'\"]+)['\"]",
        re.I,
    )
    for match in rails_pattern.finditer(content):
        path = match.group(1)
        method = content[match.start():match.start() + content[match.start():].find("'")].strip().split()[0].upper() if match.start() < len(content) else "ANY"
        method = content[match.start():].split("'")[0].split()[-1].upper() if content[match.start():].split("'") else "GET"
        # Simpler: just extract method from the match
        raw = content[match.start():match.start() + 10].lower()
        if raw.startswith("post"):
            method = "POST"
        elif raw.startswith("put"):
            method = "PUT"
        elif raw.startswith("delete"):
            method = "DELETE"
        elif raw.startswith("patch"):
            method = "PATCH"
        else:
            method = "GET"
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": "Unknown",
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Rails)",
        })

    # Rails: resources :controller
    resources_pattern = re.compile(r"resources\s+:(['\"]?)(\w+)\1", re.I)
    for match in resources_pattern.finditer(content):
        resource = match.group(2)
        base = f"/{resource}"
        for m, p in [("GET", base), ("GET", f"{base}/:id"), ("POST", base), ("PATCH", f"{base}/:id"), ("DELETE", f"{base}/:id")]:
            full_path = _join_route_paths(prefix_override, p)
            routes.append({
                "method": m, "path": full_path, "handler": f"{resource}Controller",
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (Rails resources)",
            })
    return routes

def _extract_rust_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract Rust actix_web / rocket / axum routes."""
    routes = []

    # actix_web: #[route(method, path)] or #[get("/path")]
    actix_pattern = re.compile(r'#\[(\w+)\(\s*"([^"]+)"\s*\)', re.I)
    actix_methods = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH", "head": "HEAD", "options": "OPTIONS", "route": "ANY"}
    for match in actix_pattern.finditer(content):
        attr, path = match.group(1).lower(), match.group(2)
        method = actix_methods.get(attr)
        if not method:
            continue
        handler = _guess_handler_nearby(content, match.end()) or "Unknown"
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Rust)",
        })

    # axum: .route("/path", get(handler)) / .route("/path", post(handler))
    axum_pattern = re.compile(r'\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|delete|patch|head|options|any|any_method)\((\w+(?:::\w+)?)\)', re.I)
    for match in axum_pattern.finditer(content):
        path, method_str, handler = match.groups()
        method = method_str.upper() if method_str.lower() != "any" and method_str.lower() != "any_method" else "ANY"
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Rust axum)",
        })
    return routes

def _extract_php_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract PHP Laravel, Symfony and common dynamic-controller routes."""
    routes = []

    # Laravel: Route::get/post/put/delete/patch/any('/path', ...)
    laravel_pattern = re.compile(
        r"Route::(get|post|put|delete|patch|any|options|match)\(\s*['\"]([^'\"]+)['\"]",
        re.I,
    )
    for match in laravel_pattern.finditer(content):
        method_str, path = match.group(1).lower(), match.group(2)
        method = "ANY" if method_str in ("any", "match") else method_str.upper()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": "Unknown",
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Laravel)",
        })

    # Laravel: Route::resource('name', Controller)
    resource_pattern = re.compile(r"Route::resource\(\s*'([^']+)'", re.I)
    for match in resource_pattern.finditer(content):
        resource = match.group(1)
        base = f"/{resource}"
        for m, p in [("GET", base), ("GET", f"{base}/{{id}}"), ("POST", base), ("PUT", f"{base}/{{id}}"), ("PATCH", f"{base}/{{id}}"), ("DELETE", f"{base}/{{id}}")]:
            full_path = _join_route_paths(prefix_override, p)
            routes.append({
                "method": m, "path": full_path, "handler": "Unknown",
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (Laravel resource)",
            })

    # Symfony: #[Route('/path', methods: ['GET'])] or @Route("/path")
    symfony_pattern = re.compile(
        r"(?:#\[Route|@Route)\(\s*['\"]([^'\"]+)['\"].*?(?:methods:\s*\[([^\]]+)\]|methods\s*=\s*\{([^}]+)\})?",
        re.I,
    )
    for match in symfony_pattern.finditer(content):
        path = match.group(1)
        methods_str = match.group(2) or match.group(3) or ""
        methods = re.findall(r"'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)'", methods_str, re.I)
        if not methods:
            methods = ["ANY"]
        for method in methods:
            full_path = _join_route_paths(prefix_override, path)
            routes.append({
                "method": method.upper(), "path": full_path, "handler": "Unknown",
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (Symfony)",
            })

    # 兼容 Ginkgo/PHPEMS 一类的动态控制器分发模式，补出阶段一需要的路由骨架。
    routes.extend(_extract_php_dynamic_controller_routes(file_path, content))

    # 兼容 api/*.php 这类独立入口脚本，避免支付回调、Webhook 等入口被漏掉。
    routes.extend(_extract_php_entry_script_routes(file_path, content))
    return routes

def _extract_php_dynamic_controller_routes(file_path: str, content: str) -> list[dict]:
    """Extract best-effort routes for PHP dynamic controller dispatchers."""
    normalized_path = file_path.replace("\\", "/")
    controller_match = re.search(
        r"(?:^|/)app/([^/]+)/controller/([^/.]+)\.([^.\/]+)\.php$",
        normalized_path,
        re.I,
    )
    if not controller_match:
        return []

    module_name, controller_name, surface_name = controller_match.groups()
    has_dynamic_dispatch = (
        re.search(r"\$action\s*=\s*\$this->\w+->url\s*\(\s*3\s*\)", content)
        and re.search(r"method_exists\s*\(\s*\$this\s*,\s*\$action\s*\)", content)
        and re.search(r"\$this->\s*\$action\s*\(", content)
    )
    if not has_dynamic_dispatch:
        return []

    actions = []
    seen_actions = set()
    for action_match in re.finditer(r"(?:public|protected|private)\s+function\s+([A-Za-z_]\w*)\s*\(", content):
        action_name = action_match.group(1)
        normalized_action = action_name.lower()
        if normalized_action == "display" or normalized_action.startswith("__"):
            continue
        if normalized_action in seen_actions:
            continue
        seen_actions.add(normalized_action)
        actions.append(action_name)

    if not actions:
        return []

    route_key = f"{module_name}-{surface_name}-{controller_name}"
    routes = []

    default_action = "index" if any(action.lower() == "index" for action in actions) else actions[0]
    default_path = _normalize_route_path(f"/index.php?{route_key}")
    routes.append(
        {
            "method": "ANY",
            "path": default_path,
            "handler": f"{module_name}/{controller_name}.{surface_name}::{default_action}",
            "file_path": file_path,
            "auth": _guess_auth_type(content),
            "params": _extract_route_params(default_path),
            "notes": "Static route extraction (PHP dynamic controller)",
        }
    )

    for action_name in actions:
        if action_name.lower() == "index":
            continue
        action_path = _normalize_route_path(f"/index.php?{route_key}-{action_name}")
        routes.append(
            {
                "method": "ANY",
                "path": action_path,
                "handler": f"{module_name}/{controller_name}.{surface_name}::{action_name}",
                "file_path": file_path,
                "auth": _guess_auth_type(content),
                "params": _extract_route_params(action_path),
                "notes": "Static route extraction (PHP dynamic controller)",
            }
        )
    return routes

def _extract_php_entry_script_routes(file_path: str, content: str) -> list[dict]:
    """Extract best-effort routes for standalone PHP entry scripts."""
    normalized_path = file_path.replace("\\", "/")
    if not re.match(r"^api/[^/]+\.php$", normalized_path, re.I):
        return []
    if "class app" not in content or "$app->run()" not in content:
        return []

    route_path = _normalize_route_path(f"/{normalized_path}")
    handler_name = f"{os.path.splitext(os.path.basename(normalized_path))[0]}::run"
    return [
        {
            "method": "ANY",
            "path": route_path,
            "handler": handler_name,
            "file_path": file_path,
            "auth": _guess_auth_type(content),
            "params": _extract_route_params(route_path),
            "notes": "Static route extraction (PHP entry script)",
        }
    ]

def _extract_python_async_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract FastAPI WebSocket, Tornado, aiohttp routes."""
    routes = []

    # FastAPI: @app.websocket("/path") or @router.websocket("/path")
    ws_pattern = re.compile(r'@(\w+)\.websocket\(\s*["\']([^"\']+)["\']', re.I)
    for match in ws_pattern.finditer(content):
        path = match.group(2)
        full_path = _join_route_paths(prefix_override, path)
        handler = _guess_handler_nearby(content, match.end()) or "Unknown"
        routes.append({
            "method": "WS", "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": [], "notes": "Static route extraction (WebSocket)",
        })

    # FastAPI: @app.api_route("/path", methods=[...])
    api_route_pattern = re.compile(r'@(\w+)\.api_route\(\s*["\']([^"\']+)["\'][^)]*methods\s*=\s*\[([^\]]+)\]', re.I)
    for match in api_route_pattern.finditer(content):
        _, path, methods_str = match.groups()
        methods = re.findall(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"', methods_str, re.I)
        handler = _guess_handler_nearby(content, match.end()) or "Unknown"
        for method in methods:
            full_path = _join_route_paths(prefix_override, path)
            routes.append({
                "method": method.upper(), "path": full_path, "handler": _normalize_handler_name(handler),
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (FastAPI api_route)",
            })

    # Tornado: (r"/path", Handler)
    tornado_pattern = re.compile(r'\(r?["\']([^"\']+)["\']\s*,\s*([A-Za-z_]\w*)\s*\)')
    for match in tornado_pattern.finditer(content):
        path, handler = match.group(1), match.group(2)
        if not path.startswith("/"):
            continue
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": "ANY", "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (Tornado)",
        })

    # aiohttp: web.get("/path", handler) / web.post("/path", handler)
    aiohttp_pattern = re.compile(r'web\.(get|post|put|delete|patch|head|options|route)\(\s*["\']([^"\']+)["\']\s*,\s*(\w+)', re.I)
    for match in aiohttp_pattern.finditer(content):
        method_str, path, handler = match.groups()
        method = "ANY" if method_str.lower() == "route" else method_str.upper()
        full_path = _join_route_paths(prefix_override, path)
        routes.append({
            "method": method, "path": full_path, "handler": _normalize_handler_name(handler),
            "file_path": file_path, "auth": _guess_auth_type(content),
            "params": _extract_route_params(full_path), "notes": "Static route extraction (aiohttp)",
        })
    return routes

def _extract_drf_action_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    """Extract Django REST Framework @action decorated routes on ViewSets."""
    routes = []
    action_pattern = re.compile(
        r'@action\(([^)]*)\)',
        re.I,
    )
    for match in action_pattern.finditer(content):
        args = match.group(1)
        detail_match = re.search(r'detail\s*=\s*(True|False)', args, re.I)
        is_detail = detail_match and detail_match.group(1).lower() == "true" if detail_match else False
        url_path_match = re.search(r'url_path\s*=\s*["\']([^"\']+)["\']', args, re.I)
        url_path = url_path_match.group(1) if url_path_match else ""
        methods_match = re.findall(r'"(get|post|put|delete|patch|head|options)"', args, re.I)
        methods = [m.upper() for m in methods_match] if methods_match else ["ANY"]
        handler = _guess_handler_nearby(content, match.end()) or "Unknown"
        # detail actions use /{pk}/suffix, list actions use /suffix
        path = f"/{{pk}}/{url_path}" if is_detail and url_path else f"/{url_path}" if url_path else "/{pk}" if is_detail else "/"
        for method in methods:
            full_path = _join_route_paths(prefix_override, path)
            routes.append({
                "method": method, "path": full_path, "handler": _normalize_handler_name(handler),
                "file_path": file_path, "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path), "notes": "Static route extraction (DRF @action)",
            })
    return routes

def _looks_like_js_router_file(file_path: str, content: str) -> bool:
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return False
    lowered = content.lower()
    return (
        "express.router(" in lowered
        or "router =" in lowered
        or ".router()" in lowered
        or "router.get(" in lowered
        or "router.post(" in lowered
        or "app.use(" in lowered
        or "router.use(" in lowered
    )

def _extract_js_router_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    lowered = content.lower()
    router_vars = {"app", "router", "api"}

    router_decl_patterns = [
        re.compile(r'(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*express\.router\(\s*\)', re.I),
        re.compile(r'(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*\w+\.router\(\s*\)', re.I),
        re.compile(r'(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*router\(\s*\)', re.I),
    ]
    for pattern in router_decl_patterns:
        for var_name in pattern.findall(content):
            router_vars.add(var_name)

    var_pattern = "|".join(sorted({re.escape(name) for name in router_vars}, key=len, reverse=True))
    route_pattern = re.compile(
        rf'\b({var_pattern})\.(get|post|put|delete|patch|options|head|all)\(\s*["\']([^"\']*)["\']',
        re.I,
    )

    for match in route_pattern.finditer(content):
        _, method, path = match.groups()
        routes.append(
            {
                "method": method.upper(),
                "path": _join_route_paths(prefix_override, path),
                "handler": _normalize_handler_name(_guess_handler_nearby(content, match.start()) or "Unknown"),
                "file_path": file_path,
                "auth": _guess_auth_type(content),
                "params": _extract_route_params(path),
                "notes": "Static route extraction (JS router)",
            }
        )

    return routes

def _extract_spring_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    class_base_path = ""

    class_mapping_match = re.search(
        r'@(?:RequestMapping|Controller)\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\']',
        content,
        re.I,
    )
    if class_mapping_match:
        class_base_path = class_mapping_match.group(1)

    mapping_pattern = re.compile(
        r'@(?P<annotation>GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\((?P<args>[\s\S]{0,240}?)\)\s*(?:public|private|protected)\s+[^\(\n]+\s+(?P<handler>[A-Za-z_]\w*)\s*\(',
        re.I,
    )

    for match in mapping_pattern.finditer(content):
        annotation = match.group("annotation").lower()
        args = match.group("args") or ""
        handler = match.group("handler")
        method = "ANY"
        if "getmapping" in annotation:
            method = "GET"
        elif "postmapping" in annotation:
            method = "POST"
        elif "putmapping" in annotation:
            method = "PUT"
        elif "deletemapping" in annotation:
            method = "DELETE"
        elif "patchmapping" in annotation:
            method = "PATCH"
        else:
            method_match = re.search(r'RequestMethod\.(GET|POST|PUT|DELETE|PATCH)', args, re.I)
            if method_match:
                method = method_match.group(1).upper()

        path_match = re.search(r'(?:value|path)\s*=\s*["\']([^"\']*)["\']', args, re.I) or re.search(
            r'["\']([^"\']*)["\']',
            args,
            re.I,
        )
        method_path = path_match.group(1) if path_match else ""
        full_path = _join_route_paths(prefix_override, _join_route_paths(class_base_path, method_path))
        routes.append(
            {
                "method": method,
                "path": full_path,
                "handler": handler,
                "file_path": file_path,
                "auth": _guess_auth_type(content),
                "params": _extract_route_params(full_path),
                "notes": "Static route extraction (Spring)",
            }
        )

    return routes

def _extract_nestjs_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    controller_pattern = re.compile(
        r'@Controller\(\s*(?P<args>[\s\S]{0,200}?)\)\s*(?:export\s+)?class\s+(?P<class_name>[A-Za-z_]\w*)',
        re.I,
    )
    method_pattern = re.compile(
        r'@(?P<method>Get|Post|Put|Delete|Patch|Options|Head|All)\(\s*(?P<args>[\s\S]{0,200}?)\)\s*'
        r'(?:public\s+|private\s+|protected\s+|async\s+|static\s+)*'
        r'(?P<handler>[A-Za-z_]\w*)\s*\(',
        re.I,
    )

    for controller_match in controller_pattern.finditer(content):
        controller_args = controller_match.group("args") or ""
        controller_path = _extract_nestjs_path_from_args(controller_args)
        class_start = controller_match.end()
        next_controller = controller_pattern.search(content, class_start)
        class_block = content[class_start: next_controller.start() if next_controller else len(content)]

        for method_match in method_pattern.finditer(class_block):
            method = method_match.group("method").upper()
            handler = method_match.group("handler") or "Unknown"
            method_path = _extract_nestjs_path_from_args(method_match.group("args") or "")
            full_path = _join_route_paths(prefix_override, _join_route_paths(controller_path, method_path))
            routes.append(
                {
                    "method": "ANY" if method == "ALL" else method,
                    "path": full_path,
                    "handler": handler,
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _extract_route_params(full_path),
                    "notes": "Static route extraction (NestJS)",
                }
            )

    return routes

def _extract_nestjs_path_from_args(args: str) -> str:
    if not args:
        return ""
    string_match = re.search(r'["\']([^"\']*)["\']', args)
    if string_match:
        return string_match.group(1)
    path_match = re.search(r'\bpath\s*:\s*["\']([^"\']*)["\']', args, re.I)
    if path_match:
        return path_match.group(1)
    return ""

def _extract_fastapi_local_prefix(content: str) -> str:
    match = re.search(r'APIRouter\((?P<args>[\s\S]{0,240}?)\)', content, re.I)
    if not match:
        return ""
    args = match.group("args") or ""
    prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']*)["\']', args, re.I)
    return _normalize_route_path(prefix_match.group(1) or "") if prefix_match else ""

def _extract_flask_local_prefix(content: str) -> str:
    match = re.search(r'Blueprint\((?P<args>[\s\S]{0,240}?)\)', content, re.I)
    if not match:
        return ""
    args = match.group("args") or ""
    prefix_match = re.search(r'url_prefix\s*=\s*["\']([^"\']*)["\']', args, re.I)
    return _normalize_route_path(prefix_match.group(1) or "") if prefix_match else ""

def _extract_flask_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    blueprint_vars = {"app", "bp", "blueprint"}
    blueprint_decl_pattern = re.compile(
        r'(?:const\s+)?([A-Za-z_]\w*)\s*=\s*Blueprint\(',
        re.I,
    )
    for var_name in blueprint_decl_pattern.findall(content):
        blueprint_vars.add(var_name)

    var_pattern = "|".join(sorted({re.escape(name) for name in blueprint_vars}, key=len, reverse=True))
    if not var_pattern:
        return routes

    decorator_pattern = re.compile(
        rf'@(?P<target>{var_pattern})\.(?:route|get|post|put|delete|patch)\(\s*["\'](?P<path>[^"\']*)["\'](?P<args>[\s\S]{{0,240}}?)\)',
        re.I,
    )
    for match in decorator_pattern.finditer(content):
        args = match.group("args") or ""
        method = "ANY"
        explicit_methods = re.findall(r'["\'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)["\']', args, re.I)
        if explicit_methods:
            methods = [item.upper() for item in explicit_methods]
        else:
            methods = [method]
        handler = _guess_handler_nearby(content, match.start())
        for current_method in methods:
            routes.append(
                {
                    "method": current_method,
                    "path": _join_route_paths(prefix_override, match.group("path")),
                    "handler": _normalize_handler_name(handler or "Unknown"),
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _merge_params(
                        _extract_route_params(match.group("path")),
                        _extract_python_handler_params(content, _normalize_handler_name(handler or "Unknown")),
                    ),
                    "line_start": _line_number_from_offset(content, match.start()),
                    "source_kind": "flask_decorator",
                    "notes": "Static route extraction (Flask)",
                }
            )

    add_rule_pattern = re.compile(
        rf'\b(?P<target>{var_pattern})\.add_url_rule\(\s*["\'](?P<path>[^"\']*)["\'](?P<args>[\s\S]{{0,260}}?)\)',
        re.I,
    )
    for match in add_rule_pattern.finditer(content):
        args = match.group("args") or ""
        handler_match = re.search(r'view_func\s*=\s*([A-Za-z_][\w\.]*)', args, re.I)
        explicit_methods = re.findall(r'["\'](GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)["\']', args, re.I)
        methods = [item.upper() for item in explicit_methods] if explicit_methods else ["ANY"]
        for current_method in methods:
            routes.append(
                {
                    "method": current_method,
                    "path": _join_route_paths(prefix_override, match.group("path")),
                    "handler": _normalize_handler_name(handler_match.group(1) if handler_match else "Unknown"),
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _merge_params(
                        _extract_route_params(match.group("path")),
                        _extract_python_handler_params(content, _normalize_handler_name(handler_match.group(1) if handler_match else "Unknown")),
                    ),
                    "line_start": _line_number_from_offset(content, match.start()),
                    "source_kind": "flask_add_url_rule",
                    "notes": "Static route extraction (Flask add_url_rule)",
                }
            )

    return routes

def _extract_gin_routes(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    group_paths = {
        "engine": "",
        "gin": prefix_override,
        "router": prefix_override,
        "r": prefix_override,
        "v1": prefix_override,
    }

    assignment_pattern = re.compile(
        r'(\w+)\s*:?=\s*(\w+)\.Group\(\s*["`]([^"`]+)["`]\s*\)',
        re.I,
    )
    method_pattern = re.compile(
        r'(\w+)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Any|ANY)\(\s*["`]([^"`]+)["`]\s*,\s*([A-Za-z_][\w\.]*)',
        re.I,
    )

    changed = True
    while changed:
        changed = False
        for match in assignment_pattern.finditer(content):
            var_name, parent_name, segment = match.groups()
            parent_path = group_paths.get(parent_name)
            if parent_path is None:
                continue
            full_path = _join_route_paths(parent_path, segment)
            if group_paths.get(var_name) != full_path:
                group_paths[var_name] = full_path
                changed = True

    for match in method_pattern.finditer(content):
        group_name, method, segment, handler = match.groups()
        base_path = group_paths.get(group_name)
        if base_path is None:
            continue
        routes.append(
            {
                "method": method.upper(),
                "path": _join_route_paths(base_path, segment),
                "handler": _normalize_handler_name(handler),
                "file_path": file_path,
                "auth": _guess_auth_type(content),
                "params": _merge_params(
                    _extract_route_params(segment),
                    _extract_handler_params(content, _normalize_handler_name(handler)),
                ),
                "notes": "Static route extraction (Gin)",
            }
        )

    return routes

__all__ = [
    '_extract_jaxrs_routes',
    '_extract_dotnet_routes',
    '_extract_go_stdlib_routes',
    '_extract_rails_routes',
    '_extract_rust_routes',
    '_extract_php_routes',
    '_extract_php_dynamic_controller_routes',
    '_extract_php_entry_script_routes',
    '_extract_python_async_routes',
    '_extract_drf_action_routes',
    '_looks_like_js_router_file',
    '_extract_js_router_routes',
    '_extract_spring_routes',
    '_extract_nestjs_routes',
    '_extract_nestjs_path_from_args',
    '_extract_fastapi_local_prefix',
    '_extract_flask_local_prefix',
    '_extract_flask_routes',
    '_extract_gin_routes',
]
