"""Route prefix resolution: blueprint/router/module prefixes, module-alias resolution."""

from __future__ import annotations

import os
import re

from services.code_parser_pkg._utils import *  # noqa: F401,F403
from services.code_parser_pkg._text import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

ROUTE_EXPORT_NAMES = {
    "router", "api_router", "bp", "blueprint", "urlpatterns", "urls", "routes", "route",
}

def _extract_nestjs_forroutes_bindings(file_path: str, content: str, prefix_override: str = "") -> list[dict]:
    routes = []
    binding_pattern = re.compile(
        r'consumer\.apply\((?P<middlewares>[\s\S]{0,400}?)\)\s*\.(?:exclude\([\s\S]{0,400}?\)\s*\.)*forRoutes\((?P<targets>[\s\S]{0,1200}?)\)',
        re.I,
    )

    for match in binding_pattern.finditer(content):
        middleware_text = re.sub(r'\s+', ' ', match.group("middlewares") or "").strip()
        middleware_text = middleware_text[:160]
        targets_text = match.group("targets") or ""
        binding_text = match.group(0) or ""
        excluded_targets = _extract_nestjs_exclude_targets(binding_text)
        for target in _extract_nestjs_forroutes_targets(targets_text):
            if _is_nestjs_target_excluded(target, excluded_targets):
                continue
            raw_path = target.get("path") or target.get("controller") or ""
            full_path = _join_route_paths(prefix_override, raw_path)
            handler = target.get("handler") or target.get("controller") or "Unknown"
            method = target.get("method") or "ANY"
            notes = "Static route extraction (NestJS forRoutes)"
            if middleware_text:
                notes += f" | middleware={middleware_text}"
            routes.append(
                {
                    "method": method,
                    "path": full_path,
                    "handler": handler,
                    "file_path": file_path,
                    "auth": _guess_auth_type(content),
                    "params": _extract_route_params(full_path),
                    "notes": notes,
                }
            )

    return routes

def _extract_nestjs_exclude_targets(binding_text: str) -> list[dict]:
    exclude_match = re.search(r'\.exclude\((?P<targets>[\s\S]{0,800}?)\)\s*\.forRoutes\(', binding_text, re.I)
    if not exclude_match:
        return []

    targets_text = exclude_match.group("targets") or ""
    exclusions = _extract_nestjs_forroutes_targets(targets_text)
    for raw_path in re.findall(r'["\']([^"\']+)["\']', targets_text):
        exclusions.append({"path": raw_path, "method": "ANY", "controller": "", "handler": ""})
    return _dedupe_nestjs_forroutes_targets(exclusions)

def _is_nestjs_target_excluded(target: dict, excluded_targets: list[dict]) -> bool:
    target_path = str(target.get("path", "")).strip("/")
    target_method = str(target.get("method", "ANY")).upper()
    target_controller = str(target.get("controller", "")).strip()

    for excluded in excluded_targets:
        excluded_path = str(excluded.get("path", "")).strip("/")
        excluded_method = str(excluded.get("method", "ANY")).upper()
        excluded_controller = str(excluded.get("controller", "")).strip()

        path_match = excluded_path and (
            excluded_path in {"*", "(.*)", "**"}
            or target_path == excluded_path
            or (excluded_path.endswith("*") and target_path.startswith(excluded_path[:-1]))
        )
        controller_match = excluded_controller and target_controller == excluded_controller
        method_match = excluded_method in {"ANY", target_method}
        if method_match and (path_match or controller_match):
            return True
    return False

def _extract_nestjs_forroutes_targets(targets_text: str) -> list[dict]:
    targets: list[dict] = []

    for object_text in _extract_top_level_object_literals(targets_text):
        path_match = re.search(r'\bpath\s*:\s*["\']([^"\']*)["\']', object_text, re.I)
        method_match = re.search(r'\bmethod\s*:\s*RequestMethod\.([A-Za-z_]\w*)', object_text, re.I)
        controller_match = re.search(r'\b(?:controller|name)\s*:\s*([A-Za-z_]\w*)', object_text, re.I)
        handler_match = re.search(r'\bhandler\s*:\s*([A-Za-z_]\w*)', object_text, re.I)
        if path_match or controller_match:
            targets.append(
                {
                    "path": path_match.group(1) if path_match else "",
                    "method": method_match.group(1).upper() if method_match else "ANY",
                    "controller": controller_match.group(1) if controller_match else "",
                    "handler": handler_match.group(1) if handler_match else "",
                }
            )

    controller_refs = re.findall(r'\b([A-Z][A-Za-z0-9_]*Controller)\b', targets_text)
    for controller_name in controller_refs:
        targets.append({"path": "", "method": "ANY", "controller": controller_name, "handler": ""})

    for raw_path in re.findall(r'["\']([^"\']+)["\']', targets_text):
        if raw_path in {"*", "(.*)"} or "/" in raw_path:
            targets.append({"path": raw_path, "method": "ANY", "controller": "", "handler": ""})

    return _dedupe_nestjs_forroutes_targets(targets)

def _dedupe_nestjs_forroutes_targets(targets: list[dict]) -> list[dict]:
    merged = []
    seen = set()
    for target in targets:
        key = (
            str(target.get("path", "")),
            str(target.get("method", "ANY")).upper(),
            str(target.get("controller", "")),
            str(target.get("handler", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        normalized = dict(target)
        normalized["method"] = str(normalized.get("method", "ANY")).upper()
        merged.append(normalized)
    return merged

def _build_nestjs_module_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    existing_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith((".ts", ".tsx", ".js"))
    }
    class_to_file: dict[str, str] = {}
    file_cache: dict[str, str] = {}

    for rel_path in existing_paths:
        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue
        file_cache[rel_path] = content
        for class_name in re.findall(r'(?:export\s+)?class\s+([A-Za-z_]\w*)', content):
            class_to_file.setdefault(class_name, rel_path)

    module_controllers: dict[str, list[str]] = {}
    module_routes: list[tuple[str, str]] = []

    for rel_path, content in file_cache.items():
        if "@Module" not in content:
            continue

        aliases = _extract_js_module_aliases(rel_path, content, existing_paths)
        module_match = re.search(
            r'@Module\(\s*(?P<args>[\s\S]{0,2500}?)\)\s*(?:export\s+)?class\s+(?P<class_name>[A-Za-z_]\w*)',
            content,
            re.I,
        )
        if not module_match:
            continue

        module_name = module_match.group("class_name")
        module_args = module_match.group("args") or ""
        controller_files: list[str] = []

        controllers_block = _extract_named_array_literal(module_args, "controllers")
        for controller_name in _extract_identifier_list(controllers_block):
            target_file = aliases.get(controller_name) or class_to_file.get(controller_name)
            if target_file:
                controller_files.append(target_file)
        module_controllers[module_name] = _merge_unique_paths(controller_files)

        imports_block = _extract_named_array_literal(module_args, "imports")
        for route_prefix, route_module in _extract_nestjs_router_module_routes(imports_block):
            module_routes.append((route_prefix, route_module))

    prefixes: dict[str, str] = {}
    for route_prefix, module_name in module_routes:
        for controller_file in module_controllers.get(module_name, []):
            current_prefix = prefixes.get(controller_file)
            next_prefix = _normalize_route_path(route_prefix or "/")
            if not current_prefix or len(next_prefix) < len(current_prefix):
                prefixes[controller_file] = next_prefix

    return prefixes

def _extract_nestjs_router_module_routes(imports_block: str) -> list[tuple[str, str]]:
    if not imports_block:
        return []

    routes: list[tuple[str, str]] = []
    register_pattern = re.compile(r'RouterModule\.register\s*\(', re.I)
    for match in register_pattern.finditer(imports_block):
        open_index = imports_block.find("(", match.start())
        if open_index < 0:
            continue
        register_args = _extract_balanced_segment(imports_block, open_index, "(", ")")
        if not register_args:
            continue
        routes.extend(_parse_nestjs_route_tree(register_args[1:-1], ""))
    return routes

def _parse_nestjs_route_tree(route_text: str, parent_prefix: str) -> list[tuple[str, str]]:
    routes: list[tuple[str, str]] = []
    for object_text in _extract_top_level_object_literals(route_text):
        path_match = re.search(r'\bpath\s*:\s*["\']([^"\']*)["\']', object_text, re.I)
        module_match = re.search(r'\bmodule\s*:\s*([A-Za-z_]\w*)', object_text, re.I)
        next_prefix = _join_route_paths(parent_prefix, path_match.group(1) if path_match else "")
        if module_match:
            routes.append((next_prefix, module_match.group(1)))

        children_match = re.search(r'\bchildren\s*:\s*\[', object_text, re.I)
        if children_match:
            child_array = _extract_balanced_segment(object_text, children_match.end() - 1, "[", "]")
            if child_array:
                routes.extend(_parse_nestjs_route_tree(child_array[1:-1], next_prefix))
    return routes

def _build_js_router_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    existing_paths = {file_node["path"].replace("\\", "/") for file_node in files}
    mounts_by_file: dict[str, list[tuple[str, str]]] = {}
    router_files: set[str] = set()

    for file_node in files:
        rel_path = file_node["path"]
        ext = os.path.splitext(rel_path)[1].lower()
        if ext not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            continue

        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        aliases = _extract_js_module_aliases(rel_path, content, existing_paths)
        use_pattern = re.compile(
            r'\b([A-Za-z_]\w*)\.use\(\s*["\']([^"\']*)["\']\s*,\s*([A-Za-z_]\w*)\s*\)',
            re.I,
        )
        mounts = []
        for parent_var, prefix, alias in use_pattern.findall(content):
            target = aliases.get(alias)
            if not target:
                continue
            mounts.append((parent_var, prefix, target))
            router_files.add(target)
        if mounts:
            mounts_by_file[rel_path] = mounts

    prefixes: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for rel_path, mounts in mounts_by_file.items():
            parent_is_root = _looks_like_root_router_file(rel_path)
            parent_prefix = prefixes.get(rel_path, "")
            for parent_var, mount_prefix, target in mounts:
                base_prefix = parent_prefix
                if _is_root_router_var(parent_var) and parent_is_root:
                    base_prefix = ""
                elif rel_path not in prefixes and not parent_is_root:
                    continue
                combined_prefix = _join_route_paths(base_prefix, mount_prefix)
                if prefixes.get(target) != combined_prefix:
                    prefixes[target] = combined_prefix
                    changed = True

    return prefixes

def _is_root_router_var(name: str) -> bool:
    return name.lower() in {"app", "server", "api", "application"}

def _looks_like_root_router_file(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/").lower()
    root_markers = [
        "main.", "app.", "server.", "index.", "bootstrap.", "entry.",
        "/main.", "/app.", "/server.", "/index.", "/bootstrap.", "/entry.",
    ]
    return any(marker in normalized for marker in root_markers)

def _extract_js_module_aliases(current_path: str, content: str, existing_paths: set[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}

    import_pattern = re.compile(
        r'import\s+([A-Za-z_]\w*)\s+from\s+["\']([^"\']+)["\']',
        re.I,
    )
    named_import_pattern = re.compile(
        r'import\s*\{([^}]+)\}\s*from\s+["\']([^"\']+)["\']',
        re.I,
    )
    mixed_import_pattern = re.compile(
        r'import\s+([A-Za-z_]\w*)\s*,\s*\{([^}]+)\}\s*from\s+["\']([^"\']+)["\']',
        re.I,
    )
    require_pattern = re.compile(
        r'(?:const|let|var)\s+([A-Za-z_]\w*)\s*=\s*require\(\s*["\']([^"\']+)["\']\s*\)',
        re.I,
    )

    for alias, module_path in import_pattern.findall(content):
        resolved = _resolve_js_module_to_relpath(current_path, module_path, existing_paths)
        if resolved:
            aliases[alias] = resolved

    for default_alias, named_imports, module_path in mixed_import_pattern.findall(content):
        resolved = _resolve_js_module_to_relpath(current_path, module_path, existing_paths)
        if not resolved:
            continue
        aliases[default_alias] = resolved
        for item in named_imports.split(","):
            value = item.strip()
            if not value:
                continue
            if " as " in value:
                name, alias = [part.strip() for part in value.split(" as ", 1)]
            else:
                name = alias = value
            if name and alias:
                aliases[alias] = resolved

    for named_imports, module_path in named_import_pattern.findall(content):
        resolved = _resolve_js_module_to_relpath(current_path, module_path, existing_paths)
        if not resolved:
            continue
        for item in named_imports.split(","):
            value = item.strip()
            if not value:
                continue
            if " as " in value:
                name, alias = [part.strip() for part in value.split(" as ", 1)]
            else:
                name = alias = value
            if name and alias:
                aliases[alias] = resolved

    for alias, module_path in require_pattern.findall(content):
        resolved = _resolve_js_module_to_relpath(current_path, module_path, existing_paths)
        if resolved:
            aliases[alias] = resolved

    return aliases

def _resolve_js_module_to_relpath(current_path: str, module_path: str, existing_paths: set[str]) -> str | None:
    if not module_path.startswith("."):
        return None

    current_dir = os.path.dirname(current_path).replace("\\", "/")
    base_dir = os.path.normpath(os.path.join(current_dir, module_path)).replace("\\", "/")
    candidates = [
        base_dir,
        f"{base_dir}.js",
        f"{base_dir}.ts",
        f"{base_dir}.jsx",
        f"{base_dir}.tsx",
        f"{base_dir}/index.js",
        f"{base_dir}/index.ts",
    ]
    for candidate in candidates:
        normalized = candidate.lstrip("./")
        if normalized and normalized in existing_paths:
            return normalized
    return None

def _build_flask_blueprint_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    existing_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith(".py")
    }
    mounts_by_file: dict[str, list[tuple[str, str]]] = {}
    prefixes: dict[str, str] = {}
    root_files: set[str] = set()

    for file_node in files:
        rel_path = file_node["path"]
        if not rel_path.lower().endswith(".py"):
            continue

        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        aliases = _extract_python_module_aliases(rel_path, content, existing_paths)
        if "Flask(" in content or _looks_like_root_router_file(rel_path):
            root_files.add(rel_path)

        register_pattern = re.compile(
            r'register_blueprint\(\s*([A-Za-z_][\w\.]*)\s*(?:,\s*(?P<args>[\s\S]{0,240}?))?\)',
            re.I,
        )
        mounts: list[tuple[str, str]] = []
        for match in register_pattern.finditer(content):
            blueprint_ref = match.group(1)
            args = match.group("args") or ""
            target_path = aliases.get(blueprint_ref)
            if not target_path:
                continue
            prefix_match = re.search(r'url_prefix\s*=\s*["\']([^"\']*)["\']', args, re.I)
            mounts.append((target_path, prefix_match.group(1) if prefix_match else ""))
        if mounts:
            mounts_by_file[rel_path] = mounts

    changed = True
    while changed:
        changed = False
        for rel_path, mounts in mounts_by_file.items():
            parent_prefix = prefixes.get(rel_path, "")
            if rel_path not in root_files and rel_path not in prefixes:
                continue
            for target_path, mount_prefix in mounts:
                combined_prefix = _join_route_paths(parent_prefix, mount_prefix)
                if prefixes.get(target_path) != combined_prefix:
                    prefixes[target_path] = combined_prefix
                    changed = True

    return prefixes

def _build_fastapi_router_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    existing_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith(".py")
    }
    mounts_by_file: dict[str, list[tuple[str, str]]] = {}
    root_files: set[str] = set()

    for file_node in files:
        rel_path = file_node["path"]
        if not rel_path.lower().endswith(".py"):
            continue

        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        module_aliases = _extract_python_module_aliases(rel_path, content, existing_paths)
        if "FastAPI(" in content or _looks_like_root_router_file(rel_path):
            root_files.add(rel_path)
        if not module_aliases or "include_router" not in content:
            continue

        include_router_pattern = re.compile(
            r'include_router\(\s*([A-Za-z_][\w\.]*)\s*(?:,\s*(?P<args>[\s\S]{0,320}?))?\)',
            re.I,
        )
        mounts: list[tuple[str, str]] = []
        for match in include_router_pattern.finditer(content):
            router_ref = match.group(1)
            args = match.group("args") or ""
            target_path = module_aliases.get(router_ref)
            if not target_path and router_ref.endswith(".router"):
                target_path = module_aliases.get(router_ref.rsplit(".", 1)[0])
            if not target_path:
                continue

            prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']*)["\']', args, re.I)
            mounts.append((target_path, prefix_match.group(1) if prefix_match else ""))
        if mounts:
            mounts_by_file[rel_path] = mounts

    changed = True
    while changed:
        changed = False
        for rel_path, mounts in mounts_by_file.items():
            parent_prefix = prefixes.get(rel_path, "")
            if rel_path not in root_files and rel_path not in prefixes:
                continue
            for target_path, mount_prefix in mounts:
                combined_prefix = _join_route_paths(parent_prefix, mount_prefix)
                existing_prefix = prefixes.get(target_path)
                if existing_prefix and len(existing_prefix) <= len(combined_prefix):
                    continue
                prefixes[target_path] = combined_prefix
                changed = True

    return prefixes

def _build_django_include_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    file_paths = {
        file_node["path"].replace("\\", "/")
        for file_node in files
        if file_node["path"].lower().endswith(".py")
    }
    include_graph: dict[str, list[tuple[str, str]]] = {}
    reverse_graph: dict[str, list[tuple[str, str]]] = {}
    root_candidates: set[str] = set()

    for rel_path in file_paths:
        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        if _looks_like_django_root_urls(rel_path):
            root_candidates.add(rel_path)

        aliases = _extract_python_module_aliases(rel_path, content, file_paths)
        pattern_list_targets = _extract_django_pattern_list_targets(content, aliases)
        include_targets = _extract_django_include_targets(content, aliases, pattern_list_targets)
        include_targets.extend(_extract_django_urlpattern_extensions(content, aliases, pattern_list_targets))
        if not include_targets:
            continue

        for include_prefix, target_path in include_targets:
            if target_path not in file_paths:
                continue
            include_graph.setdefault(rel_path, []).append((include_prefix, target_path))
            reverse_graph.setdefault(target_path, []).append((rel_path, include_prefix))

    if reverse_graph:
        inferred_roots = set(include_graph) - set(reverse_graph)
        root_candidates.update(inferred_roots)

    if not root_candidates:
        root_candidates = {path for path in file_paths if _looks_like_django_root_urls(path)}

    prefixes: dict[str, str] = {}
    visited_edges: set[tuple[str, str, str]] = set()

    def dfs(current_path: str, current_prefix: str) -> None:
        normalized_prefix = _normalize_route_path(current_prefix or "/")
        existing = prefixes.get(current_path)
        if existing:
            if len(normalized_prefix) >= len(existing):
                return
        prefixes[current_path] = normalized_prefix

        for child_prefix, target_path in include_graph.get(current_path, []):
            edge = (current_path, child_prefix, target_path)
            if edge in visited_edges:
                continue
            visited_edges.add(edge)
            dfs(target_path, _join_route_paths(normalized_prefix, child_prefix))

    for root_path in sorted(root_candidates):
        dfs(root_path, "/")

    return prefixes

def _looks_like_django_root_urls(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/").lower()
    if not normalized.endswith("urls.py"):
        return False
    return (
        normalized.count("/") <= 1
        or normalized.endswith("/config/urls.py")
        or normalized.endswith("/project/urls.py")
        or normalized.endswith("/settings/urls.py")
    )

def _extract_django_include_targets(
    content: str,
    aliases: dict[str, str],
    pattern_list_targets: dict[str, list[tuple[str, str]]] | None = None,
) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    pattern_list_targets = pattern_list_targets or {}
    include_path_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*(?:\(\s*)?["\']([^"\']+)["\']',
        re.I,
    )
    include_tuple_path_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*\(\s*["\']([^"\']+)["\']\s*,',
        re.I,
    )
    include_alias_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*(?:\(\s*)?([A-Za-z_][\w\.]*)',
        re.I,
    )
    include_tuple_alias_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*\(\s*([A-Za-z_][\w\.]*)\s*,',
        re.I,
    )
    include_var_pattern = re.compile(
        r'(?:path|re_path)\(\s*r?["\']([^"\']*)["\']\s*,\s*include\(\s*([A-Za-z_][\w]*)\s*[\),]',
        re.I,
    )

    for raw_prefix, module_name in include_path_pattern.findall(content):
        target_path = _python_module_to_relpath(module_name)
        if target_path:
            targets.append((raw_prefix, target_path))

    for raw_prefix, module_name in include_tuple_path_pattern.findall(content):
        target_path = _python_module_to_relpath(module_name)
        if target_path:
            targets.append((raw_prefix, target_path))

    for raw_prefix, module_ref in include_alias_pattern.findall(content):
        target_path = aliases.get(module_ref)
        if target_path:
            targets.append((raw_prefix, target_path))

    for raw_prefix, module_ref in include_tuple_alias_pattern.findall(content):
        target_path = aliases.get(module_ref)
        if target_path:
            targets.append((raw_prefix, target_path))

    for raw_prefix, module_ref in include_var_pattern.findall(content):
        target_path = aliases.get(module_ref)
        if target_path:
            targets.append((raw_prefix, target_path))
        for nested_prefix, nested_target in pattern_list_targets.get(module_ref, []):
            targets.append((_join_route_paths(raw_prefix, nested_prefix), nested_target))

    return targets

def _extract_django_pattern_list_targets(
    content: str,
    aliases: dict[str, str],
) -> dict[str, list[tuple[str, str]]]:
    pattern_lists: dict[str, list[tuple[str, str]]] = {}
    assignment_pattern = re.compile(r'\b([A-Za-z_]\w*)\s*=\s*\[', re.I)

    for match in assignment_pattern.finditer(content):
        var_name = match.group(1)
        array_literal = _extract_balanced_segment(content, match.end() - 1, "[", "]")
        if not array_literal:
            continue
        nested_targets = _extract_django_include_targets(array_literal, aliases, {})
        if nested_targets:
            pattern_lists[var_name] = nested_targets

    return pattern_lists

def _extract_django_urlpattern_extensions(
    content: str,
    aliases: dict[str, str],
    pattern_list_targets: dict[str, list[tuple[str, str]]] | None = None,
) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    pattern_list_targets = pattern_list_targets or {}
    extension_pattern = re.compile(r'urlpatterns\s*\+=\s*([A-Za-z_][\w]*)', re.I)
    assignment_concat_pattern = re.compile(r'urlpatterns\s*=\s*([A-Za-z_][\w]*(?:\s*\+\s*[A-Za-z_][\w]*)+)', re.I)

    for alias in extension_pattern.findall(content):
        target_path = aliases.get(alias)
        if target_path and target_path.lower().endswith("urls.py"):
            targets.append(("", target_path))
        targets.extend(pattern_list_targets.get(alias, []))

    for expression in assignment_concat_pattern.findall(content):
        for alias in re.findall(r'[A-Za-z_][\w]*', expression):
            target_path = aliases.get(alias)
            if target_path and target_path.lower().endswith("urls.py"):
                targets.append(("", target_path))
            targets.extend(pattern_list_targets.get(alias, []))

    return targets

def _resolve_prefix_for_path(rel_path: str, prefixes: dict[str, str]) -> str:
    if rel_path in prefixes:
        return prefixes[rel_path]

    basename = os.path.basename(rel_path)
    if basename in prefixes:
        return prefixes[basename]

    return ""

def _extract_python_module_aliases(current_path: str, content: str, existing_paths: set[str] | None = None) -> dict[str, str]:
    aliases: dict[str, str] = {}

    from_import_pattern = re.compile(r'from\s+([A-Za-z_][\w\.]*)\s+import\s+([^\n]+)')
    relative_from_import_pattern = re.compile(r'from\s+(\.+[A-Za-z_][\w\.]*)\s+import\s+([^\n]+)')
    for module_base, imported in from_import_pattern.findall(content):
        for part in imported.split(","):
            item = part.strip()
            if not item:
                continue

            if " as " in item:
                name, alias = [value.strip() for value in item.split(" as ", 1)]
            else:
                name = alias = item

            target = _resolve_python_import_target(module_base, name, current_path=current_path, existing_paths=existing_paths)
            if target:
                aliases[alias] = target

    for module_base, imported in relative_from_import_pattern.findall(content):
        for part in imported.split(","):
            item = part.strip()
            if not item:
                continue

            if " as " in item:
                name, alias = [value.strip() for value in item.split(" as ", 1)]
            else:
                name = alias = item

            target = _resolve_python_import_target(module_base, name, current_path=current_path, existing_paths=existing_paths)
            if target:
                aliases[alias] = target

    import_pattern = re.compile(r'import\s+([A-Za-z_][\w\.]*)(?:\s+as\s+([A-Za-z_]\w*))?')
    for module_name, alias in import_pattern.findall(content):
        target = _python_module_to_relpath(module_name, current_path=current_path, existing_paths=existing_paths)
        if not target:
            continue
        aliases[alias or module_name.split(".")[-1]] = target

    return aliases

def _extract_python_wildcard_import_paths(current_path: str, content: str, existing_paths: set[str] | None = None) -> list[str]:
    targets: list[str] = []
    wildcard_pattern = re.compile(r'from\s+([A-Za-z_\.][\w\.]*)\s+import\s+\*')
    for module_base in wildcard_pattern.findall(content):
        target = _python_module_to_relpath(module_base, current_path=current_path, existing_paths=existing_paths)
        if target:
            targets.append(target)
    return _dedupe_preserve_order(targets)

def _enrich_python_route_metadata(
    route: dict,
    *,
    current_path: str,
    current_content: str,
    file_contents: dict[str, str],
    existing_paths: set[str],
) -> dict:
    if not isinstance(route, dict):
        return route
    handler = str(route.get("handler", "") or "").strip()
    if not handler or handler == "Unknown":
        return route

    handler_name = handler.split(".")[-1].replace(".as_view", "").strip()
    target_path = current_path
    target_content = current_content

    if f"def {handler_name}(" not in current_content and f"async def {handler_name}(" not in current_content:
        aliases = _extract_python_module_aliases(current_path, current_content, existing_paths)
        wildcard_targets = _extract_python_wildcard_import_paths(current_path, current_content, existing_paths)
        dotted_base = handler.split(".", 1)[0] if "." in handler else ""

        if dotted_base and dotted_base in aliases:
            candidate_path = aliases.get(dotted_base)
            candidate_content = file_contents.get(candidate_path or "", "")
            if candidate_path and candidate_content:
                target_path = candidate_path
                target_content = candidate_content
        else:
            for candidate_path in wildcard_targets:
                candidate_content = file_contents.get(candidate_path, "")
                if f"def {handler_name}(" in candidate_content or f"async def {handler_name}(" in candidate_content:
                    target_path = candidate_path
                    target_content = candidate_content
                    break

    handler_defined = (
        f"def {handler_name}(" in target_content
        or f"async def {handler_name}(" in target_content
    )
    if not handler_defined:
        return route

    params = _extract_python_handler_params(target_content, handler_name)
    if target_path and target_path != current_path:
        route["handler_file_path"] = target_path
    if params:
        route["params"] = _merge_params(route.get("params", []) if isinstance(route.get("params"), list) else [], params)
    target_auth = _guess_auth_type(target_content)
    if target_auth and str(route.get("auth", "Unknown")).lower() in {"none", "unknown", ""}:
        route["auth"] = target_auth
    return route

def _resolve_python_import_target(
    module_base: str,
    imported_name: str | None = None,
    current_path: str | None = None,
    existing_paths: set[str] | None = None,
) -> str | None:
    imported_name = (imported_name or "").strip()
    if imported_name in {"urlpatterns", "app_name"}:
        return _python_module_to_relpath(module_base, current_path=current_path, existing_paths=existing_paths)
    if imported_name.endswith("_urlpatterns") or imported_name.endswith("_urls"):
        return _python_module_to_relpath(module_base, current_path=current_path, existing_paths=existing_paths)
    if imported_name in ROUTE_EXPORT_NAMES:
        return _python_module_to_relpath(module_base, current_path=current_path, existing_paths=existing_paths)
    return _python_module_to_relpath(
        module_base,
        imported_name or None,
        current_path=current_path,
        existing_paths=existing_paths,
    )

def _python_module_to_relpath(
    module_base: str,
    imported_name: str | None = None,
    current_path: str | None = None,
    existing_paths: set[str] | None = None,
) -> str | None:
    imported_name = (imported_name or "").strip()
    current_parts = [part for part in str(current_path or "").replace("\\", "/").split("/") if part]
    if current_parts and current_parts[-1].endswith(".py"):
        current_parts = current_parts[:-1]

    if module_base.startswith("."):
        level = len(module_base) - len(module_base.lstrip("."))
        remainder = module_base[level:]
        base_parts = current_parts[: max(len(current_parts) - max(level - 1, 0), 0)]
        module_parts = base_parts + [part for part in remainder.split(".") if part]
    else:
        module_parts = [part for part in module_base.split(".") if part]

    if not module_parts:
        return None

    candidates: list[str] = []
    module_path = "/".join(module_parts)
    if imported_name and imported_name not in ROUTE_EXPORT_NAMES:
        imported_parts = [part for part in imported_name.split(".") if part]
        if imported_parts:
            candidates.append("/".join(module_parts + imported_parts) + ".py")
            candidates.append("/".join(module_parts + imported_parts + ["urls"]) + ".py")
    candidates.append(module_path + ".py")
    candidates.append(module_path + "/urls.py")
    candidates.append(module_path + "/__init__.py")

    if existing_paths:
        for candidate in candidates:
            normalized = candidate.replace("\\", "/").lstrip("./")
            resolved = _match_existing_python_path(normalized, existing_paths)
            if resolved:
                return resolved

    return candidates[0] if candidates else None

def _match_existing_python_path(candidate: str, existing_paths: set[str]) -> str | None:
    normalized = candidate.replace("\\", "/").lstrip("./")
    if normalized in existing_paths:
        return normalized
    suffix = "/" + normalized
    matches = sorted(path for path in existing_paths if path.endswith(suffix))
    return matches[0] if matches else None

def _build_gin_api_prefixes(project_dir: str, files: list[dict]) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    api_receivers: dict[str, str] = {}
    file_contents: dict[str, str] = {}

    for file_node in files:
        rel_path = file_node["path"]
        full_path = os.path.join(project_dir, rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue
        file_contents[rel_path] = content

        receiver_match = re.search(
            r"func\s+\((\w+)\s+(\w+)\)\s+API\s*\(\s*\w+\s+\*gin\.RouterGroup\s*\)",
            content,
        )
        if receiver_match:
            recv_var, recv_type = receiver_match.groups()
            api_receivers[_normalize_controller_name(recv_var)] = rel_path
            api_receivers[_normalize_controller_name(recv_type)] = rel_path

    for rel_path, content in file_contents.items():
        group_paths = _extract_gin_group_paths(content)
        for controller_name, group_var in re.findall(r"api\.(\w+)\.API\((\w+)\)", content):
            target_path = api_receivers.get(_normalize_controller_name(controller_name))
            if not target_path:
                continue
            prefix = group_paths.get(group_var, "")
            if prefix:
                prefixes[target_path] = prefix

    return prefixes

def _extract_gin_group_paths(content: str) -> dict[str, str]:
    group_paths = {"engine": "", "gin": "", "router": "", "r": "", "v1": ""}
    assignment_pattern = re.compile(
        r'(\w+)\s*:?=\s*(\w+)\.Group\(\s*["`]([^"`]+)["`]\s*\)',
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

    return group_paths

__all__ = [
    'ROUTE_EXPORT_NAMES',
    '_extract_nestjs_forroutes_bindings',
    '_extract_nestjs_exclude_targets',
    '_is_nestjs_target_excluded',
    '_extract_nestjs_forroutes_targets',
    '_dedupe_nestjs_forroutes_targets',
    '_build_nestjs_module_prefixes',
    '_extract_nestjs_router_module_routes',
    '_parse_nestjs_route_tree',
    '_build_js_router_prefixes',
    '_is_root_router_var',
    '_looks_like_root_router_file',
    '_extract_js_module_aliases',
    '_resolve_js_module_to_relpath',
    '_build_flask_blueprint_prefixes',
    '_build_fastapi_router_prefixes',
    '_build_django_include_prefixes',
    '_looks_like_django_root_urls',
    '_extract_django_include_targets',
    '_extract_django_pattern_list_targets',
    '_extract_django_urlpattern_extensions',
    '_resolve_prefix_for_path',
    '_extract_python_module_aliases',
    '_extract_python_wildcard_import_paths',
    '_enrich_python_route_metadata',
    '_resolve_python_import_target',
    '_python_module_to_relpath',
    '_match_existing_python_path',
    '_build_gin_api_prefixes',
    '_extract_gin_group_paths',
]
