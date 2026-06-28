"""Pure string / route-path / object-literal helpers (universal leaves)."""

from __future__ import annotations

import re

import logging

logger = logging.getLogger(__name__)

def _extract_named_array_literal(content: str, key: str) -> str:
    match = re.search(rf'\b{re.escape(key)}\s*:\s*\[', content, re.I)
    if not match:
        return ""
    return _extract_balanced_segment(content, match.end() - 1, "[", "]")

def _extract_balanced_segment(text: str, start_index: int, open_char: str, close_char: str) -> str:
    if start_index < 0 or start_index >= len(text) or text[start_index] != open_char:
        return ""
    depth = 0
    in_string = False
    quote_char = ""
    escaped = False

    for index in range(start_index, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                in_string = False
            continue

        if char in {"'", '"', "`"}:
            in_string = True
            quote_char = char
            continue
        if char == open_char:
            depth += 1
            continue
        if char == close_char:
            depth -= 1
            if depth == 0:
                return text[start_index:index + 1]
    return ""

def _extract_identifier_list(array_literal: str) -> list[str]:
    if not array_literal:
        return []
    identifiers = re.findall(r'\b([A-Z][A-Za-z0-9_]*)\b', array_literal)
    return _merge_unique_paths(identifiers)

def _extract_top_level_object_literals(text: str) -> list[str]:
    objects: list[str] = []
    depth = 0
    start_index = -1
    in_string = False
    quote_char = ""
    escaped = False

    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                in_string = False
            continue

        if char in {"'", '"', "`"}:
            in_string = True
            quote_char = char
            continue
        if char == "{":
            if depth == 0:
                start_index = index
            depth += 1
            continue
        if char == "}":
            depth -= 1
            if depth == 0 and start_index >= 0:
                objects.append(text[start_index:index + 1])
                start_index = -1
    return objects

def _merge_unique_paths(items: list[str]) -> list[str]:
    merged: list[str] = []
    seen = set()
    for item in items:
        normalized = str(item).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    return merged

def _normalize_controller_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.lower())

def _normalize_handler_name(handler: str) -> str:
    return handler.replace("api.", "").strip()

def _merge_params(*param_groups: list[str]) -> list[str]:
    merged = []
    for group in param_groups:
        merged.extend(group or [])
    return _dedupe_preserve_order(merged)

def _dedupe_preserve_order(items: list[str]) -> list[str]:
    result = []
    seen = set()
    for item in items:
        normalized = str(item).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result

def _guess_handler_nearby(content: str, start_idx: int) -> str:
    window = content[start_idx : start_idx + 400]
    func_match = re.search(r"def\s+([A-Za-z_]\w*)\s*\(", window)
    if func_match:
        return func_match.group(1)
    js_match = re.search(r"(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\(", window)
    if js_match:
        return js_match.group(1)
    arrow_match = re.search(r"([A-Za-z_]\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>", window)
    if arrow_match:
        return arrow_match.group(1)
    return "Unknown"

def _guess_auth_type(content: str) -> str:
    lowered = content.lower()
    if re.search(r"\bjwt\b|\bbearer\b", lowered):
        return "JWT"
    if re.search(r"\boauth\b", lowered):
        return "OAuth"
    if re.search(r"\bcookie\b|\bsessionmiddleware\b|\brequest\.session\b|\bset_cookie\b", lowered):
        return "Session"
    if re.search(r"\bauth\b|\blogin_required\b|\bauthorize\b", lowered):
        return "Unknown"
    return "None"

def _extract_route_params(path: str) -> list[str]:
    params = re.findall(r"{([^}]+)}|<([^>]+)>|:([A-Za-z_]\w*)", path)
    cleaned = []
    for group in params:
        for item in group:
            if item:
                cleaned.append(item)
    return cleaned

def _line_number_from_offset(content: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return content.count("\n", 0, min(offset, len(content))) + 1

def _is_comment_or_docstring_match(content: str, offset: int) -> bool:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if line.startswith("#"):
        return True
    prefix = content[:offset]
    if prefix.count('"""') % 2 == 1:
        return True
    if prefix.count("'''") % 2 == 1:
        return True
    return False

def _normalize_route_path(path: str) -> str:
    path = re.sub(r"\s+", "", path.strip())
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path

def _join_route_paths(base: str, segment: str) -> str:
    base = base.strip()
    segment = segment.strip()
    if not segment:
        return _normalize_route_path(base or "/")
    if not base:
        return _normalize_route_path(segment)
    return _normalize_route_path(base.rstrip("/") + "/" + segment.lstrip("/"))

__all__ = [
    '_extract_named_array_literal',
    '_extract_balanced_segment',
    '_extract_identifier_list',
    '_extract_top_level_object_literals',
    '_merge_unique_paths',
    '_normalize_controller_name',
    '_normalize_handler_name',
    '_merge_params',
    '_dedupe_preserve_order',
    '_guess_handler_nearby',
    '_guess_auth_type',
    '_extract_route_params',
    '_line_number_from_offset',
    '_is_comment_or_docstring_match',
    '_normalize_route_path',
    '_join_route_paths',
]
