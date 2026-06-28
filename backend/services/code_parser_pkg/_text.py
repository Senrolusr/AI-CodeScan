"""Source-text normalization: comment stripping, char truncation, language block + handler-param extraction."""

from __future__ import annotations

import re

from services.code_parser_pkg._utils import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

_COMMENT_STRIP_PATTERNS = [
    (re.compile(r'/\*.*?\*/', re.DOTALL), ' '),
    (re.compile(r'//[^\n]*'), ' '),
    (re.compile(r'#[^\n]*'), ' '),
    (re.compile(r'""".*?"""', re.DOTALL), '""'),
    (re.compile(r"'''.*?'''", re.DOTALL), "''"),
]

def _extract_handler_params(content: str, handler: str) -> list[str]:
    method_name = handler.split(".")[-1].strip()
    if not method_name or method_name == "Unknown":
        return []

    patterns = [
        re.compile(
            rf"func\s+\(\s*\w+\s+\w+\s*\)\s+{re.escape(method_name)}\s*\([^)]*\)\s*\{{",
            re.M,
        ),
        re.compile(
            rf"func\s+{re.escape(method_name)}\s*\([^)]*\)\s*\{{",
            re.M,
        ),
    ]

    start = -1
    for pattern in patterns:
        match = pattern.search(content)
        if match:
            start = match.end() - 1
            break

    if start == -1:
        return []

    body = _extract_go_block(content, start)
    if not body:
        return []

    params = []
    query_patterns = [
        re.compile(r'\.\s*(?:Query|DefaultQuery|GetQuery)\(\s*"([^"]+)"'),
        re.compile(r'\.\s*(?:PostForm|GetPostForm|DefaultPostForm)\(\s*"([^"]+)"'),
        re.compile(r'\.\s*Param\(\s*"([^"]+)"'),
        re.compile(r'\.\s*Header\(\s*"([^"]+)"'),
    ]
    for pattern in query_patterns:
        for name in pattern.findall(body):
            params.append(name)

    bind_patterns = [
        (re.compile(r'BindJson\(\s*\w+\s*,\s*&\w+\.(\w+)\s*\{?\s*\}\s*\)'), "body"),
        (re.compile(r'BindQuery\(\s*\w+\s*,\s*&\w+\.(\w+)\s*\{?\s*\}\s*\)'), "query"),
        (re.compile(r'ShouldBindJSON\(\s*&\w+\.(\w+)\s*\{?\s*\}\s*\)'), "body"),
        (re.compile(r'ShouldBindQuery\(\s*&\w+\.(\w+)\s*\{?\s*\}\s*\)'), "query"),
    ]
    for pattern, source in bind_patterns:
        for type_name in pattern.findall(body):
            params.append(f"{source}:*{type_name}")

    return _dedupe_preserve_order(params)

def _extract_python_handler_params(content: str, handler: str) -> list[str]:
    handler_name = str(handler or "").split(".")[-1].strip()
    if not handler_name or handler_name == "Unknown":
        return []

    patterns = [
        re.compile(rf"def\s+{re.escape(handler_name)}\s*\([^)]*\)\s*:", re.M),
        re.compile(rf"async\s+def\s+{re.escape(handler_name)}\s*\([^)]*\)\s*:", re.M),
    ]
    match = None
    for pattern in patterns:
        match = pattern.search(content)
        if match:
            break
    if not match:
        return []

    body = _extract_python_block(content, match.end())
    if not body:
        return []

    params: list[str] = []
    token_patterns = [
        re.compile(r'request\.(?:GET|get|query_params|args)\.get\(\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'request\.(?:POST|post|form|data|json|headers|cookies)\.get\(\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'req\.(?:query|params|body|headers|cookies)\.get\(\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'request\.(?:GET|POST|args|form|files|headers|cookies)\s*\[\s*["\']([^"\']+)["\']\s*\]', re.I),
        re.compile(r'req\.(?:query|params|body|headers|cookies)\s*\[\s*["\']([^"\']+)["\']\s*\]', re.I),
    ]
    for pattern in token_patterns:
        params.extend(pattern.findall(body))

    return _dedupe_preserve_order(params)

def _extract_go_block(content: str, brace_start: int) -> str:
    if brace_start < 0 or brace_start >= len(content) or content[brace_start] != "{":
        return ""

    depth = 0
    for index in range(brace_start, len(content)):
        char = content[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return content[brace_start + 1:index]
    return ""

def _extract_python_block(content: str, body_start: int) -> str:
    if body_start < 0 or body_start >= len(content):
        return ""
    lines = content[body_start:].splitlines()
    collected: list[str] = []
    base_indent = None
    for line in lines:
        if not line.strip():
            if collected:
                collected.append(line)
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if base_indent is None:
            base_indent = indent
        if indent < base_indent and collected:
            break
        collected.append(line)
    return "\n".join(collected)

def _strip_comments_and_strings(content: str) -> str:
    for pattern, replacement in _COMMENT_STRIP_PATTERNS:
        content = pattern.sub(replacement, content)
    return content

def _truncate_by_chars(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 32)] + "\n... (truncated)\n"

def _truncate_tail_by_chars(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return "\n... (truncated)\n" + text[-max(0, limit - 32):]

__all__ = [
    '_COMMENT_STRIP_PATTERNS',
    '_extract_handler_params',
    '_extract_python_handler_params',
    '_extract_go_block',
    '_extract_python_block',
    '_strip_comments_and_strings',
    '_truncate_by_chars',
    '_truncate_tail_by_chars',
]
