"""Code chunking: source-file selection, file splitting, oversized-signal windows, risk scoring."""

from __future__ import annotations

import os
from services.config import (
    MAX_AUDIT_SOURCE_FILES,
    MAX_CODE_CHUNKS,
    MAX_FILE_SIZE,
    OVERSIZED_HEAD_CHARS,
    OVERSIZED_MAX_WINDOWS,
    OVERSIZED_TAIL_CHARS,
    OVERSIZED_WINDOW_RADIUS,
    TOTAL_CHARS_LIMIT
)

from services.code_parser_pkg._constants import *  # noqa: F401,F403
from services.code_parser_pkg._text import *  # noqa: F401,F403
from services.code_parser_pkg.files import *  # noqa: F401,F403
from services.code_parser_pkg.rules import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

def _select_audit_source_files(files: list[dict]) -> tuple[list[dict], dict]:
    """Prioritize files for LLM-bound chunking without shrinking the project tree."""
    scored: list[tuple[int, int, str, dict]] = []
    for index, file_node in enumerate(files):
        scored.append((_score_audit_source_file(file_node), index, str(file_node.get("path", "")), file_node))

    scored.sort(key=lambda item: (-item[0], item[1], item[2]))
    selected = [file_node for _, _, _, file_node in scored[:MAX_AUDIT_SOURCE_FILES]]
    selected_scores = [score for score, _, _, _ in scored[:MAX_AUDIT_SOURCE_FILES]]
    return selected, {
        "audit_candidate_files": len(files),
        "files_selected_for_audit": len(selected),
        "files_skipped_by_audit_file_budget": max(0, len(files) - len(selected)),
        "truncated_by_audit_file_count": len(files) > len(selected),
        "selected_high_signal_files": sum(1 for score in selected_scores if score >= 10),
    }

def _score_audit_source_file(file_node: dict) -> int:
    path = str(file_node.get("path", "") or "").replace("\\", "/")
    lowered = path.lower()
    ext = str(file_node.get("extension", "") or "").lower()
    size = int(file_node.get("size", 0) or 0)

    score = 0
    if _is_rule_noise_path(lowered):
        score -= 30

    extension_scores = {
        ".py": 10, ".java": 10, ".php": 10, ".go": 10, ".rb": 10, ".cs": 10,
        ".js": 9, ".ts": 9, ".jsx": 8, ".tsx": 8, ".vue": 8,
        ".xml": 7, ".yaml": 7, ".yml": 7, ".json": 6, ".toml": 6, ".ini": 6,
        ".cfg": 6, ".env": 7, ".sql": 7,
        ".html": 5, ".htm": 5, ".css": 2, ".md": 1, ".txt": 1,
    }
    score += extension_scores.get(ext, 0)

    high_signal_terms = [
        "controller", "controllers", "action", "actions", "route", "router", "routes",
        "api", "endpoint", "handler", "view", "views",
        "auth", "login", "logout", "session", "cookie", "jwt", "token", "captcha",
        "security", "permission", "authorize", "authorization", "role", "roles", "acl",
        "middleware", "interceptor", "filter", "guard", "policy",
        "upload", "download", "file", "template", "attachment", "storage",
        "dao", "repository", "mapper", "model", "entity", "service", "manager",
        "admin", "member", "user", "account", "tenant", "owner",
        "config", "settings", "struts", "spring", "hibernate", "applicationcontext",
        "pom.xml", "package.json", "requirements.txt", "composer.json", "gemfile",
    ]
    medium_signal_terms = [
        "create", "update", "delete", "save", "edit", "search", "query", "execute",
        "order", "payment", "amount", "price", "workflow", "approve", "reject",
        "cache", "serializer", "deserialize", "crypto", "password", "secret",
    ]
    score += sum(4 for term in high_signal_terms if term in lowered)
    score += sum(2 for term in medium_signal_terms if term in lowered)

    if size > MAX_FILE_SIZE:
        score += 3
    elif size <= 4096:
        score += 1

    return score

def _apply_chunk_budgets(new_chunks: list[dict], total_chars: int, current_chunk_count: int) -> tuple[list[dict], int, bool, bool]:
    """Bound newly generated chunks before they are cached for LLM stages."""
    remaining_chunk_budget = MAX_CODE_CHUNKS - current_chunk_count
    if remaining_chunk_budget <= 0:
        return [], total_chars, False, True

    truncated_by_code_chunks = len(new_chunks) > remaining_chunk_budget
    bounded_chunks: list[dict] = []
    for chunk in new_chunks[:remaining_chunk_budget]:
        content = str(chunk.get("content", "") or "")
        remaining_chars = TOTAL_CHARS_LIMIT - total_chars
        if remaining_chars <= 0:
            return bounded_chunks, total_chars, True, truncated_by_code_chunks
        if len(content) > remaining_chars:
            if remaining_chars > 0:
                bounded_chunks.append(
                    _build_chunk(
                        str(chunk.get("file_path") or ""),
                        content[:remaining_chars],
                        base_file_path=str(chunk.get("base_file_path") or chunk.get("file_path") or ""),
                        chunk_type=str(chunk.get("chunk_type") or "partial"),
                    )
                )
                total_chars += remaining_chars
            return bounded_chunks, total_chars, True, truncated_by_code_chunks

        bounded_chunks.append(chunk)
        total_chars += len(content)

    return bounded_chunks, total_chars, False, truncated_by_code_chunks

def get_code_chunks(project_dir: str, file_tree: list, max_chunk_size: int = 3000, include_stats: bool = False) -> list[dict] | tuple[list[dict], dict]:
    """Read code files and split into chunks for LLM processing."""
    files = _flatten_files(file_tree)
    selected_files, selection_stats = _select_audit_source_files(files)
    chunks = []
    total_chars = 0
    stats = {
        **selection_stats,
        "files_considered": 0,
        "files_with_content": 0,
        "chunk_count": 0,
        "total_chars_loaded": 0,
        "truncated_by_total_chars": False,
        "truncated_by_code_chunks": False,
        "oversized_files_compacted": 0,
    }

    for f in selected_files:
        if len(chunks) >= MAX_CODE_CHUNKS:
            stats["truncated_by_code_chunks"] = True
            break
        if total_chars >= TOTAL_CHARS_LIMIT:
            stats["truncated_by_total_chars"] = True
            break

        full_path = os.path.join(project_dir, f["path"])
        stats["files_considered"] += 1

        try:
            content = _read_source_text(full_path)
        except Exception:
            continue

        if not content.strip():
            continue
        stats["files_with_content"] += 1

        if f.get("size", 0) > MAX_FILE_SIZE:
            new_chunks = _build_oversized_file_chunks(f["path"], content)
            if new_chunks:
                stats["oversized_files_compacted"] += 1
        elif len(content) > max_chunk_size:
            new_chunks = _split_file(f["path"], content, max_chunk_size)
        else:
            new_chunks = [_build_chunk(f["path"], content)]

        bounded_chunks, total_chars, truncated_by_total_chars, truncated_by_code_chunks = _apply_chunk_budgets(
            new_chunks,
            total_chars,
            len(chunks),
        )
        chunks.extend(bounded_chunks)
        if truncated_by_code_chunks:
            stats["truncated_by_code_chunks"] = True
        if truncated_by_total_chars:
            stats["truncated_by_total_chars"] = True
        stats["total_chars_loaded"] = total_chars
        if truncated_by_total_chars or truncated_by_code_chunks:
            break

    stats["chunk_count"] = len(chunks)
    if include_stats:
        return chunks, stats
    return chunks

def _split_file(file_path: str, content: str, max_size: int) -> list[dict]:
    """Split a large file into smaller chunks by line boundaries."""
    lines = content.split("\n")
    chunks = []
    current_lines = []
    current_size = 0
    start_line = 1

    for i, line in enumerate(lines, 1):
        line_size = len(line) + 1
        if current_size + line_size > max_size and current_lines:
            chunks.append(
                _build_chunk(
                    f"{file_path}#L{start_line}-{i - 1}",
                    "\n".join(current_lines),
                    base_file_path=file_path,
                    chunk_type="split",
                )
            )
            current_lines = []
            current_size = 0
            start_line = i

        current_lines.append(line)
        current_size += line_size

    if current_lines:
        chunks.append(
            _build_chunk(
                f"{file_path}#L{start_line}-{len(lines)}",
                "\n".join(current_lines),
                base_file_path=file_path,
                chunk_type="split",
            )
        )

    return chunks

def _build_chunk(file_path: str, content: str, base_file_path: str | None = None, chunk_type: str = "full") -> dict:
    content = content or ""
    metadata = _compute_chunk_risk(str(base_file_path or file_path), content)
    return {
        "file_path": file_path,
        "base_file_path": str(base_file_path or file_path),
        "chunk_type": chunk_type,
        "content": content,
        **metadata,
    }

def _compute_chunk_risk(file_path: str, content: str) -> dict:
    stripped = _strip_comments_and_strings(content[:12000])
    haystack = f"{file_path.lower()}\n{stripped.lower()}"
    matched_labels: list[str] = []
    risk_score = 0

    for label, keywords in RISK_KEYWORDS.items():
        hits = sum(1 for keyword in keywords if keyword in haystack)
        if hits:
            matched_labels.append(label)
            risk_score += min(hits, 4) * 3

    high_signal_paths = [
        "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
        "/middleware", "/auth", "/security", "/admin/", "urls.py", "views.py",
        "config", "settings", ".env", "requirements", "package.json",
    ]
    path_hits = sum(1 for keyword in high_signal_paths if keyword in file_path.lower())
    risk_score += path_hits * 2

    if any(file_path.lower().endswith(ext) for ext in [".php", ".py", ".java", ".go", ".rb", ".cs", ".js", ".ts", ".vue"]):
        risk_score += 1

    return {
        "risk_score": risk_score,
        "risk_labels": matched_labels,
    }

def _build_oversized_file_chunks(file_path: str, content: str) -> list[dict]:
    chunks: list[dict] = []
    lines = content.splitlines()
    if not lines:
        return chunks

    head = "\n".join(lines[: min(len(lines), 45)]).strip()
    if head:
        chunks.append(
            _build_chunk(
                f"{file_path}#head",
                _truncate_by_chars(head, OVERSIZED_HEAD_CHARS),
                base_file_path=file_path,
                chunk_type="oversized_head",
            )
        )

    windows = _extract_oversized_signal_windows(lines)
    for index, (start, end) in enumerate(windows, 1):
        window_text = "\n".join(lines[start:end]).strip()
        if not window_text:
            continue
        chunks.append(
            _build_chunk(
                f"{file_path}#signal{index}:L{start + 1}-{end}",
                window_text,
                base_file_path=file_path,
                chunk_type="oversized_signal",
            )
        )

    tail = "\n".join(lines[max(0, len(lines) - 35):]).strip()
    if tail:
        chunks.append(
            _build_chunk(
                f"{file_path}#tail",
                _truncate_tail_by_chars(tail, OVERSIZED_TAIL_CHARS),
                base_file_path=file_path,
                chunk_type="oversized_tail",
            )
        )

    if not chunks:
        chunks.append(
            _build_chunk(
                f"{file_path}#excerpt",
                _truncate_by_chars(content, max(OVERSIZED_HEAD_CHARS, OVERSIZED_TAIL_CHARS)),
                base_file_path=file_path,
                chunk_type="oversized_excerpt",
            )
        )

    deduped: list[dict] = []
    seen = set()
    for chunk in chunks:
        key = (chunk.get("file_path"), chunk.get("content"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(chunk)
    return deduped

def _extract_oversized_signal_windows(lines: list[str]) -> list[tuple[int, int]]:
    windows: list[tuple[int, int]] = []
    flattened_keywords = [keyword for keywords in RISK_KEYWORDS.values() for keyword in keywords]

    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(keyword in lowered for keyword in flattened_keywords):
            windows.append(
                (
                    max(0, index - OVERSIZED_WINDOW_RADIUS),
                    min(len(lines), index + OVERSIZED_WINDOW_RADIUS + 1),
                )
            )

    merged: list[list[int]] = []
    for start, end in windows:
        if not merged or start > merged[-1][1] + 3:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)

    return [(start, end) for start, end in merged[:OVERSIZED_MAX_WINDOWS]]

__all__ = [
    '_select_audit_source_files',
    '_score_audit_source_file',
    '_apply_chunk_budgets',
    'get_code_chunks',
    '_split_file',
    '_build_chunk',
    '_compute_chunk_risk',
    '_build_oversized_file_chunks',
    '_extract_oversized_signal_windows',
]
