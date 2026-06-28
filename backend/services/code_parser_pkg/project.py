"""Project-level parse + on-disk cache (warm/load/clear/get_or_build)."""

from __future__ import annotations

import json
import os
from services.config import (
    CACHE_SCHEMA_VERSION,
    MAX_FILE_SIZE
)

from services.code_parser_pkg._constants import *  # noqa: F401,F403
from services.code_parser_pkg.files import *  # noqa: F401,F403
from services.code_parser_pkg.pre_discovery import *  # noqa: F401,F403
from services.code_parser_pkg.rules import *  # noqa: F401,F403
from services.code_parser_pkg.chunks import *  # noqa: F401,F403
from services.code_parser_pkg.routes import *  # noqa: F401,F403
from services.code_parser_pkg.source_sink import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

CACHE_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "project_cache")

def parse_project(project_dir: str) -> tuple[list, str]:
    """Scan project directory and return (file_tree, tech_stack)."""
    state = {"file_count": 0}
    file_tree = _build_tree(project_dir, project_dir, state=state)
    tech_stack = _detect_tech_stack(project_dir, file_tree)
    return file_tree, tech_stack

def warm_project_cache(project_id: int, project_dir: str, file_tree: list) -> dict:
    code_chunks, chunk_stats = get_code_chunks(project_dir, file_tree, include_stats=True)
    static_routes, route_stats = extract_project_routes(project_dir, file_tree, include_stats=True)
    rule_hits = _build_rule_hits(code_chunks)
    source_sink_hints = _build_source_sink_hints(code_chunks, static_routes)
    project_files = _build_project_files(project_dir, file_tree, rule_hits)
    pre_discovery = run_pre_discovery(project_dir, file_tree, code_chunks, static_routes)
    source_files = _flatten_files(file_tree)
    project_fingerprint = _build_project_fingerprint(file_tree)
    analysis_strategy_fingerprint = _build_analysis_strategy_fingerprint()
    oversized_files = sum(1 for file_node in source_files if file_node.get("size", 0) > MAX_FILE_SIZE)
    scan_stats = {
        "source_files_detected": len(source_files),
        "source_files_indexed": len(source_files),
        "oversized_files_skipped": oversized_files,
        "audit_candidate_files": chunk_stats.get("audit_candidate_files", len(source_files)),
        "files_selected_for_audit": chunk_stats.get("files_selected_for_audit", chunk_stats.get("files_considered", 0)),
        "files_skipped_by_audit_file_budget": chunk_stats.get("files_skipped_by_audit_file_budget", 0),
        "files_considered_for_chunks": chunk_stats.get("files_considered", 0),
        "files_with_content": chunk_stats.get("files_with_content", 0),
        "selected_high_signal_files": chunk_stats.get("selected_high_signal_files", 0),
        "chunk_count": chunk_stats.get("chunk_count", len(code_chunks)),
        "total_chars_loaded": chunk_stats.get("total_chars_loaded", 0),
        "truncated_by_audit_file_count": bool(chunk_stats.get("truncated_by_audit_file_count")),
        "truncated_by_code_chunks": bool(chunk_stats.get("truncated_by_code_chunks")),
        "truncated_by_total_chars": bool(chunk_stats.get("truncated_by_total_chars")),
        "oversized_files_compacted": chunk_stats.get("oversized_files_compacted", 0),
        "rule_hit_count": len(rule_hits),
        "source_sink_hint_count": len(source_sink_hints),
        "project_file_count": len(project_files),
        "route_count": len(static_routes),
        "route_source_files": route_stats.get("files_scanned", 0),
        "partial_audit": bool(
            chunk_stats.get("truncated_by_audit_file_count")
            or chunk_stats.get("truncated_by_code_chunks")
            or chunk_stats.get("truncated_by_total_chars")
            or chunk_stats.get("oversized_files_compacted")
        ),
    }
    cache_payload = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "project_id": project_id,
        "project_fingerprint": project_fingerprint,
        "analysis_strategy_fingerprint": analysis_strategy_fingerprint,
        "code_chunks": code_chunks,
        "static_routes": static_routes,
        "rule_hits": rule_hits,
        "source_sink_hints": source_sink_hints,
        "project_files": project_files,
        "pre_discovery": pre_discovery,
        "scan_stats": scan_stats,
    }
    _write_project_cache(project_id, cache_payload)
    return cache_payload

def load_project_cache(project_id: int, file_tree: list | None = None) -> dict | None:
    cache_path = _project_cache_path(project_id)
    if not os.path.isfile(cache_path):
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if int(payload.get("cache_schema_version", 0) or 0) != CACHE_SCHEMA_VERSION:
        return None
    cached_strategy_fingerprint = str(payload.get("analysis_strategy_fingerprint", "") or "")
    current_strategy_fingerprint = _build_analysis_strategy_fingerprint()
    if not cached_strategy_fingerprint or cached_strategy_fingerprint != current_strategy_fingerprint:
        return None
    if file_tree is not None:
        cached_fingerprint = str(payload.get("project_fingerprint", "") or "")
        current_fingerprint = _build_project_fingerprint(file_tree)
        if not cached_fingerprint or cached_fingerprint != current_fingerprint:
            return None
    return payload

def get_or_build_project_cache(project_id: int, project_dir: str, file_tree: list) -> dict:
    cached = load_project_cache(project_id, file_tree=file_tree)
    if cached:
        code_chunks = cached.get("code_chunks")
        static_routes = cached.get("static_routes")
        rule_hits = cached.get("rule_hits")
        source_sink_hints = cached.get("source_sink_hints")
        scan_stats = cached.get("scan_stats")
        if (
            isinstance(code_chunks, list)
            and isinstance(static_routes, list)
            and isinstance(rule_hits, list)
            and isinstance(source_sink_hints, list)
            and isinstance(scan_stats, dict)
        ):
            return cached
    return warm_project_cache(project_id, project_dir, file_tree)

def clear_project_cache(project_id: int) -> None:
    cache_path = _project_cache_path(project_id)
    if os.path.isfile(cache_path):
        try:
            os.remove(cache_path)
        except OSError:
            pass

def _project_cache_dir(project_id: int) -> str:
    return os.path.join(CACHE_ROOT, str(project_id))

def _project_cache_path(project_id: int) -> str:
    return os.path.join(_project_cache_dir(project_id), "analysis.json")

def _write_project_cache(project_id: int, payload: dict) -> None:
    cache_dir = _project_cache_dir(project_id)
    os.makedirs(cache_dir, exist_ok=True)
    with open(_project_cache_path(project_id), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)

__all__ = [
    'CACHE_ROOT',
    'parse_project',
    'warm_project_cache',
    'load_project_cache',
    'get_or_build_project_cache',
    'clear_project_cache',
    '_project_cache_dir',
    '_project_cache_path',
    '_write_project_cache',
]
