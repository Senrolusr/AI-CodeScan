"""Generic helpers, project source-text reading, and small shared reducers for the ai_engine package."""

from __future__ import annotations

import json
import os
from models import Project

import logging

logger = logging.getLogger(__name__)

_SOURCE_TEXT_CACHE: dict[tuple[int, str], str] = {}

def _normalize_stage_num_list(*values) -> list[int]:
    stage_nums: list[int] = []
    for value in values:
        if value is None:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, int) or str(item).isdigit():
                stage_num = int(item)
                if 2 <= stage_num <= 9 and stage_num not in stage_nums:
                    stage_nums.append(stage_num)
    return stage_nums

def _normalize_match_path(path: str) -> str:
    return str(path or "").replace("\\", "/").strip().strip("/").lower()

def _resolve_project_source_path(project: Project | None, file_path: str) -> str:
    if not project or not str(file_path or "").strip():
        return ""

    upload_root = os.path.abspath(str(project.upload_path or ""))
    if not upload_root or not os.path.isdir(upload_root):
        return ""

    normalized = str(file_path or "").replace("\\", "/").strip().strip("/")
    if not normalized:
        return ""

    root_name = os.path.basename(upload_root.rstrip(os.sep))
    candidates = [normalized]
    if root_name and normalized.lower().startswith(root_name.lower() + "/"):
        candidates.append(normalized[len(root_name) + 1 :])

    for candidate in candidates:
        abs_path = os.path.abspath(os.path.join(upload_root, candidate))
        if abs_path == upload_root or not abs_path.startswith(upload_root + os.sep):
            continue
        if os.path.isfile(abs_path):
            return abs_path

    wanted_suffixes = {_normalize_match_path(item) for item in candidates if item}
    for root, _, files in os.walk(upload_root):
        for name in files:
            abs_path = os.path.join(root, name)
            rel_path = _normalize_match_path(os.path.relpath(abs_path, upload_root))
            if rel_path in wanted_suffixes or any(rel_path.endswith("/" + suffix) for suffix in wanted_suffixes):
                return abs_path
    return ""

def _read_project_source_text(project: Project | None, file_path: str) -> str:
    if not project or not file_path:
        return ""
    cache_key = (int(getattr(project, "id", 0) or 0), _normalize_match_path(file_path))
    if cache_key in _SOURCE_TEXT_CACHE:
        return _SOURCE_TEXT_CACHE[cache_key]

    resolved = _resolve_project_source_path(project, file_path)
    if not resolved:
        _SOURCE_TEXT_CACHE[cache_key] = ""
        return ""
    try:
        with open(resolved, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(60000)
    except OSError:
        text = ""
    _SOURCE_TEXT_CACHE[cache_key] = text
    return text

def _summarize_pre_discovery(pre_discovery: dict | None) -> dict | None:
    if not isinstance(pre_discovery, dict):
        return None

    summary: dict = {}

    tech_profile = pre_discovery.get("tech_profile")
    if isinstance(tech_profile, dict):
        summary["tech_profile"] = {
            key: value[:20] if isinstance(value, list) else value
            for key, value in tech_profile.items()
            if value
        }

    dir_structure = pre_discovery.get("dir_structure")
    if isinstance(dir_structure, dict):
        summary["dir_structure"] = {
            key: dir_structure.get(key)
            for key in ["pattern", "confidence", "entry_dirs", "source_dirs", "config_dirs"]
            if dir_structure.get(key)
        }

    security_files = pre_discovery.get("security_files")
    if isinstance(security_files, dict):
        summary["security_files"] = {
            "total_critical_count": int(security_files.get("total_critical_count", 0) or 0),
            "must_cover_files": (security_files.get("must_cover_files") or [])[:60],
        }

    middleware_map = pre_discovery.get("middleware_map")
    if isinstance(middleware_map, dict):
        summary["middleware_map"] = {
            "middleware_chain": (middleware_map.get("middleware_chain") or [])[:30],
            "auth_decorators": dict(list((middleware_map.get("auth_decorators") or {}).items())[:30])
            if isinstance(middleware_map.get("auth_decorators"), dict)
            else {},
        }

    return summary or None

def _safe_positive_int(value, default: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default

def _incremental_submit_stage_nums() -> set[int]:
    """M5b：返回开启增量提交的阶段集合（默认空 = 关闭，零行为变化）。

    读取运行时配置（``CODE_SCAN_INCREMENTAL_SUBMIT_STAGES``），测试中可改环境变量并
    ``get_settings.cache_clear()`` 后即时生效。
    """
    try:
        from services.config import get_settings
        return get_settings().incremental_submit_stage_nums
    except Exception:
        return set()

def _merge_unique_items(existing, incoming):
    result = []
    seen = set()

    for item in list(existing or []) + list(incoming or []):
        if isinstance(item, dict):
            key = json.dumps(item, ensure_ascii=False, sort_keys=True)
        else:
            key = str(item).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(item)

    return result

def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 32)] + "\n... (truncated)\n"

__all__ = [
    '_SOURCE_TEXT_CACHE',
    '_normalize_stage_num_list',
    '_normalize_match_path',
    '_resolve_project_source_path',
    '_read_project_source_text',
    '_summarize_pre_discovery',
    '_safe_positive_int',
    '_incremental_submit_stage_nums',
    '_merge_unique_items',
    '_truncate_text',
]
