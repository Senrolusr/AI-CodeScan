"""项目结构化索引：把 ``warm_project_cache`` 产出的 ``static_routes`` / ``rule_hits`` /
``source_sink_hints`` 影子写入 ``project_routes`` / ``project_rule_hits`` /
``project_source_sink_hints`` 三表（全量替换，匹配 warm 的覆写语义）。

分层：本模块是 code_parser_pkg 的「调用方」——code_parser_pkg 只产 payload（纯解析，
不引 models/database），DB 写入集中在此。route_id 复用 ``ai_engine.routes._route_id``，
与 M4a 漏洞侧 route_id 同源，故 ``project_routes`` 即 ``vulnerabilities.route_id`` 的主表。
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import delete, insert

from models import ProjectFile, ProjectRoute, ProjectRuleHit, ProjectSourceSinkHint
from services.ai_engine.routes import _route_id


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _route_row(project_id: int, route: dict) -> dict:
    route = route if isinstance(route, dict) else {}
    params = route.get("params")
    return {
        "project_id": project_id,
        "route_id": _route_id(route),
        "method": _as_str(route.get("method")),
        "path": _as_str(route.get("path")),
        "handler": _as_str(route.get("handler")),
        "file_path": _as_str(route.get("file_path") or route.get("handler_file_path")),
        "auth": _as_str(route.get("auth")),
        "line_start": route.get("line_start"),
        "source_kind": _as_str(route.get("source_kind") or route.get("framework")),
        "params": _as_str(params) if params else "",
        "notes": _as_str(route.get("notes")),
    }


def _rule_row(project_id: int, rule: dict) -> dict:
    rule = rule if isinstance(rule, dict) else {}
    stage_nums = rule.get("stage_nums")
    return {
        "project_id": project_id,
        "label": _as_str(rule.get("label")),
        "title": _as_str(rule.get("title")),
        "file_path": _as_str(rule.get("file_path") or rule.get("chunk_path")),
        "chunk_path": _as_str(rule.get("chunk_path")),
        "chunk_type": _as_str(rule.get("chunk_type")),
        "risk_score": _as_int(rule.get("risk_score")),
        "keyword_hit_count": _as_int(rule.get("keyword_hit_count")),
        "weighted_score": _as_float(rule.get("weighted_score")),
        "stage_nums": _as_str(stage_nums) if stage_nums else "",
        "evidence": _as_str(rule.get("evidence")),
    }


def _source_sink_row(project_id: int, hint: dict) -> dict:
    hint = hint if isinstance(hint, dict) else {}
    stage_nums = hint.get("stage_nums")
    return {
        "project_id": project_id,
        "label": _as_str(hint.get("label")),
        "title": _as_str(hint.get("title")),
        "file_path": _as_str(hint.get("file_path")),
        "chunk_path": _as_str(hint.get("chunk_path")),
        "stage_nums": _as_str(stage_nums) if stage_nums else "",
        "source_types": _as_str(hint.get("source_types")),
        "sink_keywords": _as_str(hint.get("sink_keywords")),
        "route_paths": _as_str(hint.get("route_paths")),
        "risk_score": _as_int(hint.get("risk_score")),
        "evidence": _as_str(hint.get("evidence")),
    }


def _file_row(project_id: int, file: dict) -> dict:
    file = file if isinstance(file, dict) else {}
    return {
        "project_id": project_id,
        "path": _as_str(file.get("path")),
        "size": _as_int(file.get("size")),
        "extension": _as_str(file.get("extension")),
        "role": _as_str(file.get("role")),
        "risk_score": _as_int(file.get("risk_score")),
        "content_hash": _as_str(file.get("content_hash")),
    }


async def sync_project_index(session, project_id: int, payload: dict) -> None:
    """全量替换 project_routes / project_rule_hits / project_source_sink_hints / project_files（幂等可重入；先删后插）。

    匹配 ``warm_project_cache`` 的覆写语义：缓存重建即整表替换，不做逐条 diff。
    单条 dict 缺字段一律回退默认值，不让一条坏数据中断整批 sync。
    """
    payload = payload if isinstance(payload, dict) else {}
    static_routes = [r for r in (payload.get("static_routes") or []) if isinstance(r, dict)]
    rule_hits = [r for r in (payload.get("rule_hits") or []) if isinstance(r, dict)]
    source_sink_hints = [r for r in (payload.get("source_sink_hints") or []) if isinstance(r, dict)]
    project_files = [r for r in (payload.get("project_files") or []) if isinstance(r, dict)]

    await session.execute(delete(ProjectRoute).where(ProjectRoute.project_id == project_id))
    await session.execute(delete(ProjectRuleHit).where(ProjectRuleHit.project_id == project_id))
    await session.execute(delete(ProjectSourceSinkHint).where(ProjectSourceSinkHint.project_id == project_id))
    await session.execute(delete(ProjectFile).where(ProjectFile.project_id == project_id))
    if static_routes:
        await session.execute(
            insert(ProjectRoute), [_route_row(project_id, r) for r in static_routes]
        )
    if rule_hits:
        await session.execute(
            insert(ProjectRuleHit), [_rule_row(project_id, r) for r in rule_hits]
        )
    if source_sink_hints:
        await session.execute(
            insert(ProjectSourceSinkHint), [_source_sink_row(project_id, r) for r in source_sink_hints]
        )
    if project_files:
        await session.execute(
            insert(ProjectFile), [_file_row(project_id, r) for r in project_files]
        )
    await session.flush()
