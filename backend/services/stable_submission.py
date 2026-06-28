"""Stable staged submission helpers for audit runs.

The LLM flow can submit routes, findings, and review decisions incrementally.
The persisted state lives in AuditStage.compressed_summary so the current
schema does not need a migration.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditStage, AuditTask, Project
from services.code_parser import get_or_build_project_cache

SUBMISSION_KEY = "stable_submissions"
VALID_REVIEW_STATUSES = {"confirmed", "uncertain", "rejected"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []


def _submission_state(stage: AuditStage) -> dict:
    compressed = _as_dict(stage.compressed_summary)
    state = _as_dict(compressed.get(SUBMISSION_KEY))
    state.setdefault("routes", [])
    state.setdefault("findings", [])
    state.setdefault("reviews", [])
    return state


def _write_submission_state(stage: AuditStage, state: dict) -> None:
    compressed = _as_dict(stage.compressed_summary)
    compressed[SUBMISSION_KEY] = state
    stage.compressed_summary = compressed


def _stable_hash(*parts: Any) -> str:
    raw = "\x00".join(str(part or "").strip() for part in parts)
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _normalize_route(route: dict) -> dict | None:
    if not isinstance(route, dict):
        return None
    method = str(route.get("method") or route.get("http_method") or "UNKNOWN").strip().upper() or "UNKNOWN"
    path = str(route.get("path") or route.get("url") or route.get("endpoint") or "").strip()
    if not path:
        return None
    source = str(route.get("source") or route.get("source_file") or route.get("file_path") or route.get("file") or "").strip()
    handler = str(route.get("handler") or route.get("function") or "").strip()
    route_id = str(route.get("id") or route.get("route_id") or _stable_hash(method, path, source, handler))
    normalized = dict(route)
    normalized.update(
        {
            "id": route_id,
            "route_id": route_id,
            "method": method,
            "path": path,
            "source": source,
            "source_file": source,
            "file_path": str(route.get("file_path") or source).strip(),
            "handler": handler,
            "notes": str(route.get("notes") or route.get("description") or "").strip(),
            "submitted_at": str(route.get("submitted_at") or _now_iso()),
        }
    )
    return normalized


def _normalize_finding(finding: dict, stage_num: int) -> dict | None:
    if not isinstance(finding, dict):
        return None
    title = str(finding.get("title") or finding.get("vuln_type") or finding.get("description") or "").strip()
    vuln_type = str(finding.get("vuln_type") or finding.get("type") or "").strip()
    file_path = str(finding.get("file_path") or finding.get("file") or "").strip()
    endpoint = str(finding.get("endpoint") or finding.get("route") or "").strip()
    description = str(finding.get("description") or "").strip()
    if not any([title, vuln_type, file_path, endpoint, description]):
        return None
    normalized = dict(finding)
    normalized.setdefault("origin", "submitted")
    normalized.setdefault("stage_num", stage_num)
    finding_id = str(
        finding.get("id")
        or finding.get("finding_id")
        or _stable_hash(stage_num, title, vuln_type, file_path, endpoint, description[:240])
    )
    normalized["id"] = finding_id
    normalized["finding_id"] = finding_id
    normalized["submitted_at"] = str(finding.get("submitted_at") or _now_iso())
    return normalized


def _normalize_review(review: dict) -> dict | None:
    if not isinstance(review, dict):
        return None
    try:
        finding_index = int(review.get("finding_index"))
    except (TypeError, ValueError):
        return None
    status = str(review.get("verification_status") or "").strip().lower()
    if status not in VALID_REVIEW_STATUSES:
        return None
    normalized = {
        "finding_index": finding_index,
        "verification_status": status,
        "reviewed_severity": str(review.get("reviewed_severity") or "").strip(),
        "verification_reason": str(review.get("verification_reason") or "").strip(),
        "submitted_at": str(review.get("submitted_at") or _now_iso()),
    }
    finding_id = str(review.get("finding_id") or review.get("id") or "").strip()
    if finding_id:
        normalized["finding_id"] = finding_id
    return normalized


def _merge_by_id(existing: list[dict], incoming: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    order: list[str] = []
    for item in [*existing, *incoming]:
        if not isinstance(item, dict):
            continue
        item_copy = dict(item)
        item_id = str(item_copy.get("id") or item_copy.get("route_id") or item_copy.get("finding_id") or "").strip()
        if not item_id:
            item_id = _stable_hash(
                item_copy.get("method"),
                item_copy.get("path"),
                item_copy.get("source") or item_copy.get("source_file") or item_copy.get("file_path"),
                item_copy.get("title"),
                item_copy.get("vuln_type") or item_copy.get("type"),
                item_copy.get("endpoint"),
                str(item_copy.get("description") or "")[:240],
            )
            item_copy["id"] = item_id
        if item_id not in merged:
            merged[item_id] = item_copy
            order.append(item_id)
            continue
        previous = merged[item_id]
        previous.update({key: value for key, value in item_copy.items() if value not in (None, "", [], {})})
    return [merged[item_id] for item_id in order]


def _merge_reviews(existing: list[dict], incoming: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    order: list[str] = []
    index_to_key: dict[int, str] = {}

    for review in [*existing, *incoming]:
        if not isinstance(review, dict):
            continue
        try:
            finding_index = int(review.get("finding_index"))
        except (TypeError, ValueError):
            continue
        item = dict(review)
        item["finding_index"] = finding_index
        finding_id = str(item.get("finding_id") or item.get("id") or "").strip()
        if finding_id:
            item["finding_id"] = finding_id

        id_key = f"id:{finding_id}" if finding_id else ""
        existing_key = index_to_key.get(finding_index)
        key = id_key or existing_key or f"index:{finding_index}"

        if id_key and existing_key and existing_key.startswith("index:") and existing_key != id_key:
            previous = merged.pop(existing_key, {})
            for pos, current_key in enumerate(order):
                if current_key == existing_key:
                    order[pos] = id_key
                    break
            merged[id_key] = previous
            key = id_key

        if key not in merged:
            merged[key] = item
            order.append(key)
        else:
            merged[key].update({field: value for field, value in item.items() if value not in (None, "", [], {})})
        index_to_key[finding_index] = key

    return sorted(
        (merged[key] for key in order if key in merged),
        key=lambda item: (int(item.get("finding_index", 0)), str(item.get("finding_id") or "")),
    )


def _page_items(items: list[dict], page: int = 1, page_size: int = 50) -> dict:
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or 50), 200))
    total = len(items)
    offset = (page - 1) * page_size
    return {
        "items": items[offset : offset + page_size],
        "page": page,
        "page_size": page_size,
        "total": total,
        "has_more": offset + page_size < total,
    }


def _response_submission_payload(response: dict | list) -> dict:
    if not isinstance(response, dict):
        return {}
    payload = _as_dict(response.get(SUBMISSION_KEY))
    if not payload:
        payload = _as_dict(response.get("submissions"))
    for source_key, target_key in [
        ("submitted_routes", "routes"),
        ("submitted_findings", "findings"),
        ("submitted_reviews", "reviews"),
    ]:
        value = response.get(source_key)
        if isinstance(value, list) and target_key not in payload:
            payload[target_key] = value
    return payload


def strip_response_submissions(response: dict | list) -> dict | list:
    if not isinstance(response, dict):
        return response
    cleaned = dict(response)
    for key in [SUBMISSION_KEY, "submissions", "submitted_routes", "submitted_findings", "submitted_reviews"]:
        cleaned.pop(key, None)
    return cleaned


def consume_response_submissions(stage: AuditStage, response: dict | list) -> tuple[dict | list, dict]:
    """Persist inline model submissions from a parsed response into stage state.

    This is the non-tool-call bridge for the current LLM client: models can return
    a top-level stable_submissions object in normal JSON, and the engine persists
    it before normal stage output processing.
    """

    payload = _response_submission_payload(response)
    if not payload:
        return response, {}

    state = _submission_state(stage)
    stats: dict[str, dict[str, int]] = {}
    changed = False

    if stage.stage_num == 1:
        normalized_routes = [_normalize_route(route) for route in _as_list(payload.get("routes"))]
        normalized_routes = [route for route in normalized_routes if route]
        if normalized_routes:
            before = len(_as_list(state.get("routes")))
            state["routes"] = _merge_by_id(_as_list(state.get("routes")), normalized_routes)
            stats["routes"] = {"submitted": len(normalized_routes), "total": len(state["routes"]), "new": max(0, len(state["routes"]) - before)}
            changed = True

    if 2 <= stage.stage_num <= 9:
        normalized_findings = [_normalize_finding(finding, stage.stage_num) for finding in _as_list(payload.get("findings"))]
        normalized_findings = [finding for finding in normalized_findings if finding]
        if normalized_findings:
            before = len(_as_list(state.get("findings")))
            state["findings"] = _merge_by_id(_as_list(state.get("findings")), normalized_findings)
            stats["findings"] = {"submitted": len(normalized_findings), "total": len(state["findings"]), "new": max(0, len(state["findings"]) - before)}
            changed = True

        normalized_reviews = [_normalize_review(review) for review in _as_list(payload.get("reviews"))]
        normalized_reviews = [review for review in normalized_reviews if review]
        if normalized_reviews:
            before = len(_as_list(state.get("reviews")))
            state["reviews"] = _merge_reviews(_as_list(state.get("reviews")), normalized_reviews)
            stats["reviews"] = {"submitted": len(normalized_reviews), "total": len(state["reviews"]), "new": max(0, len(state["reviews"]) - before)}
            changed = True

    if changed:
        state["updated_at"] = _now_iso()
        _write_submission_state(stage, state)

    return strip_response_submissions(response), stats


def merge_inline_submission_payloads(base: dict, incoming: dict | list) -> dict:
    if not isinstance(base, dict) or not isinstance(incoming, dict):
        return base
    incoming_payload = _response_submission_payload(incoming)
    if not incoming_payload:
        return base

    merged = dict(base)
    base_payload = _response_submission_payload(base)
    next_payload = dict(base_payload)

    routes = _merge_by_id(_as_list(base_payload.get("routes")), _as_list(incoming_payload.get("routes")))
    if routes:
        next_payload["routes"] = routes
    findings = _merge_by_id(_as_list(base_payload.get("findings")), _as_list(incoming_payload.get("findings")))
    if findings:
        next_payload["findings"] = findings
    reviews = _merge_reviews(_as_list(base_payload.get("reviews")), _as_list(incoming_payload.get("reviews")))
    if reviews:
        next_payload["reviews"] = reviews

    if next_payload:
        merged[SUBMISSION_KEY] = next_payload
    return merged


async def load_stage(db: AsyncSession, task_id: int, stage_num: int) -> AuditStage:
    task_result = await db.execute(select(AuditTask.id).where(AuditTask.id == task_id))
    if task_result.scalar_one_or_none() is None:
        raise HTTPException(404, "Audit task not found")
    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id, AuditStage.stage_num == stage_num)
    )
    stage = result.scalar_one_or_none()
    if not stage:
        raise HTTPException(404, "Audit stage not found")
    return stage


async def submit_routes(db: AsyncSession, task_id: int, routes: list[dict]) -> dict:
    stage = await load_stage(db, task_id, 1)
    normalized = [_normalize_route(route) for route in _as_list(routes)]
    normalized = [route for route in normalized if route]
    if not normalized:
        raise HTTPException(400, "No valid routes submitted")
    state = _submission_state(stage)
    state["routes"] = _merge_by_id(_as_list(state.get("routes")), normalized)
    state["updated_at"] = _now_iso()
    _write_submission_state(stage, state)
    stage.findings = apply_submitted_routes(stage, stage.findings)
    await db.commit()
    return {"submitted": len(normalized), "total": len(state["routes"])}


async def submit_findings(db: AsyncSession, task_id: int, stage_num: int, findings: list[dict]) -> dict:
    if stage_num < 2 or stage_num > 9:
        raise HTTPException(400, "Findings can only be submitted for stages 2-9")
    stage = await load_stage(db, task_id, stage_num)
    normalized = [_normalize_finding(finding, stage_num) for finding in _as_list(findings)]
    normalized = [finding for finding in normalized if finding]
    if not normalized:
        raise HTTPException(400, "No valid findings submitted")
    state = _submission_state(stage)
    state["findings"] = _merge_by_id(_as_list(state.get("findings")), normalized)
    state["updated_at"] = _now_iso()
    _write_submission_state(stage, state)
    stage.findings = apply_submitted_findings(stage, stage.findings)
    await db.commit()
    return {"submitted": len(normalized), "total": len(state["findings"])}


async def submit_reviews(db: AsyncSession, task_id: int, stage_num: int, reviews: list[dict]) -> dict:
    if stage_num < 2 or stage_num > 9:
        raise HTTPException(400, "Reviews can only be submitted for stages 2-9")
    stage = await load_stage(db, task_id, stage_num)
    normalized = [_normalize_review(review) for review in _as_list(reviews)]
    normalized = [review for review in normalized if review]
    if not normalized:
        raise HTTPException(400, "No valid reviews submitted")
    state = _submission_state(stage)
    state["reviews"] = _merge_reviews(_as_list(state.get("reviews")), normalized)
    state["updated_at"] = _now_iso()
    _write_submission_state(stage, state)
    stage.findings = apply_submitted_reviews(stage, stage.findings)
    await db.commit()
    return {"submitted": len(normalized), "total": len(state["reviews"])}


def preserve_submission_state(stage: AuditStage, compressed_summary: dict | list) -> dict | list:
    if not isinstance(compressed_summary, dict):
        return compressed_summary
    existing_state = _as_dict(_as_dict(stage.compressed_summary).get(SUBMISSION_KEY))
    if not existing_state:
        return compressed_summary
    next_summary = dict(compressed_summary)
    next_summary[SUBMISSION_KEY] = existing_state
    return next_summary


def submitted_routes(stage: AuditStage) -> list[dict]:
    return _as_list(_submission_state(stage).get("routes"))


def submitted_findings(stage: AuditStage) -> list[dict]:
    return _as_list(_submission_state(stage).get("findings"))


def submitted_reviews(stage: AuditStage) -> list[dict]:
    return _as_list(_submission_state(stage).get("reviews"))


def apply_submitted_routes(stage: AuditStage, response: dict | list) -> dict | list:
    routes = submitted_routes(stage)
    if not routes:
        return response
    if isinstance(response, dict):
        next_response = dict(response)
        architecture = _as_dict(next_response.get("architecture_info"))
        architecture["routes"] = _merge_by_id(_as_list(architecture.get("routes")), routes)
        next_response["architecture_info"] = architecture
        return next_response
    return {"stage_summary": "", "architecture_info": {"routes": routes}, "vulnerabilities": []}


def apply_submitted_findings(stage: AuditStage, response: dict | list) -> dict | list:
    findings = submitted_findings(stage)
    if not findings:
        return response
    if isinstance(response, dict):
        next_response = dict(response)
        next_response["vulnerabilities"] = _merge_by_id(_as_list(next_response.get("vulnerabilities")), findings)
        return next_response
    return _merge_by_id(_as_list(response), findings)


def apply_submitted_reviews(stage: AuditStage, response: dict | list) -> dict | list:
    reviews = submitted_reviews(stage)
    if not reviews:
        return response
    if isinstance(response, dict):
        next_response = dict(response)
        vulnerabilities = _as_list(next_response.get("vulnerabilities"))
        next_response["vulnerabilities"] = _apply_reviews_to_list(vulnerabilities, reviews)
        return next_response
    return _apply_reviews_to_list(_as_list(response), reviews)


def _apply_reviews_to_list(findings: list[dict], reviews: list[dict]) -> list[dict]:
    reviews_by_id = {
        str(review.get("finding_id")): review
        for review in reviews
        if isinstance(review, dict) and str(review.get("finding_id") or "").strip()
    }
    reviews_by_index = {}
    for review in reviews:
        if not isinstance(review, dict):
            continue
        try:
            reviews_by_index[int(review.get("finding_index"))] = review
        except (TypeError, ValueError):
            continue
    merged: list[dict] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        item = dict(finding)
        finding_id = str(item.get("finding_id") or item.get("id") or "").strip()
        review = reviews_by_id.get(finding_id) if finding_id else None
        if not review:
            review = reviews_by_index.get(index)
        if review:
            item["verification_status"] = review.get("verification_status")
            if review.get("reviewed_severity"):
                item["reviewed_severity"] = review.get("reviewed_severity")
            if review.get("verification_reason"):
                item["verification_reason"] = review.get("verification_reason")
        merged.append(item)
    return merged


def apply_stage_submissions(stage: AuditStage, response: dict | list) -> dict | list:
    if stage.stage_num == 1:
        return apply_submitted_routes(stage, response)
    response = apply_submitted_findings(stage, response)
    return apply_submitted_reviews(stage, response)


async def query_routes(
    db: AsyncSession,
    task_id: int,
    method: str | None = None,
    path: str | None = None,
    source: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    stage = await load_stage(db, task_id, 1)
    findings = _as_dict(stage.findings)
    architecture = _as_dict(findings.get("architecture_info"))
    routes = _as_list(architecture.get("routes"))
    routes = _merge_by_id(routes, submitted_routes(stage))
    if method:
        routes = [route for route in routes if str(route.get("method", "")).upper() == method.upper()]
    if path:
        routes = [route for route in routes if path.lower() in str(route.get("path", "")).lower()]
    if source:
        routes = [
            route
            for route in routes
            if source.lower() in str(route.get("source") or route.get("source_file") or route.get("file_path") or "").lower()
        ]
    return _page_items(routes, page, page_size)


async def query_stage_output(
    db: AsyncSession,
    task_id: int,
    stage_num: int,
    verification_status: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    stage = await load_stage(db, task_id, stage_num)
    findings_payload = _as_dict(stage.findings)
    findings = _as_list(findings_payload.get("vulnerabilities")) if findings_payload else _as_list(stage.findings)
    findings = apply_submitted_findings(stage, findings)
    findings = apply_submitted_reviews(stage, findings)
    if isinstance(findings, dict):
        findings = _as_list(findings.get("vulnerabilities"))
    indexed = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        item = dict(finding)
        item["finding_index"] = index
        item["finding_id"] = str(item.get("finding_id") or item.get("id") or "").strip()
        indexed.append(item)
    if verification_status:
        status = verification_status.strip().lower()
        indexed = [item for item in indexed if str(item.get("verification_status") or "").strip().lower() == status]
    return _page_items(indexed, page, page_size)


async def query_manifest(db: AsyncSession, task_id: int, page_size: int = 80) -> dict:
    task_result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = task_result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "Audit task not found")
    project_result = await db.execute(select(Project).where(Project.id == task.project_id))
    project = project_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    cache = get_or_build_project_cache(project.id, project.upload_path, project.file_tree or [])
    static_routes = _as_list(cache.get("static_routes"))
    rule_hits = _as_list(cache.get("rule_hits"))
    source_sink_hints = _as_list(cache.get("source_sink_hints"))
    code_chunks = _as_list(cache.get("code_chunks"))
    page_size = max(1, min(int(page_size or 80), 200))
    return {
        "project_id": project.id,
        "project_name": project.name,
        "tech_stack": project.tech_stack,
        "scan_stats": _as_dict(cache.get("scan_stats")),
        "route_count": len(static_routes),
        "routes": static_routes[:page_size],
        "rule_hit_count": len(rule_hits),
        "rule_hits": rule_hits[:page_size],
        "source_sink_hint_count": len(source_sink_hints),
        "source_sink_hints": source_sink_hints[:page_size],
        "code_chunk_count": len(code_chunks),
        "candidate_files": [chunk.get("file_path") for chunk in code_chunks[:page_size] if isinstance(chunk, dict)],
        "pre_discovery": cache.get("pre_discovery") if isinstance(cache.get("pre_discovery"), dict) else {},
    }
