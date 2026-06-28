"""Route identity/coverage normalization, merge, and vulnerability-endpoint hydration."""

from __future__ import annotations

import hashlib
import re
from models import AuditStage, Vulnerability

from services.ai_engine._utils import _normalize_match_path, _safe_positive_int
from services.ai_engine.poc import _build_route_derived_raw_http_artifacts, _classify_poc_requirement, _normalize_http_path, _parse_endpoint_hint, _parse_raw_http_request
from services.ai_engine.findings import _coerce_stage_findings
from services.ai_engine.vulnerability_store import _normalize_endpoint_anchor

import logging

logger = logging.getLogger(__name__)

ROUTE_COVERAGE_AUDITED_STATUSES = {
    "audited_no_finding",
    "finding",
    "confirmed_finding",
    "skipped_with_reason",
    "not_applicable",
}

ROUTE_COVERAGE_GAP_STATUSES = {
    "insufficient_context",
    "needs_followup",
    "missing",
}

def _normalize_route_coverage_status(value) -> str:
    status = str(value or "").strip().lower()
    status = re.sub(r"[\s-]+", "_", status)
    aliases = {
        "audited": "audited_no_finding",
        "covered": "audited_no_finding",
        "reviewed": "audited_no_finding",
        "no_finding": "audited_no_finding",
        "has_finding": "finding",
        "vulnerable": "finding",
        "finding_confirmed": "confirmed_finding",
        "confirmed": "confirmed_finding",
        "skipped": "skipped_with_reason",
        "not_enough_context": "insufficient_context",
        "need_followup": "needs_followup",
        "gap": "needs_followup",
        "n/a": "not_applicable",
        "na": "not_applicable",
    }
    return aliases.get(status, status or "audited_no_finding")

def _is_route_coverage_status_audited(status) -> bool:
    return _normalize_route_coverage_status(status) in ROUTE_COVERAGE_AUDITED_STATUSES

def _is_route_coverage_status_gap(status) -> bool:
    return _normalize_route_coverage_status(status) in ROUTE_COVERAGE_GAP_STATUSES

def _normalize_route_method(value) -> str:
    method = str(value or "UNKNOWN").strip().upper()
    return method or "UNKNOWN"

def _normalize_route_path(value) -> str:
    path = str(value or "").strip()
    if not path:
        return ""
    return re.sub(r"\s+", "", path)

def _route_identity(route: dict | None) -> tuple[str, str, str, str]:
    route = route if isinstance(route, dict) else {}
    return (
        _normalize_route_method(route.get("method")),
        _normalize_route_path(route.get("path")),
        str(route.get("handler", "") or "").strip(),
        _normalize_match_path(str(route.get("file_path", "") or "").strip()),
    )

def _route_id(route: dict | None) -> str:
    route = route if isinstance(route, dict) else {}
    existing = str(route.get("route_id", "") or "").strip()
    if existing:
        return existing
    method, path, handler, file_path = _route_identity(route)
    raw = "|".join([method, path, handler, file_path])
    return f"rt_{hashlib.sha1(raw.encode('utf-8', errors='ignore')).hexdigest()[:12]}"

def _route_with_id(route: dict | None) -> dict:
    normalized = dict(route) if isinstance(route, dict) else {}
    normalized["route_id"] = _route_id(normalized)
    normalized["method"] = _normalize_route_method(normalized.get("method"))
    normalized["path"] = str(normalized.get("path", "") or "").strip()
    return normalized

def _extract_route_ids_from_lines(route_lines) -> list[str]:
    if not isinstance(route_lines, list):
        return []
    route_ids: list[str] = []
    seen: set[str] = set()
    for line in route_lines:
        for match in re.finditer(r"\broute_id=([A-Za-z0-9_-]+)", str(line or "")):
            route_id = match.group(1).strip()
            if route_id and route_id not in seen:
                seen.add(route_id)
                route_ids.append(route_id)
    return route_ids

def _merge_routes_by_id(*route_lists) -> list[dict]:
    merged: dict[str, dict] = {}
    order: list[str] = []
    for route_list in route_lists:
        if not isinstance(route_list, list):
            continue
        for route in route_list:
            if not isinstance(route, dict):
                continue
            normalized = _route_with_id(route)
            route_id = normalized["route_id"]
            if route_id not in merged:
                merged[route_id] = normalized
                order.append(route_id)
                continue
            merged[route_id] = {
                **normalized,
                **{key: value for key, value in merged[route_id].items() if value not in (None, "", [], {})},
            }
    return [merged[route_id] for route_id in order]

def _normalize_route_coverage_item(item, stage_num: int | None = None) -> dict | None:
    if not isinstance(item, dict):
        return None
    route_id = str(item.get("route_id", "") or "").strip()
    route_payload = item.get("route") if isinstance(item.get("route"), dict) else item
    if not route_id:
        if not str(route_payload.get("path", "") or "").strip():
            return None
        route_id = _route_id(route_payload)
    status = _normalize_route_coverage_status(item.get("status"))
    normalized = {
        "route_id": route_id,
        "status": status,
        "reason": str(item.get("reason", "") or item.get("notes", "") or "").strip()[:500],
    }
    if stage_num is not None:
        normalized["stage_num"] = stage_num
    for key in ["method", "path", "handler", "file_path", "auth"]:
        value = item.get(key)
        if not value and isinstance(route_payload, dict):
            value = route_payload.get(key)
        if value:
            normalized[key] = value
    return normalized

def _extract_route_coverage_items(payload, stage_num: int | None = None) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    coverage = payload.get("route_coverage")
    if not isinstance(coverage, list):
        return []
    result = []
    for item in coverage:
        normalized = _normalize_route_coverage_item(item, stage_num=stage_num)
        if normalized:
            result.append(normalized)
    return result

def _extract_architecture_routes(payload) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    architecture_info = payload.get("architecture_info")
    if not isinstance(architecture_info, dict):
        return []
    routes = architecture_info.get("routes")
    return routes if isinstance(routes, list) else []

def _extract_stage_coverage_payload(stage: AuditStage) -> dict:
    compressed = stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {}
    stage_coverage = compressed.get("_stage_coverage", {})
    return stage_coverage if isinstance(stage_coverage, dict) else {}

def _extract_stage_focus_routes(stage_coverage: dict) -> list[dict]:
    focus_routes = stage_coverage.get("focus_routes") if isinstance(stage_coverage, dict) else []
    if not isinstance(focus_routes, list):
        return []
    return [_route_with_id(route) for route in focus_routes if isinstance(route, dict) and str(route.get("path", "") or "").strip()]

def _extract_stage_focus_route_ids(stage_coverage: dict) -> list[str]:
    focus_ids = stage_coverage.get("focus_route_ids") if isinstance(stage_coverage, dict) else []
    normalized: list[str] = []
    seen: set[str] = set()
    if isinstance(focus_ids, list):
        for route_id in focus_ids:
            route_id = str(route_id or "").strip()
            if route_id and route_id not in seen:
                seen.add(route_id)
                normalized.append(route_id)
    for route in _extract_stage_focus_routes(stage_coverage):
        route_id = str(route.get("route_id", "") or "").strip()
        if route_id and route_id not in seen:
            seen.add(route_id)
            normalized.append(route_id)
    return normalized

def _extract_stage_route_coverage_items(stage: AuditStage) -> list[dict]:
    findings = _coerce_stage_findings(stage.findings)
    compressed = stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {}
    stage_coverage = _extract_stage_coverage_payload(stage)
    items: list[dict] = []
    seen: set[tuple] = set()
    for source in [findings, compressed, stage_coverage]:
        for item in _extract_route_coverage_items(source, stage_num=stage.stage_num):
            key = (
                item.get("route_id"),
                item.get("stage_num"),
                item.get("status"),
                item.get("reason"),
            )
            if key in seen:
                continue
            seen.add(key)
            items.append(item)
    return items

def _public_route_fields(route: dict | None) -> dict:
    route = _route_with_id(route)
    result = {
        "route_id": route.get("route_id", ""),
        "method": _normalize_route_method(route.get("method")),
        "path": str(route.get("path", "") or "").strip(),
        "handler": str(route.get("handler", "") or "").strip(),
        "file_path": str(route.get("file_path", "") or "").strip(),
    }
    auth = str(route.get("auth", "") or "").strip()
    if auth:
        result["auth"] = auth
    return result

def _route_match_path(path: str) -> str:
    normalized = _normalize_route_path(path).lower().replace("\\", "/")
    normalized = normalized.split("?", 1)[0]
    normalized = re.sub(r"/:[^/]+", "/{id}", normalized)
    normalized = re.sub(r"/<[^/]+>", "/{id}", normalized)
    normalized = re.sub(r"/\{[^/]+\}", "/{id}", normalized)
    normalized = re.sub(r"/\d+(?=/|$)", "/{id}", normalized)
    normalized = re.sub(r"/[0-9a-f-]{8,}(?=/|$)", "/{id}", normalized)
    normalized = re.sub(r"/+", "/", normalized).strip()
    return normalized

def _route_endpoint_keys(route: dict) -> set[str]:
    method = _normalize_route_method(route.get("method"))
    path = _route_match_path(str(route.get("path", "") or ""))
    if not path:
        return set()
    return {f"{method} {path}", f"ANY {path}", f"UNKNOWN {path}", path}

def _vulnerability_endpoint_keys(endpoint: str) -> set[str]:
    endpoint = str(endpoint or "").strip()
    if not endpoint:
        return set()
    anchor = _normalize_endpoint_anchor(endpoint)
    if not anchor:
        return set()
    keys = {anchor}
    if " " in anchor:
        _, path = anchor.split(" ", 1)
        path = _route_match_path(path)
        if path:
            keys.add(path)
            keys.add(f"ANY {path}")
            keys.add(f"UNKNOWN {path}")
    return keys

def _resolve_vuln_route_id(vuln, route_by_id: dict, route_by_endpoint: dict) -> str:
    """vuln→route 匹配：优先 M4a 回填的稳定 route_id，回退 endpoint 模糊匹配（兼容无 route_id 旧 vuln）。

    route_id 命中但已不在 route_by_id（stale，路由被删/重建）时回退 endpoint；都不匹配返回空串。
    """
    matched = str(getattr(vuln, "route_id", "") or "").strip()
    if matched and matched in route_by_id:
        return matched
    endpoint = str(getattr(vuln, "endpoint", "") or "").strip()
    for key in _vulnerability_endpoint_keys(endpoint):
        candidate = route_by_endpoint.get(key)
        if candidate:
            return candidate
    return ""

def _status_summary_for_route(statuses: list[str]) -> str:
    normalized = [_normalize_route_coverage_status(status) for status in statuses if status]
    if any(status == "confirmed_finding" for status in normalized):
        return "confirmed_finding"
    if any(status == "finding" for status in normalized):
        return "finding"
    if any(status == "audited_no_finding" for status in normalized):
        return "audited_no_finding"
    if any(status == "not_applicable" for status in normalized):
        return "not_applicable"
    if any(status == "skipped_with_reason" for status in normalized):
        return "skipped_with_reason"
    if any(_is_route_coverage_status_gap(status) for status in normalized):
        return "needs_followup"
    return "missing"

def _build_task_route_coverage_summary(
    stages: list[AuditStage],
    *,
    static_routes: list | None = None,
    scan_stats: dict | None = None,
    vulns: list[Vulnerability] | None = None,
) -> dict | None:
    scan_stats = scan_stats if isinstance(scan_stats, dict) else {}
    static_route_source = static_routes if isinstance(static_routes, list) else []
    inventory_routes = _merge_routes_by_id(static_route_source)
    inventory_ids = {_route_id(route) for route in inventory_routes if _route_id(route)}
    route_sources: list[list] = [static_route_source]
    coverage_items_by_stage: dict[int, list[dict]] = {}
    stage_coverage_rows: list[dict] = []

    for stage in stages:
        findings = _coerce_stage_findings(stage.findings)
        compressed = stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {}
        stage_coverage = _extract_stage_coverage_payload(stage)
        route_sources.extend([
            _extract_architecture_routes(findings),
            _extract_architecture_routes(compressed),
            _extract_stage_focus_routes(stage_coverage),
        ])
        if 2 <= int(stage.stage_num or 0) <= 9:
            coverage_items = _extract_stage_route_coverage_items(stage)
            coverage_items_by_stage[stage.stage_num] = coverage_items
            route_sources.append([item for item in coverage_items if str(item.get("path", "") or "").strip()])

    canonical_routes = _merge_routes_by_id(*route_sources)
    canonical_routes.sort(key=lambda item: (-_route_priority_score(item), item.get("path", ""), item.get("method", ""), item.get("handler", "")))
    route_by_id = {_route_id(route): _public_route_fields(route) for route in canonical_routes}
    canonical_ids = set(route_by_id.keys())

    coverage_by_route: dict[str, dict] = {}
    status_counts: dict[str, int] = {}
    model_attested_route_ids: set[str] = set()

    for stage in stages:
        stage_num = int(stage.stage_num or 0)
        if not 2 <= stage_num <= 9:
            continue
        stage_coverage = _extract_stage_coverage_payload(stage)
        focus_ids = _extract_stage_focus_route_ids(stage_coverage)
        coverage_items = coverage_items_by_stage.get(stage_num, [])
        attested_ids: set[str] = set()
        audited_ids: set[str] = set()

        for item in coverage_items:
            route_id = str(item.get("route_id", "") or "").strip()
            if not route_id:
                continue
            status = _normalize_route_coverage_status(item.get("status"))
            status_counts[status] = status_counts.get(status, 0) + 1
            attested_ids.add(route_id)
            model_attested_route_ids.add(route_id)
            if _is_route_coverage_status_audited(status):
                audited_ids.add(route_id)
            record = coverage_by_route.setdefault(
                route_id,
                {"statuses": [], "stage_nums": [], "reasons": []},
            )
            if status not in record["statuses"]:
                record["statuses"].append(status)
            if stage_num not in record["stage_nums"]:
                record["stage_nums"].append(stage_num)
            reason = str(item.get("reason", "") or "").strip()
            if reason and reason not in record["reasons"]:
                record["reasons"].append(reason[:240])
            if route_id not in route_by_id and str(item.get("path", "") or "").strip():
                route_by_id[route_id] = _public_route_fields(item)
                canonical_ids.add(route_id)

        unattested_focus_ids = [
            route_id
            for route_id in focus_ids
            if route_id not in attested_ids
        ]
        gap_focus_ids = [
            route_id
            for route_id in focus_ids
            if route_id in attested_ids and route_id not in audited_ids
        ]
        missing_focus_ids = [
            route_id
            for route_id in focus_ids
            if route_id not in audited_ids
        ]
        stage_coverage_rows.append(
            {
                "stage_num": stage_num,
                "stage_name": str(stage.stage_name or ""),
                "focus_route_count": len(focus_ids),
                "attested_route_count": len(attested_ids),
                "audited_route_count": len(audited_ids),
                "missing_focus_route_count": len(missing_focus_ids),
                "unattested_focus_route_count": len(unattested_focus_ids),
                "gap_focus_route_count": len(gap_focus_ids),
                "missing_focus_route_ids": missing_focus_ids[:30],
                "unattested_focus_route_ids": unattested_focus_ids[:30],
                "gap_focus_route_ids": gap_focus_ids[:30],
            }
        )

    route_by_endpoint: dict[str, str] = {}
    for route_id, route in route_by_id.items():
        for key in _route_endpoint_keys(route):
            route_by_endpoint.setdefault(key, route_id)

    stage_num_by_id = {getattr(stage, "id", None): int(stage.stage_num or 0) for stage in stages}
    for vuln in vulns or []:
        matched_route_id = _resolve_vuln_route_id(vuln, route_by_id, route_by_endpoint)
        if not matched_route_id:
            continue
        stage_num = stage_num_by_id.get(getattr(vuln, "stage_id", None))
        record = coverage_by_route.setdefault(matched_route_id, {"statuses": [], "stage_nums": [], "reasons": []})
        if "finding" not in record["statuses"]:
            record["statuses"].append("finding")
        if stage_num and stage_num not in record["stage_nums"]:
            record["stage_nums"].append(stage_num)
        if "formal vulnerability recorded" not in record["reasons"]:
            record["reasons"].append("formal vulnerability recorded")

    canonical_ids = set(route_by_id.keys())
    attested_ids = {route_id for route_id in model_attested_route_ids if route_id in canonical_ids}
    audited_ids = {
        route_id
        for route_id, record in coverage_by_route.items()
        if route_id in canonical_ids and any(_is_route_coverage_status_audited(status) for status in record.get("statuses", []))
    }
    finding_ids = {
        route_id
        for route_id, record in coverage_by_route.items()
        if route_id in canonical_ids and any(_normalize_route_coverage_status(status) in {"finding", "confirmed_finding"} for status in record.get("statuses", []))
    }
    missing_known_ids = sorted(
        [route_id for route_id in canonical_ids if route_id not in audited_ids],
        key=lambda route_id: (
            -_route_priority_score(route_by_id.get(route_id, {})),
            route_by_id.get(route_id, {}).get("path", ""),
            route_by_id.get(route_id, {}).get("method", ""),
        ),
    )

    known_route_count = len(canonical_ids)
    inventory_route_count = len(inventory_ids)
    model_derived_route_count = len(canonical_ids - inventory_ids)
    scanned_route_count = _safe_positive_int(scan_stats.get("route_count"), 0)
    total_routes = max(known_route_count, scanned_route_count)
    if total_routes <= 0 and not stage_coverage_rows:
        return None

    audited_route_count = len(audited_ids)
    missing_route_count = max(total_routes - audited_route_count, 0)
    unknown_missing_route_count = max(0, missing_route_count - len(missing_known_ids))
    coverage_ratio = (audited_route_count / total_routes) if total_routes else 1.0
    focus_gap_count = sum(row["missing_focus_route_count"] for row in stage_coverage_rows)
    focus_unattested_count = sum(row["unattested_focus_route_count"] for row in stage_coverage_rows)
    unattested_route_ids = sorted(
        [route_id for route_id in canonical_ids if route_id not in attested_ids and route_id not in audited_ids],
        key=lambda route_id: (
            -_route_priority_score(route_by_id.get(route_id, {})),
            route_by_id.get(route_id, {}).get("path", ""),
            route_by_id.get(route_id, {}).get("method", ""),
        ),
    )
    attested_gap_route_ids = sorted(
        [route_id for route_id in canonical_ids if route_id in attested_ids and route_id not in audited_ids],
        key=lambda route_id: (
            -_route_priority_score(route_by_id.get(route_id, {})),
            route_by_id.get(route_id, {}).get("path", ""),
            route_by_id.get(route_id, {}).get("method", ""),
        ),
    )
    gap_reason_counts = {
        "not_model_attested": len(unattested_route_ids),
        "attested_but_not_audited": len(attested_gap_route_ids),
        "missing_from_known_inventory": unknown_missing_route_count,
        "missing_focus_audits": focus_gap_count,
        "missing_focus_attestations": focus_unattested_count,
    }

    missing_routes = []
    for route_id in missing_known_ids[:40]:
        route = dict(route_by_id.get(route_id, {}))
        record = coverage_by_route.get(route_id, {})
        route["status"] = _status_summary_for_route(record.get("statuses", []))
        route["stage_nums"] = sorted(record.get("stage_nums", []))[:8]
        if route_id not in attested_ids:
            route["gap_reason"] = "not_model_attested"
        elif not any(_is_route_coverage_status_audited(status) for status in record.get("statuses", [])):
            route["gap_reason"] = "attested_but_not_audited"
        else:
            route["gap_reason"] = "not_counted"
        if record.get("reasons"):
            route["coverage_reasons"] = record.get("reasons", [])[:3]
        missing_routes.append(route)

    return {
        "total_routes": total_routes,
        "known_route_count": known_route_count,
        "canonical_route_count": known_route_count,
        "inventory_route_count": inventory_route_count,
        "scan_reported_route_count": scanned_route_count,
        "model_derived_route_count": model_derived_route_count,
        "audited_route_count": audited_route_count,
        "attested_route_count": len(attested_ids),
        "finding_route_count": len(finding_ids),
        "missing_route_count": missing_route_count,
        "unknown_missing_route_count": unknown_missing_route_count,
        "coverage_ratio": round(coverage_ratio, 4),
        "has_route_gaps": missing_route_count > 0 or focus_gap_count > 0,
        "focus_gap_count": focus_gap_count,
        "focus_unattested_count": focus_unattested_count,
        "gap_reason_counts": gap_reason_counts,
        "unattested_route_count": len(unattested_route_ids),
        "attested_gap_route_count": len(attested_gap_route_ids),
        "next_route_batch": [dict(route_by_id.get(route_id, {})) for route_id in missing_known_ids[:24]],
        "status_counts": status_counts,
        "stage_coverage": stage_coverage_rows,
        "missing_routes": missing_routes,
    }

def _hydrate_vulnerability_endpoints(
    *,
    response: dict,
    static_routes: list[dict] | None = None,
    audit_memory: dict | None = None,
) -> dict:
    if not isinstance(response, dict):
        return {"vulnerabilities": []}

    vulnerabilities = response.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return response

    route_candidates = _collect_endpoint_route_candidates(response, static_routes, audit_memory)
    hydrated_vulns = []
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        normalized = dict(vuln)
        endpoint = _resolve_vulnerability_endpoint(normalized, route_candidates)
        if endpoint:
            normalized["endpoint"] = endpoint
        matched = _find_route_candidate_for_vulnerability(normalized, route_candidates)
        if matched:
            normalized["route_id"] = _route_id(matched)
            normalized["route_method"] = matched.get("method", "")
            normalized["route_path"] = matched.get("path", "")
            normalized["route_handler"] = matched.get("handler", "")
        hydrated_vulns.append(normalized)

    normalized_response = dict(response)
    normalized_response["vulnerabilities"] = hydrated_vulns
    return normalized_response

def _backfill_vulnerability_poc_templates(
    *,
    stage_num: int,
    response: dict,
    static_routes: list[dict] | None = None,
    audit_memory: dict | None = None,
) -> dict:
    if not isinstance(response, dict):
        return {"vulnerabilities": []}

    vulnerabilities = response.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return response

    route_candidates = _collect_endpoint_route_candidates(response, static_routes, audit_memory)
    hydrated_vulns = []
    template_note = "系统已基于静态路由生成最小请求模板，仍需补全真实参数值、认证上下文和利用前提。"

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        normalized = dict(vuln)
        requirement = _classify_poc_requirement(stage_num, normalized)
        poc_raw = str(normalized.get("poc_raw", "") or "").strip()
        parsed = _parse_raw_http_request(poc_raw)
        needs_template = (
            requirement == "raw_http"
            and (
                not poc_raw
                or poc_raw.startswith("未提供可复现 POC")
                or not parsed.get("valid")
            )
        )
        if not needs_template:
            hydrated_vulns.append(normalized)
            continue

        route_candidate = _find_route_candidate_for_vulnerability(normalized, route_candidates)
        endpoint, template = _build_route_derived_raw_http_artifacts(normalized, route_candidate)
        if template:
            normalized["poc_raw"] = template
            if endpoint:
                normalized["endpoint"] = endpoint
            normalized["_poc_template_generated"] = True
            normalized["_poc_validation"] = {"accepted": False, "reason": template_note}
        hydrated_vulns.append(normalized)

    normalized_response = dict(response)
    normalized_response["vulnerabilities"] = hydrated_vulns
    return normalized_response

def _collect_endpoint_route_candidates(
    response: dict,
    static_routes: list[dict] | None = None,
    audit_memory: dict | None = None,
) -> list[dict]:
    candidates: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()
    sources = []
    if isinstance(static_routes, list):
        sources.extend(static_routes)
    route_inventory = (audit_memory or {}).get("route_inventory", [])
    if isinstance(route_inventory, list):
        sources.extend(route_inventory)
    architecture_info = response.get("architecture_info", {})
    if isinstance(architecture_info, dict) and isinstance(architecture_info.get("routes"), list):
        sources.extend(architecture_info.get("routes", []))

    for route in sources:
        if not isinstance(route, dict):
            continue
        path = _normalize_http_path(str(route.get("path", "") or "").strip())
        if not path:
            continue
        method = str(route.get("method", "UNKNOWN") or "UNKNOWN").upper()
        file_path = str(route.get("handler_file_path", "") or route.get("file_path", "") or "").strip()
        handler = str(route.get("handler", "") or "").strip()
        key = (method, path, file_path.lower(), handler.lower())
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "method": method,
                "path": path,
                "file_path": file_path,
                "handler": handler,
                "auth": str(route.get("auth", "Unknown") or "Unknown").strip() or "Unknown",
                "params": route.get("params", [])[:12] if isinstance(route.get("params"), list) else [],
                "notes": str(route.get("notes", "") or "").strip(),
            }
        )
    return candidates

def _find_route_candidate_for_vulnerability(vuln: dict, route_candidates: list[dict]) -> dict | None:
    file_path = str(vuln.get("file_path", "") or "").strip().lower()
    endpoint_method, endpoint_path = _parse_endpoint_hint(str(vuln.get("endpoint", "") or ""))
    if endpoint_path:
        matched = _select_best_route_candidate(
            route_candidates,
            file_path=file_path,
            method=endpoint_method,
            path=endpoint_path,
        )
        if matched:
            return matched

    packet = _parse_raw_http_request(str(vuln.get("poc_raw", "") or "").strip())
    if packet.get("valid"):
        matched = _select_best_route_candidate(
            route_candidates,
            file_path=file_path,
            method=str(packet.get("method", "") or "").upper(),
            path=str(packet.get("target", "") or "").strip(),
        )
        if matched:
            return matched

    return _select_best_route_candidate(
        route_candidates,
        file_path=file_path,
        method="UNKNOWN",
        path="",
    )

def _resolve_vulnerability_endpoint(vuln: dict, route_candidates: list[dict]) -> str:
    endpoint_text = str(vuln.get("endpoint", "") or "").strip()
    file_path = str(vuln.get("file_path", "") or "").strip().lower()
    packet = _parse_raw_http_request(str(vuln.get("poc_raw", "") or "").strip())
    packet_method = str(packet.get("method", "") or "").upper() if packet.get("valid") else ""
    packet_path = _normalize_http_path(str(packet.get("target", "") or "").strip()) if packet.get("valid") else ""

    endpoint_method = "UNKNOWN"
    endpoint_path = ""
    if endpoint_text:
        match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|ANY|UNKNOWN)\s+(\S+)$", endpoint_text, re.I)
        if match:
            endpoint_method = match.group(1).upper()
            endpoint_path = _normalize_http_path(match.group(2).strip())
        else:
            endpoint_path = _normalize_http_path(endpoint_text)

    direct_packet_endpoint = f"{packet_method} {packet_path}".strip() if packet_method and packet_path else ""
    if direct_packet_endpoint:
        matched = _select_best_route_candidate(
            route_candidates,
            file_path=file_path,
            method=packet_method,
            path=packet_path,
        )
        if matched:
            return f"{matched['method']} {matched['path']}"
        return direct_packet_endpoint

    if endpoint_path:
        matched = _select_best_route_candidate(
            route_candidates,
            file_path=file_path,
            method=endpoint_method,
            path=endpoint_path,
        )
        if matched:
            return f"{matched['method']} {matched['path']}"
        if endpoint_method not in {"", "UNKNOWN"}:
            return f"{endpoint_method} {endpoint_path}"
        if endpoint_path:
            return endpoint_path

    matched = _select_best_route_candidate(
        route_candidates,
        file_path=file_path,
        method="UNKNOWN",
        path="",
    )
    if matched:
        return f"{matched['method']} {matched['path']}"
    return endpoint_text

def _select_best_route_candidate(
    route_candidates: list[dict],
    *,
    file_path: str,
    method: str,
    path: str,
) -> dict | None:
    scored: list[tuple[int, dict]] = []
    normalized_method = str(method or "").upper()
    normalized_path = _normalize_http_path(path)
    has_specific_route_signal = bool(normalized_path or (normalized_method and normalized_method not in {"", "UNKNOWN", "ANY"}))

    for route in route_candidates:
        if not isinstance(route, dict):
            continue
        route_method = str(route.get("method", "UNKNOWN") or "UNKNOWN").upper()
        route_path = _normalize_http_path(str(route.get("path", "") or "").strip())
        route_file = str(route.get("file_path", "") or "").strip().lower()
        if not route_path:
            continue

        score = 0
        if has_specific_route_signal and file_path and route_file:
            if route_file == file_path:
                score += 12
            elif route_file.endswith("/" + file_path) or file_path.endswith("/" + route_file):
                score += 8
        if normalized_path:
            if route_path == normalized_path:
                score += 20
            elif route_path and normalized_path and (route_path in normalized_path or normalized_path in route_path):
                score += 10
            elif route_path.rsplit("/", 1)[-1] and route_path.rsplit("/", 1)[-1] == normalized_path.rsplit("/", 1)[-1]:
                score += 4
        if normalized_method and normalized_method not in {"UNKNOWN", "ANY"}:
            if route_method == normalized_method:
                score += 6
            elif route_method == "ANY":
                score += 2
            else:
                score -= 4
        if score > 0:
            scored.append((score, route))

    if not scored:
        fallback = [route for route in route_candidates if str(route.get("file_path", "") or "").strip().lower() == file_path]
        if len(fallback) == 1:
            return fallback[0]
        return None

    scored.sort(key=lambda item: (-item[0], item[1].get("path", ""), item[1].get("method", "")))
    return scored[0][1]

def _merge_stage1_routes(response: dict, static_routes: list[dict]) -> dict:
    if not isinstance(response, dict):
        return response

    architecture = response.setdefault("architecture_info", {})
    llm_routes = architecture.get("routes")
    if not isinstance(llm_routes, list):
        llm_routes = []

    merged = []
    seen = set()
    for route in llm_routes + static_routes:
        if not isinstance(route, dict):
            continue
        normalized = {
            "method": str(route.get("method", "UNKNOWN")).upper(),
            "path": route.get("path", ""),
            "handler": route.get("handler", "Unknown"),
            "file_path": route.get("file_path", ""),
            "auth": route.get("auth", "Unknown"),
            "params": route.get("params", []) if isinstance(route.get("params", []), list) else [],
            "notes": route.get("notes", ""),
        }
        key = (normalized["method"], normalized["path"], normalized["handler"], normalized["file_path"])
        if key in seen:
            continue
        seen.add(key)
        merged.append(normalized)

    merged.sort(key=lambda item: (-_route_priority_score(item), item["path"], item["method"], item["handler"]))
    architecture["routes"] = merged
    response["architecture_info"] = architecture
    if "vulnerabilities" not in response or not isinstance(response["vulnerabilities"], list):
        response["vulnerabilities"] = []
    return response

def _route_priority_score(route: dict) -> int:
    if not isinstance(route, dict):
        return 0

    path = str(route.get("path", "")).lower()
    handler = str(route.get("handler", "")).lower()
    file_path = str(route.get("file_path", "")).lower()
    auth = str(route.get("auth", "")).lower()
    method = str(route.get("method", "")).upper()
    score = 0

    critical_path_markers = [
        "/admin", "/auth", "/login", "/token", "/oauth", "/callback", "/webhook",
        "/upload", "/download", "/export", "/import", "/payment", "/order",
        "/user", "/account", "/password", "/reset", "/debug", "/internal",
    ]
    high_value_file_markers = [
        "/controller", "/controllers/", "/routes/", "/router", "urls.py",
        "route.ts", "route.js", "view", "handler", "gateway", "proxy",
    ]
    risky_handler_markers = [
        "login", "auth", "token", "upload", "download", "export", "import",
        "callback", "webhook", "admin", "delete", "update", "create",
    ]

    for marker in critical_path_markers:
        if marker in path:
            score += 4
    for marker in high_value_file_markers:
        if marker in file_path:
            score += 2
    for marker in risky_handler_markers:
        if marker in handler:
            score += 2

    if auth in {"none", ""}:
        score += 2
    elif auth in {"unknown"}:
        score += 1

    if method in {"POST", "PUT", "PATCH", "DELETE", "ANY"}:
        score += 2
    if any(param in path for param in [":", "{", "<"]):
        score += 1

    return score

__all__ = [
    'ROUTE_COVERAGE_AUDITED_STATUSES',
    'ROUTE_COVERAGE_GAP_STATUSES',
    '_normalize_route_coverage_status',
    '_is_route_coverage_status_audited',
    '_is_route_coverage_status_gap',
    '_normalize_route_method',
    '_normalize_route_path',
    '_route_identity',
    '_route_id',
    '_route_with_id',
    '_extract_route_ids_from_lines',
    '_merge_routes_by_id',
    '_normalize_route_coverage_item',
    '_extract_route_coverage_items',
    '_extract_architecture_routes',
    '_extract_stage_coverage_payload',
    '_extract_stage_focus_routes',
    '_extract_stage_focus_route_ids',
    '_extract_stage_route_coverage_items',
    '_public_route_fields',
    '_route_match_path',
    '_route_endpoint_keys',
    '_vulnerability_endpoint_keys',
    '_status_summary_for_route',
    '_build_task_route_coverage_summary',
    '_hydrate_vulnerability_endpoints',
    '_backfill_vulnerability_poc_templates',
    '_collect_endpoint_route_candidates',
    '_find_route_candidate_for_vulnerability',
    '_resolve_vulnerability_endpoint',
    '_select_best_route_candidate',
    '_merge_stage1_routes',
    '_route_priority_score',
]
