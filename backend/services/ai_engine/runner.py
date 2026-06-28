"""Audit orchestration core: stage drivers, retries, enrichment, summary refresh."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from sqlalchemy import delete, select
from models import AuditTask, AuditStage, Vulnerability
from prompts.stage_prompts import SYSTEM_BASE, get_spec_label, get_stage_prompt
from services.audit_cleanup import get_stage_artifact_dir, resolve_audit_artifact_path
from services.audit_runtime import emit_event, EVENT_ARTIFACT_WRITTEN
from services.llm_client import call_llm_with_meta
from services.stable_submission import apply_stage_submissions, consume_response_submissions, preserve_submission_state
from services.vulnerability_review import parse_finding_actions as _parse_finding_actions, snapshot_review_state as _snapshot_review_state, stash_review_state as _stash_review_state

from services.ai_engine._utils import _incremental_submit_stage_nums, _merge_unique_items, _normalize_match_path, _summarize_pre_discovery, _truncate_text
from services.ai_engine._constants import ROUTE_FOLLOWUP_BATCH_SIZE, ROUTE_FOLLOWUP_MAX_BATCHES, SECONDARY_STAGE_CHUNK_LIMIT, SECONDARY_STAGE_MAX_ROUNDS, STAGE1_EARLY_STOP_COVERAGE, STAGE1_MIN_PASSES, STAGE1_STRONG_STOP_COVERAGE, _get_stage_retry_policy
from services.ai_engine.severity import _severity_rank
from services.ai_engine.poc import _classify_poc_requirement, _validate_vulnerability_poc
from services.ai_engine.parser import _build_retry_meta, _coerce_incomplete_stage_response, _coerce_stage_summary, _describe_retry_reason, _extract_stage1_delta, _merge_compressed_summary, _merge_stage1_pass_response, _merge_stage_vulnerability_response, _parse_structured_response, _score_stage_response, _should_retry_incomplete_response, _summarize_architecture_info, _summarize_stage1_pass_outputs
from services.ai_engine.findings import _build_task_severity_stats, _coerce_stage_findings, _stage1_response_with_risk_hints
from services.ai_engine.routes import _backfill_vulnerability_poc_templates, _build_task_route_coverage_summary, _extract_route_coverage_items, _extract_route_ids_from_lines, _hydrate_vulnerability_endpoints, _merge_stage1_routes, _route_priority_score, _route_with_id
from services.ai_engine.vulnerability_store import _enforce_vulnerability_output_policy, _store_vulnerabilities, _vuln_key
from services.ai_engine.stage_schema import validate_stage_output
from services.ai_engine.chunk_selector import _build_stage1_pass_context, _frontload_route_related_stage1_chunks, _select_stage5_chunks, _select_stage_chunks, _split_chunks_for_stage1
from services.ai_engine.prompt_budget import _apply_exploit_stage_prompt_budget, _apply_lightweight_stage_prompt_budget, _apply_stage5_prompt_budget, _apply_stage6_prompt_budget, _apply_stage9_prompt_budget
from services.ai_engine.prompt_builders import _build_audit_memory, _build_exploit_stage_skeleton_retry_prompt, _build_incomplete_json_retry_prompt, _build_lightweight_stage_skeleton_retry_prompt, _build_prev_context, _build_stage1_microcompact_context, _build_stage5_skeleton_retry_prompt, _build_stage9_skeleton_retry_prompt, _build_stage_focus_compact_context, _build_stage_user_prompt, _build_summary_stage_skeleton_retry_prompt, _compact_audit_memory_for_stage, _format_non_stage1_chunks_for_prompt, _format_stage1_chunks_for_prompt, _format_static_route_lines

import logging

logger = logging.getLogger(__name__)

def _is_auto_second_pass_enabled(task: AuditTask) -> bool:
    summary = task.summary if isinstance(task.summary, dict) else {}
    return bool(summary.get("auto_second_pass", False))

async def _is_task_cancelled(session, task_id: int) -> bool:
    result = await session.execute(select(AuditTask.status).where(AuditTask.id == task_id))
    return result.scalar_one_or_none() == "cancelled"


async def _is_task_paused(session, task_id: int) -> bool:
    """GAP3：任务是否已被暂停（/pause 置 ``status="paused"``）。

    与 ``_is_task_cancelled`` 并列；supervisor 在阶段边界用它做协作式让出（暂停后保留已完成阶段，
    /resume 续跑剩余）。paused 非 run 终态（见 ``_TERMINAL_RUN_STATUSES``），故 paused run 保留为历史记录。
    """
    result = await session.execute(select(AuditTask.status).where(AuditTask.id == task_id))
    return result.scalar_one_or_none() == "paused"


async def _is_task_stopping(session, task_id: int) -> bool:
    """supervisor 协作式停机检查：cancelled（终态中止）或 paused（暂停让出）。

    两者在 checkpoint 处的处理相同（``return``，保留 task 当前 status）；统一谓词避免每个 checkpoint
    写两遍。对 cancel 行为零变化（cancelled ⇒ stopping=True）。
    """
    result = await session.execute(select(AuditTask.status).where(AuditTask.id == task_id))
    return result.scalar_one_or_none() in {"cancelled", "paused"}

def _build_stage_coverage_snapshot(compact_context: dict | None, selected_chunks: list[dict]) -> dict:
    compact_context = compact_context if isinstance(compact_context, dict) else {}
    focus_files = compact_context.get("focus_files", []) if isinstance(compact_context.get("focus_files"), list) else []
    focus_routes = compact_context.get("focus_routes", []) if isinstance(compact_context.get("focus_routes"), list) else []
    visible_route_ids = _extract_route_ids_from_lines(compact_context.get("route_lines"))
    visible_route_id_set = set(visible_route_ids)
    normalized_focus_routes = [
        _route_with_id(route)
        for route in focus_routes[:32]
        if isinstance(route, dict) and str(route.get("path", "") or "").strip()
    ]
    if visible_route_id_set:
        normalized_focus_routes = [
            route for route in normalized_focus_routes if route.get("route_id") in visible_route_id_set
        ]
    return {
        "selected_chunk_count": len(selected_chunks),
        "focus_files": focus_files[:40],
        "focus_file_count": len(focus_files),
        "focus_routes": [
            {
                "route_id": route.get("route_id", ""),
                "method": str(route.get("method", "UNKNOWN") or "UNKNOWN").upper(),
                "path": str(route.get("path", "") or "").strip(),
                "handler": str(route.get("handler", "") or "").strip(),
                "file_path": str(route.get("file_path", "") or "").strip(),
                "auth": str(route.get("auth", "") or "").strip(),
            }
            for route in normalized_focus_routes
        ],
        "focus_route_ids": [route.get("route_id", "") for route in normalized_focus_routes if route.get("route_id")],
    }

def _attach_stage_runtime_summary(
    response: dict | list | None,
    *,
    coverage_snapshot: dict,
) -> dict:
    if isinstance(response, dict):
        normalized = dict(response)
    elif isinstance(response, list):
        normalized = {"vulnerabilities": response}
    else:
        normalized = {"vulnerabilities": []}
    normalized["_stage_coverage"] = coverage_snapshot
    route_coverage = _extract_route_coverage_items(normalized)
    if route_coverage:
        focus_ids = set(coverage_snapshot.get("focus_route_ids", []) if isinstance(coverage_snapshot.get("focus_route_ids"), list) else [])
        attested_ids = {item.get("route_id") for item in route_coverage if item.get("route_id")}
        normalized["_stage_coverage"]["attested_route_count"] = len(attested_ids)
        normalized["_stage_coverage"]["missing_focus_route_ids"] = sorted(focus_ids - attested_ids)[:50]
        normalized["_stage_coverage"]["route_coverage"] = route_coverage[:80]
    vulnerabilities = normalized.get("vulnerabilities", [])
    normalized["_vulnerability_count"] = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
    return normalized

def _build_task_rescan_recommendations(vulns: list[Vulnerability], scan_stats: dict) -> list[str]:
    recommendations: list[str] = []
    severity_stats = _build_task_severity_stats(vulns)

    if severity_stats.get("Critical", 0) or severity_stats.get("High", 0):
        recommendations.append("优先复核新增的严重和高危问题，先处理可直接形成利用链的入口点。")

    if scan_stats.get("oversized_files_compacted", 0):
        recommendations.append("本轮存在大文件补偿切片，建议对相关大文件做人工抽查，避免关键信息落在切片边界之外。")

    if (
        scan_stats.get("truncated_files", 0)
        or scan_stats.get("truncated_by_audit_file_count")
        or scan_stats.get("truncated_by_code_chunks")
        or scan_stats.get("truncated_by_total_chars")
    ):
        recommendations.append("存在审计文件数、代码块或总代码截断，建议针对核心入口文件单独精扫，降低上下文截断带来的漏报风险。")

    if int(scan_stats.get("rule_hit_count", 0) or 0) >= max(len(vulns) * 2, 20):
        recommendations.append("规则命中数明显高于入库漏洞数，建议把规则命中最集中的目录作为下一轮定向审计范围。")

    if not recommendations:
        recommendations.append("当前扫描覆盖和结果结构较稳定，下一轮可优先关注新增代码区域和新增高危问题。")

    return recommendations[:5]

def _accumulate_token_usage(task: AuditTask, meta: dict | None) -> None:
    """将单次 LLM 调用的 token 用量累计到 task.summary。"""
    if not isinstance(meta, dict):
        return
    usage = meta.get("usage")
    if not isinstance(usage, dict):
        return
    summary = task.summary if isinstance(task.summary, dict) else {}
    token_stats = summary.get("token_stats", {})
    if not isinstance(token_stats, dict):
        token_stats = {}
    token_stats["prompt_tokens"] = int(token_stats.get("prompt_tokens", 0) or 0) + int(usage.get("prompt_tokens", 0) or 0)
    token_stats["completion_tokens"] = int(token_stats.get("completion_tokens", 0) or 0) + int(usage.get("completion_tokens", 0) or 0)
    token_stats["total_tokens"] = int(token_stats.get("total_tokens", 0) or 0) + int(usage.get("total_tokens", 0) or 0)
    token_stats["llm_call_count"] = int(token_stats.get("llm_call_count", 0) or 0) + 1
    summary["token_stats"] = token_stats
    task.summary = dict(summary)

async def _refresh_task_summary(
    session,
    task: AuditTask,
    *,
    scan_stats: dict | None = None,
    pre_discovery: dict | None = None,
    static_routes: list | None = None,
) -> None:
    await session.flush()
    summary = dict(task.summary) if isinstance(task.summary, dict) else {}
    if isinstance(scan_stats, dict):
        summary["scan_stats"] = scan_stats
    pre_discovery_summary = _summarize_pre_discovery(pre_discovery)
    if pre_discovery_summary:
        summary["pre_discovery"] = pre_discovery_summary

    vuln_result = await session.execute(
        select(Vulnerability)
        .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
        .where(
            Vulnerability.task_id == task.id,
            AuditStage.stage_num.between(2, 9),
        )
        .execution_options(populate_existing=True)
    )
    vulns = list(vuln_result.scalars().all())
    effective_scan_stats = summary.get("scan_stats", {}) if isinstance(summary.get("scan_stats"), dict) else {}
    for stale_key in [
        "verification_stats",
        "candidate_severity_stats",
        "diff_stats",
        "candidate_diff_stats",
    ]:
        summary.pop(stale_key, None)
    summary["total_vulnerabilities"] = len(vulns)
    summary["formal_vulnerability_count"] = len(vulns)
    summary["severity_stats"] = _build_task_severity_stats(vulns)
    summary["rescan_recommendations"] = _build_task_rescan_recommendations(vulns, effective_scan_stats)
    stage_result = await session.execute(
        select(AuditStage)
        .where(AuditStage.task_id == task.id)
        .order_by(AuditStage.stage_num)
        .execution_options(populate_existing=True)
    )
    task_stages = list(stage_result.scalars().all())
    stage1 = next((stage for stage in task_stages if stage.stage_num == 1), None)
    stage1_compressed = stage1.compressed_summary if stage1 and isinstance(stage1.compressed_summary, dict) else {}
    stage1_coverage = stage1_compressed.get("coverage", {}) if isinstance(stage1_compressed.get("coverage"), dict) else {}
    if stage1_coverage:
        total_chunks = max(1, int(stage1_coverage.get("audit_scope_chunk_count") or stage1_coverage.get("total_chunk_count") or 1))
        scanned_chunks = int(stage1_coverage.get("scanned_chunk_count") or 0)
        summary["stage1_coverage"] = {
            "label": str(stage1_coverage.get("audit_scope_label", "审计集覆盖率") or "审计集覆盖率"),
            "ratio": round(scanned_chunks / total_chunks, 4),
            "scope_type": str(stage1_coverage.get("audit_scope_type", "selected_high_value_chunks") or "selected_high_value_chunks"),
            "scope_note": str(stage1_coverage.get("audit_scope_note", "") or ""),
            "covered_file_count": len(stage1_coverage.get("covered_paths", []) or []),
            "audit_scope_file_count": int(stage1_coverage.get("audit_scope_file_count") or 0),
            "scanned_chunk_count": scanned_chunks,
            "audit_scope_chunk_count": int(stage1_coverage.get("audit_scope_chunk_count") or stage1_coverage.get("total_chunk_count") or 0),
        }
    route_coverage_summary = _build_task_route_coverage_summary(
        task_stages,
        static_routes=static_routes,
        scan_stats=effective_scan_stats,
        vulns=vulns,
    )
    if route_coverage_summary:
        summary["route_coverage"] = route_coverage_summary
    else:
        summary.pop("route_coverage", None)
    task.summary = dict(summary)


def _is_route_followup_enabled(task: AuditTask) -> bool:
    summary = task.summary if isinstance(task.summary, dict) else {}
    return summary.get("route_followup_enabled", True) is not False


def _route_followup_text(route: dict) -> str:
    return "\n".join(
        [
            str(route.get("method", "") or ""),
            str(route.get("path", "") or ""),
            str(route.get("handler", "") or ""),
            str(route.get("file_path", "") or ""),
            str(route.get("auth", "") or ""),
        ]
    ).lower()


def _route_followup_stage_score(stage_num: int, route: dict) -> int:
    text = _route_followup_text(route)
    keywords = {
        2: ["exec", "shell", "cmd", "command", "template", "deserialize", "script"],
        3: ["sql", "query", "search", "filter", "datasource", "promql", "clickhouse", "ldap", "redis", "raw", "where"],
        4: ["xss", "html", "render", "template", "redirect", "callback", "comment"],
        5: ["login", "auth", "token", "session", "password", "jwt", "oidc", "apikey", "api_key", "register", "captcha"],
        6: ["user", "role", "tenant", "permission", "admin", "owner", "authz", "acl", "policy", "scope", "team", "project"],
        7: ["config", "setting", "secret", "key", "webhook", "callback", "url", "cors", "debug"],
        8: ["upload", "download", "file", "path", "import", "export", "template", "attachment", "backup"],
        9: ["create", "update", "delete", "reset", "bind", "assign", "approve", "workflow", "order", "payment", "balance"],
    }.get(stage_num, [])
    score = sum(1 for keyword in keywords if keyword in text)
    if stage_num == 6 and any(marker in text for marker in ["user", "role", "tenant", "permission"]):
        score += 2
    if stage_num == 5 and any(marker in text for marker in ["login", "token", "password", "session"]):
        score += 5
    if stage_num == 3 and any(marker in text for marker in ["query", "search", "datasource"]):
        score += 2
    if stage_num == 8 and any(marker in text for marker in ["upload", "download", "file"]):
        score += 2
    return score


def _suggest_route_followup_stage_num(route: dict, completed_stage_nums: set[int]) -> int | None:
    if not completed_stage_nums:
        return None
    preferred = [5, 6, 3, 9, 8, 2, 7, 4]
    candidates = [stage_num for stage_num in preferred if stage_num in completed_stage_nums]
    candidates.extend(stage_num for stage_num in sorted(completed_stage_nums) if stage_num not in candidates)
    if not candidates:
        return None

    return max(
        candidates,
        key=lambda stage_num: (
            _route_followup_stage_score(stage_num, route),
            -preferred.index(stage_num) if stage_num in preferred else -99,
        ),
    )


def _group_missing_routes_for_followup(route_coverage: dict, stages: list[AuditStage]) -> list[tuple[int, list[dict]]]:
    completed_stage_nums = {
        int(stage.stage_num)
        for stage in stages or []
        if 2 <= int(stage.stage_num or 0) <= 9 and stage.status == "completed"
    }
    if not completed_stage_nums:
        return []

    next_routes = route_coverage.get("next_route_batch") if isinstance(route_coverage, dict) else []
    missing_routes = route_coverage.get("missing_routes") if isinstance(route_coverage, dict) else []
    if not isinstance(next_routes, list):
        next_routes = []
    if not isinstance(missing_routes, list):
        missing_routes = []
    candidate_routes = _merge_unique_items(next_routes, missing_routes)
    if not candidate_routes:
        return []

    grouped: dict[int, list[dict]] = {}
    max_routes = max(ROUTE_FOLLOWUP_MAX_BATCHES * ROUTE_FOLLOWUP_BATCH_SIZE * 4, ROUTE_FOLLOWUP_BATCH_SIZE)
    for route in candidate_routes[:max_routes]:
        if not isinstance(route, dict) or not str(route.get("path", "") or "").strip():
            continue
        stage_num = _suggest_route_followup_stage_num(route, completed_stage_nums)
        if stage_num is None:
            continue
        grouped.setdefault(stage_num, []).append(_route_with_id(route))

    ordered_stage_nums = [
        stage_num
        for stage_num, _routes in sorted(
            grouped.items(),
            key=lambda item: (
                -max((_route_priority_score(route) for route in item[1]), default=0),
                item[0],
            ),
        )
    ]
    queues = {
        stage_num: sorted(
            routes,
            key=lambda route: (-_route_priority_score(route), route.get("path", ""), route.get("method", "")),
        )
        for stage_num, routes in grouped.items()
    }
    batches: list[tuple[int, list[dict]]] = []
    while len(batches) < ROUTE_FOLLOWUP_MAX_BATCHES and any(queues.values()):
        progressed = False
        for stage_num in ordered_stage_nums:
            routes = queues.get(stage_num) or []
            if not routes:
                continue
            batches.append((stage_num, routes[:ROUTE_FOLLOWUP_BATCH_SIZE]))
            queues[stage_num] = routes[ROUTE_FOLLOWUP_BATCH_SIZE:]
            progressed = True
            if len(batches) >= ROUTE_FOLLOWUP_MAX_BATCHES:
                break
        if not progressed:
            break
    return batches


def _merge_route_coverage_payloads(base: dict | list | None, incoming: dict | list | None) -> list[dict]:
    if isinstance(base, list):
        base_items = [_extract_route_coverage_items({"route_coverage": base})]
    else:
        base_items = [_extract_route_coverage_items(base)]
    if isinstance(incoming, list):
        incoming_items = [_extract_route_coverage_items({"route_coverage": incoming})]
    else:
        incoming_items = [_extract_route_coverage_items(incoming)]

    merged: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for item in [entry for group in base_items + incoming_items for entry in group]:
        route_id = str(item.get("route_id", "") or "").strip()
        status = str(item.get("status", "") or "").strip()
        reason = str(item.get("reason", "") or "").strip()
        if not route_id:
            continue
        key = (route_id, status, reason)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _route_attestation_gaps(route_batch: list[dict], route_coverage: list[dict]) -> tuple[set[str], set[str], list[str]]:
    required_route_ids = {
        str(route.get("route_id", "") or "").strip()
        for route in route_batch
        if str(route.get("route_id", "") or "").strip()
    }
    attested_route_ids = {
        str(item.get("route_id", "") or "").strip()
        for item in route_coverage
        if str(item.get("route_id", "") or "").strip() in required_route_ids
    }
    missing_attestation_route_ids = sorted(required_route_ids - attested_route_ids)
    return required_route_ids, attested_route_ids, missing_attestation_route_ids


def _build_route_followup_attestation_retry_prompt(stage: AuditStage, routes: list[dict], selected_response: dict | list) -> str:
    route_lines = _format_static_route_lines(routes, total_count=len(routes))
    route_lines_text = "\n".join(str(line) for line in route_lines) if isinstance(route_lines, list) else str(route_lines or "")
    route_ids = [
        str(route.get("route_id", "") or "").strip()
        for route in routes
        if str(route.get("route_id", "") or "").strip()
    ]
    previous_summary = ""
    if isinstance(selected_response, dict):
        previous_summary = _truncate_text(str(selected_response.get("stage_summary", "") or ""), 900)
    skeleton = {
        "stage_summary": "route coverage attestation retry",
        "vulnerabilities": [],
        "route_coverage": [
            {
                "route_id": route_id,
                "status": "audited_no_finding",
                "reason": "one sentence based on the already reviewed evidence",
            }
            for route_id in route_ids
        ],
    }
    return "\n".join(
        [
            "Route coverage attestation retry.",
            f"Stage {stage.stage_num}: {stage.stage_name}",
            "The prior follow-up response did not attest every required route_id.",
            "Return only valid JSON. Do not add unrelated vulnerabilities.",
            "route_coverage must contain exactly one item for every Required route_id.",
            "Allowed status values: audited_no_finding, finding, skipped_with_reason, insufficient_context, not_applicable.",
            f"Required route_ids: {', '.join(route_ids)}",
            "Routes:",
            route_lines_text,
            "Previous stage summary:",
            previous_summary,
            "JSON skeleton:",
            json.dumps(skeleton, ensure_ascii=False),
        ]
    )


async def _retry_missing_route_attestations(
    *,
    llm_config,
    task: AuditTask,
    stage: AuditStage,
    route_batch: list[dict],
    missing_route_ids: list[str],
    selected_response: dict | list,
) -> tuple[dict | list, dict]:
    missing_id_set = set(missing_route_ids)
    missing_routes = [
        route for route in route_batch
        if str(route.get("route_id", "") or "").strip() in missing_id_set
    ]
    retry_meta = {
        "triggered": bool(missing_routes),
        "route_ids": [route.get("route_id", "") for route in missing_routes if route.get("route_id")],
    }
    if not missing_routes:
        retry_meta["success"] = False
        retry_meta["reason"] = "no_missing_routes"
        return selected_response, retry_meta

    prompt = _build_route_followup_attestation_retry_prompt(stage, missing_routes, selected_response)
    retry_meta["prompt_length"] = len(prompt)
    llm_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, prompt)
    _accumulate_token_usage(task, llm_result.get("meta"))
    retry_meta["success"] = bool(llm_result.get("success"))
    if not llm_result.get("success"):
        retry_meta["error"] = llm_result.get("error", {}).get("message", "route attestation retry failed")
        return selected_response, retry_meta

    retry_response = _parse_structured_response(llm_result["content"], llm_result.get("meta"))
    retry_coverage = _extract_route_coverage_items(retry_response, stage_num=stage.stage_num)
    retry_attested_ids = {
        str(item.get("route_id", "") or "").strip()
        for item in retry_coverage
        if str(item.get("route_id", "") or "").strip() in missing_id_set
    }
    retry_meta["attested_route_count"] = len(retry_attested_ids)
    retry_meta["missing_attestation_route_ids"] = sorted(missing_id_set - retry_attested_ids)[:20]
    retry_meta["success"] = not retry_meta["missing_attestation_route_ids"]

    if isinstance(selected_response, dict):
        merged = _merge_stage_vulnerability_response(selected_response, retry_response)
    else:
        merged = _merge_stage_vulnerability_response(
            {"vulnerabilities": selected_response if isinstance(selected_response, list) else []},
            retry_response,
        )
    route_coverage = _merge_route_coverage_payloads(merged, retry_response)
    if route_coverage:
        merged["route_coverage"] = route_coverage
    return merged, retry_meta


def _merge_stage_coverage_payload(base: dict | None, incoming: dict | None) -> dict:
    base = dict(base) if isinstance(base, dict) else {}
    incoming = dict(incoming) if isinstance(incoming, dict) else {}
    merged = dict(base)
    merged["focus_routes"] = _merge_unique_items(base.get("focus_routes"), incoming.get("focus_routes"))
    focus_ids: list[str] = []
    for route_id in list(base.get("focus_route_ids") or []) + list(incoming.get("focus_route_ids") or []):
        route_id = str(route_id or "").strip()
        if route_id and route_id not in focus_ids:
            focus_ids.append(route_id)
    if focus_ids:
        merged["focus_route_ids"] = focus_ids
    route_coverage = _merge_route_coverage_payloads(
        base.get("route_coverage") if isinstance(base.get("route_coverage"), list) else [],
        incoming.get("route_coverage") if isinstance(incoming.get("route_coverage"), list) else [],
    )
    if route_coverage:
        merged["route_coverage"] = route_coverage[:160]
        attested_ids = {item.get("route_id") for item in route_coverage if item.get("route_id")}
        merged["attested_route_count"] = len(attested_ids)
        if focus_ids:
            merged["missing_focus_route_ids"] = sorted(set(focus_ids) - attested_ids)[:50]
    merged["selected_chunk_count"] = max(int(base.get("selected_chunk_count", 0) or 0), int(incoming.get("selected_chunk_count", 0) or 0))
    merged["focus_file_count"] = max(int(base.get("focus_file_count", 0) or 0), int(incoming.get("focus_file_count", 0) or 0))
    merged["focus_files"] = _merge_unique_items(base.get("focus_files"), incoming.get("focus_files"))[:60]
    return merged


def _merge_route_followup_response(stage: AuditStage, response: dict | list, coverage_snapshot: dict, meta: dict) -> dict:
    base = _coerce_stage_findings(stage.findings)
    incoming = response if isinstance(response, dict) else {"vulnerabilities": response if isinstance(response, list) else []}
    merged = _merge_stage_vulnerability_response(base, incoming)
    route_coverage = _merge_route_coverage_payloads(base, incoming)
    if route_coverage:
        merged["route_coverage"] = route_coverage
    followups = list(base.get("_route_followups", [])) if isinstance(base.get("_route_followups"), list) else []
    followups.append(meta)
    merged["_route_followups"] = followups[-10:]

    existing_compressed = stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {}
    incoming_summary = _attach_stage_runtime_summary(incoming, coverage_snapshot=coverage_snapshot)
    compressed = dict(existing_compressed)
    compressed["_stage_coverage"] = _merge_stage_coverage_payload(
        existing_compressed.get("_stage_coverage") if isinstance(existing_compressed.get("_stage_coverage"), dict) else {},
        incoming_summary.get("_stage_coverage") if isinstance(incoming_summary.get("_stage_coverage"), dict) else {},
    )
    compressed_followups = list(compressed.get("_route_followups", [])) if isinstance(compressed.get("_route_followups"), list) else []
    compressed_followups.append(meta)
    compressed["_route_followups"] = compressed_followups[-10:]
    stage.compressed_summary = preserve_submission_state(stage, compressed)
    return merged


def _build_route_followup_guidance(routes: list[dict]) -> str:
    route_ids = ", ".join(str(route.get("route_id", "")) for route in routes if route.get("route_id"))
    return "\n".join(
        [
            "Route coverage follow-up pass.",
            "Only audit the listed missing routes. Do not repeat unrelated vulnerabilities.",
            f"Required route_ids: {route_ids}",
            "Return top-level route_coverage for every listed route_id.",
            "Use audited_no_finding, finding, skipped_with_reason, insufficient_context, or not_applicable.",
            "If a real issue is found, include it in vulnerabilities and align endpoint/route_id to the listed route.",
        ]
    )


def _apply_followup_prompt_budget(stage_num: int, compact_context: dict, code_text: str, prev_context: str) -> tuple[dict, str, str]:
    if stage_num in {2, 3, 4, 8}:
        return _apply_exploit_stage_prompt_budget(compact_context, code_text, prev_context, stage_num=stage_num)
    if stage_num == 5:
        return _apply_stage5_prompt_budget(compact_context, code_text, prev_context)
    if stage_num == 6:
        return _apply_stage6_prompt_budget(compact_context, code_text, prev_context)
    if stage_num == 7:
        return _apply_lightweight_stage_prompt_budget(compact_context, code_text, prev_context, stage_num=stage_num)
    return _apply_stage9_prompt_budget(compact_context, code_text, prev_context)


def _build_route_followup_artifact_path(task_id: int, stage_num: int, batch_index: int) -> str:
    os.makedirs(get_stage_artifact_dir(task_id), exist_ok=True)
    return os.path.join("data", "stage_artifacts", str(task_id), f"stage_{stage_num}_route_followup_{batch_index}.json")


async def _run_route_followup_batch(
    *,
    session,
    task: AuditTask,
    stage: AuditStage,
    llm_config,
    project,
    code_chunks: list[dict],
    static_routes: list[dict],
    audit_memory: dict,
    prev_context: str,
    source_sink_hints: list[dict],
    routes: list[dict],
    batch_index: int,
) -> dict:
    route_file_paths = [
        str(route.get("file_path", "") or "").strip()
        for route in routes
        if str(route.get("file_path", "") or "").strip()
    ]
    selected_chunks = _select_stage_chunks(
        stage.stage_num,
        code_chunks,
        static_routes=static_routes,
        audit_memory=audit_memory,
        source_sink_hints=source_sink_hints,
        focus_files=route_file_paths,
    )[:16]
    route_batch = [_route_with_id(route) for route in routes]
    compact_context = _build_stage_focus_compact_context(
        stage=stage,
        project=project,
        static_routes=static_routes,
        selected_chunks=selected_chunks,
        audit_memory=audit_memory,
        rule_hits=[],
        source_sink_hints=source_sink_hints,
        forced_routes=route_batch,
    )
    compact_context["focus_routes"] = route_batch
    compact_context["route_lines"] = _format_static_route_lines(route_batch, total_count=len(route_batch))
    compact_context["route_text_limit"] = 3200
    compact_context["extra_guidance"] = "\n".join(
        part
        for part in [
            str(compact_context.get("extra_guidance", "") or "").strip(),
            _build_route_followup_guidance(route_batch),
        ]
        if part
    )
    code_text = _format_non_stage1_chunks_for_prompt(selected_chunks, stage.stage_num, audit_memory=audit_memory)
    compact_context, code_text, effective_prev_context = _apply_followup_prompt_budget(
        stage.stage_num,
        compact_context,
        code_text,
        _truncate_text(prev_context or "", 1000),
    )
    user_prompt = _build_stage_user_prompt(
        stage,
        project,
        get_stage_prompt(stage.stage_num),
        code_text,
        effective_prev_context,
        static_routes,
        compact_context=compact_context,
        audit_memory=audit_memory,
    )
    llm_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, user_prompt)
    _accumulate_token_usage(task, llm_result.get("meta"))
    batch_meta = {
        "batch_index": batch_index,
        "stage_num": stage.stage_num,
        "route_count": len(route_batch),
        "route_ids": [route.get("route_id", "") for route in route_batch if route.get("route_id")],
        "selected_chunk_count": len(selected_chunks),
        "prompt_length": len(user_prompt),
        "success": bool(llm_result.get("success")),
    }
    if not llm_result.get("success"):
        batch_meta["error"] = llm_result.get("error", {}).get("message", "route follow-up failed")
        return batch_meta

    response = _parse_structured_response(llm_result["content"], llm_result.get("meta"))
    retry_policy = _get_stage_retry_policy(stage.stage_num)
    _, selected_response, retry_meta = await _retry_incomplete_stage_response(
        llm_config=llm_config,
        stage=stage,
        project=project,
        stage_prompt=get_stage_prompt(stage.stage_num),
        code_text=code_text,
        prev_context=effective_prev_context,
        static_routes=static_routes,
        compact_context=compact_context,
        audit_memory=audit_memory,
        initial_result=llm_result,
        initial_response=response,
        retry_policy=retry_policy,
    )
    selected_response, local_recovery_applied = _coerce_incomplete_stage_response(
        stage_num=stage.stage_num,
        response=selected_response,
        retry_policy=retry_policy,
    )
    if local_recovery_applied:
        retry_meta["local_recovery_applied"] = True
    selected_response = await _enrich_vulnerability_details(
        llm_config=llm_config,
        stage=stage,
        project=project,
        stage_prompt=get_stage_prompt(stage.stage_num),
        response=selected_response,
        code_text=code_text,
        prev_context=effective_prev_context,
        static_routes=static_routes,
    )
    if isinstance(selected_response, dict):
        selected_response = _hydrate_vulnerability_endpoints(
            response=selected_response,
            static_routes=static_routes,
            audit_memory=audit_memory,
        )
        selected_response = _backfill_vulnerability_poc_templates(
            stage_num=stage.stage_num,
            response=selected_response,
            static_routes=static_routes,
            audit_memory=audit_memory,
        )
        selected_response, policy_meta = _enforce_vulnerability_output_policy(stage, selected_response)
    else:
        selected_response, policy_meta = _enforce_vulnerability_output_policy(stage, {"vulnerabilities": selected_response if isinstance(selected_response, list) else []})

    coverage_snapshot = _build_stage_coverage_snapshot(compact_context, selected_chunks)
    route_coverage = _extract_route_coverage_items(selected_response, stage_num=stage.stage_num)
    _, attested_route_ids, missing_attestation_route_ids = _route_attestation_gaps(route_batch, route_coverage)
    if missing_attestation_route_ids:
        selected_response, attestation_retry_meta = await _retry_missing_route_attestations(
            llm_config=llm_config,
            task=task,
            stage=stage,
            route_batch=route_batch,
            missing_route_ids=missing_attestation_route_ids,
            selected_response=selected_response,
        )
        batch_meta["attestation_retry"] = attestation_retry_meta
        route_coverage = _extract_route_coverage_items(selected_response, stage_num=stage.stage_num)
        _, attested_route_ids, missing_attestation_route_ids = _route_attestation_gaps(route_batch, route_coverage)
    batch_meta["attested_route_count"] = len(attested_route_ids)
    batch_meta["missing_attestation_count"] = len(missing_attestation_route_ids)
    batch_meta["missing_attestation_route_ids"] = missing_attestation_route_ids[:20]
    if missing_attestation_route_ids:
        batch_meta["success"] = False
        batch_meta["failure_reason"] = "missing_required_route_coverage"
    batch_meta["retry"] = retry_meta
    if policy_meta:
        batch_meta["policy"] = policy_meta
    merged_findings = _merge_route_followup_response(stage, selected_response, coverage_snapshot, batch_meta)
    stage.findings = merged_findings
    vulns = selected_response.get("vulnerabilities", []) if isinstance(selected_response, dict) else []
    batch_meta["new_vulnerability_count"] = await _store_vulnerabilities(session, task, stage, vulns)

    artifact_path = _build_route_followup_artifact_path(task.id, stage.stage_num, batch_index)
    _persist_single_stage_artifact(
        artifact_path=artifact_path,
        task_id=task.id,
        stage=stage,
        compact_context=compact_context,
        selected_chunks=selected_chunks,
        code_text=code_text,
        audit_memory=audit_memory,
        response=selected_response if isinstance(selected_response, dict) else {"vulnerabilities": []},
        execution_meta={"route_followup": batch_meta},
    )
    await _emit_artifact_written(session, task, stage, artifact_path)
    return batch_meta


async def _run_missing_route_followup(
    session,
    task: AuditTask,
    stages: list[AuditStage],
    llm_config,
    project,
    code_chunks: list[dict],
    static_routes: list[dict],
    scan_stats: dict | None,
    pre_discovery: dict | None,
    source_sink_hints: list[dict] | None = None,
) -> dict:
    if not _is_route_followup_enabled(task):
        return {"triggered": False, "reason": "disabled"}

    await _refresh_task_summary(
        session,
        task,
        scan_stats=scan_stats,
        pre_discovery=pre_discovery,
        static_routes=static_routes,
    )
    summary = task.summary if isinstance(task.summary, dict) else {}
    route_coverage = summary.get("route_coverage") if isinstance(summary.get("route_coverage"), dict) else {}
    if not route_coverage or int(route_coverage.get("missing_route_count", 0) or 0) <= 0:
        return {"triggered": False, "reason": "no_missing_routes"}

    batches = _group_missing_routes_for_followup(route_coverage, stages)
    if not batches:
        return {"triggered": False, "reason": "no_executable_batches"}

    stage_map = {int(stage.stage_num): stage for stage in stages if 2 <= int(stage.stage_num or 0) <= 9}
    batch_results: list[dict] = []
    for batch_index, (stage_num, routes) in enumerate(batches, start=1):
        stage = stage_map.get(stage_num)
        if not stage or stage.status != "completed":
            continue
        audit_memory = _build_audit_memory(list(stages), current_stage_num=stage_num)
        prev_context = _build_prev_context(audit_memory)
        batch_meta = await _run_route_followup_batch(
            session=session,
            task=task,
            stage=stage,
            llm_config=llm_config,
            project=project,
            code_chunks=code_chunks,
            static_routes=static_routes,
            audit_memory=audit_memory,
            prev_context=prev_context,
            source_sink_hints=source_sink_hints or [],
            routes=routes,
            batch_index=batch_index,
        )
        batch_results.append(batch_meta)
        await session.commit()

    await _refresh_task_summary(
        session,
        task,
        scan_stats=scan_stats,
        pre_discovery=pre_discovery,
        static_routes=static_routes,
    )
    final_summary = task.summary if isinstance(task.summary, dict) else {}
    route_followup = {
        "triggered": bool(batch_results),
        "batch_count": len(batch_results),
        "batches": batch_results,
        "initial_missing_route_count": int(route_coverage.get("missing_route_count", 0) or 0),
        "final_missing_route_count": int((final_summary.get("route_coverage") or {}).get("missing_route_count", 0) or 0)
        if isinstance(final_summary.get("route_coverage"), dict)
        else None,
    }
    final_summary["route_followup"] = route_followup
    task.summary = dict(final_summary)
    await session.commit()
    return route_followup

def _apply_schema_gate(stage, response):
    """§10.2 阶段输出 schema quality gate：成功归一化 dict，失败保留原始 + warn（降级不阻断）。"""
    if not isinstance(response, dict):
        return response
    kind = "stage1" if stage.stage_num == 1 else "vulnerability"
    validated, err = validate_stage_output(kind, response)
    if validated is not None:
        return validated
    if err:
        logger.warning("Stage %s output schema validation failed, keeping raw findings: %s", stage.stage_num, err[:200])
    return response


async def _apply_stage_payload(stage, stage_payload: dict, session=None, task=None, static_routes=None, audit_memory=None):
    """Apply stage execution result to the stage object (findings, prompt, artifact)."""
    response = stage_payload["response"]
    stage.prompt_used = stage_payload["prompt_used"]
    stage.llm_response = stage_payload["llm_response"]
    if isinstance(stage_payload.get("compressed_summary"), (dict, list)):
        stage.compressed_summary = preserve_submission_state(stage, stage_payload["compressed_summary"])
    if stage_payload.get("artifact_path"):
        stage.artifact_path = stage_payload["artifact_path"]

    response, submission_stats = consume_response_submissions(stage, response)

    if isinstance(response, dict):
        if stage.stage_num == 1:
            response = _stage1_response_with_risk_hints(response)
            if static_routes is not None:
                response = _merge_stage1_routes(response, static_routes)
        elif static_routes is not None and audit_memory is not None:
            response = _hydrate_vulnerability_endpoints(
                response=response,
                static_routes=static_routes,
                audit_memory=audit_memory,
            )
            response = _backfill_vulnerability_poc_templates(
                stage_num=stage.stage_num,
                response=response,
                static_routes=static_routes,
                audit_memory=audit_memory,
            )
        response = apply_stage_submissions(stage, response)
        if stage.stage_num != 1:
            response, _ = _enforce_vulnerability_output_policy(stage, response)
        response = _apply_schema_gate(stage, response)
        if submission_stats and isinstance(response, dict):
            response["_stable_submission_stats"] = submission_stats
        stage.findings = response
    elif isinstance(response, list):
        if stage.stage_num == 1:
            response = apply_stage_submissions(stage, _stage1_response_with_risk_hints(response))
            if submission_stats and isinstance(response, dict):
                response["_stable_submission_stats"] = submission_stats
            stage.findings = response
        else:
            normalized_payload = {"vulnerabilities": response}
            if static_routes is not None and audit_memory is not None:
                normalized_payload = _hydrate_vulnerability_endpoints(
                    response=normalized_payload,
                    static_routes=static_routes,
                    audit_memory=audit_memory,
                )
                normalized_payload = _backfill_vulnerability_poc_templates(
                    stage_num=stage.stage_num,
                    response=normalized_payload,
                    static_routes=static_routes,
                    audit_memory=audit_memory,
                )
            normalized_payload = apply_stage_submissions(stage, normalized_payload)
            normalized_response, _ = _enforce_vulnerability_output_policy(stage, normalized_payload)
            response = _apply_schema_gate(stage, normalized_response)
            if submission_stats and isinstance(response, dict):
                response["_stable_submission_stats"] = submission_stats
            stage.findings = response
    else:
        if stage.stage_num == 1:
            response = apply_stage_submissions(
                stage,
                {"raw_response": str(response)[:5000], "risk_hints": [], "vulnerabilities": []},
            )
            if submission_stats and isinstance(response, dict):
                response["_stable_submission_stats"] = submission_stats
            stage.findings = response
        else:
            response = apply_stage_submissions(stage, {"raw_response": str(response)[:5000], "vulnerabilities": []})
            response, _ = _enforce_vulnerability_output_policy(stage, response)
            response = _apply_schema_gate(stage, response)
            if submission_stats and isinstance(response, dict):
                response["_stable_submission_stats"] = submission_stats
            stage.findings = response

    if session and task and stage.stage_num != 1:
        findings = stage.findings.get("vulnerabilities", []) if isinstance(stage.findings, dict) else stage.findings
        # M5b：开启增量提交的阶段，从 actions 中补提 findings（默认关闭，零行为变化）
        if stage.stage_num in _incremental_submit_stage_nums():
            action_findings = _parse_finding_actions(stage.findings if isinstance(stage.findings, dict) else stage.llm_response)
            if action_findings:
                findings = (findings if isinstance(findings, list) else []) + action_findings
        await _store_vulnerabilities(session, task, stage, findings)

async def _run_single_pass_stage(
    session,
    task,
    stage,
    llm_config,
    project,
    stage_prompt,
    selected_chunks,
    code_chunks,
    static_routes,
    prev_context,
    audit_memory,
    rule_hits,
    source_sink_hints,
    supervisor_focus: str | None = None,
    forced_routes: list | None = None,
):
    if supervisor_focus:
        stage_prompt = f"{supervisor_focus}\n\n{stage_prompt}"
    prompt_selected_chunks = selected_chunks
    compact_context = _build_stage_focus_compact_context(
        stage=stage,
        project=project,
        static_routes=static_routes,
        selected_chunks=prompt_selected_chunks,
        audit_memory=audit_memory,
        rule_hits=rule_hits,
        source_sink_hints=source_sink_hints,
        forced_routes=forced_routes,
    )
    code_text = _format_non_stage1_chunks_for_prompt(prompt_selected_chunks, stage.stage_num, audit_memory=audit_memory)
    effective_prev_context = prev_context
    if stage.stage_num in {2, 3, 4, 8}:
        effective_prev_context = _truncate_text(prev_context or "", 1800)
        compact_context, code_text, effective_prev_context = _apply_exploit_stage_prompt_budget(
            compact_context=compact_context,
            code_text=code_text,
            prev_context=effective_prev_context or "",
            stage_num=stage.stage_num,
        )
    elif stage.stage_num == 5:
        effective_prev_context = _truncate_text(prev_context or "", 1800)
        compact_context, code_text, effective_prev_context = _apply_stage5_prompt_budget(
            compact_context=compact_context,
            code_text=code_text,
            prev_context=effective_prev_context or "",
        )
    elif stage.stage_num == 6:
        effective_prev_context = _truncate_text(prev_context or "", 2800)
        compact_context, code_text, effective_prev_context = _apply_stage6_prompt_budget(
            compact_context=compact_context,
            code_text=code_text,
            prev_context=effective_prev_context or "",
        )
    elif stage.stage_num == 7:
        effective_prev_context = _truncate_text(prev_context or "", 1200)
        compact_context, code_text, effective_prev_context = _apply_lightweight_stage_prompt_budget(
            compact_context=compact_context,
            code_text=code_text,
            prev_context=effective_prev_context or "",
            stage_num=stage.stage_num,
        )
    elif stage.stage_num == 9:
        effective_prev_context = _truncate_text(prev_context or "", 1800)
        compact_context, code_text, effective_prev_context = _apply_stage9_prompt_budget(
            compact_context=compact_context,
            code_text=code_text,
            prev_context=effective_prev_context or "",
        )
    artifact_path = _build_stage_artifact_path(task.id, stage.stage_num)
    user_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        code_text,
        effective_prev_context,
        static_routes,
        compact_context=compact_context,
        audit_memory=audit_memory,
    )
    if stage.stage_num in {2, 3, 4, 5, 6, 7, 8, 9}:
        over_budget = (
            (stage.stage_num in {2, 3, 4, 8} and len(user_prompt) > 22000)
            or (stage.stage_num == 5 and len(user_prompt) > 18000)
            or (stage.stage_num == 6 and len(user_prompt) > 24000)
            or (stage.stage_num == 9 and len(user_prompt) > 22000)
        )
        if over_budget:
            if stage.stage_num in {2, 3, 4, 8}:
                compact_context, code_text, effective_prev_context = _apply_exploit_stage_prompt_budget(
                    compact_context=compact_context,
                    code_text=code_text,
                    prev_context=effective_prev_context or "",
                    stage_num=stage.stage_num,
                    aggressive=True,
                )
            elif stage.stage_num == 5:
                compact_context, code_text, effective_prev_context = _apply_stage5_prompt_budget(
                    compact_context=compact_context,
                    code_text=code_text,
                    prev_context=effective_prev_context or "",
                    aggressive=True,
                )
            elif stage.stage_num == 6:
                compact_context, code_text, effective_prev_context = _apply_stage6_prompt_budget(
                    compact_context=compact_context,
                    code_text=code_text,
                    prev_context=effective_prev_context or "",
                    aggressive=True,
                )
            elif stage.stage_num == 7:
                compact_context, code_text, effective_prev_context = _apply_lightweight_stage_prompt_budget(
                    compact_context=compact_context,
                    code_text=code_text,
                    prev_context=effective_prev_context or "",
                    stage_num=stage.stage_num,
                    aggressive=True,
                )
            elif stage.stage_num == 9:
                compact_context, code_text, effective_prev_context = _apply_stage9_prompt_budget(
                    compact_context=compact_context,
                    code_text=code_text,
                    prev_context=effective_prev_context or "",
                    aggressive=True,
                )
            user_prompt = _build_stage_user_prompt(
                stage,
                project,
                stage_prompt,
                code_text,
                effective_prev_context,
                static_routes,
                compact_context=compact_context,
                audit_memory=audit_memory,
            )

    prompt_used = json.dumps(
        {
            "system_prompt": SYSTEM_BASE,
            "user_prompt": user_prompt,
            "debug": {
                "spec_label": get_spec_label(),
                "stage_num": stage.stage_num,
                "selected_chunk_count": len(prompt_selected_chunks),
                "available_chunk_count": len(code_chunks),
                "code_text_length": len(code_text),
                "user_prompt_length": len(user_prompt),
                "static_route_count": len(static_routes) if stage.stage_num == 1 else None,
                "prev_context_length": len(effective_prev_context or ""),
                "focus_route_count": len(compact_context.get("route_lines", []) or []),
                "focus_file_count": len(compact_context.get("focus_files", []) or []),
                "pass_count": 1,
                "exploit_prompt_budget_applied": stage.stage_num in {2, 3, 4, 8},
                "lightweight_prompt_budget_applied": stage.stage_num == 7,
                "stage5_prompt_budget_applied": stage.stage_num == 5,
                "stage6_prompt_budget_applied": stage.stage_num == 6,
                "stage9_prompt_budget_applied": stage.stage_num == 9,
            },
        },
        ensure_ascii=False,
    )
    stage.prompt_used = prompt_used
    stage.artifact_path = artifact_path
    await session.commit()
    _persist_single_stage_artifact(
        artifact_path=artifact_path,
        task_id=task.id,
        stage=stage,
        compact_context=compact_context,
        selected_chunks=prompt_selected_chunks,
        code_text=code_text,
        audit_memory=audit_memory,
        response={},
        execution_meta={"retry": {"triggered": False}},
    )

    if await _is_task_cancelled(session, task.id):
        stage.status = "cancelled"
        stage.completed_at = datetime.now(timezone.utc)
        await session.commit()
        return {"response": {"vulnerabilities": []}, "prompt_used": prompt_used, "llm_response": "", "artifact_path": artifact_path}

    # M5：删除前快照复核状态，重插时按 dedupe_key carry-forward
    _stash_review_state(task, await _snapshot_review_state(session, task.id, [stage.id]))
    await session.execute(delete(Vulnerability).where(Vulnerability.stage_id == stage.id))
    await session.commit()

    llm_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, user_prompt)
    _accumulate_token_usage(task, llm_result.get("meta"))
    if not llm_result["success"]:
        raise RuntimeError(json.dumps({
            "message": llm_result["error"]["message"],
            "meta": llm_result.get("meta"),
            "error": llm_result.get("error"),
            "prompt_length": len(user_prompt),
            "stage_num": stage.stage_num,
        }, ensure_ascii=False))
    response = _parse_structured_response(llm_result["content"], llm_result.get("meta"))
    retry_policy = _get_stage_retry_policy(stage.stage_num)
    selected_result, selected_response, retry_meta = await _retry_incomplete_stage_response(
        llm_config=llm_config,
        stage=stage,
        project=project,
        stage_prompt=stage_prompt,
        code_text=code_text,
        prev_context=prev_context,
        static_routes=static_routes,
        compact_context=compact_context,
        audit_memory=audit_memory,
        initial_result=llm_result,
        initial_response=response,
        retry_policy=retry_policy,
    )
    selected_response, local_recovery_applied = _coerce_incomplete_stage_response(
        stage_num=stage.stage_num,
        response=selected_response,
        retry_policy=retry_policy,
    )
    if local_recovery_applied:
        retry_meta["local_recovery_applied"] = True
    selected_response = await _enrich_vulnerability_details(
        llm_config=llm_config,
        stage=stage,
        project=project,
        stage_prompt=stage_prompt,
        response=selected_response,
        code_text=code_text,
        prev_context=prev_context,
        static_routes=static_routes,
    )
    stage5_followup_meta = {"triggered": False}
    if stage.stage_num == 5 and isinstance(selected_response, dict) and _should_run_stage5_followup_scan(selected_response, retry_meta):
        selected_response, stage5_followup_meta = await _run_stage5_followup_scan(
            llm_config=llm_config,
            stage=stage,
            project=project,
            stage_prompt=stage_prompt,
            code_chunks=code_chunks,
            static_routes=static_routes,
            prev_context=prev_context,
            audit_memory=audit_memory,
            selected_chunks=prompt_selected_chunks,
            current_response=selected_response,
            source_sink_hints=source_sink_hints,
        )
    second_pass_meta = {"triggered": False}
    if _is_auto_second_pass_enabled(task) and _should_run_secondary_stage_pass(stage.stage_num, selected_response):
        selected_response, second_pass_meta = await _run_secondary_stage_pass(
            llm_config=llm_config,
            stage=stage,
            project=project,
            stage_prompt=stage_prompt,
            code_chunks=code_chunks,
            static_routes=static_routes,
            prev_context=prev_context,
            audit_memory=audit_memory,
            selected_chunks=prompt_selected_chunks,
            current_response=selected_response,
            source_sink_hints=source_sink_hints,
        )

    llm_response = json.dumps(
        {
            "meta": selected_result.get("meta", {}),
            "content": selected_result["content"][:8000],
            "retry": retry_meta,
            "stage5_followup": stage5_followup_meta,
            "second_pass": second_pass_meta,
        },
        ensure_ascii=False,
    )[:10000]
    coverage_snapshot = _build_stage_coverage_snapshot(compact_context, prompt_selected_chunks)
    compressed_summary = _attach_stage_runtime_summary(
        selected_response,
        coverage_snapshot=coverage_snapshot,
    )
    _persist_single_stage_artifact(
        artifact_path=artifact_path,
        task_id=task.id,
        stage=stage,
        compact_context=compact_context,
        selected_chunks=prompt_selected_chunks,
        code_text=code_text,
        audit_memory=audit_memory,
        response=compressed_summary,
        execution_meta={"retry": retry_meta, "stage5_followup": stage5_followup_meta, "second_pass": second_pass_meta},
    )
    await _emit_artifact_written(session, task, stage, artifact_path)

    return {
        "response": selected_response,
        "prompt_used": prompt_used,
        "llm_response": llm_response,
        "compressed_summary": compressed_summary,
        "artifact_path": artifact_path,
        "repair_code_text": code_text,
        "repair_prev_context": effective_prev_context,
    }

async def _run_stage1_multi_pass(
    session,
    task,
    stage,
    llm_config,
    project,
    stage_prompt,
    selected_chunks,
    code_chunks,
    static_routes,
    prev_context,
    audit_memory,
    rule_hits,
    source_sink_hints,
    pre_discovery: dict | None = None,
):
    selected_chunks = _frontload_route_related_stage1_chunks(selected_chunks, static_routes)
    total_selected_chunk_count = len(selected_chunks)
    total_selected_file_count = len(
        {
            str(chunk.get("file_path", "") or "").strip().lower()
            for chunk in selected_chunks
            if str(chunk.get("file_path", "") or "").strip()
        }
    )
    chunk_batches = _split_chunks_for_stage1(selected_chunks, pre_discovery=pre_discovery)
    pass_outputs = []
    merged_response = {"stage_summary": "", "architecture_info": {}, "risk_hints": [], "vulnerabilities": []}
    compressed_summary = _coerce_stage_summary(stage.compressed_summary)
    artifact_path = _build_stage_artifact_path(task.id, stage.stage_num)
    early_stop = {"triggered": False, "reason": "", "after_pass": 0}

    stage.prompt_used = json.dumps(
        {
            "system_prompt": SYSTEM_BASE,
                "debug": {
                    "spec_label": get_spec_label(),
                    "stage_num": stage.stage_num,
                    "selected_chunk_count": total_selected_chunk_count,
                    "available_chunk_count": len(code_chunks),
                    "batch_count": len(chunk_batches),
                    "static_route_count": len(static_routes),
                    "prev_context_length": len(prev_context or ""),
                    "summary_mode": "compressed_summary",
            },
        },
        ensure_ascii=False,
    )
    stage.compressed_summary = compressed_summary
    stage.artifact_path = artifact_path
    await session.commit()
    _persist_stage_pass_artifact(
        artifact_path=artifact_path,
        task_id=task.id,
        stage_id=stage.id,
        pass_outputs=pass_outputs,
        compressed_summary=compressed_summary,
        merged_response=merged_response,
        static_routes=static_routes,
        early_stop=early_stop,
    )

    if await _is_task_cancelled(session, task.id):
        stage.status = "cancelled"
        stage.completed_at = datetime.now(timezone.utc)
        await session.commit()
        return {"response": merged_response, "prompt_used": stage.prompt_used, "llm_response": ""}

    # M5：删除前快照复核状态，重插时按 dedupe_key carry-forward
    _stash_review_state(task, await _snapshot_review_state(session, task.id, [stage.id]))
    await session.execute(delete(Vulnerability).where(Vulnerability.stage_id == stage.id))
    await session.commit()

    for pass_index, chunk_batch in enumerate(chunk_batches, start=1):
        if await _is_task_cancelled(session, task.id):
            stage.status = "cancelled"
            stage.completed_at = datetime.now(timezone.utc)
            await session.commit()
            return {"response": merged_response, "prompt_used": stage.prompt_used, "llm_response": stage.llm_response or ""}

        batch_code_text, code_compaction = _format_stage1_chunks_for_prompt(
            chunk_batch,
            compressed_summary,
            pass_index,
        )
        batch_prev_context = _build_stage1_pass_context(prev_context, compressed_summary, pass_index, len(chunk_batches))
        microcompact_context = _build_stage1_microcompact_context(
            project=project,
            static_routes=static_routes,
            compressed_summary=compressed_summary,
            chunk_batch=chunk_batch,
            pass_index=pass_index,
            total_passes=len(chunk_batches),
            pre_discovery=pre_discovery,
        )
        user_prompt = _build_stage_user_prompt(
            stage,
            project,
            stage_prompt,
            batch_code_text,
            batch_prev_context,
            static_routes,
            compact_context=microcompact_context,
            audit_memory=audit_memory,
        )

        llm_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, user_prompt)
        _accumulate_token_usage(task, llm_result.get("meta"))
        if not llm_result["success"]:
            raise RuntimeError(json.dumps({
                "message": llm_result["error"]["message"],
                "meta": llm_result.get("meta"),
                "error": llm_result.get("error"),
                "prompt_length": len(user_prompt),
                "stage_num": stage.stage_num,
                "pass_index": pass_index,
            }, ensure_ascii=False))

        initial_response = _parse_structured_response(llm_result["content"], llm_result.get("meta"))
        retry_policy = _get_stage_retry_policy(stage.stage_num)
        selected_result, response, retry_meta = await _retry_incomplete_stage_response(
            llm_config=llm_config,
            stage=stage,
            project=project,
            stage_prompt=stage_prompt,
            code_text=batch_code_text,
            prev_context=batch_prev_context,
            static_routes=static_routes,
            compact_context=microcompact_context,
            audit_memory=audit_memory,
            initial_result=llm_result,
            initial_response=initial_response,
            retry_policy=retry_policy,
        )
        response = _stage1_response_with_risk_hints(response)
        summary_delta = _extract_stage1_delta(response)
        pass_progress = _assess_stage1_pass_progress(
            compressed_summary,
            summary_delta,
            chunk_batch,
            total_selected_chunk_count,
            static_routes=static_routes,
        )
        pass_outputs.append(
            {
                "pass_index": pass_index,
                "chunk_count": len(chunk_batch),
                "code_text_length": len(batch_code_text),
                "user_prompt_length": len(user_prompt),
                "chunk_files": [chunk.get("file_path", "") for chunk in chunk_batch[:40]],
                "meta": selected_result.get("meta", {}),
                "content": selected_result["content"][:2000],
                "retry": retry_meta,
                "summary_delta": summary_delta,
                "progress": pass_progress,
                "microcompact": {
                    "project_tree_len": len(microcompact_context.get("project_tree_summary", "")),
                    "route_line_count": len(microcompact_context.get("route_lines", []) or []),
                    "focus_file_count": len(microcompact_context.get("focus_files", []) or []),
                    "compacted_chunk_count": code_compaction.get("compacted_chunk_count", 0),
                    "compacted_path_count": len(code_compaction.get("compacted_paths", []) or []),
                    "signal_window_chunk_count": code_compaction.get("signal_window_chunk_count", 0),
                },
            }
        )
        merged_response = _merge_stage1_pass_response(merged_response, response)
        compressed_summary = _merge_compressed_summary(
            compressed_summary,
            summary_delta,
            chunk_batch,
            total_selected_chunk_count,
            total_selected_file_count=total_selected_file_count,
            compression_stats=code_compaction,
        )
        stage.compressed_summary = compressed_summary
        await session.commit()

        early_stop_reason = _should_stop_stage1_early(
            pass_index=pass_index,
            total_passes=len(chunk_batches),
            pass_progress=pass_progress,
            must_cover_uncovered=_count_must_cover_uncovered(compressed_summary, pre_discovery),
        )
        if early_stop_reason:
            early_stop = {
                "triggered": True,
                "reason": early_stop_reason,
                "after_pass": pass_index,
            }
            pass_outputs[-1]["early_stop_reason"] = early_stop_reason

        _persist_stage_pass_artifact(
            artifact_path=artifact_path,
            task_id=task.id,
            stage_id=stage.id,
            pass_outputs=pass_outputs,
            compressed_summary=compressed_summary,
            merged_response=merged_response,
            static_routes=static_routes,
            early_stop=early_stop,
        )

        if early_stop_reason:
            break

    _persist_stage_pass_artifact(
        artifact_path=artifact_path,
        task_id=task.id,
        stage_id=stage.id,
        pass_outputs=pass_outputs,
        compressed_summary=compressed_summary,
        merged_response=merged_response,
        static_routes=static_routes,
        early_stop=early_stop,
    )
    await _emit_artifact_written(session, task, stage, artifact_path)

    # Back-fill missing routes into compressed_summary so audit_memory carries them forward
    final_gap = _build_stage1_route_gap_summary(static_routes or [], compressed_summary)
    missing_routes = final_gap.get("missing_route_samples", [])
    if missing_routes:
        existing_routes = compressed_summary.get("architecture_info", {}).get("routes", [])
        if isinstance(existing_routes, list):
            compressed_summary.setdefault("architecture_info", {})["routes"] = existing_routes + missing_routes[:60]

    merged_code_text = _truncate_text(
        _format_non_stage1_chunks_for_prompt(selected_chunks, stage.stage_num, audit_memory=audit_memory),
        16000,
    )
    merged_response = await _enrich_vulnerability_details(
        llm_config=llm_config,
        stage=stage,
        project=project,
        stage_prompt=stage_prompt,
        response=merged_response,
        code_text=merged_code_text,
        prev_context=prev_context,
        static_routes=static_routes,
    )
    merged_response = _stage1_response_with_risk_hints(merged_response)

    prompt_used = json.dumps(
        {
            "system_prompt": SYSTEM_BASE,
            "debug": {
                "spec_label": get_spec_label(),
                "stage_num": stage.stage_num,
                "selected_chunk_count": total_selected_chunk_count,
                "available_chunk_count": len(code_chunks),
                "batch_count": len(chunk_batches),
                "static_route_count": len(static_routes),
                "prev_context_length": len(prev_context or ""),
                "artifact_path": artifact_path,
                "planned_batch_count": len(chunk_batches),
                "executed_batch_count": len(pass_outputs),
                "early_stop": early_stop,
                "passes": [
                    {
                        "pass_index": item["pass_index"],
                        "chunk_count": item["chunk_count"],
                        "code_text_length": item["code_text_length"],
                        "user_prompt_length": item["user_prompt_length"],
                    }
                    for item in pass_outputs
                ],
            },
        },
        ensure_ascii=False,
    )
    llm_response = json.dumps(
        {
            "pass_count": len(pass_outputs),
            "passes": pass_outputs[-6:],
        },
        ensure_ascii=False,
    )[:10000]

    # Gap analysis
    gap_analysis = _run_stage1_gap_analysis(merged_response, static_routes, pre_discovery, compressed_summary)
    if isinstance(merged_response, dict):
        merged_response.setdefault("architecture_info", {})
        merged_response["architecture_info"]["_gap_analysis"] = gap_analysis
    compressed_summary = _attach_stage_runtime_summary(
        compressed_summary,
        coverage_snapshot={
            "selected_chunk_count": len(selected_chunks),
            "focus_files": [chunk.get("file_path", "") for chunk in selected_chunks[:40] if chunk.get("file_path")],
            "focus_file_count": len({chunk.get("file_path", "") for chunk in selected_chunks if chunk.get("file_path")}),
            "focus_routes": [
                {
                    "method": str(route.get("method", "UNKNOWN") or "UNKNOWN").upper(),
                    "path": str(route.get("path", "") or "").strip(),
                    "handler": str(route.get("handler", "") or "").strip(),
                    "file_path": str(route.get("file_path", "") or "").strip(),
                    "auth": str(route.get("auth", "") or "").strip(),
                }
                for route in (merged_response.get("architecture_info", {}).get("routes", []) or [])[:60]
                if isinstance(route, dict) and str(route.get("path", "") or "").strip()
            ],
        },
    )

    return {
        "response": merged_response,
        "prompt_used": prompt_used,
        "llm_response": llm_response,
        "compressed_summary": compressed_summary,
        "artifact_path": artifact_path,
        "repair_code_text": merged_code_text,
        "repair_prev_context": prev_context,
    }

async def _retry_incomplete_stage_response(
    *,
    llm_config,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    initial_result: dict,
    initial_response: dict | list,
    retry_policy: dict,
) -> tuple[dict, dict | list, dict]:
    selected_result = initial_result
    selected_response = initial_response
    retry_meta = _build_retry_meta(initial_response, retry_policy)

    if not _should_retry_incomplete_response(stage.stage_num, initial_response):
        return selected_result, selected_response, retry_meta

    retry_prompt = _build_incomplete_json_retry_prompt(
        stage=stage,
        project=project,
        stage_prompt=stage_prompt,
        code_text=code_text,
        prev_context=prev_context,
        static_routes=static_routes,
        compact_context=compact_context,
        audit_memory=audit_memory,
        previous_raw_response=initial_result["content"],
        retry_policy=retry_policy,
    )
    retry_meta.update(
        {
            "triggered": True,
            "reason": _describe_retry_reason(initial_response),
            "prompt_length": len(retry_prompt),
        }
    )

    retry_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, retry_prompt)
    retry_meta["success"] = bool(retry_result.get("success"))
    if not retry_result["success"]:
        retry_meta["error"] = retry_result.get("error", {}).get("message", "retry failed")
        return selected_result, selected_response, retry_meta

    retry_response = _parse_structured_response(retry_result["content"], retry_result.get("meta"))
    retry_meta["retry_parse_error"] = bool(
        isinstance(retry_response, dict) and retry_response.get("parse_error")
    )
    retry_meta["retry_response_incomplete"] = bool(
        isinstance(retry_response, dict) and retry_response.get("response_incomplete")
    )
    retry_meta["retry_salvaged"] = bool(
        isinstance(retry_response, dict) and retry_response.get("_salvaged")
    )
    if _score_stage_response(retry_response) >= _score_stage_response(initial_response):
        selected_result = retry_result
        selected_response = retry_response
        retry_meta["selected_attempt"] = "retry"

    if stage.stage_num in {2, 3, 4, 5, 7, 8, 9} and _should_retry_incomplete_response(stage.stage_num, selected_response):
        second_policy = dict(retry_policy)
        second_policy["max_vulnerabilities"] = min(int(second_policy.get("max_vulnerabilities", 3) or 3), 2)
        second_policy["code_limit"] = min(int(second_policy.get("code_limit", 18000) or 18000), 12000)
        second_policy["prev_context_limit"] = min(int(second_policy.get("prev_context_limit", 1200) or 1200), 700)
        second_policy["route_limit"] = min(int(second_policy.get("route_limit", 8) or 8), 5)

        second_retry_prompt = _build_incomplete_json_retry_prompt(
            stage=stage,
            project=project,
            stage_prompt=stage_prompt,
            code_text=code_text,
            prev_context=prev_context,
            static_routes=static_routes,
            compact_context=compact_context,
            audit_memory=audit_memory,
            previous_raw_response=selected_result["content"],
            retry_policy=second_policy,
        )
        retry_meta["second_retry_triggered"] = True
        retry_meta["second_retry_prompt_length"] = len(second_retry_prompt)

        second_retry_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, second_retry_prompt)
        retry_meta["second_retry_success"] = bool(second_retry_result.get("success"))
        if second_retry_result.get("success"):
            second_retry_response = _parse_structured_response(second_retry_result["content"], second_retry_result.get("meta"))
            retry_meta["second_retry_parse_error"] = bool(
                isinstance(second_retry_response, dict) and second_retry_response.get("parse_error")
            )
            retry_meta["second_retry_response_incomplete"] = bool(
                isinstance(second_retry_response, dict) and second_retry_response.get("response_incomplete")
            )
            retry_meta["second_retry_salvaged"] = bool(
                isinstance(second_retry_response, dict) and second_retry_response.get("_salvaged")
            )
            if _score_stage_response(second_retry_response) >= _score_stage_response(selected_response):
                selected_result = second_retry_result
                selected_response = second_retry_response
                retry_meta["selected_attempt"] = "second_retry"

    if stage.stage_num in {2, 3, 4, 5, 7, 8, 9} and _should_retry_incomplete_response(stage.stage_num, selected_response):
        if stage.stage_num in {2, 3, 4, 8}:
            skeleton_prompt = _build_exploit_stage_skeleton_retry_prompt(
                stage=stage,
                project=project,
                stage_prompt=stage_prompt,
                code_text=code_text,
                prev_context=prev_context,
                static_routes=static_routes,
                compact_context=compact_context,
                audit_memory=audit_memory,
                previous_raw_response=selected_result["content"],
            )
        elif stage.stage_num == 5:
            skeleton_prompt = _build_stage5_skeleton_retry_prompt(
                stage=stage,
                project=project,
                stage_prompt=stage_prompt,
                code_text=code_text,
                prev_context=prev_context,
                static_routes=static_routes,
                compact_context=compact_context,
                audit_memory=audit_memory,
                previous_raw_response=selected_result["content"],
            )
        elif stage.stage_num == 7:
            skeleton_prompt = _build_lightweight_stage_skeleton_retry_prompt(
                stage=stage,
                project=project,
                stage_prompt=stage_prompt,
                code_text=code_text,
                prev_context=prev_context,
                static_routes=static_routes,
                compact_context=compact_context,
                audit_memory=audit_memory,
                previous_raw_response=selected_result["content"],
            )
        elif stage.stage_num == 9:
            skeleton_prompt = _build_stage9_skeleton_retry_prompt(
                stage=stage,
                project=project,
                stage_prompt=stage_prompt,
                code_text=code_text,
                prev_context=prev_context,
                static_routes=static_routes,
                compact_context=compact_context,
                audit_memory=audit_memory,
                previous_raw_response=selected_result["content"],
            )
        else:
            skeleton_prompt = _build_summary_stage_skeleton_retry_prompt(
                stage=stage,
                project=project,
                stage_prompt=stage_prompt,
                code_text=code_text,
                prev_context=prev_context,
                static_routes=static_routes,
                compact_context=compact_context,
                audit_memory=audit_memory,
                previous_raw_response=selected_result["content"],
            )
        retry_meta["skeleton_retry_triggered"] = True
        retry_meta["skeleton_retry_prompt_length"] = len(skeleton_prompt)

        skeleton_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, skeleton_prompt)
        retry_meta["skeleton_retry_success"] = bool(skeleton_result.get("success"))
        if skeleton_result.get("success"):
            skeleton_response = _parse_structured_response(skeleton_result["content"], skeleton_result.get("meta"))
            retry_meta["skeleton_retry_parse_error"] = bool(
                isinstance(skeleton_response, dict) and skeleton_response.get("parse_error")
            )
            retry_meta["skeleton_retry_response_incomplete"] = bool(
                isinstance(skeleton_response, dict) and skeleton_response.get("response_incomplete")
            )
            retry_meta["skeleton_retry_salvaged"] = bool(
                isinstance(skeleton_response, dict) and skeleton_response.get("_salvaged")
            )
            if _score_stage_response(skeleton_response) >= _score_stage_response(selected_response):
                selected_result = skeleton_result
                selected_response = skeleton_response
                retry_meta["selected_attempt"] = "skeleton_retry"

    return selected_result, selected_response, retry_meta

def _needs_vulnerability_detail_enrichment(stage_num: int, vuln: dict) -> bool:
    if not isinstance(vuln, dict):
        return False

    requirement = _classify_poc_requirement(stage_num, vuln)
    required_fields = ["code_snippet", "description", "fix_suggestion"]
    if requirement != "none":
        required_fields.append("poc_raw")
    for field in required_fields:
        if not str(vuln.get(field, "") or "").strip():
            return True

    # 已有 POC 非空但不合规时，也要进入补全，否则 invalid 会直接落库。
    validation = vuln.get("_poc_validation")
    if not isinstance(validation, dict):
        validation = _validate_vulnerability_poc(stage_num, vuln)
    if not validation.get("accepted") and requirement != "none":
        return True
    return bool(vuln.get("_salvaged"))

def _vulnerability_detail_priority(vuln: dict) -> int:
    if not isinstance(vuln, dict):
        return 0

    score = _severity_rank(vuln.get("severity")) * 100
    if vuln.get("_salvaged"):
        score += 40
    if not str(vuln.get("poc_raw", "") or "").strip():
        score += 30
    if not str(vuln.get("code_snippet", "") or "").strip():
        score += 20
    if not str(vuln.get("fix_suggestion", "") or "").strip():
        score += 10
    if str(vuln.get("endpoint", "") or "").strip():
        score += 8
    if str(vuln.get("file_path", "") or "").strip():
        score += 5
    validation = vuln.get("_poc_validation")
    if isinstance(validation, dict) and not validation.get("accepted"):
        score += 35
    return score

def _build_vulnerability_detail_prompt(
    *,
    stage,
    stage_prompt: str,
    vulnerability: dict,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
) -> str:
    route_text = ""
    if static_routes:
        route_text = _truncate_text("\n".join(_format_static_route_lines(static_routes[:20], total_count=len(static_routes))), 2400)

    vulnerability_seed = json.dumps(vulnerability, ensure_ascii=False, indent=2)
    requirement = _classify_poc_requirement(stage.stage_num, vulnerability)
    validation = vulnerability.get("_poc_validation")
    validation_reason = ""
    if isinstance(validation, dict) and validation.get("reason"):
        validation_reason = str(validation.get("reason") or "").strip()

    poc_requirement_text = {
        "raw_http": "当前漏洞必须输出完整 raw HTTP 请求包，至少包含请求行、Host、必要 Header 和请求体（如需要），并与 endpoint 对齐。",
        "stepwise": "当前漏洞允许使用步骤化 PoC，也允许给出完整 raw HTTP 请求包；如果使用步骤化描述，必须写清前置条件、攻击步骤和预期结果。",
        "cli": "当前漏洞允许使用命令行验证、配置 diff、日志/环境变量检查或完整 raw HTTP 请求包，不要只写一句笼统判断。",
        "none": "当前漏洞允许写“无需 PoC，凭代码证据即可确认”，但 description 必须明确代码证据与影响。",
    }.get(requirement, "请根据漏洞类型提供可复现的 PoC，不要编造不存在的请求。")

    validation_guidance = ""
    if validation_reason:
        validation_guidance = f"当前漏洞上一次 PoC 校验未通过，原因：{validation_reason}。补全时优先修正这个问题。"

    return "\n".join(
        [
            "补全单条漏洞详情。只补全当前这一个漏洞，不要新增其他漏洞。",
            "必须返回单个合法 JSON 对象，不要返回数组，不要输出 Markdown。",
            "严格禁止修改以下字段：title、severity、vuln_type、file_path、line_start、line_end、endpoint。这些字段必须与输入完全一致，不得升级严重性或更改漏洞类型。",
            "只允许补强以下字段：code_snippet、poc_raw、description、fix_suggestion。",
            "如果代码证据不足以支持完整漏洞结论，保持原字段并将 description 写得更谨慎，但仍只基于代码证据。",
            poc_requirement_text,
            validation_guidance or "若确实无法从代码推出完整内容，则保留原值，不要编造。",
            "",
            "[当前阶段要求]",
            stage_prompt,
            "",
            "[待补全漏洞]",
            vulnerability_seed,
            "",
            "[前序上下文]",
            _truncate_text(prev_context or "", 1800) if prev_context else "无",
            "",
            "[静态路由线索]",
            route_text or "无",
            "",
            "[相关代码]",
            _truncate_text(code_text or "", 12000),
            "",
            "返回单个 JSON 对象。",
        ]
    )

async def _enrich_vulnerability_details(
    *,
    llm_config,
    stage,
    project,
    stage_prompt: str,
    response: dict | list,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
) -> dict | list:
    if not isinstance(response, dict):
        return response

    vulnerabilities = response.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return response

    policy = _get_stage_retry_policy(stage.stage_num)
    max_items = int(policy.get("detail_enrichment_max_items", 4) or 0)
    concurrency = max(1, int(policy.get("detail_enrichment_concurrency", 2) or 1))
    if max_items <= 0:
        return response

    candidates = [
        (index, vuln)
        for index, vuln in enumerate(vulnerabilities)
        if isinstance(vuln, dict) and _needs_vulnerability_detail_enrichment(stage.stage_num, vuln)
    ]
    if not candidates:
        return response

    candidates.sort(
        key=lambda item: (
            -_vulnerability_detail_priority(item[1]),
            item[0],
        )
    )
    candidate_indexes = {
        index for index, _ in candidates[:max_items]
    }

    semaphore = asyncio.Semaphore(concurrency)

    async def enrich_one(vuln: dict) -> dict:
        prompt = _build_vulnerability_detail_prompt(
            stage=stage,
            stage_prompt=stage_prompt,
            vulnerability=vuln,
            code_text=code_text,
            prev_context=prev_context,
            static_routes=static_routes,
        )
        async with semaphore:
            detail_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, prompt)
        if not detail_result.get("success"):
            return vuln

        detail_response = _parse_structured_response(detail_result["content"], detail_result.get("meta"))
        if not isinstance(detail_response, dict) or detail_response.get("parse_error"):
            return vuln

        merged = dict(vuln)
        for field in [
            "title",
            "severity",
            "vuln_type",
            "file_path",
            "line_start",
            "line_end",
            "endpoint",
            "code_snippet",
            "poc_raw",
            "description",
            "fix_suggestion",
        ]:
            value = detail_response.get(field)
            if value is None:
                continue
            if isinstance(value, str):
                if value.strip():
                    merged[field] = value
            else:
                merged[field] = value

        merged["_detail_enriched"] = True
        return merged

    enrichment_tasks = {
        index: asyncio.create_task(enrich_one(vuln))
        for index, vuln in candidates[:max_items]
    }

    enriched_vulns: list[dict] = []
    changed = False
    for index, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        if index not in candidate_indexes:
            enriched_vulns.append(vuln)
            continue

        enriched = await enrichment_tasks[index]
        enriched_vulns.append(enriched)
        if enriched is not vuln:
            changed = True

    if not changed:
        return response

    normalized = dict(response)
    normalized["vulnerabilities"] = enriched_vulns
    normalized["_details_enriched"] = True
    normalized["_detail_enrichment_policy"] = {
        "max_items": max_items,
        "concurrency": concurrency,
    }
    normalized["_detail_enrichment_count"] = sum(
        1 for vuln in enriched_vulns if isinstance(vuln, dict) and vuln.get("_detail_enriched")
    )
    return normalized

def _should_run_stage5_followup_scan(response: dict | list, retry_meta: dict | None = None) -> bool:
    if not isinstance(response, dict):
        return False
    if response.get("parse_error") or response.get("response_incomplete"):
        return False
    vulnerabilities = response.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return False
    if len(vulnerabilities) <= 2:
        return True
    if isinstance(retry_meta, dict) and retry_meta.get("selected_attempt") in {"second_retry", "skeleton_retry"}:
        return True
    return False

def _should_run_secondary_stage_pass(stage_num: int, response: dict | list | None = None) -> bool:
    if stage_num not in {2, 3, 4, 5, 6, 7, 8, 9}:
        return False
    if not isinstance(response, dict):
        return True
    if response.get("parse_error") or response.get("response_incomplete") or response.get("_salvaged"):
        return True
    vulns = response.get("vulnerabilities", [])
    if isinstance(vulns, list) and len(vulns) < 3:
        return True
    return False

def _select_secondary_stage_chunks(
    *,
    stage_num: int,
    code_chunks: list[dict],
    selected_chunks: list[dict],
    static_routes: list[dict],
    audit_memory: dict | None = None,
    source_sink_hints: list[dict] | None = None,
    already_scanned_paths: set[str] | None = None,
    chunk_limit: int = SECONDARY_STAGE_CHUNK_LIMIT,
) -> list[dict]:
    selected_paths = {
        str(chunk.get("file_path", "")).strip().lower()
        for chunk in selected_chunks
        if isinstance(chunk, dict) and str(chunk.get("file_path", "")).strip()
    }
    selected_paths |= {str(path).strip().lower() for path in (already_scanned_paths or set()) if str(path).strip()}
    remaining = [
        chunk
        for chunk in code_chunks
        if str(chunk.get("file_path", "")).strip().lower() not in selected_paths
    ]
    if not remaining:
        return []

    preferred_remaining = [
        chunk
        for chunk in remaining
        if not _is_low_signal_secondary_chunk(chunk)
    ]
    if not preferred_remaining:
        return []
    secondary_pool = preferred_remaining
    selected = _select_stage_chunks(
        stage_num,
        secondary_pool,
        static_routes=static_routes,
        audit_memory=audit_memory,
        source_sink_hints=source_sink_hints,
    )[: max(1, chunk_limit)]
    return selected

def _is_low_signal_secondary_chunk(chunk: dict) -> bool:
    file_path = str(chunk.get("base_file_path") or chunk.get("file_path") or "").strip().lower()
    if not file_path:
        return False
    low_signal_suffixes = (".md", ".txt", ".rst")
    if file_path.endswith(low_signal_suffixes):
        return True
    return "/document/" in file_path or "/docs/" in file_path or file_path.startswith("document/")

def _build_secondary_pass_prev_context(prev_context: str, response: dict) -> str:
    parts = [str(prev_context or "").strip()]
    stage_summary = str(response.get("stage_summary", "") or "").strip()
    if stage_summary:
        parts.append("当前轮次已确认摘要：")
        parts.append(stage_summary[:700])
    vulnerabilities = response.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list) and vulnerabilities:
        parts.append("当前轮次已确认漏洞排除清单：")
        for vuln in vulnerabilities[:8]:
            if not isinstance(vuln, dict):
                continue
            parts.append(
                "- "
                + f"{str(vuln.get('title', '') or '').strip()[:100]} | "
                + f"type={str(vuln.get('vuln_type', '') or '').strip()[:60]} | "
                + f"file={str(vuln.get('file_path', '') or '').strip()[:180]} | "
                + f"endpoint={str(vuln.get('endpoint', '') or '').strip()[:180]}"
            )
    return _truncate_text("\n".join([part for part in parts if part]).strip(), 1400)

def _build_secondary_pass_guidance(response: dict) -> str:
    lines = [
        "当前为自动二次审计补漏轮次。",
        "以下已确认问题必须视为排除集，不要重复输出相同漏洞、同一路径同一根因的等价变体，优先寻找不同根因、不同入口、不同参数链的新问题。",
        "若仅能找到与排除集本质相同的问题，请不要重复列出。",
    ]
    vulnerabilities = response.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list) and vulnerabilities:
        lines.append("【首轮已确认漏洞】")
        for vuln in vulnerabilities[:8]:
            if not isinstance(vuln, dict):
                continue
            lines.append(
                "- "
                + f"{str(vuln.get('title', '') or '').strip()[:100]} | "
                + f"type={str(vuln.get('vuln_type', '') or '').strip()[:60]} | "
                + f"file={str(vuln.get('file_path', '') or '').strip()[:180]} | "
                + f"endpoint={str(vuln.get('endpoint', '') or '').strip()[:180]}"
            )
    return "\n".join(lines)

async def _run_secondary_stage_pass(
    *,
    llm_config,
    stage,
    project,
    stage_prompt: str,
    code_chunks: list[dict],
    static_routes: list[dict],
    prev_context: str,
    audit_memory: dict | None,
    selected_chunks: list[dict],
    current_response: dict,
    source_sink_hints: list[dict] | None = None,
) -> tuple[dict, dict]:
    if not isinstance(current_response, dict):
        return current_response, {"triggered": False, "reason": "current_response_not_dict"}

    merged_response = current_response
    scanned_paths: set[str] = set()
    round_meta: list[dict] = []

    # 二次补扫改为有限多轮，逐轮覆盖剩余高价值代码，而不是只补一次固定小样本。
    for round_index in range(1, SECONDARY_STAGE_MAX_ROUNDS + 1):
        if round_index > 1 and not _should_run_secondary_stage_pass(stage.stage_num, merged_response):
            break

        secondary_chunks = _select_secondary_stage_chunks(
            stage_num=stage.stage_num,
            code_chunks=code_chunks,
            selected_chunks=selected_chunks,
            static_routes=static_routes,
            audit_memory=audit_memory,
            source_sink_hints=source_sink_hints,
            already_scanned_paths=scanned_paths,
        )
        if not secondary_chunks:
            if round_index == 1:
                return current_response, {"triggered": False, "reason": "no_secondary_chunks", "rounds": []}
            break

        compact_context = _build_stage_focus_compact_context(
            stage=stage,
            project=project,
            static_routes=static_routes,
            selected_chunks=secondary_chunks,
            audit_memory=audit_memory,
            rule_hits=[],
            source_sink_hints=source_sink_hints,
        )
        base_code_text = _format_non_stage1_chunks_for_prompt(secondary_chunks, stage.stage_num, audit_memory=audit_memory)
        effective_prev_context = _build_secondary_pass_prev_context(prev_context, merged_response)
        if stage.stage_num in {2, 3, 4, 8}:
            compact_context, base_code_text, effective_prev_context = _apply_exploit_stage_prompt_budget(
                compact_context=compact_context,
                code_text=base_code_text,
                prev_context=effective_prev_context,
                stage_num=stage.stage_num,
                aggressive=True,
            )
        elif stage.stage_num == 5:
            compact_context, base_code_text, effective_prev_context = _apply_stage5_prompt_budget(
                compact_context=compact_context,
                code_text=base_code_text,
                prev_context=effective_prev_context,
                aggressive=True,
            )
        elif stage.stage_num == 6:
            compact_context, base_code_text, effective_prev_context = _apply_stage6_prompt_budget(
                compact_context=compact_context,
                code_text=base_code_text,
                prev_context=effective_prev_context,
                aggressive=True,
            )
        elif stage.stage_num == 7:
            compact_context, base_code_text, effective_prev_context = _apply_lightweight_stage_prompt_budget(
                compact_context=compact_context,
                code_text=base_code_text,
                prev_context=effective_prev_context,
                stage_num=stage.stage_num,
                aggressive=True,
            )
        else:
            compact_context, base_code_text, effective_prev_context = _apply_stage9_prompt_budget(
                compact_context=compact_context,
                code_text=base_code_text,
                prev_context=effective_prev_context,
                aggressive=True,
            )

        compact_context["extra_guidance"] = "\n".join(
            [part for part in [str(compact_context.get("extra_guidance", "") or "").strip(), _build_secondary_pass_guidance(merged_response)] if part]
        )
        user_prompt = _build_stage_user_prompt(
            stage,
            project,
            stage_prompt,
            base_code_text,
            effective_prev_context,
            static_routes,
            compact_context=compact_context,
            audit_memory=audit_memory,
        )
        llm_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, user_prompt)
        current_round_meta = {
            "round_index": round_index,
            "selected_chunk_count": len(secondary_chunks),
            "prompt_length": len(user_prompt),
            "success": bool(llm_result.get("success")),
            "selected_files": [
                str(chunk.get("file_path", "") or "").strip()
                for chunk in secondary_chunks[:24]
                if str(chunk.get("file_path", "") or "").strip()
            ],
        }
        if not llm_result.get("success"):
            current_round_meta["error"] = llm_result.get("error", {}).get("message", "second pass failed")
            round_meta.append(current_round_meta)
            return merged_response if round_index > 1 else current_response, {
                "triggered": round_index > 1,
                "selected_chunk_count": sum(int(item.get("selected_chunk_count", 0) or 0) for item in round_meta),
                "round_count": len(round_meta),
                "rounds": round_meta,
                "success": False,
            }

        response = _parse_structured_response(llm_result["content"], llm_result.get("meta"))
        retry_policy = _get_stage_retry_policy(stage.stage_num)
        _, selected_response, retry_meta = await _retry_incomplete_stage_response(
            llm_config=llm_config,
            stage=stage,
            project=project,
            stage_prompt=stage_prompt,
            code_text=base_code_text,
            prev_context=effective_prev_context,
            static_routes=static_routes,
            compact_context=compact_context,
            audit_memory=audit_memory,
            initial_result=llm_result,
            initial_response=response,
            retry_policy=retry_policy,
        )
        selected_response, local_recovery_applied = _coerce_incomplete_stage_response(
            stage_num=stage.stage_num,
            response=selected_response,
            retry_policy=retry_policy,
        )
        if local_recovery_applied:
            retry_meta["local_recovery_applied"] = True
        selected_response = await _enrich_vulnerability_details(
            llm_config=llm_config,
            stage=stage,
            project=project,
            stage_prompt=stage_prompt,
            response=selected_response,
            code_text=base_code_text,
            prev_context=effective_prev_context,
            static_routes=static_routes,
        )

        previous_vuln_count = len(merged_response.get("vulnerabilities", []) if isinstance(merged_response.get("vulnerabilities"), list) else [])
        merged_response = _merge_stage_vulnerability_response(merged_response, selected_response)
        merged_response["_second_pass_applied"] = True
        current_round_meta["retry"] = retry_meta
        current_round_meta["new_vulnerability_count"] = max(
            0,
            len(merged_response.get("vulnerabilities", []) if isinstance(merged_response.get("vulnerabilities"), list) else []) - previous_vuln_count,
        )
        round_meta.append(current_round_meta)
        scanned_paths.update(
            str(chunk.get("file_path", "")).strip().lower()
            for chunk in secondary_chunks
            if str(chunk.get("file_path", "")).strip()
        )

    if not round_meta:
        return current_response, {"triggered": False, "reason": "no_secondary_chunks", "rounds": []}

    return merged_response, {
        "triggered": True,
        "selected_chunk_count": sum(int(item.get("selected_chunk_count", 0) or 0) for item in round_meta),
        "round_count": len(round_meta),
        "rounds": round_meta,
        "success": all(bool(item.get("success")) for item in round_meta),
        "new_vulnerability_count": sum(int(item.get("new_vulnerability_count", 0) or 0) for item in round_meta),
    }

def _select_stage5_followup_chunks(
    code_chunks: list[dict],
    already_selected_chunks: list[dict],
    static_routes: list[dict],
    audit_memory: dict | None = None,
    source_sink_hints: list[dict] | None = None,
) -> list[dict]:
    selected_paths = {
        str(chunk.get("file_path", "")).strip().lower()
        for chunk in already_selected_chunks
        if isinstance(chunk, dict) and str(chunk.get("file_path", "")).strip()
    }
    remaining = [
        chunk
        for chunk in code_chunks
        if str(chunk.get("file_path", "")).strip().lower() not in selected_paths
    ]
    if not remaining:
        return []

    route_files = {
        str(route.get("file_path", "")).strip().lower()
        for route in static_routes
        if isinstance(route, dict) and str(route.get("file_path", "")).strip()
    }
    evidence_files = {
        str(path).strip().lower()
        for path in (audit_memory or {}).get("evidence_files", [])
        if str(path).strip()
    }
    source_sink_files = {
        str(item.get("file_path", "")).strip().lower()
        for item in (source_sink_hints or [])
        if isinstance(item, dict)
        and 5 in (item.get("stage_nums", []) if isinstance(item.get("stage_nums"), list) else [])
        and str(item.get("file_path", "")).strip()
    }
    evidence_files = evidence_files | source_sink_files
    return _select_stage5_chunks(remaining, route_files=route_files, evidence_files=evidence_files)[:12]

def _build_stage5_followup_prev_context(prev_context: str, response: dict) -> str:
    summary_lines = []
    existing_summary = str(response.get("stage_summary", "") or "").strip()
    if existing_summary:
        summary_lines.append("当前阶段已确认摘要：")
        summary_lines.append(existing_summary[:600])

    vulnerabilities = response.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list) and vulnerabilities:
        summary_lines.append("当前阶段已确认漏洞索引：")
        for vuln in vulnerabilities[:6]:
            if not isinstance(vuln, dict):
                continue
            title = str(vuln.get("title", "") or "").strip() or "未命名漏洞"
            severity = str(vuln.get("severity", "") or "").strip() or "Unknown"
            vuln_type = str(vuln.get("vuln_type", "") or "").strip() or "Unknown"
            file_path = str(vuln.get("file_path", "") or "").strip()
            endpoint = str(vuln.get("endpoint", "") or "").strip()
            summary_lines.append(
                f"- {title} | severity={severity} | type={vuln_type} | file={file_path} | endpoint={endpoint}"
            )

    merged = "\n".join([part for part in [prev_context.strip(), "\n".join(summary_lines).strip()] if part]).strip()
    return _truncate_text(merged, 1200)

async def _run_stage5_followup_scan(
    *,
    llm_config,
    stage,
    project,
    stage_prompt: str,
    code_chunks: list[dict],
    static_routes: list[dict],
    prev_context: str,
    audit_memory: dict | None,
    selected_chunks: list[dict],
    current_response: dict,
    source_sink_hints: list[dict] | None = None,
) -> tuple[dict, dict]:
    followup_chunks = _select_stage5_followup_chunks(
        code_chunks=code_chunks,
        already_selected_chunks=selected_chunks,
        static_routes=static_routes,
        audit_memory=audit_memory,
        source_sink_hints=source_sink_hints,
    )
    if not followup_chunks:
        return current_response, {"triggered": False, "reason": "no_followup_chunks"}

    compact_context = _build_stage_focus_compact_context(
        stage=stage,
        project=project,
        static_routes=static_routes,
        selected_chunks=followup_chunks,
        audit_memory=audit_memory,
        rule_hits=[],
        source_sink_hints=source_sink_hints,
    )
    compact_context, code_text, effective_prev_context = _apply_stage5_prompt_budget(
        compact_context=compact_context,
        code_text=_format_non_stage1_chunks_for_prompt(followup_chunks, stage.stage_num, audit_memory=audit_memory),
        prev_context=_build_stage5_followup_prev_context(prev_context, current_response),
        aggressive=True,
    )
    compact_context["audit_memory_limit"] = min(int(compact_context.get("audit_memory_limit", 1200) or 1200), 1200)
    existing_keys = []
    for vuln in current_response.get("vulnerabilities", [])[:8]:
        if not isinstance(vuln, dict):
            continue
        existing_keys.append(
            {
                "title": str(vuln.get("title", "") or "").strip(),
                "vuln_type": str(vuln.get("vuln_type", "") or "").strip(),
                "file_path": str(vuln.get("file_path", "") or "").strip(),
                "endpoint": str(vuln.get("endpoint", "") or "").strip(),
            }
        )
    compact_context["extra_guidance"] = "\n".join(
        [
            str(compact_context.get("extra_guidance", "") or "").strip(),
            "阶段五补漏扫描：本轮只允许补充新增漏洞，不要重复已有结论。",
            "若发现与已确认漏洞属于同一根因或同一利用模式，请合并理解，不要重复输出。",
            "本轮最多新增 2 条认证与会话漏洞。",
            "继续优先保证完整闭合 JSON，不要展开完整认证流程。",
            "[已确认漏洞去重键]",
            json.dumps(existing_keys, ensure_ascii=False),
        ]
    ).strip()

    user_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        code_text,
        effective_prev_context,
        static_routes,
        compact_context=compact_context,
        audit_memory=audit_memory,
    )
    llm_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, user_prompt)
    followup_meta = {
        "triggered": True,
        "selected_chunk_count": len(followup_chunks),
        "prompt_length": len(user_prompt),
        "success": bool(llm_result.get("success")),
    }
    if not llm_result.get("success"):
        followup_meta["error"] = llm_result.get("error", {}).get("message", "followup failed")
        return current_response, followup_meta

    response = _parse_structured_response(llm_result["content"], llm_result.get("meta"))
    retry_policy = _get_stage_retry_policy(stage.stage_num)
    selected_result, selected_response, retry_meta = await _retry_incomplete_stage_response(
        llm_config=llm_config,
        stage=stage,
        project=project,
        stage_prompt=stage_prompt,
        code_text=code_text,
        prev_context=effective_prev_context,
        static_routes=static_routes,
        compact_context=compact_context,
        audit_memory=audit_memory,
        initial_result=llm_result,
        initial_response=response,
        retry_policy=retry_policy,
    )
    followup_meta["retry"] = retry_meta
    followup_meta["selected_attempt"] = retry_meta.get("selected_attempt", "initial")
    followup_meta["finish_reason"] = (selected_result.get("meta") or {}).get("finish_reason")

    if not isinstance(selected_response, dict):
        return current_response, followup_meta

    new_vulnerabilities = selected_response.get("vulnerabilities", [])
    if not isinstance(new_vulnerabilities, list):
        new_vulnerabilities = []
    existing_keys_set = {_vuln_key(vuln) for vuln in current_response.get("vulnerabilities", []) if isinstance(vuln, dict)}
    filtered_new = [vuln for vuln in new_vulnerabilities if isinstance(vuln, dict) and _vuln_key(vuln) not in existing_keys_set]
    if not filtered_new:
        followup_meta["new_vulnerability_count"] = 0
        return current_response, followup_meta

    followup_payload = dict(selected_response)
    followup_payload["vulnerabilities"] = filtered_new[:2]
    followup_payload = await _enrich_vulnerability_details(
        llm_config=llm_config,
        stage=stage,
        project=project,
        stage_prompt=stage_prompt,
        response=followup_payload,
        code_text=code_text,
        prev_context=effective_prev_context,
        static_routes=static_routes,
    )
    merged_response = _merge_stage_vulnerability_response(current_response, followup_payload)
    merged_response["_stage5_followup_applied"] = True
    followup_meta["new_vulnerability_count"] = len(filtered_new[:2])
    return merged_response, followup_meta

def _assess_stage1_pass_progress(
    compressed_summary: dict,
    summary_delta: dict,
    chunk_batch: list[dict],
    total_chunk_count: int,
    static_routes: list[dict] | None = None,
) -> dict:
    coverage = compressed_summary.get("coverage", {}) if isinstance(compressed_summary.get("coverage"), dict) else {}
    covered_paths = set(coverage.get("covered_paths", []) or [])
    covered_chunk_keys = set(coverage.get("covered_chunks", []) or [])
    batch_paths = [chunk.get("file_path", "") for chunk in chunk_batch if chunk.get("file_path")]
    batch_chunk_keys = [
        str(chunk.get("file_path", "") or chunk.get("base_file_path", "") or "").strip()
        for chunk in chunk_batch
        if str(chunk.get("file_path", "") or chunk.get("base_file_path", "") or "").strip()
    ]
    new_paths = [path for path in _merge_unique_items([], batch_paths) if path not in covered_paths]
    # 阶段一覆盖率必须按“唯一 chunk”统计，不能把重复回看批次累加后截顶成 100%。
    projected_scanned_chunk_count = min(total_chunk_count, len(covered_chunk_keys.union(batch_chunk_keys)))
    coverage_ratio = (projected_scanned_chunk_count / total_chunk_count) if total_chunk_count > 0 else 1.0

    architecture_info = summary_delta.get("architecture_info", {})
    route_count = 0
    module_count = 0
    data_flow_count = 0
    if isinstance(architecture_info, dict):
        routes = architecture_info.get("routes")
        modules = architecture_info.get("modules")
        data_flows = architecture_info.get("data_flows")
        if isinstance(routes, list):
            route_count = len(routes)
        elif architecture_info.get("route_count"):
            route_count = int(architecture_info.get("route_count", 0) or 0)
        if isinstance(modules, list):
            module_count = len(modules)
        if isinstance(data_flows, list):
            data_flow_count = len(data_flows)

    vulnerability_hints = summary_delta.get("vulnerability_hints", [])
    stage_summary_added = 1 if str(summary_delta.get("stage_summary", "")).strip() else 0
    signal_gain = stage_summary_added + route_count + module_count + data_flow_count + len(vulnerability_hints)
    route_coverage = _estimate_stage1_route_coverage(compressed_summary, chunk_batch, static_routes or [])
    discovered_route_delta = route_count

    return {
        "coverage_ratio": round(coverage_ratio, 4),
        "projected_scanned_chunk_count": projected_scanned_chunk_count,
        "new_path_count": len(new_paths),
        "new_paths_preview": new_paths[:12],
        "route_signal_count": route_count,
        "module_signal_count": module_count,
        "data_flow_signal_count": data_flow_count,
        "vulnerability_hint_count": len(vulnerability_hints),
        "stage_summary_added": bool(stage_summary_added),
        "signal_gain": signal_gain,
        "discovered_route_delta": discovered_route_delta,
        "route_file_coverage_ratio": round(route_coverage["coverage_ratio"], 4),
        "covered_route_file_count": route_coverage["covered_route_file_count"],
        "total_route_file_count": route_coverage["total_route_file_count"],
        "route_path_coverage_ratio": round(route_coverage["route_path_coverage_ratio"], 4),
        "covered_route_count": route_coverage["covered_route_count"],
        "total_route_count": route_coverage["total_route_count"],
    }

def _should_stop_stage1_early(pass_index: int, total_passes: int, pass_progress: dict, must_cover_uncovered: int = 0) -> str:
    if total_passes <= STAGE1_MIN_PASSES or pass_index < STAGE1_MIN_PASSES or pass_index >= total_passes:
        return ""

    coverage_ratio = float(pass_progress.get("coverage_ratio", 0.0) or 0.0)
    route_file_coverage_ratio = float(pass_progress.get("route_file_coverage_ratio", 0.0) or 0.0)
    covered_route_file_count = int(pass_progress.get("covered_route_file_count", 0) or 0)
    total_route_file_count = int(pass_progress.get("total_route_file_count", 0) or 0)
    signal_gain = int(pass_progress.get("signal_gain", 0) or 0)
    new_path_count = int(pass_progress.get("new_path_count", 0) or 0)
    discovered_route_delta = int(pass_progress.get("discovered_route_delta", 0) or 0)
    route_path_coverage_ratio = float(pass_progress.get("route_path_coverage_ratio", 0.0) or 0.0)
    covered_route_count = int(pass_progress.get("covered_route_count", 0) or 0)
    total_route_count = int(pass_progress.get("total_route_count", 0) or 0)

    # 本轮优先保证阶段一审计集完整送入模型，未接近全量覆盖时不允许提前停止。
    if coverage_ratio < 0.995:
        return ""
    if total_route_file_count > 0 and covered_route_file_count < total_route_file_count:
        return ""
    if total_route_count > 0 and covered_route_count < total_route_count:
        return ""
    if must_cover_uncovered > 0:
        return ""

    if (
        coverage_ratio >= STAGE1_STRONG_STOP_COVERAGE
        and route_file_coverage_ratio >= 0.95
        and route_path_coverage_ratio >= 0.95
    ):
        return (
            f"coverage {coverage_ratio:.0%} reached strong-stop threshold "
            f"and route discovery coverage reached files={route_file_coverage_ratio:.0%}, paths={route_path_coverage_ratio:.0%}"
        )

    if (
        coverage_ratio >= STAGE1_EARLY_STOP_COVERAGE
        and route_file_coverage_ratio >= 0.9
        and route_path_coverage_ratio >= 0.9
        and signal_gain <= 2
        and discovered_route_delta <= 1
        and new_path_count <= 2
    ):
        return (
            f"coverage {coverage_ratio:.0%} is sufficient and this pass produced limited new signal "
            f"(signal_gain={signal_gain}, discovered_routes={discovered_route_delta}, new_paths={new_path_count}, "
            f"route_file_coverage={route_file_coverage_ratio:.0%}, route_path_coverage={route_path_coverage_ratio:.0%})"
        )

    return ""

def _count_must_cover_uncovered(compressed_summary: dict, pre_discovery: dict | None) -> int:
    """Count how many must-cover files have not been scanned yet."""
    if not pre_discovery:
        return 0
    sf = pre_discovery.get("security_files") or {}
    must_cover = set((sf.get("must_cover_files") or [])[:60])
    if not must_cover:
        return 0
    coverage = compressed_summary.get("coverage", {}) if isinstance(compressed_summary.get("coverage"), dict) else {}
    covered = set(p.lower() for p in (coverage.get("covered_paths") or []))
    return sum(1 for fp in must_cover if fp.lower() not in covered)

def _estimate_stage1_route_coverage(compressed_summary: dict, chunk_batch: list[dict], static_routes: list[dict]) -> dict:
    route_files = []
    route_keys = []
    for route in static_routes:
        if not isinstance(route, dict):
            continue
        file_path = str(route.get("file_path", "")).strip()
        if file_path:
            route_files.append(file_path)
        path = str(route.get("path", "")).strip()
        if path:
            route_keys.append(f"{str(route.get('method', 'UNKNOWN')).upper()} {path}")
    route_files = _merge_unique_items([], route_files)
    route_keys = _merge_unique_items([], route_keys)

    if not route_files and not route_keys:
        return {
            "coverage_ratio": 1.0,
            "covered_route_file_count": 0,
            "total_route_file_count": 0,
            "route_path_coverage_ratio": 1.0,
            "covered_route_count": 0,
            "total_route_count": 0,
        }

    coverage = compressed_summary.get("coverage", {}) if isinstance(compressed_summary.get("coverage"), dict) else {}
    covered_paths = set(coverage.get("covered_paths", []) or [])
    batch_paths = {chunk.get("file_path", "") for chunk in chunk_batch if chunk.get("file_path")}
    covered_route_file_count = sum(1 for path in route_files if path in covered_paths or path in batch_paths)
    total_route_file_count = len(route_files)
    architecture_info = compressed_summary.get("architecture_info", {}) if isinstance(compressed_summary.get("architecture_info"), dict) else {}
    discovered_routes = architecture_info.get("routes", []) if isinstance(architecture_info.get("routes"), list) else []
    discovered_route_keys = _merge_unique_items(
        [],
        [
            f"{str(route.get('method', 'UNKNOWN')).upper()} {str(route.get('path', '')).strip()}"
            for route in discovered_routes
            if isinstance(route, dict) and str(route.get("path", "")).strip()
        ],
    )
    covered_route_count = sum(1 for key in route_keys if key in discovered_route_keys)
    return {
        "coverage_ratio": (covered_route_file_count / total_route_file_count) if total_route_file_count else 1.0,
        "covered_route_file_count": covered_route_file_count,
        "total_route_file_count": total_route_file_count,
        "route_path_coverage_ratio": (covered_route_count / len(route_keys)) if route_keys else 1.0,
        "covered_route_count": covered_route_count,
        "total_route_count": len(route_keys),
    }

def _build_stage_artifact_path(task_id: int, stage_num: int) -> str:
    os.makedirs(get_stage_artifact_dir(task_id), exist_ok=True)
    return os.path.join("data", "stage_artifacts", str(task_id), f"stage_{stage_num}_passes.json")


async def _emit_artifact_written(session, task, stage, artifact_path: str) -> None:
    """§9.2：阶段产物落盘后发 ``artifact.written`` 事件（活动流可观测产物就绪）。

    emit_event 内部捕获异常，故产物观测失败不会拖垮主审计流程。
    """
    await emit_event(
        session,
        task_id=task.id,
        event_type=EVENT_ARTIFACT_WRITTEN,
        stage_num=stage.stage_num,
        payload={"artifact_path": artifact_path, "stage_num": stage.stage_num},
    )

def _persist_stage_pass_artifact(
    artifact_path: str,
    task_id: int,
    stage_id: int,
    pass_outputs: list[dict],
    compressed_summary: dict,
    merged_response: dict,
    static_routes: list[dict] | None = None,
    early_stop: dict | None = None,
):
    route_gap_summary = _build_stage1_route_gap_summary(static_routes or [], compressed_summary)
    payload = {
        "task_id": task_id,
        "stage_id": stage_id,
        "pass_count": len(pass_outputs),
        "early_stop": early_stop or {"triggered": False, "reason": "", "after_pass": 0},
        "pass_summary": _summarize_stage1_pass_outputs(pass_outputs),
        "passes": pass_outputs,
        "compressed_summary": compressed_summary,
        "route_gap_summary": route_gap_summary,
        "merged_response_preview": {
            "stage_summary": str(merged_response.get("stage_summary", ""))[:4000],
            "architecture_info": _summarize_architecture_info(merged_response.get("architecture_info")),
            "risk_hint_count": len(merged_response.get("risk_hints", [])) if isinstance(merged_response.get("risk_hints"), list) else 0,
            "risk_hints": (merged_response.get("risk_hints", []) if isinstance(merged_response.get("risk_hints"), list) else [])[:20],
        },
    }
    with open(resolve_audit_artifact_path(artifact_path), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

def _persist_single_stage_artifact(
    artifact_path: str,
    task_id: int,
    stage,
    compact_context: dict,
    selected_chunks: list[dict],
    code_text: str,
    audit_memory: dict | None,
    response: dict,
    execution_meta: dict | None = None,
):
    focus_files = compact_context.get("focus_files", []) if isinstance(compact_context.get("focus_files"), list) else []
    route_lines = compact_context.get("route_lines", []) if isinstance(compact_context.get("route_lines"), list) else []
    payload = {
        "task_id": task_id,
        "stage_id": stage.id,
        "stage_num": stage.stage_num,
        "stage_name": stage.stage_name,
        "status": stage.status,
        "focus_summary": {
            "selected_chunk_count": len(selected_chunks),
            "focus_file_count": len(focus_files),
            "focus_files": focus_files[:50],
            "route_line_count": len(route_lines),
            "route_lines": route_lines[:40],
            "code_text_length": len(code_text or ""),
            "evidence_file_count": len(audit_memory.get("evidence_files", []) if isinstance(audit_memory, dict) and isinstance(audit_memory.get("evidence_files"), list) else []),
        },
        "compact_context": {
            "project_tree_summary": _truncate_text(str(compact_context.get("project_tree_summary", "")), 3000),
            "route_intro": str(compact_context.get("route_intro", ""))[:500],
            "extra_guidance": str(compact_context.get("extra_guidance", ""))[:2000],
        },
        "audit_memory_preview": _compact_audit_memory_for_stage(getattr(stage, "stage_num", 0), audit_memory or {}),
        "response_preview": {
            "stage_summary": str(response.get("stage_summary", ""))[:3000] if isinstance(response, dict) else "",
            "architecture_info": _summarize_architecture_info(response.get("architecture_info")) if isinstance(response, dict) else {},
            "vulnerability_count": len(response.get("vulnerabilities", [])) if isinstance(response, dict) and isinstance(response.get("vulnerabilities"), list) else 0,
        },
        "execution_meta": execution_meta or {},
    }
    with open(resolve_audit_artifact_path(artifact_path), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

def _build_stage1_route_gap_summary(static_routes: list[dict], compressed_summary: dict) -> dict:
    static_route_map = {}
    for route in static_routes:
        if not isinstance(route, dict):
            continue
        method = str(route.get("method", "UNKNOWN")).upper()
        path = str(route.get("path", "")).strip()
        if not path:
            continue
        key = f"{method} {path}"
        static_route_map[key] = {
            "method": method,
            "path": path,
            "handler": str(route.get("handler", "Unknown")),
            "file_path": str(route.get("file_path", "")),
            "auth": str(route.get("auth", "Unknown")),
            "params": route.get("params", []) if isinstance(route.get("params"), list) else [],
        }

    architecture_info = compressed_summary.get("architecture_info", {}) if isinstance(compressed_summary, dict) else {}
    discovered_routes = architecture_info.get("routes", []) if isinstance(architecture_info, dict) else []
    discovered_keys = set()
    for route in discovered_routes:
        if not isinstance(route, dict):
            continue
        path = str(route.get("path", "")).strip()
        if not path:
            continue
        discovered_keys.add(f"{str(route.get('method', 'UNKNOWN')).upper()} {path}")

    missing_routes = [route for key, route in static_route_map.items() if key not in discovered_keys]
    missing_routes.sort(key=lambda item: (-_route_priority_score(item), item["path"], item["method"], item["handler"]))

    return {
        "static_route_count": len(static_route_map),
        "confirmed_route_count": len(discovered_keys),
        "missing_route_count": len(missing_routes),
        "missing_route_samples": missing_routes[:40],
    }

def _run_stage1_gap_analysis(merged_response: dict, static_routes: list[dict], pre_discovery: dict | None, compressed_summary: dict | None = None) -> dict:
    """Post-scan gap analysis for route coverage, must-cover files, and architecture completeness."""
    gaps = {"missing_routes": [], "missing_must_cover": [], "missing_fields": [], "overall_health": "ok"}

    if not isinstance(merged_response, dict):
        return gaps

    arch = merged_response.get("architecture_info") or {}
    if not isinstance(arch, dict):
        return gaps

    llm_route_paths = set()
    for route in (arch.get("routes") or []):
        if isinstance(route, dict):
            key = (str(route.get("method", "")).upper(), str(route.get("path", "")))
            llm_route_paths.add(key)

    for route in static_routes[:200]:
        if not isinstance(route, dict):
            continue
        key = (str(route.get("method", "")).upper(), str(route.get("path", "")))
        if key not in llm_route_paths and key[1]:
            gaps["missing_routes"].append({"method": key[0], "path": key[1], "file_path": route.get("file_path", "")})

    if pre_discovery:
        sf = pre_discovery.get("security_files") or {}
        coverage = compressed_summary.get("coverage", {}) if isinstance(compressed_summary, dict) and isinstance(compressed_summary.get("coverage"), dict) else {}
        covered_paths = {str(path).strip().lower() for path in (coverage.get("covered_paths") or []) if str(path).strip()}
        for fp in (sf.get("must_cover_files") or [])[:60]:
            normalized_fp = str(fp).strip()
            if normalized_fp and normalized_fp.lower() not in covered_paths:
                gaps["missing_must_cover"].append(normalized_fp)

    for field in ["tech_stack", "framework", "database", "auth_mechanism"]:
        if not str(arch.get(field, "")).strip():
            gaps["missing_fields"].append(field)

    total_static = len(static_routes)
    missing_count = len(gaps["missing_routes"])
    if total_static > 0 and missing_count / total_static > 0.3:
        gaps["overall_health"] = "poor_route_coverage"
    elif gaps["missing_fields"]:
        gaps["overall_health"] = "incomplete_architecture"
    elif len(gaps["missing_must_cover"]) > 10:
        gaps["overall_health"] = "poor_file_coverage"

    return gaps

__all__ = [
    '_is_auto_second_pass_enabled',
    '_is_task_cancelled',
    '_is_task_paused',
    '_is_task_stopping',
    '_build_stage_coverage_snapshot',
    '_attach_stage_runtime_summary',
    '_build_task_rescan_recommendations',
    '_accumulate_token_usage',
    '_refresh_task_summary',
    '_run_missing_route_followup',
    '_apply_stage_payload',
    '_run_single_pass_stage',
    '_run_stage1_multi_pass',
    '_retry_incomplete_stage_response',
    '_needs_vulnerability_detail_enrichment',
    '_vulnerability_detail_priority',
    '_build_vulnerability_detail_prompt',
    '_enrich_vulnerability_details',
    '_should_run_stage5_followup_scan',
    '_should_run_secondary_stage_pass',
    '_select_secondary_stage_chunks',
    '_is_low_signal_secondary_chunk',
    '_build_secondary_pass_prev_context',
    '_build_secondary_pass_guidance',
    '_run_secondary_stage_pass',
    '_select_stage5_followup_chunks',
    '_build_stage5_followup_prev_context',
    '_run_stage5_followup_scan',
    '_assess_stage1_pass_progress',
    '_should_stop_stage1_early',
    '_count_must_cover_uncovered',
    '_estimate_stage1_route_coverage',
    '_build_stage_artifact_path',
    '_persist_stage_pass_artifact',
    '_persist_single_stage_artifact',
    '_build_stage1_route_gap_summary',
    '_run_stage1_gap_analysis',
]
