"""Core audit engine for the staged 9-phase LLM code audit workflow."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import re
from datetime import datetime, timezone

from sqlalchemy import case, delete, select

from database import async_session
from models import AuditTask, AuditStage, Vulnerability, LlmConfig, Project
from prompts.stage_prompts import SYSTEM_BASE, get_spec_label, get_stage_name, get_stage_prompt
from services.code_parser import get_or_build_project_cache
from services.audit_cleanup import get_stage_artifact_dir, resolve_audit_artifact_path
from services.llm_client import call_llm_with_meta
from vulnerability_normalization import normalize_vulnerability_fields

logger = logging.getLogger(__name__)

STAGE1_MAX_PASSES = 5
STAGE1_BATCH_TARGET_LEN = 120000
STAGE1_MIN_PASSES = 3
STAGE1_EARLY_STOP_COVERAGE = 0.82
STAGE1_STRONG_STOP_COVERAGE = 0.94
STAGE1_PASS1_CODE_MAX_LEN = 150000
STAGE1_LATER_PASS_CODE_MAX_LEN = 90000
STAGE1_SOFT_MAX_BATCHES = 12
SECONDARY_STAGE_MAX_ROUNDS = 3
SECONDARY_STAGE_CHUNK_LIMIT = 16
STAGE_RETRY_POLICIES = {
    1: {"enabled": True, "max_vulnerabilities": 0, "code_limit": 22000, "prev_context_limit": 800, "route_limit": 20, "detail_enrichment_max_items": 0, "detail_enrichment_concurrency": 1},
    2: {"enabled": True, "max_vulnerabilities": 4, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    3: {"enabled": True, "max_vulnerabilities": 4, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    4: {"enabled": True, "max_vulnerabilities": 4, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    5: {"enabled": True, "max_vulnerabilities": 3, "code_limit": 14000, "prev_context_limit": 900, "route_limit": 6, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    6: {"enabled": True, "max_vulnerabilities": 5, "code_limit": 18000, "prev_context_limit": 1400, "route_limit": 10, "detail_enrichment_max_items": 3, "detail_enrichment_concurrency": 1},
    7: {"enabled": True, "max_vulnerabilities": 3, "code_limit": 14000, "prev_context_limit": 1000, "route_limit": 8, "detail_enrichment_max_items": 1, "detail_enrichment_concurrency": 1},
    8: {"enabled": True, "max_vulnerabilities": 3, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
    9: {"enabled": True, "max_vulnerabilities": 3, "code_limit": 18000, "prev_context_limit": 1200, "route_limit": 8, "detail_enrichment_max_items": 2, "detail_enrichment_concurrency": 1},
}


def _is_auto_second_pass_enabled(task: AuditTask) -> bool:
    summary = task.summary if isinstance(task.summary, dict) else {}
    return bool(summary.get("auto_second_pass", True))


def _coerce_stage_findings(findings):
    if isinstance(findings, dict):
        return findings
    if isinstance(findings, list):
        return {"vulnerabilities": findings}
    return {}


SEVERITY_ALIASES = {
    "critical": "Critical", "严重": "Critical",
    "high": "High", "高危": "High", "高": "High",
    "medium": "Medium", "中危": "Medium", "中": "Medium",
    "low": "Low", "低危": "Low", "低": "Low",
    "info": "Info", "提示": "Info", "信息": "Info", "informational": "Info",
}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _normalize_severity(severity: str) -> str:
    if not severity:
        return "Medium"
    stripped = severity.strip()
    if stripped in VALID_SEVERITIES:
        return stripped
    return SEVERITY_ALIASES.get(stripped.lower(), SEVERITY_ALIASES.get(stripped, "Medium"))


def _severity_match_values(severity: str) -> list[str]:
    normalized = _normalize_severity(severity)
    aliases = [k for k, v in SEVERITY_ALIASES.items() if v == normalized]
    return list(set([normalized] + aliases))


def _severity_order_expr(column):
    return case(
        (column.in_(_severity_match_values("Critical")), 5),
        (column.in_(_severity_match_values("High")), 4),
        (column.in_(_severity_match_values("Medium")), 3),
        (column.in_(_severity_match_values("Low")), 2),
        (column.in_(_severity_match_values("Info")), 1),
        else_=0,
    )


def _normalize_confidence(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in CONFIDENCE_RANK:
        return normalized
    return "medium"


async def _is_task_cancelled(session, task_id: int) -> bool:
    result = await session.execute(select(AuditTask.status).where(AuditTask.id == task_id))
    return result.scalar_one_or_none() == "cancelled"


def _build_task_severity_stats(vulns: list[Vulnerability]) -> dict:
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for vuln in vulns:
        severity = getattr(vuln, "severity", None)
        if severity in stats:
            stats[severity] += 1
    return stats


def _build_stage_coverage_snapshot(compact_context: dict | None, selected_chunks: list[dict]) -> dict:
    compact_context = compact_context if isinstance(compact_context, dict) else {}
    focus_files = compact_context.get("focus_files", []) if isinstance(compact_context.get("focus_files"), list) else []
    focus_routes = compact_context.get("focus_routes", []) if isinstance(compact_context.get("focus_routes"), list) else []
    return {
        "selected_chunk_count": len(selected_chunks),
        "focus_files": focus_files[:40],
        "focus_file_count": len(focus_files),
        "focus_routes": [
            {
                "method": str(route.get("method", "UNKNOWN") or "UNKNOWN").upper(),
                "path": str(route.get("path", "") or "").strip(),
                "handler": str(route.get("handler", "") or "").strip(),
                "file_path": str(route.get("file_path", "") or "").strip(),
                "auth": str(route.get("auth", "") or "").strip(),
            }
            for route in focus_routes[:32]
            if isinstance(route, dict) and str(route.get("path", "") or "").strip()
        ],
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
    rule_hits: list | None = None,
) -> None:
    summary = task.summary if isinstance(task.summary, dict) else {}
    if isinstance(scan_stats, dict):
        summary["scan_stats"] = scan_stats
    if isinstance(rule_hits, list):
        summary["rule_hits_preview"] = rule_hits[:20]

    vuln_result = await session.execute(select(Vulnerability).where(Vulnerability.task_id == task.id))
    vulns = list(vuln_result.scalars().all())
    effective_scan_stats = summary.get("scan_stats", {}) if isinstance(summary.get("scan_stats"), dict) else {}
    for stale_key in [
        "verification_stats",
        "candidate_severity_stats",
        "diff_stats",
        "candidate_diff_stats",
    ]:
        summary.pop(stale_key, None)
    summary["severity_stats"] = _build_task_severity_stats(vulns)
    summary["rescan_recommendations"] = _build_task_rescan_recommendations(vulns, effective_scan_stats)
    stage1_result = await session.execute(
        select(AuditStage).where(AuditStage.task_id == task.id, AuditStage.stage_num == 1)
    )
    stage1 = stage1_result.scalar_one_or_none()
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
    task.summary = dict(summary)


async def _run_stage(session, task, stage, llm_config, project, code_chunks, static_routes, prev_context, audit_memory, rule_hits, source_sink_hints):
    if await _is_task_cancelled(session, task.id):
        stage.status = "cancelled"
        stage.completed_at = datetime.now(timezone.utc)
        await session.commit()
        return

    stage.status = "running"
    stage.started_at = datetime.now(timezone.utc)
    stage.completed_at = None
    task.current_stage = stage.stage_num
    await session.commit()

    stage_prompt = get_stage_prompt(stage.stage_num)
    selected_chunks = _select_stage_chunks(
        stage.stage_num,
        code_chunks,
        static_routes=static_routes,
        audit_memory=audit_memory,
        source_sink_hints=source_sink_hints,
    )
    if stage.stage_num == 1:
        stage_payload = await _run_stage1_multi_pass(
            session=session,
            task=task,
            stage=stage,
            llm_config=llm_config,
            project=project,
            stage_prompt=stage_prompt,
            selected_chunks=selected_chunks,
            code_chunks=code_chunks,
            static_routes=static_routes,
            prev_context=prev_context,
            audit_memory=audit_memory,
            rule_hits=rule_hits,
            source_sink_hints=source_sink_hints,
        )
    else:
        stage_payload = await _run_single_pass_stage(
            session=session,
            task=task,
            stage=stage,
            llm_config=llm_config,
            project=project,
            stage_prompt=stage_prompt,
            selected_chunks=selected_chunks,
            code_chunks=code_chunks,
            static_routes=static_routes,
            prev_context=prev_context,
            audit_memory=audit_memory,
            rule_hits=rule_hits,
            source_sink_hints=source_sink_hints,
        )

    response = stage_payload["response"]
    stage.prompt_used = stage_payload["prompt_used"]
    stage.llm_response = stage_payload["llm_response"]
    repair_code_text = str(stage_payload.get("repair_code_text", "") or "")
    repair_prev_context = str(stage_payload.get("repair_prev_context", "") or "")
    if isinstance(stage_payload.get("compressed_summary"), (dict, list)):
        stage.compressed_summary = stage_payload["compressed_summary"]
    if stage_payload.get("artifact_path"):
        stage.artifact_path = stage_payload["artifact_path"]

    vulns_created = 0
    policy_stats = {"invalid_poc_vulnerabilities": 0, "invalid_poc_titles": [], "merged_duplicate_vulnerabilities": 0}
    if isinstance(response, dict):
        if stage.stage_num == 1 and "vulnerabilities" not in response:
            response["vulnerabilities"] = []
        if stage.stage_num == 1:
            response = _merge_stage1_routes(response, static_routes)
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
        response = await _repair_invalid_vulnerability_pocs(
            llm_config=llm_config,
            stage=stage,
            project=project,
            stage_prompt=get_stage_prompt(stage.stage_num),
            response=response,
            code_text=repair_code_text,
            prev_context=repair_prev_context or _build_prev_context(audit_memory),
            static_routes=static_routes,
        )
        response, policy_stats = _enforce_vulnerability_output_policy(stage, response)
        stage.findings = response
        vulns_created = await _store_vulnerabilities(session, task, stage, response.get("vulnerabilities", []))
    elif isinstance(response, list):
        normalized_payload = _hydrate_vulnerability_endpoints(
            response={"vulnerabilities": response},
            static_routes=static_routes,
            audit_memory=audit_memory,
        )
        normalized_payload = _backfill_vulnerability_poc_templates(
            stage_num=stage.stage_num,
            response=normalized_payload,
            static_routes=static_routes,
            audit_memory=audit_memory,
        )
        normalized_payload = await _repair_invalid_vulnerability_pocs(
            llm_config=llm_config,
            stage=stage,
            project=project,
            stage_prompt=get_stage_prompt(stage.stage_num),
            response=normalized_payload,
            code_text=repair_code_text,
            prev_context=repair_prev_context or _build_prev_context(audit_memory),
            static_routes=static_routes,
        )
        normalized_response, policy_stats = _enforce_vulnerability_output_policy(stage, normalized_payload)
        response = normalized_response
        stage.findings = response
        vulns_created = await _store_vulnerabilities(session, task, stage, response.get("vulnerabilities", []))
    else:
        stage.findings = {"raw_response": str(response)[:5000], "vulnerabilities": []}

    if isinstance(stage.findings, dict) and policy_stats["invalid_poc_vulnerabilities"]:
        stage.findings.setdefault(
            "_policy_note",
            "已按 code_audit.md 规则校验 POC；漏洞均已入库，但部分漏洞未提供与其类型匹配的合规 PoC。",
        )
        stage.findings["_policy_stats"] = policy_stats

    stage.status = "completed"
    stage.completed_at = datetime.now(timezone.utc)
    await session.commit()
    logger.info("Task %s Stage %s: completed, %s vulns found", task.id, stage.stage_num, vulns_created)


async def _apply_stage_payload(stage, stage_payload: dict, session=None, task=None, static_routes=None, audit_memory=None):
    """Apply stage execution result to the stage object (findings, prompt, artifact)."""
    response = stage_payload["response"]
    stage.prompt_used = stage_payload["prompt_used"]
    stage.llm_response = stage_payload["llm_response"]
    if isinstance(stage_payload.get("compressed_summary"), (dict, list)):
        stage.compressed_summary = stage_payload["compressed_summary"]
    if stage_payload.get("artifact_path"):
        stage.artifact_path = stage_payload["artifact_path"]

    if isinstance(response, dict):
        if stage.stage_num == 1 and "vulnerabilities" not in response:
            response["vulnerabilities"] = []
        if stage.stage_num == 1 and static_routes is not None:
            response = _merge_stage1_routes(response, static_routes)
        if static_routes is not None and audit_memory is not None:
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
        response, _ = _enforce_vulnerability_output_policy(stage, response)
        stage.findings = response
    elif isinstance(response, list):
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
        normalized_response, _ = _enforce_vulnerability_output_policy(stage, normalized_payload)
        response = normalized_response
        stage.findings = response
    else:
        stage.findings = {"raw_response": str(response)[:5000], "vulnerabilities": []}

    if session and task:
        await _store_vulnerabilities(session, task, stage, stage.findings.get("vulnerabilities", []) if isinstance(stage.findings, dict) else stage.findings)


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
    merged_response = {"stage_summary": "", "architecture_info": {}, "vulnerabilities": []}
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


async def _store_vulnerabilities(session, task, stage, vulns_data) -> int:
    if stage.stage_num >= 10:
        return 0

    result = await session.execute(select(Vulnerability).where(Vulnerability.task_id == task.id))
    existing = {}
    for vuln in result.scalars().all():
        existing[_vuln_key(
            {
                "title": vuln.title,
                "vuln_type": vuln.vuln_type,
                "file_path": vuln.file_path,
                "line_start": vuln.line_start,
                "line_end": vuln.line_end,
                "code_snippet": vuln.code_snippet,
                "endpoint": vuln.endpoint,
                "description": vuln.description,
            }
        )] = vuln

    normalized_vulns = _merge_vulnerability_lists([], vulns_data if isinstance(vulns_data, list) else [])

    created = 0
    for vuln_data in normalized_vulns:
        if not isinstance(vuln_data, dict):
            continue
        vuln_data = normalize_vulnerability_fields(vuln_data)
        vuln_data["severity"] = _normalize_severity(vuln_data.get("severity", "Medium"))
        poc_raw = str(vuln_data.get("poc_raw", "") or "").strip()
        if not poc_raw:
            endpoint = str(vuln_data.get("endpoint", "") or "").strip()
            file_path = str(vuln_data.get("file_path", "") or "").strip()
            poc_raw = (
                "未提供可复现 POC。"
                f"{' 相关入口：' + endpoint if endpoint else ''}"
                f"{' 相关文件：' + file_path if file_path else ''}"
                " 请基于代码证据补充触发条件、请求样例或复现步骤。"
            ).strip()
            vuln_data["poc_raw"] = poc_raw
        poc_validation = vuln_data.get("_poc_validation") if isinstance(vuln_data.get("_poc_validation"), dict) else {}
        poc_validation_status = "valid" if poc_validation.get("accepted") else "invalid"
        poc_validation_note = str(poc_validation.get("reason", "") or "").strip()
        description = vuln_data.get("description", "")
        vuln_key = _vuln_key(vuln_data)
        dedupe_key = _stable_vuln_dedupe_key(vuln_data)
        existing_vuln = existing.get(vuln_key)
        if existing_vuln:
            merged_existing = _merge_duplicate_vulnerability(
                {
                    "title": existing_vuln.title,
                    "severity": existing_vuln.severity,
                    "vuln_type": existing_vuln.vuln_type,
                    "file_path": existing_vuln.file_path,
                    "line_start": existing_vuln.line_start,
                    "line_end": existing_vuln.line_end,
                    "code_snippet": existing_vuln.code_snippet,
                    "endpoint": existing_vuln.endpoint,
                    "poc_raw": existing_vuln.poc_raw,
                    "poc_validation_status": existing_vuln.poc_validation_status,
                    "poc_validation_note": existing_vuln.poc_validation_note,
                    "description": existing_vuln.description,
                    "fix_suggestion": existing_vuln.fix_suggestion,
                    "confidence": existing_vuln.confidence,
                },
                {
                    **vuln_data,
                    "poc_raw": poc_raw,
                    "poc_validation_status": poc_validation_status,
                    "poc_validation_note": poc_validation_note,
                    "description": description,
                },
            )
            existing_vuln.title = merged_existing.get("title", existing_vuln.title)
            existing_vuln.severity = merged_existing.get("severity", existing_vuln.severity)
            existing_vuln.vuln_type = merged_existing.get("vuln_type", existing_vuln.vuln_type)
            existing_vuln.file_path = merged_existing.get("file_path", existing_vuln.file_path)
            existing_vuln.line_start = merged_existing.get("line_start", existing_vuln.line_start)
            existing_vuln.line_end = merged_existing.get("line_end", existing_vuln.line_end)
            existing_vuln.code_snippet = merged_existing.get("code_snippet", existing_vuln.code_snippet)
            existing_vuln.endpoint = merged_existing.get("endpoint", existing_vuln.endpoint)
            existing_vuln.poc_raw = merged_existing.get("poc_raw", existing_vuln.poc_raw)
            existing_vuln.poc_validation_status = merged_existing.get("poc_validation_status", poc_validation_status)
            existing_vuln.poc_validation_note = merged_existing.get("poc_validation_note", poc_validation_note)
            existing_vuln.description = merged_existing.get("description", existing_vuln.description)
            existing_vuln.fix_suggestion = merged_existing.get("fix_suggestion", existing_vuln.fix_suggestion)
            existing_vuln.dedupe_key = dedupe_key
            existing_vuln.confidence = merged_existing.get("confidence", existing_vuln.confidence)
            continue
        if vuln_data.get("_salvaged"):
            salvage_note = "系统备注：该漏洞由截断的模型响应中自动恢复，请人工复核原始响应。"
            description = f"{salvage_note}\n\n{description}".strip()
        if poc_validation_status != "valid" and poc_validation_note:
            poc_note = f"POC校验备注：{poc_validation_note}"
            description = f"{poc_note}\n\n{description}".strip()
        vuln = Vulnerability(
            task_id=task.id,
            stage_id=stage.id,
            title=vuln_data.get("title", "Unknown"),
            severity=vuln_data.get("severity", "Medium"),
            vuln_type=vuln_data.get("vuln_type", "Unknown"),
            file_path=vuln_data.get("file_path", ""),
            line_start=vuln_data.get("line_start"),
            line_end=vuln_data.get("line_end"),
            code_snippet=vuln_data.get("code_snippet", ""),
            endpoint=vuln_data.get("endpoint", ""),
            poc_raw=poc_raw,
            poc_validation_status=poc_validation_status,
            poc_validation_note=poc_validation_note,
            description=description,
            fix_suggestion=vuln_data.get("fix_suggestion", ""),
            dedupe_key=dedupe_key,
            confidence=vuln_data.get("confidence", "medium"),
        )
        session.add(vuln)
        existing[vuln_key] = vuln
        created += 1
    return created


def _response_meta_indicates_truncation(meta: dict | None) -> bool:
    if not isinstance(meta, dict):
        return False

    finish_reason = str(meta.get("finish_reason") or "").strip().lower()
    if finish_reason in {"length", "max_output_tokens", "max_tokens", "incomplete"}:
        return True

    response_status = str(meta.get("response_status") or "").strip().lower()
    if response_status == "incomplete":
        return True

    incomplete_details = meta.get("incomplete_details")
    if isinstance(incomplete_details, dict):
        reason = str(incomplete_details.get("reason") or incomplete_details.get("type") or "").strip().lower()
        if reason in {"max_output_tokens", "max_tokens", "length"}:
            return True

    return False


def _annotate_response_completion(response: dict | list, meta: dict | None) -> dict | list:
    if not isinstance(response, dict):
        return response

    annotated = dict(response)
    if _response_meta_indicates_truncation(meta):
        annotated["response_incomplete"] = True
        annotated["_meta_truncated"] = True
        if not annotated.get("parse_error"):
            annotated["parse_error"] = "模型响应因输出长度限制被截断"
    return annotated


def _parse_structured_response(raw: str, meta: dict | None = None) -> dict | list:
    text = _normalize_llm_json_text(raw)

    try:
        return _annotate_response_completion(json.loads(text), meta)
    except json.JSONDecodeError:
        extracted = _extract_best_json_candidate(text)
        if extracted:
            try:
                return _annotate_response_completion(json.loads(extracted), meta)
            except json.JSONDecodeError:
                pass

    salvaged = _salvage_partial_structured_response(text, raw)
    if salvaged is not None:
        return _annotate_response_completion(salvaged, meta)

    return _annotate_response_completion(
        {
            "raw_response": raw,
            "parse_error": "无法从模型响应中提取 JSON",
            "response_incomplete": _looks_like_truncated_response(text),
            "vulnerabilities": [],
        },
        meta,
    )
def _get_stage_retry_policy(stage_num: int) -> dict:
    base = {
        "enabled": False,
        "max_vulnerabilities": 5,
        "code_limit": 32000,
        "prev_context_limit": 2400,
        "route_limit": 16,
        "detail_enrichment_max_items": 4,
        "detail_enrichment_concurrency": 2,
    }
    return {**base, **STAGE_RETRY_POLICIES.get(stage_num, {})}


def _should_retry_incomplete_response(stage_num: int, response: dict | list) -> bool:
    policy = _get_stage_retry_policy(stage_num)
    if not policy.get("enabled"):
        return False
    if not isinstance(response, dict):
        return False
    return bool(response.get("parse_error") or response.get("response_incomplete") or response.get("_salvaged"))


def _describe_retry_reason(response: dict | list) -> str:
    if not isinstance(response, dict):
        return ""
    reasons = []
    if response.get("parse_error"):
        reasons.append("parse_error")
    if response.get("response_incomplete"):
        reasons.append("response_incomplete")
    if response.get("_salvaged"):
        reasons.append("salvaged")
    return ",".join(reasons)


def _build_retry_meta(response: dict | list, retry_policy: dict) -> dict:
    return {
        "triggered": False,
        "reason": "",
        "prompt_length": 0,
        "success": False,
        "selected_attempt": "initial",
        "initial_parse_error": bool(isinstance(response, dict) and response.get("parse_error")),
        "initial_response_incomplete": bool(isinstance(response, dict) and response.get("response_incomplete")),
        "initial_salvaged": bool(isinstance(response, dict) and response.get("_salvaged")),
        "policy": retry_policy,
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
def _score_stage_response(response: dict | list) -> int:
    if isinstance(response, list):
        return 10 + len(response)
    if not isinstance(response, dict):
        return 0

    score = 0
    if not response.get("parse_error"):
        score += 40
    if not response.get("response_incomplete"):
        score += 30
    if not response.get("_salvaged"):
        score += 20

    vulnerabilities = response.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        score += min(len(vulnerabilities), 8) * 3
        for vuln in vulnerabilities[:8]:
            if isinstance(vuln, dict) and str(vuln.get("poc_raw", "")).strip():
                score += 1

    if str(response.get("stage_summary", "")).strip():
        score += 3
    if isinstance(response.get("architecture_info"), dict) and response.get("architecture_info"):
        score += 3
    return score


def _coerce_incomplete_stage_response(
    *,
    stage_num: int,
    response: dict | list,
    retry_policy: dict | None = None,
) -> tuple[dict | list, bool]:
    if isinstance(response, list):
        return {"stage_summary": "", "architecture_info": {}, "vulnerabilities": response}, True
    if not isinstance(response, dict):
        return {"stage_summary": "", "architecture_info": {}, "vulnerabilities": []}, True

    if not (response.get("parse_error") or response.get("response_incomplete") or response.get("_salvaged")):
        return response, False

    retry_policy = retry_policy or {}
    max_vulnerabilities = max(1, int(retry_policy.get("max_vulnerabilities", 3) or 3))
    route_limit = min(8, max(2, max_vulnerabilities * 3))

    architecture_info = response.get("architecture_info", {})
    normalized_arch = {}
    if isinstance(architecture_info, dict):
        for key in ["tech_stack", "framework", "database", "auth_mechanism"]:
            value = architecture_info.get(key)
            if value:
                normalized_arch[key] = str(value)[:200]
        routes = architecture_info.get("routes")
        if isinstance(routes, list) and routes:
            normalized_routes = []
            for route in routes[:route_limit]:
                if not isinstance(route, dict):
                    continue
                path = str(route.get("path", "") or "").strip()
                if not path:
                    continue
                normalized_routes.append(
                    {
                        "method": str(route.get("method", "UNKNOWN") or "UNKNOWN").upper(),
                        "path": path,
                        "handler": str(route.get("handler", "") or "")[:160],
                        "file_path": str(route.get("file_path", "") or "")[:260],
                        "auth": str(route.get("auth", "Unknown") or "Unknown")[:40],
                        "params": route.get("params", [])[:6] if isinstance(route.get("params"), list) else [],
                        "notes": str(route.get("notes", "") or "")[:200],
                    }
                )
            if normalized_routes:
                normalized_arch["routes"] = normalized_routes

    normalized_vulns = []
    vulnerabilities = response.get("vulnerabilities", [])
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities[:max_vulnerabilities]:
            if not isinstance(vuln, dict):
                continue
            normalized_vulns.append(
                {
                    "title": str(vuln.get("title", "") or "")[:160],
                    "severity": str(vuln.get("severity", "") or "")[:20],
                    "vuln_type": str(vuln.get("vuln_type", "") or "")[:120],
                    "file_path": str(vuln.get("file_path", "") or "")[:260],
                    "line_start": int(vuln.get("line_start", 0) or 0),
                    "line_end": int(vuln.get("line_end", 0) or 0),
                    "code_snippet": str(vuln.get("code_snippet", "") or "")[:1200],
                    "endpoint": str(vuln.get("endpoint", "") or "")[:260],
                    "poc_raw": str(vuln.get("poc_raw", "") or "")[:1500],
                    "description": str(vuln.get("description", "") or "")[:1200],
                    "fix_suggestion": str(vuln.get("fix_suggestion", "") or "")[:800],
                    "confidence": str(vuln.get("confidence", "medium") or "medium")[:20],
                }
            )

    stage_summary = str(response.get("stage_summary", "") or "").strip()
    if not stage_summary:
        stage_summary = f"阶段{stage_num} 模型响应出现截断，系统已根据可恢复字段整理为完整 JSON。"

    normalized = {
        "stage_summary": stage_summary[:1200],
        "architecture_info": normalized_arch,
        "vulnerabilities": normalized_vulns,
        "_recovered_from_incomplete_response": True,
    }
    if response.get("parse_error"):
        normalized["_recovery_reason"] = str(response.get("parse_error"))[:200]
    return normalized, True


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


def _severity_rank(severity: str) -> int:
    order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    return order.get(str(severity or "").strip(), 0)


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


def _build_vulnerability_poc_repair_prompt(
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
        "raw_http": "当前漏洞必须修正为完整 raw HTTP 请求包，至少包含请求行、Host、必要 Header 和请求体（如需要），并与 endpoint 对齐。",
        "stepwise": "当前漏洞可使用步骤化 PoC 或完整 raw HTTP 请求包；如果保留步骤化描述，必须写清前置条件、攻击步骤和预期结果。",
        "cli": "当前漏洞可使用命令行验证、配置 diff、日志/环境变量检查或完整 raw HTTP 请求包，必须能直接指导人工复现。",
        "none": "当前漏洞无需补 PoC，保持代码证据说明即可。",
    }.get(requirement, "请根据漏洞类型修正为可复现的 PoC，不要编造不存在的请求。")

    return "\n".join(
        [
            "修复当前漏洞的 PoC 可复现性问题。只处理这一条漏洞，不要新增其他漏洞。",
            "必须返回单个合法 JSON 对象，不要返回数组，不要输出 Markdown。",
            "默认保持以下字段不变：title、severity、vuln_type、file_path、line_start、line_end。",
            "允许修正以下字段：endpoint、code_snippet、poc_raw、description、fix_suggestion。",
            "若 endpoint 缺失或与 PoC 不匹配，可以根据代码和静态路由线索修正 endpoint；若证据不足，则保留原值，不要编造。",
            poc_requirement_text,
            f"当前校验失败原因：{validation_reason or '未提供明确原因'}。请优先修复这个问题。",
            "",
            "[当前阶段要求]",
            stage_prompt,
            "",
            "[待修复漏洞]",
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


def _poc_repair_priority(stage_num: int, vuln: dict) -> int:
    score = _vulnerability_detail_priority(vuln)
    validation = vuln.get("_poc_validation")
    if not isinstance(validation, dict):
        validation = _validate_vulnerability_poc(stage_num, vuln)
    if not validation.get("accepted"):
        score += 60
    if not str(vuln.get("endpoint", "") or "").strip():
        score += 20
    return score


def _poc_quality_score(stage_num: int, vuln: dict, validation: dict | None = None) -> int:
    if not isinstance(vuln, dict):
        return 0
    validation = validation if isinstance(validation, dict) else _validate_vulnerability_poc(stage_num, vuln)
    requirement = _classify_poc_requirement(stage_num, vuln)
    poc_raw = str(vuln.get("poc_raw", "") or "").strip()
    endpoint = str(vuln.get("endpoint", "") or "").strip()
    score = 0
    if validation.get("accepted"):
        score += 100
    if endpoint:
        score += 20
    if poc_raw:
        score += min(20, max(1, len(poc_raw) // 80))
    if requirement == "raw_http":
        packet = _parse_raw_http_request(poc_raw)
        if packet.get("valid"):
            score += 25
    elif requirement == "stepwise":
        if _looks_like_stepwise_poc(poc_raw) or _parse_raw_http_request(poc_raw).get("valid"):
            score += 20
    elif requirement == "cli":
        if _looks_like_cli_or_config_poc(poc_raw) or _parse_raw_http_request(poc_raw).get("valid"):
            score += 20
    return score


async def _repair_invalid_vulnerability_pocs(
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
    max_items = min(2, max(0, int(policy.get("detail_enrichment_max_items", 4) or 0)))
    if max_items <= 0:
        return response

    candidates: list[tuple[int, dict]] = []
    for index, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        validation = vuln.get("_poc_validation")
        if not isinstance(validation, dict):
            validation = _validate_vulnerability_poc(stage.stage_num, vuln)
            vuln["_poc_validation"] = validation
        if validation.get("accepted"):
            continue
        if _classify_poc_requirement(stage.stage_num, vuln) == "none":
            continue
        candidates.append((index, vuln))

    if not candidates:
        return response

    candidates.sort(key=lambda item: (-_poc_repair_priority(stage.stage_num, item[1]), item[0]))
    candidate_indexes = {index for index, _ in candidates[:max_items]}
    semaphore = asyncio.Semaphore(1)

    async def repair_one(vuln: dict) -> dict:
        original_validation = vuln.get("_poc_validation")
        if not isinstance(original_validation, dict):
            original_validation = _validate_vulnerability_poc(stage.stage_num, vuln)
        prompt = _build_vulnerability_poc_repair_prompt(
            stage=stage,
            stage_prompt=stage_prompt,
            vulnerability=vuln,
            code_text=code_text,
            prev_context=prev_context,
            static_routes=static_routes,
        )
        async with semaphore:
            repair_result = await call_llm_with_meta(llm_config, SYSTEM_BASE, prompt)
        if not repair_result.get("success"):
            return vuln

        repair_response = _parse_structured_response(repair_result["content"], repair_result.get("meta"))
        if not isinstance(repair_response, dict) or repair_response.get("parse_error"):
            return vuln

        repaired = dict(vuln)
        for field in ["endpoint", "code_snippet", "poc_raw", "description", "fix_suggestion"]:
            value = repair_response.get(field)
            if value is None:
                continue
            if isinstance(value, str):
                if value.strip():
                    repaired[field] = value
            else:
                repaired[field] = value
        repaired.pop("_poc_template_generated", None)
        repaired_validation = _validate_vulnerability_poc(stage.stage_num, repaired)
        repaired["_poc_validation"] = repaired_validation

        if _poc_quality_score(stage.stage_num, repaired, repaired_validation) <= _poc_quality_score(stage.stage_num, vuln, original_validation):
            vuln["_poc_validation"] = original_validation
            return vuln

        repaired["_poc_repaired"] = True
        return repaired

    repair_tasks = {
        index: asyncio.create_task(repair_one(vuln))
        for index, vuln in candidates[:max_items]
    }

    repaired_vulns: list[dict] = []
    changed = False
    repaired_count = 0
    for index, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        if index not in candidate_indexes:
            repaired_vulns.append(vuln)
            continue

        repaired = await repair_tasks[index]
        repaired_vulns.append(repaired)
        if repaired is not vuln:
            changed = True
        if isinstance(repaired, dict) and repaired.get("_poc_repaired"):
            repaired_count += 1

    if not changed:
        return response

    normalized = dict(response)
    normalized["vulnerabilities"] = repaired_vulns
    normalized["_poc_repair_policy"] = {"max_items": max_items}
    normalized["_poc_repair_count"] = repaired_count
    if repaired_count:
        normalized["_poc_repair_applied"] = True
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
        merged_response = _merge_stage1_pass_response(merged_response, selected_response)
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
    merged_response = _merge_stage1_pass_response(current_response, followup_payload)
    merged_response["_stage5_followup_applied"] = True
    followup_meta["new_vulnerability_count"] = len(filtered_new[:2])
    return merged_response, followup_meta


def _enforce_vulnerability_output_policy(stage, response: dict) -> tuple[dict, dict]:
    if not isinstance(response, dict):
        return {"vulnerabilities": []}, {"invalid_poc_vulnerabilities": 0, "invalid_poc_titles": [], "merged_duplicate_vulnerabilities": 0}

    vulnerabilities = response.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return response, {"invalid_poc_vulnerabilities": 0, "invalid_poc_titles": [], "merged_duplicate_vulnerabilities": 0}

    annotated: list[dict] = []
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        vuln = normalize_vulnerability_fields(vuln)
        vuln["severity"] = _normalize_severity(vuln.get("severity", "Medium"))
        validation = _validate_vulnerability_poc(stage.stage_num, vuln)
        vuln["_poc_validation"] = validation
        annotated.append(vuln)

    deduped = _merge_vulnerability_lists([], annotated)
    invalid_items: list[dict] = []
    for vuln in deduped:
        validation = vuln.get("_poc_validation") if isinstance(vuln.get("_poc_validation"), dict) else {}
        if not validation.get("accepted"):
            invalid_items.append(
                {
                    "title": str(vuln.get("title", "未命名漏洞")).strip() or "未命名漏洞",
                    "reason": validation.get("reason", "POC 不符合规范"),
                }
            )
    normalized = dict(response)
    normalized["vulnerabilities"] = deduped
    if invalid_items:
        normalized["_invalid_poc_vulnerabilities"] = invalid_items[:20]
    return normalized, {
        "invalid_poc_vulnerabilities": len(invalid_items),
        "invalid_poc_titles": [item["title"] for item in invalid_items[:10]],
        "merged_duplicate_vulnerabilities": max(0, len(annotated) - len(deduped)),
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


def _parse_endpoint_hint(endpoint_text: str) -> tuple[str, str]:
    endpoint_text = str(endpoint_text or "").strip()
    if not endpoint_text:
        return "UNKNOWN", ""
    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|ANY|UNKNOWN)\s+(\S+)$", endpoint_text, re.I)
    if match:
        return match.group(1).upper(), _normalize_http_path(match.group(2).strip())
    return "UNKNOWN", _normalize_http_path(endpoint_text)


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


def _materialize_route_path(path: str) -> str:
    text = _normalize_http_path(path)
    if not text:
        return ""
    text = re.sub(r"\{[^}/]+\}", "1", text)
    text = re.sub(r"<[^>/]+>", "1", text)
    text = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "1", text)
    return text


def _sample_poc_value(name: str) -> str | int | bool:
    lowered = str(name or "").strip().lower()
    if any(token in lowered for token in ["id", "_id", "ids", "page", "limit", "offset", "count", "size"]):
        return 1
    if any(token in lowered for token in ["enabled", "active", "admin", "debug", "flag"]):
        return True
    if "email" in lowered:
        return "audit@example.com"
    if any(token in lowered for token in ["token", "jwt", "code", "key", "secret"]):
        return "test-token"
    return "test"


def _split_route_params(params: list) -> tuple[list[str], list[str], list[str]]:
    query_params: list[str] = []
    body_params: list[str] = []
    path_params: list[str] = []

    for item in params if isinstance(params, list) else []:
        name = str(item or "").strip()
        if not name:
            continue
        lowered = name.lower()
        if lowered.startswith("query."):
            query_params.append(name.split(".", 1)[1])
        elif lowered.startswith("body.") or lowered.startswith("json.") or lowered.startswith("form."):
            body_params.append(name.split(".", 1)[1])
        elif lowered.startswith("path.") or lowered.startswith("param.") or lowered.startswith("params."):
            path_params.append(name.split(".", 1)[1])
        else:
            body_params.append(name)

    return _merge_unique_items([], query_params), _merge_unique_items([], body_params), _merge_unique_items([], path_params)


def _build_route_auth_headers(auth: str) -> list[str]:
    auth_value = str(auth or "Unknown").strip()
    if auth_value == "JWT":
        return ["Authorization: Bearer <JWT_TOKEN>"]
    if auth_value == "OAuth":
        return ["Authorization: Bearer <OAUTH_TOKEN>"]
    if auth_value == "Session":
        return ["Cookie: session=<SESSION_ID>"]
    return []


def _build_route_derived_raw_http_artifacts(vuln: dict, route_candidate: dict | None) -> tuple[str, str]:
    endpoint_method, endpoint_path = _parse_endpoint_hint(str(vuln.get("endpoint", "") or ""))
    route_method = str((route_candidate or {}).get("method", "") or endpoint_method or "GET").upper()
    route_path = str((route_candidate or {}).get("path", "") or endpoint_path or "").strip()
    if not route_path:
        return "", ""

    params = (route_candidate or {}).get("params", []) if isinstance((route_candidate or {}).get("params"), list) else []
    auth = str((route_candidate or {}).get("auth", "Unknown") or "Unknown").strip()
    concrete_path = _materialize_route_path(route_path)
    query_params, body_params, _ = _split_route_params(params)
    query_string = "&".join(f"{name}={_sample_poc_value(name)}" for name in query_params[:8])
    request_target = concrete_path if not query_string else f"{concrete_path}?{query_string}"

    headers = ["Host: example.com"]
    headers.extend(_build_route_auth_headers(auth))
    body = ""

    if route_method in {"POST", "PUT", "PATCH", "DELETE"}:
        payload = {name: _sample_poc_value(name) for name in body_params[:8]}
        headers.append("Content-Type: application/json")
        body = json.dumps(payload or {"test": "value"}, ensure_ascii=False, indent=2)

    request_lines = [f"{route_method or 'GET'} {request_target} HTTP/1.1", *headers, ""]
    if body:
        request_lines.append(body)
    return f"{route_method} {concrete_path}".strip(), "\n".join(request_lines).strip()


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


def _validate_vulnerability_poc(stage_num: int, vuln: dict) -> dict:
    requirement = _classify_poc_requirement(stage_num, vuln)
    endpoint = str(vuln.get("endpoint", "") or "").strip()
    poc_raw = str(vuln.get("poc_raw", "") or "").strip()
    if requirement == "none":
        return {"accepted": True, "reason": "code_evidence_only"}
    if vuln.get("_poc_template_generated"):
        return {"accepted": False, "reason": "已根据静态路由生成请求模板，仍需补全真实参数和利用前提"}

    if not poc_raw:
        return {"accepted": False, "reason": "缺少 poc_raw"}

    if requirement == "raw_http":
        if not endpoint:
            return {"accepted": False, "reason": "缺少完整路由 endpoint"}
        packet = _parse_raw_http_request(poc_raw)
        if not packet["valid"]:
            return {"accepted": False, "reason": packet["reason"]}
        if not _endpoint_matches_packet(endpoint, packet):
            return {"accepted": False, "reason": "endpoint 与 poc_raw 中的请求行不一致"}
        return {"accepted": True, "reason": "valid_raw_http"}

    if requirement == "stepwise":
        if not endpoint:
            return {"accepted": False, "reason": "缺少完整路由 endpoint"}
        packet = _parse_raw_http_request(poc_raw)
        if packet["valid"]:
            if not _endpoint_matches_packet(endpoint, packet):
                return {"accepted": False, "reason": "endpoint 与 poc_raw 中的请求行不一致"}
            return {"accepted": True, "reason": "valid_raw_http"}
        if _looks_like_stepwise_poc(poc_raw):
            return {"accepted": True, "reason": "valid_stepwise_poc"}
        return {"accepted": False, "reason": "缺少可执行的步骤化 PoC 或合法 raw HTTP 请求包"}

    if requirement == "cli":
        packet = _parse_raw_http_request(poc_raw)
        if packet["valid"]:
            if endpoint and not _endpoint_matches_packet(endpoint, packet):
                return {"accepted": False, "reason": "endpoint 与 poc_raw 中的请求行不一致"}
            return {"accepted": True, "reason": "valid_raw_http"}
        if _looks_like_cli_or_config_poc(poc_raw):
            return {"accepted": True, "reason": "valid_cli_or_config_poc"}
        return {"accepted": False, "reason": "缺少可执行的命令行验证、配置 diff 或合法 raw HTTP 请求包"}

    return {"accepted": True, "reason": "requirement_unclassified"}


def _requires_strict_http_poc(stage_num: int, vuln: dict) -> bool:
    return _classify_poc_requirement(stage_num, vuln) == "raw_http"


def _classify_poc_requirement(stage_num: int, vuln: dict) -> str:
    # 先按漏洞语义判断 PoC 形态，阶段号只作为兜底，避免业务逻辑类被误判成必须 raw HTTP。
    haystack = " ".join(
        [
            str(vuln.get("title", "") or ""),
            str(vuln.get("vuln_type", "") or ""),
            str(vuln.get("description", "") or ""),
            str(vuln.get("fix_suggestion", "") or ""),
            str(vuln.get("endpoint", "") or ""),
            str(vuln.get("file_path", "") or ""),
            str(vuln.get("poc_raw", "") or ""),
        ]
    ).lower()

    none_markers = [
        "硬编码",
        "hardcoded",
        "hard code",
        "hard-coded",
        "api key",
        "access key",
        "private key",
        "secret key",
        "hardcoded secret",
        "ak/sk",
        "弱密码哈希",
        "无盐",
        "无盐 md5",
        "无盐md5",
        "weak md5",
        "weak sha1",
        "密码哈希",
        "哈希算法",
        "无需 poc",
        "无需poc",
        "code evidence only",
    ]
    cli_markers = [
        "配置",
        "config",
        "信息泄露",
        "debug",
        "日志泄露",
        "目录索引",
        "directory listing",
        ".env",
        "env 泄露",
        "stack trace",
        "依赖",
        "dependency",
        "版本泄露",
    ]
    stepwise_markers = [
        "业务逻辑",
        "logic bypass",
        "竞态",
        "race",
        "会话固定",
        "session fixation",
        "暴力破解",
        "brute force",
        "越权",
        "idor",
        "权限绕过",
        "水平越权",
        "垂直越权",
        "支付绕过",
        "下载绕过",
        "流程绕过",
        "状态机",
        "多步",
    ]
    raw_http_markers = [
        "sqli",
        "nosqli",
        "注入",
        "rce",
        "命令执行",
        "command execution",
        "ssrf",
        "xss",
        "文件上传",
        "文件下载",
        "路径穿越",
        "目录遍历",
        "任意文件",
        "反序列化",
        "模板注入",
        "表达式注入",
    ]

    if any(marker in haystack for marker in none_markers):
        return "none"
    if any(marker in haystack for marker in cli_markers):
        return "cli"
    if any(marker in haystack for marker in stepwise_markers):
        return "stepwise"
    if any(marker in haystack for marker in raw_http_markers):
        return "raw_http"

    if stage_num in {2, 3, 4, 8}:
        return "raw_http"
    if stage_num in {5, 6, 9}:
        return "stepwise"
    if stage_num == 7:
        return "cli"
    return "none" if stage_num == 1 else "raw_http"


def _looks_like_stepwise_poc(poc_raw: str) -> bool:
    text = str(poc_raw or "").strip()
    if not text:
        return False
    lines = [line.strip() for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if len(lines) < 2:
        return False
    step_pattern = re.compile(r"^(\d+[.)、]|步骤\s*[一二三四五六七八九十0-9]+[：:]?|step\s*\d+[：:]?)", re.I)
    if any(step_pattern.match(line) for line in lines):
        return True
    lowered = text.lower()
    step_markers = ["步骤", "复现", "攻击流程", "利用流程", "先 ", "然后", "再 ", "最后", "登录后"]
    return sum(1 for marker in step_markers if marker in lowered) >= 2


def _looks_like_cli_or_config_poc(poc_raw: str) -> bool:
    text = str(poc_raw or "").strip()
    if not text:
        return False
    lowered = text.lower()
    cli_markers = [
        "curl ",
        "wget ",
        "httpie ",
        "grep ",
        "findstr ",
        "cat ",
        "type ",
        "php ",
        "python ",
        "node ",
        "diff ",
        "git diff",
        "printenv",
        "set ",
        "export ",
        ".env",
        "配置",
        "环境变量",
        "日志",
        "堆栈",
    ]
    if any(marker in lowered for marker in cli_markers):
        return True
    return any(token in text for token in ["=>", "BEGIN", "END", "---", "+++", "@@"])


def _parse_raw_http_request(poc_raw: str) -> dict:
    lines = [line.rstrip() for line in str(poc_raw or "").replace("\r\n", "\n").split("\n")]
    lines = [line for line in lines if line.strip() or line == ""]
    if not lines:
        return {"valid": False, "reason": "poc_raw 为空"}

    request_line = lines[0].strip()
    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/1\.[01]$", request_line, re.I)
    if not match:
        return {"valid": False, "reason": "缺少合法的 raw HTTP 请求行"}

    method = match.group(1).upper()
    target = match.group(2).strip()
    header_lines = []
    body_lines = []
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line == "":
                in_body = True
                continue
            if ":" not in line and header_lines:
                in_body = True
                body_lines.append(line)
                continue
            header_lines.append(line)
        else:
            body_lines.append(line)

    headers = {}
    for line in header_lines:
        if ":" not in line:
            return {"valid": False, "reason": "存在不合法的 HTTP Header 行"}
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    if "host" not in headers or not headers["host"]:
        return {"valid": False, "reason": "缺少 Host Header"}

    return {
        "valid": True,
        "method": method,
        "target": target,
        "headers": headers,
        "body": "\n".join(body_lines).strip(),
    }


def _endpoint_matches_packet(endpoint: str, packet: dict) -> bool:
    endpoint_text = str(endpoint or "").strip()
    endpoint_method = "ANY"
    endpoint_path = endpoint_text

    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|ANY|UNKNOWN)\s+(\S+)$", endpoint_text, re.I)
    if match:
        endpoint_method = match.group(1).upper()
        endpoint_path = match.group(2).strip()

    packet_method = str(packet.get("method", "")).upper()
    packet_target = str(packet.get("target", "")).strip()
    if endpoint_method not in {"ANY", "UNKNOWN"} and endpoint_method != packet_method:
        return False

    packet_path = _normalize_http_path(packet_target)
    endpoint_path = _normalize_http_path(endpoint_path)
    if endpoint_path == packet_path:
        return True
    if endpoint_path and packet_path and (endpoint_path in packet_path or packet_path in endpoint_path):
        return True
    if endpoint_method == "ANY" and endpoint_path:
        endpoint_tail = endpoint_path.rsplit("/", 1)[-1]
        packet_tail = packet_path.rsplit("/", 1)[-1]
        if endpoint_tail and endpoint_tail == packet_tail:
            return True
    return False


def _normalize_http_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("http://") or text.startswith("https://"):
        text = re.sub(r"^https?://[^/]+", "", text, flags=re.I) or "/"
    text = text.split("?", 1)[0].split("#", 1)[0].strip()
    if not text.startswith("/"):
        text = "/" + text.lstrip("/")
    text = re.sub(r"/{2,}", "/", text)
    if len(text) > 1 and text.endswith("/"):
        text = text.rstrip("/")
    return text


def _normalize_llm_json_text(raw: str) -> str:
    text = (raw or "").strip()
    text = text.replace("\ufeff", "").replace("\u200b", "")
    text = text.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
    if text.startswith("```"):
        lines = text.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _extract_best_json_candidate(text: str) -> str:
    for start_char in ["{", "["]:
        start_idx = text.find(start_char)
        if start_idx == -1:
            continue
        object_text, _ = _extract_balanced_json_value(text, start_idx)
        if object_text:
            return object_text

    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start_idx = text.find(start_char)
        end_idx = text.rfind(end_char)
        if start_idx != -1 and end_idx > start_idx:
            return text[start_idx : end_idx + 1]
    return ""


def _salvage_partial_structured_response(text: str, raw: str) -> dict | None:
    stage_summary = _extract_partial_json_string_field(text, "stage_summary") or ""
    architecture_info = _extract_partial_architecture_info(text)
    vulnerabilities = _extract_partial_vulnerabilities(text)
    if not vulnerabilities and not stage_summary and not architecture_info:
        return None

    for vuln in vulnerabilities:
        if isinstance(vuln, dict):
            vuln["_salvaged"] = True

    if not stage_summary and architecture_info:
        stage_summary = _generate_fallback_stage_summary(architecture_info)

    return {
        "_salvaged": True,
        "raw_response": raw,
        "parse_error": "模型响应 JSON 不完整，已从截断内容中恢复部分漏洞数据",
        "response_incomplete": _looks_like_truncated_response(text),
        "stage_summary": stage_summary,
        "architecture_info": architecture_info,
        "vulnerabilities": vulnerabilities,
    }


def _generate_fallback_stage_summary(architecture_info: dict) -> str:
    parts = []
    tech_stack = architecture_info.get("tech_stack", "")
    framework = architecture_info.get("framework", "")
    database = architecture_info.get("database", "")
    auth = architecture_info.get("auth_mechanism", "")
    routes = architecture_info.get("routes", [])
    if isinstance(routes, list):
        route_count = len(routes)
    else:
        route_count = 0
    modules = architecture_info.get("modules", [])
    if isinstance(modules, list):
        module_count = len(modules)
    else:
        module_count = 0

    if tech_stack:
        parts.append(f"技术栈：{tech_stack}")
    if framework:
        parts.append(f"框架：{framework}")
    if database:
        parts.append(f"数据库：{database}")
    if auth:
        parts.append(f"认证方式：{auth}")
    if route_count:
        parts.append(f"识别到 {route_count} 条路由")
    if module_count:
        parts.append(f"{module_count} 个功能模块")

    if parts:
        return "项目架构概要（从截断响应中恢复）：" + "；".join(parts) + "。"
    return "模型响应被截断，架构信息不完整，已恢复部分数据。"


def _looks_like_truncated_response(text: str) -> bool:
    stripped = (text or "").rstrip()
    if not stripped:
        return False
    return not stripped.endswith(("}", "]"))


def _extract_partial_architecture_info(text: str) -> dict:
    marker = '"architecture_info"'
    marker_index = text.find(marker)
    if marker_index == -1:
        return {}

    object_start = text.find("{", marker_index)
    if object_start == -1:
        return {}

    object_text, _ = _extract_balanced_json_value(text, object_start)
    if object_text:
        try:
            value = json.loads(object_text)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            pass

    data = {}
    for key in ["tech_stack", "framework", "database", "auth_mechanism"]:
        value = _extract_partial_json_string_field(text[object_start:], key)
        if value:
            data[key] = value
    return data


def _extract_partial_vulnerabilities(text: str) -> list[dict]:
    marker = '"vulnerabilities"'
    marker_index = text.find(marker)
    if marker_index == -1:
        return []

    array_start = text.find("[", marker_index)
    if array_start == -1:
        return []

    decoder = json.JSONDecoder()
    items: list[dict] = []
    index = array_start + 1
    length = len(text)

    while index < length:
        while index < length and text[index] in " \r\n\t,":
            index += 1
        if index >= length:
            break
        if text[index] == "]":
            break
        if text[index] != "{":
            next_object = text.find("{", index)
            if next_object == -1:
                break
            index = next_object

        try:
            obj, next_index = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            object_text, next_index = _extract_balanced_json_object(text, index)
            if not object_text:
                trailing = _extract_partial_object_fragment(text[index:])
                vuln = _extract_partial_vulnerability_fields(trailing)
                if vuln:
                    items.append(vuln)
                break
            try:
                obj = json.loads(object_text)
            except json.JSONDecodeError:
                vuln = _extract_partial_vulnerability_fields(object_text)
                if vuln:
                    items.append(vuln)
                break
            index = next_index
        else:
            index += next_index

        if isinstance(obj, dict):
            items.append(obj)

    if items:
        return items

    return _extract_vulnerabilities_by_field_patterns(text[array_start + 1 :])


def _extract_vulnerabilities_by_field_patterns(text: str) -> list[dict]:
    object_segments = _split_partial_object_segments(text)
    items: list[dict] = []

    for segment in object_segments[:20]:
        vuln = _extract_partial_vulnerability_fields(segment)
        if vuln:
            items.append(vuln)

    return items


def _split_partial_object_segments(text: str) -> list[str]:
    segments: list[str] = []
    cursor = 0
    length = len(text)

    while cursor < length:
        start = text.find("{", cursor)
        if start == -1:
            break
        object_text, next_index = _extract_balanced_json_object(text, start)
        if object_text:
            segments.append(object_text)
            cursor = next_index
            continue

        fragment = _extract_partial_object_fragment(text[start:])
        if fragment:
            segments.append(fragment)
        break

    if not segments and text.strip():
        segments.append(text)
    return segments


def _extract_partial_object_fragment(text: str) -> str:
    if not text:
        return ""
    start = text.find("{")
    if start == -1:
        return text

    in_string = False
    escaped = False
    depth = 0

    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue
        if char == "{":
            depth += 1
            continue
        if char == "}":
            depth = max(0, depth - 1)
            continue
        if depth == 1 and char == ",":
            lookahead = text[index + 1 : index + 80]
            if re.match(r'\s*\{', lookahead):
                return text[start:index].rstrip()
            if re.match(r'\s*\]', lookahead):
                return text[start:index].rstrip()
    return text[start:].rstrip()


def _extract_partial_vulnerability_fields(segment: str) -> dict | None:
    keys = [
        "title",
        "severity",
        "vuln_type",
        "file_path",
        "line_start",
        "line_end",
        "code_snippet",
        "endpoint",
        "poc_raw",
        "description",
        "fix_suggestion",
    ]
    data: dict = {}

    for key in keys:
        if key in {"line_start", "line_end"}:
            value = _extract_partial_json_number_field(segment, key)
        else:
            value = _extract_partial_json_string_field(segment, key)
        if value not in (None, ""):
            data[key] = value

    if not any(data.get(key) for key in ("title", "vuln_type", "file_path", "endpoint", "description")):
        return None

    data.setdefault("title", "未命名漏洞")
    data.setdefault("severity", "Medium")
    data.setdefault("vuln_type", "未分类漏洞")
    data.setdefault("file_path", "")
    data.setdefault("code_snippet", "")
    data.setdefault("endpoint", "")
    data.setdefault("poc_raw", "未提供可复现 POC，请结合代码补充复现步骤。")
    data.setdefault("description", "")
    data.setdefault("fix_suggestion", "")
    data["_salvaged"] = True
    return data


def _extract_partial_json_string_field(segment: str, field: str) -> str | None:
    complete_match = re.search(rf'"{re.escape(field)}"\s*:\s*"((?:\\.|[^"\\])*)"', segment, re.S)
    if complete_match:
        return _decode_json_string_fragment(complete_match.group(1))

    partial_match = re.search(rf'"{re.escape(field)}"\s*:\s*"([^\r\n]*)', segment)
    if partial_match:
        return _decode_json_string_fragment(partial_match.group(1)).strip()

    return None


def _extract_partial_json_number_field(segment: str, field: str) -> int | None:
    match = re.search(rf'"{re.escape(field)}"\s*:\s*(-?\d+)', segment)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _decode_json_string_fragment(value: str) -> str:
    try:
        return json.loads(f'"{value}"')
    except Exception:
        return value.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")


def _extract_balanced_json_object(text: str, start_index: int) -> tuple[str, int]:
    return _extract_balanced_json_value(text, start_index, "{", "}")


def _extract_balanced_json_value(
    text: str,
    start_index: int,
    open_char: str = "{",
    close_char: str = "}",
) -> tuple[str, int]:
    depth = 0
    in_string = False
    escaped = False

    for index in range(start_index, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue
        if char == open_char:
            depth += 1
            continue
        if char == close_char:
            depth -= 1
            if depth == 0:
                return text[start_index : index + 1], index + 1

    return "", start_index


def _build_incomplete_json_retry_prompt(
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
    retry_policy: dict | None = None,
) -> str:
    compact_context = dict(compact_context or {})
    retry_policy = retry_policy or _get_stage_retry_policy(stage.stage_num)
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    max_vulnerabilities = int(retry_policy.get("max_vulnerabilities", 5) or 5)
    code_limit = int(retry_policy.get("code_limit", 32000) or 32000)
    prev_context_limit = int(retry_policy.get("prev_context_limit", 2400) or 2400)
    route_limit = int(retry_policy.get("route_limit", 16) or 16)

    retry_guidance = [
        "上一轮响应中的 JSON 不完整，本轮必须优先返回完整闭合、可解析的 JSON。",
        f"请压缩输出体积：architecture_info 仅保留必要字段，vulnerabilities 最多保留 {max_vulnerabilities} 条。",
        "如果 PoC 很长，请只保留最小可复现请求、关键参数或关键触发步骤，不要展开冗长 raw HTTP。",
        "不要输出 Markdown、代码围栏、解释性前后缀或额外文本。",
        "如果确实没有发现漏洞，也必须返回完整 JSON，并使用 vulnerabilities: []。",
    ]
    if stage.stage_num == 3:
        retry_guidance.append("阶段三优先保留最强注入证据和最短 PoC，避免把输出预算耗尽在攻击链叙述上。")
    if stage.stage_num == 5:
        retry_guidance.append("阶段五不要展开完整认证流程，只保留最强认证/会话漏洞证据。")
        retry_guidance.append("阶段五的首要目标是先闭合 JSON，再补 title、severity、vuln_type、file_path、endpoint、description。")
        retry_guidance.append("阶段五首轮最多保留 2 到 3 条漏洞；若登录、注册、验证码、刷新令牌问题本质相同，优先合并为代表性结果。")
    if stage.stage_num == 8:
        retry_guidance.append("阶段八最多保留 3 到 4 条文件操作漏洞，同类路径遍历问题优先合并为代表性结果。")
        retry_guidance.append("阶段八的 architecture_info 只保留最小必要入口、文件读写点和路径校验结论。")
    if stage.stage_num == 9:
        retry_guidance.append("阶段九只保留最强业务逻辑漏洞索引，不要铺陈业务背景或交易流程叙述。")

    compact_context["extra_guidance"] = "\n".join([part for part in [extra_guidance, *retry_guidance] if part])
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 5000) or 5000), 2500)
    if stage.stage_num == 5:
        compact_context["audit_memory_limit"] = min(int(compact_context.get("audit_memory_limit", 1800) or 1800), 1800)

    retry_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", code_limit),
        _truncate_text(prev_context or "", prev_context_limit),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 1500)
    return "\n".join(
        [
            retry_prompt,
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )


def _build_exploit_stage_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:4]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 1200) or 1200), 1200)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:4]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:12]
    compact_context["audit_memory_limit"] = min(int(compact_context.get("audit_memory_limit", 1200) or 1200), 1200)
    stage_label = "阶段二" if stage.stage_num == 2 else "阶段三/四/八"
    compact_context["extra_guidance"] = "\n".join(
        part for part in [
            extra_guidance,
            f"{stage_label} 进入骨架恢复模式：本次目标只有一个，先返回完整闭合 JSON。",
            "只输出最多 2 条最强漏洞结果。",
            "不要展开攻击面背景，不要输出长篇利用链叙述。",
            "每条 vulnerability 优先填写：title、severity、vuln_type、file_path、line_start、line_end、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以先写短字符串或空字符串，后续再补齐。",
        ] if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 9000),
        _truncate_text(prev_context or "", 500),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 1000)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Exploit skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )


def _build_stage9_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:4]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 1200) or 1200), 1200)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:4]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:12]
    compact_context["extra_guidance"] = "\n".join(
        part
        for part in [
            extra_guidance,
            "阶段九进入骨架恢复模式：本次目标只有一个，先返回完整闭合 JSON。",
            "只输出最多 2 条最强业务逻辑漏洞。",
            "architecture_info 仅保留 tech_stack、framework，以及最多 3 条 routes。",
            "每条 vulnerability 仅优先填写：title、severity、vuln_type、file_path、line_start、line_end、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以留空字符串，后续会单独补全。",
            "不要展开业务背景，不要写长段说明，不要为了完整叙述牺牲 JSON 闭合。",
        ]
        if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 9000),
        _truncate_text(prev_context or "", 500),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 1000)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Stage 9 skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )


def _build_stage5_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:4]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 1200) or 1200), 1200)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:4]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:12]
    compact_context["extra_guidance"] = "\n".join(
        part
        for part in [
            extra_guidance,
            "阶段五进入骨架恢复模式：本次先返回完整闭合 JSON。",
            "只输出最多 1 到 2 条最强认证与会话安全漏洞。",
            "不要展开登录、注册、找回密码、验证码、刷新令牌等完整流程背景。",
            "每条 vulnerability 优先填写：title、severity、vuln_type、file_path、line_start、line_end、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以先留空字符串，后续再补全。",
        ]
        if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 7000),
        _truncate_text(prev_context or "", 350),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 1000)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Stage 5 skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )


def _build_lightweight_stage_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:3]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", 1000) or 1000), 1000)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:3]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:10]
    compact_context["extra_guidance"] = "\n".join(
        part for part in [
            extra_guidance,
            f"阶段{stage.stage_num} 进入骨架恢复模式：本次先保证 JSON 完整闭合。",
            "只保留最必要的阶段结论和漏洞索引。",
            "每条 vulnerability 优先填写：title、severity、vuln_type、file_path、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以留空字符串或极短说明。",
        ] if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 8000),
        _truncate_text(prev_context or "", 400),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 800)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Lightweight skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )


def _build_summary_stage_skeleton_retry_prompt(
    *,
    stage,
    project,
    stage_prompt: str,
    code_text: str,
    prev_context: str,
    static_routes: list[dict],
    compact_context: dict | None,
    audit_memory: dict | None,
    previous_raw_response: str,
) -> str:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    compact_context["route_lines"] = []
    compact_context["route_text_limit"] = 0
    compact_context["rule_hit_lines"] = []
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:10]
    compact_context["extra_guidance"] = "\n".join(
        part for part in [
            extra_guidance,
            "进入骨架恢复模式：先返回完整闭合 JSON，再考虑扩展说明。",
            "只保留综合结论、最关键架构摘要和最多 3 条代表性漏洞。",
            "architecture_info 保持最小化，vulnerabilities 仅保留核心字段。",
            "每条 vulnerability 优先填写：title、severity、vuln_type、file_path、endpoint、description。",
            "code_snippet、poc_raw、fix_suggestion 可以留空字符串或极短说明。",
        ] if part
    )

    skeleton_prompt = _build_stage_user_prompt(
        stage,
        project,
        stage_prompt,
        _truncate_text(code_text or "", 8000),
        _truncate_text(prev_context or "", 400),
        static_routes,
        compact_context=compact_context,
        audit_memory=_compact_audit_memory_for_stage(stage.stage_num, audit_memory or {}),
    )
    previous_excerpt = _truncate_text(_normalize_llm_json_text(previous_raw_response or ""), 800)
    return "\n".join(
        [
            skeleton_prompt,
            "",
            "[Summary skeleton mode JSON schema]",
            "{",
            '  "stage_summary": "中文阶段结论，1到2句",',
            '  "architecture_info": {',
            '    "tech_stack": "",',
            '    "framework": "",',
            '    "database": "",',
            '    "auth_mechanism": "",',
            '    "routes": []',
            "  },",
            '  "vulnerabilities": [',
            "    {",
            '      "title": "",',
            '      "severity": "Critical|High|Medium|Low|Info",',
            '      "vuln_type": "",',
            '      "file_path": "",',
            '      "line_start": 0,',
            '      "line_end": 0,',
            '      "code_snippet": "",',
            '      "endpoint": "",',
            '      "poc_raw": "",',
            '      "description": "",',
            '      "fix_suggestion": ""',
            "    }",
            "  ]",
            "}",
            "",
            "[Previous incomplete response excerpt]",
            previous_excerpt or "N/A",
            "",
            "Return valid JSON only.",
        ]
    )


def _is_static_asset_chunk(file_path: str) -> bool:
    path = str(file_path or "").lower()
    if not path:
        return False
    static_suffixes = (
        ".min.js",
        ".min.css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".avi",
        ".pdf",
    )
    if path.endswith(static_suffixes):
        return True
    static_markers = [
        "/assets/",
        "\\assets\\",
        "/static/",
        "\\static\\",
        "/fonts/",
        "\\fonts\\",
        "/images/",
        "\\images\\",
        "/cache/index.html",
        "\\cache\\index.html",
    ]
    return any(marker in path for marker in static_markers)


def _score_stage8_chunk(chunk: dict) -> int:
    file_path = str(chunk.get("file_path", "") or "").lower()
    content_head = str(chunk.get("content", "") or "")[:6000].lower()
    haystack = f"{file_path}\n{content_head}"
    score = 0

    strong_keywords = [
        "move_uploaded_file",
        "readfile(",
        "file_get_contents",
        "file_put_contents",
        "fopen(",
        "fwrite(",
        "fread(",
        "unlink(",
        "mkdir(",
        "rmdir(",
        "copy(",
        "rename(",
        "ziparchive",
        "extractto",
        "realpath",
        "pathinfo(",
        "basename(",
        "scandir(",
        "opendir(",
        "readdir(",
        "glob(",
        "download",
        "upload",
        "attachment",
        "archive",
        "backup",
        "import",
        "export",
        "tempfile",
        "mktemp",
        "symlink",
        "readlink",
        "move_uploaded_file",
        "is_uploaded_file",
        "parse_ini_file",
        "chdir(",
        "chroot(",
        "multipartfile",
        "files.delete",
        "files.copy",
        "files.move",
        "fs.unlink",
        "fs.readfile",
        "fs.writefile",
        "filepath.join",
        "filepath.clean",
        "shutil.rmtree",
        "shutil.copy",
        "shutil.move",
        "shutil.unpack_archive",
        "sendfile",
        "send_file",
        "content-disposition",
        "phar(",
    ]
    medium_keywords = [
        "file",
        "path",
        "open(",
        "os.path",
        "filesystem",
        "storage",
        "saveas",
        "zip",
        "tar",
        "../",
        "..\\",
        "directory",
        "folder",
        "read(",
        "write(",
        "stream",
        "blob",
        "chunk",
        "buffer",
        "tmp",
        "temp",
        "filename",
        "extension",
        "mime_type",
        "content_type",
    ]
    weak_noise = [
        "index.html",
        "<html",
        "jquery",
        "sweetalert",
        "datatables",
        "fontawesome",
        "plupload.min",
        ".min.js", ".min.css",
        "bootstrap", "lodash.min", "underscore.min",
        "react-dom.production", "react.production",
        "angular.min", "vue.min", "d3.min", "chart.min",
        "tinymce", "ckeditor", "monaco", "codemirror",
        "three.min", "echarts.min", "antd.min",
        "element-ui", "ant-design",
        "/vendor/", "\\vendor\\",
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/node_modules/", "\\node_modules\\",
        ".test.js", ".spec.js", ".test.ts", ".spec.ts",
        "_test.py", "_test.go",
        "/migrations/", "\\migrations\\",
        "/generated/", "\\generated\\",
        "/docs/", "\\docs\\",
        "/demo/", "\\demo\\",
    ]

    score += sum(4 for keyword in strong_keywords if keyword in haystack)
    score += sum(1 for keyword in medium_keywords if keyword in haystack)
    score -= sum(2 for keyword in weak_noise if keyword in haystack)

    if any(token in file_path for token in ["upload", "download", "file", "path", "backup", "archive", "import", "export"]):
        score += 4
    if any(token in file_path for token in ["/admin/", "\\admin\\", "/front/", "\\front\\"]):
        score += 1
    if any(file_path.endswith(ext) for ext in [".php", ".py", ".java", ".go", ".rb", ".cs", ".js", ".ts"]):
        score += 2
    if any(token in file_path for token in [".min.", "/cache/", "\\cache\\", "/open/assets/", "\\open\\assets\\"]):
        score -= 5

    return score


def _select_stage8_chunks(
    chunks: list[dict],
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> list[dict]:
    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "")
        if _is_static_asset_chunk(file_path):
            continue
        score = _score_stage8_chunk(chunk) + _shared_chunk_priority_boost(
            chunk,
            stage_num=8,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if score > 0:
            scored.append((score, chunk))
        elif len(fallback) < 80:
            fallback.append(chunk)

    scored.sort(
        key=lambda item: (
            -item[0],
            str(item[1].get("file_path", "") or ""),
        )
    )
    selected = [chunk for _, chunk in scored[:24]]
    if len(selected) < 12:
        selected.extend(fallback[: 12 - len(selected)])
    return selected or chunks[:12]


def _score_stage4_chunk(chunk: dict) -> int:
    file_path = str(chunk.get("file_path", "") or "").lower()
    content_head = str(chunk.get("content", "") or "")[:7000].lower()
    haystack = f"{file_path}\n{content_head}"
    score = 0

    strong_keywords = [
        "innerhtml",
        "outerhtml",
        "document.write",
        "dangerouslysetinnerhtml",
        "v-html",
        "render(",
        "template",
        "echo $_get",
        "echo $_post",
        "htmlspecialchars",
        "strip_tags",
        "sanitize",
        "escape",
        "xss",
        "insertadjacenthtml",
        "domparser",
        "parsefromstring",
        "srcdoc",
        "javascript:",
        "bypasssecuritytrusthtml",
        "bypasssecuritytrusturl",
        "domsanitizer",
        "[innerhtml]",
        "v-bind:html",
        "contenteditable",
        "document.writeln",
        "writeln",
        "createtextnode",
        "object.data",
        "embed.src",
        "iframe.src",
        "location.href",
        "postmessage(",
    ]
    medium_keywords = [
        ".vue",
        ".jsx",
        ".tsx",
        ".html",
        "render",
        "html",
        "iframe",
        "script",
        "onclick",
        "onerror",
        "contenteditable",
        "onload=",
        "onfocus=",
        "onmouseover=",
        "data:",
        "encodeuricomponent",
        "decodeuricomponent",
        "textcontent",
        "innertext",
        "createelement",
    ]
    weak_noise = [
        ".min.js",
        ".min.css",
        "jquery.min",
        "fontawesome",
        "sweetalert",
        "datatables",
        "bootstrap", "lodash.min", "underscore.min",
        "react-dom.production", "react.production",
        "angular.min", "vue.min", "d3.min", "chart.min",
        "tinymce", "ckeditor", "monaco", "codemirror",
        "three.min", "echarts.min", "antd.min",
        "element-ui", "ant-design",
        "/vendor/", "\\vendor\\",
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/node_modules/", "\\node_modules\\",
        ".test.js", ".spec.js", ".test.ts", ".spec.ts",
        "/docs/", "\\docs\\",
        "/demo/", "\\demo\\",
    ]

    score += sum(4 for keyword in strong_keywords if keyword in haystack)
    score += sum(1 for keyword in medium_keywords if keyword in haystack)
    score -= sum(2 for keyword in weak_noise if keyword in haystack)

    if any(token in file_path for token in ["template", "view", "render", "admin", "front"]):
        score += 2
    if any(file_path.endswith(ext) for ext in [".php", ".vue", ".jsx", ".tsx", ".js", ".ts", ".html"]):
        score += 2
    if any(token in file_path for token in ["/cache/", "\\cache\\", "/open/assets/", "\\open\\assets\\"]):
        score -= 5

    return score


def _select_stage4_chunks(
    chunks: list[dict],
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> list[dict]:
    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "")
        if _is_static_asset_chunk(file_path):
            continue
        score = _score_stage4_chunk(chunk) + _shared_chunk_priority_boost(
            chunk,
            stage_num=4,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if score > 0:
            scored.append((score, chunk))
        elif len(fallback) < 80:
            fallback.append(chunk)

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "") or "")))
    selected = [chunk for _, chunk in scored[:24]]
    if len(selected) < 12:
        selected.extend(fallback[: 12 - len(selected)])
    return selected or chunks[:12]


def _score_stage5_chunk(chunk: dict) -> int:
    file_path = str(chunk.get("file_path", "") or "").lower()
    content_head = str(chunk.get("content", "") or "")[:7000].lower()
    haystack = f"{file_path}\n{content_head}"
    score = 0

    strong_keywords = [
        "login",
        "logout",
        "session_start",
        "session_regenerate_id",
        "setcookie",
        "cookie(",
        "jwt",
        "bearer",
        "oauth",
        "password_hash",
        "password_verify",
        "md5(",
        "sha1(",
        "captcha",
        "token",
        "signin",
        "signup",
        "remember",
        "authenticate",
        "verify_token",
        "validate_token",
        "refresh_token",
        "access_token",
        "saml",
        "samlresponse",
        "kerberos",
        "ntlm",
        "recaptcha",
        "hcaptcha",
        "totp",
        "mfa",
        "2fa",
        "bcrypt",
        "argon2",
        "pbkdf2",
        "antiforgerytoken",
        "xsrf",
        "_csrf",
        "password_reset",
        "forgot_password",
        "session_destroy",
        "session_id(",
    ]
    medium_keywords = [
        "auth",
        "session",
        "cookie",
        "user",
        "role",
        "permission",
        "verify",
        "csrf",
        "credential",
        "secret",
        "authorization",
        "identity",
        "principal",
        "claim",
        "privilege",
        "oauth2",
        "openid",
        "sso",
        "logout",
        "register",
        "rate_limit",
        "throttle",
        "lockout",
        "login_attempts",
        "failed_attempts",
        "account_lock",
        "password_change",
        "changepassword",
    ]
    weak_noise = [
        ".min.js",
        ".min.css",
        "index.html",
        "jquery.min",
        "fontawesome",
        "datatables",
        "bootstrap", "lodash.min",
        "react-dom.production", "react.production",
        "angular.min", "vue.min",
        "tinymce", "ckeditor",
        "/vendor/", "\\vendor\\",
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/node_modules/", "\\node_modules\\",
        ".test.js", ".spec.js", ".test.ts", ".spec.ts",
        "/docs/", "\\docs\\",
        "/demo/", "\\demo\\",
    ]

    score += sum(4 for keyword in strong_keywords if keyword in haystack)
    score += sum(1 for keyword in medium_keywords if keyword in haystack)
    score -= sum(2 for keyword in weak_noise if keyword in haystack)

    if any(token in file_path for token in ["login", "session", "oauth", "auth", "user", "role", "captcha", "token"]):
        score += 4
    if any(token in file_path for token in ["/admin/", "\\admin\\", "/front/", "\\front\\", "/api/", "\\api\\"]):
        score += 1
    if any(file_path.endswith(ext) for ext in [".php", ".py", ".java", ".go", ".rb", ".cs", ".js", ".ts"]):
        score += 2
    if any(token in file_path for token in ["/cache/", "\\cache\\", "/open/assets/", "\\open\\assets\\"]):
        score -= 5

    return score


def _select_stage5_chunks(
    chunks: list[dict],
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> list[dict]:
    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "")
        if _is_static_asset_chunk(file_path):
            continue
        score = _score_stage5_chunk(chunk) + _shared_chunk_priority_boost(
            chunk,
            stage_num=5,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if score > 0:
            scored.append((score, chunk))
        elif len(fallback) < 80:
            fallback.append(chunk)

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "") or "")))
    selected = [chunk for _, chunk in scored[:24]]
    if len(selected) < 12:
        selected.extend(fallback[: 12 - len(selected)])
    return selected or chunks[:12]


def _score_stage6_chunk(chunk: dict) -> int:
    file_path = str(chunk.get("file_path", "") or "").lower()
    content = str(chunk.get("content", "") or "")[:5000].lower()
    haystack = f"{file_path}\n{content}"
    score = 0

    strong_signals = [
        "permission", "permissions", "authorize", "authorization", "acl", "role", "roles",
        "tenant", "tenant_id", "owner", "ownership", "resource_id", "user_id", "account_id",
        "idor", "scope", "guard", "policy", "preauthorize", "haspermission", "isadmin",
        "hasrole", "hasauthority", "secured", "roles_allowed",
        "accesscontrol", "access_control", "rbac", "abac",
        "isauthenticated", "isfullyauthenticated", "isrememberme",
        "hasanyrole", "hasanyauthority", "withpermission",
        "checkpermission", "checkauthorization",
        "tenant隔离", "multi_tenant",
        "belongsto", "ownedby", "createdby",
        "resource_type", "target_id", "target_user",
        "impersonate", "sudo", "escalate", "privilege_escalation",
    ]
    medium_signals = [
        "admin", "member", "staff", "org_id", "project_id", "team_id", "customer_id",
        "current_user", "currentuser", "subject", "principal", "can_access", "allowed",
        "isowner", "ismember", "isadmin", "isstaff", "issuperuser",
        "department_id", "branch_id", "division_id",
        "belongs_to", "belongs_to_current_user",
        "filter_by_user", "filter_by_tenant", "scope_by",
        "visible_to", "accessible_by", "shared_with",
        "ownership_check", "access_check", "permission_check",
        "viewer", "editor", "contributor", "manager",
        "superadmin", "sysadmin", "root",
        "group_id", "organization_id", "company_id",
        "row_level", "field_level", "column_level",
    ]
    weak_noise = [
        "captcha", "logout", "forgot password", "reset password", "register", "signup",
        "/open/assets/", "\\open\\assets\\", "/cache/", "\\cache\\",
        ".min.js", ".min.css",
        "jquery", "sweetalert", "fontawesome", "datatables",
        "bootstrap", "lodash.min",
        "/vendor/", "\\vendor\\",
        "/__tests__/", "\\__tests__\\",
        "/__mocks__/", "\\__mocks__\\",
        "/node_modules/", "\\node_modules\\",
        ".test.js", ".spec.js", ".test.ts", ".spec.ts",
        "/docs/", "\\docs\\",
        "/demo/", "\\demo\\",
    ]

    score += sum(5 for keyword in strong_signals if keyword in haystack)
    score += sum(2 for keyword in medium_signals if keyword in haystack)
    score -= sum(2 for keyword in weak_noise if keyword in haystack)

    if any(token in file_path for token in ["permission", "authorize", "policy", "guard", "role", "tenant", "acl"]):
        score += 5
    if any(token in file_path for token in ["/controller", "/controllers/", "/service", "/services/", "/api/", "/routes/", "/routers/"]):
        score += 2
    if any(file_path.endswith(ext) for ext in [".php", ".py", ".java", ".go", ".rb", ".cs", ".js", ".ts"]):
        score += 1
    if _is_static_asset_chunk(file_path):
        score -= 8

    return score


def _select_stage6_chunks(
    chunks: list[dict],
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> list[dict]:
    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "")
        if _is_static_asset_chunk(file_path):
            continue
        score = _score_stage6_chunk(chunk) + _shared_chunk_priority_boost(
            chunk,
            stage_num=6,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if score > 0:
            scored.append((score, chunk))
        elif len(fallback) < 60:
            fallback.append(chunk)

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "") or "")))
    selected = [chunk for _, chunk in scored[:24]]
    if len(selected) < 12:
        selected.extend(fallback[: 12 - len(selected)])
    return selected or chunks[:12]


def _shared_chunk_priority_boost(
    chunk: dict,
    stage_num: int,
    route_files: set[str] | None = None,
    evidence_files: set[str] | None = None,
) -> int:
    route_files = route_files or set()
    evidence_files = evidence_files or set()
    file_path = str(chunk.get("file_path", "") or "")
    base_file_path = str(chunk.get("base_file_path", file_path) or file_path)
    normalized_path = base_file_path.lower()
    chunk_type = str(chunk.get("chunk_type", "") or "")
    risk_score = int(chunk.get("risk_score", 0) or 0)
    risk_labels = [str(label).lower() for label in (chunk.get("risk_labels") or []) if str(label).strip()]

    score = risk_score
    if normalized_path in route_files:
        score += 8
    if normalized_path in evidence_files:
        score += 6
    if chunk_type.startswith("oversized_signal"):
        score += 5
    elif chunk_type.startswith("oversized_"):
        score += 2

    stage_label_map = {
        2: {"rce"},
        3: {"injection"},
        4: {"xss"},
        5: {"auth"},
        6: {"auth"},
        7: {"config"},
        8: {"file"},
        9: {"business"},
    }
    if any(label in stage_label_map.get(stage_num, set()) for label in risk_labels):
        score += 8

    if any(token in normalized_path for token in ["/routes/", "/routers/", "/api/", "/controller", "/controllers/", "urls.py", "views.py"]):
        score += 3
    if any(token in normalized_path for token in ["/auth", "/security", "/middleware", "config", "settings", ".env"]):
        score += 2
    return score


def _select_stage_chunks(
    stage_num: int,
    chunks: list[dict],
    static_routes: list[dict] | None = None,
    audit_memory: dict | None = None,
    source_sink_hints: list[dict] | None = None,
    focus_files: list[str] | None = None,
    focus_functions: list[str] | None = None,
    pre_discovery: dict | None = None,
) -> list[dict]:
    route_files = {
        str(route.get("file_path", "")).strip().lower()
        for route in (static_routes or [])
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
        and stage_num in (item.get("stage_nums", []) if isinstance(item.get("stage_nums"), list) else [])
        and str(item.get("file_path", "")).strip()
    }
    evidence_files = evidence_files | source_sink_files
    focus_file_set = {
        str(f).strip().lower()
        for f in (focus_files or [])
        if str(f).strip()
    }
    focus_func_list = [str(f).strip().lower() for f in (focus_functions or []) if str(f).strip()]

    if stage_num == 1:
        return _select_stage1_skeleton_chunks(chunks, pre_discovery=pre_discovery)
    if stage_num == 4:
        return _select_stage4_chunks(chunks, route_files=route_files, evidence_files=evidence_files)
    if stage_num == 5:
        return _select_stage5_chunks(chunks, route_files=route_files, evidence_files=evidence_files)
    if stage_num == 6:
        return _select_stage6_chunks(chunks, route_files=route_files, evidence_files=evidence_files)
    if stage_num == 8:
        return _select_stage8_chunks(chunks, route_files=route_files, evidence_files=evidence_files)

    rules = {
        2: [
            "exec", "subprocess", "system", "shell", "eval", "popen", "runtime.exec", "processbuilder",
            "child_process", "pickle", "unserialize", "yaml.load", "marshal", "deserialize",
            "proc_open", "pcntl_exec", "assert", "vm.run", "class.forname", "scriptengine",
            "objectinputstream", "os/exec", "exec.command", "spawn", "compile",
            "jinja2", "freemarker", "velocity", "ognl", "spel", "mvel",
        ],
        3: [
            "sql", "query", "cursor", "mongodb", "redis", "orm", "database",
            "select ", "insert ", "update ", "delete ",
            "execute(", "raw(", "executescript(", "rawsql", "raw_query",
            "preparedstatement", "jdbctemplate", "hibernate", "mybatis",
            "sequelize", "knex", "typeorm", "prisma", "mongoose",
            "db.query", "db.exec", "gorm", "sqlx",
            "$where", "ldap_search", "graphql",
        ],
        4: [
            "xss", "csrf", ".vue", ".jsx", ".tsx", ".html", "template", "render",
            "innerhtml", "v-html", "document.write",
            "outerhtml", "dangerouslysetinnerhtml", "domparser",
            "insertadjacenthtml", "contenteditable",
            "srcdoc", "javascript:", "postmessage",
            "bypasssecuritytrust", "domsanitizer",
            "htmlspecialchars", "strip_tags", "escape", "sanitize",
        ],
        5: [
            "auth", "login", "jwt", "token", "session", "cookie", "oauth",
            "signin", "signup", "password", "captcha",
            "bearer", "authenticate", "verify_token",
            "saml", "kerberos", "ntlm",
            "recaptcha", "hcaptcha", "totp", "mfa", "2fa",
            "bcrypt", "argon2", "pbkdf2",
            "refresh_token", "access_token", "csrf",
        ],
        6: [
            "permission", "role", "acl", "authorize", "preauthorize",
            "idor", "tenant", "owner", "resource_id", "user_id",
            "authorization", "policy", "scope", "guard",
            "tenant_id", "account_id", "isadmin", "hasrole",
            "org_id", "project_id", "team_id",
            "current_user", "principal", "can_access",
            "ownership", "access_control",
        ],
        7: [
            ".env", "config", "settings", "docker", "compose",
            "yaml", "yml", "toml", "ini", "requirements", "package.json",
            "secret", "api_key", "private_key", "access_key", "credentials",
            "db_password", "database_url", "debug=true",
            "cors_origin", "allowed_hosts", "ssl", "tls",
            "aws_secret", "azure_key", "gcp_key",
            "kubernetes", "nginx", "apache",
            "github_token", "slack_token", "stripe_key",
            "0.0.0.0", "verify=false",
        ],
        8: [
            "file", "upload", "download", "path", "open(", "os.", "shutil", "zip", "tar",
            "fopen", "readfile", "file_get_contents", "unlink",
            "mkdir", "rmdir", "copy(", "rename(", "scandir",
            "realpath", "basename", "dirname", "glob(",
            "tempfile", "symlink", "move_uploaded_file",
            "fs.readfile", "fs.writefile", "multipartfile",
            "filepath.join", "os.path", "extractto",
            "../", "..\\",
        ],
        9: [
            "order", "payment", "amount", "price", "inventory", "coupon",
            "workflow", "status", "balance", "logic", "business",
            "refund", "withdraw", "deposit", "transfer",
            "invoice", "billing", "receipt", "tax",
            "discount", "promo", "voucher", "reward",
            "stock", "quantity", "merchant", "customer",
            "settlement", "commission", "profit",
            "approve", "reject", "cancel", "confirm",
            "points", "level", "vip", "membership",
            "quota", "threshold",
        ],
    }
    keywords = rules.get(stage_num, [])
    if not keywords:
        return chunks[:30]

    scored = []
    fallback = []
    for chunk in chunks:
        file_path = str(chunk.get("file_path", "") or "").lower()
        content_head = str(chunk.get("content", "") or "")[:4000].lower()
        haystack = f"{file_path}\n{content_head}"
        priority = _shared_chunk_priority_boost(
            chunk,
            stage_num=stage_num,
            route_files=route_files,
            evidence_files=evidence_files,
        )
        if file_path in source_sink_files:
            priority += 10
        if focus_file_set and file_path in focus_file_set:
            priority += 30
        if focus_func_list and any(fn in content_head for fn in focus_func_list):
            priority += 8
        if any(keyword in haystack for keyword in keywords):
            scored.append((priority + 12, chunk))
        elif priority > 0:
            scored.append((priority, chunk))
        elif len(fallback) < 120:
            fallback.append(chunk)

    target = 40 if stage_num == 1 else 32
    minimum = 20 if stage_num == 1 else 16
    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "") or "")))
    selected = [chunk for _, chunk in scored[:target]]
    if len(selected) < minimum:
        selected.extend(fallback[: minimum - len(selected)])
    return selected or chunks[:minimum]


def _format_chunks_for_prompt(chunks: list[dict], stage_num: int, max_len: int | None = None) -> str:
    parts = []
    total_len = 0
    max_len = max_len or (180000 if stage_num == 1 else 70000)

    for chunk in chunks:
        role_tags = chunk.get("risk_labels") or []
        role_prefix = f" [{', '.join(str(t) for t in role_tags[:3])}]" if role_tags else ""
        header = f"\n### File: {chunk['file_path']}{role_prefix}\n```\n"
        footer = "\n```\n"
        content = chunk["content"]
        entry = header + content + footer

        if total_len + len(entry) > max_len:
            remaining = max_len - total_len - len(header) - len(footer) - 50
            if remaining > 200:
                entry = header + content[:remaining] + "\n... (truncated)\n```\n"
                parts.append(entry)
            break

        parts.append(entry)
        total_len += len(entry)

    return "".join(parts)


def _format_stage1_chunks_for_prompt(chunk_batch: list[dict], compressed_summary: dict, pass_index: int) -> tuple[str, dict]:
    batch_max_len = max(
        STAGE1_PASS1_CODE_MAX_LEN if pass_index <= 1 else STAGE1_LATER_PASS_CODE_MAX_LEN,
        _estimate_chunks_prompt_len(chunk_batch) + 2048,
    )
    # 已经分配到本轮的 chunk 不应再被提示词格式化阶段二次截断。
    if pass_index <= 1:
        return _format_chunks_for_prompt(chunk_batch, 1, max_len=batch_max_len), {
            "compacted_chunk_count": 0,
            "compacted_paths": [],
        }

    parts = []
    total_len = 0
    max_len = batch_max_len
    coverage = compressed_summary.get("coverage", {}) if isinstance(compressed_summary, dict) else {}
    covered_paths = set(coverage.get("covered_paths", []) if isinstance(coverage, dict) else [])
    seen_paths_in_pass: set[str] = set()
    compacted_paths: list[str] = []
    compacted_chunk_count = 0
    signal_window_chunk_count = 0

    for chunk in chunk_batch:
        file_path = str(chunk.get("file_path", ""))
        content = str(chunk.get("content", ""))
        revisit = file_path in covered_paths
        repeated_in_pass = file_path in seen_paths_in_pass
        high_signal = _is_high_signal_stage1_chunk(chunk)

        if (revisit or repeated_in_pass) and not high_signal:
            entry, excerpt_mode = _format_compacted_chunk_entry(
                file_path=file_path,
                content=content,
                revisit=revisit,
                repeated_in_pass=repeated_in_pass,
            )
            compacted_chunk_count += 1
            if excerpt_mode == "signal_windows":
                signal_window_chunk_count += 1
            if file_path:
                compacted_paths.append(file_path)
        else:
            entry = _format_prompt_chunk_entry(file_path, content)

        if total_len + len(entry) > max_len:
            remaining = max_len - total_len - 80
            if remaining > 200:
                parts.append(_truncate_text(entry, remaining))
            break

        parts.append(entry)
        total_len += len(entry)
        if file_path:
            seen_paths_in_pass.add(file_path)

    return "".join(parts), {
        "compacted_chunk_count": compacted_chunk_count,
        "compacted_paths": _merge_unique_items([], compacted_paths),
        "signal_window_chunk_count": signal_window_chunk_count,
    }


def _format_non_stage1_chunks_for_prompt(
    chunks: list[dict],
    stage_num: int,
    audit_memory: dict | None = None,
) -> str:
    if not chunks:
        return ""

    audit_memory = audit_memory or {}
    focus_files = set(audit_memory.get("evidence_files", []) if isinstance(audit_memory.get("evidence_files"), list) else [])
    parts = []
    total_len = 0
    max_len = 40000 if stage_num == 6 else 70000
    topic_keywords = _get_stage_topic_keywords(stage_num)

    for chunk in chunks:
        file_path = str(chunk.get("file_path", ""))
        content = str(chunk.get("content", ""))
        if not content:
            continue

        if file_path in focus_files:
            entry = _format_prompt_chunk_entry(file_path, content)
        else:
            excerpt, excerpt_mode = _extract_stage_focus_excerpt(content, topic_keywords)
            compacted_body = (
                f"# compacted context for stage {stage_num}\n"
                f"# excerpt mode: {excerpt_mode}\n"
                f"{excerpt}"
            )
            entry = _format_prompt_chunk_entry(file_path, compacted_body)

        if total_len + len(entry) > max_len:
            remaining = max_len - total_len - 80
            if remaining > 200:
                parts.append(_truncate_text(entry, remaining))
            break

        parts.append(entry)
        total_len += len(entry)

    return "".join(parts)


def _format_prompt_chunk_entry(file_path: str, content: str) -> str:
    header = f"\n### File: {file_path}\n```\n"
    footer = "\n```\n"
    return header + content + footer


def _format_compacted_chunk_entry(file_path: str, content: str, revisit: bool, repeated_in_pass: bool) -> tuple[str, str]:
    reason_parts = []
    if revisit:
        reason_parts.append("previously covered in earlier pass")
    if repeated_in_pass:
        reason_parts.append("same file already appeared in this pass")
    reason_text = ", ".join(reason_parts) if reason_parts else "prompt compression"
    excerpt, excerpt_mode = _extract_compacted_excerpt(content)
    compacted_body = (
        f"# compacted context: {reason_text}\n"
        f"# excerpt mode: {excerpt_mode}\n"
        "# keep the file role, sink/source patterns, auth checks, and data flow in mind.\n"
        f"{excerpt}"
    )
    return _format_prompt_chunk_entry(file_path, compacted_body), excerpt_mode


def _extract_compacted_excerpt(content: str, head_limit: int = 700, tail_limit: int = 500) -> tuple[str, str]:
    if len(content) <= head_limit + tail_limit + 80:
        return content, "full"

    signal_excerpt = _extract_signal_excerpt(content)
    if signal_excerpt:
        return signal_excerpt, "signal_windows"

    head = content[:head_limit].rstrip()
    tail = content[-tail_limit:].lstrip()
    return head + "\n\n... (middle omitted for stage1 microcompact) ...\n\n" + tail, "head_tail"


def _extract_signal_excerpt(content: str, window_radius: int = 8, max_segments: int = 4, max_chars: int = 2200) -> str:
    lines = content.splitlines()
    if len(lines) < 20:
        return ""

    keywords = [
        "route", "router", "app.", "@app.", "@router.", "include_router", "apirouter",
        "auth", "login", "jwt", "token", "session", "cookie", "oauth", "permission", "authorize",
        "sql", "query", "cursor", "select ", "insert ", "update ", "delete ", "execute(", "raw(",
        "exec(", "eval(", "subprocess", "system(", "popen", "runtime.exec",
        "upload", "download", "open(", "path", "os.", "shutil", "zip", "tar",
        "request", "response", "body", "params", "header", "form", "json",
        "pickle.loads", "yaml.load(", "unserialize(", "deserialize(", "marshal.loads",
        ".extra(", "cursor.execute", "mysqli_query", "pg_query", "orm",
        "csrf", "xsrf", "_csrf", "verify_token", "authenticate",
        "md5(", "sha1(", "des", "rc4", "ecb",
        "requests.get(", "urlopen(", "fetch(", "axios",
        "xml.parse", "xml.etree", "saxparser", "fromstring(",
        "order", "payment", "amount", "price", "inventory", "coupon", "balance", "refund",
    ]

    matched_indexes = []
    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords):
            matched_indexes.append(index)

    if not matched_indexes:
        return ""

    windows = []
    for index in matched_indexes[:24]:
        start = max(0, index - window_radius)
        end = min(len(lines), index + window_radius + 1)
        windows.append((start, end))

    merged_windows = []
    for start, end in sorted(windows):
        if not merged_windows or start > merged_windows[-1][1] + 2:
            merged_windows.append([start, end])
        else:
            merged_windows[-1][1] = max(merged_windows[-1][1], end)

    segments = []
    total_chars = 0
    for start, end in merged_windows[:max_segments]:
        segment = "\n".join(lines[start:end]).strip()
        if not segment:
            continue
        labeled = f"# lines {start + 1}-{end}\n{segment}"
        next_size = total_chars + len(labeled)
        if segments and next_size > max_chars:
            break
        segments.append(labeled)
        total_chars = next_size

    if not segments:
        return ""

    return "\n\n... (non-matching regions omitted for stage1 microcompact) ...\n\n".join(segments)


def _extract_stage_focus_excerpt(content: str, topic_keywords: list[str]) -> tuple[str, str]:
    if len(content) <= 2600:
        return content, "full"

    excerpt = _extract_keyword_excerpt(content, topic_keywords, max_segments=5, max_chars=2600)
    if excerpt:
        return excerpt, "topic_windows"

    return _extract_compacted_excerpt(content)


def _extract_keyword_excerpt(
    content: str,
    keywords: list[str],
    window_radius: int = 10,
    max_segments: int = 5,
    max_chars: int = 2600,
) -> str:
    lines = content.splitlines()
    if len(lines) < 20 or not keywords:
        return ""

    matched_indexes = []
    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords):
            matched_indexes.append(index)
    if not matched_indexes:
        return ""

    windows = []
    for index in matched_indexes:
        windows.append((max(0, index - window_radius), min(len(lines), index + window_radius + 1)))
    windows.sort()

    merged_windows = []
    for start, end in windows:
        if not merged_windows or start > merged_windows[-1][1]:
            merged_windows.append([start, end])
        else:
            merged_windows[-1][1] = max(merged_windows[-1][1], end)

    segments = []
    total_chars = 0
    for start, end in merged_windows[:max_segments]:
        segment = "\n".join(lines[start:end]).strip()
        if not segment:
            continue
        labeled = f"# lines {start + 1}-{end}\n{segment}"
        next_size = total_chars + len(labeled)
        if segments and next_size > max_chars:
            break
        segments.append(labeled)
        total_chars = next_size

    if not segments:
        return ""
    return "\n\n... (non-topic regions omitted for stage focus compact) ...\n\n".join(segments)


def _is_high_signal_stage1_chunk(chunk: dict) -> bool:
    file_path = str(chunk.get("file_path", "")).lower()
    content = str(chunk.get("content", "")[:4000]).lower()
    high_signal_paths = [
        "main.py", "app.py", "server.js", "index.js", "manage.py",
        "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
        "/middleware", "/auth", "/security", "urls.py", ".module.ts", "package.json",
        "requirements.txt", "pyproject.toml", ".env", "config",
    ]
    high_signal_content = [
        "include_router", "apirouter", "@router.", "@app.", "fastapi(",
        "jwt", "oauth", "session", "middleware", "auth", "login",
        "router.get(", "router.post(", "app.get(", "app.post(",
        "urlpatterns", "include(", "@controller(", "@module(",
        "permission", "authorize", "cookie", "csrf",
    ]
    return any(keyword in file_path for keyword in high_signal_paths) or any(
        keyword in content for keyword in high_signal_content
    )


def _prioritize_stage1_chunks(chunks: list[dict]) -> list[dict]:
    def score(chunk: dict) -> tuple[int, str]:
        file_path = str(chunk.get("file_path", "")).lower()
        content = str(chunk.get("content", "")[:4000]).lower()
        path_boost = 0
        content_boost = 0

        high_signal_paths = [
            "main.py", "app.py", "server.js", "index.js", "manage.py",
            "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
            "/middleware", "/auth", "/security", "urls.py",
            "package.json", "requirements.txt", "pyproject.toml", ".env",
        ]
        high_signal_content = [
            "include_router", "apirouter", "@router.", "@app.", "fastapi(",
            "jwt", "oauth", "session", "middleware", "auth", "login",
            "router.get(", "router.post(", "app.get(", "app.post(",
        ]

        for keyword in high_signal_paths:
            if keyword in file_path:
                path_boost += 3
        for keyword in high_signal_content:
            if keyword in content:
                content_boost += 2

        # Smaller files often contain entry wiring and config that are cheap but high value.
        size_penalty = min(len(str(chunk.get("content", ""))) // 4000, 9)
        return (path_boost + content_boost - size_penalty, file_path)

    return sorted(chunks, key=score, reverse=True)


def _is_stage1_low_value_chunk(chunk: dict, must_keep_paths: set[str] | None = None) -> bool:
    file_path = str(chunk.get("file_path", "") or "").strip().lower()
    if not file_path:
        return True

    normalized_file_path = re.sub(r"#l\d+(?:-\d+)?$", "", file_path)
    must_keep_paths = must_keep_paths or set()
    if normalized_file_path in must_keep_paths:
        return False

    basename = normalized_file_path.replace("\\", "/").rsplit("/", 1)[-1]
    content = str(chunk.get("content", "")[:2000] or "").lower()

    low_value_exts = (
        ".md", ".txt", ".css", ".scss", ".sass", ".less", ".map",
        ".svg", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ttf",
    )
    if basename.endswith(low_value_exts):
        return True

    low_value_names = {"readme.md", "license", "license.md", "changelog", "changelog.md", "changes.md"}
    if basename in low_value_names:
        return True

    low_value_path_markers = [
        "/ckeditor/", "/codemirror/", "/tinymce/", "/ueditor/",
        "/styles/", "/style/", "/css/", "/fonts/", "/images/", "/img/",
        "/static/", "/assets/", "/public/", "/docs/", "/doc/", "/manual/",
        "/vendor/", "/dist/", "/build/",
    ]
    if any(marker in normalized_file_path for marker in low_value_path_markers):
        return True

    if basename.endswith(".min.js") or basename.endswith(".bundle.js"):
        return True

    # 阶段一只做入口与架构扫描，纯静态资源或第三方说明文档会稀释扫描预算。
    if "copyright" in content and "license" in content and len(content) < 1200:
        return True

    return False


def _is_stage1_entry_file(chunk: dict) -> bool:
    file_path = str(chunk.get("file_path", "")).lower()
    content = str(chunk.get("content", "")[:5000]).lower()
    strong_paths = [
        "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
        "/middleware", "/auth", "/security", "/guard", "/permission", "/policy",
        "urls.py", "views.py", "handlers/", "endpoints/", "gateway", "proxy",
        "webhook", "callback", "dto", "schema", "serializer", "validator",
        "request", "response", "route.ts", "route.js", ".module.ts", "main.py", "app.py",
        "server.js", "index.js", "manage.py",
    ]
    strong_content = [
        "include_router", "apirouter", "@router.", "@app.", "fastapi(",
        "router.get(", "router.post(", "router.put(", "router.delete(",
        "app.get(", "app.post(", "app.put(", "app.delete(", "router.use(", "app.use(",
        "urlpatterns", "re_path(", "path(", "blueprint.route(", "route::",
        "include(", "@controller(", "@module(", "@requestmapping(", "@getmapping(", "@postmapping(",
        "gin.", ".group(", "middleware", "jwt", "oauth", "session", "permission",
        "authorize", "shouldbind", "bindjson", "validator", "schema", "dto",
    ]
    return any(keyword in file_path for keyword in strong_paths) or any(keyword in content for keyword in strong_content)


def _select_stage1_entry_chunks(chunks: list[dict]) -> list[dict]:
    selected = []
    seen_paths = set()

    for chunk in _prioritize_stage1_chunks(chunks):
        file_path = str(chunk.get("file_path", ""))
        normalized_path = file_path.lower()
        if not _is_stage1_entry_file(chunk):
            continue
        if normalized_path in seen_paths:
            continue
        seen_paths.add(normalized_path)
        selected.append(chunk)
        if len(selected) >= 120:
            break

    return selected


def _estimate_chunk_prompt_len(chunk: dict) -> int:
    return len(str(chunk.get("content", "") or "")) + len(str(chunk.get("file_path", "") or "")) + 32


def _estimate_chunks_prompt_len(chunks: list[dict]) -> int:
    return sum(_estimate_chunk_prompt_len(chunk) for chunk in chunks)


def _select_stage1_skeleton_chunks(chunks: list[dict], pre_discovery: dict | None = None) -> list[dict]:
    """Select Stage 1 skeleton chunks, enriched with pre-discovery signals."""
    rule_hit_scores: dict[str, int] = {}
    source_sink_scores: dict[str, int] = {}
    hub_boost: dict[str, int] = {}
    must_cover_set: set[str] = set()
    file_roles: dict[str, str] = {}

    if pre_discovery:
        for hit in (pre_discovery.get("rule_hits") or []):
            if isinstance(hit, dict):
                fp = str(hit.get("file_path", "")).strip().lower()
                if fp:
                    rule_hit_scores[fp] = rule_hit_scores.get(fp, 0) + int(hit.get("risk_score", 0) or 0)
        for hint in (pre_discovery.get("source_sink_hints") or []):
            if isinstance(hint, dict):
                fp = str(hint.get("file_path", "")).strip().lower()
                if fp:
                    source_sink_scores[fp] = source_sink_scores.get(fp, 0) + int(hint.get("risk_score", 0) or 0)
        ig = pre_discovery.get("import_graph") or {}
        for fp, score in (ig.get("hub_scores") or {}).items():
            hub_boost[str(fp).strip().lower()] = min(int(score), 10) * 2
        sf = pre_discovery.get("security_files") or {}
        must_cover_set = {fp.lower() for fp in (sf.get("must_cover_files") or [])}
        file_roles = {fp.lower(): role for fp, role in (ig.get("file_roles") or {}).items()}

    filtered_chunks = [chunk for chunk in chunks if not _is_stage1_low_value_chunk(chunk, must_keep_paths=must_cover_set)]
    candidate_chunks = filtered_chunks or chunks
    prioritized = _prioritize_stage1_chunks(candidate_chunks)
    entry_first = _select_stage1_entry_chunks(prioritized)

    def _pre_discovery_boost(chunk: dict) -> int:
        fp = str(chunk.get("file_path", "")).strip().lower()
        s = rule_hit_scores.get(fp, 0) // 10 + source_sink_scores.get(fp, 0) // 10 + hub_boost.get(fp, 0)
        if fp in must_cover_set:
            s += 50
        role = file_roles.get(fp, "")
        if role in {"auth", "middleware", "config", "route"}:
            s += 15
        elif role in {"controller", "service"}:
            s += 8
        return s

    scored = sorted(prioritized, key=lambda c: (-_pre_discovery_boost(c), str(c.get("file_path", ""))))
    entry_paths = {str(c.get("file_path", "")).lower() for c in entry_first}
    non_entry = [c for c in scored if str(c.get("file_path", "")).lower() not in entry_paths]
    merged = entry_first + non_entry

    selected: list[dict] = []
    seen_paths = set()
    # 阶段一要尽量覆盖完整审计集，不能再被固定文件数或固定总字符数硬截断。
    for chunk in merged:
        normalized_path = str(chunk.get("file_path", "")).lower()
        if normalized_path in seen_paths:
            continue
        selected.append(chunk)
        seen_paths.add(normalized_path)
    return selected or prioritized


def _split_chunks_for_stage1(
    chunks: list[dict],
    max_len: int = STAGE1_BATCH_TARGET_LEN,
    max_batches: int | None = None,
    pre_discovery: dict | None = None,
) -> list[list[dict]]:
    if not chunks:
        return [[]]

    if max_batches is None or max_batches <= 0:
        # 阶段一批次数按审计集体量动态扩展，避免大项目被固定 5 轮截断。
        estimated_total_len = _estimate_chunks_prompt_len(chunks)
        max_batches = max(STAGE1_MAX_PASSES, math.ceil(estimated_total_len / max(max_len, 1)))
    max_batches = max(1, max_batches)

    # Build import relationships for grouping related files together
    imports = {}
    if pre_discovery:
        imports = (pre_discovery.get("import_graph") or {}).get("imports") or {}

    # Build a file -> group_id mapping based on import relationships
    fp_to_idx = {str(c.get("file_path", "")).lower(): i for i, c in enumerate(chunks)}
    parent = list(range(len(chunks)))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: int, b: int):
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[ra] = rb

    for i, chunk in enumerate(chunks):
        fp = str(chunk.get("file_path", "")).lower()
        for dep_fp in imports.get(fp, []):
            j = fp_to_idx.get(dep_fp.lower())
            if j is not None:
                _union(i, j)

    # Group chunks by their connected component, then assign groups to batches
    groups: dict[int, list[int]] = {}
    for i in range(len(chunks)):
        root = _find(i)
        groups.setdefault(root, []).append(i)

    # Sort groups: largest first to spread evenly
    sorted_groups = sorted(groups.values(), key=lambda g: (-len(g), g[0]))

    batches: list[list[dict]] = [[] for _ in range(max_batches)]
    batch_lens = [0 for _ in range(max_batches)]

    for group_indices in sorted_groups:
        # 保持导入关系相近的代码尽量落在同一轮，同时优先填充最轻的批次。
        best_idx = min(range(max_batches), key=lambda bi: batch_lens[bi])
        for idx in group_indices:
            chunk = chunks[idx]
            estimated_len = _estimate_chunk_prompt_len(chunk)
            batches[best_idx].append(chunk)
            batch_lens[best_idx] += estimated_len

    batches = [batch for batch in batches if batch]
    batches = _merge_stage1_batches_for_soft_cap(batches, soft_cap=STAGE1_SOFT_MAX_BATCHES)
    return batches or [chunks[:1]]


def _merge_stage1_batches_for_soft_cap(batches: list[list[dict]], soft_cap: int) -> list[list[dict]]:
    if not isinstance(batches, list):
        return batches

    soft_cap = max(1, int(soft_cap or 1))
    merged_batches = [list(batch) for batch in batches if batch]
    if len(merged_batches) <= soft_cap:
        return merged_batches

    batch_lens = [
        sum(_estimate_chunk_prompt_len(chunk) for chunk in batch)
        for batch in merged_batches
    ]

    while len(merged_batches) > soft_cap:
        smallest_idx = min(range(len(merged_batches)), key=lambda idx: (batch_lens[idx], len(merged_batches[idx])))
        target_candidates = [idx for idx in range(len(merged_batches)) if idx != smallest_idx]
        if not target_candidates:
            break
        target_idx = min(target_candidates, key=lambda idx: (batch_lens[idx], len(merged_batches[idx])))
        merged_batches[target_idx].extend(merged_batches[smallest_idx])
        batch_lens[target_idx] += batch_lens[smallest_idx]
        del merged_batches[smallest_idx]
        del batch_lens[smallest_idx]

    return merged_batches


def _frontload_route_related_stage1_chunks(chunks: list[dict], static_routes: list[dict]) -> list[dict]:
    route_files = set()
    for route in static_routes:
        if not isinstance(route, dict):
            continue
        file_path = str(route.get("file_path", "")).strip()
        if file_path:
            route_files.add(file_path.lower())

    def score(chunk: dict) -> tuple[int, int, str]:
        file_path = str(chunk.get("file_path", "")).lower()
        content = str(chunk.get("content", "")[:4000]).lower()
        route_file_boost = 0
        path_boost = 0
        content_boost = 0

        if file_path in route_files:
            route_file_boost += 10

        route_paths = [
            "/router", "/routers/", "/routes/", "/api/", "/controller", "/controllers/",
            "urls.py", "views.py", "handlers/", "endpoints/", "gateway", "proxy",
            "webhook", "callback", "resolver", "resource", "route.ts", "route.js", ".module.ts",
        ]
        support_paths = [
            "/middleware", "/auth", "/security", "permission", "acl", "guard", "interceptor",
            "dto", "schema", "serializer", "validator", "request", "response", "policy",
        ]
        route_content = [
            "include_router", "apirouter", "@router.", "@app.", "fastapi(",
            "router.get(", "router.post(", "router.put(", "router.delete(",
            "app.get(", "app.post(", "app.put(", "app.delete(",
            "blueprint.route(", "route::", "urlpatterns", "re_path(", "path(",
            "include(", "router.use(", "app.use(", "@controller(", "@module(", "@get(", "@post(", "@requestmapping(",
            "@getmapping(", "@postmapping(", ".group(", "gin.",
        ]
        support_content = [
            "jwt", "oauth", "session", "middleware", "auth", "login",
            "permission", "authorize", "cookie", "csrf", "bindjson", "shouldbind",
            "validator", "schema", "dto", "serialize", "deserialize",
        ]

        for keyword in route_paths:
            if keyword in file_path:
                path_boost += 4
        for keyword in support_paths:
            if keyword in file_path:
                path_boost += 2
        for keyword in route_content:
            if keyword in content:
                content_boost += 3
        for keyword in support_content:
            if keyword in content:
                content_boost += 1

        size_penalty = min(len(str(chunk.get("content", ""))) // 6000, 6)
        return (route_file_boost + path_boost + content_boost - size_penalty, -len(file_path), file_path)

    return sorted(chunks, key=score, reverse=True)


def _build_stage1_pass_context(prev_context: str, compressed_summary: dict, pass_index: int, total_passes: int) -> str:
    sections = []
    if prev_context:
        sections.append(_truncate_text(prev_context, 5000 if pass_index > 1 else 8000))

    sections.append(f"[Stage 1 Multi-pass Progress] Current pass {pass_index}/{total_passes}.")
    sections.append("[Current Compressed Summary]")
    sections.append(_truncate_text(json.dumps(compressed_summary, ensure_ascii=False), 5000 if pass_index > 1 else 8000))
    sections.append("Requirement: continue filling new architecture, route, and data-flow findings based on the compressed summary above. Do not repeat large amounts of already confirmed information.")
    return "\n".join(sections)


def _coerce_stage_summary(value) -> dict:
    if isinstance(value, dict) and value:
        return value
    return {
        "stage_summary": "",
        "architecture_info": {},
        "vulnerability_hints": [],
        "coverage": {
            "passes_completed": 0,
            "scanned_chunk_count": 0,
            "total_chunk_count": 0,
            "covered_paths": [],
            "compacted_chunk_count": 0,
            "signal_window_chunk_count": 0,
            "compacted_paths": [],
            "audit_scope_label": "审计集覆盖率",
            "audit_scope_type": "selected_high_value_chunks",
            "audit_scope_note": "仅统计纳入阶段一审计集的高价值代码块，不代表全仓源码 100% 覆盖。",
            "audit_scope_file_count": 0,
            "audit_scope_chunk_count": 0,
        },
    }


def _extract_stage1_delta(response: dict | list) -> dict:
    if isinstance(response, list):
        return {
            "stage_summary": "",
            "architecture_info": {},
            "vulnerability_hints": response[:12],
        }
    if not isinstance(response, dict):
        return {"stage_summary": "", "architecture_info": {}, "vulnerability_hints": []}
    return {
        "stage_summary": str(response.get("stage_summary", "")).strip()[:4000],
        "architecture_info": _compact_stage1_architecture_info(response.get("architecture_info")),
        "vulnerability_hints": response.get("vulnerabilities", [])[:12] if isinstance(response.get("vulnerabilities"), list) else [],
    }


def _compact_stage1_architecture_info(architecture_info: dict | None) -> dict:
    if not isinstance(architecture_info, dict):
        return {}

    compact = {}
    for key in ["tech_stack", "framework", "database", "auth_mechanism"]:
        value = architecture_info.get(key)
        if value:
            compact[key] = str(value)[:200]

    routes = architecture_info.get("routes")
    if isinstance(routes, list) and routes:
        normalized_routes = []
        for route in routes[:24]:
            if not isinstance(route, dict):
                continue
            path = str(route.get("path", "")).strip()
            if not path:
                continue
            normalized_routes.append(
                {
                    "method": str(route.get("method", "UNKNOWN")).upper(),
                    "path": path,
                    "handler": str(route.get("handler", "Unknown"))[:160],
                    "file_path": str(route.get("file_path", ""))[:260],
                    "auth": str(route.get("auth", "Unknown"))[:40],
                    "params": route.get("params", [])[:8] if isinstance(route.get("params"), list) else [],
                    "notes": str(route.get("notes", ""))[:240],
                }
            )
        if normalized_routes:
            compact["routes"] = normalized_routes
        compact["route_count"] = len(routes)

    for key, limit in [("entry_points", 12), ("output_points", 12), ("modules", 12), ("data_flows", 12)]:
        value = architecture_info.get(key)
        if isinstance(value, list) and value:
            compact[key] = value[:limit]

    for key in ["middleware_chain", "database_models", "security_boundaries", "external_integrations"]:
        value = architecture_info.get(key)
        if value:
            compact[key] = value if isinstance(value, list) else value

    return compact


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


def _merge_compressed_summary(
    base: dict,
    delta: dict,
    chunk_batch: list[dict],
    total_chunk_count: int,
    total_selected_file_count: int | None = None,
    compression_stats: dict | None = None,
) -> dict:
    merged = _coerce_stage_summary(base)

    stage_summary = str(delta.get("stage_summary", "")).strip()
    if stage_summary:
        existing = merged.get("stage_summary", "")
        if stage_summary not in existing:
            merged["stage_summary"] = (existing + "\n\n" + stage_summary).strip() if existing else stage_summary

    merged["architecture_info"] = _merge_architecture_info(
        merged.get("architecture_info"),
        delta.get("architecture_info"),
    )
    merged["vulnerability_hints"] = _merge_vulnerability_lists(
        merged.get("vulnerability_hints"),
        delta.get("vulnerability_hints"),
    )[:24]

    coverage = merged.get("coverage", {}) if isinstance(merged.get("coverage"), dict) else {}
    covered_paths = _merge_unique_items(
        coverage.get("covered_paths"),
        [chunk.get("file_path", "") for chunk in chunk_batch if chunk.get("file_path")],
    )
    covered_chunk_keys = _merge_unique_items(
        coverage.get("covered_chunks"),
        [
            str(chunk.get("file_path", "") or chunk.get("base_file_path", "") or "").strip()
            for chunk in chunk_batch
            if str(chunk.get("file_path", "") or chunk.get("base_file_path", "") or "").strip()
        ],
    )
    coverage["passes_completed"] = int(coverage.get("passes_completed", 0)) + 1
    coverage["scanned_chunk_count"] = min(total_chunk_count, len(covered_chunk_keys))
    coverage["total_chunk_count"] = total_chunk_count
    coverage["covered_paths"] = covered_paths[:500]
    coverage["covered_chunks"] = covered_chunk_keys[:2000]
    coverage["audit_scope_label"] = "审计集覆盖率"
    coverage["audit_scope_type"] = "selected_high_value_chunks"
    coverage["audit_scope_note"] = "仅统计纳入阶段一审计集的高价值代码块，不代表全仓源码 100% 覆盖。"
    coverage["audit_scope_file_count"] = max(0, int(total_selected_file_count or len(covered_paths)))
    coverage["audit_scope_chunk_count"] = total_chunk_count
    compression_stats = compression_stats or {}
    coverage["compacted_chunk_count"] = max(
        0,
        int(coverage.get("compacted_chunk_count", 0)) + int(compression_stats.get("compacted_chunk_count", 0)),
    )
    coverage["signal_window_chunk_count"] = max(
        0,
        int(coverage.get("signal_window_chunk_count", 0)) + int(compression_stats.get("signal_window_chunk_count", 0)),
    )
    coverage["compacted_paths"] = _merge_unique_items(
        coverage.get("compacted_paths"),
        compression_stats.get("compacted_paths"),
    )[:400]
    merged["coverage"] = coverage

    return merged


def _build_stage_artifact_path(task_id: int, stage_num: int) -> str:
    os.makedirs(get_stage_artifact_dir(task_id), exist_ok=True)
    return os.path.join("data", "stage_artifacts", str(task_id), f"stage_{stage_num}_passes.json")


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
            "vulnerability_count": len(merged_response.get("vulnerabilities", [])) if isinstance(merged_response.get("vulnerabilities"), list) else 0,
        },
    }
    with open(resolve_audit_artifact_path(artifact_path), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _summarize_stage1_pass_outputs(pass_outputs: list[dict]) -> dict:
    if not isinstance(pass_outputs, list) or not pass_outputs:
        return {
            "executed_pass_count": 0,
            "total_prompt_length": 0,
            "total_code_length": 0,
            "max_coverage_ratio": 0.0,
            "avg_signal_gain": 0.0,
            "peak_signal_gain": 0,
            "new_path_total": 0,
            "compacted_chunk_total": 0,
        }

    coverage_values = [
        float((item.get("progress") or {}).get("coverage_ratio", 0.0) or 0.0)
        for item in pass_outputs
        if isinstance(item, dict)
    ]
    signal_values = [
        int((item.get("progress") or {}).get("signal_gain", 0) or 0)
        for item in pass_outputs
        if isinstance(item, dict)
    ]
    return {
        "executed_pass_count": len(pass_outputs),
        "last_pass_index": int(pass_outputs[-1].get("pass_index", len(pass_outputs)) or len(pass_outputs)),
        "total_prompt_length": sum(int(item.get("user_prompt_length", 0) or 0) for item in pass_outputs if isinstance(item, dict)),
        "total_code_length": sum(int(item.get("code_text_length", 0) or 0) for item in pass_outputs if isinstance(item, dict)),
        "max_coverage_ratio": round(max(coverage_values) if coverage_values else 0.0, 4),
        "avg_signal_gain": round((sum(signal_values) / len(signal_values)) if signal_values else 0.0, 2),
        "peak_signal_gain": max(signal_values) if signal_values else 0,
        "new_path_total": sum(int((item.get("progress") or {}).get("new_path_count", 0) or 0) for item in pass_outputs if isinstance(item, dict)),
        "compacted_chunk_total": sum(int((item.get("microcompact") or {}).get("compacted_chunk_count", 0) or 0) for item in pass_outputs if isinstance(item, dict)),
    }


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


def _summarize_architecture_info(architecture_info: dict | None) -> dict:
    if not isinstance(architecture_info, dict):
        return {}
    summary = {}
    for key in ["tech_stack", "framework", "database", "auth_mechanism"]:
        value = architecture_info.get(key)
        if value:
            summary[key] = str(value)[:200]
    routes = architecture_info.get("routes")
    if isinstance(routes, list):
        summary["route_count"] = len(routes)
    for key in ["entry_points", "output_points", "modules", "data_flows"]:
        value = architecture_info.get(key)
        if isinstance(value, list) and value:
            summary[key] = value[:8]
    return summary


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


def _merge_stage1_pass_response(base: dict, response: dict | list) -> dict:
    if isinstance(response, list):
        response = {"vulnerabilities": response}
    if not isinstance(response, dict):
        return base

    merged = {
        "stage_summary": str(base.get("stage_summary", "")).strip(),
        "architecture_info": dict(base.get("architecture_info", {})) if isinstance(base.get("architecture_info"), dict) else {},
        "vulnerabilities": list(base.get("vulnerabilities", [])) if isinstance(base.get("vulnerabilities"), list) else [],
    }

    if response.get("stage_summary"):
        existing = merged.get("stage_summary", "")
        addition = str(response.get("stage_summary", "")).strip()
        if addition and addition not in existing:
            merged["stage_summary"] = (existing + "\n\n" + addition).strip() if existing else addition

    merged["architecture_info"] = _merge_architecture_info(merged["architecture_info"], response.get("architecture_info"))
    merged["vulnerabilities"] = _merge_vulnerability_lists(merged["vulnerabilities"], response.get("vulnerabilities"))

    for key, value in response.items():
        if key not in {"stage_summary", "architecture_info", "vulnerabilities"} and key not in merged:
            merged[key] = value

    return merged


def _merge_architecture_info(base: dict | None, incoming: dict | None) -> dict:
    result = dict(base) if isinstance(base, dict) else {}
    if not isinstance(incoming, dict):
        return result

    singular_fields = ["tech_stack", "framework", "database", "auth_mechanism"]
    list_fields = ["routes", "entry_points", "output_points", "modules", "data_flows"]

    for field in singular_fields:
        if not result.get(field) and incoming.get(field):
            result[field] = incoming.get(field)

    for field in list_fields:
        merged_list = _merge_unique_items(result.get(field), incoming.get(field))
        if merged_list:
            result[field] = merged_list

    for key, value in incoming.items():
        if key in singular_fields or key in list_fields:
            continue
        if key not in result and value not in (None, "", [], {}):
            result[key] = value

    return result


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


def _merge_vulnerability_lists(existing, incoming) -> list[dict]:
    merged_by_key: dict[tuple, dict] = {}
    ordered_keys: list[tuple] = []

    for vuln in list(existing or []) + list(incoming or []):
        if not isinstance(vuln, dict):
            continue
        key = _vuln_key(vuln)
        if key not in merged_by_key:
            merged_by_key[key] = dict(vuln)
            ordered_keys.append(key)
            continue
        merged_by_key[key] = _merge_duplicate_vulnerability(merged_by_key[key], vuln)

    return [merged_by_key[key] for key in ordered_keys]


def _build_stage_user_prompt(stage, project, stage_prompt: str, code_text: str, prev_context: str, static_routes: list[dict], compact_context: dict | None = None, audit_memory: dict | None = None) -> str:
    compact_context = compact_context or {}
    project_tree_summary = compact_context.get("project_tree_summary") or _summarize_project_tree(project.file_tree or [])
    route_lines_override = compact_context.get("route_lines")
    route_text_limit = int(compact_context.get("route_text_limit", 12000) or 12000)
    route_intro = compact_context.get("route_intro") or "以下为系统基于源码静态抽取得到的候选路由，供你补充、纠正和完善，不可机械照抄，需结合源码确认："
    extra_guidance = compact_context.get("extra_guidance")

    sections = [
        f"请严格执行根目录文档《{get_spec_label()}》中当前阶段的原文要求。",
        "不要改写阶段目标，不要跨阶段扩展主题；若文档原文与其他说明冲突，以文档原文为准。",
        "",
        "【当前阶段原文】",
        stage_prompt,
        "",
        "【项目基础信息】",
        f"项目技术栈线索：{project.tech_stack or 'Unknown'}",
        "项目文件树摘要：",
        project_tree_summary,
    ]

    if stage.stage_num == 1 and static_routes:
        route_lines = route_lines_override if isinstance(route_lines_override, list) else _format_static_route_lines(static_routes[:80], total_count=len(static_routes))
        sections.extend([
            "",
            "【静态提取路由线索】",
            route_intro,
            _truncate_text("\n".join(route_lines), route_text_limit),
        ])

    if extra_guidance:
        sections.extend([
            "",
            "【本轮补充约束】",
            extra_guidance,
        ])

    if stage.stage_num > 1:
        sections.extend([
            "",
            "【前序阶段结果】",
            prev_context if prev_context else "暂无前序阶段结果",
        ])

    sections.extend([
        "",
        "【待审计代码】",
        code_text or "未提取到代码片段",
        "",
        "请输出合法 JSON。",
    ])

    return "\n".join(sections)


def _build_stage1_microcompact_context(project, static_routes: list[dict], compressed_summary: dict, chunk_batch: list[dict], pass_index: int, total_passes: int, pre_discovery: dict | None = None) -> dict:
    focus_files = [chunk.get("file_path", "") for chunk in chunk_batch if chunk.get("file_path")]
    focus_files = _merge_unique_items([], focus_files)
    covered_paths = (
        compressed_summary.get("coverage", {}).get("covered_paths", [])
        if isinstance(compressed_summary.get("coverage"), dict)
        else []
    )
    confirmed_routes = []
    architecture_info = compressed_summary.get("architecture_info")
    if isinstance(architecture_info, dict) and isinstance(architecture_info.get("routes"), list):
        confirmed_routes = architecture_info.get("routes", [])

    project_tree_summary = (
        _summarize_project_tree(project.file_tree or [], limit=120)
        if pass_index == 1
        else _summarize_focus_files(focus_files, covered_paths)
    )
    route_lines = _select_route_delta_lines(
        static_routes=static_routes,
        focus_files=focus_files,
        confirmed_routes=confirmed_routes,
        pass_index=pass_index,
    )
    route_intro = (
        "以下为首轮高价值静态路由候选，请优先建立全局接口地图。"
        if pass_index == 1
        else "以下仅保留与本轮代码批次强相关、且尚未在压缩摘要中确认的静态路由 delta。"
    )
    extra_guidance = (
        f"本轮聚焦 {len(focus_files)} 个文件。已覆盖文件数：{len(covered_paths)}。"
        if pass_index > 1
        else f"本轮为阶段一首轮扫描，共计划 {total_passes} 轮，请先建立项目骨架。"
    )

    pre_discovery_summary = ""
    if pass_index == 1 and pre_discovery:
        tp = pre_discovery.get("tech_profile") or {}
        ds = pre_discovery.get("dir_structure") or {}
        mm = pre_discovery.get("middleware_map") or {}
        sf = pre_discovery.get("security_files") or {}
        parts = []
        for key in ["language", "framework", "database", "orm", "auth_library"]:
            vals = tp.get(key, [])
            if vals:
                parts.append(f"{key}: {', '.join(vals[:5])}")
        if ds.get("pattern") and ds["pattern"] != "unknown":
            parts.append(f"project_pattern: {ds['pattern']}")
        if mm.get("middleware_chain"):
            parts.append(f"middleware_count: {len(mm['middleware_chain'])}")
        if mm.get("auth_decorators"):
            parts.append(f"auth_decorators: {', '.join(list(mm['auth_decorators'].keys())[:5])}")
        if sf.get("total_critical_count"):
            parts.append(f"security_critical_files: {sf['total_critical_count']}")
        if parts:
            pre_discovery_summary = "【静态预发现】" + "；".join(parts) + "。请优先识别以上技术栈特征，并在架构信息中标注。"

    return {
        "project_tree_summary": project_tree_summary,
        "route_lines": route_lines,
        "route_text_limit": 12000 if pass_index == 1 else 5000,
        "route_intro": route_intro,
        "extra_guidance": extra_guidance,
        "focus_files": focus_files[:50],
        "pre_discovery_summary": pre_discovery_summary,
    }


def _summarize_focus_files(focus_files: list[str], covered_paths: list[str]) -> str:
    lines = ["- 本轮重点文件："]
    for path in focus_files[:40]:
        marker = " (new)" if path not in covered_paths else " (revisit)"
        lines.append(f"  - {path}{marker}")
    if covered_paths:
        lines.append(f"- 累计已覆盖文件数：{len(covered_paths)}")
    return "\n".join(lines)


def _format_static_route_lines(routes: list[dict], total_count: int | None = None) -> list[str]:
    route_lines = []
    for route in routes:
        params = ",".join(route.get("params", [])) if isinstance(route.get("params"), list) else ""
        route_lines.append(
            f"- {route.get('method', 'UNKNOWN')} {route.get('path', '')} | "
            f"handler={route.get('handler', 'Unknown')} | file={route.get('file_path', '')} | "
            f"auth={route.get('auth', 'Unknown')} | params={params}"
        )
    if total_count and total_count > len(routes):
        route_lines.append(f"- ... total static routes: {total_count}")
    return route_lines


def _select_route_delta_lines(static_routes: list[dict], focus_files: list[str], confirmed_routes: list[dict], pass_index: int) -> list[str]:
    confirmed_keys = set()
    for route in confirmed_routes:
        if not isinstance(route, dict):
            continue
        confirmed_keys.add(
            (
                str(route.get("method", "UNKNOWN")).upper(),
                route.get("path", ""),
                route.get("handler", "Unknown"),
                route.get("file_path", ""),
            )
        )

    focus_set = set(focus_files)
    filtered = []
    global_uncovered = []
    for route in static_routes:
        if not isinstance(route, dict):
            continue
        route_key = (
            str(route.get("method", "UNKNOWN")).upper(),
            route.get("path", ""),
            route.get("handler", "Unknown"),
            route.get("file_path", ""),
        )
        if pass_index > 1 and route_key in confirmed_keys:
            continue
        if pass_index > 1 and focus_set and route.get("file_path", "") not in focus_set:
            global_uncovered.append(route)
            continue
        filtered.append(route)

    if pass_index == 1:
        filtered = filtered[:60]
    else:
        filtered = filtered[:16]
        if len(filtered) < 24:
            filtered.extend(global_uncovered[: 24 - len(filtered)])

    if not filtered and focus_files:
        return [f"- 本轮批次文件未命中新静态路由；请重点从代码中补充 {', '.join(focus_files[:8])} 的模块职责与数据流。"]
    return _format_static_route_lines(filtered, total_count=len(filtered))


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 32)] + "\n... (truncated)\n"


def _apply_exploit_stage_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    stage_num: int,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 12000 if aggressive else 18000
    prev_limit = 700 if aggressive else 1200
    route_limit = 5 if aggressive else 8
    route_text_limit = 1400 if aggressive else 2200
    rule_hit_limit = 4 if aggressive else 6
    focus_file_limit = 16 if aggressive else 24

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:rule_hit_limit]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    stage_label = "阶段二" if stage_num == 2 else "阶段三/四/八"
    budget_guidance = (
        f"{stage_label} 请优先压缩输出，先保证完整 JSON 闭合。"
        "architecture_info 仅保留最关键入口、框架和约束信息；"
        "vulnerabilities 优先保留 title、severity、vuln_type、file_path、endpoint、description 和可复现 PoC，压缩背景说明，不要压缩请求行、Host、必要 Header、请求体或关键复现步骤。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)


def _apply_stage5_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 9000 if aggressive else 14000
    prev_limit = 500 if aggressive else 900
    route_limit = 4 if aggressive else 6
    route_text_limit = 1000 if aggressive else 1600
    rule_hit_limit = 3 if aggressive else 5
    focus_file_limit = 12 if aggressive else 18
    audit_memory_limit = 1400 if aggressive else 2200

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:rule_hit_limit]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]
    compact_context["audit_memory_limit"] = min(int(compact_context.get("audit_memory_limit", audit_memory_limit) or audit_memory_limit), audit_memory_limit)

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    budget_guidance = (
        "阶段五请压缩认证与会话背景描述，先保证完整 JSON。"
        "architecture_info 只保留认证机制、令牌/会话线索和关键入口；"
        "vulnerabilities 优先保留 title、severity、vuln_type、file_path、endpoint、description 和可复现 PoC，压缩背景说明，不要压缩关键请求行或核心复现步骤。"
        "首轮不要展开登录、注册、找回密码、刷新令牌、验证码的完整链路。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)


def _apply_stage6_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    code_limit = 16000 if aggressive else 24000
    prev_limit = 900 if aggressive else 1600
    route_limit = 6 if aggressive else 10
    route_text_limit = 1800 if aggressive else 2800
    rule_hit_limit = 6 if aggressive else 10
    focus_file_limit = 20 if aggressive else 28

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:rule_hit_limit]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    budget_guidance = (
        "阶段六请优先保留对象级授权、资源归属校验、tenant 约束和可形成越权链的最强证据；"
        "不要展开登录、注册、找回密码、验证码等认证背景。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)


def _apply_stage9_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 12000 if aggressive else 18000
    prev_limit = 700 if aggressive else 1200
    route_limit = 5 if aggressive else 8
    route_text_limit = 1400 if aggressive else 2200
    rule_hit_limit = 4 if aggressive else 6
    focus_file_limit = 16 if aggressive else 24

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:rule_hit_limit]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    budget_guidance = (
        "阶段九首轮只保留最强业务逻辑漏洞索引，不要铺陈业务背景。"
        "architecture_info 仅保留最关键入口、核心约束和受影响对象。"
        "vulnerabilities 优先保留 title、severity、vuln_type、file_path、endpoint、简短 description 和可复现 PoC，压缩背景说明，不要压缩关键复现步骤。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)


def _apply_lightweight_stage_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    stage_num: int,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 9000 if aggressive else 14000
    prev_limit = 500 if aggressive else 1000
    route_limit = 4 if aggressive else 6
    route_text_limit = 1200 if aggressive else 1800
    focus_file_limit = 12 if aggressive else 18

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:route_limit]
    compact_context["route_text_limit"] = min(int(compact_context.get("route_text_limit", route_text_limit) or route_text_limit), route_text_limit)
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:4]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    stage_label = f"阶段{stage_num}"
    budget_guidance = (
        f"{stage_label} 请优先保证 JSON 完整闭合，减少背景铺陈。"
        "architecture_info 和 vulnerabilities 都只保留最小必要信息。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)


def _apply_summary_stage_prompt_budget(
    compact_context: dict | None,
    code_text: str,
    prev_context: str,
    stage_num: int,
    aggressive: bool = False,
) -> tuple[dict, str, str]:
    compact_context = dict(compact_context or {})
    compact_context["response_mode"] = "index_first"
    code_limit = 9000 if aggressive else 14000
    prev_limit = 500 if aggressive else 1000
    focus_file_limit = 12 if aggressive else 18

    compact_context["route_lines"] = (compact_context.get("route_lines") or [])[:0]
    compact_context["route_text_limit"] = 0
    compact_context["rule_hit_lines"] = (compact_context.get("rule_hit_lines") or [])[:0]
    compact_context["focus_files"] = (compact_context.get("focus_files") or [])[:focus_file_limit]

    extra_guidance = str(compact_context.get("extra_guidance", "") or "").strip()
    budget_guidance = (
        "请优先输出可闭合的综合 JSON，避免长篇报告化描述。"
        "architecture_info 仅保留全局关键结构；"
        "vulnerabilities 优先保留 title、severity、vuln_type、file_path、endpoint、description。"
    )
    compact_context["extra_guidance"] = "\n".join(part for part in [extra_guidance, budget_guidance] if part)

    return compact_context, _truncate_text(code_text or "", code_limit), _truncate_text(prev_context or "", prev_limit)


def _summarize_project_tree(tree: list, limit: int = 180) -> str:
    lines: list[str] = []

    def walk(nodes: list, level: int):
        for node in nodes:
            if len(lines) >= limit:
                return
            prefix = "  " * level
            lines.append(f"{prefix}- {node.get('path', node.get('name', ''))}")
            if node.get("type") == "directory" and node.get("children"):
                walk(node["children"], level + 1)

    walk(tree, 0)
    if not lines:
        return "- 无文件树信息"
    if len(lines) >= limit:
        lines.append("- ... (truncated)")
    return "\n".join(lines)


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


def _vuln_key(vuln_data: dict) -> tuple:
    return _root_cause_vuln_key(vuln_data)


def _root_cause_vuln_key(vuln_data: dict) -> tuple:
    family = _normalize_vuln_family(vuln_data)
    file_anchor = _normalize_file_anchor(str(vuln_data.get("file_path", "") or ""))
    line_anchor = _normalize_line_anchor(
        vuln_data.get("line_start"),
        vuln_data.get("line_end"),
        str(vuln_data.get("code_snippet", "") or ""),
    )
    endpoint_anchor = _normalize_endpoint_anchor(str(vuln_data.get("endpoint", "") or ""))
    if line_anchor:
        location_anchor = line_anchor
    elif endpoint_anchor:
        location_anchor = endpoint_anchor
    else:
        location_anchor = _normalize_code_anchor(
            str(vuln_data.get("code_snippet", "") or "") or str(vuln_data.get("description", "") or "")
        )
    return (
        family,
        file_anchor,
        location_anchor or "global",
    )


def _stable_vuln_dedupe_key(vuln_data: dict) -> str:
    parts = [str(part) for part in _root_cause_vuln_key(vuln_data)]
    normalized = "|".join(parts)
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:32]


def _normalize_vuln_family(vuln_data: dict) -> str:
    haystack = " ".join(
        [
            str(vuln_data.get("title", "") or ""),
            str(vuln_data.get("vuln_type", "") or ""),
            str(vuln_data.get("description", "") or ""),
            str(vuln_data.get("code_snippet", "") or ""),
        ]
    ).lower()

    if "注入" in haystack:
        if "sql" in haystack or any(marker in haystack for marker in ["select ", "update ", "insert ", "delete from", "where "]):
            return "sql_injection"
        if any(marker in haystack for marker in ["mongo", "bson", "nosql"]):
            return "nosql_injection"
        if any(marker in haystack for marker in ["exec", "shell", "command", "system("]):
            return "command_injection"

    family_markers = [
        ("sql_injection", ["sql 注入", "sql注入", "sqli", "sql injection"]),
        ("nosql_injection", ["nosql", "mongo injection", "nosql injection"]),
        ("command_execution", ["rce", "命令执行", "command execution", "remote code execution"]),
        ("command_injection", ["命令注入", "command injection"]),
        ("xss", ["xss", "跨站脚本"]),
        ("ssrf", ["ssrf", "服务端请求伪造"]),
        ("file_upload", ["文件上传", "upload"]),
        ("file_download", ["文件下载", "download"]),
        ("path_traversal", ["路径穿越", "目录遍历", "path traversal", "directory traversal"]),
        ("arbitrary_file_access", ["任意文件", "file read", "file write"]),
        ("deserialization", ["反序列化", "deserialize"]),
        ("template_injection", ["模板注入", "ssti", "template injection"]),
        ("session_fixation", ["会话固定", "session fixation"]),
        ("brute_force", ["暴力破解", "brute force"]),
        ("weak_password_hash", ["弱密码哈希", "无盐 md5", "无盐md5", "weak md5", "weak sha1", "密码哈希"]),
        ("hardcoded_secret", ["硬编码", "hardcoded", "secret key", "api key", "access key", "private key"]),
        ("config_leak", ["配置泄露", "信息泄露", ".env", "目录索引", "directory listing", "stack trace"]),
        ("authorization_bypass", ["越权", "idor", "权限绕过", "水平越权", "垂直越权"]),
        ("business_logic_bypass", ["业务逻辑", "支付绕过", "下载绕过", "流程绕过", "logic bypass"]),
        ("race_condition", ["竞态", "race"]),
    ]
    for family, markers in family_markers:
        if any(marker in haystack for marker in markers):
            return family

    base = _normalize_keyword_text(str(vuln_data.get("vuln_type", "") or "") or str(vuln_data.get("title", "") or ""))
    return base[:80] or "generic_vulnerability"


def _normalize_keyword_text(text: str) -> str:
    normalized = str(text or "").strip().lower().replace("\\", "/")
    normalized = re.sub(r"https?://\S+", " ", normalized)
    normalized = re.sub(r"[^0-9a-z\u4e00-\u9fff/._-]+", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _normalize_file_anchor(file_path: str) -> str:
    normalized = _normalize_keyword_text(file_path)
    if not normalized:
        return ""
    segments = [segment for segment in normalized.split("/") if segment]
    if len(segments) > 4:
        segments = segments[-4:]
    return "/".join(segments)


def _normalize_line_anchor(line_start, line_end, code_snippet: str) -> str:
    if line_start is not None:
        try:
            start = int(line_start)
            end = int(line_end) if line_end is not None else start
            return f"line:{start}-{end}"
        except (TypeError, ValueError):
            pass
    code_anchor = _normalize_code_anchor(code_snippet)
    return f"code:{code_anchor}" if code_anchor else ""


def _normalize_code_anchor(text: str) -> str:
    normalized = _normalize_keyword_text(text)
    if not normalized:
        return ""
    normalized = re.sub(r"\b\d+\b", "{n}", normalized)
    normalized = re.sub(r"\b[0-9a-f]{8,}\b", "{hex}", normalized)
    normalized = normalized[:160]
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _normalize_endpoint_anchor(endpoint: str) -> str:
    text = str(endpoint or "").strip()
    if not text:
        return ""
    match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|ANY|UNKNOWN)\s+(\S+)$", text, re.I)
    if match:
        method = match.group(1).upper()
        path = match.group(2).strip()
    else:
        method = "UNKNOWN"
        path = text
    path = path.split("?", 1)[0].strip().lower().replace("\\", "/")
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    path = re.sub(r"/[0-9a-f-]{8,}(?=/|$)", "/{id}", path)
    path = re.sub(r"/+", "/", path).strip()
    return f"{method} {path}".strip()


def _vulnerability_merge_score(vuln: dict) -> int:
    if not isinstance(vuln, dict):
        return 0
    score = _severity_rank(vuln.get("severity")) * 100
    score += CONFIDENCE_RANK.get(_normalize_confidence(vuln.get("confidence")), 2) * 20
    if str(vuln.get("poc_validation_status", "") or "").strip().lower() == "valid":
        score += 20
    if str(vuln.get("code_snippet", "") or "").strip():
        score += 12
    if str(vuln.get("poc_raw", "") or "").strip():
        score += 10
    if str(vuln.get("endpoint", "") or "").strip():
        score += 6
    if str(vuln.get("description", "") or "").strip():
        score += min(12, len(str(vuln.get("description", "") or "").strip()) // 80)
    return score


def _merge_duplicate_vulnerability(primary: dict, incoming: dict) -> dict:
    primary_copy = dict(primary or {})
    incoming_copy = dict(incoming or {})
    preferred = primary_copy if _vulnerability_merge_score(primary_copy) >= _vulnerability_merge_score(incoming_copy) else incoming_copy
    secondary = incoming_copy if preferred is primary_copy else primary_copy
    merged = dict(preferred)

    merged["severity"] = _normalize_severity(
        preferred.get("severity")
        if _severity_rank(preferred.get("severity")) >= _severity_rank(secondary.get("severity"))
        else secondary.get("severity")
    )
    merged["confidence"] = (
        preferred.get("confidence")
        if CONFIDENCE_RANK.get(_normalize_confidence(preferred.get("confidence")), 2)
        >= CONFIDENCE_RANK.get(_normalize_confidence(secondary.get("confidence")), 2)
        else secondary.get("confidence")
    )

    if str(primary_copy.get("poc_validation_status", "") or "").strip().lower() == "valid" or str(incoming_copy.get("poc_validation_status", "") or "").strip().lower() == "valid":
        merged["poc_validation_status"] = "valid"
    elif str(preferred.get("poc_validation_status", "") or "").strip():
        merged["poc_validation_status"] = preferred.get("poc_validation_status")
    elif str(secondary.get("poc_validation_status", "") or "").strip():
        merged["poc_validation_status"] = secondary.get("poc_validation_status")

    for field in ["title", "vuln_type", "file_path", "code_snippet", "endpoint", "poc_raw", "description", "fix_suggestion", "poc_validation_note"]:
        preferred_value = str(preferred.get(field, "") or "").strip()
        secondary_value = str(secondary.get(field, "") or "").strip()
        if preferred_value:
            merged[field] = preferred_value
        elif secondary_value:
            merged[field] = secondary_value

    line_start = preferred.get("line_start")
    line_end = preferred.get("line_end")
    if line_start is None and secondary.get("line_start") is not None:
        line_start = secondary.get("line_start")
    if line_end is None and secondary.get("line_end") is not None:
        line_end = secondary.get("line_end")
    merged["line_start"] = line_start
    merged["line_end"] = line_end

    # 同根因的等价入口压成简短备注，避免前端出现多张几乎相同的卡片。
    endpoints = [value for value in _merge_unique_items([], [preferred.get("endpoint"), secondary.get("endpoint")]) if str(value or "").strip()]
    if endpoints:
        merged["endpoint"] = str(endpoints[0]).strip()
        if len(endpoints) > 1:
            note = f"等价入口：{'；'.join(str(item).strip() for item in endpoints[1:4])}"
            description = str(merged.get("description", "") or "").strip()
            if note not in description:
                merged["description"] = f"{description}\n\n{note}".strip() if description else note

    if "_poc_validation" in preferred or "_poc_validation" in secondary:
        primary_validation = preferred.get("_poc_validation") if isinstance(preferred.get("_poc_validation"), dict) else {}
        secondary_validation = secondary.get("_poc_validation") if isinstance(secondary.get("_poc_validation"), dict) else {}
        merged["_poc_validation"] = (
            primary_validation
            if primary_validation.get("accepted")
            else secondary_validation
            if secondary_validation.get("accepted")
            else primary_validation or secondary_validation
        )
    if preferred.get("_detail_enriched") or secondary.get("_detail_enriched"):
        merged["_detail_enriched"] = True
    if preferred.get("_salvaged") or secondary.get("_salvaged"):
        merged["_salvaged"] = True
    return merged


def _get_stage_topic_keywords(stage_num: int) -> list[str]:
    rules = {
        2: [
            "exec", "eval", "system(", "shell", "popen", "runtime.exec", "processbuilder",
            "command", "os.system", "subprocess", "child_process",
            "pickle", "unserialize", "yaml.load", "marshal", "deserialize",
            "proc_open", "pcntl_exec", "assert(", "compile(",
            "vm.run", "class.forname", "scriptengine", "objectinputstream",
            "os/exec", "exec.command", "spawn(",
            "jinja2", "freemarker", "velocity", "ognl", "spel", "mvel",
            "xstream", "xmldecoder", "invocationhandler",
        ],
        3: [
            "sql", "query", "cursor", "select ", "insert ", "update ", "delete ",
            "execute(", "raw(", "orm", "mongodb", "redis",
            "preparedstatement", "jdbctemplate", "hibernate",
            "sequelize", "knex", "typeorm", "prisma", "mongoose",
            "db.query", "db.exec", "gorm", "sqlx",
            "$where", "$gt", "$regex", "nosql",
            "ldap_search", "ldap_bind", "graphql",
            "executescript(", "rawsql", "raw_query",
            "statement", "createorreplace",
        ],
        4: [
            "xss", "html", "template", "render", "innerhtml", "v-html",
            "document.write", "escape", "sanitize", "encode",
            "outerhtml", "dangerouslysetinnerhtml", "domparser",
            "insertadjacenthtml", "contenteditable",
            "srcdoc", "javascript:", "postmessage(",
            "bypasssecuritytrust", "domsanitizer",
            "htmlspecialchars", "strip_tags",
            "onerror", "onclick", "onload",
        ],
        5: [
            "auth", "login", "jwt", "token", "session", "cookie", "oauth",
            "password", "signin", "signup",
            "bearer", "authenticate", "verify_token",
            "saml", "kerberos", "ntlm",
            "recaptcha", "hcaptcha", "totp", "mfa", "2fa",
            "bcrypt", "argon2", "pbkdf2",
            "refresh_token", "access_token",
            "rate_limit", "lockout", "login_attempts",
            "session_regenerate", "csrf",
        ],
        6: [
            "permission", "authorize", "acl", "role", "idor", "tenant",
            "owner", "resource_id", "user_id", "guard",
            "authorization", "policy", "scope", "preauthorize",
            "tenant_id", "account_id", "isadmin", "hasrole",
            "org_id", "project_id", "team_id", "customer_id",
            "current_user", "principal", "can_access",
            "ownership", "resource", "access_control",
        ],
        7: [
            "config", "secret", ".env", "yaml", "yml", "toml", "ini",
            "docker", "compose", "dependency", "package.json",
            "api_key", "private_key", "access_key", "credentials",
            "db_password", "database_url", "debug=true",
            "cors_origin", "allowed_hosts", "ssl", "tls",
            "aws_secret", "azure_key", "gcp_key",
            "kubernetes", "nginx", "apache",
            "requirements.txt", "go.mod", "pom.xml", "gemfile",
            "github_token", "slack_token", "stripe_key",
            "0.0.0.0", "verify=false",
        ],
        8: [
            "file", "upload", "download", "open(", "path", "shutil",
            "zip", "tar", "filesystem", "storage",
            "fopen", "readfile", "file_get_contents", "unlink",
            "mkdir", "rmdir", "copy(", "rename(", "scandir",
            "realpath", "basename", "dirname", "glob(",
            "tempfile", "symlink", "move_uploaded_file",
            "fs.readfile", "fs.writefile", "multipartfile",
            "filepath.join", "os.path",
            "../", "..\\", "extractto", "phar",
        ],
        9: [
            "order", "payment", "amount", "price", "inventory", "coupon",
            "workflow", "status", "balance", "logic",
            "refund", "withdraw", "deposit", "transfer",
            "invoice", "billing", "receipt", "tax",
            "discount", "promo", "voucher", "reward",
            "stock", "quantity", "merchant", "customer",
            "settlement", "commission", "profit",
            "approve", "reject", "cancel", "confirm",
            "points", "level", "vip", "membership",
            "quota", "threshold", "limit",
        ],
    }
    return rules.get(stage_num, [])


def _build_stage_focus_compact_context(
    stage,
    project,
    static_routes: list[dict],
    selected_chunks: list[dict],
    audit_memory: dict | None = None,
    rule_hits: list[dict] | None = None,
    source_sink_hints: list[dict] | None = None,
) -> dict:
    audit_memory = audit_memory or {}
    rule_hits = rule_hits or []
    source_sink_hints = source_sink_hints or []
    focus_file_limit = 32 if stage.stage_num == 6 else 40
    focus_files = _merge_unique_items([], [chunk.get("file_path", "") for chunk in selected_chunks if chunk.get("file_path")])[:focus_file_limit]
    topic_keywords = _get_stage_topic_keywords(stage.stage_num)
    focus_routes = _select_stage_focus_routes(stage.stage_num, static_routes, audit_memory, focus_files)
    route_lines = _format_static_route_lines(focus_routes, total_count=len(focus_routes))
    evidence_files = audit_memory.get("evidence_files", []) if isinstance(audit_memory.get("evidence_files"), list) else []
    route_inventory = audit_memory.get("route_inventory", []) if isinstance(audit_memory.get("route_inventory"), list) else []
    vulnerability_hints = audit_memory.get("vulnerability_hints", []) if isinstance(audit_memory.get("vulnerability_hints"), list) else []
    stage_rule_hits = _select_stage_rule_hits(stage.stage_num, rule_hits, focus_files)
    rule_hit_lines = _format_stage_rule_hit_lines(stage_rule_hits)
    stage_source_sink_hints = _select_stage_source_sink_hints(stage.stage_num, source_sink_hints, focus_files)
    source_sink_lines = _format_stage_source_sink_lines(stage_source_sink_hints)

    guidance = [
        f"当前阶段专题关键词：{', '.join(topic_keywords[:10])}" if topic_keywords else "当前阶段请严格聚焦本阶段目标，不要重复全局架构复述。",
        f"本轮重点文件数：{len(focus_files)}。",
        f"前序证据文件数：{len(evidence_files)}，路由库存数：{len(route_inventory)}，漏洞提示数：{len(vulnerability_hints)}。",
    ]
    if stage_rule_hits:
        guidance.append(f"规则预筛命中数：{len(stage_rule_hits)}，优先核查这些线索，再扩展到相邻调用链。")
    if stage_source_sink_hints:
        guidance.append(f"已注入轻量 source-sink 线索：{len(stage_source_sink_hints)}，优先验证这些可达路径，再扩展到相邻调用链。")
    if stage.stage_num == 6:
        guidance.append("阶段六请只关注对象级授权、租户隔离、资源归属校验和越权访问链，不要重复展开登录认证流程。")
    if stage.stage_num == 9:
        guidance.append("阶段九请优先输出最强证据的业务逻辑漏洞，减少冗长背景描述，避免响应被截断。")
    if stage.stage_num == 3:
        guidance.append("阶段三请优先保证 JSON 完整闭合，再输出注入类漏洞细节。")
    if stage.stage_num == 8:
        guidance.append("阶段八请只保留证据最强的 3-4 个文件操作漏洞；若为同一路径遍历模式，合并为一条代表性结果。")
        guidance.append("阶段八的 architecture_info 仅保留最小必要入口、文件读写点和路径校验结论，不要展开冗长背景。")
        guidance.append("阶段八每条漏洞描述尽量精简，优先保留危险文件操作、可控参数、路径拼接方式和最小 PoC。")

    return {
        "project_tree_summary": _summarize_stage_focus_files(project.file_tree or [], focus_files, evidence_files),
        "route_lines": route_lines,
        "route_text_limit": 3600 if stage.stage_num == 6 else 5000,
        "route_intro": "以下仅保留与当前阶段专题高度相关的入口与路由证据，请结合源码核对，不要机械照抄。",
        "extra_guidance": "\n".join(guidance),
        "focus_files": focus_files,
        "focus_routes": focus_routes,
        "rule_hit_lines": rule_hit_lines[:12] if stage.stage_num == 6 else rule_hit_lines,
        "source_sink_lines": source_sink_lines,
    }


def _select_stage_source_sink_hints(stage_num: int, source_sink_hints: list[dict], focus_files: list[str], limit: int = 8) -> list[dict]:
    if not source_sink_hints:
        return []

    focus_set = {str(path).strip().lower() for path in focus_files if str(path).strip()}
    scored = []
    for hint in source_sink_hints:
        if not isinstance(hint, dict):
            continue
        stage_nums = hint.get("stage_nums", [])
        if isinstance(stage_nums, list) and stage_num not in stage_nums:
            continue
        file_path = str(hint.get("file_path", "") or "").strip()
        if not file_path:
            continue
        score = int(hint.get("risk_score", 0) or 0)
        if file_path.lower() in focus_set:
            score += 12
        scored.append((score, hint))

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "")), str(item[1].get("label", ""))))
    return [hint for score, hint in scored[:limit] if score > 0]


def _format_stage_source_sink_lines(source_sink_hints: list[dict]) -> list[str]:
    lines = []
    for hint in source_sink_hints:
        if not isinstance(hint, dict):
            continue
        routes = ",".join((hint.get("route_paths") or [])[:3]) if isinstance(hint.get("route_paths"), list) else ""
        sources = ",".join((hint.get("source_types") or [])[:3]) if isinstance(hint.get("source_types"), list) else ""
        sinks = ",".join((hint.get("sink_keywords") or [])[:4]) if isinstance(hint.get("sink_keywords"), list) else ""
        lines.append(
            "- "
            + f"{hint.get('title', 'source-sink hint')} | file={hint.get('file_path', '')} | "
            + f"sources={sources} | sinks={sinks} | routes={routes} | "
            + f"evidence={str(hint.get('evidence', '')).replace(chr(10), ' / ')}"
        )
    return lines


def _compact_audit_memory_for_stage(stage_num: int, audit_memory: dict) -> dict:
    if not isinstance(audit_memory, dict):
        return {}
    if stage_num in {2, 3, 4}:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-4:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:20],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:32] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "entry_points": (audit_memory.get("entry_points") or [])[:16] if isinstance(audit_memory.get("entry_points"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:16] if isinstance(audit_memory.get("modules"), list) else [],
            "data_flows": (audit_memory.get("data_flows") or [])[:12] if isinstance(audit_memory.get("data_flows"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:8] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    if stage_num == 7:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-4:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:16],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:24] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:16] if isinstance(audit_memory.get("modules"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:6] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    if stage_num == 5:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-3:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:12],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:20] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "entry_points": (audit_memory.get("entry_points") or [])[:10] if isinstance(audit_memory.get("entry_points"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:10] if isinstance(audit_memory.get("modules"), list) else [],
            "data_flows": (audit_memory.get("data_flows") or [])[:8] if isinstance(audit_memory.get("data_flows"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:5] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    if stage_num == 6:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-5:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:24],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:40] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "entry_points": (audit_memory.get("entry_points") or [])[:20] if isinstance(audit_memory.get("entry_points"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:20] if isinstance(audit_memory.get("modules"), list) else [],
            "data_flows": (audit_memory.get("data_flows") or [])[:16] if isinstance(audit_memory.get("data_flows"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:10] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    if stage_num == 8:
        return {
            "completed_stage_count": audit_memory.get("completed_stage_count", 0),
            "stages": audit_memory.get("stages", [])[-4:] if isinstance(audit_memory.get("stages"), list) else [],
            "evidence_files": (audit_memory.get("evidence_files") or [])[:20],
            "route_inventory": (audit_memory.get("route_inventory") or [])[:40] if isinstance(audit_memory.get("route_inventory"), list) else [],
            "modules": (audit_memory.get("modules") or [])[:20] if isinstance(audit_memory.get("modules"), list) else [],
            "data_flows": (audit_memory.get("data_flows") or [])[:20] if isinstance(audit_memory.get("data_flows"), list) else [],
            "vulnerability_hints": (audit_memory.get("vulnerability_hints") or [])[:12] if isinstance(audit_memory.get("vulnerability_hints"), list) else [],
        }
    compact = {
        "completed_stage_count": audit_memory.get("completed_stage_count", 0),
        "stages": audit_memory.get("stages", [])[-6:] if isinstance(audit_memory.get("stages"), list) else [],
        "evidence_files": (audit_memory.get("evidence_files") or [])[:30],
    }

    route_inventory = audit_memory.get("route_inventory", [])
    if isinstance(route_inventory, list):
        compact["route_inventory"] = route_inventory[:80]
    for key in ["modules", "data_flows", "entry_points", "output_points"]:
        value = audit_memory.get(key)
        if isinstance(value, list):
            compact[key] = value[:30]
    vulnerability_hints = audit_memory.get("vulnerability_hints")
    if isinstance(vulnerability_hints, list):
        compact["vulnerability_hints"] = vulnerability_hints[:20]
    return compact


def _select_stage_focus_routes(
    stage_num: int,
    static_routes: list[dict],
    audit_memory: dict,
    focus_files: list[str],
) -> list[dict]:
    if not static_routes:
        return []

    topic_keywords = _get_stage_topic_keywords(stage_num)
    focus_set = set(focus_files)
    evidence_files = set(audit_memory.get("evidence_files", []) if isinstance(audit_memory.get("evidence_files"), list) else [])
    inventory_routes = audit_memory.get("route_inventory", []) if isinstance(audit_memory.get("route_inventory"), list) else []
    inventory_keys = {
        (str(route.get("method", "UNKNOWN")).upper(), str(route.get("path", "")).strip())
        for route in inventory_routes
        if isinstance(route, dict) and str(route.get("path", "")).strip()
    }

    scored = []
    for route in static_routes:
        if not isinstance(route, dict):
            continue
        file_path = str(route.get("file_path", ""))
        haystack = "\n".join([
            str(route.get("method", "")),
            str(route.get("path", "")),
            str(route.get("handler", "")),
            file_path,
            str(route.get("auth", "")),
        ]).lower()
        score = 0
        if any(keyword in haystack for keyword in topic_keywords):
            score += 5
        if file_path in focus_set:
            score += 4
        if file_path in evidence_files:
            score += 3
        route_key = (str(route.get("method", "UNKNOWN")).upper(), str(route.get("path", "")).strip())
        if route_key in inventory_keys:
            score += 2
        score += _route_priority_score(route)
        scored.append((score, route))

    scored.sort(key=lambda item: (-item[0], item[1].get("path", ""), item[1].get("method", "")))
    selected = [route for score, route in scored if score > 0][:24]
    if len(selected) < 12:
        selected.extend([route for _, route in scored[len(selected):12]])
    return _merge_unique_items([], selected)


def _summarize_stage_focus_files(tree: list, focus_files: list[str], evidence_files: list[str]) -> str:
    if not focus_files:
        return _summarize_project_tree(tree, limit=100)
    lines = ["- 当前阶段重点文件："]
    for path in focus_files[:30]:
        marker = " [evidence]" if path in evidence_files else ""
        lines.append(f"  - {path}{marker}")
    if evidence_files:
        lines.append(f"- 前序证据文件数：{len(evidence_files)}")
    return "\n".join(lines)


def _select_stage_rule_hits(stage_num: int, rule_hits: list[dict], focus_files: list[str], limit: int = 10) -> list[dict]:
    if not rule_hits:
        return []

    focus_set = {str(path).strip().lower() for path in focus_files if str(path).strip()}
    scored = []
    for hit in rule_hits:
        if not isinstance(hit, dict):
            continue
        file_path = str(hit.get("file_path", "")).strip()
        if not file_path:
            continue
        score = int(hit.get("risk_score", 0) or 0)
        stage_nums = hit.get("stage_nums", [])
        if isinstance(stage_nums, list) and stage_num in stage_nums:
            score += 8
        if file_path.lower() in focus_set:
            score += 6
        if any(keyword in str(hit.get("label", "")).lower() for keyword in _get_stage_topic_keywords(stage_num)[:6]):
            score += 2
        scored.append((score, hit))

    scored.sort(key=lambda item: (-item[0], str(item[1].get("file_path", "")), str(item[1].get("label", ""))))
    return [hit for _, hit in scored[:limit] if _ > 0]


def _format_stage_rule_hit_lines(rule_hits: list[dict]) -> list[str]:
    lines = []
    for hit in rule_hits:
        if not isinstance(hit, dict):
            continue
        lines.append(
            "- "
            + f"{hit.get('title', '规则命中')} | file={hit.get('file_path', '')} | "
            + f"chunk={hit.get('chunk_path', '')} | score={hit.get('risk_score', 0)} | "
            + f"evidence={str(hit.get('evidence', '')).replace(chr(10), ' / ')}"
        )
    return lines


def _build_prev_context(audit_memory: dict) -> str:
    if not audit_memory:
        return ""
    return _truncate_text(json.dumps(audit_memory, ensure_ascii=False, indent=2), 12000)


def _build_audit_memory(stages: list[AuditStage], current_stage_num: int | None = None) -> dict:
    completed_stages = []
    route_inventory = []
    audited_route_inventory = []
    modules = []
    data_flows = []
    entry_points = []
    output_points = []
    vulnerability_hints = []
    evidence_files = []
    architecture_summary = {}

    for stage in sorted(stages, key=lambda item: item.stage_num):
        if current_stage_num is not None and stage.stage_num == current_stage_num:
            continue
        if stage.status != "completed":
            continue

        findings = _coerce_stage_findings(stage.findings)
        compressed = stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {}
        architecture_info = findings.get("architecture_info") if isinstance(findings.get("architecture_info"), dict) else {}
        if not architecture_info and isinstance(compressed.get("architecture_info"), dict):
            architecture_info = compressed.get("architecture_info", {})
        stage_coverage = compressed.get("_stage_coverage", {}) if isinstance(compressed.get("_stage_coverage"), dict) else {}

        stage_vulns = findings.get("vulnerabilities", [])
        if not isinstance(stage_vulns, list):
            stage_vulns = []

        stage_summary = str(
            compressed.get("stage_summary")
            or findings.get("stage_summary")
            or ""
        ).strip()

        stage_record = {
            "stage_num": stage.stage_num,
            "stage_name": stage.stage_name,
            "stage_summary": stage_summary[:1200],
            "vulnerability_count": len(stage_vulns),
            "high_severity_count": sum(
                1 for vuln in stage_vulns if str(vuln.get("severity", "")).strip() in {"Critical", "High"}
            ),
            "audited_route_count": len(stage_coverage.get("focus_routes", [])) if isinstance(stage_coverage.get("focus_routes"), list) else 0,
            "files": _merge_unique_items(
                [],
                [vuln.get("file_path", "") for vuln in stage_vulns if isinstance(vuln, dict) and vuln.get("file_path")]
                + [route.get("file_path", "") for route in architecture_info.get("routes", []) if isinstance(route, dict) and route.get("file_path")]
                + list((compressed.get("coverage", {}) or {}).get("covered_paths", []) if isinstance(compressed.get("coverage"), dict) else []),
            )[:20],
        }

        completed_stages.append(stage_record)
        if not architecture_summary and architecture_info:
            architecture_summary = _summarize_architecture_info(architecture_info)
        route_inventory = _merge_unique_items(route_inventory, architecture_info.get("routes"))
        if isinstance(route_inventory, list):
            route_inventory = sorted(
                [item for item in route_inventory if isinstance(item, dict)],
                key=lambda item: (-_route_priority_score(item), item.get("path", ""), item.get("method", ""), item.get("handler", "")),
            )
        audited_route_inventory = _merge_unique_items(audited_route_inventory, stage_coverage.get("focus_routes"))
        modules = _merge_unique_items(modules, architecture_info.get("modules"))
        data_flows = _merge_unique_items(data_flows, architecture_info.get("data_flows"))
        entry_points = _merge_unique_items(entry_points, architecture_info.get("entry_points"))
        output_points = _merge_unique_items(output_points, architecture_info.get("output_points"))
        vulnerability_hints = _merge_vulnerability_lists(
            vulnerability_hints,
            compressed.get("vulnerability_hints") if isinstance(compressed.get("vulnerability_hints"), list) else stage_vulns,
        )[:30]
        evidence_files = _merge_unique_items(evidence_files, stage_record["files"])[:40]

    return {
        "completed_stage_count": len(completed_stages),
        "stages": completed_stages[-8:],
        "architecture_info": architecture_summary,
        "route_inventory": route_inventory[:200],
        "audited_route_inventory": audited_route_inventory[:200],
        "modules": modules[:80],
        "data_flows": data_flows[:80],
        "entry_points": entry_points[:80],
        "output_points": output_points[:80],
        "vulnerability_hints": vulnerability_hints[:30],
        "evidence_files": evidence_files[:40],
    }


def _update_task_audit_memory(task: AuditTask, audit_memory: dict, selected_stage_nums: list[int] | None = None) -> None:
    summary = task.summary if isinstance(task.summary, dict) else {}
    if selected_stage_nums is not None:
        summary["selected_stage_nums"] = list(selected_stage_nums)
    summary["audit_memory"] = audit_memory
    task.summary = dict(summary)
