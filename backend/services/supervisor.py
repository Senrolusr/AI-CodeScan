"""Supervisor multi-agent audit orchestrator."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import delete, select

from database import async_session
from models import AuditStage, AuditTask, LlmConfig, Project, Vulnerability
from prompts.stage_prompts import SUPERVISOR_PLAN_STAGE_NAME, SUPERVISOR_REVIEW_STAGE_NAME, get_stage_name, get_stage_prompt, STAGE_SPECS
from prompts.supervisor_prompts import (
    SUPERVISOR_PLANNING_SYSTEM,
    SUPERVISOR_PLANNING_USER,
    SUPERVISOR_REVIEW_SYSTEM,
    SUPERVISOR_REVIEW_USER,
    AGENT_FOCUS_PREFIX,
)
from services.code_parser import get_or_build_project_cache
from services.project_index import sync_project_index
from services import audit_runtime as rt
from services.vulnerability_review import (
    clear_stashed_review_state as _clear_stashed_review_state,
    snapshot_review_state as _snapshot_review_state,
    stash_review_state as _stash_review_state,
)
from services.json_repair import (
    decode_json_string_fragment as _decode_json_string_fragment,
    extract_balanced_json_value as _extract_balanced_json_value,
)
from services.llm_client import call_llm_with_meta
from services.ai_engine.severity import SEVERITY_ORDER
from services.ai_engine.stage_schema import validate_stage_output
from services.audit_engine import (
    _accumulate_token_usage,
    _apply_stage_payload,
    _coerce_stage_findings,
    _build_audit_memory,
    _build_prev_context,
    _is_task_stopping,
    _refresh_task_summary,
    _run_missing_route_followup,
    _run_single_pass_stage,
    _run_stage1_multi_pass,
    _select_stage_chunks,
    _parse_structured_response,
    _summarize_pre_discovery,
)

logger = logging.getLogger(__name__)

FALLBACK_MAX_AGENT_COUNT = 9


async def _record_agent_meta(session, task_id: int, agent_role: str, result, *, stage_num: int | None = None, error: str | None = None, subtask_id: int | None = None) -> None:
    """把一次 LLM 调用的 meta（token/latency/finish_reason）落成一条 AuditAgentRun。

    ``result`` 为 None 或失败时按 failed 记录。仅做影子写入，失败不阻断审计。
    """
    status = "completed"
    prompt_tokens = None
    completion_tokens = None
    latency_ms = None
    finish_reason = ""
    if result is None:
        status = "failed"
    else:
        meta = result.get("meta") if isinstance(result, dict) else None
        success = result.get("success") if isinstance(result, dict) else False
        if not success:
            status = "failed"
            error = error or (result.get("error", {}) or {}).get("message", "")
        if isinstance(meta, dict):
            usage = meta.get("usage") or {}
            prompt_tokens = usage.get("prompt_tokens") if isinstance(usage, dict) else None
            completion_tokens = usage.get("completion_tokens") if isinstance(usage, dict) else None
            latency_ms = meta.get("latency_ms")
            finish_reason = meta.get("finish_reason") or ""
    try:
        await rt.record_agent_run(
            session,
            task_id=task_id,
            agent_role=agent_role,
            status=status,
            stage_num=stage_num,
            subtask_id=subtask_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            finish_reason=finish_reason,
            error_message=error,
        )
    except Exception:  # noqa: BLE001 - 影子写入，失败不得阻断审计主流程
        logger.exception("record_agent_meta failed (task=%s role=%s stage=%s)", task_id, agent_role, stage_num)


def _add_task_degradation(task: AuditTask, code: str, message: str, phase: str) -> None:
    summary = dict(task.summary) if isinstance(task.summary, dict) else {}
    notes = summary.get("degradation_notes", [])
    if not isinstance(notes, list):
        notes = []

    note = {
        "code": code,
        "phase": phase,
        "message": message,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if not any(isinstance(item, dict) and item.get("code") == code and item.get("message") == message for item in notes):
        notes.append(note)

    summary["degraded"] = True
    summary["degradation_notes"] = notes[-20:]
    task.summary = summary


def _planned_sub_agent_stage_nums(agent_plan: dict | None) -> list[int]:
    if not isinstance(agent_plan, dict):
        return []
    stage_nums: list[int] = []
    seen: set[int] = set()
    for spec in agent_plan.get("selected_agents") or []:
        if not isinstance(spec, dict):
            continue
        stage_num = _safe_int(spec.get("stage_num"))
        if 2 <= stage_num <= 9 and stage_num not in seen:
            stage_nums.append(stage_num)
            seen.add(stage_num)
    return stage_nums


def _explainable_skipped_stage_nums(agent_plan: dict | None) -> set[int]:
    if not isinstance(agent_plan, dict):
        return set()
    stage_nums: set[int] = set()
    for spec in agent_plan.get("skipped_agents") or []:
        if not isinstance(spec, dict):
            continue
        stage_num = _safe_int(spec.get("stage_num"))
        reason = str(spec.get("skip_reason") or spec.get("reason") or "").strip()
        if 2 <= stage_num <= 9 and reason:
            stage_nums.add(stage_num)
    return stage_nums


def _build_orchestration_guard(agent_plan: dict | None, stages: list[AuditStage]) -> dict:
    planned_stage_nums = _planned_sub_agent_stage_nums(agent_plan)
    explainable_skips = _explainable_skipped_stage_nums(agent_plan)
    stage_map = {
        _safe_int(getattr(stage, "stage_num", None)): stage
        for stage in stages or []
        if 2 <= _safe_int(getattr(stage, "stage_num", None)) <= 9
    }

    completed_stage_nums: list[int] = []
    failed_stage_nums: list[int] = []
    missing_stage_nums: list[int] = []
    pending_stage_nums: list[int] = []
    running_stage_nums: list[int] = []
    skipped_stage_nums: list[int] = []
    unresolved_stage_nums: list[int] = []
    stage_statuses: dict[str, str] = {}

    for stage_num in planned_stage_nums:
        stage = stage_map.get(stage_num)
        if not stage:
            missing_stage_nums.append(stage_num)
            unresolved_stage_nums.append(stage_num)
            stage_statuses[str(stage_num)] = "missing"
            continue

        status = str(getattr(stage, "status", "") or "pending").strip().lower()
        stage_statuses[str(stage_num)] = status
        if status == "completed":
            completed_stage_nums.append(stage_num)
        elif status == "failed":
            failed_stage_nums.append(stage_num)
            unresolved_stage_nums.append(stage_num)
        elif status == "running":
            running_stage_nums.append(stage_num)
            unresolved_stage_nums.append(stage_num)
        elif status == "skipped":
            skipped_stage_nums.append(stage_num)
            if stage_num not in explainable_skips:
                unresolved_stage_nums.append(stage_num)
        elif status in {"pending", ""}:
            pending_stage_nums.append(stage_num)
            unresolved_stage_nums.append(stage_num)
        else:
            unresolved_stage_nums.append(stage_num)

    status = "ok"
    if not planned_stage_nums or unresolved_stage_nums:
        status = "blocked"

    if not planned_stage_nums:
        message = "阶段三没有可校验的并行审计计划，已阻止进入复核。"
    elif unresolved_stage_nums:
        stage_list = ", ".join(f"Stage {num}" for num in unresolved_stage_nums)
        message = f"阶段三并行审计未收敛，已阻止进入复核：{stage_list}。"
    else:
        message = "阶段三并行审计已收敛，可以进入复核。"

    return {
        "status": status,
        "planned_stage_nums": planned_stage_nums,
        "completed_stage_nums": completed_stage_nums,
        "failed_stage_nums": failed_stage_nums,
        "missing_stage_nums": missing_stage_nums,
        "pending_stage_nums": pending_stage_nums,
        "running_stage_nums": running_stage_nums,
        "skipped_stage_nums": skipped_stage_nums,
        "unresolved_stage_nums": sorted(set(unresolved_stage_nums)),
        "stage_statuses": stage_statuses,
        "message": message,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _persist_orchestration_guard(task: AuditTask, guard: dict) -> None:
    summary = dict(task.summary) if isinstance(task.summary, dict) else {}
    summary["orchestration_guard"] = guard
    task.summary = summary


async def _assert_sub_agent_phase_converged(session, task: AuditTask, agent_plan: dict | None, stages: list[AuditStage]) -> None:
    guard = _build_orchestration_guard(agent_plan, stages)
    _persist_orchestration_guard(task, guard)
    if guard.get("status") == "ok":
        await session.commit()
        return

    message = str(guard.get("message") or "阶段三并行审计未收敛，已阻止进入复核。")
    _add_task_degradation(
        task,
        "sub_agent_phase_not_converged",
        message,
        "sub_agent",
    )
    _persist_orchestration_guard(task, guard)
    await rt.emit_event(
        session,
        task_id=task.id,
        event_type=rt.EVENT_STAGE_FAILED,
        payload={
            "phase": "sub_agents",
            "message": message,
            "planned_stage_nums": guard.get("planned_stage_nums", []),
            "unresolved_stage_nums": guard.get("unresolved_stage_nums", []),
            "failed_stage_nums": guard.get("failed_stage_nums", []),
            "missing_stage_nums": guard.get("missing_stage_nums", []),
        },
    )
    await session.commit()
    raise RuntimeError(message)


def _normalize_rerun_stage_nums(rerun_agents: list) -> list[int]:
    stage_nums = []
    for item in rerun_agents or []:
        value = item.get("stage_num") if isinstance(item, dict) else item
        if isinstance(value, int) or str(value).isdigit():
            stage_num = int(value)
            if 2 <= stage_num <= 9 and stage_num not in stage_nums:
                stage_nums.append(stage_num)
    return stage_nums


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_json_string_field(text: str, field: str) -> str:
    match = re.search(rf'"{re.escape(field)}"\s*:\s*"((?:\\.|[^"\\])*)"', text, re.S)
    if not match:
        return ""
    return _decode_json_string_fragment(match.group(1)).strip()


def _extract_balanced_json_object(text: str, start_index: int) -> tuple[str, int]:
    return _extract_balanced_json_value(text, start_index, "{", "}")


def _extract_balanced_json_array(text: str, start_index: int) -> tuple[str, int, bool]:
    array_text, next_index = _extract_balanced_json_value(text, start_index, "[", "]")
    if array_text:
        return array_text, next_index, True
    return text[start_index:], len(text), False


def _extract_json_array_objects(text: str, field: str) -> list[dict]:
    marker_index = text.find(f'"{field}"')
    if marker_index == -1:
        return []
    array_start = text.find("[", marker_index)
    if array_start == -1:
        return []

    array_text, _, completed = _extract_balanced_json_array(text, array_start)
    items: list[dict] = []
    cursor = 1
    while cursor < len(array_text):
        object_start = array_text.find("{", cursor)
        if object_start == -1:
            break
        object_text, next_index = _extract_balanced_json_object(array_text, object_start)
        if not object_text:
            break
        try:
            value = json.loads(object_text)
        except json.JSONDecodeError:
            cursor = next_index
            continue
        if isinstance(value, dict):
            items.append(value)
        cursor = next_index
        if completed and cursor >= len(array_text) - 1:
            break
    return items


def _extract_json_array_stage_nums(text: str, field: str) -> list[int]:
    marker_index = text.find(f'"{field}"')
    if marker_index == -1:
        return []
    array_start = text.find("[", marker_index)
    if array_start == -1:
        return []

    array_text, _, _ = _extract_balanced_json_array(text, array_start)
    stage_nums: list[int] = []
    for match in re.finditer(r'"stage_num"\s*:\s*(\d+)', array_text):
        stage_num = _safe_int(match.group(1))
        if 2 <= stage_num <= 9 and stage_num not in stage_nums:
            stage_nums.append(stage_num)
    return stage_nums


def _normalize_agent_specs(items: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    seen_stage_nums: set[int] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        stage_num = _safe_int(item.get("stage_num"))
        if stage_num < 2 or stage_num > 9 or stage_num in seen_stage_nums:
            continue
        spec = dict(item)
        spec["stage_num"] = stage_num
        for key in ["focus_files", "focus_routes", "focus_functions", "focus_data_flows"]:
            if not isinstance(spec.get(key), list):
                spec[key] = []
        normalized.append(spec)
        seen_stage_nums.add(stage_num)

    for index, item in enumerate(normalized, start=1):
        item["priority"] = index
    return normalized


# §10.3 确定性合并时从 LLM 输出叠加到确定性候选 stage 的 focus 字段集合。
_FOCUS_KEYS = ("focus_guidance", "focus_files", "focus_routes", "focus_functions", "focus_data_flows")


def _merge_plan_with_llm_focus(deterministic_plan: dict, llm_plan: dict | None) -> dict:
    """§10.3 确定性主导合并：``deterministic_plan`` 锁定 **which stages**（stage_num 集合 +
    baseline + 证据排期），``llm_plan`` 仅贡献 focus 增强——按 stage_num 匹配叠加到对应
    候选 stage，绝不增删 stage。

    容忍 LLM 漂移：无论 LLM 返回旧格式 ``selected_agents``（带 stage_num）还是 focus-only
    结构，都按 stage_num 取 focus 字段叠加；LLM 自行增删的 stage 一律忽略（which stages
    由后端掌控，符合 §17.1「执行计划由后端决定」）。LLM 缺失某 stage 的 focus 时保留
    确定性默认 focus_guidance。
    """
    merged = dict(deterministic_plan) if isinstance(deterministic_plan, dict) else {"selected_agents": [], "skipped_agents": []}
    selected = [dict(item) for item in merged.get("selected_agents", []) if isinstance(item, dict)]
    skipped = [dict(item) for item in merged.get("skipped_agents", []) if isinstance(item, dict)]

    llm_focus_by_stage: dict[int, dict] = {}
    llm_analysis = ""
    if isinstance(llm_plan, dict):
        llm_analysis = str(llm_plan.get("analysis_summary") or "")
        for item in llm_plan.get("selected_agents", []):
            if not isinstance(item, dict):
                continue
            stage_num = _safe_int(item.get("stage_num"))
            if 2 <= stage_num <= 9:
                llm_focus_by_stage[stage_num] = item

    for agent in selected:
        stage_num = _safe_int(agent.get("stage_num"))
        focus = llm_focus_by_stage.get(stage_num)
        if not focus:
            continue
        for key in _FOCUS_KEYS:
            value = focus.get(key)
            if key == "focus_guidance":
                if isinstance(value, str) and value.strip():
                    agent[key] = value.strip()
            elif isinstance(value, list) and value:
                agent[key] = list(value)

    if llm_analysis.strip():
        merged["analysis_summary"] = llm_analysis.strip()
    elif "analysis_summary" not in merged:
        merged["analysis_summary"] = ""

    merged["selected_agents"] = selected
    merged["skipped_agents"] = skipped
    return merged


def _minimal_agent_spec(stage_num: int, *, reason: str, evidence: int = 0) -> dict:
    focus_guidance = BASELINE_AGENT_GUIDANCE.get(stage_num)
    if not focus_guidance:
        spec_label = STAGE_SPECS.get(stage_num, f"Stage {stage_num}")
        evidence_text = f"静态证据 {evidence} 条，" if evidence > 0 else ""
        focus_guidance = (
            f"Supervisor 规划响应被截断，已根据{evidence_text}阶段主题补入该 Agent。"
            f"请聚焦 {spec_label}，只输出有明确代码证据、入口和可复现条件的结论。"
        )
    return {
        "stage_num": stage_num,
        "priority": 0,
        "focus_guidance": focus_guidance,
        "focus_files": [],
        "focus_routes": [],
        "_recovered_agent": True,
        "_recovery_reason": reason,
    }


def _agent_plan_available_slots(selected: list[dict], max_agents: int | None) -> int:
    if not max_agents:
        return 100
    selected_stage_nums = {_safe_int(item.get("stage_num")) for item in selected if isinstance(item, dict)}
    missing_baseline_count = sum(1 for stage_num in BASELINE_AGENT_GUIDANCE if stage_num not in selected_stage_nums)
    return max(0, int(max_agents) - len(selected) - missing_baseline_count)


def _append_agent_if_budget(
    selected: list[dict],
    stage_num: int,
    *,
    max_agents: int | None,
    reason: str,
    evidence: int = 0,
) -> None:
    if stage_num < 2 or stage_num > 9:
        return
    selected_stage_nums = {_safe_int(item.get("stage_num")) for item in selected if isinstance(item, dict)}
    if stage_num in selected_stage_nums:
        return
    if stage_num not in BASELINE_AGENT_GUIDANCE and _agent_plan_available_slots(selected, max_agents) <= 0:
        return
    selected.append(_minimal_agent_spec(stage_num, reason=reason, evidence=evidence))


def _augment_salvaged_plan_with_evidence(
    agent_plan: dict,
    raw: str,
    rule_hits: list,
    source_sink_hints: list,
    max_agents: int | None = None,
) -> dict:
    normalized = dict(agent_plan) if isinstance(agent_plan, dict) else {}
    selected = [dict(item) for item in normalized.get("selected_agents", []) if isinstance(item, dict)]
    stage_evidence = _build_stage_evidence_scores(rule_hits, source_sink_hints)

    recovered_stage_nums: list[int] = []
    for stage_num in _extract_json_array_stage_nums(str(raw or ""), "selected_agents"):
        before = len(selected)
        _append_agent_if_budget(
            selected,
            stage_num,
            max_agents=max_agents,
            reason="partial_selected_agents_fragment",
            evidence=stage_evidence.get(stage_num, 0),
        )
        if len(selected) > before:
            recovered_stage_nums.append(stage_num)

    for stage_num in _select_fallback_stage_nums(stage_evidence, max_agents=max_agents):
        if _agent_plan_available_slots(selected, max_agents) <= 0:
            break
        _append_agent_if_budget(
            selected,
            stage_num,
            max_agents=max_agents,
            reason="static_evidence_backfill",
            evidence=stage_evidence.get(stage_num, 0),
        )

    for index, item in enumerate(selected, start=1):
        item["priority"] = index

    normalized["selected_agents"] = selected
    if recovered_stage_nums:
        normalized["_salvaged_partial_stage_nums"] = recovered_stage_nums
    return normalized


def _salvage_supervisor_plan(raw: str, rule_hits: list | None = None, source_sink_hints: list | None = None, max_agents: int | None = None) -> dict | None:
    text = str(raw or "").strip().replace("\ufeff", "").replace("\u200b", "")
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    selected_agents = _normalize_agent_specs(_extract_json_array_objects(text, "selected_agents"))
    if not selected_agents:
        return None

    skipped_agents = _normalize_agent_specs(_extract_json_array_objects(text, "skipped_agents"))
    plan = {
        "analysis_summary": _extract_json_string_field(text, "analysis_summary"),
        "selected_agents": selected_agents,
        "skipped_agents": skipped_agents,
        "_salvaged": True,
        "_salvage_reason": "planning_response_truncated",
    }
    return _augment_salvaged_plan_with_evidence(plan, raw, rule_hits or [], source_sink_hints or [], max_agents=max_agents)


BASELINE_AGENT_GUIDANCE = {
    2: "RCE 与危险执行是基线审计阶段。即使规则命中较少，也要抽查命令执行、脚本执行、模板执行、反序列化、插件/告警规则执行、表达式求值和外部进程调用链，确认是否存在用户可控输入进入危险执行点。",
    7: "配置与依赖安全是基线审计阶段。即使规则命中较少，也要检查配置文件、环境变量模板、默认密钥、调试开关、CORS、部署文件和依赖清单，确认是否存在可由本项目暴露面触发的风险。",
    9: "业务逻辑安全是基线审计阶段。即使规则命中较少，也要围绕状态变更、导入导出、创建/删除/更新、审批/订阅/通知等接口检查服务端约束、幂等性和越权业务流程。",
}


def _trim_agent_plan_to_budget(selected: list[dict], skipped: list[dict], max_agents: int | None) -> tuple[list[dict], list[dict]]:
    if not max_agents or len(selected) <= int(max_agents):
        return selected, skipped

    required_stage_nums = {
        _safe_int(item.get("stage_num"))
        for item in selected
        if _safe_int(item.get("stage_num")) in BASELINE_AGENT_GUIDANCE
    }
    non_baseline_slots = max(0, int(max_agents) - len(required_stage_nums))
    non_baseline_candidates = [
        item for item in selected
        if _safe_int(item.get("stage_num")) not in BASELINE_AGENT_GUIDANCE
    ]
    non_baseline_candidates.sort(
        key=lambda item: (
            -_safe_int(item.get("evidence")),
            _safe_int(item.get("priority"), 999),
            _safe_int(item.get("stage_num")),
        )
    )
    kept_non_baseline: set[int] = set()
    for item in non_baseline_candidates:
        stage_num = _safe_int(item.get("stage_num"))
        if stage_num in kept_non_baseline:
            continue
        if len(kept_non_baseline) >= non_baseline_slots:
            continue
        kept_non_baseline.add(stage_num)

    keep_stage_nums = required_stage_nums | kept_non_baseline
    trimmed: list[dict] = []
    for item in selected:
        stage_num = _safe_int(item.get("stage_num"))
        if stage_num in keep_stage_nums:
            trimmed.append(item)
            continue
        skipped_item = dict(item)
        skipped_item["skip_reason"] = (
            f"Skipped by agent budget after baseline stage enforcement "
            f"(max_agents={int(max_agents)}, baseline={sorted(BASELINE_AGENT_GUIDANCE)})"
        )
        skipped_item["_budget_trimmed"] = True
        skipped.append(skipped_item)

    return trimmed, skipped


def _ensure_baseline_agents(agent_plan: dict, max_agents: int | None = None) -> dict:
    """Force baseline stages that are easy to miss in evidence-driven planning."""
    normalized = dict(agent_plan) if isinstance(agent_plan, dict) else {}
    selected = [dict(item) for item in normalized.get("selected_agents", []) if isinstance(item, dict)]
    skipped = [dict(item) for item in normalized.get("skipped_agents", []) if isinstance(item, dict)]
    selected_stage_nums = {_safe_int(item.get("stage_num")) for item in selected}

    for stage_num, guidance in BASELINE_AGENT_GUIDANCE.items():
        if stage_num in selected_stage_nums:
            continue
        selected.append(
            {
                "stage_num": stage_num,
                "priority": len(selected) + 1,
                "focus_guidance": guidance,
                "focus_files": [],
                "focus_routes": [],
                "_baseline_required": True,
            }
        )
        selected_stage_nums.add(stage_num)

    skipped = [
        item
        for item in skipped
        if _safe_int(item.get("stage_num")) not in BASELINE_AGENT_GUIDANCE
    ]
    selected, skipped = _trim_agent_plan_to_budget(selected, skipped, max_agents)

    for index, item in enumerate(selected, start=1):
        item["priority"] = index

    normalized["selected_agents"] = selected
    normalized["skipped_agents"] = skipped
    return normalized


def _build_rerun_execution(stages: list[AuditStage], requested_stage_nums: list[int]) -> dict:
    requested = _normalize_rerun_stage_nums(requested_stage_nums)
    stage_map = {stage.stage_num: stage for stage in stages}
    executed_stage_nums: list[int] = []
    failed_stage_nums: list[int] = []
    stage_results: list[dict] = []

    for stage_num in requested:
        stage = stage_map.get(stage_num)
        if not stage:
            continue
        executed_stage_nums.append(stage_num)
        vuln_count = 0
        findings = _coerce_stage_findings(stage.findings)
        vulnerabilities = findings.get("vulnerabilities", [])
        if isinstance(vulnerabilities, list):
            vuln_count = len(vulnerabilities)
        if stage.status != "completed":
            failed_stage_nums.append(stage_num)
        stage_results.append(
            {
                "stage_num": stage_num,
                "status": stage.status,
                "vulnerability_count": vuln_count,
            }
        )

    return {
        "triggered": bool(requested),
        "requested_stage_nums": requested,
        "executed_stage_nums": executed_stage_nums,
        "failed_stage_nums": failed_stage_nums,
        "stage_results": stage_results,
    }


def _finalize_review_result(review: dict, stages: list[AuditStage]) -> dict:
    normalized = dict(review) if isinstance(review, dict) else {}
    normalized["request_rerun"] = bool(normalized.get("request_rerun"))
    normalized["rerun_agents"] = _normalize_rerun_stage_nums(normalized.get("rerun_agents"))

    findings_assessment = normalized.get("findings_assessment")
    if not isinstance(findings_assessment, dict):
        findings_assessment = {}
    questionable_count = max(0, _safe_int(findings_assessment.get("questionable_count"), 0))
    coverage_gaps = findings_assessment.get("coverage_gaps", [])
    if not isinstance(coverage_gaps, list):
        coverage_gaps = []
    findings_assessment["questionable_count"] = questionable_count
    findings_assessment["high_quality_count"] = max(0, _safe_int(findings_assessment.get("high_quality_count"), 0))
    findings_assessment["coverage_gaps"] = [str(item).strip() for item in coverage_gaps if str(item).strip()][:12]
    normalized["findings_assessment"] = findings_assessment

    rerun_execution = normalized.get("rerun_execution")
    if isinstance(rerun_execution, dict):
        requested_stage_nums = _normalize_rerun_stage_nums(rerun_execution.get("requested_stage_nums"))
        executed_stage_nums = _normalize_rerun_stage_nums(rerun_execution.get("executed_stage_nums"))
        failed_stage_nums = _normalize_rerun_stage_nums(rerun_execution.get("failed_stage_nums"))
        if not failed_stage_nums:
            stage_results = rerun_execution.get("stage_results", [])
            if isinstance(stage_results, list):
                failed_stage_nums = [
                    _safe_int(item.get("stage_num"))
                    for item in stage_results
                    if isinstance(item, dict) and str(item.get("status", "") or "").strip() != "completed"
                ]
                failed_stage_nums = [num for num in failed_stage_nums if 2 <= num <= 9]
        rerun_execution = {
            "triggered": bool(rerun_execution.get("triggered") or requested_stage_nums or executed_stage_nums),
            "requested_stage_nums": requested_stage_nums,
            "executed_stage_nums": executed_stage_nums,
            "failed_stage_nums": failed_stage_nums,
            "stage_results": rerun_execution.get("stage_results", []) if isinstance(rerun_execution.get("stage_results"), list) else [],
        }
        normalized["rerun_execution"] = rerun_execution
    else:
        rerun_execution = None

    closure_status = "accepted"
    next_action = "none"
    status_summary = "审核通过，无需重跑。"
    unresolved_stage_nums: list[int] = []

    if rerun_execution and rerun_execution.get("triggered"):
        requested = rerun_execution.get("requested_stage_nums", [])
        executed = rerun_execution.get("executed_stage_nums", [])
        failed = rerun_execution.get("failed_stage_nums", [])
        unresolved_stage_nums = normalized["rerun_agents"] or failed
        if failed:
            closure_status = "manual_followup_required"
            next_action = "manual_review"
            status_summary = f"已自动重跑 {', '.join(f'Stage {num}' for num in executed)}，但以下阶段仍执行失败：{', '.join(f'Stage {num}' for num in failed)}。"
        elif normalized["request_rerun"] and normalized["rerun_agents"]:
            closure_status = "manual_followup_required"
            next_action = "manual_review"
            status_summary = f"已自动重跑 {', '.join(f'Stage {num}' for num in executed)}，但复核后仍建议继续关注 {', '.join(f'Stage {num}' for num in normalized['rerun_agents'])}。"
        else:
            closure_status = "auto_rerun_resolved"
            next_action = "none"
            status_summary = f"已自动重跑 {', '.join(f'Stage {num}' for num in executed)}，复核后未再要求重跑。"
    elif normalized["request_rerun"] and normalized["rerun_agents"]:
        closure_status = "rerun_recommended"
        next_action = "rerun"
        unresolved_stage_nums = normalized["rerun_agents"]
        status_summary = f"审核建议重跑 {', '.join(f'Stage {num}' for num in normalized['rerun_agents'])}。"
    elif findings_assessment["coverage_gaps"] or questionable_count > 0:
        closure_status = "accepted_with_notes"
        next_action = "monitor"
        status_summary = "审核完成，但仍存在覆盖缺口或待人工关注项。"

    rerun_requested_stage_nums = (
        rerun_execution.get("requested_stage_nums", [])
        if rerun_execution
        else normalized["rerun_agents"]
    )
    normalized["review_closure"] = {
        "status": closure_status,
        "next_action": next_action,
        "status_summary": status_summary,
        "requested_stage_nums": rerun_requested_stage_nums,
        "executed_stage_nums": rerun_execution.get("executed_stage_nums", []) if rerun_execution else [],
        "failed_stage_nums": rerun_execution.get("failed_stage_nums", []) if rerun_execution else [],
        "unresolved_stage_nums": unresolved_stage_nums,
        "questionable_count": questionable_count,
        "coverage_gap_count": len(findings_assessment["coverage_gaps"]),
        "auto_handled": closure_status == "auto_rerun_resolved",
    }

    review_summary = str(normalized.get("review_summary", "") or "").strip()
    if status_summary and status_summary not in review_summary:
        normalized["review_summary"] = f"{status_summary}\n\n{review_summary}".strip() if review_summary else status_summary
    elif not review_summary:
        normalized["review_summary"] = status_summary

    additional_guidance = str(normalized.get("additional_guidance", "") or "").strip()
    if not additional_guidance:
        if closure_status == "manual_followup_required":
            normalized["additional_guidance"] = "自动重跑已完成，但仍有问题未收敛。请优先人工复核上述阶段的覆盖范围、证据链和 PoC 完整性。"
        elif closure_status == "accepted_with_notes":
            normalized["additional_guidance"] = "当前结果可以先使用；如果后续需要进一步降低漏报率，建议优先补扫上述覆盖缺口。"

    return normalized


async def _run_supervisor_review_closure(
    session,
    task,
    stages,
    llm_config,
    project,
    code_chunks,
    static_routes,
    rule_hits,
    source_sink_hints,
    agent_plan,
):
    audit_memory = _build_audit_memory(list(stages))
    await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_REVIEW_STARTED, payload={"role": "supervisor_review"}, stage_num=-2)
    review = await _run_supervisor_review(session, task, stages, llm_config, audit_memory, agent_plan)
    rerun_stage_nums = _normalize_rerun_stage_nums(review.get("rerun_agents"))
    if review.get("request_rerun") and rerun_stage_nums:
        await rt.emit_event(
            session,
            task_id=task.id,
            event_type=rt.EVENT_RERUN_REQUESTED,
            payload={"stage_nums": rerun_stage_nums, "role": "supervisor_review"},
            stage_num=-2,
        )
        # M5：重跑删除前快照已有复核状态，重插时 carry-forward（按 dedupe_key）
        _stash_review_state(task, await _snapshot_review_state(session, task.id))
        await _reset_agent_stages_for_rerun(session, task.id, stages, rerun_stage_nums)
        await rt.emit_event(
            session,
            task_id=task.id,
            event_type=rt.EVENT_STAGE_RESET_FOR_RERUN,
            payload={"stage_nums": rerun_stage_nums},
            stage_num=-2,
        )
        rerun_plan = {"selected_agents": [{"stage_num": stage_num} for stage_num in rerun_stage_nums], "skipped_agents": []}
        await _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, rerun_plan)
        stages = await _reload_task_stages(session, task.id)
        audit_memory = _build_audit_memory(list(stages))
        rerun_execution = _build_rerun_execution(stages, rerun_stage_nums)
        review = await _run_supervisor_review(
            session,
            task,
            stages,
            llm_config,
            audit_memory,
            agent_plan,
            extra_findings={"rerun_execution": rerun_execution},
        )
    await rt.emit_event(
        session,
        task_id=task.id,
        event_type=rt.EVENT_REVIEW_COMPLETED,
        payload={"request_rerun": bool(review.get("request_rerun")), "rerun_stage_nums": rerun_stage_nums},
        stage_num=-2,
    )
    return review, stages


async def _reset_agent_stages_for_rerun(session, task_id: int, stages: list[AuditStage], stage_nums: list[int]) -> None:
    """Reset target stages before rerun so completed stages are not skipped."""
    if not stage_nums:
        return

    target_stage_ids = []
    for stage in stages:
        if stage.stage_num not in stage_nums:
            continue
        stage.status = "pending"
        stage.findings = {"vulnerabilities": []}
        stage.prompt_used = ""
        stage.llm_response = ""
        stage.compressed_summary = {}
        stage.started_at = None
        stage.completed_at = None
        target_stage_ids.append(stage.id)

    if target_stage_ids:
        await session.execute(
            delete(Vulnerability).where(
                Vulnerability.task_id == task_id,
                Vulnerability.stage_id.in_(target_stage_ids),
            )
        )
    await session.commit()


async def _reload_task_stages(session, task_id: int) -> list[AuditStage]:
    await session.flush()
    result = await session.execute(
        select(AuditStage)
        .where(AuditStage.task_id == task_id)
        .order_by(AuditStage.stage_num)
        .execution_options(populate_existing=True)
    )
    return result.scalars().all()

from services.config import MAX_CONCURRENT_AGENTS


async def _load_audit_context(session, task_id: int):
    """Load task, config, project, stages, and cache. Returns None on failure."""
    result = await session.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        logger.error("Task %s not found", task_id)
        return None

    result = await session.execute(select(LlmConfig).where(LlmConfig.id == task.llm_config_id))
    llm_config = result.scalar_one_or_none()
    if not llm_config:
        task.status = "failed"
        task.error_message = "LLM config not found"
        await session.commit()
        return None

    result = await session.execute(select(Project).where(Project.id == task.project_id))
    project = result.scalar_one_or_none()
    if not project:
        task.status = "failed"
        task.error_message = "Project not found"
        await session.commit()
        return None

    result = await session.execute(
        select(AuditStage).where(AuditStage.task_id == task_id).order_by(AuditStage.stage_num)
    )
    stages = result.scalars().all()

    project_cache = get_or_build_project_cache(project.id, project.upload_path, project.file_tree or [])

    if await _is_task_stopping(session, task_id):
        return None

    scan_stats = project_cache.get("scan_stats", {})
    rule_hits = project_cache.get("rule_hits", [])  # ctx（L689）仍需；summary.rule_hits_preview 已移除（前端改读 project_rule_hits 表）
    pre_discovery = project_cache.get("pre_discovery")
    summary = dict(task.summary) if isinstance(task.summary, dict) else {}
    if isinstance(scan_stats, dict):
        summary["scan_stats"] = scan_stats
    pre_discovery_summary = _summarize_pre_discovery(pre_discovery)
    if pre_discovery_summary:
        summary["pre_discovery"] = pre_discovery_summary
    summary.pop("worker_failure", None)
    summary.pop("orchestration_guard", None)
    task.summary = summary
    task.status = "running"
    task.error_message = ""
    task.completed_at = None
    # M4b：把项目缓存里的 static_routes / rule_hits 影子写入结构化表（与本次状态变更同事务）。
    await sync_project_index(session, project.id, project_cache)
    await session.commit()

    return {
        "task": task,
        "llm_config": llm_config,
        "project": project,
        "stages": stages,
        "code_chunks": project_cache.get("code_chunks", []),
        "static_routes": project_cache.get("static_routes", []),
        "scan_stats": scan_stats,
        "rule_hits": rule_hits,
        "source_sink_hints": project_cache.get("source_sink_hints", []),
        "pre_discovery": pre_discovery,
    }


def _set_task_phase(task: AuditTask, phase_num: int) -> None:
    summary = dict(task.summary) if isinstance(task.summary, dict) else {}
    summary["current_phase"] = phase_num
    summary["multi_agent_phase_mode"] = True
    task.summary = summary


async def run_multi_agent_audit(task_id: int):
    """Run the full multi-agent audit flow."""
    async with async_session() as session:
        ctx = await _load_audit_context(session, task_id)
        if not ctx:
            return
        task = ctx["task"]
        llm_config = ctx["llm_config"]
        project = ctx["project"]
        stages = ctx["stages"]
        code_chunks = ctx["code_chunks"]
        static_routes = ctx["static_routes"]
        scan_stats = ctx["scan_stats"]
        rule_hits = ctx["rule_hits"]
        source_sink_hints = ctx["source_sink_hints"]
        pre_discovery = ctx["pre_discovery"]

        try:
            current_run = await rt.get_current_run(session, task_id)
            run_id = current_run.id if current_run else None
        except Exception:  # noqa: BLE001 - 事件流为辅助观测，不得阻断审计
            run_id = None

        try:

            # Phase 1: architecture agent (Stage 1)
            _set_task_phase(task, 1)
            await session.commit()
            await rt.emit_event(session, task_id=task_id, event_type=rt.EVENT_PHASE_CHANGED, payload={"phase": 1, "name": "architecture"}, run_id=run_id)
            await session.commit()
            await _run_phase1_architecture(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, pre_discovery)
            if await _is_task_stopping(session, task_id):
                return

            # Phase 2: supervisor planning
            _set_task_phase(task, 2)
            await session.commit()
            await rt.emit_event(session, task_id=task_id, event_type=rt.EVENT_PHASE_CHANGED, payload={"phase": 2, "name": "supervisor_plan"}, run_id=run_id)
            await session.commit()
            audit_memory = _build_audit_memory(list(stages))
            agent_plan = await _run_supervisor_planning(session, task, stages, llm_config, project, audit_memory, rule_hits, source_sink_hints)

            if await _is_task_stopping(session, task_id):
                return

            # Phase 3: sub-agents in parallel
            _set_task_phase(task, 3)
            await session.commit()
            await rt.emit_event(session, task_id=task_id, event_type=rt.EVENT_PHASE_CHANGED, payload={"phase": 3, "name": "sub_agents"}, run_id=run_id)
            await session.commit()
            await _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, agent_plan)
            stages = await _reload_task_stages(session, task.id)

            if await _is_task_stopping(session, task_id):
                return
            await _assert_sub_agent_phase_converged(session, task, agent_plan, stages)
            route_followup = await _run_missing_route_followup(
                session,
                task,
                stages,
                llm_config,
                project,
                code_chunks,
                static_routes,
                scan_stats,
                pre_discovery,
                source_sink_hints,
            )
            if route_followup.get("triggered"):
                stages = await _reload_task_stages(session, task.id)

            # Phase 4: supervisor review
            _set_task_phase(task, 4)
            await session.commit()
            await rt.emit_event(session, task_id=task_id, event_type=rt.EVENT_PHASE_CHANGED, payload={"phase": 4, "name": "supervisor_review"}, run_id=run_id)
            await session.commit()
            review, stages = await _run_supervisor_review_closure(
                session,
                task,
                stages,
                llm_config,
                project,
                code_chunks,
                static_routes,
                rule_hits,
                source_sink_hints,
                agent_plan,
            )

            if await _is_task_stopping(session, task_id):
                return

            task.status = "completed"
            task.current_stage = task.total_stages or 9
            task.completed_at = datetime.now(timezone.utc)
            await _refresh_task_summary(
                session,
                task,
                scan_stats=scan_stats,
                pre_discovery=pre_discovery,
                static_routes=static_routes,
            )
            if run_id:
                await rt.complete_run(session, run_id)
            await rt.emit_event(session, task_id=task_id, event_type=rt.EVENT_RUN_COMPLETED, payload={}, run_id=run_id)
            await session.commit()
            logger.info("Multi-agent task %s completed", task_id)
            _clear_stashed_review_state(task)

        except Exception as exc:
            logger.error("Multi-agent task %s failed: %s", task_id, exc)
            _add_task_degradation(
                task,
                "multi_agent_audit_failed",
                "审计主流程异常终止，任务已标记失败。",
                "audit",
            )
            failed_at = datetime.now(timezone.utc)
            task.status = "failed"
            task.error_message = str(exc)[:2000]
            task.completed_at = failed_at
            for stage in stages:
                if stage.status == "running":
                    stage.status = "failed"
                    stage.completed_at = failed_at
            if run_id:
                await rt.fail_run(session, run_id, str(exc)[:500])
            await rt.emit_event(
                session,
                task_id=task_id,
                event_type=rt.EVENT_RUN_FAILED,
                payload={"message": str(exc)[:500]},
                run_id=run_id,
            )
            await session.commit()
            _clear_stashed_review_state(task)


async def _run_phase1_architecture(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, pre_discovery=None):
    """Phase 1: run the architecture agent with multi-pass scanning."""
    stage_map = {s.stage_num: s for s in stages}
    stage = stage_map.get(1)
    if not stage or stage.status == "completed":
        return

    stage.status = "running"
    stage.started_at = datetime.now(timezone.utc)
    task.current_stage = 1
    await session.commit()
    await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_STAGE_STARTED, payload={"stage_name": "architecture"}, stage_num=1)
    subtask = await rt.start_subtask(session, task_id=task.id, stage_num=1, role="architecture")
    await session.commit()

    audit_memory = _build_audit_memory(list(stages), current_stage_num=1)
    prev_context = _build_prev_context(audit_memory)

    try:
        stage_payload = await _run_stage1_multi_pass(
            session=session, task=task, stage=stage, llm_config=llm_config, project=project,
            stage_prompt=get_stage_prompt(1),
            selected_chunks=_select_stage_chunks(1, code_chunks, static_routes=static_routes, audit_memory=audit_memory, source_sink_hints=source_sink_hints, pre_discovery=pre_discovery),
            code_chunks=code_chunks, static_routes=static_routes, prev_context=prev_context,
            audit_memory=audit_memory, rule_hits=rule_hits, source_sink_hints=source_sink_hints,
            pre_discovery=pre_discovery,
        )
        await _apply_stage_payload(stage, stage_payload, session=session, task=task, static_routes=static_routes, audit_memory=audit_memory)
        stage.status = "completed"
        await rt.complete_subtask(session, subtask.id if subtask else None)
        await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_STAGE_COMPLETED, payload={"stage_name": "architecture"}, stage_num=1)
    except Exception:
        stage.status = "failed"
        await rt.fail_subtask(session, subtask.id if subtask else None, "architecture 阶段失败")
        await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_STAGE_FAILED, payload={"stage_name": "architecture"}, stage_num=1)
        logger.exception("Phase 1 failed for task %s", task.id)
    stage.completed_at = datetime.now(timezone.utc)
    await session.commit()


async def _run_supervisor_planning(session, task, stages, llm_config, project, audit_memory, rule_hits, source_sink_hints):
    """Phase 2: run supervisor planning."""
    stage_map = {s.stage_num: s for s in stages}
    plan_stage = stage_map.get(-1)
    if not plan_stage:
        plan_stage = AuditStage(task_id=task.id, stage_num=-1, stage_name=SUPERVISOR_PLAN_STAGE_NAME, agent_role="supervisor_plan", status="pending")
        session.add(plan_stage)
        await session.commit()
        await session.refresh(plan_stage)

    plan_stage.status = "running"
    plan_stage.started_at = datetime.now(timezone.utc)
    await session.commit()
    await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_AGENT_STARTED, payload={"role": "supervisor_plan"}, stage_num=-1)
    subtask = await rt.start_subtask(session, task_id=task.id, stage_num=-1, role="supervisor_plan")
    await session.commit()

    # §10.3 确定性主导：先用证据驱动的确定性 planner 锁定「执行哪些阶段」（stage_num 集合 +
    # baseline 2/7/9 + 证据排期）。LLM 规划降级为「聚焦增强」——只为候选 stage 补 focus 字段，
    # 不增删 stage（which stages 由后端掌控，符合 §17.1「执行计划由后端决定，不让模型跳过
    # 必须执行的阶段」）。
    deterministic_plan = _build_default_plan(
        rule_hits,
        source_sink_hints,
        max_agents=FALLBACK_MAX_AGENT_COUNT,
    )
    deterministic_plan["_deterministic"] = True

    planning_context = _build_planning_context(
        project,
        audit_memory,
        rule_hits,
        source_sink_hints,
        candidate_agents=deterministic_plan.get("selected_agents", []),
    )
    user_prompt = SUPERVISOR_PLANNING_USER.format(**planning_context)

    try:
        result = await call_llm_with_meta(llm_config, SUPERVISOR_PLANNING_SYSTEM, user_prompt)
        _accumulate_token_usage(task, result.get("meta"))
        if not result["success"]:
            raise RuntimeError(f"Supervisor planning failed: {result['error']['message']}")

        llm_plan = _parse_structured_response(result["content"], result.get("meta"))
        if isinstance(llm_plan, dict) and llm_plan.get("parse_error"):
            salvaged_plan = _salvage_supervisor_plan(
                result["content"],
                rule_hits=rule_hits,
                source_sink_hints=source_sink_hints,
                max_agents=FALLBACK_MAX_AGENT_COUNT,
            )
            if salvaged_plan:
                _add_task_degradation(
                    task,
                    "supervisor_planning_salvaged",
                    "Supervisor 规划响应被截断，已恢复可用 focus 增强并合并到确定性计划。",
                    "planning",
                )
                llm_plan = salvaged_plan
            else:
                _add_task_degradation(
                    task,
                    "supervisor_planning_parse_error",
                    "Supervisor 规划响应解析失败，已使用纯确定性审计计划继续执行。",
                    "planning",
                )
                llm_plan = {}

        # §10.3 后端合并：确定性 plan 锁定 which stages，LLM 仅叠加 focus 字段到匹配 stage
        # （LLM 增删 stage 一律忽略）。
        agent_plan = _merge_plan_with_llm_focus(deterministic_plan, llm_plan)
        agent_plan = _ensure_baseline_agents(agent_plan, max_agents=FALLBACK_MAX_AGENT_COUNT)
        # §10.2 schema quality gate：校验 plan 结构。仅检测+记 note，不替换归一化
        # （执行型数据，须保留 priority/_baseline_required 等全部字段供 _execute_sub_agents 使用）。
        _validated, _err = validate_stage_output("plan", agent_plan)
        if _err:
            _add_task_degradation(task, "plan_output_schema_validation_failed", f"Supervisor 规划输出 schema 校验失败：{_err[:120]}", "planning")

        plan_stage.findings = agent_plan if isinstance(agent_plan, dict) else {"raw": str(agent_plan)[:5000]}
        plan_stage.llm_response = result["content"][:10000]
        plan_stage.status = "completed"
        plan_stage.completed_at = datetime.now(timezone.utc)
        await rt.complete_subtask(session, subtask.id if subtask else None)
        await _record_agent_meta(session, task.id, "supervisor_plan", result, stage_num=-1, error=None, subtask_id=subtask.id if subtask else None)
        await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_AGENT_COMPLETED, payload={"role": "supervisor_plan"}, stage_num=-1)

        summary = task.summary if isinstance(task.summary, dict) else {}
        summary["agent_plan"] = agent_plan if isinstance(agent_plan, dict) else {}
        task.summary = dict(summary)
        await session.commit()
        return agent_plan

    except Exception as exc:
        plan_stage.status = "failed"
        plan_stage.completed_at = datetime.now(timezone.utc)
        plan_stage.llm_response = str(exc)[:2000]
        await rt.fail_subtask(session, subtask.id if subtask else None, f"supervisor_plan 失败：{exc}"[:2000])
        await _record_agent_meta(session, task.id, "supervisor_plan", None, stage_num=-1, error=str(exc), subtask_id=subtask.id if subtask else None)
        await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_AGENT_FAILED, payload={"role": "supervisor_plan", "message": str(exc)[:300]}, stage_num=-1)
        _add_task_degradation(
            task,
            "supervisor_planning_failed",
            "Supervisor 规划失败，已使用纯确定性审计计划继续执行。",
            "planning",
        )
        await session.commit()
        logger.warning("Supervisor planning failed, using deterministic plan: %s", exc)
        # LLM 全失败 → 纯确定性 plan（已含 baseline + 证据排期），不依赖 LLM 的阶段取舍。
        fallback_plan = _ensure_baseline_agents(deterministic_plan, max_agents=FALLBACK_MAX_AGENT_COUNT)
        fallback_plan["_fallback"] = True
        fallback_plan["_fallback_reason"] = "planning_failed"
        return fallback_plan


async def _run_supervisor_review(session, task, stages, llm_config, audit_memory, agent_plan, extra_findings: dict | None = None):
    """Phase 4: run supervisor review."""
    stage_map = {s.stage_num: s for s in stages}
    review_stage = stage_map.get(-2)
    if not review_stage:
        review_stage = AuditStage(task_id=task.id, stage_num=-2, stage_name=SUPERVISOR_REVIEW_STAGE_NAME, agent_role="supervisor_review", status="pending")
        session.add(review_stage)
        await session.commit()
        await session.refresh(review_stage)

    review_stage.status = "running"
    review_stage.started_at = datetime.now(timezone.utc)
    await session.commit()
    await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_AGENT_STARTED, payload={"role": "supervisor_review"}, stage_num=-2)
    subtask = await rt.start_subtask(session, task_id=task.id, stage_num=-2, role="supervisor_review")
    await session.commit()

    review_context = _build_review_context(audit_memory, agent_plan, stages)
    user_prompt = SUPERVISOR_REVIEW_USER.format(**review_context)

    try:
        result = await call_llm_with_meta(llm_config, SUPERVISOR_REVIEW_SYSTEM, user_prompt)
        _accumulate_token_usage(task, result.get("meta"))
        if not result["success"]:
            raise RuntimeError(f"Supervisor review failed: {result['error']['message']}")

        review = _parse_structured_response(result["content"], result.get("meta"))
        if isinstance(review, dict) and review.get("parse_error"):
            _add_task_degradation(
                task,
                "supervisor_review_parse_error",
                "Supervisor 复核响应解析失败，已跳过自动重跑并保留已有结果。",
                "review",
            )
            review = {"review_summary": "审核响应解析失败，已跳过自动重跑。", "request_rerun": False, "rerun_agents": []}
        if isinstance(review, dict) and isinstance(extra_findings, dict):
            # Feed rerun execution back into the review payload for frontend visibility.
            review.update(extra_findings)
        review = _finalize_review_result(review if isinstance(review, dict) else {}, stages)
        if isinstance(review, dict):
            # §10.2 schema quality gate：校验 review 结构。仅检测+记 note，不替换归一化
            # （须保留 review_closure 等字段供 summary.review_outcome 与前端使用）。
            _validated, _err = validate_stage_output("review", review)
            if _err:
                _add_task_degradation(task, "review_output_schema_validation_failed", f"Supervisor 复核输出 schema 校验失败：{_err[:120]}", "review")
        review_stage.findings = review if isinstance(review, dict) else {"raw": str(review)[:5000]}
        review_stage.llm_response = result["content"][:10000]
        review_stage.status = "completed"
        review_stage.completed_at = datetime.now(timezone.utc)
        await rt.complete_subtask(session, subtask.id if subtask else None)
        await _record_agent_meta(session, task.id, "supervisor_review", result, stage_num=-2, error=None, subtask_id=subtask.id if subtask else None)
        await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_AGENT_COMPLETED, payload={"role": "supervisor_review"}, stage_num=-2)
        summary = dict(task.summary) if isinstance(task.summary, dict) else {}
        summary["review_outcome"] = review.get("review_closure", {}) if isinstance(review, dict) else {}
        task.summary = summary
        await session.commit()
        return review

    except Exception as exc:
        review_stage.status = "failed"
        review_stage.completed_at = datetime.now(timezone.utc)
        review_stage.llm_response = str(exc)[:2000]
        await rt.fail_subtask(session, subtask.id if subtask else None, f"supervisor_review 失败：{exc}"[:2000])
        await _record_agent_meta(session, task.id, "supervisor_review", None, stage_num=-2, error=str(exc), subtask_id=subtask.id if subtask else None)
        await rt.emit_event(session, task_id=task.id, event_type=rt.EVENT_AGENT_FAILED, payload={"role": "supervisor_review", "message": str(exc)[:300]}, stage_num=-2)
        _add_task_degradation(
            task,
            "supervisor_review_failed",
            "Supervisor 复核失败，任务结果需要人工关注。",
            "review",
        )
        summary = dict(task.summary) if isinstance(task.summary, dict) else {}
        summary["review_outcome"] = {
            "status": "review_failed",
            "next_action": "manual_review",
            "status_summary": "审核失败，需要人工复核。",
            "auto_handled": False,
        }
        task.summary = summary
        await session.commit()
        logger.warning("Supervisor review failed: %s", exc)
        return {"review_summary": "审核失败", "request_rerun": False, "rerun_agents": []}


async def _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, agent_plan):
    """Phase 3: execute selected sub-agents in parallel."""
    if not isinstance(agent_plan, dict):
        agent_plan = {}

    selected = agent_plan.get("selected_agents", [])
    if not selected:
        selected = _build_default_plan(rule_hits, source_sink_hints).get("selected_agents", [])

    normalized_selected: list[dict] = []
    seen_selected_stage_nums: set[int] = set()
    for spec in selected:
        if not isinstance(spec, dict):
            continue
        try:
            stage_num = int(spec.get("stage_num", 0))
        except (TypeError, ValueError):
            continue
        if stage_num < 2 or stage_num > 9 or stage_num in seen_selected_stage_nums:
            continue
        normalized = dict(spec)
        normalized["stage_num"] = stage_num
        normalized_selected.append(normalized)
        seen_selected_stage_nums.add(stage_num)
    selected = normalized_selected
    if not selected:
        message = "Phase 3 did not receive any executable sub-agent stages from the planner."
        _add_task_degradation(
            task,
            "sub_agent_phase_empty_plan",
            "阶段三没有收到任何可执行的子 Agent 阶段，任务已停止以避免直接进入复核造成假完成。",
            "sub_agent",
        )
        await rt.emit_event(
            session,
            task_id=task.id,
            event_type=rt.EVENT_STAGE_FAILED,
            payload={"phase": "sub_agents", "message": message},
        )
        await session.commit()
        raise RuntimeError(message)

    stage_map = {s.stage_num: s for s in stages}
    missing_stage_nums = [
        int(spec["stage_num"])
        for spec in selected
        if int(spec["stage_num"]) not in stage_map
    ]
    for stage_num in missing_stage_nums:
        stage = AuditStage(
            task_id=task.id,
            stage_num=stage_num,
            stage_name=get_stage_name(stage_num),
            status="pending",
        )
        session.add(stage)
        stages.append(stage)
        stage_map[stage_num] = stage
        _add_task_degradation(
            task,
            f"sub_agent_stage_{stage_num}_record_recovered",
            f"阶段三执行前发现 Stage {stage_num} 记录缺失，已自动补齐后继续执行。",
            "sub_agent",
        )
    # Release any phase/event writes held by the parent session before child
    # agent sessions start concurrent SQLite writes.
    await session.commit()

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)

    async def run_one_agent(agent_spec: dict):
        stage_num = int(agent_spec.get("stage_num", 0))
        if stage_num < 2 or stage_num > 9:
            return {"stage_num": stage_num, "status": "ignored"}

        stage = stage_map.get(stage_num)
        if not stage:
            return {"stage_num": stage_num, "status": "missing_stage"}
        if stage.status == "completed":
            return {"stage_num": stage_num, "status": "already_completed"}

        async with semaphore:
            async with async_session() as agent_session:
                result = await agent_session.execute(
                    select(AuditTask).where(AuditTask.id == task.id)
                )
                agent_task = result.scalar_one_or_none()
                if not agent_task:
                    return {"stage_num": stage_num, "status": "missing_task"}

                result = await agent_session.execute(
                    select(AuditStage).where(
                        AuditStage.task_id == task.id,
                        AuditStage.stage_num == stage_num,
                    )
                )
                agent_stage = result.scalar_one_or_none()
                if not agent_stage:
                    agent_stage = AuditStage(
                        task_id=task.id,
                        stage_num=stage_num,
                        stage_name=get_stage_name(stage_num),
                        status="pending",
                    )
                    agent_session.add(agent_stage)
                    await agent_session.flush()
                if agent_stage.status == "completed":
                    return {"stage_num": stage_num, "status": "already_completed"}

                if await _is_task_stopping(agent_session, task.id):
                    return {"stage_num": stage_num, "status": "stopping"}

                agent_stage.agent_role = "sub_agent"
                agent_stage.status = "running"
                agent_stage.started_at = datetime.now(timezone.utc)
                await agent_session.commit()
                await rt.emit_event(agent_session, task_id=task.id, event_type=rt.EVENT_STAGE_STARTED, payload={"role": "sub_agent"}, stage_num=stage_num)
                subtask = await rt.start_subtask(agent_session, task_id=task.id, stage_num=stage_num, role="sub_agent")
                await agent_session.commit()

                audit_memory = _build_audit_memory(list(stages), current_stage_num=stage_num)
                prev_context = _build_prev_context(audit_memory)

                focus_guidance = str(agent_spec.get("focus_guidance", "")).strip()
                focus_files = agent_spec.get("focus_files", []) or []
                focus_routes = agent_spec.get("focus_routes", []) or []
                focus_functions = agent_spec.get("focus_functions", []) or []
                focus_data_flows = agent_spec.get("focus_data_flows", []) or []
                supervisor_focus = ""
                if focus_guidance or focus_files or focus_routes or focus_functions or focus_data_flows:
                    flow_text = ""
                    if focus_data_flows:
                        flow_text = "\nKey data flows: " + "; ".join(str(f) for f in focus_data_flows[:5])
                    func_text = ""
                    if focus_functions:
                        func_text = "\nKey functions: " + ", ".join(str(f) for f in focus_functions[:12])
                    supervisor_focus = AGENT_FOCUS_PREFIX.format(
                        focus_guidance=(focus_guidance or "No extra guidance") + flow_text,
                        focus_files=", ".join(str(f) for f in focus_files[:10]) or "None",
                        focus_routes=", ".join(str(r) for r in focus_routes[:10]) or "None",
                    ) + func_text

                selected_chunks = _select_stage_chunks(
                    stage_num, code_chunks, static_routes=static_routes,
                    audit_memory=audit_memory, source_sink_hints=source_sink_hints,
                    focus_files=focus_files, focus_functions=focus_functions,
                )
                agent_started = datetime.now(timezone.utc)
                try:
                    stage_payload = await _run_single_pass_stage(
                        agent_session, agent_task, agent_stage, llm_config, project,
                        get_stage_prompt(stage_num), selected_chunks,
                        code_chunks, static_routes, prev_context, audit_memory,
                        rule_hits, source_sink_hints,
                        supervisor_focus=supervisor_focus if supervisor_focus else None,
                        forced_routes=focus_routes if isinstance(focus_routes, list) else None,
                    )
                    await _apply_stage_payload(agent_stage, stage_payload, session=agent_session, task=agent_task, static_routes=static_routes, audit_memory=audit_memory)
                    agent_stage.status = "completed"
                    await rt.complete_subtask(agent_session, subtask.id if subtask else None)
                    await rt.record_agent_run(
                        agent_session,
                        task_id=task.id,
                        agent_role="sub_agent",
                        status="completed",
                        stage_num=stage_num,
                        subtask_id=subtask.id if subtask else None,
                        latency_ms=int((datetime.now(timezone.utc) - agent_started).total_seconds() * 1000),
                        started_at=agent_started,
                        completed_at=datetime.now(timezone.utc),
                    )
                    await rt.emit_event(agent_session, task_id=task.id, event_type=rt.EVENT_STAGE_COMPLETED, payload={"role": "sub_agent"}, stage_num=stage_num)
                    result_status = "completed"
                except Exception as exc:
                    agent_stage.status = "failed"
                    await rt.fail_subtask(agent_session, subtask.id if subtask else None, f"sub_agent Stage {stage_num} 失败：{exc}"[:2000])
                    await rt.record_agent_run(
                        agent_session,
                        task_id=task.id,
                        agent_role="sub_agent",
                        status="failed",
                        stage_num=stage_num,
                        subtask_id=subtask.id if subtask else None,
                        latency_ms=int((datetime.now(timezone.utc) - agent_started).total_seconds() * 1000),
                        error_message=str(exc),
                        started_at=agent_started,
                        completed_at=datetime.now(timezone.utc),
                    )
                    await rt.emit_event(agent_session, task_id=task.id, event_type=rt.EVENT_STAGE_FAILED, payload={"role": "sub_agent", "message": str(exc)[:300]}, stage_num=stage_num)
                    _add_task_degradation(
                        agent_task,
                        f"sub_agent_stage_{stage_num}_failed",
                        f"子 Agent Stage {stage_num} 执行失败，已保留该阶段失败状态并阻止进入复核。",
                        "sub_agent",
                    )
                    logger.exception("Sub-agent stage %s failed for task %s", stage_num, task.id)
                    result_status = "failed"
                agent_stage.completed_at = datetime.now(timezone.utc)
                await agent_session.commit()
                logger.info("Task %s sub-agent stage %s completed", task.id, stage_num)
                return {"stage_num": stage_num, "status": result_status}

    tasks = [run_one_agent(spec) for spec in selected]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    unexpected_errors = [result for result in results if isinstance(result, Exception)]
    if unexpected_errors:
        message = f"Phase 3 sub-agent scheduling failed before execution: {unexpected_errors[0]}"
        _add_task_degradation(
            task,
            "sub_agent_phase_scheduling_failed",
            "阶段三子 Agent 调度在进入实际审计前失败，任务已停止以避免直接进入复核造成假完成。",
            "sub_agent",
        )
        await rt.emit_event(
            session,
            task_id=task.id,
            event_type=rt.EVENT_STAGE_FAILED,
            payload={"phase": "sub_agents", "message": str(unexpected_errors[0])[:500]},
        )
        await session.commit()
        raise RuntimeError(message)

    outcome_by_stage = {
        int(result.get("stage_num")): str(result.get("status") or "")
        for result in results
        if isinstance(result, dict) and result.get("stage_num") is not None
    }

    for s in stages:
        await session.refresh(s)
    await session.refresh(task)

    if await _is_task_stopping(session, task.id):
        return

    planned_stage_nums = [int(spec["stage_num"]) for spec in selected]
    executed_stage_nums = [
        stage.stage_num
        for stage in stages
        if stage.stage_num in planned_stage_nums and stage.status in {"completed", "failed", "running"}
    ]
    already_completed_stage_nums = [
        stage_num
        for stage_num in planned_stage_nums
        if outcome_by_stage.get(stage_num) == "already_completed"
    ]
    if planned_stage_nums and not executed_stage_nums and len(already_completed_stage_nums) != len(planned_stage_nums):
        message = (
            "Phase 3 did not start any planned sub-agent stages. "
            f"planned={planned_stage_nums}, outcomes={outcome_by_stage}"
        )
        _add_task_degradation(
            task,
            "sub_agent_phase_not_started",
            "阶段三没有任何子 Agent 真正启动，任务已停止以避免直接进入复核造成假完成。",
            "sub_agent",
        )
        await rt.emit_event(
            session,
            task_id=task.id,
            event_type=rt.EVENT_STAGE_FAILED,
            payload={"phase": "sub_agents", "planned_stage_nums": planned_stage_nums, "outcomes": outcome_by_stage},
        )
        await session.commit()
        raise RuntimeError(message)

    for stage in stages:
        if 2 <= stage.stage_num <= 9 and stage.status == "failed":
            _add_task_degradation(
                task,
                f"sub_agent_stage_{stage.stage_num}_failed",
                f"子 Agent Stage {stage.stage_num} 执行失败，已保留该阶段失败状态并阻止进入复核。",
                "sub_agent",
            )

    skipped = agent_plan.get("skipped_agents", [])
    for skip_spec in skipped:
        stage_num = int(skip_spec.get("stage_num", 0))
        stage = stage_map.get(stage_num)
        if stage and stage.status == "pending":
            stage.status = "skipped"
            stage.agent_role = "skipped_sub_agent"
            stage.findings = {"skipped": True, "skip_reason": skip_spec.get("skip_reason", "")}
            await rt.emit_event(
                session,
                task_id=task.id,
                event_type=rt.EVENT_STAGE_SKIPPED,
                payload={"role": "sub_agent", "reason": skip_spec.get("skip_reason", "")},
                stage_num=stage_num,
            )
            await rt.start_subtask(
                session,
                task_id=task.id,
                stage_num=stage_num,
                role="sub_agent",
                status="skipped",
                reason=str(skip_spec.get("skip_reason", "")),
            )
    await session.commit()


def _build_planning_context(project, audit_memory: dict, rule_hits: list, source_sink_hints: list, candidate_agents: list | None = None) -> dict:
    """Build the supervisor planning prompt context.

    §10.3：``candidate_agents`` 是后端确定性 planner 已选定的候选阶段（``_build_default_plan``
    产出），喂给 LLM 作为「必须为其补充聚焦信息」的阶段清单——LLM 不再自由决定执行哪些阶段。
    """
    arch_info = audit_memory.get("architecture_info", {}) if isinstance(audit_memory, dict) else {}
    if not isinstance(arch_info, dict):
        arch_info = {}

    routes = audit_memory.get("route_inventory", []) if isinstance(audit_memory, dict) else []
    entry_points = audit_memory.get("entry_points", []) if isinstance(audit_memory, dict) else []
    evidence_files = audit_memory.get("evidence_files", []) if isinstance(audit_memory, dict) else []

    rule_hits_summary = _summarize_rule_hits(rule_hits)
    source_sink_summary = _summarize_source_sink_hints(source_sink_hints)

    agent_specs_lines = []
    for stage_num in range(2, 10):
        spec = STAGE_SPECS.get(stage_num, f"Stage {stage_num}")
        hit_count = len([h for h in rule_hits if isinstance(h, dict) and stage_num in (h.get("stage_nums") or [])])
        hint_count = len([h for h in source_sink_hints if isinstance(h, dict) and stage_num in (h.get("stage_nums") or [])])
        agent_specs_lines.append(f"- Stage {stage_num}: {spec} (rule hits={hit_count}, source-sink hints={hint_count})")

    # §10.3 候选阶段清单：后端已选定，LLM 只为其补 focus。
    candidate_lines = []
    for agent in candidate_agents or []:
        if not isinstance(agent, dict):
            continue
        stage_num = _safe_int(agent.get("stage_num"))
        spec = STAGE_SPECS.get(stage_num, f"Stage {stage_num}")
        guidance = str(agent.get("focus_guidance") or "")[:200]
        files = agent.get("focus_files") or []
        files_str = ", ".join(str(f) for f in files[:5]) if isinstance(files, list) else ""
        candidate_lines.append(f"- Stage {stage_num}（{spec}）：证据已命中，必须执行。默认聚焦：{guidance}；参考文件：{files_str}")
    candidate_stages = "\n".join(candidate_lines) if candidate_lines else "（无候选阶段，将由 baseline 兜底）"

    return {
        "tech_stack": getattr(project, "tech_stack", "") or "Unknown",
        "file_count": len(evidence_files),
        "route_count": len(routes),
        "entry_point_count": len(entry_points),
        "architecture_summary": json.dumps(arch_info, ensure_ascii=False)[:4000] if arch_info else "None",
        "rule_hits_summary": rule_hits_summary,
        "source_sink_summary": source_sink_summary,
        "agent_specs": "\n".join(agent_specs_lines),
        "candidate_stages": candidate_stages,
    }


def _build_route_key(method: str, path: str) -> tuple[str, str] | None:
    normalized_method = str(method or "UNKNOWN").strip().upper() or "UNKNOWN"
    normalized_path = str(path or "").strip()
    if not normalized_path:
        return None
    return normalized_method, normalized_path


def _build_uncovered_route_summary(audit_memory: dict, stages) -> str:
    if not isinstance(audit_memory, dict):
        return "No route inventory"

    inventory = audit_memory.get("route_inventory", [])
    if not isinstance(inventory, list) or not inventory:
        return "No route inventory"

    covered_route_keys: set[tuple[str, str]] = set()
    audited_inventory = audit_memory.get("audited_route_inventory", [])
    if isinstance(audited_inventory, list):
        for route in audited_inventory:
            if not isinstance(route, dict):
                continue
            route_key = _build_route_key(route.get("method", "UNKNOWN"), route.get("path", ""))
            if route_key:
                covered_route_keys.add(route_key)

    for stage in stages:
        findings = _coerce_stage_findings(stage.findings)
        vulns = findings.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            endpoint = str(vuln.get("endpoint", "") or "").strip()
            if not endpoint:
                continue
            if " " in endpoint:
                method, path = endpoint.split(" ", 1)
            else:
                method, path = "UNKNOWN", endpoint
            route_key = _build_route_key(method, path)
            if route_key:
                covered_route_keys.add(route_key)

    uncovered = []
    for route in inventory:
        if not isinstance(route, dict):
            continue
        route_key = _build_route_key(route.get("method", "UNKNOWN"), route.get("path", ""))
        if route_key and route_key not in covered_route_keys:
            uncovered.append(route)

    if not uncovered:
        return "No uncovered routes found"

    samples = [
        f"{str(route.get('method', 'UNKNOWN')).upper()} {route.get('path', '')}"
        for route in uncovered[:12]
        if isinstance(route, dict)
    ]
    return f"{len(uncovered)} uncovered routes: {'; ' .join(samples)}"


def _build_review_context(audit_memory: dict, agent_plan: dict, stages) -> dict:
    """Build the supervisor review prompt context."""
    stage_summaries = []
    executed = []
    total_vulns = 0
    severity_dist = {sev: 0 for sev in SEVERITY_ORDER}

    for stage in stages:
        findings = _coerce_stage_findings(stage.findings)
        vulns = findings.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            continue
        count = len(vulns)
        if count > 0 or stage.status == "completed":
            executed.append(f"Stage {stage.stage_num}")
            total_vulns += count
            for v in vulns:
                sev = v.get("severity", "") if isinstance(v, dict) else ""
                if sev in severity_dist:
                    severity_dist[sev] += 1
            stage_summaries.append(
                f"Stage {stage.stage_num} ({stage.stage_name}): {count} findings"
            )

    uncovered_routes = _build_uncovered_route_summary(audit_memory, stages)
    return {
        "executed_agents": ", ".join(executed) or "None",
        "total_vulns": total_vulns,
        "severity_distribution": ", ".join(f"{k}:{v}" for k, v in severity_dist.items()),
        "agent_results_summary": "\n".join(stage_summaries) or "No results",
        "uncovered_routes": uncovered_routes,
        "original_plan": json.dumps(agent_plan, ensure_ascii=False)[:2000] if isinstance(agent_plan, dict) else "None",
    }


def _summarize_rule_hits(rule_hits: list) -> str:
    """Summarize rule hits by stage."""
    if not rule_hits:
        return "No rule hits"
    by_stage: dict[int, list] = {}
    for hit in rule_hits:
        if not isinstance(hit, dict):
            continue
        for sn in (hit.get("stage_nums") or []):
            by_stage.setdefault(int(sn), []).append(hit)
    lines = []
    for stage_num in sorted(by_stage.keys()):
        hits = by_stage[stage_num]
        sample_files = list({str(h.get("file_path", "")) for h in hits[:5]})[:3]
        lines.append(f"Stage {stage_num}: {len(hits)} hits; sample files: {', ' .join(sample_files)}")
    return "\n".join(lines) if lines else "No rule hits"


def _summarize_source_sink_hints(hints: list) -> str:
    """Summarize source-sink hints by stage."""
    if not hints:
        return "No source-sink hints"
    by_stage: dict[int, list] = {}
    for hint in hints:
        if not isinstance(hint, dict):
            continue
        for sn in (hint.get("stage_nums") or []):
            by_stage.setdefault(int(sn), []).append(hint)
    lines = []
    for stage_num in sorted(by_stage.keys()):
        count = len(by_stage[stage_num])
        lines.append(f"Stage {stage_num}: {count} hints")
    return "\n".join(lines) if lines else "No source-sink hints"


def _build_stage_evidence_scores(rule_hits: list, source_sink_hints: list) -> dict[int, int]:
    stage_evidence: dict[int, int] = {}
    for hit in rule_hits:
        if not isinstance(hit, dict):
            continue
        for sn in (hit.get("stage_nums") or []):
            stage_evidence[int(sn)] = stage_evidence.get(int(sn), 0) + 1
    for hint in source_sink_hints:
        if not isinstance(hint, dict):
            continue
        for sn in (hint.get("stage_nums") or []):
            stage_evidence[int(sn)] = stage_evidence.get(int(sn), 0) + 1
    return stage_evidence


def _select_fallback_stage_nums(stage_evidence: dict[int, int], max_agents: int | None = None) -> list[int]:
    candidates = [
        stage_num
        for stage_num in range(2, 10)
        if stage_evidence.get(stage_num, 0) > 0 or stage_num in BASELINE_AGENT_GUIDANCE
    ]
    if not candidates:
        candidates = list(range(2, 10))

    if max_agents and len(candidates) > max_agents:
        required = [stage_num for stage_num in BASELINE_AGENT_GUIDANCE if stage_num in candidates]
        slots = max(0, int(max_agents) - len(required))
        ranked = sorted(
            [stage_num for stage_num in candidates if stage_num not in required],
            key=lambda stage_num: (-stage_evidence.get(stage_num, 0), stage_num),
        )
        selected_set = set(required + ranked[:slots])
        candidates = [stage_num for stage_num in range(2, 10) if stage_num in selected_set]

    return candidates


def _build_default_plan(rule_hits: list, source_sink_hints: list, max_agents: int | None = None) -> dict:
    """Build a fallback agent plan from static evidence counts."""
    stage_evidence = _build_stage_evidence_scores(rule_hits, source_sink_hints)

    if not any(stage_evidence.values()):
        stage_nums = _select_fallback_stage_nums(stage_evidence, max_agents=max_agents)
        selected = [
            {
                "stage_num": sn,
                "priority": i + 1,
                "evidence": stage_evidence.get(sn, 0),
                "focus_guidance": BASELINE_AGENT_GUIDANCE.get(sn, ""),
                "focus_files": [],
                "focus_routes": [],
                **({"_baseline_required": True} if sn in BASELINE_AGENT_GUIDANCE else {}),
            }
            for i, sn in enumerate(stage_nums)
        ]
        skipped = [
            {"stage_num": sn, "skip_reason": "Skipped by fallback agent budget"}
            for sn in range(2, 10)
            if sn not in stage_nums
        ]
        return _ensure_baseline_agents({"selected_agents": selected, "skipped_agents": skipped}, max_agents=max_agents)

    selected = []
    skipped = []
    selected_stage_nums = set(_select_fallback_stage_nums(stage_evidence, max_agents=max_agents))
    for stage_num in range(2, 10):
        evidence = stage_evidence.get(stage_num, 0)
        if stage_num in selected_stage_nums:
            selected.append({
                "stage_num": stage_num,
                "priority": len(selected) + 1,
                "evidence": evidence,
                "focus_guidance": (
                    f"Audit based on {evidence} static evidence signals"
                    if evidence > 0
                    else BASELINE_AGENT_GUIDANCE[stage_num]
                ),
                "focus_files": [],
                "focus_routes": [],
                **({"_baseline_required": True} if stage_num in BASELINE_AGENT_GUIDANCE and evidence <= 0 else {}),
            })
        else:
            skip_reason = "Skipped by fallback agent budget" if evidence > 0 else "No supporting static evidence"
            skipped.append({"stage_num": stage_num, "skip_reason": skip_reason})

    return _ensure_baseline_agents({"selected_agents": selected, "skipped_agents": skipped}, max_agents=max_agents)
