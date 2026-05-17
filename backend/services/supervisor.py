"""Supervisor multi-agent audit orchestrator."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import delete, select

from database import async_session
from models import AuditStage, AuditTask, LlmConfig, Project, Vulnerability
from prompts.stage_prompts import get_stage_prompt, STAGE_SPECS
from prompts.supervisor_prompts import (
    SUPERVISOR_PLANNING_SYSTEM,
    SUPERVISOR_PLANNING_USER,
    SUPERVISOR_REVIEW_SYSTEM,
    SUPERVISOR_REVIEW_USER,
    AGENT_FOCUS_PREFIX,
)
from services.code_parser import get_or_build_project_cache
from services.llm_client import call_llm_with_meta
from services.audit_engine import (
    _accumulate_token_usage,
    _apply_stage_payload,
    _build_audit_memory,
    _build_prev_context,
    _get_stage_retry_policy,
    _is_task_cancelled,
    _merge_stage1_routes,
    _refresh_task_summary,
    _run_single_pass_stage,
    _run_stage1_multi_pass,
    _select_stage_chunks,
    _store_vulnerabilities,
    _parse_structured_response,
    _enforce_vulnerability_output_policy,
    _hydrate_vulnerability_endpoints,
    _build_stage_artifact_path,
)

logger = logging.getLogger(__name__)


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
        findings = stage.findings if isinstance(stage.findings, dict) else {}
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

    normalized["review_closure"] = {
        "status": closure_status,
        "next_action": next_action,
        "status_summary": status_summary,
        "requested_stage_nums": normalized["rerun_agents"],
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
    review = await _run_supervisor_review(session, task, stages, llm_config, audit_memory, agent_plan)
    rerun_stage_nums = _normalize_rerun_stage_nums(review.get("rerun_agents"))
    if review.get("request_rerun") and rerun_stage_nums:
        await _reset_agent_stages_for_rerun(session, task.id, stages, rerun_stage_nums)
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
        stage.findings = []
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
    result = await session.execute(
        select(AuditStage).where(AuditStage.task_id == task_id).order_by(AuditStage.stage_num)
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

    if await _is_task_cancelled(session, task_id):
        return None

    task.status = "running"
    task.error_message = ""
    task.completed_at = None
    await session.commit()

    return {
        "task": task,
        "llm_config": llm_config,
        "project": project,
        "stages": stages,
        "code_chunks": project_cache.get("code_chunks", []),
        "static_routes": project_cache.get("static_routes", []),
        "scan_stats": project_cache.get("scan_stats", {}),
        "rule_hits": project_cache.get("rule_hits", []),
        "source_sink_hints": project_cache.get("source_sink_hints", []),
        "pre_discovery": project_cache.get("pre_discovery"),
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
            # Phase 1: architecture agent (Stage 1)
            _set_task_phase(task, 1)
            await session.commit()
            await _run_phase1_architecture(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, pre_discovery)
            if await _is_task_cancelled(session, task_id):
                return

            # Phase 2: supervisor planning
            _set_task_phase(task, 2)
            await session.commit()
            audit_memory = _build_audit_memory(list(stages))
            agent_plan = await _run_supervisor_planning(session, task, stages, llm_config, project, audit_memory, rule_hits, source_sink_hints)

            if await _is_task_cancelled(session, task_id):
                return

            # Phase 3: sub-agents in parallel
            _set_task_phase(task, 3)
            await session.commit()
            await _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, agent_plan)
            stages = await _reload_task_stages(session, task.id)

            if await _is_task_cancelled(session, task_id):
                return

            # Phase 4: supervisor review
            _set_task_phase(task, 4)
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

            if await _is_task_cancelled(session, task_id):
                return

            task.status = "completed"
            task.current_stage = 0
            task.completed_at = datetime.now(timezone.utc)
            await _refresh_task_summary(session, task, scan_stats=scan_stats, rule_hits=rule_hits)
            await session.commit()
            logger.info("Multi-agent task %s completed", task_id)

        except Exception as exc:
            logger.error("Multi-agent task %s failed: %s", task_id, exc)
            task.status = "failed"
            task.error_message = str(exc)[:2000]
            task.completed_at = datetime.now(timezone.utc)
            await session.commit()


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
    except Exception:
        stage.status = "failed"
        logger.exception("Phase 1 failed for task %s", task.id)
    stage.completed_at = datetime.now(timezone.utc)
    await session.commit()


async def _run_supervisor_planning(session, task, stages, llm_config, project, audit_memory, rule_hits, source_sink_hints):
    """Phase 2: run supervisor planning."""
    stage_map = {s.stage_num: s for s in stages}
    plan_stage = stage_map.get(-1)
    if not plan_stage:
        plan_stage = AuditStage(task_id=task.id, stage_num=-1, stage_name="审计规划", agent_role="supervisor_plan", status="pending")
        session.add(plan_stage)
        await session.commit()
        await session.refresh(plan_stage)

    plan_stage.status = "running"
    plan_stage.started_at = datetime.now(timezone.utc)
    await session.commit()

    planning_context = _build_planning_context(project, audit_memory, rule_hits, source_sink_hints)
    user_prompt = SUPERVISOR_PLANNING_USER.format(**planning_context)

    try:
        result = await call_llm_with_meta(llm_config, SUPERVISOR_PLANNING_SYSTEM, user_prompt)
        _accumulate_token_usage(task, result.get("meta"))
        if not result["success"]:
            raise RuntimeError(f"Supervisor planning failed: {result['error']['message']}")

        agent_plan = _parse_structured_response(result["content"], result.get("meta"))
        if isinstance(agent_plan, dict) and agent_plan.get("parse_error"):
            agent_plan = _build_default_plan(rule_hits, source_sink_hints)

        plan_stage.findings = agent_plan if isinstance(agent_plan, dict) else {"raw": str(agent_plan)[:5000]}
        plan_stage.llm_response = result["content"][:10000]
        plan_stage.status = "completed"
        plan_stage.completed_at = datetime.now(timezone.utc)

        summary = task.summary if isinstance(task.summary, dict) else {}
        summary["agent_plan"] = agent_plan if isinstance(agent_plan, dict) else {}
        task.summary = dict(summary)
        await session.commit()
        return agent_plan

    except Exception as exc:
        plan_stage.status = "failed"
        plan_stage.completed_at = datetime.now(timezone.utc)
        plan_stage.llm_response = str(exc)[:2000]
        await session.commit()
        logger.warning("Supervisor planning failed, using default plan: %s", exc)
        return _build_default_plan(rule_hits, source_sink_hints)


async def _run_supervisor_review(session, task, stages, llm_config, audit_memory, agent_plan, extra_findings: dict | None = None):
    """Phase 4: run supervisor review."""
    stage_map = {s.stage_num: s for s in stages}
    review_stage = stage_map.get(-2)
    if not review_stage:
        review_stage = AuditStage(task_id=task.id, stage_num=-2, stage_name="审核复核", agent_role="supervisor_review", status="pending")
        session.add(review_stage)
        await session.commit()
        await session.refresh(review_stage)

    review_stage.status = "running"
    review_stage.started_at = datetime.now(timezone.utc)
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
            review = {"review_summary": "审核响应解析失败，已跳过自动重跑。", "request_rerun": False, "rerun_agents": []}
        if isinstance(review, dict) and isinstance(extra_findings, dict):
            # Feed rerun execution back into the review payload for frontend visibility.
            review.update(extra_findings)
        review = _finalize_review_result(review if isinstance(review, dict) else {}, stages)
        review_stage.findings = review if isinstance(review, dict) else {"raw": str(review)[:5000]}
        review_stage.llm_response = result["content"][:10000]
        review_stage.status = "completed"
        review_stage.completed_at = datetime.now(timezone.utc)
        summary = dict(task.summary) if isinstance(task.summary, dict) else {}
        summary["review_outcome"] = review.get("review_closure", {}) if isinstance(review, dict) else {}
        task.summary = summary
        await session.commit()
        return review

    except Exception as exc:
        review_stage.status = "failed"
        review_stage.completed_at = datetime.now(timezone.utc)
        review_stage.llm_response = str(exc)[:2000]
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

    stage_map = {s.stage_num: s for s in stages}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)

    async def run_one_agent(agent_spec: dict):
        stage_num = int(agent_spec.get("stage_num", 0))
        if stage_num < 2 or stage_num > 9:
            return

        stage = stage_map.get(stage_num)
        if not stage or stage.status == "completed":
            return

        async with semaphore:
            async with async_session() as agent_session:
                result = await agent_session.execute(
                    select(AuditTask).where(AuditTask.id == task.id)
                )
                agent_task = result.scalar_one_or_none()
                if not agent_task:
                    return

                result = await agent_session.execute(
                    select(AuditStage).where(
                        AuditStage.task_id == task.id,
                        AuditStage.stage_num == stage_num,
                    )
                )
                agent_stage = result.scalar_one_or_none()
                if not agent_stage or agent_stage.status == "completed":
                    return

                if await _is_task_cancelled(agent_session, task.id):
                    return

                agent_stage.agent_role = "sub_agent"
                agent_stage.status = "running"
                agent_stage.started_at = datetime.now(timezone.utc)
                agent_task.current_stage = stage_num
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
                try:
                    stage_payload = await _run_single_pass_stage(
                        agent_session, agent_task, agent_stage, llm_config, project,
                        get_stage_prompt(stage_num), selected_chunks,
                        code_chunks, static_routes, prev_context, audit_memory,
                        rule_hits, source_sink_hints,
                        supervisor_focus=supervisor_focus if supervisor_focus else None,
                    )
                    await _apply_stage_payload(agent_stage, stage_payload, session=agent_session, task=agent_task, static_routes=static_routes, audit_memory=audit_memory)
                    agent_stage.status = "completed"
                except Exception:
                    agent_stage.status = "failed"
                    logger.exception("Sub-agent stage %s failed for task %s", stage_num, task.id)
                agent_stage.completed_at = datetime.now(timezone.utc)
                await agent_session.commit()
                logger.info("Task %s sub-agent stage %s completed", task.id, stage_num)

    tasks = [run_one_agent(spec) for spec in selected]
    await asyncio.gather(*tasks, return_exceptions=True)

    for s in stages:
        await session.refresh(s)

    skipped = agent_plan.get("skipped_agents", [])
    for skip_spec in skipped:
        stage_num = int(skip_spec.get("stage_num", 0))
        stage = stage_map.get(stage_num)
        if stage and stage.status == "pending":
            stage.status = "skipped"
            stage.agent_role = "skipped_sub_agent"
            stage.findings = {"skipped": True, "skip_reason": skip_spec.get("skip_reason", "")}
    await session.commit()


def _build_planning_context(project, audit_memory: dict, rule_hits: list, source_sink_hints: list) -> dict:
    """Build the supervisor planning prompt context."""
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

    return {
        "tech_stack": getattr(project, "tech_stack", "") or "Unknown",
        "file_count": len(evidence_files),
        "route_count": len(routes),
        "entry_point_count": len(entry_points),
        "architecture_summary": json.dumps(arch_info, ensure_ascii=False)[:4000] if arch_info else "None",
        "rule_hits_summary": rule_hits_summary,
        "source_sink_summary": source_sink_summary,
        "agent_specs": "\n".join(agent_specs_lines),
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
        findings = stage.findings if isinstance(stage.findings, dict) else {}
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
    severity_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for stage in stages:
        if not isinstance(stage.findings, dict):
            continue
        vulns = stage.findings.get("vulnerabilities", [])
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


def _build_default_plan(rule_hits: list, source_sink_hints: list) -> dict:
    """Build a fallback agent plan from static evidence counts."""
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

    selected = []
    skipped = []
    for stage_num in range(2, 10):
        evidence = stage_evidence.get(stage_num, 0)
        if evidence > 0:
            selected.append({
                "stage_num": stage_num,
                "priority": len(selected) + 1,
                "focus_guidance": f"Audit based on {evidence} static evidence signals",
                "focus_files": [],
                "focus_routes": [],
            })
        else:
            skipped.append({"stage_num": stage_num, "skip_reason": "No supporting static evidence"})

    if not selected:
        selected = [{"stage_num": sn, "priority": i + 1, "focus_guidance": "", "focus_files": [], "focus_routes": []} for i, sn in enumerate(range(2, 10))]
        skipped = []

    return {"selected_agents": selected, "skipped_agents": skipped}
