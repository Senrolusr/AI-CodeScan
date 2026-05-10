"""Supervisor 多 Agent 审计编排器。"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select

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
        task.error_message = "模型配置不存在"
        await session.commit()
        return None

    result = await session.execute(select(Project).where(Project.id == task.project_id))
    project = result.scalar_one_or_none()
    if not project:
        task.status = "failed"
        task.error_message = "项目不存在"
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


async def run_multi_agent_audit(task_id: int, stage_nums: list[int] | None = None):
    """多 Agent 审计入口。"""
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
            # Phase 1: 架构 Agent（Stage 1）
            await _run_phase1_architecture(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, pre_discovery)

            if await _is_task_cancelled(session, task_id):
                return

            # Phase 2: Supervisor 规划
            audit_memory = _build_audit_memory(list(stages))
            agent_plan = await _run_supervisor_planning(session, task, stages, llm_config, project, audit_memory, rule_hits, source_sink_hints)

            if await _is_task_cancelled(session, task_id):
                return

            # Phase 3: 子 Agent 并行执行
            await _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, agent_plan)

            if await _is_task_cancelled(session, task_id):
                return

            # Phase 4: Supervisor 审核
            audit_memory = _build_audit_memory(list(stages))
            review = await _run_supervisor_review(session, task, stages, llm_config, audit_memory, agent_plan)

            if review.get("request_rerun") and review.get("rerun_agents"):
                rerun_plan = {"selected_agents": review["rerun_agents"], "skipped_agents": []}
                await _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, rerun_plan)

            if await _is_task_cancelled(session, task_id):
                return

            task.status = "completed"
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


PHASE_NAMES = {1: "架构分析", 2: "Supervisor 规划", 3: "并行审计", 4: "Supervisor 审核"}


async def run_multi_agent_phase(task_id: int, phase_num: int):
    """按 Phase 执行多 Agent 审计，完成后 paused 或 completed。"""
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
            next_phase = None

            if phase_num == 1:
                await _run_phase1_architecture(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, pre_discovery)
                if await _is_task_cancelled(session, task_id):
                    return
                next_phase = 2

            elif phase_num == 2:
                audit_memory = _build_audit_memory(list(stages))
                _plan = await _run_supervisor_planning(session, task, stages, llm_config, project, audit_memory, rule_hits, source_sink_hints)
                if await _is_task_cancelled(session, task_id):
                    return
                next_phase = 3

            elif phase_num == 3:
                summary = task.summary if isinstance(task.summary, dict) else {}
                agent_plan = summary.get("agent_plan")
                if not agent_plan or not isinstance(agent_plan, dict):
                    agent_plan = _build_default_plan(rule_hits, source_sink_hints)
                await _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, agent_plan)
                if await _is_task_cancelled(session, task_id):
                    return
                next_phase = 4

            elif phase_num == 4:
                summary = task.summary if isinstance(task.summary, dict) else {}
                agent_plan = summary.get("agent_plan", {})
                audit_memory = _build_audit_memory(list(stages))
                review = await _run_supervisor_review(session, task, stages, llm_config, audit_memory, agent_plan)
                if review.get("request_rerun") and review.get("rerun_agents"):
                    rerun_plan = {"selected_agents": review["rerun_agents"], "skipped_agents": []}
                    await _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, rerun_plan)
                if await _is_task_cancelled(session, task_id):
                    return
                task.status = "completed"
                task.completed_at = datetime.now(timezone.utc)
                await _refresh_task_summary(session, task, scan_stats=scan_stats, rule_hits=rule_hits)
                await session.commit()
                logger.info("Multi-agent task %s completed (Phase 4)", task_id)
                return

            if next_phase:
                await session.refresh(task)
                summary = dict(task.summary) if isinstance(task.summary, dict) else {}
                summary["current_phase"] = next_phase
                summary["multi_agent_phase_mode"] = True
                task.summary = summary
                task.status = "paused"
                task.current_stage = 0
                await _refresh_task_summary(session, task, scan_stats=scan_stats, rule_hits=rule_hits)
                await session.commit()
                logger.info("Multi-agent task %s Phase %s completed, paused for Phase %s", task_id, phase_num, next_phase)

        except Exception as exc:
            logger.error("Multi-agent task %s Phase %s failed: %s", task_id, phase_num, exc)
            task.status = "failed"
            task.error_message = str(exc)[:2000]
            task.completed_at = datetime.now(timezone.utc)
            await session.commit()


async def _run_phase1_architecture(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, pre_discovery=None):
    """Phase 1: 执行架构 Agent（Stage 1 多轮）。"""
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
    """Phase 2: Supervisor 规划。"""
    stage_map = {s.stage_num: s for s in stages}
    plan_stage = stage_map.get(-1)
    if not plan_stage:
        plan_stage = AuditStage(task_id=task.id, stage_num=-1, stage_name="Supervisor 规划", agent_role="supervisor_plan", status="pending")
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
            raise RuntimeError(f"Supervisor 规划失败：{result['error']['message']}")

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


async def _run_supervisor_review(session, task, stages, llm_config, audit_memory, agent_plan):
    """Phase 4: Supervisor 审核。"""
    stage_map = {s.stage_num: s for s in stages}
    review_stage = stage_map.get(-2)
    if not review_stage:
        review_stage = AuditStage(task_id=task.id, stage_num=-2, stage_name="Supervisor 审核", agent_role="supervisor_review", status="pending")
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
            raise RuntimeError(f"Supervisor 审核失败：{result['error']['message']}")

        review = _parse_structured_response(result["content"], result.get("meta"))
        if isinstance(review, dict) and review.get("parse_error"):
            review = {"review_summary": "审核响应解析失败，跳过迭代", "request_rerun": False, "rerun_agents": []}

        review_stage.findings = review if isinstance(review, dict) else {"raw": str(review)[:5000]}
        review_stage.llm_response = result["content"][:10000]
        review_stage.status = "completed"
        review_stage.completed_at = datetime.now(timezone.utc)
        await session.commit()
        return review

    except Exception as exc:
        review_stage.status = "failed"
        review_stage.completed_at = datetime.now(timezone.utc)
        review_stage.llm_response = str(exc)[:2000]
        await session.commit()
        logger.warning("Supervisor review failed: %s", exc)
        return {"review_summary": "审核失败", "request_rerun": False, "rerun_agents": []}


async def _execute_sub_agents(session, task, stages, llm_config, project, code_chunks, static_routes, rule_hits, source_sink_hints, agent_plan):
    """Phase 3: 并行执行选中的子 Agent。"""
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
                        flow_text = "\n关键数据流：" + "；".join(str(f) for f in focus_data_flows[:5])
                    func_text = ""
                    if focus_functions:
                        func_text = "\n关键函数：" + ", ".join(str(f) for f in focus_functions[:12])
                    supervisor_focus = AGENT_FOCUS_PREFIX.format(
                        focus_guidance=(focus_guidance or "无额外指导") + flow_text,
                        focus_files=", ".join(str(f) for f in focus_files[:10]) or "无",
                        focus_routes=", ".join(str(r) for r in focus_routes[:10]) or "无",
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
    """构建 Supervisor 规划的用户 Prompt 上下文。"""
    arch_info = audit_memory.get("architecture_info", {}) if isinstance(audit_memory, dict) else {}
    if not isinstance(arch_info, dict):
        arch_info = {}

    routes = audit_memory.get("route_inventory", []) if isinstance(audit_memory, dict) else []
    entry_points = audit_memory.get("entry_points", []) if isinstance(audit_memory, dict) else []

    rule_hits_summary = _summarize_rule_hits(rule_hits)
    source_sink_summary = _summarize_source_sink_hints(source_sink_hints)

    agent_specs_lines = []
    for stage_num in range(2, 10):
        spec = STAGE_SPECS.get(stage_num, f"阶段 {stage_num}")
        hit_count = len([h for h in rule_hits if isinstance(h, dict) and stage_num in (h.get("stage_nums") or [])])
        hint_count = len([h for h in source_sink_hints if isinstance(h, dict) and stage_num in (h.get("stage_nums") or [])])
        agent_specs_lines.append(f"- Stage {stage_num}：{spec}（规则命中 {hit_count}，源-汇线索 {hint_count}）")

    return {
        "tech_stack": getattr(project, "tech_stack", "") or "未知",
        "file_count": audit_memory.get("evidence_files_count", 0) if isinstance(audit_memory, dict) else 0,
        "route_count": len(routes),
        "entry_point_count": len(entry_points),
        "architecture_summary": json.dumps(arch_info, ensure_ascii=False)[:4000] if arch_info else "无",
        "rule_hits_summary": rule_hits_summary,
        "source_sink_summary": source_sink_summary,
        "agent_specs": "\n".join(agent_specs_lines),
    }


def _build_review_context(audit_memory: dict, agent_plan: dict, stages) -> dict:
    """构建 Supervisor 审核的用户 Prompt 上下文。"""
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
                f"Stage {stage.stage_num}（{stage.stage_name}）：{count} 个漏洞"
            )

    confirmed_routes = set()
    if isinstance(audit_memory, dict):
        for route in audit_memory.get("route_inventory", [])[:200]:
            if isinstance(route, dict):
                path = str(route.get("path", "")).strip()
                if path:
                    confirmed_routes.add(path)

    return {
        "executed_agents": "、".join(executed) or "无",
        "total_vulns": total_vulns,
        "severity_distribution": "、".join(f"{k}:{v}" for k, v in severity_dist.items()),
        "agent_results_summary": "\n".join(stage_summaries) or "无结果",
        "uncovered_routes": "暂未实现路由覆盖分析" if confirmed_routes else "无路由信息",
        "original_plan": json.dumps(agent_plan, ensure_ascii=False)[:2000] if isinstance(agent_plan, dict) else "无",
    }


def _summarize_rule_hits(rule_hits: list) -> str:
    """按阶段分组汇总规则命中。"""
    if not rule_hits:
        return "无规则命中"
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
        lines.append(f"Stage {stage_num}：{len(hits)} 次命中，文件示例：{', '.join(sample_files)}")
    return "\n".join(lines) if lines else "无规则命中"


def _summarize_source_sink_hints(hints: list) -> str:
    """按阶段分组汇总源-汇线索。"""
    if not hints:
        return "无源-汇线索"
    by_stage: dict[int, list] = {}
    for hint in hints:
        if not isinstance(hint, dict):
            continue
        for sn in (hint.get("stage_nums") or []):
            by_stage.setdefault(int(sn), []).append(hint)
    lines = []
    for stage_num in sorted(by_stage.keys()):
        count = len(by_stage[stage_num])
        lines.append(f"Stage {stage_num}：{count} 条线索")
    return "\n".join(lines) if lines else "无源-汇线索"


def _build_default_plan(rule_hits: list, source_sink_hints: list) -> dict:
    """当 Supervisor 规划失败时，基于规则命中数生成默认计划。"""
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
                "focus_guidance": f"基于 {evidence} 条静态证据进行审计",
                "focus_files": [],
                "focus_routes": [],
            })
        else:
            skipped.append({"stage_num": stage_num, "skip_reason": "无静态证据支持"})

    if not selected:
        selected = [{"stage_num": sn, "priority": i + 1, "focus_guidance": "", "focus_files": [], "focus_routes": []} for i, sn in enumerate(range(2, 10))]
        skipped = []

    return {"selected_agents": selected, "skipped_agents": skipped}
