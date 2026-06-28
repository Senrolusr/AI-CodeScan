import json
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from errors import ApiError
from models import AuditRun, AuditStage, AuditTask, LlmConfig, Project, Vulnerability
from prompts.stage_prompts import SUPERVISOR_PLAN_STAGE_NAME, SUPERVISOR_REVIEW_STAGE_NAME, get_stage_name
from schemas import AuditCreate, AuditRerunRequest, AuditStageOut, AuditTaskOut, VulnerabilityOut
from services.audit_engine import (
    _coerce_stage_findings,
    _collect_stage1_risk_hints,
    _severity_match_values,
    _severity_order_expr,
)
from services.audit_worker import clear_task_queue_state, mark_task_queued
from services import audit_runtime as rt
from services.audit_cleanup import (
    delete_audit_task_records,
    get_audit_report_dir,
    remove_audit_artifact_file,
    resolve_audit_artifact_path,
)
from services.auth import verify_token_query

router = APIRouter()

REMOVED_SUMMARY_KEYS = {
    "verification_stats",
    "candidate_severity_stats",
    "diff_stats",
    "candidate_diff_stats",
}


def _strip_removed_summary_keys(summary):
    if not isinstance(summary, dict):
        return summary
    sanitized = dict(summary)
    for key in REMOVED_SUMMARY_KEYS:
        sanitized.pop(key, None)
    return sanitized


def _serialize_task(task: AuditTask) -> dict:
    current_stage = task.current_stage or 0
    total_stages = task.total_stages or 9
    if task.status == "completed" and current_stage <= 0:
        current_stage = total_stages

    return {
        "id": task.id,
        "name": task.name or f"审计 #{task.id}",
        "project_id": task.project_id,
        "llm_config_id": task.llm_config_id,
        "status": task.status,
        "current_stage": current_stage,
        "total_stages": total_stages,
        "audit_mode": task.audit_mode,
        "summary": _strip_removed_summary_keys(task.summary),
        "error_message": task.error_message,
        "created_at": task.created_at,
        "completed_at": task.completed_at,
    }


def _serialize_vulnerability(vuln: Vulnerability) -> dict:
    return VulnerabilityOut.model_validate(vuln).model_dump()


def _serialize_run(run) -> dict | None:
    if run is None:
        return None
    return {
        "id": run.id,
        "task_id": run.task_id,
        "status": run.status,
        "mode": run.mode,
        "selected_stage_nums": run.selected_stage_nums if isinstance(run.selected_stage_nums, list) else [],
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "error_message": run.error_message,
        "created_at": run.created_at,
    }


def _serialize_event(event) -> dict:
    # 委托到 audit_runtime.serialize_event：JSON /events 与 SSE /events/stream 共用同一序列化。
    return rt.serialize_event(event)


def _serialize_subtask(subtask) -> dict:
    return {
        "id": subtask.id,
        "run_id": subtask.run_id,
        "task_id": subtask.task_id,
        "stage_num": subtask.stage_num,
        "role": subtask.role,
        "status": subtask.status,
        "attempt_count": subtask.attempt_count,
        "blocked_reason": subtask.blocked_reason,
        "started_at": subtask.started_at,
        "completed_at": subtask.completed_at,
    }


def _serialize_agent_run(agent_run) -> dict:
    return {
        "id": agent_run.id,
        "subtask_id": agent_run.subtask_id,
        "run_id": agent_run.run_id,
        "task_id": agent_run.task_id,
        "stage_num": agent_run.stage_num,
        "agent_role": agent_run.agent_role,
        "attempt": agent_run.attempt,
        "llm_config_id": agent_run.llm_config_id,
        "status": agent_run.status,
        "prompt_tokens": agent_run.prompt_tokens,
        "completion_tokens": agent_run.completion_tokens,
        "latency_ms": agent_run.latency_ms,
        "finish_reason": agent_run.finish_reason,
        "error_message": agent_run.error_message,
        "started_at": agent_run.started_at,
        "completed_at": agent_run.completed_at,
    }


def _list_report_files(task_id: int) -> list[dict]:
    report_dir = get_audit_report_dir(task_id)
    if not os.path.exists(report_dir):
        return []

    files = []
    for file_name in os.listdir(report_dir):
        if not file_name.lower().endswith(".html"):
            continue
        filepath = os.path.join(report_dir, file_name)
        if not os.path.isfile(filepath):
            continue
        files.append(
            {
                "filename": file_name,
                "size": os.path.getsize(filepath),
                "download_url": f"/api/reports/download/{task_id}/{file_name}",
            }
        )
    return files


async def _create_stage_records(db: AsyncSession, task_id: int):
    for stage_num in range(1, 10):
        db.add(
            AuditStage(
                task_id=task_id,
                stage_num=stage_num,
                stage_name=get_stage_name(stage_num),
                status="pending",
            )
        )
    db.add(AuditStage(task_id=task_id, stage_num=-1, stage_name=SUPERVISOR_PLAN_STAGE_NAME, agent_role="supervisor_plan", status="pending"))
    db.add(AuditStage(task_id=task_id, stage_num=-2, stage_name=SUPERVISOR_REVIEW_STAGE_NAME, agent_role="supervisor_review", status="pending"))


async def _reset_stage_state(db: AsyncSession, task_id: int, stage_nums: list[int]):
    if not stage_nums:
        return

    result = await db.execute(
        select(AuditStage).where(
            AuditStage.task_id == task_id,
            AuditStage.stage_num.in_(stage_nums),
        )
    )
    stages = result.scalars().all()

    for stage in stages:
        if stage.artifact_path:
            remove_audit_artifact_file(stage.artifact_path)

        stage.status = "pending"
        stage.findings = {"vulnerabilities": []}
        stage.prompt_used = ""
        stage.llm_response = ""
        stage.compressed_summary = {}
        stage.artifact_path = ""
        stage.started_at = None
        stage.completed_at = None

    await db.execute(
        delete(Vulnerability).where(
            Vulnerability.task_id == task_id,
            Vulnerability.stage_id.in_([stage.id for stage in stages]),
        )
    )


async def _get_task_with_stages(db: AsyncSession, task_id: int) -> tuple[AuditTask, list[AuditStage]]:
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)

    result = await db.execute(select(AuditStage).where(AuditStage.task_id == task_id).order_by(AuditStage.stage_num))
    stages = result.scalars().all()
    return task, stages


async def _close_task_runs(db: AsyncSession, task_id: int, *, status: str, reason: str) -> None:
    """把该任务所有非终态 run 置为 status，用于取消/清理场景。影子写入，不影响旧逻辑。"""
    from models import AuditRun

    result = await db.execute(
        select(AuditRun).where(
            AuditRun.task_id == task_id,
            AuditRun.status.notin_(["completed", "failed", "cancelled"]),
        )
    )
    now = datetime.now(timezone.utc)
    for run in result.scalars().all():
        run.status = status
        run.completed_at = now
        run.error_message = reason[:2000]


@router.post("", response_model=AuditTaskOut)
async def create_audit(
    data: AuditCreate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Project).where(Project.id == data.project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)

    result = await db.execute(select(LlmConfig).where(LlmConfig.id == data.llm_config_id))
    llm_config = result.scalar_one_or_none()
    if not llm_config:
        raise ApiError("LLM_CONFIG_NOT_FOUND", "模型配置不存在", status_code=404)

    audit_name = (data.name or "").strip()
    if not audit_name:
        audit_name = f"{project.name} 审计 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    audit_name = audit_name[:255]

    summary_data = {
        "selected_stage_nums": list(range(1, 10)),
        "current_phase": 1,
        "multi_agent_phase_mode": True,
        "auto_second_pass": False,
    }

    task = AuditTask(
        name=audit_name,
        project_id=data.project_id,
        llm_config_id=data.llm_config_id,
        status="paused",
        current_stage=0,
        total_stages=9,
        audit_mode="multi_agent",
        summary=summary_data,
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    await _create_stage_records(db, task.id)
    mark_task_queued(task, list(range(1, 10)))
    await rt.emit_event(
        db,
        task_id=task.id,
        event_type=rt.EVENT_RUN_QUEUED,
        payload={"mode": "full", "selected_stage_nums": list(range(1, 10))},
    )
    await db.commit()

    return _serialize_task(task)


@router.get("", response_model=list[AuditTaskOut])
async def list_audits(
    project_id: int = None,
    limit: int = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditTask).order_by(AuditTask.created_at.desc())
    if project_id:
        query = query.where(AuditTask.project_id == project_id)
    if limit:
        query = query.limit(min(limit, 100))
    result = await db.execute(query)
    return [_serialize_task(task) for task in result.scalars().all()]


@router.get("/{task_id}/snapshot")
async def get_audit_snapshot(
    task_id: int,
    severity: str = None,
    review_status: str = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)

    stages_result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id).order_by(AuditStage.stage_num)
    )
    stages = stages_result.scalars().all()
    formal_counts = await _get_stage_formal_vuln_counts(db, task_id)
    serialized_stages = [
        _serialize_stage(stage, include_payloads=False, formal_count=formal_counts.get(stage.stage_num, 0))
        for stage in stages
    ]

    stage_one_detail = None
    for stage in stages:
        if stage.stage_num == 1:
            stage_one_detail = _serialize_stage(
                stage,
                include_payloads=True,
                formal_count=formal_counts.get(stage.stage_num, 0),
            )
            break

    vulns_query = (
        select(Vulnerability)
        .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
        .where(
            Vulnerability.task_id == task_id,
            AuditStage.stage_num.between(2, 9),
        )
    )
    if severity:
        vulns_query = vulns_query.where(Vulnerability.severity.in_(_severity_match_values(severity)))
    if review_status:
        wanted = [s.strip() for s in review_status.split(",") if s.strip()]
        if wanted:
            vulns_query = vulns_query.where(Vulnerability.review_status.in_(wanted))
    vulns_result = await db.execute(
        vulns_query.order_by(_severity_order_expr(Vulnerability.severity).desc(), Vulnerability.id.desc())
    )
    vulns = vulns_result.scalars().all()

    # review_summary 始终基于该任务全部正式漏洞（不受 severity/review_status 过滤影响），
    # 供前端展示复核队列徽章。
    review_counts_rows = await db.execute(
        select(Vulnerability.review_status, func.count(Vulnerability.id))
        .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
        .where(Vulnerability.task_id == task_id, AuditStage.stage_num.between(2, 9))
        .group_by(Vulnerability.review_status)
    )
    review_summary = {"unreviewed": 0, "confirmed": 0, "rejected": 0, "needs_review": 0}
    for status_value, count in review_counts_rows.all():
        if status_value in review_summary:
            review_summary[status_value] = count

    current_run = await rt.get_current_run(db, task_id)
    subtasks = await rt.list_subtasks(db, current_run.id) if current_run else []
    agent_runs = await rt.list_agent_runs(db, current_run.id) if current_run else []
    recent_events = await rt.list_recent_events(db, task_id, limit=100)

    # ── §12.3 顶层稳定 view model 键（§17.3：聚合数据不埋在 task.summary 让前端解析）──
    summary_dict = task.summary if isinstance(task.summary, dict) else {}
    # route_coverage：runner 已算好存 summary，提升为顶层键（summary 副本保留兼容旧前端）。
    route_coverage = summary_dict.get("route_coverage") or {}

    # findings_summary：全量正式漏洞（stage 2-9）按严重度聚合，不受 severity/review_status 过滤影响。
    severity_rows = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
        .where(Vulnerability.task_id == task_id, AuditStage.stage_num.between(2, 9))
        .group_by(Vulnerability.severity)
    )
    by_severity: dict[str, int] = {}
    findings_total = 0
    for severity_value, count in severity_rows.all():
        key = str(severity_value or "").strip() or "Unknown"
        by_severity[key] = by_severity.get(key, 0) + int(count or 0)
        findings_total += int(count or 0)
    findings_summary = {"total": findings_total, "by_severity": by_severity}

    # quality_notices：各阶段 preview 聚合的质量信号。
    quality_notices = _collect_quality_notices(serialized_stages)

    return {
        "task": _serialize_task(task),
        "stages": serialized_stages,
        "stage_one_detail": stage_one_detail,
        "vulnerabilities": [_serialize_vulnerability(vuln) for vuln in vulns],
        "findings_summary": findings_summary,
        "route_coverage": route_coverage,
        "quality_notices": quality_notices,
        "reports": _list_report_files(task_id),
        "current_run": _serialize_run(current_run),
        "subtasks": [_serialize_subtask(s) for s in subtasks],
        "agent_runs": [_serialize_agent_run(a) for a in agent_runs],
        "recent_events": [_serialize_event(e) for e in recent_events],
        "diagnostics": rt.build_run_diagnostics(task, current_run, subtasks, agent_runs, recent_events),
        "review_summary": review_summary,
    }


@router.get("/{task_id}/events")
async def get_audit_events(
    task_id: int,
    limit: int = 100,
    after_id: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """返回该任务的事件流（活动流）。支持 ``after_id`` 增量轮询。"""
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    if not result.scalar_one_or_none():
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)
    events = await rt.list_events(db, task_id, limit=limit, after_id=after_id)
    serialized_events = [_serialize_event(e) for e in events]
    event_ids = [int(e.get("id") or 0) for e in serialized_events]
    latest_after_id = max(event_ids) if event_ids else after_id
    return {
        "task_id": task_id,
        "after_id": latest_after_id,
        "events": serialized_events,
    }


@router.get("/{task_id}/events/stream")
async def stream_audit_events(
    task_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(verify_token_query),
):
    """SSE 事件流（§11.3）。原生 EventSource 无法发送 Authorization 头 → 经 ``?token=`` 鉴权。

    - 流内容与 JSON ``/events`` 同源（``rt.iter_event_stream`` 复用 ``list_events`` + ``serialize_event``）。
    - ``Last-Event-ID`` 请求头作为断点续传起点（EventSource 重连时浏览器自动带）。
    - 与 JSON ``/events`` 并存、互不影响（additive）。
    """
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    if not result.scalar_one_or_none():
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)

    last_event_id = 0
    raw = request.headers.get("last-event-id")
    if raw:
        try:
            last_event_id = int(raw)
        except (TypeError, ValueError):
            last_event_id = 0

    return StreamingResponse(
        rt.iter_event_stream(task_id, last_event_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@router.get("/{task_id}/runs")
async def list_audit_runs(task_id: int, db: AsyncSession = Depends(get_db)):
    """列出该任务全部 run（§12.2 行1091：runs 列表查询）。

    按 id 倒序（最新优先）；复用 snapshot 里的 ``_serialize_run`` view model。
    """
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    if not result.scalar_one_or_none():
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)
    runs = await rt.list_runs(db, task_id)
    return [_serialize_run(run) for run in runs]


@router.get("/{task_id}/runs/{run_id}")
async def get_audit_run(task_id: int, run_id: int, db: AsyncSession = Depends(get_db)):
    """单个 run 详情（§12.2：runs 详情查询）。

    带 task_id 约束，防越权串读别的任务的 run。附该 run 的 subtask 列表，供追溯执行计划。
    """
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    if not result.scalar_one_or_none():
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)
    run = await rt.get_run(db, task_id, run_id)
    if run is None:
        raise ApiError("AUDIT_RUN_NOT_FOUND", "审计运行不存在", status_code=404)
    subtasks = await rt.list_subtasks(db, run.id)
    return {
        **_serialize_run(run),
        "subtasks": [_serialize_subtask(s) for s in subtasks],
    }


@router.get("/{task_id}", response_model=AuditTaskOut)
async def get_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)
    return _serialize_task(task)


@router.post("/{task_id}/cancel", response_model=AuditTaskOut)
async def cancel_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)
    if task.status not in {"pending", "running", "paused"}:
        raise HTTPException(400, "只有待处理、运行中或已暂停的审计可以取消")

    task.status = "cancelled"
    task.error_message = "已由用户取消"
    task.completed_at = datetime.now(timezone.utc)
    clear_task_queue_state(task)

    result = await db.execute(select(AuditStage).where(AuditStage.task_id == task_id))
    for stage in result.scalars().all():
        if stage.status == "running":
            stage.status = "cancelled"
            stage.completed_at = datetime.now(timezone.utc)

    # 关闭非终态 run 并记录取消事件（影子写入）。
    await _close_task_runs(db, task_id, status="cancelled", reason="用户取消")
    await rt.emit_event(
        db,
        task_id=task_id,
        event_type=rt.EVENT_RUN_CANCELLED,
        payload={"reason": "用户取消"},
    )

    await db.commit()
    await db.refresh(task)
    return _serialize_task(task)


@router.post("/{task_id}/retry", response_model=AuditTaskOut)
async def retry_audit(
    task_id: int,
    payload: AuditRerunRequest | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
):
    """重跑审计阶段。

    - 无 body 或 ``stage_nums`` 为空 → 重跑**全部**可重试阶段（failed/completed/cancelled），向后兼容。
    - ``stage_nums`` 非空 → 仅重跑指定子集（必须 ⊆ 可重试阶段，否则 400）。

    runtime 已按 ``summary.selected_stage_nums`` 只执行选定阶段（audit_worker），故 subset 透传即可。
    """
    task, stages = await _get_task_with_stages(db, task_id)
    if task.status not in {"completed", "failed", "cancelled"}:
        raise HTTPException(400, "只有已完成、失败或已取消的审计可以重试")

    eligible_stage_nums = [
        stage.stage_num for stage in stages if stage.status in {"failed", "completed", "cancelled"}
    ]
    if not eligible_stage_nums:
        raise HTTPException(400, "没有可重试的阶段")

    requested = payload.stage_nums if (payload and payload.stage_nums) else None
    if requested:
        eligible_set = set(eligible_stage_nums)
        requested_set = {int(num) for num in requested}
        invalid = requested_set - eligible_set
        if invalid:
            raise HTTPException(400, f"不可重试的阶段：{sorted(invalid)}")
        rerun_stage_nums = [num for num in eligible_stage_nums if num in requested_set]
    else:
        rerun_stage_nums = eligible_stage_nums

    summary = task.summary if isinstance(task.summary, dict) else {}
    summary["selected_stage_nums"] = rerun_stage_nums
    summary["current_phase"] = 1
    summary["multi_agent_phase_mode"] = True
    summary.pop("audit_memory", None)
    summary.pop("agent_plan", None)
    summary.pop("review_outcome", None)
    task.summary = summary
    mark_task_queued(task, rerun_stage_nums)
    await _reset_stage_state(db, task.id, rerun_stage_nums)
    await rt.emit_event(
        db,
        task_id=task.id,
        event_type=rt.EVENT_RUN_QUEUED,
        payload={"mode": "rerun", "selected_stage_nums": rerun_stage_nums},
    )
    await db.commit()

    await db.refresh(task)
    return _serialize_task(task)


@router.post("/{task_id}/pause", response_model=AuditTaskOut)
async def pause_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    """暂停运行中的审计（GAP3，§12.2）。

    - 仅 ``running`` 可暂停（否则 400）。
    - 置 ``status="paused"``；当前 run 标 ``paused``（非 run 终态，保留为历史记录）。
    - **协作式让出**：supervisor 在阶段边界 ``_is_task_stopping`` 命中 paused 即 return，
      保留已完成阶段；正在执行的 stage 跑完本轮后停。暂停粒度≈一个 stage。
    - paused 非 ``_TERMINAL_RUN_STATUSES``，故 recover 跳过 paused 任务（不自动改态）。
    """
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)
    if task.status != "running":
        raise HTTPException(400, "只有运行中的审计可以暂停")

    task.status = "paused"
    await _close_task_runs(db, task_id, status="paused", reason="用户暂停")
    await rt.emit_event(
        db,
        task_id=task_id,
        event_type=rt.EVENT_RUN_PAUSED,
        payload={"reason": "用户暂停"},
    )
    await db.commit()
    await db.refresh(task)
    return _serialize_task(task)


@router.post("/{task_id}/resume", response_model=AuditTaskOut)
async def resume_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    """恢复已暂停的审计（GAP3，§12.2）。

    - 仅 ``paused`` 可恢复（否则 400）。
    - **续跑而非重跑**：``selected_stage_nums`` = 未完成的 sub_agent 阶段（2-9 且 status≠completed），
      已完成阶段不重置（与 /retry「全部重置」正交）。重置这些剩余阶段（清残留 running/部分 findings）。
    - 重新入队（status→pending）→ worker 认领 → 新 rerun run → supervisor 各 phase 幂等跳过已完成阶段。
    """
    task, stages = await _get_task_with_stages(db, task_id)
    if task.status != "paused":
        raise HTTPException(400, "只有已暂停的审计可以恢复")

    remaining = [
        stage.stage_num for stage in stages
        if 2 <= stage.stage_num <= 9 and stage.status != "completed"
    ]
    if not remaining:
        # 已无剩余阶段：直接收口为完成态（避免空入队）。
        task.status = "completed"
        task.current_stage = task.total_stages or 9
        task.completed_at = datetime.now(timezone.utc)
        clear_task_queue_state(task)
        await rt.emit_event(
            db,
            task_id=task.id,
            event_type=rt.EVENT_RUN_COMPLETED,
            payload={"note": "resume 时已无剩余阶段，直接完成"},
        )
        await db.commit()
        await db.refresh(task)
        return _serialize_task(task)

    # mark_task_queued 置 selected_stage_nums + queue keys + status=pending。
    # _reset_stage_state 清所有「未完成」阶段的残留 running/部分 findings（含可能卡住的 stage 1/-1/-2，
    # 防御 worker 崩溃后 resume；已完成阶段不在其中、不动）。干净暂停下这里多为 no-op。
    mark_task_queued(task, remaining)
    to_reset = [stage.stage_num for stage in stages if stage.status != "completed"]
    await _reset_stage_state(db, task.id, to_reset)
    await rt.emit_event(
        db,
        task_id=task.id,
        event_type=rt.EVENT_RUN_RESUMED,
        payload={"mode": "rerun", "selected_stage_nums": remaining},
    )
    await db.commit()
    await db.refresh(task)
    return _serialize_task(task)


def _build_stage_debug_payload(stage: AuditStage) -> dict | None:
    try:
        prompt_data = json.loads(stage.prompt_used) if stage.prompt_used else {}
    except Exception:
        prompt_data = {}
    try:
        response_data = json.loads(stage.llm_response) if stage.llm_response else {}
    except Exception:
        response_data = {}

    debug = prompt_data.get("debug") if isinstance(prompt_data, dict) else None
    if not debug and not (isinstance(response_data, dict) and response_data.get("error")):
        return None
    return {
        "prompt_length": len(stage.prompt_used or ""),
        "selected_chunk_count": (debug or {}).get("selected_chunk_count"),
        "code_text_length": (debug or {}).get("code_text_length"),
        "user_prompt_length": (debug or {}).get("user_prompt_length"),
        "static_route_count": (debug or {}).get("static_route_count"),
        "prev_context_length": (debug or {}).get("prev_context_length"),
        "planned_batch_count": (debug or {}).get("planned_batch_count") or (debug or {}).get("batch_count"),
        "executed_batch_count": (debug or {}).get("executed_batch_count"),
        "early_stop": (debug or {}).get("early_stop"),
        "error": response_data.get("error") if isinstance(response_data, dict) else None,
    }


def _stage1_risk_hints_from_findings(findings: dict, compressed: dict | None = None) -> list:
    payload = {"risk_hints": [], "vulnerability_hints": [], "vulnerabilities": []}
    compressed = compressed if isinstance(compressed, dict) else {}
    for source in [findings, compressed]:
        for key in ["risk_hints", "vulnerability_hints", "vulnerabilities"]:
            value = source.get(key) if isinstance(source, dict) else None
            if isinstance(value, list):
                payload[key].extend(value)
    return _collect_stage1_risk_hints(payload)


def _build_stage_quality_counts(stage: AuditStage, findings: dict, formal_count: int | None = None) -> dict:
    vulnerabilities = findings.get("vulnerabilities", []) if isinstance(findings, dict) else []
    candidate_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
    if stage.stage_num == 1:
        candidate_count = 0
        formal_count = 0
    formal_count = max(0, int(formal_count or 0))
    filtered_count = max(0, candidate_count - formal_count)
    payload = {
        "_candidate_vulnerability_count": candidate_count,
        "_formal_vulnerability_count": formal_count,
        "_filtered_vulnerability_count": filtered_count,
    }
    if 2 <= stage.stage_num <= 9 and filtered_count > 0:
        payload["_quality_gate_note"] = "部分候选因缺少标题/类型/入口证据、缺少 file_path 与 endpoint，或与已有漏洞同根因去重，未进入正式漏洞列表。"
    return payload


def _build_stage_findings_preview(stage: AuditStage, formal_count: int | None = None) -> list | dict:
    findings = _coerce_stage_findings(stage.findings)
    compressed = stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {}
    vulnerabilities = findings.get("vulnerabilities", [])
    vulnerability_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
    if stage.stage_num == 1:
        vulnerability_count = 0

    preview = {
        "stage_summary": compressed.get("stage_summary") or findings.get("stage_summary") or "",
        "_vulnerability_count": vulnerability_count,
    }
    preview.update(_build_stage_quality_counts(stage, findings, formal_count))
    for key in ["parse_error", "raw_response", "_policy_note", "_policy_stats", "_salvaged", "skipped", "skip_reason"]:
        if key in findings:
            preview[key] = findings.get(key)

    if stage.stage_num == -1:
        for key in ["analysis_summary", "selected_agents", "skipped_agents"]:
            if key in findings:
                preview[key] = findings.get(key)

    if stage.stage_num == -2:
        for key in ["review_summary", "findings_assessment", "request_rerun", "rerun_agents", "additional_guidance", "rerun_execution", "review_closure"]:
            if key in findings:
                preview[key] = findings.get(key)

    if stage.stage_num == 1:
        risk_hints = _stage1_risk_hints_from_findings(findings, compressed)
        preview["risk_hints"] = risk_hints[:8]
        preview["_risk_hint_count"] = len(risk_hints)
        preview["vulnerabilities"] = []
        arch = findings.get("architecture_info") if isinstance(findings.get("architecture_info"), dict) else {}
        if not arch and isinstance(compressed.get("architecture_info"), dict):
            arch = compressed.get("architecture_info", {})
        if isinstance(arch, dict) and arch:
            routes = arch.get("routes", []) if isinstance(arch.get("routes"), list) else []
            preview["architecture_info"] = {
                "tech_stack": arch.get("tech_stack", ""),
                "framework": arch.get("framework", ""),
                "database": arch.get("database", ""),
                "auth_mechanism": arch.get("auth_mechanism", ""),
                "routes": routes[:12],
                "_route_count": len(routes),
                "middleware_chain": arch.get("middleware_chain", []),
                "database_models": arch.get("database_models", []),
                "security_boundaries": arch.get("security_boundaries"),
                "external_integrations": arch.get("external_integrations", []),
                "_gap_analysis": arch.get("_gap_analysis"),
                "entry_points": arch.get("entry_points", []),
                "output_points": arch.get("output_points", []),
                "modules": arch.get("modules", []),
                "data_flows": arch.get("data_flows", []),
            }

    debug_payload = _build_stage_debug_payload(stage)
    if debug_payload:
        preview["_debug"] = debug_payload
    return preview


def _serialize_stage(stage: AuditStage, *, include_payloads: bool, formal_count: int | None = None) -> dict:
    if 1 <= stage.stage_num <= 9:
        stage_name = get_stage_name(stage.stage_num)
    else:
        stage_name = stage.stage_name

    findings = _coerce_stage_findings(stage.findings) if include_payloads else _build_stage_findings_preview(stage, formal_count)
    if include_payloads and stage.stage_num == 1 and isinstance(findings, dict):
        findings = dict(findings)
        findings["risk_hints"] = _stage1_risk_hints_from_findings(
            findings,
            stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {},
        )
        findings["vulnerabilities"] = []
    if include_payloads and isinstance(findings, dict):
        findings.update(_build_stage_quality_counts(stage, findings, formal_count))
    if include_payloads:
        debug_payload = _build_stage_debug_payload(stage)
        if debug_payload:
            findings.setdefault("_debug", debug_payload)

    return {
        "id": stage.id,
        "task_id": stage.task_id,
        "stage_num": stage.stage_num,
        "stage_name": stage_name,
        "agent_role": stage.agent_role,
        "status": stage.status,
        "prompt_used": stage.prompt_used if include_payloads else "",
        "findings": findings,
        "llm_response": stage.llm_response if include_payloads else "",
        "compressed_summary": stage.compressed_summary,
        "artifact_path": stage.artifact_path,
        "started_at": stage.started_at,
        "completed_at": stage.completed_at,
    }


async def _get_stage_formal_vuln_counts(db: AsyncSession, task_id: int) -> dict[int, int]:
    result = await db.execute(
        select(AuditStage.stage_num, func.count(Vulnerability.id))
        .join(Vulnerability, Vulnerability.stage_id == AuditStage.id)
        .where(
            Vulnerability.task_id == task_id,
            AuditStage.stage_num.between(2, 9),
        )
        .group_by(AuditStage.stage_num)
    )
    return {int(stage_num): int(count or 0) for stage_num, count in result.all()}


def _collect_quality_notices(serialized_stages: list[dict]) -> list[dict]:
    """§12.3 quality_notices：从各阶段 preview 聚合质量信号为扁平列表（§17.3 稳定 view model）。

    每条 notice：{stage_num, stage_name, kind, count?, message}。
    kind ∈ filtered（质量门过滤的候选）/ salvaged（截断恢复）/ parse_error / skipped。
    数据全部来自已序列化的 stage preview（``_build_stage_findings_preview`` 产出的 ``_`` 前缀计数字段）。
    """
    notices: list[dict] = []
    for stage in serialized_stages:
        findings = stage.get("findings") if isinstance(stage.get("findings"), dict) else {}
        stage_num = stage.get("stage_num")
        stage_name = stage.get("stage_name") or ""
        filtered = findings.get("_filtered_vulnerability_count")
        if isinstance(filtered, (int, float)) and int(filtered) > 0:
            notices.append({
                "stage_num": stage_num,
                "stage_name": stage_name,
                "kind": "filtered",
                "count": int(filtered),
                "message": findings.get("_quality_gate_note") or "部分候选未进入正式漏洞列表",
            })
        if findings.get("_salvaged"):
            notices.append({
                "stage_num": stage_num,
                "stage_name": stage_name,
                "kind": "salvaged",
                "message": "阶段输出由截断响应中自动恢复，请人工复核",
            })
        if findings.get("parse_error"):
            notices.append({
                "stage_num": stage_num,
                "stage_name": stage_name,
                "kind": "parse_error",
                "message": str(findings.get("parse_error"))[:240],
            })
        if findings.get("skipped"):
            notices.append({
                "stage_num": stage_num,
                "stage_name": stage_name,
                "kind": "skipped",
                "message": str(findings.get("skip_reason") or "阶段已跳过")[:240],
            })
    return notices


@router.get("/{task_id}/stages", response_model=list[AuditStageOut])
async def get_audit_stages(
    task_id: int,
    include_payloads: bool = False,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id).order_by(AuditStage.stage_num)
    )
    stages = result.scalars().all()
    formal_counts = await _get_stage_formal_vuln_counts(db, task_id)
    return [
        _serialize_stage(stage, include_payloads=include_payloads, formal_count=formal_counts.get(stage.stage_num, 0))
        for stage in stages
    ]


@router.get("/{task_id}/stages/{stage_num}", response_model=AuditStageOut)
async def get_audit_stage_detail(task_id: int, stage_num: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id, AuditStage.stage_num == stage_num)
    )
    stage = result.scalar_one_or_none()
    if not stage:
        raise HTTPException(404, "审计阶段不存在")
    formal_counts = await _get_stage_formal_vuln_counts(db, task_id)
    return _serialize_stage(stage, include_payloads=True, formal_count=formal_counts.get(stage.stage_num, 0))


@router.get("/{task_id}/stages/{stage_num}/artifact")
async def get_audit_stage_artifact(task_id: int, stage_num: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id, AuditStage.stage_num == stage_num)
    )
    stage = result.scalar_one_or_none()
    if not stage:
        raise HTTPException(404, "审计阶段不存在")
    if not stage.artifact_path:
        raise HTTPException(404, "阶段产物不存在")

    artifact_path = resolve_audit_artifact_path(stage.artifact_path)

    if not os.path.isfile(artifact_path):
        raise HTTPException(404, "阶段产物文件不存在")

    try:
        with open(artifact_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as exc:
        raise HTTPException(500, f"读取阶段产物失败：{exc}")

    return {
        "task_id": task_id,
        "stage_num": stage_num,
        "artifact_path": stage.artifact_path,
        "payload": payload,
    }


@router.get("/{task_id}/vulns", response_model=list[VulnerabilityOut])
async def get_audit_vulns(
    task_id: int,
    severity: str = None,
    review_status: str = None,
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Vulnerability)
        .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
        .where(
            Vulnerability.task_id == task_id,
            AuditStage.stage_num.between(2, 9),
        )
    )
    if severity:
        query = query.where(Vulnerability.severity.in_(_severity_match_values(severity)))
    if review_status:
        wanted = [s.strip() for s in review_status.split(",") if s.strip()]
        if wanted:
            query = query.where(Vulnerability.review_status.in_(wanted))
    result = await db.execute(
        query.order_by(_severity_order_expr(Vulnerability.severity).desc(), Vulnerability.id.desc())
    )
    return result.scalars().all()


@router.delete("/{task_id}")
async def delete_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)
    if task.status in {"pending", "running"}:
        raise HTTPException(400, "运行中的审计不能删除，请先取消")

    await delete_audit_task_records(db, task)
    await db.commit()

    return {"message": "审计已删除"}
