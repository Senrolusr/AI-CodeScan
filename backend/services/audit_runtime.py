"""运行时状态机服务（M2）。

集中所有 run/subtask/agent_run/event 的写入与查询，避免散落在 worker/supervisor/router。
设计要点：
- 所有写入函数接受调用方传入的 ``AsyncSession``，由调用方控制事务边界
  （supervisor 用自身 session → 与 stage 写入同事务、顺序一致；
   worker 自开 session）。
- ``emit_event`` 在未显式传 ``run_id`` 时，自动绑定该任务最新的非终态 run。
- 仅做**影子写入**：不读取、不修改 ``AuditTask.summary``，旧逻辑完全不受影响。

参见改造文档第 9.2 节。
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditAgentRun, AuditEvent, AuditRun, AuditSubtask, AuditTask

logger = logging.getLogger(__name__)

# ── 事件类型枚举（改造文档 9.2）─────────────────────────────────────────────
EVENT_RUN_QUEUED = "run.queued"
EVENT_RUN_STARTED = "run.started"
EVENT_RUN_COMPLETED = "run.completed"
EVENT_RUN_FAILED = "run.failed"
EVENT_RUN_CANCELLED = "run.cancelled"
EVENT_RUN_PAUSED = "run.paused"
EVENT_RUN_RESUMED = "run.resumed"
EVENT_PHASE_CHANGED = "phase.changed"
EVENT_STAGE_STARTED = "stage.started"
EVENT_STAGE_COMPLETED = "stage.completed"
EVENT_STAGE_FAILED = "stage.failed"
EVENT_STAGE_SKIPPED = "stage.skipped"
EVENT_REVIEW_STARTED = "review.started"
EVENT_REVIEW_COMPLETED = "review.completed"
EVENT_RERUN_REQUESTED = "rerun.requested"
EVENT_STAGE_RESET_FOR_RERUN = "stage.reset_for_rerun"
EVENT_AGENT_STARTED = "agent.started"
EVENT_AGENT_COMPLETED = "agent.completed"
EVENT_AGENT_FAILED = "agent.failed"
EVENT_FINDING_CREATED = "finding.created"
EVENT_FINDING_FILTERED = "finding.filtered"
EVENT_ARTIFACT_WRITTEN = "artifact.written"
EVENT_WORKER_TIMEOUT = "worker.timeout"
EVENT_WORKER_RECOVERED = "worker.recovered"

EVENT_TYPES = frozenset(
    {
        EVENT_RUN_QUEUED,
        EVENT_RUN_STARTED,
        EVENT_RUN_COMPLETED,
        EVENT_RUN_FAILED,
        EVENT_RUN_CANCELLED,
        EVENT_RUN_PAUSED,
        EVENT_RUN_RESUMED,
        EVENT_PHASE_CHANGED,
        EVENT_STAGE_STARTED,
        EVENT_STAGE_COMPLETED,
        EVENT_STAGE_FAILED,
        EVENT_STAGE_SKIPPED,
        EVENT_REVIEW_STARTED,
        EVENT_REVIEW_COMPLETED,
        EVENT_RERUN_REQUESTED,
        EVENT_STAGE_RESET_FOR_RERUN,
        EVENT_AGENT_STARTED,
        EVENT_AGENT_COMPLETED,
        EVENT_AGENT_FAILED,
        EVENT_FINDING_CREATED,
        EVENT_FINDING_FILTERED,
        EVENT_ARTIFACT_WRITTEN,
        EVENT_WORKER_TIMEOUT,
        EVENT_WORKER_RECOVERED,
    }
)

_TERMINAL_RUN_STATUSES = {"completed", "failed", "cancelled"}

# AuditTask 的终态（SSE 流据此判定「事件已排空且任务结束」→ 关闭流）。
TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})

# SSE 流参数（§11.3）。
SSE_POLL_INTERVAL_SECONDS = 2.0  # 每轮轮询新事件的间隔
SSE_MAX_LIFETIME_SECONDS = 600.0  # 单条流最长存活（10 分钟）→ 让客户端重连，避免无限流
SSE_BATCH_LIMIT = 100  # 每轮拉取的事件上限（list_events 内部再 clamp 到 [1,500]）
RUN_DIAGNOSTIC_STALL_THRESHOLD_SECONDS = 15 * 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    value = _utc(value)
    return value.isoformat() if value else None


# ── Run 生命周期 ─────────────────────────────────────────────────────────────
async def start_run(
    session: AsyncSession,
    task_id: int,
    *,
    mode: str = "full",
    selected_stage_nums: list[int] | None = None,
) -> AuditRun:
    """创建一条 running 态的 run 并返回。调用方负责 commit。"""
    run = AuditRun(
        task_id=task_id,
        status="running",
        mode=mode,
        selected_stage_nums=list(selected_stage_nums or []),
        started_at=_now(),
    )
    session.add(run)
    await session.flush()
    return run


async def complete_run(session: AsyncSession, run_id: int) -> None:
    run = await session.get(AuditRun, run_id)
    if run and run.status not in _TERMINAL_RUN_STATUSES:
        run.status = "completed"
        run.completed_at = _now()


async def fail_run(session: AsyncSession, run_id: int, message: str) -> None:
    run = await session.get(AuditRun, run_id)
    if run and run.status not in _TERMINAL_RUN_STATUSES:
        run.status = "failed"
        run.completed_at = _now()
        run.error_message = (message or "")[:2000]


async def get_current_run(session: AsyncSession, task_id: int) -> AuditRun | None:
    """取该任务最新的非终态 run；若全部已终态则返回最近一条 run。"""
    result = await session.execute(
        select(AuditRun)
        .where(
            AuditRun.task_id == task_id,
            AuditRun.status.notin_(list(_TERMINAL_RUN_STATUSES)),
        )
        .order_by(AuditRun.id.desc())
        .limit(1)
    )
    run = result.scalar_one_or_none()
    if run is not None:
        return run
    # 回退：取最近一条（已终态），供事件回溯绑定。
    result = await session.execute(
        select(AuditRun)
        .where(AuditRun.task_id == task_id)
        .order_by(AuditRun.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def list_runs(session: AsyncSession, task_id: int) -> list[AuditRun]:
    """返回该任务全部 run，按 id 倒序（最新优先）。供 ``GET /runs`` 列表消费。"""
    result = await session.execute(
        select(AuditRun).where(AuditRun.task_id == task_id).order_by(AuditRun.id.desc())
    )
    return list(result.scalars().all())


async def get_run(session: AsyncSession, task_id: int, run_id: int) -> AuditRun | None:
    """取单个 run（带 task_id 约束，防越权串读别的任务的 run）。供 ``GET /runs/{run_id}`` 详情。"""
    result = await session.execute(
        select(AuditRun).where(AuditRun.id == run_id, AuditRun.task_id == task_id)
    )
    return result.scalar_one_or_none()


# ── 事件 ─────────────────────────────────────────────────────────────────────
async def emit_event(
    session: AsyncSession,
    *,
    task_id: int,
    event_type: str,
    payload: dict[str, Any] | None = None,
    stage_num: int | None = None,
    run_id: int | None = None,
) -> AuditEvent | None:
    """写入一条事件。``run_id`` 缺省时自动绑定当前 run。

    事件写入失败不应中断主审计流程，故内部捕获异常仅记录日志。
    """
    try:
        if run_id is None:
            run = await get_current_run(session, task_id)
            run_id = run.id if run else None
        event = AuditEvent(
            task_id=task_id,
            run_id=run_id,
            stage_num=stage_num,
            event_type=event_type,
            payload=dict(payload or {}),
        )
        session.add(event)
        await session.flush()
        return event
    except Exception:  # noqa: BLE001 - 事件流是辅助观测，不能阻断审计
        logger.exception("emit_event failed (task=%s type=%s)", task_id, event_type)
        return None


# ── AgentRun ─────────────────────────────────────────────────────────────────
async def record_agent_run(
    session: AsyncSession,
    *,
    task_id: int,
    agent_role: str,
    status: str,
    run_id: int | None = None,
    stage_num: int | None = None,
    subtask_id: int | None = None,
    llm_config_id: int | None = None,
    attempt: int = 1,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    latency_ms: int | None = None,
    finish_reason: str | None = None,
    error_message: str | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> AuditAgentRun | None:
    """记录一次 Agent 执行尝试。失败仅记日志，不阻断审计。"""
    try:
        if run_id is None:
            run = await get_current_run(session, task_id)
            run_id = run.id if run else None
        agent_run = AuditAgentRun(
            task_id=task_id,
            subtask_id=subtask_id,
            run_id=run_id,
            stage_num=stage_num,
            agent_role=agent_role,
            attempt=attempt,
            llm_config_id=llm_config_id,
            status=status,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            finish_reason=(finish_reason or ""),
            error_message=(error_message or "")[:2000],
            started_at=started_at or (datetime.now(timezone.utc) if status != "running" else None),
            completed_at=completed_at or (datetime.now(timezone.utc) if status != "running" else None),
        )
        session.add(agent_run)
        await session.flush()
        return agent_run
    except Exception:  # noqa: BLE001
        logger.exception("record_agent_run failed (task=%s role=%s)", task_id, agent_role)
        return None


# ── Subtask（阶段在一次 run 内的执行计划项；M2 影子写入）──────────────────────
async def start_subtask(
    session: AsyncSession,
    *,
    task_id: int,
    stage_num: int,
    role: str,
    run_id: int | None = None,
    status: str = "running",
    reason: str = "",
) -> AuditSubtask | None:
    """创建一条 subtask（默认 running；``status="skipped"`` 用于规划阶段就被跳过者）。

    ``run_id`` 缺省自动绑定当前 run；无活动 run 时返回 None。
    影子写入：失败仅记日志、不阻断审计。
    """
    try:
        if run_id is None:
            run = await get_current_run(session, task_id)
            run_id = run.id if run else None
        if run_id is None:
            return None
        subtask = AuditSubtask(
            task_id=task_id,
            run_id=run_id,
            stage_num=stage_num,
            role=role,
            status=status,
            attempt_count=1,
            started_at=_now() if status == "running" else None,
        )
        if status != "running" and reason:
            subtask.blocked_reason = reason[:2000]
        session.add(subtask)
        await session.flush()
        return subtask
    except Exception:  # noqa: BLE001
        logger.exception("start_subtask failed (task=%s stage=%s)", task_id, stage_num)
        return None


async def _set_subtask_status(
    session: AsyncSession,
    subtask_id: int | None,
    status: str,
    *,
    reason: str = "",
) -> None:
    """把 running 态 subtask 推到终态（completed/failed/skipped/cancelled）。

    ``subtask_id`` 为 None 时空操作；非 running 态不再覆盖（避免终态被改写）。
    """
    if not subtask_id:
        return
    try:
        subtask = await session.get(AuditSubtask, subtask_id)
        if subtask and subtask.status == "running":
            subtask.status = status
            subtask.completed_at = _now()
            if status in {"failed", "skipped"} and reason:
                subtask.blocked_reason = reason[:2000]
    except Exception:  # noqa: BLE001
        logger.exception("set_subtask_status failed (id=%s status=%s)", subtask_id, status)


async def complete_subtask(session: AsyncSession, subtask_id: int | None) -> None:
    await _set_subtask_status(session, subtask_id, "completed")


async def fail_subtask(session: AsyncSession, subtask_id: int | None, reason: str = "") -> None:
    await _set_subtask_status(session, subtask_id, "failed", reason=reason)


async def skip_subtask(session: AsyncSession, subtask_id: int | None, reason: str = "") -> None:
    await _set_subtask_status(session, subtask_id, "skipped", reason=reason)


# ── 查询（供 API 使用）──────────────────────────────────────────────────────
async def list_events(
    session: AsyncSession,
    task_id: int,
    *,
    limit: int = 100,
    after_id: int = 0,
) -> list[AuditEvent]:
    """返回该任务 id > after_id 的事件，按 id 正序，最多 limit 条。"""
    limit = max(1, min(int(limit or 100), 500))
    result = await session.execute(
        select(AuditEvent)
        .where(AuditEvent.task_id == task_id, AuditEvent.id > after_id)
        .order_by(AuditEvent.id.asc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def list_recent_events(session: AsyncSession, task_id: int, *, limit: int = 100) -> list[AuditEvent]:
    limit = max(1, min(int(limit or 100), 500))
    result = await session.execute(
        select(AuditEvent)
        .where(AuditEvent.task_id == task_id)
        .order_by(AuditEvent.id.desc())
        .limit(limit)
    )
    events = list(result.scalars().all())
    events.reverse()
    return events


async def list_agent_runs(session: AsyncSession, run_id: int) -> list[AuditAgentRun]:
    result = await session.execute(
        select(AuditAgentRun)
        .where(AuditAgentRun.run_id == run_id)
        .order_by(AuditAgentRun.id.asc())
    )
    return list(result.scalars().all())


async def list_subtasks(session: AsyncSession, run_id: int) -> list[AuditSubtask]:
    """返回某 run 的全部 subtask，按 id 正序（创建顺序）。供 snapshot 暴露。"""
    result = await session.execute(
        select(AuditSubtask)
        .where(AuditSubtask.run_id == run_id)
        .order_by(AuditSubtask.id.asc())
    )
    return list(result.scalars().all())


def _event_progress_time(event: AuditEvent) -> datetime | None:
    return _utc(getattr(event, "created_at", None))


def _status_priority(items: list[Any], statuses: set[str]) -> Any | None:
    for item in items:
        if getattr(item, "status", None) in statuses:
            return item
    return None


def _latest_event(events: list[AuditEvent]) -> AuditEvent | None:
    if not events:
        return None
    return max(
        events,
        key=lambda event: (
            _event_progress_time(event) or datetime.min.replace(tzinfo=timezone.utc),
            int(getattr(event, "id", 0) or 0),
        ),
    )


def _latest_progress_at(
    run: AuditRun | None,
    subtasks: list[AuditSubtask],
    agent_runs: list[AuditAgentRun],
    events: list[AuditEvent],
) -> datetime | None:
    candidates: list[datetime] = []
    if run:
        for value in [run.started_at, run.completed_at, run.created_at]:
            normalized = _utc(value)
            if normalized:
                candidates.append(normalized)
    for subtask in subtasks:
        for value in [subtask.started_at, subtask.completed_at]:
            normalized = _utc(value)
            if normalized:
                candidates.append(normalized)
    for agent_run in agent_runs:
        for value in [agent_run.started_at, agent_run.completed_at]:
            normalized = _utc(value)
            if normalized:
                candidates.append(normalized)
    for event in events:
        normalized = _event_progress_time(event)
        if normalized:
            candidates.append(normalized)
    return max(candidates) if candidates else None


def _event_message(event: AuditEvent | None) -> str:
    if not event:
        return ""
    payload = event.payload if isinstance(event.payload, dict) else {}
    for key in ["message", "reason", "error", "note", "status"]:
        value = payload.get(key)
        if value not in (None, "", [], {}):
            return str(value)[:500]
    return str(event.event_type or "")[:500]


def _diagnostic_base(
    *,
    task: AuditTask,
    run: AuditRun | None,
    subtasks: list[AuditSubtask],
    agent_runs: list[AuditAgentRun],
    events: list[AuditEvent],
    now: datetime,
) -> dict:
    latest = _latest_event(events)
    last_progress_at = _latest_progress_at(run, subtasks, agent_runs, events)
    silence_seconds = None
    if last_progress_at:
        silence_seconds = max(0, int((now - last_progress_at).total_seconds()))
    active_agent = _status_priority(agent_runs, {"running"})
    focus_subtask = _status_priority(subtasks, {"running"})
    current_stage_num = (
        getattr(focus_subtask, "stage_num", None)
        if focus_subtask is not None
        else getattr(active_agent, "stage_num", None)
    )
    current_role = (
        getattr(focus_subtask, "role", None)
        if focus_subtask is not None
        else getattr(active_agent, "agent_role", None)
    )
    return {
        "focus_status": "not_started",
        "focus_reason": "审计尚未开始",
        "current_stage_num": current_stage_num,
        "current_role": current_role or "",
        "focus_subtask_id": getattr(focus_subtask, "id", None),
        "active_agent_run_id": getattr(active_agent, "id", None),
        "blocked_reason": "",
        "error_message": "",
        "latest_event_type": getattr(latest, "event_type", None),
        "latest_event_message": _event_message(latest),
        "latest_event_at": _iso(getattr(latest, "created_at", None)),
        "last_progress_at": _iso(last_progress_at),
        "silence_seconds": silence_seconds,
        "stalled": False,
        "stall_threshold_seconds": RUN_DIAGNOSTIC_STALL_THRESHOLD_SECONDS,
        "run_id": getattr(run, "id", None),
        "run_status": getattr(run, "status", None),
        "task_status": getattr(task, "status", None),
    }


def build_run_diagnostics(
    task: AuditTask,
    run: AuditRun | None,
    subtasks: list[AuditSubtask] | None,
    agent_runs: list[AuditAgentRun] | None,
    events: list[AuditEvent] | None,
    *,
    now: datetime | None = None,
    stall_threshold_seconds: int = RUN_DIAGNOSTIC_STALL_THRESHOLD_SECONDS,
) -> dict:
    """Build a stable snapshot diagnosis for the current audit run.

    The router supplies already-loaded rows; this pure function keeps status
    inference in one place and avoids frontend-side guessing.
    """
    subtasks = list(subtasks or [])
    agent_runs = list(agent_runs or [])
    events = list(events or [])
    now = _utc(now) or _now()
    base = _diagnostic_base(
        task=task,
        run=run,
        subtasks=subtasks,
        agent_runs=agent_runs,
        events=events,
        now=now,
    )
    base["stall_threshold_seconds"] = int(stall_threshold_seconds or RUN_DIAGNOSTIC_STALL_THRESHOLD_SECONDS)
    task_summary = getattr(task, "summary", None)
    orchestration_guard = (
        task_summary.get("orchestration_guard")
        if isinstance(task_summary, dict) and isinstance(task_summary.get("orchestration_guard"), dict)
        else {}
    )
    base["orchestration_guard"] = orchestration_guard

    def finish(status: str, reason: str, **updates: Any) -> dict:
        base.update({"focus_status": status, "focus_reason": reason})
        base.update(updates)
        if (
            status in {"running", "starting", "waiting"}
            and isinstance(base.get("silence_seconds"), int)
            and base["silence_seconds"] >= base["stall_threshold_seconds"]
        ):
            base["focus_status"] = "stalled"
            base["focus_reason"] = "运行中超过阈值未记录新进展"
            base["stalled"] = True
        return base

    task_status = str(getattr(task, "status", "") or "")
    run_status = str(getattr(run, "status", "") or "") if run else ""
    task_error = str(getattr(task, "error_message", "") or "")
    run_error = str(getattr(run, "error_message", "") or "") if run else ""
    guard_status = str(orchestration_guard.get("status", "") or "")
    guard_message = str(orchestration_guard.get("message", "") or "")

    if task_status == "paused" or run_status == "paused":
        return finish("paused", "审计已暂停", blocked_reason=run_error or "审计已暂停")

    cancelled_subtask = _status_priority(subtasks, {"cancelled"})
    if task_status == "cancelled" or run_status == "cancelled" or cancelled_subtask:
        return finish(
            "cancelled",
            "审计已取消",
            current_stage_num=getattr(cancelled_subtask, "stage_num", base.get("current_stage_num")),
            current_role=getattr(cancelled_subtask, "role", base.get("current_role")),
            focus_subtask_id=getattr(cancelled_subtask, "id", base.get("focus_subtask_id")),
            blocked_reason=run_error or task_error or str(getattr(cancelled_subtask, "blocked_reason", "") or "审计已取消"),
        )

    if guard_status == "blocked" and task_status != "completed":
        unresolved = orchestration_guard.get("unresolved_stage_nums")
        current_stage_num = None
        if isinstance(unresolved, list) and unresolved:
            current_stage_num = unresolved[0]
        return finish(
            "blocked",
            guard_message or "阶段三并行审计未收敛，已阻止进入复核",
            current_stage_num=current_stage_num or base.get("current_stage_num"),
            current_role="sub_agent",
            blocked_reason=guard_message or task_error or run_error,
            error_message=task_error or run_error or guard_message,
        )

    failed_subtask = _status_priority(subtasks, {"failed"})
    failed_agent = _status_priority(agent_runs, {"failed"})
    if task_status == "failed" or run_status == "failed" or failed_subtask or failed_agent:
        error_message = (
            getattr(failed_subtask, "blocked_reason", "")
            or getattr(failed_agent, "error_message", "")
            or run_error
            or task_error
        )
        return finish(
            "failed",
            "审计执行失败",
            current_stage_num=getattr(failed_subtask, "stage_num", base.get("current_stage_num")),
            current_role=getattr(failed_subtask, "role", base.get("current_role")),
            focus_subtask_id=getattr(failed_subtask, "id", base.get("focus_subtask_id")),
            active_agent_run_id=getattr(failed_agent, "id", base.get("active_agent_run_id")),
            blocked_reason=str(getattr(failed_subtask, "blocked_reason", "") or ""),
            error_message=str(error_message or "")[:2000],
        )

    blocked_subtask = _status_priority(subtasks, {"blocked"})
    if blocked_subtask:
        reason = str(getattr(blocked_subtask, "blocked_reason", "") or "子任务被阻塞")
        return finish(
            "blocked",
            reason,
            current_stage_num=blocked_subtask.stage_num,
            current_role=blocked_subtask.role,
            focus_subtask_id=blocked_subtask.id,
            blocked_reason=reason,
        )

    running_subtask = _status_priority(subtasks, {"running"})
    running_agent = _status_priority(agent_runs, {"running"})
    if running_subtask or running_agent or run_status == "running" or task_status == "running":
        return finish(
            "running",
            "审计正在执行",
            current_stage_num=getattr(running_subtask, "stage_num", getattr(running_agent, "stage_num", None)),
            current_role=getattr(running_subtask, "role", getattr(running_agent, "agent_role", "")) or "",
            focus_subtask_id=getattr(running_subtask, "id", None),
            active_agent_run_id=getattr(running_agent, "id", None),
        )

    if task_status == "pending" or run_status == "pending":
        return finish("starting", "审计已排队，等待 worker 认领")

    skipped_or_pending = _status_priority(subtasks, {"skipped", "pending"})
    if skipped_or_pending and task_status not in TERMINAL_TASK_STATUSES:
        reason = str(getattr(skipped_or_pending, "blocked_reason", "") or "等待后续阶段推进")
        return finish(
            "waiting",
            reason,
            current_stage_num=skipped_or_pending.stage_num,
            current_role=skipped_or_pending.role,
            focus_subtask_id=skipped_or_pending.id,
            blocked_reason=str(getattr(skipped_or_pending, "blocked_reason", "") or ""),
        )

    if task_status == "completed" or run_status == "completed":
        return finish("completed", "审计已完成")

    if run is not None:
        return finish("waiting", "运行记录存在但当前没有活动子任务")

    return base


# ── 事件序列化 / SSE 流（§11.3）─────────────────────────────────────────────
def serialize_event(event: AuditEvent) -> dict:
    """事件 → 稳定 view model（routers 的 JSON ``/events`` 与 SSE ``/events/stream`` 共用）。

    ``created_at`` 显式转 ISO 字符串：SSE 端用 ``json.dumps`` 手写帧，datetime 不可直接序列化；
    JSON 端经 FastAPI 序列化时 ISO 字符串与原 datetime 输出同形（additive，契约不变）。
    """
    return {
        "id": event.id,
        "task_id": event.task_id,
        "run_id": event.run_id,
        "stage_num": event.stage_num,
        "event_type": event.event_type,
        "payload": event.payload if isinstance(event.payload, dict) else {},
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


def _sse_data(payload: dict, *, id_: int) -> str:
    """组装一条 SSE 帧：``id:\\ndata:\\n\\n``。

    不带 ``event:`` 字段 → 前端 ``EventSource.onmessage`` 统一接收所有帧
    （``event_type`` 已在 payload 内，前端无需逐类型 addEventListener）。
    """
    return f"id: {id_}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


async def iter_event_stream(task_id: int, last_event_id: int = 0) -> AsyncIterator[str]:
    """SSE 异步生成器：按 ``last_event_id`` 增量轮询 ``list_events`` 并逐帧 yield。

    - 增量语义：每帧带 ``id:``，前端 EventSource 断线重连时浏览器自动带 ``Last-Event-ID``，
      router 透传为 ``last_event_id``，实现断点续传、不丢不重（前端按 id 去重双保险）。
    - 终止：任务进入终态且本轮无新事件 → 自然结束（return）；否则每轮间发 ``: ping`` 心跳保活。
    - 防泄漏：``SSE_MAX_LIFETIME_SECONDS`` 到点强制结束，客户端 EventSource 自动重连开新流。
    - 会话：每轮独立 ``async with database.async_session()``（流的生命周期超出单次请求的 get_db
      会话）。动态引用 ``database.async_session``（局部 import 模块对象），便于测试 monkeypatch。
    """
    import database  # 局部引用模块对象 → 测试可 monkeypatch database.async_session

    last_id = int(last_event_id or 0)
    deadline = time.monotonic() + SSE_MAX_LIFETIME_SECONDS
    while time.monotonic() < deadline:
        terminal_drained = False
        async with database.async_session() as db:
            task = (
                await db.execute(select(AuditTask).where(AuditTask.id == task_id))
            ).scalar_one_or_none()
            if task is None:
                # 任务被删除：发一条收尾帧后关闭。
                yield _sse_data({"type": "task.deleted", "task_id": task_id}, id_=last_id)
                return
            events = await list_events(db, task_id, limit=SSE_BATCH_LIMIT, after_id=last_id)
            for e in events:
                yield _sse_data(serialize_event(e), id_=e.id)
                last_id = e.id
            # 终态 + 本轮未拉满（已排空）→ 关流。
            # 用 ``len < SSE_BATCH_LIMIT`` 而非 ``not events``：首轮有事件时 ``not events`` 为假，
            # 会多发一个心跳并多睡一拍才关；改判「本轮不满批量」即可在终态首轮就干净结束。
            terminal_drained = task.status in TERMINAL_TASK_STATUSES and len(events) < SSE_BATCH_LIMIT
        if terminal_drained:
            return
        yield ": ping\n\n"
        await asyncio.sleep(SSE_POLL_INTERVAL_SECONDS)
