from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import func, select

from database import async_session
from models import AuditRun, AuditStage, AuditTask
from services import audit_runtime as rt
from services.config import WORKER_POLL_INTERVAL_SECONDS, WORKER_TASK_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

QUEUE_PENDING_KEY = "_queue_pending"
QUEUE_ENQUEUED_AT_KEY = "_queue_enqueued_at"
QUEUE_CLAIMED_AT_KEY = "_queue_claimed_at"


def _task_summary(task: AuditTask) -> dict:
    return dict(task.summary) if isinstance(task.summary, dict) else {}


def mark_task_queued(task: AuditTask, stage_nums: list[int]) -> None:
    summary = _task_summary(task)
    summary["selected_stage_nums"] = list(stage_nums)
    summary[QUEUE_PENDING_KEY] = True
    summary[QUEUE_ENQUEUED_AT_KEY] = datetime.now(timezone.utc).isoformat()
    summary[QUEUE_CLAIMED_AT_KEY] = None
    summary.pop("worker_failure", None)
    task.summary = dict(summary)
    task.status = "pending"
    task.current_stage = 0
    task.error_message = ""
    task.completed_at = None


def clear_task_queue_state(task: AuditTask) -> None:
    summary = _task_summary(task)
    summary.pop(QUEUE_PENDING_KEY, None)
    summary.pop(QUEUE_ENQUEUED_AT_KEY, None)
    summary.pop(QUEUE_CLAIMED_AT_KEY, None)
    task.summary = dict(summary)


async def finalize_task_queue_state(task_id: int) -> None:
    async with async_session() as session:
        result = await session.execute(select(AuditTask).where(AuditTask.id == task_id))
        task = result.scalar_one_or_none()
        if not task:
            return
        clear_task_queue_state(task)
        await session.commit()


async def mark_task_worker_failed(task_id: int, message: str) -> None:
    async with async_session() as session:
        result = await session.execute(select(AuditTask).where(AuditTask.id == task_id))
        task = result.scalar_one_or_none()
        if not task or task.status in {"completed", "cancelled"}:
            return

        now = datetime.now(timezone.utc)
        summary = _task_summary(task)
        summary["worker_failure"] = {
            "message": message[:500],
            "failed_at": now.isoformat(),
        }

        task.status = "failed"
        task.error_message = message[:2000]
        task.completed_at = now
        task.summary = dict(summary)

        stage_result = await session.execute(
            select(AuditStage).where(
                AuditStage.task_id == task_id,
                AuditStage.status == "running",
            )
        )
        for stage in stage_result.scalars().all():
            stage.status = "failed"
            stage.completed_at = now

        await session.commit()


async def recover_incomplete_audits() -> None:
    async with async_session() as session:
        task_result = await session.execute(select(AuditTask).order_by(AuditTask.id))
        tasks = task_result.scalars().all()
        if not tasks:
            return

        stage_result = await session.execute(select(AuditStage).order_by(AuditStage.task_id, AuditStage.stage_num))
        stages_by_task: dict[int, list[AuditStage]] = {}
        for stage in stage_result.scalars().all():
            stages_by_task.setdefault(stage.task_id, []).append(stage)

        changed = False
        for task in tasks:
            summary = _task_summary(task)
            if not summary.get(QUEUE_PENDING_KEY) and task.status != "running":
                continue

            selected_stage_nums = [
                int(stage_num)
                for stage_num in summary.get("selected_stage_nums", [])
                if isinstance(stage_num, int) or str(stage_num).isdigit()
            ]
            if not selected_stage_nums:
                selected_stage_nums = [stage.stage_num for stage in stages_by_task.get(task.id, [])]

            remaining_stage_nums: list[int] = []
            for stage in stages_by_task.get(task.id, []):
                if stage.stage_num not in selected_stage_nums:
                    continue
                if stage.status == "running":
                    stage.status = "pending"
                    stage.started_at = None
                    stage.completed_at = None
                    changed = True
                if stage.status in {"pending", "running"}:
                    remaining_stage_nums.append(stage.stage_num)

            if not remaining_stage_nums:
                clear_task_queue_state(task)
                changed = True
                continue

            mark_task_queued(task, remaining_stage_nums)
            # 关闭进程重启前遗留的 running 态 run，并记录恢复事件（影子写入，不影响旧逻辑）。
            await _close_stale_runs(session, task.id, reason="worker 重启，任务已重新入队恢复")
            await rt.emit_event(
                session,
                task_id=task.id,
                event_type=rt.EVENT_WORKER_RECOVERED,
                payload={"selected_stage_nums": remaining_stage_nums},
            )
            changed = True

        if changed:
            await session.commit()


async def _close_stale_runs(session, task_id: int, *, reason: str) -> None:
    """将该任务所有非终态 run 标记为 failed（用于进程重启/取消等场景的陈旧清理）。"""
    result = await session.execute(
        select(AuditRun).where(
            AuditRun.task_id == task_id,
            AuditRun.status.notin_(["completed", "failed", "cancelled"]),
        )
    )
    for run in result.scalars().all():
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)
        run.error_message = reason[:2000]


async def _claim_next_task() -> tuple[int, list[int], int] | None:
    """认领下一个待处理任务，并开启一条 running 态 run。

    返回 ``(task_id, stage_nums, run_id)``。
    """
    async with async_session() as session:
        result = await session.execute(select(AuditTask).where(AuditTask.status == "pending").order_by(AuditTask.created_at))
        for task in result.scalars().all():
            summary = _task_summary(task)
            if not summary.get(QUEUE_PENDING_KEY):
                continue
            if summary.get(QUEUE_CLAIMED_AT_KEY):
                continue

            stage_nums = [
                int(stage_num)
                for stage_num in summary.get("selected_stage_nums", [])
                if isinstance(stage_num, int) or str(stage_num).isdigit()
            ]

            summary[QUEUE_CLAIMED_AT_KEY] = datetime.now(timezone.utc).isoformat()
            task.summary = dict(summary)

            # 开启运行记录。mode：首次（无历史 run）记 full，否则 rerun。
            prior_count = (
                await session.execute(select(func.count(AuditRun.id)).where(AuditRun.task_id == task.id))
            ).scalar() or 0
            mode = "full" if prior_count == 0 else "rerun"
            run = await rt.start_run(
                session,
                task_id=task.id,
                mode=mode,
                selected_stage_nums=stage_nums,
            )
            run_id = run.id
            await rt.emit_event(
                session,
                task_id=task.id,
                event_type=rt.EVENT_RUN_STARTED,
                payload={"mode": mode, "selected_stage_nums": stage_nums},
                run_id=run_id,
            )
            await session.commit()
            return task.id, stage_nums, run_id
    return None


async def _ensure_run_failed(run_id: int | None, message: str, *, event_type: str = rt.EVENT_RUN_FAILED) -> None:
    """幂等地把 run 标记为 failed 并发事件；若已终态则什么都不做。"""
    if not run_id:
        return
    async with async_session() as session:
        run = await session.get(AuditRun, run_id)
        if run and run.status not in {"completed", "failed", "cancelled"}:
            run.status = "failed"
            run.completed_at = datetime.now(timezone.utc)
            run.error_message = message[:2000]
            await rt.emit_event(
                session,
                task_id=run.task_id,
                event_type=event_type,
                payload={"message": message[:500]},
                run_id=run_id,
            )
            await session.commit()


async def audit_worker_loop(stop_event: asyncio.Event) -> None:
    logger.info("Audit worker started")
    while not stop_event.is_set():
        claimed = await _claim_next_task()
        if not claimed:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=WORKER_POLL_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass
            continue

        task_id, _stage_nums, run_id = claimed
        try:
            from services.supervisor import run_multi_agent_audit
            await asyncio.wait_for(run_multi_agent_audit(task_id), timeout=WORKER_TASK_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            message = f"审计任务超过 {WORKER_TASK_TIMEOUT_SECONDS} 秒未完成，已由 Worker 标记失败"
            logger.error("Audit worker timed out after %ss on task %s", WORKER_TASK_TIMEOUT_SECONDS, task_id)
            await mark_task_worker_failed(task_id, message)
            # 超时会把 supervisor 的协程取消，supervisor 自身无法捕获 → 这里兜底关闭 run。
            await rt_emit_worker_timeout(task_id, run_id, message)
        except Exception:
            logger.exception("Audit worker failed while executing task %s", task_id)
            await mark_task_worker_failed(task_id, "审计 Worker 执行异常，任务已标记失败")
            # supervisor 自身的 except 通常已 fail 该 run；此处幂等兜底。
            await _ensure_run_failed(run_id, "审计 Worker 执行异常，任务已标记失败")
        finally:
            await finalize_task_queue_state(task_id)

    logger.info("Audit worker stopped")


async def rt_emit_worker_timeout(task_id: int, run_id: int | None, message: str) -> None:
    async with async_session() as session:
        await rt.emit_event(
            session,
            task_id=task_id,
            event_type=rt.EVENT_WORKER_TIMEOUT,
            payload={"timeout_seconds": WORKER_TASK_TIMEOUT_SECONDS, "message": message[:500]},
            run_id=run_id,
        )
        run = await session.get(AuditRun, run_id) if run_id else None
        if run and run.status not in {"completed", "failed", "cancelled"}:
            run.status = "failed"
            run.completed_at = datetime.now(timezone.utc)
            run.error_message = message[:2000]
            await rt.emit_event(
                session,
                task_id=task_id,
                event_type=rt.EVENT_RUN_FAILED,
                payload={"message": message[:500]},
                run_id=run_id,
            )
        await session.commit()
