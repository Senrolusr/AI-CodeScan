from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from database import async_session
from models import AuditStage, AuditTask
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
            changed = True

        if changed:
            await session.commit()


async def _claim_next_task() -> tuple[int, list[int], int | None] | None:
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

            phase_num = None
            if summary.get("multi_agent_phase_mode"):
                phase_num = summary.get("current_phase", 1)
            elif not stage_nums:
                phase_num = 1

            summary[QUEUE_CLAIMED_AT_KEY] = datetime.now(timezone.utc).isoformat()
            task.summary = dict(summary)
            await session.commit()
            return task.id, stage_nums, phase_num
    return None


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

        task_id, stage_nums, phase_num = claimed
        try:
            if phase_num is not None:
                from services.supervisor import run_multi_agent_phase
                await asyncio.wait_for(run_multi_agent_phase(task_id, phase_num), timeout=WORKER_TASK_TIMEOUT_SECONDS)
            else:
                from services.supervisor import run_multi_agent_phase
                await asyncio.wait_for(run_multi_agent_phase(task_id, 1), timeout=WORKER_TASK_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            logger.error("Audit worker timed out after %ss on task %s", WORKER_TASK_TIMEOUT_SECONDS, task_id)
        except Exception:
            logger.exception("Audit worker failed while executing task %s", task_id)
        finally:
            await finalize_task_queue_state(task_id)

    logger.info("Audit worker stopped")
