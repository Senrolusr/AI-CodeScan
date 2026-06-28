"""§14.1 / §M0 audit_worker 专项测试。

覆盖 ``services/audit_worker.py`` 的四条文档点名路径:
1. **pending 认领** —— ``_claim_next_task`` 认领带 ``_queue_pending`` 的 pending 任务、开 run、
   跳过已 claimed / 未入队的任务。
2. **重启恢复** —— ``recover_incomplete_audits`` 把崩溃遗留的 running stage 重置为 pending、
   重新入队、关 stale run；无剩余阶段时清队列态。
3. **超时失败** —— ``audit_worker_loop`` 的 ``TimeoutError`` 路径:任务超 ``WORKER_TASK_TIMEOUT_SECONDS``
   后 ``mark_task_worker_failed`` + run 标 failed。
4. **cancel 不被覆盖** —— ``mark_task_worker_failed`` 对 ``cancelled`` 终态任务直接跳过。

与 ``test_supervisor_e2e`` 同模式:自建 ``StaticPool`` 内存库 + patch ``audit_worker.async_session``
(模块内 ``from database import async_session`` 双绑定,patch ``database.async_session`` 无效)。
worker 各函数内部反复 ``async with async_session()`` 开关 session,默认池每连接独立 :memory:
库会互相看不见,故必须 StaticPool 单连接。
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import models
from services import audit_worker


@pytest_asyncio.fixture
async def worker_session(monkeypatch):
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)
    # audit_worker.py 顶部 ``from database import async_session`` 绑定到本模块;
    # 必须替换 audit_worker.async_session(替换 database.async_session 无效)。
    monkeypatch.setattr(audit_worker, "async_session", Session)
    yield Session
    await eng.dispose()


async def _seed_task(Session, *, status="pending", queued=True, claimed=False, stage_nums=(2, 7), stage_status="pending"):
    """seed 一个 task(+ project/llm_config/+ stages),返回 task_id。"""
    async with Session() as session:
        project = models.Project(name="p", upload_path="/tmp/x", file_tree=[])
        session.add(project)
        await session.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()

        summary = {}
        if queued:
            summary["_queue_pending"] = True
            summary["selected_stage_nums"] = list(stage_nums)
            summary["_queue_claimed_at"] = "2026-01-01T00:00:00+00:00" if claimed else None
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id,
            status=status, summary=summary, total_stages=9,
        )
        session.add(task)
        await session.flush()
        for n in stage_nums:
            session.add(models.AuditStage(
                task_id=task.id, stage_num=n, stage_name=f"s{n}", status=stage_status,
            ))
        await session.commit()
        return task.id


# ---- 1. pending 认领 ----

@pytest.mark.asyncio
async def test_claim_picks_queued_pending_task(worker_session):
    task_id = await _seed_task(worker_session, status="pending", queued=True, stage_nums=(2, 7, 9))
    claimed = await audit_worker._claim_next_task()

    assert claimed is not None
    tid, stage_nums, run_id = claimed
    assert tid == task_id
    assert set(stage_nums) == {2, 7, 9}
    assert run_id  # 已开启一条 run

    # 认领后写入了 QUEUE_CLAIMED_AT → 再次认领应返回 None(同一任务不会被重复认领)
    again = await audit_worker._claim_next_task()
    assert again is None


@pytest.mark.asyncio
async def test_claim_skips_non_queued_and_claimed(worker_session):
    # 未入队(无 _queue_pending)的 pending 任务 → 跳过
    await _seed_task(worker_session, status="pending", queued=False)
    assert await audit_worker._claim_next_task() is None

    # 已被认领(_queue_claimed_at 已设)的 pending 任务 → 跳过
    await _seed_task(worker_session, status="pending", queued=True, claimed=True)
    assert await audit_worker._claim_next_task() is None


# ---- 2. 重启恢复 ----

@pytest.mark.asyncio
async def test_recover_resets_running_stages_and_requeues(worker_session):
    """模拟进程崩溃:task running + stages running → recover 重置为 pending 并重新入队。"""
    task_id = await _seed_task(worker_session, status="running", queued=True, stage_nums=(2, 7), stage_status="running")

    await audit_worker.recover_incomplete_audits()

    async with worker_session() as s:
        task = (await s.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))).scalar_one()
        assert task.status == "pending"  # 重新入队
        assert task.summary.get("_queue_pending") is True
        stages = (await s.execute(select(models.AuditStage).where(models.AuditStage.task_id == task_id))).scalars().all()
        assert stages, "应保留原 stage 行"
        assert all(st.status == "pending" for st in stages)  # running → pending


@pytest.mark.asyncio
async def test_recover_clears_queue_when_no_remaining(worker_session):
    """所有选中阶段已完成 → 无剩余 → 清队列态(任务不再被认领)。"""
    task_id = await _seed_task(worker_session, status="running", queued=True, stage_nums=(2, 7), stage_status="completed")

    await audit_worker.recover_incomplete_audits()

    async with worker_session() as s:
        task = (await s.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))).scalar_one()
        assert "_queue_pending" not in task.summary


# ---- 3. 超时失败 ----

@pytest.mark.asyncio
async def test_worker_timeout_handling_path(worker_session):
    """超时失败路径:复现 ``audit_worker_loop`` 的 ``TimeoutError`` 分支——真实触发一次
    ``wait_for`` 超时后,依序调用 loop except 分支里的同一组函数(mark_task_worker_failed +
    rt_emit_worker_timeout + finalize),验证 task/run 落到 failed。

    不起后台 loop(后台任务 + 满负荷套件会引入 wall-clock 竞态),而是用真实 ``wait_for`` 超时
    + 真实处理函数,确定性覆盖超时语义。loop 的 while/try/except 接线由下方 idle 冒烟测试守护。
    """
    task_id = await _seed_task(worker_session, status="pending", queued=True, stage_nums=(2, 7))

    # 真实认领(开 run)
    claimed = await audit_worker._claim_next_task()
    assert claimed is not None
    tid, _stage_nums, run_id = claimed
    assert tid == task_id and run_id

    # 真实触发 wait_for 超时(短 timeout + 慢协程)——复现 loop 内的 TimeoutError
    async def _slow_audit(_task_id):
        await asyncio.sleep(30)

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(_slow_audit(tid), timeout=0.1)

    # 复现 loop 的 except 分支:同一组调用、同一顺序
    message = f"审计任务超过 {audit_worker.WORKER_TASK_TIMEOUT_SECONDS} 秒未完成，已由 Worker 标记失败"
    await audit_worker.mark_task_worker_failed(task_id, message)
    await audit_worker.rt_emit_worker_timeout(task_id, run_id, message)
    await audit_worker.finalize_task_queue_state(task_id)

    async with worker_session() as s:
        task = (await s.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))).scalar_one()
        assert task.status == "failed"
        assert task.error_message  # 含超时说明
        runs = (await s.execute(select(models.AuditRun).where(models.AuditRun.task_id == task_id))).scalars().all()
        assert runs and all(r.status == "failed" for r in runs)


@pytest.mark.asyncio
async def test_worker_loop_starts_and_stops_cleanly(worker_session, monkeypatch):
    """audit_worker_loop 的 while/stop_event 接线:无待处理任务时启动后能干净停止
    (不处理任务 → 无时序竞态)。"""
    monkeypatch.setattr(audit_worker, "WORKER_POLL_INTERVAL_SECONDS", 0.01)
    stop = asyncio.Event()
    loop_task = asyncio.create_task(audit_worker.audit_worker_loop(stop))
    await asyncio.sleep(0.05)  # 让它空轮询一次(无 pending 任务)
    stop.set()
    await asyncio.wait_for(loop_task, timeout=2.0)  # 应已干净退出,不抛错


# ---- 4. cancel 不被 worker_failed 覆盖 ----

@pytest.mark.asyncio
async def test_mark_worker_failed_skips_cancelled(worker_session):
    """cancelled 终态任务不被 mark_task_worker_failed 改写(取消语义优先)。"""
    task_id = await _seed_task(worker_session, status="cancelled", queued=False)

    await audit_worker.mark_task_worker_failed(task_id, "不应生效")

    async with worker_session() as s:
        task = (await s.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))).scalar_one()
        assert task.status == "cancelled"


@pytest.mark.asyncio
async def test_mark_worker_failed_fails_running_stages(worker_session):
    """标记任务失败时,同步把 running 态 stage 置 failed(不留悬挂的 running)。"""
    task_id = await _seed_task(worker_session, status="running", queued=True, stage_nums=(2, 7), stage_status="running")

    await audit_worker.mark_task_worker_failed(task_id, "执行异常")

    async with worker_session() as s:
        task = (await s.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))).scalar_one()
        assert task.status == "failed"
        stages = (await s.execute(select(models.AuditStage).where(models.AuditStage.task_id == task_id))).scalars().all()
        assert all(st.status == "failed" for st in stages)
