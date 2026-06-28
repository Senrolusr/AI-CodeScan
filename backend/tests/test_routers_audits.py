"""§14.1 routers 端到端测试:API 状态码、统一错误结构、删除运行中任务限制、cancel/retry 业务约束。

走 httpx AsyncClient + ASGITransport(经 conftest ``db_client`` fixture:内存库 +
seed admin token),断言 router 级 HTTP 行为而非内部函数。覆盖文档 §14.1 行1174 点名项。

核心断言:
- **统一错误结构**:404 返 ``{code,message,details}``(§11.4);400 经全局 handler 包成 ``HTTP_400``。
- **删除运行中任务限制**:DELETE 运行中/待处理 → 400;已完成/取消/失败 → 200;不存在 → 404。
- **cancel/retry 状态约束**:非法状态 → 400;合法 → 状态迁移正确。
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

import models


async def _seed(Session, status: str, *, with_stages=False, stage_status="completed"):
    """seed project+llm_config+task(+可选 stages),返回 (task_id, project_id, cfg_id)。"""
    async with Session() as s:
        proj = models.Project(name="p", upload_path="/tmp/x", file_tree=[])
        s.add(proj)
        await s.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        s.add(cfg)
        await s.flush()
        task = models.AuditTask(
            project_id=proj.id, llm_config_id=cfg.id,
            status=status, summary={}, total_stages=9,
        )
        s.add(task)
        await s.flush()
        if with_stages:
            for n in (2, 7):
                s.add(models.AuditStage(
                    task_id=task.id, stage_num=n, stage_name=f"s{n}", status=stage_status,
                ))
        await s.commit()
        return task.id, proj.id, cfg.id


# ---- 统一错误结构(§11.4)----

@pytest.mark.asyncio
async def test_get_missing_task_returns_unified_error(db_client):
    client, _ = db_client
    r = await client.get("/api/audits/999999")
    assert r.status_code == 404
    body = r.json()
    assert body["code"] == "AUDIT_NOT_FOUND"
    assert body["message"]
    assert "details" in body


@pytest.mark.asyncio
async def test_400_response_uses_unified_structure(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="running")
    r = await client.delete(f"/api/audits/{tid}")
    assert r.status_code == 400
    body = r.json()
    # 裸 HTTPException 经全局 handler 包成 HTTP_{status}
    assert body["code"] == "HTTP_400"
    assert "运行中" in body["message"]


# ---- 删除运行中任务限制(§14.1 行1174)----

@pytest.mark.asyncio
async def test_delete_running_task_rejected(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="running")
    r = await client.delete(f"/api/audits/{tid}")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_delete_pending_task_rejected(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="pending")
    r = await client.delete(f"/api/audits/{tid}")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_delete_completed_task_ok(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="completed")
    r = await client.delete(f"/api/audits/{tid}")
    assert r.status_code == 200
    # 删除后 GET 应 404(确认真删了)
    assert (await client.get(f"/api/audits/{tid}")).status_code == 404


@pytest.mark.asyncio
async def test_delete_cancelled_and_failed_ok(db_client):
    client, Session = db_client
    for status in ("cancelled", "failed"):
        tid, _, _ = await _seed(Session, status=status)
        r = await client.delete(f"/api/audits/{tid}")
        assert r.status_code == 200, f"{status}: {r.text}"


@pytest.mark.asyncio
async def test_delete_missing_task_404(db_client):
    client, _ = db_client
    r = await client.delete("/api/audits/999999")
    assert r.status_code == 404
    assert r.json()["code"] == "AUDIT_NOT_FOUND"


# ---- cancel 状态约束 ----

@pytest.mark.asyncio
async def test_cancel_pending_to_cancelled(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="pending")
    r = await client.post(f"/api/audits/{tid}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"


@pytest.mark.asyncio
async def test_cancel_completed_rejected(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="completed")
    r = await client.post(f"/api/audits/{tid}/cancel")
    assert r.status_code == 400


# ---- retry 状态约束 ----

@pytest.mark.asyncio
async def test_retry_pending_rejected(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="pending")
    r = await client.post(f"/api/audits/{tid}/retry")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_retry_completed_requeues(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="completed", with_stages=True, stage_status="completed")
    r = await client.post(f"/api/audits/{tid}/retry")
    assert r.status_code == 200
    assert r.json()["status"] == "pending"  # mark_task_queued 重新入队


# ---- GAP4 部分 stage 重跑（§12.2）----

@pytest.mark.asyncio
async def test_retry_subset_only_resets_requested_stages(db_client):
    """指定 stage_nums 子集 → 仅重置/入队这些阶段，未选阶段保持原态。"""
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="completed", with_stages=True, stage_status="completed")
    r = await client.post(f"/api/audits/{tid}/retry", json={"stage_nums": [2]})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending"
    assert body["summary"]["selected_stage_nums"] == [2]  # 仅 stage 2 入队
    # stage 2 复位 pending，stage 7 仍 completed
    async with Session() as s:
        stages = (await s.execute(
            select(models.AuditStage).where(models.AuditStage.task_id == tid)
        )).scalars().all()
    by_num = {st.stage_num: st.status for st in stages}
    assert by_num[2] == "pending"
    assert by_num[7] == "completed"


@pytest.mark.asyncio
async def test_retry_subset_rejects_ineligible_stage(db_client):
    """请求不可重试的阶段（不存在/未运行）→ 400。"""
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="completed", with_stages=True, stage_status="completed")
    r = await client.post(f"/api/audits/{tid}/retry", json={"stage_nums": [2, 99]})
    assert r.status_code == 400
    assert "99" in r.json()["message"]


@pytest.mark.asyncio
async def test_retry_empty_stage_nums_runs_all_eligible(db_client):
    """空 stage_nums 列表 → 与无 body 同语义（重跑全部可重试阶段，向后兼容）。"""
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="completed", with_stages=True, stage_status="completed")
    r = await client.post(f"/api/audits/{tid}/retry", json={"stage_nums": []})
    assert r.status_code == 200
    assert sorted(r.json()["summary"]["selected_stage_nums"]) == [2, 7]


# ---- GAP3 暂停/恢复（§12.2）----

async def _seed_with_run(Session, status: str, stages_spec: list[tuple[int, str]]):
    """seed task(+stages with per-stage status)+一条 running run，返回 task_id。"""
    async with Session() as s:
        proj = models.Project(name="p", upload_path="/tmp/x", file_tree=[])
        s.add(proj)
        await s.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        s.add(cfg)
        await s.flush()
        task = models.AuditTask(
            project_id=proj.id, llm_config_id=cfg.id,
            status=status, summary={"selected_stage_nums": [n for n, _ in stages_spec]},
            total_stages=9,
        )
        s.add(task)
        await s.flush()
        for stage_num, stage_status in stages_spec:
            s.add(models.AuditStage(
                task_id=task.id, stage_num=stage_num, stage_name=f"s{stage_num}", status=stage_status,
            ))
        s.add(models.AuditRun(
            task_id=task.id, status="running", mode="full",
            selected_stage_nums=[n for n, _ in stages_spec],
        ))
        await s.commit()
        return task.id


@pytest.mark.asyncio
async def test_pause_running_marks_task_and_run_paused(db_client):
    """running 任务 /pause → status=paused，当前 run 标 paused。"""
    client, Session = db_client
    tid = await _seed_with_run(Session, status="running", stages_spec=[(2, "running"), (7, "pending")])
    r = await client.post(f"/api/audits/{tid}/pause")
    assert r.status_code == 200
    assert r.json()["status"] == "paused"
    async with Session() as s:
        runs = (await s.execute(select(models.AuditRun).where(models.AuditRun.task_id == tid))).scalars().all()
    assert runs and all(run.status == "paused" for run in runs)


@pytest.mark.asyncio
async def test_pause_rejected_when_not_running(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="completed")
    r = await client.post(f"/api/audits/{tid}/pause")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_resume_continues_only_remaining_stages(db_client):
    """paused 任务 /resume → 续跑：仅未完成阶段入队，已完成阶段保留。"""
    client, Session = db_client
    tid = await _seed_with_run(Session, status="paused", stages_spec=[(2, "completed"), (7, "pending")])
    r = await client.post(f"/api/audits/{tid}/resume")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending"
    assert body["summary"]["selected_stage_nums"] == [7]  # 仅未完成的 stage 7
    async with Session() as s:
        stages = (await s.execute(
            select(models.AuditStage).where(models.AuditStage.task_id == tid)
        )).scalars().all()
    by_num = {st.stage_num: st.status for st in stages}
    assert by_num[2] == "completed"  # 已完成阶段保留
    assert by_num[7] == "pending"    # 剩余阶段重置待跑


@pytest.mark.asyncio
async def test_resume_no_remaining_completes(db_client):
    """paused 且无剩余阶段 → 直接完成（避免空入队）。"""
    client, Session = db_client
    tid = await _seed_with_run(Session, status="paused", stages_spec=[(2, "completed"), (7, "completed")])
    r = await client.post(f"/api/audits/{tid}/resume")
    assert r.status_code == 200
    assert r.json()["status"] == "completed"


@pytest.mark.asyncio
async def test_resume_rejected_when_not_paused(db_client):
    client, Session = db_client
    tid, _, _ = await _seed(Session, status="running")
    r = await client.post(f"/api/audits/{tid}/resume")
    assert r.status_code == 400


# ---- POST 创建 ----

@pytest.mark.asyncio
async def test_create_audit_missing_project(db_client):
    client, Session = db_client
    async with Session() as s:
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        s.add(cfg)
        await s.commit()
        cfg_id = cfg.id
    r = await client.post("/api/audits", json={"project_id": 999999, "llm_config_id": cfg_id})
    assert r.status_code == 404
    assert r.json()["code"] == "PROJECT_NOT_FOUND"


@pytest.mark.asyncio
async def test_create_audit_ok(db_client):
    client, Session = db_client
    async with Session() as s:
        proj = models.Project(name="p", upload_path="/tmp/x", file_tree=[])
        s.add(proj)
        await s.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        s.add(cfg)
        await s.commit()
        pid, cfg_id = proj.id, cfg.id
    r = await client.post("/api/audits", json={"project_id": pid, "llm_config_id": cfg_id})
    assert r.status_code == 200
    assert r.json()["status"] == "pending"  # 创建后即入队 pending
