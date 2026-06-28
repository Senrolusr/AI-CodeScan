"""§12.2：GET /api/audits/{task_id}/runs（列表）+ /runs/{run_id}（详情）测试。"""

from __future__ import annotations

import pytest

from models import AuditTask, LlmConfig, Project
from services import audit_runtime as rt


async def _seed(db_client):
    """seed project+llm+task，返回 (client, task_id)。"""
    client, Session = db_client
    async with Session() as s:
        s.add(Project(name="p", upload_path="/tmp", file_tree=[], tech_stack="flask"))
        s.add(LlmConfig(name="c", api_key="k", base_url="http://x", api_mode="chat_completions", model_name="m"))
        await s.commit()
        s.add(AuditTask(id=3, name="t", project_id=1, llm_config_id=1, status="running"))
        await s.commit()
    return client, 3


@pytest.mark.asyncio
async def test_list_runs_ordered_by_id_desc(db_client):
    client, task_id = await _seed(db_client)
    _, Session = db_client
    async with Session() as s:
        run1 = await rt.start_run(s, task_id=task_id, mode="full", selected_stage_nums=[1, 2])
        await s.commit()
        run2 = await rt.start_run(s, task_id=task_id, mode="rerun", selected_stage_nums=[3])
        await rt.complete_run(s, run2.id)
        await s.commit()

    r = await client.get(f"/api/audits/{task_id}/runs")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2
    ids = [d["id"] for d in data]
    assert ids == sorted(ids, reverse=True)  # 最新优先
    assert data[0]["mode"] == "rerun"
    assert data[0]["status"] == "completed"
    # view model 字段齐全（与 snapshot.current_run 同形）
    assert {"id", "task_id", "status", "mode", "selected_stage_nums", "created_at"} <= set(data[0].keys())


@pytest.mark.asyncio
async def test_get_run_detail_with_subtasks(db_client):
    client, task_id = await _seed(db_client)
    _, Session = db_client
    async with Session() as s:
        run = await rt.start_run(s, task_id=task_id, mode="full", selected_stage_nums=[2])
        sub = await rt.start_subtask(s, task_id=task_id, stage_num=2, role="sub_agent")
        await s.commit()
        run_id, sub_id = run.id, sub.id

    r = await client.get(f"/api/audits/{task_id}/runs/{run_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == run_id
    assert data["task_id"] == task_id
    assert len(data["subtasks"]) == 1
    assert data["subtasks"][0]["id"] == sub_id
    assert data["subtasks"][0]["stage_num"] == 2


@pytest.mark.asyncio
async def test_get_run_404_when_missing(db_client):
    client, task_id = await _seed(db_client)
    r = await client.get(f"/api/audits/{task_id}/runs/999999")
    assert r.status_code == 404
    assert r.json()["code"] == "AUDIT_RUN_NOT_FOUND"


@pytest.mark.asyncio
async def test_list_runs_404_when_task_missing(db_client):
    client, _ = db_client
    r = await client.get("/api/audits/999999/runs")
    assert r.status_code == 404
    assert r.json()["code"] == "AUDIT_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_run_scoped_to_task(db_client):
    """run 查询带 task_id 约束：另一任务的 run_id 在本任务下应 404（防越权串读）。"""
    client, Session = db_client
    async with Session() as s:
        s.add(Project(name="p", upload_path="/tmp", file_tree=[], tech_stack="flask"))
        s.add(LlmConfig(name="c", api_key="k", base_url="http://x", api_mode="chat_completions", model_name="m"))
        await s.commit()
        s.add(AuditTask(id=30, name="a", project_id=1, llm_config_id=1, status="running"))
        s.add(AuditTask(id=31, name="b", project_id=1, llm_config_id=1, status="running"))
        await s.commit()
        run30 = await rt.start_run(s, task_id=30, mode="full", selected_stage_nums=[1])
        await s.commit()
        other_run_id = run30.id

    # 用 task 31 去读 task 30 的 run → 404（task_id 约束生效）
    r = await client.get(f"/api/audits/31/runs/{other_run_id}")
    assert r.status_code == 404
