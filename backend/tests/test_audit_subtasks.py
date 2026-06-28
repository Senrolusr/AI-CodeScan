"""AuditSubtask 影子写入（M2 补全）：helper 生命周期 + snapshot 暴露。

supervisor 4 个阶段现在会创建/推进 subtask（run 级执行计划项），
与 task 级、跨 rerun 复用的 AuditStage 正交。本文件覆盖 audit_runtime 的
subtask helper 与 snapshot 暴露；supervisor 侧接线为错误隔离的影子写入，
其结构性正确由全量套件守护。
"""

import pytest

from services import audit_runtime as rt


@pytest.mark.asyncio
async def test_subtask_lifecycle_running_to_completed(session):
    run = await rt.start_run(session, task_id=201, selected_stage_nums=[1])
    await session.commit()

    sub = await rt.start_subtask(session, task_id=201, stage_num=1, role="architecture")
    assert sub is not None
    assert sub.status == "running"
    assert sub.role == "architecture"
    assert sub.run_id == run.id  # 自动绑定当前 run
    assert sub.attempt_count == 1
    assert sub.started_at is not None

    await rt.complete_subtask(session, sub.id)
    await session.commit()

    subs = await rt.list_subtasks(session, run.id)
    assert len(subs) == 1
    assert subs[0].status == "completed"
    assert subs[0].completed_at is not None


@pytest.mark.asyncio
async def test_subtask_fail_records_reason(session):
    run = await rt.start_run(session, task_id=202, selected_stage_nums=[3])
    await session.commit()
    sub = await rt.start_subtask(session, task_id=202, stage_num=3, role="sub_agent")
    await rt.fail_subtask(session, sub.id, reason="LLM 超时")
    await session.commit()
    subs = await rt.list_subtasks(session, run.id)
    assert subs[0].status == "failed"
    assert "LLM 超时" in subs[0].blocked_reason


@pytest.mark.asyncio
async def test_subtask_skipped_direct_create(session):
    """规划阶段即跳过：status=skipped 直接建，无 started_at，reason 入 blocked_reason。"""
    run = await rt.start_run(session, task_id=203, selected_stage_nums=[7])
    await session.commit()
    sub = await rt.start_subtask(
        session, task_id=203, stage_num=7, role="sub_agent", status="skipped", reason="无相关规则命中"
    )
    await session.commit()
    assert sub.status == "skipped"
    assert sub.started_at is None
    assert "无相关规则命中" in sub.blocked_reason


@pytest.mark.asyncio
async def test_start_subtask_no_run_returns_none(session):
    """无活动 run 时返回 None（不抛异常）。"""
    sub = await rt.start_subtask(session, task_id=999, stage_num=2, role="sub_agent")
    assert sub is None


@pytest.mark.asyncio
async def test_subtask_none_id_noop(session):
    """subtask_id 为 None 时 complete/fail/skip 空操作（调用方无需 guard）。"""
    await rt.complete_subtask(session, None)
    await rt.fail_subtask(session, None, "x")
    await rt.skip_subtask(session, None, "y")


@pytest.mark.asyncio
async def test_subtask_terminal_not_overwritten(session):
    """终态 subtask 不被二次覆盖（_set_subtask_status 只改 running 态）。"""
    run = await rt.start_run(session, task_id=204, selected_stage_nums=[1])
    await session.commit()
    sub = await rt.start_subtask(session, task_id=204, stage_num=1, role="architecture")
    await rt.complete_subtask(session, sub.id)
    await session.commit()
    await rt.fail_subtask(session, sub.id, "late")  # 不应改写已 completed
    await session.commit()
    subs = await rt.list_subtasks(session, run.id)
    assert subs[0].status == "completed"


@pytest.mark.asyncio
async def test_agent_run_links_subtask_id(session):
    """record_agent_run 的 subtask_id 串接（让 agent 尝试可 JOIN 到 subtask）。"""
    run = await rt.start_run(session, task_id=205, selected_stage_nums=[3])
    await session.commit()
    sub = await rt.start_subtask(session, task_id=205, stage_num=3, role="sub_agent")
    await rt.record_agent_run(
        session, task_id=205, agent_role="sub_agent", status="completed",
        stage_num=3, subtask_id=sub.id, latency_ms=1234,
    )
    await session.commit()
    agents = await rt.list_agent_runs(session, run.id)
    assert agents[0].subtask_id == sub.id


@pytest.mark.asyncio
async def test_snapshot_exposes_subtasks(db_client):
    from models import AuditTask, LlmConfig, Project

    client, Session = db_client
    async with Session() as s:
        s.add(Project(name="p", upload_path="/tmp", file_tree=[], tech_stack="flask"))
        s.add(LlmConfig(name="c", api_key="k", base_url="http://x", api_mode="chat_completions", model_name="m"))
        await s.commit()
        s.add(AuditTask(id=2, name="t", project_id=1, llm_config_id=1, status="pending"))
        await s.commit()
        run = await rt.start_run(s, task_id=2, mode="full", selected_stage_nums=[1, 3])
        sub = await rt.start_subtask(s, task_id=2, stage_num=1, role="architecture")
        await rt.record_agent_run(
            s,
            task_id=2,
            run_id=run.id,
            subtask_id=sub.id,
            stage_num=1,
            agent_role="architecture",
            status="running",
        )
        await rt.start_subtask(s, task_id=2, stage_num=3, role="sub_agent", status="skipped", reason="无命中")
        await rt.emit_event(s, task_id=2, event_type=rt.EVENT_STAGE_STARTED, stage_num=1, run_id=run.id)
        await s.commit()

    snap = (await client.get("/api/audits/2/snapshot")).json()
    assert snap["current_run"]["id"] == run.id
    by_stage = {sub["stage_num"]: sub for sub in snap["subtasks"]}
    assert by_stage[1]["status"] == "running"
    assert by_stage[1]["role"] == "architecture"
    assert by_stage[3]["status"] == "skipped"
    assert "无命中" in by_stage[3]["blocked_reason"]
    assert snap["agent_runs"][0]["status"] == "running"
    assert snap["agent_runs"][0]["subtask_id"] == by_stage[1]["id"]
    assert snap["diagnostics"]["focus_status"] == "running"
    assert snap["diagnostics"]["current_stage_num"] == 1
    assert snap["diagnostics"]["current_role"] == "architecture"
    assert snap["diagnostics"]["active_agent_run_id"] == snap["agent_runs"][0]["id"]
    assert snap["diagnostics"]["latest_event_type"] == rt.EVENT_STAGE_STARTED


@pytest.mark.asyncio
async def test_snapshot_diagnostics_surfaces_failed_subtask_reason(db_client):
    from models import AuditTask, LlmConfig, Project

    client, Session = db_client
    async with Session() as s:
        s.add(Project(name="p", upload_path="/tmp", file_tree=[], tech_stack="flask"))
        s.add(LlmConfig(name="c", api_key="k", base_url="http://x", api_mode="chat_completions", model_name="m"))
        await s.commit()
        s.add(AuditTask(id=3, name="t", project_id=1, llm_config_id=1, status="running"))
        await s.commit()
        run = await rt.start_run(s, task_id=3, mode="full", selected_stage_nums=[2])
        sub = await rt.start_subtask(s, task_id=3, stage_num=2, role="sub_agent")
        await rt.fail_subtask(s, sub.id, reason="LLM 超时")
        await rt.fail_run(s, run.id, "LLM 超时")
        await rt.emit_event(s, task_id=3, event_type=rt.EVENT_STAGE_FAILED, stage_num=2, run_id=run.id, payload={"reason": "LLM 超时"})
        await s.commit()

    snap = (await client.get("/api/audits/3/snapshot")).json()

    assert snap["diagnostics"]["focus_status"] == "failed"
    assert snap["diagnostics"]["current_stage_num"] == 2
    assert snap["diagnostics"]["current_role"] == "sub_agent"
    assert "LLM 超时" in snap["diagnostics"]["blocked_reason"]
    assert "LLM 超时" in snap["diagnostics"]["error_message"]


@pytest.mark.asyncio
async def test_snapshot_diagnostics_surfaces_orchestration_guard(db_client):
    from models import AuditTask, LlmConfig, Project

    client, Session = db_client
    guard = {
        "status": "blocked",
        "planned_stage_nums": [2, 3, 7, 9],
        "completed_stage_nums": [2, 3, 9],
        "failed_stage_nums": [7],
        "missing_stage_nums": [],
        "pending_stage_nums": [],
        "running_stage_nums": [],
        "skipped_stage_nums": [],
        "unresolved_stage_nums": [7],
        "message": "阶段三并行审计未收敛，已阻止进入复核：Stage 7。",
    }
    async with Session() as s:
        s.add(Project(name="p", upload_path="/tmp", file_tree=[], tech_stack="flask"))
        s.add(LlmConfig(name="c", api_key="k", base_url="http://x", api_mode="chat_completions", model_name="m"))
        await s.commit()
        s.add(AuditTask(
            id=4,
            name="t",
            project_id=1,
            llm_config_id=1,
            status="failed",
            error_message="阶段三并行审计未收敛，已阻止进入复核：Stage 7。",
            summary={"orchestration_guard": guard},
        ))
        await s.commit()
        run = await rt.start_run(s, task_id=4, mode="full", selected_stage_nums=[2, 3, 7, 9])
        await rt.fail_run(s, run.id, "阶段三并行审计未收敛")
        await rt.emit_event(
            s,
            task_id=4,
            event_type=rt.EVENT_STAGE_FAILED,
            stage_num=7,
            run_id=run.id,
            payload={"reason": "阶段三并行审计未收敛"},
        )
        await s.commit()

    snap = (await client.get("/api/audits/4/snapshot")).json()

    assert snap["diagnostics"]["focus_status"] == "blocked"
    assert snap["diagnostics"]["current_stage_num"] == 7
    assert snap["diagnostics"]["current_role"] == "sub_agent"
    assert snap["diagnostics"]["orchestration_guard"]["status"] == "blocked"
    assert snap["diagnostics"]["orchestration_guard"]["unresolved_stage_nums"] == [7]
    assert "阶段三并行审计未收敛" in snap["diagnostics"]["blocked_reason"]
