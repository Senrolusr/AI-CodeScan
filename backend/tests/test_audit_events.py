"""运行时事件/Run 服务与 API 测试（M2）。"""

import pytest

from services import audit_runtime as rt


@pytest.mark.asyncio
async def test_run_lifecycle_and_event_autobind(session):
    run = await rt.start_run(session, task_id=101, mode="full", selected_stage_nums=[1, 2, 3])
    await session.commit()
    run_id = run.id

    # 不传 run_id，应自动绑定到当前 run
    await rt.emit_event(session, task_id=101, event_type=rt.EVENT_RUN_STARTED, payload={"mode": "full"})
    await rt.emit_event(session, task_id=101, event_type=rt.EVENT_PHASE_CHANGED, payload={"phase": 1}, stage_num=1)
    await rt.record_agent_run(
        session,
        task_id=101,
        agent_role="supervisor_plan",
        status="completed",
        stage_num=-1,
        prompt_tokens=120,
        completion_tokens=60,
        latency_ms=900,
        finish_reason="stop",
    )
    await rt.complete_run(session, run_id)
    await rt.emit_event(session, task_id=101, event_type=rt.EVENT_RUN_COMPLETED)
    await session.commit()

    events = await rt.list_events(session, 101)
    assert [e.event_type for e in events] == ["run.started", "phase.changed", "run.completed"]
    # 全部自动绑定到同一条 run
    assert all(e.run_id == run_id for e in events)
    # 阶段事件带 stage_num
    phase_event = next(e for e in events if e.event_type == "phase.changed")
    assert phase_event.stage_num == 1

    agents = await rt.list_agent_runs(session, run_id)
    assert len(agents) == 1
    assert agents[0].prompt_tokens == 120
    assert agents[0].latency_ms == 900

    current = await rt.get_current_run(session, 101)
    assert current.status == "completed"


@pytest.mark.asyncio
async def test_fail_run_records_message(session):
    run = await rt.start_run(session, task_id=102, mode="rerun", selected_stage_nums=[2])
    await session.commit()
    await rt.fail_run(session, run.id, "boom")
    await session.commit()
    current = await rt.get_current_run(session, 102)
    assert current.status == "failed"
    assert "boom" in current.error_message


@pytest.mark.asyncio
async def test_list_events_after_id(session):
    run = await rt.start_run(session, task_id=103, selected_stage_nums=[1])
    await session.commit()
    rid = run.id
    for i in range(5):
        await rt.emit_event(session, task_id=103, event_type=rt.EVENT_STAGE_STARTED, payload={"i": i}, run_id=rid)
    await session.commit()
    all_events = await rt.list_events(session, 103)
    assert len(all_events) == 5
    cutoff = all_events[2].id
    tail = await rt.list_events(session, 103, after_id=cutoff)
    assert len(tail) == 2
    assert all(e.id > cutoff for e in tail)


@pytest.mark.asyncio
async def test_events_and_snapshot_endpoints(db_client):
    from models import AuditTask, LlmConfig, Project

    client, Session = db_client
    async with Session() as s:
        s.add(Project(name="p", upload_path="/tmp", file_tree=[], tech_stack="flask"))
        s.add(LlmConfig(name="c", api_key="k", base_url="http://x", api_mode="chat_completions", model_name="m"))
        await s.commit()
        s.add(AuditTask(id=1, name="t", project_id=1, llm_config_id=1, status="pending"))
        await s.commit()
        run = await rt.start_run(s, task_id=1, mode="full", selected_stage_nums=list(range(1, 10)))
        await rt.emit_event(s, task_id=1, event_type=rt.EVENT_RUN_STARTED, run_id=run.id)
        await rt.emit_event(s, task_id=1, event_type=rt.EVENT_PHASE_CHANGED, payload={"phase": 1}, stage_num=1, run_id=run.id)
        await rt.complete_run(s, run.id)
        await rt.emit_event(s, task_id=1, event_type=rt.EVENT_RUN_COMPLETED, run_id=run.id)
        await s.commit()

    r = await client.get("/api/audits/1/events")
    assert r.status_code == 200
    payload = r.json()
    types = [e["event_type"] for e in payload["events"]]
    assert types == ["run.started", "phase.changed", "run.completed"]
    assert all(e["run_id"] == run.id for e in payload["events"])

    # after_id 增量
    after = payload["events"][0]["id"]
    r2 = await client.get(f"/api/audits/1/events?after_id={after}")
    assert [e["event_type"] for e in r2.json()["events"]] == ["phase.changed", "run.completed"]

    latest_after = payload["events"][-1]["id"]
    r3 = await client.get(f"/api/audits/1/events?after_id={latest_after}")
    assert r3.json()["events"] == []
    assert r3.json()["after_id"] == latest_after

    # snapshot 含 current_run + recent_events
    snap = (await client.get("/api/audits/1/snapshot")).json()
    assert snap["current_run"]["status"] == "completed"
    assert len(snap["recent_events"]) == 3

    # 不存在的任务
    assert (await client.get("/api/audits/9999/events")).status_code == 404
