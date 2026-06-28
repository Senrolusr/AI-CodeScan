"""端到端：run_multi_agent_audit 走完 supervisor 4 阶段（架构→规划→子 Agent→复核）。

堵「假绿」缺口：supervisor 4 阶段接线此前无 LLM 级端到端测试，仅靠 import 语法 +
helper 单测守护——曾因此让 ``_load_audit_context`` 的 NameError 漏网（见
test_load_audit_context 的历史说明）。本测试 mock 掉 ``call_llm_with_meta``（封死全部
网络）+ project cache + session maker，驱动完整流程并断言各阶段产物。

mock 策略：
- ``runner.call_llm_with_meta``：所有调用（stage1 多 pass + 各 sub_agent）统一返回
  「零内容」响应——stage1 的 ``architecture_info={}`` 不触发 degradation、sub_agent 的
  ``vulnerabilities=[]`` 零漏洞通过，故一份响应通吃两阶段。
- ``supervisor.call_llm_with_meta``：supervisor 恰调两次（Phase2 plan → Phase4 review），
  用调用计数路由。
- ``database.async_session``：supervisor 内部 ``async with async_session()`` 会重开
  session，必须指向测试内存库。
- ``call_llm_with_meta`` 是 ``from ... import`` 到 supervisor / runner 各自模块的，故
  必须 patch 两个目标（只 patch llm_client 模块无效）。

自建 StaticPool 内存库：supervisor 内部重开 session、Phase3 并发各 sub_agent 也各开
session，必须共享同一内存库（StaticPool 单连接），故不走 conftest 的 session/engine
fixture（其默认池每连接独立 :memory: 库，supervisor 新 session 会看不到 seed）。
"""

from __future__ import annotations

import asyncio
import json
import re
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import database
import models
from services import supervisor
from services.ai_engine import runner

_META = {
    "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
    "finish_reason": "stop",  # 必须非 "length"，否则被判 truncation 触发重试
    "latency_ms": 0, "model": "fake", "attempt": 1,
}

# runner 统一响应：stage1（architecture_info={} 不降级）+ sub_agent（vulnerabilities=[] 零漏洞）通用。
_RUNNER_CONTENT = json.dumps(
    {"stage_summary": "mock:占位。", "architecture_info": {}, "risk_hints": [], "vulnerabilities": []},
    ensure_ascii=False,
)


async def _fake_runner_llm(config, system_prompt, user_prompt):
    return {"success": True, "content": _RUNNER_CONTENT, "meta": dict(_META)}


async def _fake_runner_llm_with_route_followup(config, system_prompt, user_prompt):
    if "Route coverage follow-up pass." in user_prompt:
        route_ids = list(dict.fromkeys(re.findall(r"route_id=(rt_[A-Za-z0-9_]+)", user_prompt)))
        content = json.dumps(
            {
                "stage_summary": "mock: route follow-up",
                "vulnerabilities": [],
                "route_coverage": [
                    {"route_id": route_id, "status": "audited_no_finding", "reason": "follow-up covered"}
                    for route_id in route_ids
                ],
            },
            ensure_ascii=False,
        )
        return {"success": True, "content": content, "meta": dict(_META)}
    return await _fake_runner_llm(config, system_prompt, user_prompt)


async def _fake_runner_llm_missing_route_followup_attestations(config, system_prompt, user_prompt):
    if "Route coverage follow-up pass." in user_prompt:
        content = json.dumps(
            {"stage_summary": "mock: route follow-up omitted coverage", "vulnerabilities": []},
            ensure_ascii=False,
        )
        return {"success": True, "content": content, "meta": dict(_META)}
    return await _fake_runner_llm(config, system_prompt, user_prompt)


async def _fake_runner_llm_with_attestation_retry(config, system_prompt, user_prompt):
    if "Route coverage attestation retry." in user_prompt:
        route_ids = list(dict.fromkeys(re.findall(r"rt_[A-Za-z0-9_]+", user_prompt)))
        content = json.dumps(
            {
                "stage_summary": "mock: attestation retry covered",
                "vulnerabilities": [],
                "route_coverage": [
                    {"route_id": route_id, "status": "audited_no_finding", "reason": "retry covered"}
                    for route_id in route_ids
                ],
            },
            ensure_ascii=False,
        )
        return {"success": True, "content": content, "meta": dict(_META)}
    if "Route coverage follow-up pass." in user_prompt:
        content = json.dumps(
            {"stage_summary": "mock: initial follow-up omitted coverage", "vulnerabilities": []},
            ensure_ascii=False,
        )
        return {"success": True, "content": content, "meta": dict(_META)}
    return await _fake_runner_llm(config, system_prompt, user_prompt)


def _make_supervisor_llm():
    """supervisor 恰调两次：第 1 次 Phase2 规划，第 2 次 Phase4 复核。

    §10.3 确定性主导后，Phase2 的 LLM 只做 focus 增强——which stages 由后端定。
    故 mock 的 plan 故意：(a) 给候选 stage 3 补一段可识别的 focus_guidance（验证叠加）；
    (b) 额外塞一个 stage 5（验证后端忽略 LLM 的新增阶段，确定性锁定 which stages）。
    """
    state = {"n": 0}
    plan = json.dumps(
        {
            "analysis_summary": "mock 规划：命中注入信号。",
            "selected_agents": [
                {
                    "stage_num": 3, "focus_guidance": "LLM 聚焦增强：核查 SQL 注入",
                    "focus_files": ["app.py"], "focus_routes": ["/api/login"],
                },
                # LLM 试图新增的阶段——后端确定性计划不含 5，应被合并函数丢弃。
                {"stage_num": 5, "focus_guidance": "LLM 试图新增，应被忽略"},
            ],
            "skipped_agents": [],
        },
        ensure_ascii=False,
    )
    review = json.dumps(
        {
            "review_summary": "mock 复核通过，无需重跑。",
            "request_rerun": False, "rerun_agents": [],
            "findings_assessment": {"high_quality_count": 0, "questionable_count": 0, "coverage_gaps": []},
        },
        ensure_ascii=False,
    )

    async def _fake(config, system_prompt, user_prompt):
        state["n"] += 1
        return {"success": True, "content": plan if state["n"] == 1 else review, "meta": dict(_META)}

    return _fake


async def _async_false(*_a, **_k):
    return False


async def _async_none(*_a, **_k):
    return None


@pytest.mark.asyncio
async def test_run_multi_agent_audit_completes_all_phases(monkeypatch):
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    # seed（临时 session，用完归还连接，让 supervisor 内部新 session 能 checkout 同一连接）
    async with Session() as session:
        project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
        session.add(project)
        await session.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id, status="pending", summary={}, total_stages=9,
        )
        session.add(task)
        await session.flush()
        # 预建 stage 1-9：multi_agent 复用 task 创建时预置的 stage 行——_execute_sub_agents
        # 用 stage_map.get(stage_num) 取行，行不存在则该 sub_agent 直接跳过。只建 stage 1
        # 会让 plan 选的 3 + baseline 强制的 2/7/9 全部因「无行」而 return。
        for n in range(1, 10):
            session.add(models.AuditStage(task_id=task.id, stage_num=n, stage_name=f"stage{n}", status="pending"))
        await session.commit()
        task_id = task.id

    fake_cache = {
        "scan_stats": {"route_count": 1},
        # §10.3：stage 3 命中注入规则 → 确���性 planner 据此选定 stage 3（+ baseline 2/7/9）。
        # which stages 现由后端证据驱动，不再由 LLM 决定。
        "rule_hits": [{"stage_nums": [3], "file_path": "app.py", "label": "sql_injection", "title": "疑似 SQL 注入"}],
        "static_routes": [{"method": "POST", "path": "/api/login", "handler": "login", "file_path": "app.py"}],
        "pre_discovery": None,
        "code_chunks": [],
        "source_sink_hints": [],
    }

    monkeypatch.setattr(supervisor, "call_llm_with_meta", _make_supervisor_llm())
    monkeypatch.setattr(runner, "call_llm_with_meta", _fake_runner_llm)
    monkeypatch.setattr(supervisor, "get_or_build_project_cache", lambda *_a, **_k: fake_cache)
    monkeypatch.setattr(supervisor, "sync_project_index", _async_none)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    # supervisor 用 ``from database import async_session``，绑定在 supervisor 模块；
    # patch database.async_session 无效，必须 patch supervisor.async_session（与
    # call_llm_with_meta 双绑定同理）。
    monkeypatch.setattr(supervisor, "async_session", Session)

    await supervisor.run_multi_agent_audit(task_id)

    async with Session() as s:
        final_task = (await s.execute(
            select(models.AuditTask).where(models.AuditTask.id == task_id)
        )).scalar_one()
        stages = {st.stage_num: st for st in (await s.execute(
            select(models.AuditStage).where(models.AuditStage.task_id == task_id)
        )).scalars().all()}
    await eng.dispose()

    # 主流程成功收尾（失败时 error_message 帮定位）
    assert final_task.status == "completed", final_task.error_message
    # Phase 1 架构阶段完成
    assert 1 in stages and stages[1].status == "completed"

    # §10.3 确定性 planner 主导：persisted plan 的 selected_agents stage_num 集合来自后端
    # 证据驱动（stage 3 命中注入规则）+ baseline 2/7/9，而非 LLM mock 的输出。
    agent_plan = (final_task.summary or {}).get("agent_plan") or {}
    selected_specs = agent_plan.get("selected_agents", []) if isinstance(agent_plan, dict) else []
    selected_stage_nums = {spec.get("stage_num") for spec in selected_specs if isinstance(spec, dict)}
    assert selected_stage_nums == {2, 3, 7, 9}, selected_stage_nums
    # LLM 试图新增的 stage 5 被后端忽略（确定性锁定 which stages）
    assert 5 not in selected_stage_nums
    # LLM 对候选 stage 3 的 focus_guidance 被叠加（合并生效）
    stage3 = next((s for s in selected_specs if isinstance(s, dict) and s.get("stage_num") == 3), None)
    assert stage3 is not None and stage3.get("focus_guidance") == "LLM 聚焦增强：核查 SQL 注入"

    # 4 个 sub_agent 阶段都应存在并执行完成
    for n in (2, 3, 7, 9):
        assert n in stages, f"stage {n} missing: {sorted(stages)}"
        assert stages[n].status == "completed"
        assert stages[n].agent_role == "sub_agent"
    # 无主流程异常降级（run_multi_agent_audit 的 except 分支会写此 code）
    notes = (final_task.summary or {}).get("degradation_notes") or []
    assert not any(isinstance(n, dict) and n.get("code") == "multi_agent_audit_failed" for n in notes)


@pytest.mark.asyncio
async def test_run_multi_agent_audit_route_followup_covers_missing_routes(monkeypatch):
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    async with Session() as session:
        project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
        session.add(project)
        await session.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id, status="pending", summary={}, total_stages=9,
        )
        session.add(task)
        await session.flush()
        for n in range(1, 10):
            session.add(models.AuditStage(task_id=task.id, stage_num=n, stage_name=f"stage{n}", status="pending"))
        await session.commit()
        task_id = task.id

    fake_cache = {
        "scan_stats": {"route_count": 1},
        "rule_hits": [{"stage_nums": [3], "file_path": "app.py", "label": "sql_injection", "title": "疑似 SQL 注入"}],
        "static_routes": [{"method": "POST", "path": "/api/login", "handler": "login", "file_path": "app.py"}],
        "pre_discovery": None,
        "code_chunks": [{"file_path": "app.py", "content": "def login(): pass", "risk_score": 1}],
        "source_sink_hints": [],
    }

    monkeypatch.setattr(supervisor, "call_llm_with_meta", _make_supervisor_llm())
    monkeypatch.setattr(runner, "call_llm_with_meta", _fake_runner_llm_with_route_followup)
    monkeypatch.setattr(supervisor, "get_or_build_project_cache", lambda *_a, **_k: fake_cache)
    monkeypatch.setattr(supervisor, "sync_project_index", _async_none)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    monkeypatch.setattr(supervisor, "async_session", Session)

    await supervisor.run_multi_agent_audit(task_id)

    async with Session() as s:
        final_task = (await s.execute(
            select(models.AuditTask).where(models.AuditTask.id == task_id)
        )).scalar_one()
        stage3 = (await s.execute(
            select(models.AuditStage).where(models.AuditStage.task_id == task_id, models.AuditStage.stage_num == 3)
        )).scalar_one()
    await eng.dispose()

    assert final_task.status == "completed", final_task.error_message
    route_followup = (final_task.summary or {}).get("route_followup") or {}
    route_coverage = (final_task.summary or {}).get("route_coverage") or {}
    assert route_followup["triggered"] is True
    assert route_followup["final_missing_route_count"] == 0
    assert route_coverage["audited_route_count"] == 1
    assert route_coverage["missing_route_count"] == 0
    assert stage3.findings["route_coverage"][0]["status"] == "audited_no_finding"


@pytest.mark.asyncio
async def test_run_multi_agent_audit_route_followup_requires_attestations(monkeypatch):
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    async with Session() as session:
        project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
        session.add(project)
        await session.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id, status="pending", summary={}, total_stages=9,
        )
        session.add(task)
        await session.flush()
        for n in range(1, 10):
            session.add(models.AuditStage(task_id=task.id, stage_num=n, stage_name=f"stage{n}", status="pending"))
        await session.commit()
        task_id = task.id

    fake_cache = {
        "scan_stats": {"route_count": 1},
        "rule_hits": [{"stage_nums": [3], "file_path": "app.py", "label": "sql_injection", "title": "疑似 SQL 注入"}],
        "static_routes": [{"method": "POST", "path": "/api/login", "handler": "login", "file_path": "app.py"}],
        "pre_discovery": None,
        "code_chunks": [{"file_path": "app.py", "content": "def login(): pass", "risk_score": 1}],
        "source_sink_hints": [],
    }

    monkeypatch.setattr(supervisor, "call_llm_with_meta", _make_supervisor_llm())
    monkeypatch.setattr(runner, "call_llm_with_meta", _fake_runner_llm_missing_route_followup_attestations)
    monkeypatch.setattr(supervisor, "get_or_build_project_cache", lambda *_a, **_k: fake_cache)
    monkeypatch.setattr(supervisor, "sync_project_index", _async_none)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    monkeypatch.setattr(supervisor, "async_session", Session)

    await supervisor.run_multi_agent_audit(task_id)

    async with Session() as s:
        final_task = (await s.execute(
            select(models.AuditTask).where(models.AuditTask.id == task_id)
        )).scalar_one()
    await eng.dispose()

    assert final_task.status == "completed", final_task.error_message
    route_followup = (final_task.summary or {}).get("route_followup") or {}
    route_coverage = (final_task.summary or {}).get("route_coverage") or {}
    batch = route_followup["batches"][0]
    assert route_followup["triggered"] is True
    assert batch["success"] is False
    assert batch["failure_reason"] == "missing_required_route_coverage"
    assert batch["missing_attestation_count"] == 1
    assert route_followup["final_missing_route_count"] == 1
    assert route_coverage["missing_route_count"] == 1


@pytest.mark.asyncio
async def test_run_multi_agent_audit_route_followup_attestation_retry_covers_missing(monkeypatch):
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    async with Session() as session:
        project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
        session.add(project)
        await session.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id, status="pending", summary={}, total_stages=9,
        )
        session.add(task)
        await session.flush()
        for n in range(1, 10):
            session.add(models.AuditStage(task_id=task.id, stage_num=n, stage_name=f"stage{n}", status="pending"))
        await session.commit()
        task_id = task.id

    fake_cache = {
        "scan_stats": {"route_count": 1},
        "rule_hits": [{"stage_nums": [3], "file_path": "app.py", "label": "sql_injection", "title": "疑似 SQL 注入"}],
        "static_routes": [{"method": "POST", "path": "/api/login", "handler": "login", "file_path": "app.py"}],
        "pre_discovery": None,
        "code_chunks": [{"file_path": "app.py", "content": "def login(): pass", "risk_score": 1}],
        "source_sink_hints": [],
    }

    monkeypatch.setattr(supervisor, "call_llm_with_meta", _make_supervisor_llm())
    monkeypatch.setattr(runner, "call_llm_with_meta", _fake_runner_llm_with_attestation_retry)
    monkeypatch.setattr(supervisor, "get_or_build_project_cache", lambda *_a, **_k: fake_cache)
    monkeypatch.setattr(supervisor, "sync_project_index", _async_none)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    monkeypatch.setattr(supervisor, "async_session", Session)

    await supervisor.run_multi_agent_audit(task_id)

    async with Session() as s:
        final_task = (await s.execute(
            select(models.AuditTask).where(models.AuditTask.id == task_id)
        )).scalar_one()
    await eng.dispose()

    route_followup = (final_task.summary or {}).get("route_followup") or {}
    route_coverage = (final_task.summary or {}).get("route_coverage") or {}
    batch = route_followup["batches"][0]
    assert batch["success"] is True
    assert batch["attestation_retry"]["triggered"] is True
    assert batch["attestation_retry"]["success"] is True
    assert batch["missing_attestation_count"] == 0
    assert route_followup["final_missing_route_count"] == 0
    assert route_coverage["missing_route_count"] == 0


def test_group_missing_routes_for_followup_shards_across_stage_topics():
    stages = [
        SimpleNamespace(stage_num=stage_num, status="completed")
        for stage_num in (3, 5, 6, 8)
    ]
    route_coverage = {
        "missing_routes": [
            {"method": "POST", "path": "/api/system/login", "handler": "UserController.Login", "file_path": "api/user.go"},
            {"method": "POST", "path": "/api/w8t/user/userUpdate", "handler": "userController.Update", "file_path": "api/user.go"},
        ],
    }

    batches = runner._group_missing_routes_for_followup(route_coverage, stages)

    assert [stage_num for stage_num, _routes in batches] == [5, 6]
    assert any(route["path"] == "/api/system/login" for route in batches[0][1])
    assert any(route["path"] == "/api/w8t/user/userUpdate" for route in batches[1][1])


@pytest.mark.asyncio
async def test_refresh_task_summary_uses_fresh_stage_rows():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    route = {
        "route_id": "rt_refresh_login",
        "method": "POST",
        "path": "/api/login",
        "handler": "login",
        "file_path": "app.py",
    }
    stale_coverage = [{"route_id": route["route_id"], "status": "insufficient_context", "reason": "old"}]
    fresh_coverage = [{"route_id": route["route_id"], "status": "audited_no_finding", "reason": "fresh"}]

    async with Session() as seed:
        project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
        seed.add(project)
        await seed.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        seed.add(cfg)
        await seed.flush()
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id, status="running", summary={}, total_stages=9,
        )
        seed.add(task)
        await seed.flush()
        stage = models.AuditStage(
            task_id=task.id,
            stage_num=3,
            stage_name="stage3",
            status="completed",
            findings={"route_coverage": stale_coverage, "vulnerabilities": []},
            compressed_summary={
                "_stage_coverage": {
                    "focus_routes": [route],
                    "focus_route_ids": [route["route_id"]],
                    "route_coverage": stale_coverage,
                }
            },
        )
        seed.add(stage)
        await seed.commit()
        task_id = task.id
        stage_id = stage.id

    async with Session() as stale_session:
        task = (await stale_session.execute(
            select(models.AuditTask).where(models.AuditTask.id == task_id)
        )).scalar_one()
        stage = (await stale_session.execute(
            select(models.AuditStage).where(models.AuditStage.id == stage_id)
        )).scalar_one()
        assert stage.findings["route_coverage"][0]["reason"] == "old"

        async with Session() as writer:
            fresh_stage = (await writer.execute(
                select(models.AuditStage).where(models.AuditStage.id == stage_id)
            )).scalar_one()
            fresh_stage.findings = {"route_coverage": fresh_coverage, "vulnerabilities": []}
            fresh_stage.compressed_summary = {
                "_stage_coverage": {
                    "focus_routes": [route],
                    "focus_route_ids": [route["route_id"]],
                    "route_coverage": fresh_coverage,
                }
            }
            await writer.commit()

        await runner._refresh_task_summary(
            stale_session,
            task,
            scan_stats={"route_count": 1},
            static_routes=[route],
        )

        route_summary = (task.summary or {}).get("route_coverage") or {}
        assert route_summary["audited_route_count"] == 1
        assert route_summary["missing_route_count"] == 0
        assert route_summary["stage_coverage"][0]["audited_route_count"] == 1

    await eng.dispose()


@pytest.mark.asyncio
async def test_run_multi_agent_audit_recovers_missing_sub_agent_stage_rows(monkeypatch):
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    async with Session() as session:
        project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
        session.add(project)
        await session.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id, status="pending", summary={}, total_stages=9,
        )
        session.add(task)
        await session.flush()
        session.add(models.AuditStage(task_id=task.id, stage_num=1, stage_name="stage1", status="pending"))
        await session.commit()
        task_id = task.id

    fake_cache = {
        "scan_stats": {"route_count": 1},
        "rule_hits": [{"stage_nums": [3], "file_path": "app.py", "label": "sql_injection", "title": "疑似 SQL 注入"}],
        "static_routes": [{"method": "POST", "path": "/api/login", "handler": "login", "file_path": "app.py"}],
        "pre_discovery": None,
        "code_chunks": [],
        "source_sink_hints": [],
    }

    monkeypatch.setattr(supervisor, "call_llm_with_meta", _make_supervisor_llm())
    monkeypatch.setattr(runner, "call_llm_with_meta", _fake_runner_llm)
    monkeypatch.setattr(supervisor, "get_or_build_project_cache", lambda *_a, **_k: fake_cache)
    monkeypatch.setattr(supervisor, "sync_project_index", _async_none)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    monkeypatch.setattr(supervisor, "async_session", Session)

    await supervisor.run_multi_agent_audit(task_id)

    async with Session() as s:
        final_task = (await s.execute(
            select(models.AuditTask).where(models.AuditTask.id == task_id)
        )).scalar_one()
        stages = {st.stage_num: st for st in (await s.execute(
            select(models.AuditStage).where(models.AuditStage.task_id == task_id)
        )).scalars().all()}
    await eng.dispose()

    assert final_task.status == "completed", final_task.error_message
    for n in (2, 3, 7, 9):
        assert n in stages, f"stage {n} was not recovered: {sorted(stages)}"
        assert stages[n].status == "completed"
        assert stages[n].agent_role == "sub_agent"
    assert stages[-2].status == "completed"

    notes = (final_task.summary or {}).get("degradation_notes") or []
    recovered_codes = {
        note.get("code") for note in notes if isinstance(note, dict)
    }
    assert {
        "sub_agent_stage_2_record_recovered",
        "sub_agent_stage_3_record_recovered",
        "sub_agent_stage_7_record_recovered",
        "sub_agent_stage_9_record_recovered",
    }.issubset(recovered_codes)
    assert "sub_agent_phase_not_started" not in recovered_codes
    assert "multi_agent_audit_failed" not in recovered_codes


@pytest.mark.asyncio
async def test_run_multi_agent_audit_blocks_review_when_sub_agent_phase_not_converged(monkeypatch):
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    async with Session() as session:
        project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
        session.add(project)
        await session.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id, status="pending", summary={}, total_stages=9,
        )
        session.add(task)
        await session.flush()
        for n in range(1, 10):
            session.add(models.AuditStage(task_id=task.id, stage_num=n, stage_name=f"stage{n}", status="pending"))
        await session.commit()
        task_id = task.id

    fake_cache = {
        "scan_stats": {"route_count": 1},
        "rule_hits": [{"stage_nums": [3], "file_path": "app.py", "label": "sql_injection", "title": "疑似 SQL 注入"}],
        "static_routes": [{"method": "POST", "path": "/api/login", "handler": "login", "file_path": "app.py"}],
        "pre_discovery": None,
        "code_chunks": [],
        "source_sink_hints": [],
    }

    original_single_pass = supervisor._run_single_pass_stage

    async def _failing_stage7(*args, **kwargs):
        stage = args[2]
        if stage.stage_num == 7:
            raise RuntimeError("stage7 forced failure")
        return await original_single_pass(*args, **kwargs)

    monkeypatch.setattr(supervisor, "call_llm_with_meta", _make_supervisor_llm())
    monkeypatch.setattr(runner, "call_llm_with_meta", _fake_runner_llm)
    monkeypatch.setattr(supervisor, "get_or_build_project_cache", lambda *_a, **_k: fake_cache)
    monkeypatch.setattr(supervisor, "sync_project_index", _async_none)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    monkeypatch.setattr(supervisor, "_run_single_pass_stage", _failing_stage7)
    monkeypatch.setattr(supervisor, "async_session", Session)

    await supervisor.run_multi_agent_audit(task_id)

    async with Session() as s:
        final_task = (await s.execute(
            select(models.AuditTask).where(models.AuditTask.id == task_id)
        )).scalar_one()
        stages = {st.stage_num: st for st in (await s.execute(
            select(models.AuditStage).where(models.AuditStage.task_id == task_id)
        )).scalars().all()}
    await eng.dispose()

    assert final_task.status == "failed"
    assert "阶段三并行审计未收敛" in final_task.error_message
    assert stages[7].status == "failed"
    assert -2 not in stages or stages[-2].status != "completed"

    guard = (final_task.summary or {}).get("orchestration_guard") or {}
    assert guard["status"] == "blocked"
    assert guard["planned_stage_nums"] == [2, 3, 7, 9]
    assert guard["completed_stage_nums"] == [2, 3, 9]
    assert guard["failed_stage_nums"] == [7]
    assert guard["unresolved_stage_nums"] == [7]

    notes = (final_task.summary or {}).get("degradation_notes") or []
    codes = {note.get("code") for note in notes if isinstance(note, dict)}
    assert "sub_agent_phase_not_converged" in codes


@pytest.mark.asyncio
async def test_execute_sub_agents_releases_sqlite_write_lock_before_llm(tmp_path, monkeypatch):
    db_path = tmp_path / "audit-lock.db"
    eng = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 0.1},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    async with Session() as session:
        project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
        session.add(project)
        await session.flush()
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()
        task = models.AuditTask(project_id=project.id, llm_config_id=cfg.id, status="running", summary={})
        session.add(task)
        await session.flush()
        session.add(models.AuditStage(task_id=task.id, stage_num=2, stage_name="stage2", status="pending"))
        await session.commit()
        task_id = task.id
        project_id = project.id
        cfg_id = cfg.id

    async def _fake_single_pass(*args, **_kwargs):
        stage = args[2]
        async with Session() as probe:
            result = await probe.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))
            probe_task = result.scalar_one()
            probe_task.error_message = f"probe-stage-{stage.stage_num}"
            await probe.commit()
        await asyncio.sleep(0)
        return {
            "response": {"stage_summary": "mock", "vulnerabilities": []},
            "prompt_used": "{}",
            "llm_response": "{}",
        }

    monkeypatch.setattr(supervisor, "async_session", Session)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    monkeypatch.setattr(supervisor, "_run_single_pass_stage", _fake_single_pass)

    async with Session() as session:
        task = (await session.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))).scalar_one()
        project = (await session.execute(select(models.Project).where(models.Project.id == project_id))).scalar_one()
        cfg = (await session.execute(select(models.LlmConfig).where(models.LlmConfig.id == cfg_id))).scalar_one()
        stages = (await session.execute(
            select(models.AuditStage).where(models.AuditStage.task_id == task_id)
        )).scalars().all()

        await supervisor._execute_sub_agents(
            session,
            task,
            stages,
            cfg,
            project,
            code_chunks=[],
            static_routes=[],
            rule_hits=[],
            source_sink_hints=[],
            agent_plan={"selected_agents": [{"stage_num": 2}], "skipped_agents": []},
        )

    async with Session() as session:
        task = (await session.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))).scalar_one()
        stage = (await session.execute(
            select(models.AuditStage).where(
                models.AuditStage.task_id == task_id,
                models.AuditStage.stage_num == 2,
            )
        )).scalar_one()

    await eng.dispose()

    assert task.error_message == "probe-stage-2"
    assert stage.status == "completed"
