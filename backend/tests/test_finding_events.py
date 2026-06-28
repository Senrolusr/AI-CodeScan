"""§9.2：finding.created / finding.filtered / artifact.written 三类事件发射测试。

finding.* 经 ``_store_vulnerabilities`` 的落库/过滤两个分支覆盖；
artifact.written 经 runner 的 ``_emit_artifact_written`` helper 覆盖（thin wrapper，
emit_event 内部容错，失败不阻断）。
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from models import AuditEvent, AuditStage, AuditTask, LlmConfig, Project
from services import audit_runtime as rt
from services.ai_engine.runner import _emit_artifact_written
from services.ai_engine.vulnerability_store import _store_vulnerabilities


async def _seed_task_stage(session, *, stage_num=2):
    """seed project+llm+task+stage，返回 (task, stage)。"""
    proj = Project(name="p", upload_path="/tmp", file_tree=[], tech_stack="flask")
    cfg = LlmConfig(name="c", api_key="k", base_url="http://x", api_mode="chat_completions", model_name="m")
    session.add_all([proj, cfg])
    await session.flush()
    task = AuditTask(id=400, name="t", project_id=proj.id, llm_config_id=cfg.id, status="running")
    session.add(task)
    await session.flush()
    stage = AuditStage(id=500, task_id=task.id, stage_num=stage_num, stage_name="s", status="running")
    session.add(stage)
    await session.flush()
    return task, stage


@pytest.mark.asyncio
async def test_finding_created_emitted_per_new_vuln(session):
    task, stage = await _seed_task_stage(session, stage_num=2)
    vulns = [
        {"title": "SQL 注入", "vuln_type": "sqli", "file_path": "app/api.py", "line_start": 1, "severity": "High"},
        {"title": "硬编码 secret", "vuln_type": "hardcoded", "file_path": "app/config.py", "line_start": 2, "severity": "Medium"},
    ]
    created = await _store_vulnerabilities(session, task, stage, vulns)
    await session.commit()

    assert created == 2
    events = (await session.execute(
        select(AuditEvent).where(AuditEvent.task_id == task.id, AuditEvent.event_type == rt.EVENT_FINDING_CREATED)
    )).scalars().all()
    assert len(events) == 2
    titles = [e.payload.get("title") for e in events]
    assert "SQL 注入" in titles
    # payload 携带关键字段 + stage_num 绑定
    sqli = next(e for e in events if "SQL" in (e.payload.get("title") or ""))
    assert sqli.stage_num == 2
    assert sqli.payload.get("severity") == "High"
    assert sqli.payload.get("file_path") == "app/api.py"


@pytest.mark.asyncio
async def test_finding_filtered_emitted_for_quality_gate_rejection(session):
    task, stage = await _seed_task_stage(session, stage_num=2)
    # 缺 file_path 与 endpoint → 非正式候选 → 质量门过滤
    vulns = [{"title": "幽灵漏洞", "vuln_type": "xss"}]
    await _store_vulnerabilities(session, task, stage, vulns)
    await session.commit()

    filtered = (await session.execute(
        select(AuditEvent).where(AuditEvent.task_id == task.id, AuditEvent.event_type == rt.EVENT_FINDING_FILTERED)
    )).scalars().all()
    assert len(filtered) == 1
    assert filtered[0].payload.get("title") == "幽灵漏洞"
    assert filtered[0].payload.get("reason")  # 带过滤原因
    # 不应产生 finding.created（被过滤了）
    created = (await session.execute(
        select(AuditEvent).where(AuditEvent.task_id == task.id, AuditEvent.event_type == rt.EVENT_FINDING_CREATED)
    )).scalars().all()
    assert created == []


@pytest.mark.asyncio
async def test_artifact_written_helper_emits_event(session):
    task, stage = await _seed_task_stage(session, stage_num=3)
    await _emit_artifact_written(session, task, stage, "data/stage_artifacts/400/stage_3_passes.json")
    await session.commit()

    events = (await session.execute(
        select(AuditEvent).where(AuditEvent.task_id == task.id, AuditEvent.event_type == rt.EVENT_ARTIFACT_WRITTEN)
    )).scalars().all()
    assert len(events) == 1
    ev = events[0]
    assert ev.stage_num == 3
    assert ev.payload.get("artifact_path") == "data/stage_artifacts/400/stage_3_passes.json"
    assert ev.payload.get("stage_num") == 3


@pytest.mark.asyncio
async def test_store_vulns_on_stage_one_emits_nothing(session):
    """stage_num == 1 早退（架构阶段不产漏洞）→ 不发任何 finding 事件。"""
    task, stage = await _seed_task_stage(session, stage_num=1)
    created = await _store_vulnerabilities(session, task, stage, [
        {"title": "SQL 注入", "vuln_type": "sqli", "file_path": "app/api.py", "line_start": 1},
    ])
    await session.commit()
    assert created == 0
    finding_events = (await session.execute(
        select(AuditEvent).where(
            AuditEvent.task_id == task.id,
            AuditEvent.event_type.in_([rt.EVENT_FINDING_CREATED, rt.EVENT_FINDING_FILTERED]),
        )
    )).scalars().all()
    assert finding_events == []
