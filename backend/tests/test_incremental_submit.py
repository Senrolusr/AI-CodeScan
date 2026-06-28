"""M5b 增量提交试点测试：parse_finding_actions 解析（正常/截断/无 actions）、
配置开关解析、store 落盘等价性（actions vs legacy vulnerabilities[]）、
开关关闭时行为不变、prompt 引导仅在开启阶段追加。"""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select

from models import AuditStage, AuditTask, Project, Vulnerability
from services import audit_engine
from services.audit_engine import _apply_stage_payload, _build_stage_user_prompt, _store_vulnerabilities
from services.ai_engine import prompt_builders
from services.config import Settings, _parse_stage_nums
from services.vulnerability_review import parse_finding_actions


# ── parse_finding_actions：三态 ──
def test_parse_finding_actions_from_dict():
    payload = {
        "actions": [
            {"type": "submit_finding", "payload": {"title": "SQLi", "severity": "High"}},
            {"type": "noop", "payload": {"title": "忽略"}},
            {"type": "submit_finding", "payload": {"title": "XSS", "severity": "Medium"}},
        ],
        "vulnerabilities": [],
        "final_summary": "ok",
    }
    findings = parse_finding_actions(payload)
    assert [f["title"] for f in findings] == ["SQLi", "XSS"]


def test_parse_finding_actions_no_actions():
    assert parse_finding_actions({"vulnerabilities": []}) == []
    assert parse_finding_actions("just prose, no json at all") == []
    assert parse_finding_actions(None) == []


def test_parse_finding_actions_truncated_tail():
    # actions 数组完整、final_summary 被截断（缺尾 }）
    raw = (
        '{"actions": ['
        '{"type": "submit_finding", "payload": {"title": "A", "severity": "High"}},'
        '{"type": "submit_finding", "payload": {"title": "B", "severity": "Medium"}}'
        '], "vulnerabilities": [], "final_summary": "结论被截断，没有闭合'
    )
    findings = parse_finding_actions(raw)
    assert [f["title"] for f in findings] == ["A", "B"]


def test_parse_finding_actions_truncated_array():
    # actions 数组自身被截断：第二条对象不完整，应只捞到第一条
    raw = (
        '{"actions": ['
        '{"type": "submit_finding", "payload": {"title": "A", "severity": "High"}},'
        '{"type": "submit_finding", "payload": {"title": "B", "severity"'
    )
    findings = parse_finding_actions(raw)
    assert len(findings) == 1
    assert findings[0]["title"] == "A"


def test_parse_finding_actions_payload_must_be_dict():
    payload = {"actions": [{"type": "submit_finding", "payload": "not-a-dict"}]}
    assert parse_finding_actions(payload) == []


# ── 配置开关解析 ──
def test_parse_stage_nums_variants():
    assert _parse_stage_nums("") == set()
    assert _parse_stage_nums("8") == {8}
    assert _parse_stage_nums("8, 9 ,10") == {8, 9, 10}
    assert _parse_stage_nums("[8, 9]") == {8, 9}
    assert _parse_stage_nums("8, junk, 9") == {8, 9}


def test_settings_default_off():
    assert Settings().incremental_submit_stages == ""
    assert Settings().incremental_submit_stage_nums == set()


# ── store 落盘等价性：actions 与等价 vulnerabilities[] 结果一致 ──
@pytest.mark.asyncio
async def test_store_actions_equivalent_to_legacy(session):
    proj = Project(name="t", upload_path="x", tech_stack="python")
    session.add(proj)
    await session.flush()
    task = AuditTask(project_id=proj.id, total_stages=9, llm_config_id=1)
    session.add(task)
    await session.flush()
    stage = AuditStage(task_id=task.id, stage_num=8, stage_name="文件操作", status="completed")
    session.add(stage)
    await session.flush()

    finding = {
        "title": "任意文件读取",
        "severity": "High",
        "vuln_type": "arbitrary_file_read",
        "file_path": "app/api.py",
        "line_start": 42,
        "line_end": 48,
        "code_snippet": "open(path)",
        "endpoint": "/api/file",
        "description": "用户可控路径直接拼入 open()，存在任意文件读取",
        "poc_raw": "GET /api/file?path=../../etc/passwd",
        "fix_suggestion": "校验并规范化路径，限制在允许目录内",
    }

    # 1) legacy 路径
    legacy_count = await _store_vulnerabilities(session, task, stage, [finding])
    await session.commit()
    rows = (await session.execute(
        select(Vulnerability).where(Vulnerability.task_id == task.id)
    )).scalars().all()
    assert legacy_count >= 1
    assert len(rows) == 1
    legacy_dedupe_key = rows[0].dedupe_key
    assert legacy_dedupe_key

    # 清空后用 actions payload 走同一入口
    await session.execute(delete(Vulnerability).where(Vulnerability.task_id == task.id))
    await session.commit()

    action_payload = parse_finding_actions({"actions": [{"type": "submit_finding", "payload": finding}]})
    assert action_payload == [finding]
    actions_count = await _store_vulnerabilities(session, task, stage, action_payload)
    await session.commit()
    rows2 = (await session.execute(
        select(Vulnerability).where(Vulnerability.task_id == task.id)
    )).scalars().all()
    assert actions_count >= 1
    assert len(rows2) == 1
    # 同字段内容 → 同 dedupe_key（去重幂等）
    assert rows2[0].dedupe_key == legacy_dedupe_key


@pytest.mark.asyncio
async def test_store_legacy_plus_actions_dedup(session):
    """同一 finding 同时以 legacy 与 actions 出现，store 应去重为一条。"""
    proj = Project(name="t", upload_path="x")
    session.add(proj)
    await session.flush()
    task = AuditTask(project_id=proj.id, total_stages=9, llm_config_id=1)
    session.add(task)
    await session.flush()
    stage = AuditStage(task_id=task.id, stage_num=8, stage_name="文件操作", status="completed")
    session.add(stage)
    await session.flush()

    finding = {
        "title": "任意文件读取",
        "severity": "High",
        "vuln_type": "arbitrary_file_read",
        "file_path": "app/api.py",
        "line_start": 42,
        "description": "任意文件读取",
        "poc_raw": "GET /api/file?path=../../etc/passwd",
    }
    # legacy 项 + 等价 actions payload 合并喂入 → 应只入库一条
    merged = [finding] + parse_finding_actions(
        {"actions": [{"type": "submit_finding", "payload": finding}]}
    )
    await _store_vulnerabilities(session, task, stage, merged)
    await session.commit()
    rows = (await session.execute(
        select(Vulnerability).where(Vulnerability.task_id == task.id)
    )).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_store_persists_route_id_fields(session):
    """M4a：含 route_id 的 finding 落库后，route_id/route_method/route_path/route_handler 持久化。"""
    proj = Project(name="t", upload_path="x", tech_stack="python")
    session.add(proj)
    await session.flush()
    task = AuditTask(project_id=proj.id, total_stages=9, llm_config_id=1)
    session.add(task)
    await session.flush()
    stage = AuditStage(task_id=task.id, stage_num=2, stage_name="注入", status="completed")
    session.add(stage)
    await session.flush()

    finding = {
        "title": "SQL 注入",
        "severity": "High",
        "vuln_type": "sqli",
        "file_path": "app/api.py",
        "line_start": 10,
        "endpoint": "POST /api/login",
        "poc_raw": "POST /api/login HTTP/1.1\nHost: x",
        "route_id": "rt_abc123",
        "route_method": "POST",
        "route_path": "/api/login",
        "route_handler": "login",
    }
    await _store_vulnerabilities(session, task, stage, [finding])
    await session.commit()
    rows = (await session.execute(
        select(Vulnerability).where(Vulnerability.task_id == task.id)
    )).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.route_id == "rt_abc123"
    assert row.route_method == "POST"
    assert row.route_path == "/api/login"
    assert row.route_handler == "login"


@pytest.mark.asyncio
async def test_apply_stage_payload_consumes_stable_submission_findings(session):
    proj = Project(name="t", upload_path="x", tech_stack="python")
    session.add(proj)
    await session.flush()
    task = AuditTask(project_id=proj.id, total_stages=9, llm_config_id=1)
    session.add(task)
    await session.flush()
    stage = AuditStage(task_id=task.id, stage_num=3, stage_name="敏感信息", status="completed")
    session.add(stage)
    await session.flush()

    finding = {
        "title": "Hardcoded secret key",
        "severity": "High",
        "vuln_type": "hardcoded_secret",
        "file_path": "settings.py",
        "line_start": 12,
        "code_snippet": "SECRET_KEY = 'dev-secret'",
        "description": "A hardcoded secret key is committed in source code.",
        "fix_suggestion": "Move secrets to environment variables or a secret manager.",
    }
    await _apply_stage_payload(
        stage,
        {
            "response": {
                "stage_summary": "stable submission only",
                "vulnerabilities": [],
                "stable_submissions": {"findings": [finding]},
            },
            "prompt_used": "{}",
            "llm_response": "{}",
            "compressed_summary": {"stage_summary": "new summary"},
        },
        session=session,
        task=task,
    )
    await session.commit()

    rows = (await session.execute(
        select(Vulnerability).where(Vulnerability.task_id == task.id)
    )).scalars().all()

    assert "stable_submissions" not in stage.findings
    assert stage.compressed_summary["stable_submissions"]["findings"][0]["title"] == "Hardcoded secret key"
    assert stage.findings["_stable_submission_stats"]["findings"]["total"] == 1
    assert stage.findings["vulnerabilities"][0]["title"] == "Hardcoded secret key"
    assert len(rows) == 1
    assert rows[0].title == "Hardcoded secret key"


# ── 开关：默认关闭 → prompt 不追加引导；开启 → 追加 ──
class _Stage:
    def __init__(self, num):
        self.stage_num = num


class _Project:
    file_tree = []
    tech_stack = "python"


def test_prompt_suffix_off_by_default(monkeypatch):
    # _build_stage_user_prompt resolves _incremental_submit_stage_nums from its own
    # module globals (prompt_builders, post-M3 split), so patch it there.
    monkeypatch.setattr(prompt_builders, "_incremental_submit_stage_nums", lambda: set())
    prompt = _build_stage_user_prompt(_Stage(8), _Project(), "原文", "code", "", [])
    assert "增量提交" not in prompt


def test_prompt_suffix_on_when_stage_enabled(monkeypatch):
    monkeypatch.setattr(prompt_builders, "_incremental_submit_stage_nums", lambda: {8})
    prompt = _build_stage_user_prompt(_Stage(8), _Project(), "原文", "code", "", [])
    assert "增量提交" in prompt
    assert "submit_finding" in prompt
    # 非开启阶段不追加
    prompt_other = _build_stage_user_prompt(_Stage(5), _Project(), "原文", "code", "", [])
    assert "增量提交" not in prompt_other
