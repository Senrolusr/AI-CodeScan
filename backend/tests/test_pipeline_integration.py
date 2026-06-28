"""§14.3 全链路集成测试:真实 vulnerable 项目 → 真实 code_parser → 确定性 planner →
真实漏洞入库 → 报告导出。

区别于 ``test_supervisor_e2e``(用 ``fake_cache`` + mock 返零漏洞),本测试用**真实源码**
跑**真实** ``parse_project``/``warm_project_cache``(code_parser_pkg 端到端),让确定性
planner 基于真实 rule_hits 证据选阶段(§10.3),mock LLM 返回漏洞,验证**真实** ``_store_
vulnerabilities`` 入库 + ``generate_html`` 报告产出。mock 仅封网络,管线代码全真实。

两个测试互补覆盖 §14.3 六步链路:
- Test 1:HTTP 上传真实 vulnerable ZIP → 真实解析 → 路由/规则命中落库(覆盖 上传→缓存)。
- Test 2:真实源码 → 真实缓存 → mock LLM 审计 → 真实漏洞入库 + 报告(覆盖 缓存→审计→漏洞→报告)。
"""

from __future__ import annotations

import io
import json
import os
import zipfile

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import models
from services import supervisor
from services.ai_engine import runner
from services.code_parser_pkg import project as cache_mod
from services.code_parser_pkg.project import (
    load_project_cache,
    parse_project,
    warm_project_cache,
)
from services.report_generator import generate_html

# 真实 vulnerable Flask 应用:字符串拼接 SQL(execute( + SELECT  + sqlite3.connect)
# → code_parser 标 injection → rule_hits.stage_nums=[3];@app.route("/login") → 静态路由。
_FLASK_APP = """from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return str(cursor.fetchall())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
"""


def _write_flask_app(src_dir: str) -> str:
    os.makedirs(src_dir, exist_ok=True)
    app_path = os.path.join(src_dir, "app.py")
    with open(app_path, "w", encoding="utf-8") as f:
        f.write(_FLASK_APP)
    # requirements.txt 让 _detect_tech_stack 识别为 flask(parse_project 依赖 manifest)
    with open(os.path.join(src_dir, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write("flask\n")
    return app_path


def _build_flask_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", _FLASK_APP)
        zf.writestr("requirements.txt", "flask\n")
    return buf.getvalue()


# ============================ Test 1:HTTP 上传 → 真实解析 → 落库 ============================

@pytest.mark.asyncio
async def test_upload_real_zip_parses_and_indexes(db_client, tmp_path, monkeypatch):
    client, _ = db_client
    # 隔离真实文件系统副作用:上传目录 + 项目缓存目录都指向 tmp
    import routers.projects as projects_mod
    monkeypatch.setattr(projects_mod, "UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setattr(cache_mod, "CACHE_ROOT", str(tmp_path / "cache"))

    zip_bytes = _build_flask_zip()
    r = await client.post(
        "/api/projects/upload",
        files={"file": ("flask-vulnerable.zip", zip_bytes, "application/zip")},
        data={"name": "flask-vuln"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    project_id = body["id"]
    assert "flask" in body["tech_stack"].lower()

    # 真实 code_parser 应抽到 /login 路由并写入结构化路由表
    routes_r = await client.get(f"/api/projects/{project_id}/routes")
    assert routes_r.status_code == 200
    paths = {r["path"] for r in routes_r.json()}
    assert "/login" in paths

    # 真实规则预筛应命中注入(injection → stage 3)并写入结构化规则命中表
    hits_r = await client.get(f"/api/projects/{project_id}/rule-hits")
    assert hits_r.status_code == 200
    hits = hits_r.json()
    assert hits, "真实 code_parser 应至少产出一条规则命中"
    assert any("3" in (h.get("stage_nums") or "") for h in hits), hits


# ============================ Test 2:真实缓存 → 审计 → 漏洞入库 → 报告 ============================

_META = {
    "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
    "finish_reason": "stop", "latency_ms": 0, "model": "fake", "attempt": 1,
}

# runner 统一响应:stage1(architecture_info={} 不降级)+ 各 sub_agent(带一条注入漏洞 → 真实入库)。
_VULN = {
    "title": "SQL 注入(字符串拼接)",
    "severity": "High",
    "vuln_type": "SQL Injection",
    "file_path": "app.py",
    "line_start": 10,
    "line_end": 11,
    "code_snippet": 'cursor.execute("SELECT * FROM users WHERE username = \'" + username + "\'")',
    "endpoint": "/login",
    "poc_raw": "username=' OR '1'='1",
    "description": "用户输入直接拼接进 SQL 语句,存在注入。",
    "fix_suggestion": "使用参数化查询,禁止拼接。",
    "confidence": "high",
}
_RUNNER_CONTENT = json.dumps(
    {"stage_summary": "mock:发现注入。", "architecture_info": {}, "risk_hints": [], "vulnerabilities": [_VULN]},
    ensure_ascii=False,
)


async def _fake_runner_llm(config, system_prompt, user_prompt):
    return {"success": True, "content": _RUNNER_CONTENT, "meta": dict(_META)}


def _make_supervisor_llm():
    """supervisor 调两次:plan / review。§10.3 下 which-stages 由后端定,mock 只回 focus/复核。"""
    state = {"n": 0}
    plan = json.dumps({"analysis_summary": "mock:注入信号。", "selected_agents": []}, ensure_ascii=False)
    review = json.dumps(
        {"review_summary": "mock 复核通过。", "request_rerun": False, "rerun_agents": [],
         "findings_assessment": {"high_quality_count": 1, "questionable_count": 0, "coverage_gaps": []}},
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
async def test_full_pipeline_real_parser_to_vulns_and_report(tmp_path, monkeypatch):
    src_dir = str(tmp_path / "src")
    _write_flask_app(src_dir)
    monkeypatch.setattr(cache_mod, "CACHE_ROOT", str(tmp_path / "cache"))

    # 真实解析 + 预热缓存(code_parser_pkg 端到端,产出真实 rule_hits/routes)
    file_tree, tech_stack = parse_project(src_dir)
    assert file_tree, "真实 code_parser 应能解析出源码文件"
    project_id_placeholder = 1  # warm 用占位 id,后面 seed 用同 id 保证 get_or_build 命中
    cache_payload = warm_project_cache(project_id_placeholder, src_dir, file_tree)
    # 确定性 planner 的证据 = rule_hits + source_sink_hints(_build_stage_evidence_scores 同口径)
    evidence_sources = cache_payload.get("rule_hits", []) + cache_payload.get("source_sink_hints", [])
    evidence_stages = {
        int(sn) for h in evidence_sources if isinstance(h, dict) for sn in (h.get("stage_nums") or [])
    }
    assert 3 in evidence_stages, f"injection 应被标到 stage 3,evidence={evidence_stages}"

    # StaticPool 内存库(supervisor 内部/Phase3 并发各开 session,须共享单连接)
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    async with Session() as session:
        project = models.Project(name="flask-vuln", upload_path=src_dir, file_tree=file_tree, tech_stack=tech_stack)
        session.add(project)
        await session.flush()
        # 固定 project.id == warm 用的占位 id,让 supervisor 的 get_or_build 命中已预热的缓存
        # (SQLite 自增从 1 起,首个 project 即 id=1;若不符则下面断言会暴露)。
        assert project.id == project_id_placeholder, project.id
        cfg = models.LlmConfig(
            name="c", provider="openai", api_key="sk-test",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        )
        session.add(cfg)
        await session.flush()
        task = models.AuditTask(
            project_id=project.id, llm_config_id=cfg.id, status="pending",
            summary={}, total_stages=9, audit_mode="multi_agent",
        )
        session.add(task)
        await session.flush()
        for n in range(1, 10):
            session.add(models.AuditStage(task_id=task.id, stage_num=n, stage_name=f"stage{n}", status="pending"))
        await session.commit()
        task_id = task.id

    # mock 仅封网络:supervisor 双 patch + runner patch(From import 各自模块绑定)
    monkeypatch.setattr(supervisor, "call_llm_with_meta", _make_supervisor_llm())
    monkeypatch.setattr(runner, "call_llm_with_meta", _fake_runner_llm)
    monkeypatch.setattr(supervisor, "sync_project_index", _async_none)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    monkeypatch.setattr(supervisor, "async_session", Session)

    await supervisor.run_multi_agent_audit(task_id)

    async with Session() as s:
        final_task = (await s.execute(select(models.AuditTask).where(models.AuditTask.id == task_id))).scalar_one()
        stages = (await s.execute(
            select(models.AuditStage).where(models.AuditStage.task_id == task_id).order_by(models.AuditStage.stage_num)
        )).scalars().all()
        db_project = (await s.execute(select(models.Project).where(models.Project.id == final_task.project_id))).scalar_one()
        vulns = (await s.execute(
            select(models.Vulnerability)
            .join(models.AuditStage, models.Vulnerability.stage_id == models.AuditStage.id)
            .where(models.Vulnerability.task_id == task_id, models.AuditStage.stage_num.between(2, 9))
        )).scalars().all()

    # 主流程成功收尾
    assert final_task.status == "completed", final_task.error_message

    # §10.3 确定性 planner 基于真实 rule_hits 证据选阶段:selected == evidence ∪ baseline(小项目在预算内)
    agent_plan = (final_task.summary or {}).get("agent_plan") or {}
    selected = {a["stage_num"] for a in agent_plan.get("selected_agents", []) if isinstance(a, dict)}
    baseline = {2, 7, 9}
    assert selected == (evidence_stages | baseline), f"selected={selected}, evidence={evidence_stages}"

    # 真实漏洞入库:≥1 条 Vulnerability(sub_agent 阶段 2-9)
    assert vulns, "应至少入库一条真实漏洞"
    assert any("SQL" in (v.vuln_type or "") or "注入" in (v.title or "") for v in vulns)

    # 报告导出:真实 generate_html 在真实漏洞上产出非空文件
    report_dir = str(tmp_path / "report")
    os.makedirs(report_dir, exist_ok=True)
    filepath = generate_html(report_dir, db_project, final_task, stages, vulns)
    assert filepath and os.path.isfile(filepath)
    assert os.path.getsize(filepath) > 0

    await eng.dispose()
