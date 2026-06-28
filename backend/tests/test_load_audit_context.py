"""回归:_load_audit_context 必须把 rule_hits 透传进 ctx(防 NameError)。

历史:清理 ``task.summary.rule_hits_preview`` 写入时,误删了同函数内 ``rule_hits`` 局部变量
定义,但返回的 ctx dict 仍引用它 → ``run_multi_agent_audit`` 触发 NameError。此前无测试
覆盖该路径,332 既有用例未发现。本测试固定该路径。
"""

from __future__ import annotations

import models
from services import supervisor


async def _async_false(*_a, **_k):
    return False


async def _async_none(*_a, **_k):
    return None


async def test_load_audit_context_returns_rule_hits_in_ctx(session, monkeypatch):
    project = models.Project(name="p", upload_path="/tmp/nonexist", file_tree=[])
    session.add(project)
    await session.flush()
    cfg = models.LlmConfig(
        name="c",
        provider="openai",
        api_key="sk-x",
        base_url="http://x",
        api_mode="chat_completions",
        model_name="m",
    )
    session.add(cfg)
    await session.flush()
    task = models.AuditTask(project_id=project.id, llm_config_id=cfg.id, status="pending", summary={})
    session.add(task)
    await session.flush()

    fake_rule_hits = [{"label": "RCE", "title": "eval()", "stage_nums": [3]}]
    fake_cache = {
        "scan_stats": {"route_count": 3},
        "rule_hits": fake_rule_hits,
        "static_routes": [],
        "pre_discovery": None,
        "code_chunks": [],
        "source_sink_hints": [],
    }
    monkeypatch.setattr(supervisor, "get_or_build_project_cache", lambda *_a, **_k: fake_cache)
    monkeypatch.setattr(supervisor, "_is_task_stopping", _async_false)
    monkeypatch.setattr(supervisor, "sync_project_index", _async_none)

    ctx = await supervisor._load_audit_context(session, task.id)

    assert ctx is not None
    # 关键:不 NameError,且 rule_hits 正确透传到 ctx
    assert ctx["rule_hits"] == fake_rule_hits
    # 本次清理目标:summary 不再写 rule_hits_preview(前端改读 project_rule_hits 表)
    assert "rule_hits_preview" not in (ctx["task"].summary or {})
    # scan_stats 仍正常写入 summary(未受清理影响)
    assert ctx["task"].summary.get("scan_stats") == fake_cache["scan_stats"]
