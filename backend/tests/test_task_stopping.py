"""GAP3：``_is_task_paused`` / ``_is_task_stopping`` 协作式停机谓词单测。"""

from __future__ import annotations

import pytest

import models
from services.ai_engine.runner import _is_task_cancelled, _is_task_paused, _is_task_stopping


async def _seed_task(session, status: str) -> int:
    proj = models.Project(name="p", upload_path="/tmp/x", file_tree=[])
    session.add(proj)
    await session.flush()
    cfg = models.LlmConfig(
        name="c", provider="openai", api_key="sk-test",
        base_url="http://x", api_mode="chat_completions", model_name="m",
    )
    session.add(cfg)
    await session.flush()
    task = models.AuditTask(
        project_id=proj.id, llm_config_id=cfg.id, status=status, summary={}, total_stages=9,
    )
    session.add(task)
    await session.flush()
    return task.id


@pytest.mark.asyncio
async def test_predicate_matrix(session):
    """cancelled/paused/running 三态下三个谓词的真值。"""
    for status, expect_cancelled, expect_paused, expect_stopping in [
        ("cancelled", True, False, True),
        ("paused", False, True, True),
        ("running", False, False, False),
    ]:
        tid = await _seed_task(session, status)
        assert await _is_task_cancelled(session, tid) is expect_cancelled
        assert await _is_task_paused(session, tid) is expect_paused
        assert await _is_task_stopping(session, tid) is expect_stopping


@pytest.mark.asyncio
async def test_stopping_predicate_covers_both(session):
    """_is_task_stopping = cancelled OR paused（supervisor checkpoint 统一谓词）。"""
    cancelled_id = await _seed_task(session, "cancelled")
    paused_id = await _seed_task(session, "paused")
    running_id = await _seed_task(session, "running")
    assert await _is_task_stopping(session, cancelled_id) is True
    assert await _is_task_stopping(session, paused_id) is True
    assert await _is_task_stopping(session, running_id) is False
