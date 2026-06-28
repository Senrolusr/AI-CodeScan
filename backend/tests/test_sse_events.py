"""§11.3 SSE 事件流端到端测试。

覆盖 ``GET /api/audits/{task_id}/events/stream``:
- 鉴权:缺 token / 坏 token → 401;合法 token 放行(query ��数 token 方案,
  原生 EventSource 无法发 Authorization 头)。
- 任务不存在 → 404 ``AUDIT_NOT_FOUND``(§11.4 统一错误)。
- 终态任务:全量推送已落盘事件后流自然结束(terminal + drained)。
- ``Last-Event-ID`` 断点续传:只推该 id 之后的事件。
- 运行态任务:推事件帧 + ``: ping`` 心跳,流持续(用限量读取,不挂)。

关键技巧(同 test_audit_worker 的双绑定坑):SSE 生成器内部 ``import database;
database.async_session()`` 动态取 session,故测试 monkeypatch ``database.async_session``
指向 conftest 内存库的同一 Session 工厂,生成器才能读到 seed 的事件。
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

import database
import models
from models import User
from services import audit_runtime as rt


def _parse_event_frames(body: str) -> list[tuple[int, dict]]:
    """从 SSE body 解析出 ``(id, data)`` 事件帧(跳过 ``: ping`` 心跳注释)。"""
    frames: list[tuple[int, dict]] = []
    for block in body.split("\n\n"):
        block = block.strip()
        if not block or block.startswith(":"):
            continue
        id_: int | None = None
        data: dict | None = None
        for line in block.split("\n"):
            if line.startswith("id:"):
                id_ = int(line[3:].strip())
            elif line.startswith("data:"):
                data = json.loads(line[5:].strip())
        if data is not None:
            frames.append((id_, data))
    return frames


async def _seed(Session, *, status="completed", events=3):
    """seed project+llm_config+task(+ N 事件),返回 (task_id, [event_ids])。"""
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
        types = ["run.started", "stage.completed", "finding.created", "agent.started", "artifact.written"]
        ids = []
        for i in range(events):
            ev = models.AuditEvent(
                task_id=task.id,
                event_type=types[i % len(types)],
                payload={"i": i},
                stage_num=(2 if i else None),
            )
            s.add(ev)
            await s.flush()
            ids.append(ev.id)
        await s.commit()
        return task.id, ids


async def _admin_token(Session) -> str:
    async with Session() as s:
        admin = (await s.execute(select(User).where(User.username == "admin"))).scalar_one()
        return admin.token


# ---- 鉴权 ----

@pytest.mark.asyncio
async def test_stream_missing_token_returns_401(db_client, monkeypatch):
    client, Session = db_client
    monkeypatch.setattr(database, "async_session", Session)
    tid, _ = await _seed(Session)
    r = await client.get(f"/api/audits/{tid}/events/stream")  # 无 ?token=
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_stream_bad_token_returns_401(db_client, monkeypatch):
    client, Session = db_client
    monkeypatch.setattr(database, "async_session", Session)
    tid, _ = await _seed(Session)
    r = await client.get(f"/api/audits/{tid}/events/stream?token=bogus")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_stream_missing_task_404(db_client, monkeypatch):
    client, Session = db_client
    monkeypatch.setattr(database, "async_session", Session)
    token = await _admin_token(Session)
    r = await client.get(f"/api/audits/999999/events/stream?token={token}")
    assert r.status_code == 404
    assert r.json()["code"] == "AUDIT_NOT_FOUND"


# ---- 终态任务:全量推送后自然结束 ----

@pytest.mark.asyncio
async def test_terminal_task_streams_all_events_then_closes(db_client, monkeypatch):
    client, Session = db_client
    monkeypatch.setattr(database, "async_session", Session)
    tid, ids = await _seed(Session, status="completed", events=3)
    token = await _admin_token(Session)

    r = await client.get(f"/api/audits/{tid}/events/stream?token={token}")
    assert r.status_code == 200
    assert "text/event-stream" in r.headers.get("content-type", "")

    frames = _parse_event_frames(r.text)
    assert len(frames) == 3
    assert [fid for fid, _ in frames] == ids  # id 正序、与 seed 一致
    # serialize_event view model 字段齐全(与 JSON /events 同形)
    first = frames[0][1]
    assert {"id", "task_id", "event_type", "payload", "created_at"} <= set(first.keys())
    assert first["task_id"] == tid
    assert ": ping" not in r.text  # 终态首轮即 drained → 不发心跳直接关流


# ---- Last-Event-ID 断点续传 ----

@pytest.mark.asyncio
async def test_resume_from_last_event_id(db_client, monkeypatch):
    client, Session = db_client
    monkeypatch.setattr(database, "async_session", Session)
    tid, ids = await _seed(Session, status="completed", events=3)
    token = await _admin_token(Session)

    r = await client.get(
        f"/api/audits/{tid}/events/stream?token={token}",
        headers={"Last-Event-ID": str(ids[0])},  # 从首条之后开始
    )
    assert r.status_code == 200
    frames = _parse_event_frames(r.text)
    assert [fid for fid, _ in frames] == ids[1:]  # 仅后两条


# ---- 运行态任务:事件帧 + 心跳,流持续 ----
# 直接驱动生成器（不经 httpx SSE 流式读取，规避 ASGITransport 对长流的缓冲/挂起），
# 验证「事件帧 + ``: ping`` 心跳」语义。生成器首轮即产出事件帧，紧接着产出心跳，
# 两者都在首次 ``asyncio.sleep`` 之前 yield，故收到两者即 break，零 wall-clock 等待。

@pytest.mark.asyncio
async def test_running_task_emits_event_then_keepalive(db_client, monkeypatch):
    _, Session = db_client
    monkeypatch.setattr(database, "async_session", Session)
    tid, ids = await _seed(Session, status="running", events=1)

    chunks: list[str] = []
    async for frame in rt.iter_event_stream(tid, 0):
        chunks.append(frame)
        body = "".join(chunks)
        if "data:" in body and ": ping" in body:
            break
    body = "".join(chunks)

    frames = _parse_event_frames(body)
    assert len(frames) == 1
    assert frames[0][0] == ids[0]
    assert ": ping" in body  # 非终态 → 心跳保活


# ---- 兼容回归:JSON /events 不受影响(additive)----

@pytest.mark.asyncio
async def test_json_events_endpoint_unchanged(db_client):
    client, Session = db_client
    tid, ids = await _seed(Session, status="completed", events=2)
    r = await client.get(f"/api/audits/{tid}/events")
    assert r.status_code == 200
    body = r.json()
    assert body["task_id"] == tid
    assert [e["id"] for e in body["events"]] == ids
    # serialize_event 迁移后 created_at 仍是字符串(JSON 可序列化)
    assert isinstance(body["events"][0]["created_at"], str)
