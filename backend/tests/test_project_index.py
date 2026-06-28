"""M4b：sync_project_index 影子写入测试（全量替换 / route_id 回填 / 容错 / 清空）。"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from models import Project, ProjectFile, ProjectRoute, ProjectRuleHit, ProjectSourceSinkHint
from services.project_index import sync_project_index


@pytest.mark.asyncio
async def test_sync_writes_routes_and_rule_hits(session):
    proj = Project(name="t", upload_path="x")
    session.add(proj)
    await session.flush()

    payload = {
        "static_routes": [
            {"method": "GET", "path": "/api/login", "handler": "login", "file_path": "app/auth.py"},
            {"method": "POST", "path": "/api/upload", "handler": "upload", "file_path": "app/upload.py", "auth": "JWT"},
        ],
        "rule_hits": [
            {"label": "rce", "title": "os.system", "file_path": "app/cmd.py",
             "risk_score": 10, "weighted_score": 9.5, "stage_nums": [3, 4]},
            {"label": "sqli", "title": "raw sql", "file_path": "app/db.py",
             "risk_score": 8, "weighted_score": 7.0},
        ],
    }
    await sync_project_index(session, proj.id, payload)
    await session.commit()

    routes = (await session.execute(
        select(ProjectRoute).where(ProjectRoute.project_id == proj.id)
    )).scalars().all()
    assert len(routes) == 2
    r0 = next(r for r in routes if r.path == "/api/login")
    assert r0.method == "GET"
    assert r0.handler == "login"
    assert r0.route_id.startswith("rt_")  # 与 M4a 漏洞侧 route_id 同源
    assert r0.file_path == "app/auth.py"
    r1 = next(r for r in routes if r.path == "/api/upload")
    assert r1.auth == "JWT"

    hits = (await session.execute(
        select(ProjectRuleHit).where(ProjectRuleHit.project_id == proj.id)
    )).scalars().all()
    assert len(hits) == 2
    h0 = next(h for h in hits if h.label == "rce")
    assert h0.risk_score == 10
    assert h0.weighted_score == 9.5
    assert h0.stage_nums  # list 被 json.dumps 成非空字符串
    assert "3" in h0.stage_nums and "4" in h0.stage_nums


@pytest.mark.asyncio
async def test_sync_full_replace_is_idempotent(session):
    """二次 sync 全量替换：旧行清空、新行就位（匹配 warm 覆写语义）。"""
    proj = Project(name="t", upload_path="x")
    session.add(proj)
    await session.flush()

    await sync_project_index(session, proj.id, {
        "static_routes": [{"method": "GET", "path": "/a"}],
        "rule_hits": [{"label": "x", "title": "t"}],
    })
    await session.commit()
    await sync_project_index(session, proj.id, {
        "static_routes": [{"method": "POST", "path": "/b"}],
        "rule_hits": [],
    })
    await session.commit()

    routes = (await session.execute(
        select(ProjectRoute).where(ProjectRoute.project_id == proj.id)
    )).scalars().all()
    assert len(routes) == 1
    assert routes[0].path == "/b"
    hits = (await session.execute(
        select(ProjectRuleHit).where(ProjectRuleHit.project_id == proj.id)
    )).scalars().all()
    assert hits == []


@pytest.mark.asyncio
async def test_sync_tolerates_missing_and_bad_elements(session):
    """单条 dict 缺字段 / 非法元素 / 非 dict payload 都不应中断整批 sync。"""
    proj = Project(name="t", upload_path="x")
    session.add(proj)
    await session.flush()

    await sync_project_index(session, proj.id, {
        "static_routes": [
            {"path": "/only-path"},   # 缺 method/handler/file_path
            "not-a-dict",             # 非法元素应被过滤
        ],
        "rule_hits": [{"label": "bare"}],
    })
    await session.commit()

    routes = (await session.execute(
        select(ProjectRoute).where(ProjectRoute.project_id == proj.id)
    )).scalars().all()
    assert len(routes) == 1
    assert routes[0].path == "/only-path"
    assert routes[0].method == ""  # 缺字段回退默认
    assert routes[0].route_id  # 仍能算出 route_id

    # 非 dict payload 不抛
    await sync_project_index(session, proj.id, None)  # type: ignore[arg-type]
    await session.commit()


@pytest.mark.asyncio
async def test_sync_empty_payload_clears_tables(session):
    """空 payload → 两表清空（不残留旧行）。"""
    proj = Project(name="t", upload_path="x")
    session.add(proj)
    await session.flush()

    await sync_project_index(session, proj.id, {
        "static_routes": [{"method": "GET", "path": "/a"}],
        "rule_hits": [{"label": "x"}],
    })
    await session.commit()
    await sync_project_index(session, proj.id, {})
    await session.commit()

    routes = (await session.execute(
        select(ProjectRoute).where(ProjectRoute.project_id == proj.id)
    )).scalars().all()
    assert routes == []
    hits = (await session.execute(
        select(ProjectRuleHit).where(ProjectRuleHit.project_id == proj.id)
    )).scalars().all()
    assert hits == []


@pytest.mark.asyncio
async def test_sync_writes_source_sink_hints(session):
    """M4b 三联：source_sink_hints 影子写入第三表，list 字段 json.dumps 成字符串。"""
    proj = Project(name="t", upload_path="x")
    session.add(proj)
    await session.flush()

    await sync_project_index(session, proj.id, {
        "source_sink_hints": [
            {
                "label": "rce",
                "title": "os.system(cmd)",
                "file_path": "app/cmd.py",
                "chunk_path": "app/cmd.py::run",
                "stage_nums": [3, 4],
                "source_types": ["query"],
                "sink_keywords": ["os.system"],
                "route_paths": ["POST /exec"],
                "risk_score": 11,
                "evidence": "taint flow",
            },
        ],
    })
    await session.commit()

    hints = (await session.execute(
        select(ProjectSourceSinkHint).where(ProjectSourceSinkHint.project_id == proj.id)
    )).scalars().all()
    assert len(hints) == 1
    h = hints[0]
    assert h.label == "rce"
    assert h.risk_score == 11
    assert "query" in h.source_types
    assert "os.system" in h.sink_keywords
    assert "POST /exec" in h.route_paths
    assert "3" in h.stage_nums and "4" in h.stage_nums

    # 全量替换：再 sync 空列表 → 第三表清空（与 routes/rule_hits 同语义）
    await sync_project_index(session, proj.id, {"source_sink_hints": []})
    await session.commit()
    hints2 = (await session.execute(
        select(ProjectSourceSinkHint).where(ProjectSourceSinkHint.project_id == proj.id)
    )).scalars().all()
    assert hints2 == []


@pytest.mark.asyncio
async def test_sync_writes_project_files(session):
    """§9.3：project_files 影子写入第四表（与三联并列），全量替换语义。"""
    proj = Project(name="t", upload_path="x")
    session.add(proj)
    await session.flush()

    await sync_project_index(session, proj.id, {
        "project_files": [
            {
                "path": "app/cmd.py",
                "size": 1024,
                "extension": ".py",
                "role": "controller",
                "risk_score": 10,
                "content_hash": "abcdef0123456789",
            },
            {
                "path": "app/util.py",
                "size": 512,
                "extension": ".py",
                "role": "service",
                # risk_score 缺字段 → 回退 0
            },
        ],
    })
    await session.commit()

    files = (await session.execute(
        select(ProjectFile).where(ProjectFile.project_id == proj.id)
    )).scalars().all()
    assert len(files) == 2
    f0 = next(f for f in files if f.path == "app/cmd.py")
    assert f0.size == 1024
    assert f0.extension == ".py"
    assert f0.role == "controller"
    assert f0.risk_score == 10
    assert f0.content_hash == "abcdef0123456789"
    f1 = next(f for f in files if f.path == "app/util.py")
    assert f1.risk_score == 0  # 缺字段回退默认

    # 全量替换：再 sync 空列表 → 第四表清空（与三联同语义）
    await sync_project_index(session, proj.id, {"project_files": []})
    await session.commit()
    files2 = (await session.execute(
        select(ProjectFile).where(ProjectFile.project_id == proj.id)
    )).scalars().all()
    assert files2 == []
