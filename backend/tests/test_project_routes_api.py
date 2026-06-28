"""M4b：GET /api/projects/{id}/routes + /rule-hits 接口测试。"""

from __future__ import annotations

import pytest

from models import Project
from services.project_index import sync_project_index


async def _seed_with_index(db_client):
    client, Session = db_client
    async with Session() as s:
        proj = Project(name="t", upload_path="x")
        s.add(proj)
        await s.flush()
        await sync_project_index(s, proj.id, {
            "static_routes": [
                {"method": "GET", "path": "/api/login", "handler": "login", "file_path": "app/auth.py"},
                {"method": "POST", "path": "/api/users", "handler": "create_user", "file_path": "app/users.py"},
            ],
            "rule_hits": [
                {"label": "rce", "title": "os.system", "file_path": "app/cmd.py", "weighted_score": 9.5},
                {"label": "sqli", "title": "raw sql", "file_path": "app/db.py", "weighted_score": 7.0},
            ],
        })
        await s.commit()
        return client, proj.id


@pytest.mark.asyncio
async def test_get_routes_returns_list_ordered_by_path(db_client):
    client, project_id = await _seed_with_index(db_client)
    r = await client.get(f"/api/projects/{project_id}/routes")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2
    paths = [d["path"] for d in data]
    assert paths == sorted(paths)  # order_by path
    login = next(d for d in data if d["path"] == "/api/login")
    assert login["method"] == "GET"
    assert login["handler"] == "login"
    assert login["route_id"].startswith("rt_")


@pytest.mark.asyncio
async def test_get_rule_hits_ordered_by_weighted_desc(db_client):
    client, project_id = await _seed_with_index(db_client)
    r = await client.get(f"/api/projects/{project_id}/rule-hits")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2
    scores = [d["weighted_score"] for d in data]
    assert scores == sorted(scores, reverse=True)
    assert data[0]["label"] == "rce"  # 9.5 > 7.0


@pytest.mark.asyncio
async def test_get_routes_404_when_project_missing(db_client):
    client, _ = db_client
    r = await client.get("/api/projects/999999/routes")
    assert r.status_code == 404
    r2 = await client.get("/api/projects/999999/rule-hits")
    assert r2.status_code == 404


@pytest.mark.asyncio
async def test_get_routes_empty_when_project_has_no_index(db_client):
    client, Session = db_client
    async with Session() as s:
        proj = Project(name="t", upload_path="x")
        s.add(proj)
        await s.commit()
        pid = proj.id
    r = await client.get(f"/api/projects/{pid}/routes")
    assert r.status_code == 200
    assert r.json() == []
    r2 = await client.get(f"/api/projects/{pid}/rule-hits")
    assert r2.status_code == 200
    assert r2.json() == []
