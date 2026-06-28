"""§9.3 GET /api/projects/{id}/files 接口测试（项目源文件结构化索引）。"""

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
            "static_routes": [],
            "rule_hits": [],
            "source_sink_hints": [],
            "project_files": [
                {
                    "path": "app/cmd.py",
                    "size": 1024,
                    "extension": ".py",
                    "role": "controller",
                    "risk_score": 12,
                    "content_hash": "abcdef0123456789",
                },
                {
                    "path": "app/util.py",
                    "size": 512,
                    "extension": ".py",
                    "role": "service",
                    "risk_score": 3,
                    "content_hash": "fedcba9876543210",
                },
                {
                    "path": "app/zero.py",
                    "size": 0,
                    "extension": ".py",
                    "risk_score": 3,  # 与 util 同分 → 按 path 升序：util 在 zero 前
                    "content_hash": "",
                },
            ],
        })
        await s.commit()
        return client, proj.id


@pytest.mark.asyncio
async def test_get_project_files_ordered_by_risk_then_path(db_client):
    client, project_id = await _seed_with_index(db_client)
    r = await client.get(f"/api/projects/{project_id}/files")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 3
    # 12 → 3 → 3；同分按 path 升序（util.py < zero.py）
    paths = [d["path"] for d in data]
    assert paths == ["app/cmd.py", "app/util.py", "app/zero.py"]
    top = data[0]
    assert top["role"] == "controller"
    assert top["size"] == 1024
    assert top["extension"] == ".py"
    assert top["content_hash"] == "abcdef0123456789"


@pytest.mark.asyncio
async def test_get_project_files_404_when_project_missing(db_client):
    client, _ = db_client
    r = await client.get("/api/projects/999999/files")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_project_files_empty_when_project_has_no_index(db_client):
    client, Session = db_client
    async with Session() as s:
        proj = Project(name="t", upload_path="x")
        s.add(proj)
        await s.commit()
        pid = proj.id
    r = await client.get(f"/api/projects/{pid}/files")
    assert r.status_code == 200
    assert r.json() == []
