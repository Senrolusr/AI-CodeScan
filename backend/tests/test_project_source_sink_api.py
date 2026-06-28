"""M4b 三联之 GET /api/projects/{id}/source-sink-hints 接口测试（§12.2 行1087）。"""

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
            "source_sink_hints": [
                {
                    "label": "rce",
                    "title": "os.system(command)",
                    "file_path": "app/cmd.py",
                    "chunk_path": "app/cmd.py::handle",
                    "stage_nums": [2, 3],
                    "source_types": ["query", "body"],
                    "sink_keywords": ["os.system", "subprocess"],
                    "route_paths": ["POST /api/exec"],
                    "risk_score": 12,
                    "evidence": "user input flows into os.system",
                },
                {
                    "label": "injection",
                    "title": "raw SQL concat",
                    "file_path": "app/db.py",
                    "source_types": ["query"],
                    "sink_keywords": ["cursor.execute"],
                    "risk_score": 8,
                },
            ],
        })
        await s.commit()
        return client, proj.id


@pytest.mark.asyncio
async def test_get_source_sink_hints_ordered_by_risk_desc(db_client):
    client, project_id = await _seed_with_index(db_client)
    r = await client.get(f"/api/projects/{project_id}/source-sink-hints")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2
    scores = [d["risk_score"] for d in data]
    assert scores == sorted(scores, reverse=True)
    top = data[0]
    assert top["label"] == "rce"  # 12 > 8
    assert top["title"] == "os.system(command)"
    # list 字段被 json.dumps 成非空字符串
    assert "query" in top["source_types"] and "body" in top["source_types"]
    assert "os.system" in top["sink_keywords"]
    assert "POST /api/exec" in top["route_paths"]
    assert "2" in top["stage_nums"] and "3" in top["stage_nums"]


@pytest.mark.asyncio
async def test_get_source_sink_hints_404_when_project_missing(db_client):
    client, _ = db_client
    r = await client.get("/api/projects/999999/source-sink-hints")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_source_sink_hints_empty_when_project_has_no_index(db_client):
    client, Session = db_client
    async with Session() as s:
        proj = Project(name="t", upload_path="x")
        s.add(proj)
        await s.commit()
        pid = proj.id
    r = await client.get(f"/api/projects/{pid}/source-sink-hints")
    assert r.status_code == 200
    assert r.json() == []
