"""M4b：project_routes / project_rule_hits 两表 + 关键索引存在性（create_all 建表）。"""

from __future__ import annotations

import pytest
from sqlalchemy import text


async def _columns(engine, table: str) -> set[str]:
    async with engine.connect() as conn:
        rows = (await conn.execute(text(f"PRAGMA table_info({table})"))).fetchall()
    return {r[1] for r in rows}


async def _index_names(engine, table: str) -> set[str]:
    async with engine.connect() as conn:
        rows = (await conn.execute(text(f"PRAGMA index_list('{table}')"))).fetchall()
    return {r[1] for r in rows}


@pytest.mark.asyncio
async def test_project_routes_table_columns(engine):
    cols = await _columns(engine, "project_routes")
    expected = {
        "id", "project_id", "route_id", "method", "path", "handler",
        "file_path", "auth", "line_start", "source_kind", "params", "notes",
    }
    assert expected <= cols


@pytest.mark.asyncio
async def test_project_routes_indexes(engine):
    idx = await _index_names(engine, "project_routes")
    assert "ix_project_routes_project_id" in idx
    assert "ix_project_routes_route_id" in idx  # JOIN vulnerabilities.route_id 的主表索引


@pytest.mark.asyncio
async def test_project_rule_hits_table_columns(engine):
    cols = await _columns(engine, "project_rule_hits")
    expected = {
        "id", "project_id", "label", "title", "file_path", "chunk_path",
        "chunk_type", "risk_score", "keyword_hit_count", "weighted_score",
        "stage_nums", "evidence",
    }
    assert expected <= cols


@pytest.mark.asyncio
async def test_project_rule_hits_indexes(engine):
    idx = await _index_names(engine, "project_rule_hits")
    assert "ix_project_rule_hits_project_id" in idx
