"""M6：全部业务接口要求登录——无 token → 401，有 token → 200。"""

from __future__ import annotations


async def test_no_token_projects_401(db_client):
    client, _ = db_client
    client.headers.pop("Authorization", None)
    assert (await client.get("/api/projects")).status_code == 401


async def test_no_token_stats_401(db_client):
    client, _ = db_client
    client.headers.pop("Authorization", None)
    assert (await client.get("/api/stats")).status_code == 401


async def test_no_token_reports_list_401(db_client):
    client, _ = db_client
    client.headers.pop("Authorization", None)
    assert (await client.get("/api/reports/list/1")).status_code == 401


async def test_no_token_vulnerabilities_401(db_client):
    client, _ = db_client
    client.headers.pop("Authorization", None)
    assert (await client.get("/api/vulnerabilities")).status_code == 401


async def test_with_token_projects_200(db_client):
    client, _ = db_client
    # db_client fixture 已注入 admin token
    assert (await client.get("/api/projects")).status_code == 200


async def test_with_token_stats_200(db_client):
    client, _ = db_client
    assert (await client.get("/api/stats")).status_code == 200
