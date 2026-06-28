"""§11.4 统一错误响应：全局 exception_handler 把所有 API 错误转成 {code, message, details}。

覆盖三类 handler：
- ``ApiError`` → 业务语义 code（AUDIT_NOT_FOUND 等）；
- 存量 ``HTTPException``（含 Starlette 路由 404）→ 自动包成 ``HTTP_<status>``；
- ``RequestValidationError`` → 422 ``VALIDATION_ERROR``。
"""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_api_error_returns_semantic_code(db_client):
    """业务端点 raise ApiError → 响应带语义化 code（非旧 detail 字符串）。"""
    client, _ = db_client
    r = await client.get("/api/audits/999999")
    assert r.status_code == 404
    body = r.json()
    assert body["code"] == "AUDIT_NOT_FOUND"
    assert body["message"]  # 非空友好提示
    assert body["details"] == {}


@pytest.mark.asyncio
async def test_bare_http_exception_wrapped_to_code(db_client):
    """存量裸 HTTPException（含 Starlette 路由 404）自动包成 HTTP_<status>。"""
    client, _ = db_client
    r = await client.get("/api/no-such-endpoint-xyz")
    assert r.status_code == 404
    body = r.json()
    assert body["code"] == "HTTP_404"
    assert body["message"]
    assert body["details"] == {}


@pytest.mark.asyncio
async def test_request_validation_error_422(db_client):
    """请求体校验失败 → 422 VALIDATION_ERROR，details 带校验明细。"""
    client, _ = db_client
    r = await client.post("/api/auth/login", json={})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "VALIDATION_ERROR"
    assert body["details"]["errors"]  # 带校验错误明细


@pytest.mark.asyncio
async def test_invalid_review_status_returns_code(db_client):
    """非法枚举（review_status）→ INVALID_REVIEW_STATUS（覆盖改用 ApiError 的业务校验）。"""
    client, Session = db_client
    from models import AuditStage, AuditTask, Project, Vulnerability

    async with Session() as s:
        proj = Project(name="t", upload_path="x")
        s.add(proj)
        await s.flush()
        task = AuditTask(project_id=proj.id, total_stages=9, llm_config_id=1)
        s.add(task)
        await s.flush()
        stage = AuditStage(task_id=task.id, stage_num=2, stage_name="RCE", status="completed")
        s.add(stage)
        await s.flush()
        v = Vulnerability(task_id=task.id, stage_id=stage.id, title="SQLi", severity="High",
                          vuln_type="sql_injection", dedupe_key="k1")
        s.add(v)
        await s.commit()
        await s.refresh(v)
        vuln_id = v.id

    r = await client.patch(f"/api/vulnerabilities/{vuln_id}", json={"review_status": "bogus"})
    assert r.status_code == 400
    assert r.json()["code"] == "INVALID_REVIEW_STATUS"
