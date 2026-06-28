"""§12.3 snapshot 顶层稳定 view model 键测试：findings_summary / route_coverage / quality_notices。

§17.3：聚合数据应由后端提供为稳定顶层键，而非埋在 task.summary 让前端解析。
"""

from __future__ import annotations

import pytest

from models import AuditStage, AuditTask, LlmConfig, Project, Vulnerability


async def _seed(db_client):
    """seed project+llm+task(+route_coverage 于 summary)+stage2/3+三正式漏洞；stage2 findings 留候选差。"""
    client, Session = db_client
    async with Session() as s:
        proj = Project(name="t", upload_path="x", file_tree=[], tech_stack="flask")
        s.add(proj)
        await s.flush()
        cfg = LlmConfig(name="c", api_key="k", base_url="http://x", api_mode="chat_completions", model_name="m")
        s.add(cfg)
        await s.flush()
        task = AuditTask(
            project_id=proj.id,
            llm_config_id=cfg.id,
            total_stages=9,
            audit_mode="multi_agent",
            status="completed",
            summary={
                "route_coverage": {
                    "coverage_ratio": 0.5,
                    "total_routes": 4,
                    "audited_route_count": 2,
                    "has_route_gaps": True,
                },
            },
        )
        s.add(task)
        await s.flush()
        stage2 = AuditStage(task_id=task.id, stage_num=2, stage_name="注入", status="completed",
                            findings={"vulnerabilities": [{"x": 1}, {"x": 2}, {"x": 3}]})  # 3 候选
        stage3 = AuditStage(task_id=task.id, stage_num=3, stage_name="XSS", status="completed", findings={})
        s.add_all([stage2, stage3])
        await s.flush()
        # 正式漏洞：stage2 两条（Critical/High），stage3 一条（Medium）→ stage2 候选 3 vs 正式 2 → filtered=1
        s.add(Vulnerability(task_id=task.id, stage_id=stage2.id, title="A", severity="Critical", vuln_type="rce", dedupe_key="k1"))
        s.add(Vulnerability(task_id=task.id, stage_id=stage2.id, title="B", severity="High", vuln_type="rce", dedupe_key="k2"))
        s.add(Vulnerability(task_id=task.id, stage_id=stage3.id, title="C", severity="Medium", vuln_type="xss", dedupe_key="k3"))
        await s.commit()
        return client, task.id


@pytest.mark.asyncio
async def test_findings_summary_aggregates_by_severity(db_client):
    client, task_id = await _seed(db_client)
    snap = (await client.get(f"/api/audits/{task_id}/snapshot")).json()
    fs = snap["findings_summary"]
    assert fs["total"] == 3
    assert fs["by_severity"]["Critical"] == 1
    assert fs["by_severity"]["High"] == 1
    assert fs["by_severity"]["Medium"] == 1


@pytest.mark.asyncio
async def test_route_coverage_promoted_from_summary(db_client):
    """route_coverage 作为顶层键暴露（数据源仍为 runner 写入 summary 的同一份 dict）。"""
    client, task_id = await _seed(db_client)
    snap = (await client.get(f"/api/audits/{task_id}/snapshot")).json()
    rc = snap["route_coverage"]
    assert rc["coverage_ratio"] == 0.5
    assert rc["total_routes"] == 4
    assert rc["has_route_gaps"] is True


@pytest.mark.asyncio
async def test_quality_notices_surface_filtered_candidates(db_client):
    """stage2 候选 3 vs 正式 2 → filtered=1 的质量门通知。"""
    client, task_id = await _seed(db_client)
    snap = (await client.get(f"/api/audits/{task_id}/snapshot")).json()
    notices = snap["quality_notices"]
    assert isinstance(notices, list)
    filtered = [n for n in notices if n["kind"] == "filtered" and n["stage_num"] == 2]
    assert len(filtered) == 1
    assert filtered[0]["count"] == 1
    assert filtered[0]["message"]  # 带说明文案


@pytest.mark.asyncio
async def test_findings_summary_unaffected_by_query_filters(db_client):
    """findings_summary 基于全量正式漏洞，不受 severity/review_status 查询参数影响（与 review_summary 同口径）。"""
    client, task_id = await _seed(db_client)
    snap = (await client.get(f"/api/audits/{task_id}/snapshot?severity=Critical")).json()
    # vulnerabilities 列表被过滤（只剩 Critical），但 findings_summary.total 仍是全量 3
    assert len(snap["vulnerabilities"]) == 1
    assert snap["findings_summary"]["total"] == 3
