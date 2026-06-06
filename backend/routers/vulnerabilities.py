from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from models import AuditStage, Vulnerability
from schemas import VulnerabilityOut
from services.audit_engine import _severity_match_values, _severity_order_expr

router = APIRouter()


@router.get("", response_model=list[VulnerabilityOut])
async def list_vulnerabilities(
    task_id: int = None,
    severity: str = None,
    limit: int = None,
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Vulnerability)
        .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
        .where(AuditStage.stage_num.between(2, 9))
    )
    if task_id:
        query = query.where(Vulnerability.task_id == task_id)
    if severity:
        query = query.where(Vulnerability.severity.in_(_severity_match_values(severity)))
    query = query.order_by(_severity_order_expr(Vulnerability.severity).desc(), Vulnerability.id.desc())
    if limit:
        query = query.limit(min(limit, 200))
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
async def get_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability)
        .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
        .where(
            Vulnerability.id == vuln_id,
            AuditStage.stage_num.between(2, 9),
        )
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "漏洞不存在")
    return vuln


@router.delete("/{vuln_id}")
async def delete_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "漏洞不存在")

    await db.delete(vuln)
    await db.commit()
    return {"message": "漏洞已删除"}
