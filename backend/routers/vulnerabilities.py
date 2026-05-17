from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import case, select
from database import get_db
from models import Vulnerability
from schemas import VulnStatusUpdate, VulnerabilityOut
from services.audit_engine import _severity_match_values

router = APIRouter()


@router.get("", response_model=list[VulnerabilityOut])
async def list_vulnerabilities(
    task_id: int = None,
    severity: str = None,
    confirmed_status: str = None,
    verification_state: str = None,
    limit: int = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Vulnerability)
    if task_id:
        query = query.where(Vulnerability.task_id == task_id)
    if severity:
        query = query.where(Vulnerability.severity.in_(_severity_match_values(severity)))
    if confirmed_status:
        query = query.where(Vulnerability.confirmed_status == confirmed_status)
    if verification_state:
        query = query.where(Vulnerability.verification_state == verification_state)
    query = query.order_by(
        case((Vulnerability.verification_state == "verified", 0), else_=1),
        Vulnerability.id.desc(),
    )
    if limit:
        query = query.limit(min(limit, 200))
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
async def get_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "漏洞不存在")
    return vuln


@router.patch("/{vuln_id}", response_model=VulnerabilityOut)
async def update_vulnerability_status(
    vuln_id: int,
    data: VulnStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    valid_statuses = ["pending", "confirmed", "false_positive", "fixed"]
    if data.confirmed_status not in valid_statuses:
        raise HTTPException(400, f"无效状态，必须是以下之一：{valid_statuses}")

    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "漏洞不存在")

    vuln.confirmed_status = data.confirmed_status
    await db.commit()
    await db.refresh(vuln)
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
