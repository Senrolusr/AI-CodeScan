from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from database import get_db
from errors import ApiError
from models import AuditStage, User, Vulnerability
from schemas import VulnerabilityOut
from services.audit_engine import _severity_match_values, _severity_order_expr
from services.auth import verify_token
from services.vulnerability_review import (
    REVIEW_STATUSES,
    VULN_STATUSES,
    is_valid_review_status,
    is_valid_vuln_status,
)

router = APIRouter()


class VulnerabilityReviewUpdate(BaseModel):
    """复核状态更新（文档 12.2 的 PUT /status + POST /review 合并为单一 PATCH）。

    不含 reviewer：复核人由后端从登录态（current_user.username）写入，前端不可声明，
    防止伪造审核责任归属。pydantic 默认忽略多余字段，旧前端即便传 reviewer 也不会报错。
    """
    review_status: str | None = None
    status: str | None = None
    review_note: str | None = None


@router.get("", response_model=list[VulnerabilityOut])
async def list_vulnerabilities(
    task_id: int = None,
    severity: str = None,
    review_status: str = None,
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
    if review_status:
        wanted = [s.strip() for s in review_status.split(",") if s.strip()]
        if wanted:
            query = query.where(Vulnerability.review_status.in_(wanted))
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
        raise ApiError("VULNERABILITY_NOT_FOUND", "漏洞不存在", status_code=404)
    return vuln


@router.delete("/{vuln_id}")
async def delete_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise ApiError("VULNERABILITY_NOT_FOUND", "漏洞不存在", status_code=404)

    await db.delete(vuln)
    await db.commit()
    return {"message": "漏洞已删除"}


@router.patch("/{vuln_id}", response_model=VulnerabilityOut)
async def update_vulnerability_review(
    vuln_id: int,
    payload: VulnerabilityReviewUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(verify_token),
):
    """更新漏洞复核状态/生命周期/备注。

    reviewer 始终取当前登录用户（current_user.username），与 reviewed_at 同步写入——
    审核责任归属来自鉴权身份，不接受前端声明。
    """
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise ApiError("VULNERABILITY_NOT_FOUND", "漏洞不存在", status_code=404)

    changed = False
    if payload.review_status is not None:
        if not is_valid_review_status(payload.review_status):
            raise ApiError("INVALID_REVIEW_STATUS", f"非法 review_status，可选：{', '.join(REVIEW_STATUSES)}", status_code=400)
        vuln.review_status = payload.review_status
        changed = True
    if payload.status is not None:
        if not is_valid_vuln_status(payload.status):
            raise ApiError("INVALID_VULN_STATUS", f"非法 status，可选：{', '.join(VULN_STATUSES)}", status_code=400)
        vuln.status = payload.status
        changed = True
    if payload.review_note is not None:
        vuln.review_note = payload.review_note
        changed = True
    if changed:
        vuln.reviewer = current_user.username
        vuln.reviewed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(vuln)
    return vuln
