import os

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db
from models import AuditTask, Vulnerability, AuditStage, Project
from schemas import ReportExport
from services.audit_cleanup import get_audit_report_dir
from services.report_generator import generate_markdown, generate_pdf

router = APIRouter()


@router.post("/export")
async def export_report(data: ReportExport, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == data.task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "审计任务不存在")

    result = await db.execute(select(Project).where(Project.id == task.project_id))
    project = result.scalar_one_or_none()

    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == data.task_id).order_by(AuditStage.stage_num)
    )
    stages = result.scalars().all()

    result = await db.execute(select(Vulnerability).where(Vulnerability.task_id == data.task_id))
    vulns = result.scalars().all()

    report_dir = get_audit_report_dir(data.task_id)
    os.makedirs(report_dir, exist_ok=True)

    if data.format == "md":
        filepath = generate_markdown(report_dir, project, task, stages, vulns)
    elif data.format == "pdf":
        filepath = generate_pdf(report_dir, project, task, stages, vulns)
    else:
        raise HTTPException(400, "不支持的导出格式，仅支持 md 或 pdf")

    filename = os.path.basename(filepath)
    return {
        "filepath": f"reports/{data.task_id}/{filename}",
        "filename": filename,
        "download_url": f"/api/reports/download/{data.task_id}/{filename}",
    }


@router.get("/download/{task_id}/{filename}")
async def download_report(task_id: int, filename: str):
    safe_name = os.path.basename(filename)
    if safe_name != filename:
        raise HTTPException(400, "非法文件名")

    filepath = os.path.join(get_audit_report_dir(task_id), safe_name)
    if not os.path.exists(filepath):
        raise HTTPException(404, "报告文件不存在")

    media_type = "application/pdf" if filename.endswith(".pdf") else "text/markdown"
    return FileResponse(filepath, media_type=media_type, filename=filename)


@router.get("/list/{task_id}")
async def list_reports(task_id: int):
    report_dir = get_audit_report_dir(task_id)
    if not os.path.exists(report_dir):
        return []

    files = []
    for file_name in os.listdir(report_dir):
        filepath = os.path.join(report_dir, file_name)
        if not os.path.isfile(filepath):
            continue
        files.append(
            {
                "filename": file_name,
                "size": os.path.getsize(filepath),
                "download_url": f"/api/reports/download/{task_id}/{file_name}",
            }
        )
    return files


@router.delete("/{task_id}/{filename}")
async def delete_report(task_id: int, filename: str):
    safe_name = os.path.basename(filename)
    if safe_name != filename:
        raise HTTPException(400, "非法文件名")

    filepath = os.path.join(get_audit_report_dir(task_id), safe_name)
    if not os.path.exists(filepath):
        raise HTTPException(404, "报告文件不存在")

    os.remove(filepath)
    return {"message": "报告已删除"}
