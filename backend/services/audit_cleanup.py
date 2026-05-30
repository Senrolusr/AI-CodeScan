import os
import shutil

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditStage, AuditTask, Vulnerability


BACKEND_ROOT = os.path.dirname(os.path.dirname(__file__))


def resolve_backend_path(*parts: str) -> str:
    return os.path.abspath(os.path.join(BACKEND_ROOT, *parts))


def get_audit_report_dir(task_id: int) -> str:
    return resolve_backend_path("reports", str(task_id))


def get_stage_artifact_dir(task_id: int) -> str:
    return resolve_backend_path("data", "stage_artifacts", str(task_id))


def resolve_audit_artifact_path(artifact_path: str) -> str:
    if not artifact_path:
        return ""
    if os.path.isabs(artifact_path):
        return os.path.abspath(artifact_path)
    return resolve_backend_path(artifact_path)


def remove_audit_artifact_file(artifact_path: str) -> None:
    resolved_path = resolve_audit_artifact_path(artifact_path)
    if resolved_path and os.path.isfile(resolved_path):
        try:
            os.remove(resolved_path)
        except OSError:
            pass


def cleanup_audit_outputs(task_id: int) -> None:
    report_dir = get_audit_report_dir(task_id)
    if os.path.isdir(report_dir):
        shutil.rmtree(report_dir, ignore_errors=True)

    artifact_dir = get_stage_artifact_dir(task_id)
    if os.path.isdir(artifact_dir):
        shutil.rmtree(artifact_dir, ignore_errors=True)


async def delete_audit_task_records(db: AsyncSession, task: AuditTask) -> None:
    await db.execute(delete(Vulnerability).where(Vulnerability.task_id == task.id))
    await db.execute(delete(AuditStage).where(AuditStage.task_id == task.id))
    await db.delete(task)
    cleanup_audit_outputs(task.id)
