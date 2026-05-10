import json
import os
import shutil
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AuditStage, AuditTask, LlmConfig, Project, Vulnerability
from prompts.stage_prompts import get_stage_name
from schemas import AuditCreate, AuditStageOut, AuditTaskOut, RunPhaseRequest, VulnerabilityOut
from services.audit_engine import _severity_match_values
from services.audit_worker import clear_task_queue_state, mark_task_queued

router = APIRouter()

VALID_STAGE_NUMS = set(range(1, 10))


async def _create_stage_records(db: AsyncSession, task_id: int):
    for stage_num in range(1, 10):
        db.add(
            AuditStage(
                task_id=task_id,
                stage_num=stage_num,
                stage_name=get_stage_name(stage_num),
                status="pending",
            )
        )
    db.add(AuditStage(task_id=task_id, stage_num=-1, stage_name="Supervisor 规划", agent_role="supervisor_plan", status="pending"))
    db.add(AuditStage(task_id=task_id, stage_num=-2, stage_name="Supervisor 审核", agent_role="supervisor_review", status="pending"))


async def _reset_stage_state(db: AsyncSession, task_id: int, stage_nums: list[int]):
    if not stage_nums:
        return

    result = await db.execute(
        select(AuditStage).where(
            AuditStage.task_id == task_id,
            AuditStage.stage_num.in_(stage_nums),
        )
    )
    stages = result.scalars().all()

    for stage in stages:
        if stage.artifact_path:
            artifact_path = stage.artifact_path
            if not os.path.isabs(artifact_path):
                artifact_path = os.path.join(os.getcwd(), artifact_path)
            artifact_path = os.path.abspath(artifact_path)
            if os.path.isfile(artifact_path):
                try:
                    os.remove(artifact_path)
                except OSError:
                    pass

        stage.status = "pending"
        stage.findings = []
        stage.prompt_used = ""
        stage.llm_response = ""
        stage.compressed_summary = {}
        stage.artifact_path = ""
        stage.started_at = None
        stage.completed_at = None

    await db.execute(
        delete(Vulnerability).where(
            Vulnerability.task_id == task_id,
            Vulnerability.stage_id.in_([stage.id for stage in stages]),
        )
    )


async def _delete_audit_records(db: AsyncSession, task: AuditTask):
    await db.execute(delete(Vulnerability).where(Vulnerability.task_id == task.id))
    await db.execute(delete(AuditStage).where(AuditStage.task_id == task.id))
    await db.delete(task)

    report_dir = os.path.join("reports", str(task.id))
    if os.path.isdir(report_dir):
        shutil.rmtree(report_dir, ignore_errors=True)
    artifact_dir = os.path.join("data", "stage_artifacts", str(task.id))
    if os.path.isdir(artifact_dir):
        shutil.rmtree(artifact_dir, ignore_errors=True)


async def _get_task_with_stages(db: AsyncSession, task_id: int) -> tuple[AuditTask, list[AuditStage]]:
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "审计任务不存在")

    result = await db.execute(select(AuditStage).where(AuditStage.task_id == task_id).order_by(AuditStage.stage_num))
    stages = result.scalars().all()
    return task, stages


@router.post("", response_model=AuditTaskOut)
async def create_audit(
    data: AuditCreate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Project).where(Project.id == data.project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "项目不存在")

    result = await db.execute(select(LlmConfig).where(LlmConfig.id == data.llm_config_id))
    llm_config = result.scalar_one_or_none()
    if not llm_config:
        raise HTTPException(404, "模型配置不存在")

    summary_data = {
        "selected_stage_nums": list(range(1, 10)),
        "current_phase": 1,
        "multi_agent_phase_mode": True,
    }

    task = AuditTask(
        project_id=data.project_id,
        llm_config_id=data.llm_config_id,
        status="paused",
        current_stage=0,
        total_stages=9,
        audit_mode="multi_agent",
        summary=summary_data,
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    await _create_stage_records(db, task.id)
    await db.commit()

    return task


@router.post("/{task_id}/run-phase", response_model=AuditTaskOut)
async def run_audit_phase(
    task_id: int,
    data: RunPhaseRequest,
    db: AsyncSession = Depends(get_db),
):
    task, stages = await _get_task_with_stages(db, task_id)

    if task.status not in {"paused", "pending"}:
        raise HTTPException(400, "只有暂停或待处理的审计可以执行下一阶段")
    if data.phase < 1 or data.phase > 4:
        raise HTTPException(400, "Phase 编号必须在 1-4 之间")

    summary = task.summary if isinstance(task.summary, dict) else {}
    current_phase = summary.get("current_phase", 1)

    if data.phase != current_phase:
        raise HTTPException(400, f"请按顺序执行：当前应执行 Phase {current_phase}")

    summary["multi_agent_phase_mode"] = True
    summary["current_phase"] = data.phase
    task.summary = summary

    all_stage_nums = [s.stage_num for s in stages]
    mark_task_queued(task, all_stage_nums)
    await db.commit()

    await db.refresh(task)
    return task


@router.get("", response_model=list[AuditTaskOut])
async def list_audits(
    project_id: int = None,
    limit: int = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditTask).order_by(AuditTask.created_at.desc())
    if project_id:
        query = query.where(AuditTask.project_id == project_id)
    if limit:
        query = query.limit(min(limit, 100))
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{task_id}", response_model=AuditTaskOut)
async def get_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "审计任务不存在")
    return task


@router.post("/{task_id}/cancel", response_model=AuditTaskOut)
async def cancel_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "审计任务不存在")
    if task.status not in {"pending", "running", "paused"}:
        raise HTTPException(400, "只有待处理、运行中或已暂停的审计可以取消")

    task.status = "cancelled"
    task.error_message = "已由用户取消"
    task.completed_at = datetime.now(timezone.utc)
    clear_task_queue_state(task)

    result = await db.execute(select(AuditStage).where(AuditStage.task_id == task_id))
    for stage in result.scalars().all():
        if stage.status == "running":
            stage.status = "cancelled"
            stage.completed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(task)
    return task


@router.post("/{task_id}/retry", response_model=AuditTaskOut)
async def retry_audit(
    task_id: int,
    db: AsyncSession = Depends(get_db),
):
    task, stages = await _get_task_with_stages(db, task_id)
    if task.status == "running":
        raise HTTPException(400, "运行中的审计不能重试")

    rerun_stage_nums = [stage.stage_num for stage in stages if stage.status in {"failed", "completed", "cancelled"}]
    if not rerun_stage_nums:
        raise HTTPException(400, "没有可重试的阶段")

    summary = task.summary if isinstance(task.summary, dict) else {}
    summary["selected_stage_nums"] = rerun_stage_nums
    summary.pop("audit_memory", None)
    task.summary = summary
    mark_task_queued(task, rerun_stage_nums)
    await _reset_stage_state(db, task.id, rerun_stage_nums)
    await db.commit()

    await db.refresh(task)
    return task


@router.get("/{task_id}/stages", response_model=list[AuditStageOut])
async def get_audit_stages(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id).order_by(AuditStage.stage_num)
    )
    stages = result.scalars().all()
    for stage in stages:
        if 1 <= stage.stage_num <= 9:
            stage.stage_name = get_stage_name(stage.stage_num)
        try:
            prompt_data = json.loads(stage.prompt_used) if stage.prompt_used else {}
        except Exception:
            prompt_data = {}
        try:
            response_data = json.loads(stage.llm_response) if stage.llm_response else {}
        except Exception:
            response_data = {}

        debug = prompt_data.get("debug") if isinstance(prompt_data, dict) else None
        if debug or (isinstance(response_data, dict) and response_data.get("error")):
            stage.findings = stage.findings if isinstance(stage.findings, dict) else {"data": stage.findings}
            stage.findings.setdefault(
                "_debug",
                {
                    "prompt_length": len(stage.prompt_used or ""),
                    "selected_chunk_count": (debug or {}).get("selected_chunk_count"),
                    "code_text_length": (debug or {}).get("code_text_length"),
                    "user_prompt_length": (debug or {}).get("user_prompt_length"),
                    "static_route_count": (debug or {}).get("static_route_count"),
                    "prev_context_length": (debug or {}).get("prev_context_length"),
                    "planned_batch_count": (debug or {}).get("planned_batch_count") or (debug or {}).get("batch_count"),
                    "executed_batch_count": (debug or {}).get("executed_batch_count"),
                    "early_stop": (debug or {}).get("early_stop"),
                    "error": response_data.get("error") if isinstance(response_data, dict) else None,
                },
            )
    return stages


@router.get("/{task_id}/stages/{stage_num}/artifact")
async def get_audit_stage_artifact(task_id: int, stage_num: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id, AuditStage.stage_num == stage_num)
    )
    stage = result.scalar_one_or_none()
    if not stage:
        raise HTTPException(404, "审计阶段不存在")
    if not stage.artifact_path:
        raise HTTPException(404, "阶段产物不存在")

    artifact_path = stage.artifact_path
    if not os.path.isabs(artifact_path):
        artifact_path = os.path.join(os.getcwd(), artifact_path)
    artifact_path = os.path.abspath(artifact_path)

    if not os.path.isfile(artifact_path):
        raise HTTPException(404, "阶段产物文件不存在")

    try:
        with open(artifact_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as exc:
        raise HTTPException(500, f"读取阶段产物失败：{exc}")

    return {
        "task_id": task_id,
        "stage_num": stage_num,
        "artifact_path": stage.artifact_path,
        "payload": payload,
    }


@router.get("/{task_id}/vulns", response_model=list[VulnerabilityOut])
async def get_audit_vulns(
    task_id: int,
    severity: str = None,
    confirmed_status: str = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Vulnerability).where(Vulnerability.task_id == task_id)
    if severity:
        query = query.where(Vulnerability.severity.in_(_severity_match_values(severity)))
    if confirmed_status:
        query = query.where(Vulnerability.confirmed_status == confirmed_status)
    result = await db.execute(query.order_by(Vulnerability.id))
    return result.scalars().all()


@router.delete("/{task_id}")
async def delete_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "审计任务不存在")
    if task.status in {"pending", "running"}:
        raise HTTPException(400, "运行中的审计不能删除，请先取消")

    await _delete_audit_records(db, task)
    await db.commit()

    return {"message": "审计已删除"}
