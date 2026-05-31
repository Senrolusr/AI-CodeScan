import json
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AuditStage, AuditTask, LlmConfig, Project, Vulnerability
from prompts.stage_prompts import get_stage_name
from schemas import AuditCreate, AuditStageOut, AuditTaskOut, VulnerabilityOut
from services.audit_engine import _coerce_stage_findings, _severity_match_values, _severity_order_expr
from services.audit_worker import clear_task_queue_state, mark_task_queued
from services.audit_cleanup import (
    delete_audit_task_records,
    remove_audit_artifact_file,
    resolve_audit_artifact_path,
)

router = APIRouter()

VALID_STAGE_NUMS = set(range(1, 10))
REMOVED_SUMMARY_KEYS = {
    "verification_stats",
    "candidate_severity_stats",
    "diff_stats",
    "candidate_diff_stats",
}


def _strip_removed_summary_keys(summary):
    if not isinstance(summary, dict):
        return summary
    sanitized = dict(summary)
    for key in REMOVED_SUMMARY_KEYS:
        sanitized.pop(key, None)
    return sanitized


def _serialize_task(task: AuditTask) -> dict:
    current_stage = task.current_stage or 0
    total_stages = task.total_stages or 9
    if task.status == "completed" and current_stage <= 0:
        current_stage = total_stages

    return {
        "id": task.id,
        "name": task.name or f"审计 #{task.id}",
        "project_id": task.project_id,
        "llm_config_id": task.llm_config_id,
        "status": task.status,
        "current_stage": current_stage,
        "total_stages": total_stages,
        "audit_mode": task.audit_mode,
        "summary": _strip_removed_summary_keys(task.summary),
        "error_message": task.error_message,
        "created_at": task.created_at,
        "completed_at": task.completed_at,
    }


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
            remove_audit_artifact_file(stage.artifact_path)

        stage.status = "pending"
        stage.findings = {"vulnerabilities": []}
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

    audit_name = (data.name or "").strip()
    if not audit_name:
        audit_name = f"{project.name} 审计 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    audit_name = audit_name[:255]

    summary_data = {
        "selected_stage_nums": list(range(1, 10)),
        "current_phase": 1,
        "multi_agent_phase_mode": True,
    }

    task = AuditTask(
        name=audit_name,
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
    mark_task_queued(task, list(range(1, 10)))
    await db.commit()

    return _serialize_task(task)


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
    return [_serialize_task(task) for task in result.scalars().all()]


@router.get("/{task_id}", response_model=AuditTaskOut)
async def get_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "审计任务不存在")
    return _serialize_task(task)


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
    return _serialize_task(task)


@router.post("/{task_id}/retry", response_model=AuditTaskOut)
async def retry_audit(
    task_id: int,
    db: AsyncSession = Depends(get_db),
):
    task, stages = await _get_task_with_stages(db, task_id)
    if task.status not in {"completed", "failed", "cancelled"}:
        raise HTTPException(400, "只有已完成、失败或已取消的审计可以重试")

    rerun_stage_nums = [stage.stage_num for stage in stages if stage.status in {"failed", "completed", "cancelled"}]
    if not rerun_stage_nums:
        raise HTTPException(400, "没有可重试的阶段")

    summary = task.summary if isinstance(task.summary, dict) else {}
    summary["selected_stage_nums"] = rerun_stage_nums
    summary["current_phase"] = 1
    summary["multi_agent_phase_mode"] = True
    summary.pop("audit_memory", None)
    summary.pop("agent_plan", None)
    summary.pop("review_outcome", None)
    task.summary = summary
    mark_task_queued(task, rerun_stage_nums)
    await _reset_stage_state(db, task.id, rerun_stage_nums)
    await db.commit()

    await db.refresh(task)
    return _serialize_task(task)


def _build_stage_debug_payload(stage: AuditStage) -> dict | None:
    try:
        prompt_data = json.loads(stage.prompt_used) if stage.prompt_used else {}
    except Exception:
        prompt_data = {}
    try:
        response_data = json.loads(stage.llm_response) if stage.llm_response else {}
    except Exception:
        response_data = {}

    debug = prompt_data.get("debug") if isinstance(prompt_data, dict) else None
    if not debug and not (isinstance(response_data, dict) and response_data.get("error")):
        return None
    return {
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
    }


def _build_stage_findings_preview(stage: AuditStage) -> list | dict:
    findings = _coerce_stage_findings(stage.findings)
    compressed = stage.compressed_summary if isinstance(stage.compressed_summary, dict) else {}
    vulnerabilities = findings.get("vulnerabilities", [])
    vulnerability_count = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0

    preview = {
        "stage_summary": compressed.get("stage_summary") or findings.get("stage_summary") or "",
        "_vulnerability_count": vulnerability_count,
    }
    for key in ["parse_error", "raw_response", "_policy_note", "_policy_stats", "_salvaged", "skipped", "skip_reason"]:
        if key in findings:
            preview[key] = findings.get(key)

    if stage.stage_num == -1:
        for key in ["analysis_summary", "selected_agents", "skipped_agents"]:
            if key in findings:
                preview[key] = findings.get(key)

    if stage.stage_num == -2:
        for key in ["review_summary", "findings_assessment", "request_rerun", "rerun_agents", "additional_guidance", "rerun_execution", "review_closure"]:
            if key in findings:
                preview[key] = findings.get(key)

    if stage.stage_num == 1:
        arch = findings.get("architecture_info") if isinstance(findings.get("architecture_info"), dict) else {}
        if not arch and isinstance(compressed.get("architecture_info"), dict):
            arch = compressed.get("architecture_info", {})
        if isinstance(arch, dict) and arch:
            routes = arch.get("routes", []) if isinstance(arch.get("routes"), list) else []
            preview["architecture_info"] = {
                "tech_stack": arch.get("tech_stack", ""),
                "framework": arch.get("framework", ""),
                "database": arch.get("database", ""),
                "auth_mechanism": arch.get("auth_mechanism", ""),
                "routes": routes[:12],
                "_route_count": len(routes),
                "middleware_chain": arch.get("middleware_chain", []),
                "database_models": arch.get("database_models", []),
                "security_boundaries": arch.get("security_boundaries"),
                "external_integrations": arch.get("external_integrations", []),
                "_gap_analysis": arch.get("_gap_analysis"),
                "entry_points": arch.get("entry_points", []),
                "output_points": arch.get("output_points", []),
                "modules": arch.get("modules", []),
                "data_flows": arch.get("data_flows", []),
            }

    debug_payload = _build_stage_debug_payload(stage)
    if debug_payload:
        preview["_debug"] = debug_payload
    return preview


def _serialize_stage(stage: AuditStage, *, include_payloads: bool) -> dict:
    if 1 <= stage.stage_num <= 9:
        stage_name = get_stage_name(stage.stage_num)
    else:
        stage_name = stage.stage_name

    findings = _coerce_stage_findings(stage.findings) if include_payloads else _build_stage_findings_preview(stage)
    if include_payloads:
        debug_payload = _build_stage_debug_payload(stage)
        if debug_payload:
            findings.setdefault("_debug", debug_payload)

    return {
        "id": stage.id,
        "task_id": stage.task_id,
        "stage_num": stage.stage_num,
        "stage_name": stage_name,
        "agent_role": stage.agent_role,
        "status": stage.status,
        "prompt_used": stage.prompt_used if include_payloads else "",
        "findings": findings,
        "llm_response": stage.llm_response if include_payloads else "",
        "compressed_summary": stage.compressed_summary,
        "artifact_path": stage.artifact_path,
        "started_at": stage.started_at,
        "completed_at": stage.completed_at,
    }


@router.get("/{task_id}/stages", response_model=list[AuditStageOut])
async def get_audit_stages(
    task_id: int,
    include_payloads: bool = False,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id).order_by(AuditStage.stage_num)
    )
    stages = result.scalars().all()
    return [_serialize_stage(stage, include_payloads=include_payloads) for stage in stages]


@router.get("/{task_id}/stages/{stage_num}", response_model=AuditStageOut)
async def get_audit_stage_detail(task_id: int, stage_num: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AuditStage).where(AuditStage.task_id == task_id, AuditStage.stage_num == stage_num)
    )
    stage = result.scalar_one_or_none()
    if not stage:
        raise HTTPException(404, "审计阶段不存在")
    return _serialize_stage(stage, include_payloads=True)


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

    artifact_path = resolve_audit_artifact_path(stage.artifact_path)

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
    db: AsyncSession = Depends(get_db),
):
    query = select(Vulnerability).where(Vulnerability.task_id == task_id)
    if severity:
        query = query.where(Vulnerability.severity.in_(_severity_match_values(severity)))
    result = await db.execute(
        query.order_by(_severity_order_expr(Vulnerability.severity).desc(), Vulnerability.id.desc())
    )
    return result.scalars().all()


@router.delete("/{task_id}")
async def delete_audit(task_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditTask).where(AuditTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "审计任务不存在")
    if task.status in {"pending", "running"}:
        raise HTTPException(400, "运行中的审计不能删除，请先取消")

    await delete_audit_task_records(db, task)
    await db.commit()

    return {"message": "审计已删除"}
