import os
import shutil
import zipfile
import logging
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from errors import ApiError
from models import AuditTask, Project, ProjectFile, ProjectRoute, ProjectRuleHit, ProjectSourceSinkHint
from services.audit_cleanup import delete_audit_task_records
from services.code_parser import clear_project_cache, load_project_cache, parse_project, warm_project_cache
from services.project_index import sync_project_index
from schemas import ProjectFileOut, ProjectRouteOut, ProjectRuleHitOut, ProjectSourceSinkHintOut
from services.config import (
    MAX_COMPRESSION_RATIO,
    MAX_EXTRACTED_BYTES,
    MAX_EXTRACTED_FILE_COUNT,
    MAX_MEMBER_FILE_BYTES,
    MAX_UPLOAD_BYTES,
)

router = APIRouter()
logger = logging.getLogger(__name__)
BACKEND_ROOT = os.path.dirname(os.path.dirname(__file__))
UPLOADS_DIR = os.path.join(BACKEND_ROOT, "uploads")

# 解压时跳过的噪声条目（macOS 资源 fork 等）。
_NOISE_MEMBER_PREFIXES = ("__MACOSX/",)
_NOISE_MEMBER_NAMES = {".DS_Store", "Thumbs.db"}


def _build_cache_summary(project: Project) -> dict:
    cached = load_project_cache(project.id, file_tree=project.file_tree or [])
    if not cached:
        return {
            "available": False,
            "scan_stats": {},
            "rule_hit_count": 0,
            "cache_schema_version": None,
        }

    scan_stats = cached.get("scan_stats", {}) if isinstance(cached.get("scan_stats"), dict) else {}
    rule_hits = cached.get("rule_hits", []) if isinstance(cached.get("rule_hits"), list) else []
    return {
        "available": True,
        "scan_stats": scan_stats,
        "rule_hit_count": len(rule_hits),
        "cache_schema_version": cached.get("cache_schema_version"),
    }


async def _save_upload_file(upload: UploadFile, destination: str, chunk_size: int = 1024 * 1024):
    """流式落盘上传文件，并强制上传体积上限（防超大上传打满磁盘）。"""
    written = 0
    with open(destination, "wb") as f:
        while True:
            chunk = await upload.read(chunk_size)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    400,
                    f"上传文件超过最大允许体积 {MAX_UPLOAD_BYTES // (1024 * 1024)}MB",
                )
            f.write(chunk)


def _normalize_zip_member_name(name: str) -> str:
    normalized = name.replace("\\", "/").lstrip("/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise HTTPException(400, f"ZIP 包含非法路径：{name}")
    normalized = "/".join(parts)
    if not normalized:
        raise HTTPException(400, f"ZIP 包含非法路径：{name}")
    return normalized


def _is_noise_member(name: str) -> bool:
    base = name.rsplit("/", 1)[-1]
    return base in _NOISE_MEMBER_NAMES or any(name.startswith(p) for p in _NOISE_MEMBER_PREFIXES)


def _safe_extract_zip(zip_path: str, target_dir: str):
    """安全解压：防 ZIP Slip、限制文件数量 / 单文件大小 / 总解压大小 / 压缩比（防 zip bomb）。"""
    target_root = os.path.abspath(target_dir)
    zip_size = os.path.getsize(zip_path)
    total_extracted = 0
    file_count = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        # 文件数量上限（先按声明计数，过滤噪声）。
        kept_members = [m for m in members if not _is_noise_member(_normalize_zip_member_name_safe(m.filename))]
        if len(kept_members) > MAX_EXTRACTED_FILE_COUNT:
            raise HTTPException(
                400,
                f"ZIP 文件数量 {len(kept_members)} 超过上限 {MAX_EXTRACTED_FILE_COUNT}",
            )

        for member in members:
            normalized_name = _normalize_zip_member_name(member.filename)
            if _is_noise_member(normalized_name):
                continue

            member_path = os.path.abspath(os.path.join(target_dir, normalized_name))
            if not member_path.startswith(target_root + os.sep) and member_path != target_root:
                raise HTTPException(400, f"ZIP 包含非法路径：{member.filename}")

            if member.is_dir():
                os.makedirs(member_path, exist_ok=True)
                continue

            # 用 zip 头里声明的大小提前做容量/压缩比校验，避免真正写出 zip bomb。
            declared_size = getattr(member, "file_size", 0) or 0
            compress_size = getattr(member, "compress_size", 0) or 0
            if declared_size > MAX_MEMBER_FILE_BYTES:
                raise HTTPException(
                    400,
                    f"ZIP 单文件过大（{normalized_name}：{declared_size} 字节）",
                )
            if compress_size > 0 and declared_size / compress_size > MAX_COMPRESSION_RATIO:
                raise HTTPException(
                    400,
                    f"ZIP 压缩比异常（{normalized_name}：{declared_size}/{compress_size}），疑似 zip bomb",
                )
            if total_extracted + declared_size > MAX_EXTRACTED_BYTES:
                raise HTTPException(
                    400,
                    f"ZIP 解压后总大小超过上限 {MAX_EXTRACTED_BYTES // (1024 * 1024)}MB",
                )

            file_count += 1
            os.makedirs(os.path.dirname(member_path), exist_ok=True)
            written = 0
            with zf.open(member, "r") as src, open(member_path, "wb") as dst:
                while True:
                    buf = src.read(1024 * 1024)
                    if not buf:
                        break
                    written += len(buf)
                    # 写出阶段再次校验真实大小（防止头部撒谎的恶意包）。
                    if written > MAX_MEMBER_FILE_BYTES:
                        raise HTTPException(400, f"ZIP 单文件实际大小超限：{normalized_name}")
                    dst.write(buf)
            total_extracted += written
            if total_extracted > MAX_EXTRACTED_BYTES:
                raise HTTPException(
                    400,
                    f"ZIP 解压后总大小超过上限 {MAX_EXTRACTED_BYTES // (1024 * 1024)}MB",
                )


def _normalize_zip_member_name_safe(name: str) -> str:
    """仅用于统计过滤的路径归一化；遇到非法路径不抛异常（统一交给解压阶段校验）。"""
    try:
        return _normalize_zip_member_name(name)
    except HTTPException:
        return name


@router.post("/upload")
async def upload_project(
    file: UploadFile = File(...),
    name: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(400, "未选择上传文件")
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "仅支持 ZIP 文件")

    project = Project(
        name=name,
        upload_path="",
        file_tree=[],
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    project_dir = os.path.join(UPLOADS_DIR, str(project.id))
    zip_path = os.path.join(project_dir, "source.zip")
    try:
        os.makedirs(project_dir, exist_ok=True)
        await _save_upload_file(file, zip_path)
        if os.path.getsize(zip_path) == 0:
            raise HTTPException(400, "上传的 ZIP 文件为空")
        _safe_extract_zip(zip_path, project_dir)
        os.remove(zip_path)

        file_tree, tech_stack = parse_project(project_dir)
        if not file_tree:
            raise HTTPException(400, "ZIP 上传成功，但未找到可解析的源码文件")

        project.upload_path = project_dir
        project.file_tree = file_tree
        project.tech_stack = tech_stack
        await db.commit()
        await db.refresh(project)
        cache_payload = warm_project_cache(project.id, project_dir, file_tree)
        # M4b：把静态路由 / 规则命中影子写入结构化表（与项目落库同事务）。
        await sync_project_index(db, project.id, cache_payload)
        await db.commit()
        return {"id": project.id, "name": project.name, "tech_stack": tech_stack}
    except zipfile.BadZipFile:
        shutil.rmtree(project_dir, ignore_errors=True)
        await db.delete(project)
        await db.commit()
        raise HTTPException(400, "无效的 ZIP 文件")
    except HTTPException:
        shutil.rmtree(project_dir, ignore_errors=True)
        await db.delete(project)
        await db.commit()
        raise
    except Exception as e:
        logger.exception("Project upload failed for name=%s filename=%s", name, file.filename)
        shutil.rmtree(project_dir, ignore_errors=True)
        await db.delete(project)
        await db.commit()
        raise HTTPException(500, f"上传失败：{str(e)}")
    finally:
        await file.close()


@router.get("")
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    projects = result.scalars().all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "tech_stack": p.tech_stack,
            "file_count": sum(1 for _ in _iter_files(p.file_tree)),
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in projects
    ]


@router.get("/{project_id}")
async def get_project(project_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)
    cache_summary = _build_cache_summary(project)
    return {
        "id": project.id,
        "name": project.name,
        "upload_path": project.upload_path,
        "file_tree": project.file_tree,
        "tech_stack": project.tech_stack,
        "cache_summary": cache_summary,
        "created_at": project.created_at.isoformat() if project.created_at else None,
    }


@router.post("/{project_id}/rebuild-cache")
async def rebuild_project_cache(project_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)
    if not project.upload_path or not os.path.isdir(project.upload_path):
        raise HTTPException(400, "项目源码目录不存在")

    file_tree, tech_stack = parse_project(project.upload_path)
    if not file_tree:
        raise HTTPException(400, "未找到可解析的源代码文件")

    project.file_tree = file_tree
    project.tech_stack = tech_stack
    await db.commit()
    await db.refresh(project)

    clear_project_cache(project.id)
    cache_payload = warm_project_cache(project.id, project.upload_path, file_tree)
    # M4b：把重建后的静态路由 / 规则命中影子写入结构化表。
    await sync_project_index(db, project.id, cache_payload)
    await db.commit()

    return {
        "id": project.id,
        "name": project.name,
        "tech_stack": project.tech_stack,
        "cache_summary": _build_cache_summary(project),
        "scan_stats": cache_payload.get("scan_stats", {}),
        "rule_hit_count": len(cache_payload.get("rule_hits", []) or []),
        "message": "项目缓存已重建",
    }


async def _project_exists(db: AsyncSession, project_id: int) -> bool:
    result = await db.execute(select(Project.id).where(Project.id == project_id))
    return result.scalar_one_or_none() is not None


@router.get("/{project_id}/routes")
async def list_project_routes(project_id: int, db: AsyncSession = Depends(get_db)):
    if not await _project_exists(db, project_id):
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)
    result = await db.execute(
        select(ProjectRoute)
        .where(ProjectRoute.project_id == project_id)
        .order_by(ProjectRoute.path)
    )
    return [ProjectRouteOut.model_validate(r).model_dump() for r in result.scalars().all()]


@router.get("/{project_id}/rule-hits")
async def list_project_rule_hits(project_id: int, db: AsyncSession = Depends(get_db)):
    if not await _project_exists(db, project_id):
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)
    result = await db.execute(
        select(ProjectRuleHit)
        .where(ProjectRuleHit.project_id == project_id)
        .order_by(ProjectRuleHit.weighted_score.desc())
    )
    return [ProjectRuleHitOut.model_validate(r).model_dump() for r in result.scalars().all()]


@router.get("/{project_id}/source-sink-hints")
async def list_project_source_sink_hints(project_id: int, db: AsyncSession = Depends(get_db)):
    """M4b 三联之 source-sink 线索（§12.2 行1087：与 routes/rule-hits 并列）。

    按 risk_score 降序，供前端项目页独立消费。
    """
    if not await _project_exists(db, project_id):
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)
    result = await db.execute(
        select(ProjectSourceSinkHint)
        .where(ProjectSourceSinkHint.project_id == project_id)
        .order_by(ProjectSourceSinkHint.risk_score.desc())
    )
    return [ProjectSourceSinkHintOut.model_validate(r).model_dump() for r in result.scalars().all()]


@router.get("/{project_id}/files")
async def list_project_files(project_id: int, db: AsyncSession = Depends(get_db)):
    """§9.3 项目源文件结构化索引（与 routes/rule-hits/source-sink-hints 并列）。

    每源文件一行：path/size/extension/role/risk_score/content_hash。
    按 risk_score 降序、path 升序，供前端项目页独立消费（高风险文件前置）。
    """
    if not await _project_exists(db, project_id):
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)
    result = await db.execute(
        select(ProjectFile)
        .where(ProjectFile.project_id == project_id)
        .order_by(ProjectFile.risk_score.desc(), ProjectFile.path.asc())
    )
    return [ProjectFileOut.model_validate(r).model_dump() for r in result.scalars().all()]


@router.get("/{project_id}/file")
async def get_project_file(
    project_id: int,
    path: str = "",
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import PlainTextResponse

    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)

    project_root = os.path.abspath(project.upload_path)
    full_path = os.path.abspath(os.path.join(project_root, path))
    if not full_path.startswith(project_root + os.sep) and full_path != project_root:
        raise HTTPException(403, "无权访问该文件")

    if not os.path.isfile(full_path):
        raise HTTPException(404, "文件不存在")

    # Skip binary files
    ext = os.path.splitext(full_path)[1].lower()
    binary_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
        ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".gz", ".tar", ".exe",
        ".dll", ".so", ".pyc", ".class", ".jar", ".pdf",
    }
    if ext in binary_exts:
        raise HTTPException(400, "二进制文件无法按文本显示")

    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return PlainTextResponse(content)
    except Exception as e:
        raise HTTPException(500, f"读取文件失败：{e}")


@router.delete("/{project_id}")
async def delete_project(project_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise ApiError("PROJECT_NOT_FOUND", "项目不存在", status_code=404)

    result = await db.execute(select(AuditTask).where(AuditTask.project_id == project_id))
    audit_tasks = result.scalars().all()
    running_task_ids = [task.id for task in audit_tasks if task.status in {"pending", "running"}]
    if running_task_ids:
        raise HTTPException(400, f"项目存在运行中的审计任务，无法删除：{running_task_ids}")

    for task in audit_tasks:
        await delete_audit_task_records(db, task)

    if project.upload_path and os.path.exists(project.upload_path):
        shutil.rmtree(project.upload_path, ignore_errors=True)
    clear_project_cache(project.id)

    await db.delete(project)
    await db.commit()
    return {"message": "项目已删除"}


def _iter_files(tree):
    if isinstance(tree, list):
        for node in tree:
            if node.get("type") == "file":
                yield node
            elif node.get("type") == "directory" and "children" in node:
                yield from _iter_files(node["children"])
