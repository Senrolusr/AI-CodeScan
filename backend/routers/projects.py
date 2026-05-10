import os
import shutil
import zipfile
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select
from database import get_db
from models import AuditStage, AuditTask, Project, Vulnerability
from services.code_parser import clear_project_cache, load_project_cache, parse_project, warm_project_cache

router = APIRouter()


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
    with open(destination, "wb") as f:
        while True:
            chunk = await upload.read(chunk_size)
            if not chunk:
                break
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


def _safe_extract_zip(zip_path: str, target_dir: str):
    target_root = os.path.abspath(target_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            normalized_name = _normalize_zip_member_name(member.filename)
            member_path = os.path.abspath(os.path.join(target_dir, normalized_name))
            if not member_path.startswith(target_root + os.sep) and member_path != target_root:
                raise HTTPException(400, f"ZIP 包含非法路径：{member.filename}")
            if member.is_dir():
                os.makedirs(member_path, exist_ok=True)
                continue

            os.makedirs(os.path.dirname(member_path), exist_ok=True)
            with zf.open(member, "r") as src, open(member_path, "wb") as dst:
                shutil.copyfileobj(src, dst)


@router.post("/upload")
async def upload_project(
    file: UploadFile = File(...),
    name: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(400, "未选择上传文件")
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "仅���持 ZIP 文件")

    project = Project(
        name=name,
        upload_path="",
        file_tree=[],
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    project_dir = os.path.join("uploads", str(project.id))
    os.makedirs(project_dir, exist_ok=True)

    zip_path = os.path.join(project_dir, "source.zip")
    try:
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
        warm_project_cache(project.id, project_dir, file_tree)
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
        raise HTTPException(404, "项目不存在")
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
        raise HTTPException(404, "项目不存在")
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

    return {
        "id": project.id,
        "name": project.name,
        "tech_stack": project.tech_stack,
        "cache_summary": _build_cache_summary(project),
        "scan_stats": cache_payload.get("scan_stats", {}),
        "rule_hit_count": len(cache_payload.get("rule_hits", []) or []),
        "message": "项目缓存已重建",
    }


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
        raise HTTPException(404, "项目不存在")

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
        raise HTTPException(404, "项目不存在")

    result = await db.execute(select(AuditTask).where(AuditTask.project_id == project_id))
    audit_tasks = result.scalars().all()
    running_task_ids = [task.id for task in audit_tasks if task.status in {"pending", "running"}]
    if running_task_ids:
        raise HTTPException(400, f"项目存在运行中的审计任务，无法删除：{running_task_ids}")

    for task in audit_tasks:
        await db.execute(delete(Vulnerability).where(Vulnerability.task_id == task.id))
        await db.execute(delete(AuditStage).where(AuditStage.task_id == task.id))
        report_dir = os.path.join("reports", str(task.id))
        if os.path.isdir(report_dir):
            shutil.rmtree(report_dir, ignore_errors=True)
        artifact_dir = os.path.join("data", "stage_artifacts", str(task.id))
        if os.path.isdir(artifact_dir):
            shutil.rmtree(artifact_dir, ignore_errors=True)
        await db.delete(task)

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
