"""Project filesystem walking, file-tree building, project fingerprint, file-role inference."""

from __future__ import annotations

import hashlib
import os
from services.config import (
    MAX_TREE_FILES
)

from services.code_parser_pkg._constants import *  # noqa: F401,F403

import logging

logger = logging.getLogger(__name__)

def _infer_file_role(file_path: str, content_head: str) -> str | None:
    """Infer a file's architectural role from path and content."""
    fp_lower = file_path.lower()
    dir_parts = fp_lower.replace("\\", "/").split("/")

    if any(p in dir_parts for p in ["middleware", "middlewares", "interceptor", "guard", "guards"]):
        return "middleware"
    if any(p in dir_parts for p in ["controller", "controllers", "handler", "handlers", "endpoints"]):
        return "controller"
    if any(p in dir_parts for p in ["service", "services", "usecase"]):
        return "service"
    if any(p in dir_parts for p in ["model", "models", "entity", "entities", "domain"]):
        return "model"
    if any(p in dir_parts for p in ["route", "routes", "router", "routers", "urls"]):
        return "route"
    if any(p in dir_parts for p in ["config", "configuration", "settings", "conf"]):
        return "config"
    if any(p in dir_parts for p in ["auth", "security", "permission"]):
        return "auth"
    if any(p in dir_parts for p in ["dao", "repository", "mapper", "persistence"]):
        return "dao"

    if "class.*middleware" in content_head or "def middleware" in content_head:
        return "middleware"
    if "@controller" in content_head or "@restcontroller" in content_head:
        return "controller"
    if "@service" in content_head:
        return "service"
    if "router.get(" in content_head or "router.post(" in content_head or "include_router" in content_head:
        return "route"
    if "jwt" in content_head and ("sign" in content_head or "verify" in content_head):
        return "auth"

    return None

def _build_project_fingerprint(file_tree: list) -> str:
    normalized_entries: list[str] = []
    for file_node in _flatten_files(file_tree or []):
        normalized_entries.append(
            "|".join(
                [
                    str(file_node.get("path", "") or ""),
                    str(file_node.get("extension", "") or ""),
                    str(file_node.get("size", 0) or 0),
                ]
            )
        )
    normalized_entries.sort()
    joined = "\n".join(normalized_entries)
    return hashlib.sha256(joined.encode("utf-8", errors="ignore")).hexdigest()

def _build_tree(base_path: str, current_path: str, depth: int = 0, state: dict | None = None) -> list:
    """Build a nested file tree structure."""
    state = state or {"file_count": 0}
    if depth > 10:
        return []

    items = []
    try:
        entries = sorted(os.listdir(current_path))
    except PermissionError:
        return []

    for entry in entries:
        if state["file_count"] >= MAX_TREE_FILES:
            state["truncated_by_tree_files"] = True
            break

        full_path = os.path.join(current_path, entry)
        rel_path = os.path.relpath(full_path, base_path).replace("\\", "/")

        if os.path.isdir(full_path):
            if entry in SKIP_DIRS or entry.startswith("."):
                continue
            children = _build_tree(base_path, full_path, depth + 1, state=state)
            if children:
                items.append({
                    "name": entry,
                    "type": "directory",
                    "path": rel_path,
                    "children": children,
                })
        else:
            if state["file_count"] >= MAX_TREE_FILES:
                state["truncated_by_tree_files"] = True
                break
            ext = os.path.splitext(entry)[1].lower()
            if ext not in CODE_EXTENSIONS:
                continue
            try:
                size = os.path.getsize(full_path)
            except OSError:
                size = 0
            state["file_count"] += 1
            items.append({
                "name": entry,
                "type": "file",
                "path": rel_path,
                "extension": ext,
                "size": size,
            })

    return items

def _read_project_file(project_dir: str, filename: str) -> str:
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        if filename in files:
            file_path = os.path.join(root, filename)
            try:
                return _read_source_text(file_path)[:200_000]
            except OSError:
                return ""
    return ""

def _read_source_text(full_path: str) -> str:
    """优先按 UTF-8 读取源码，失败后回退常见中文编码，尽量减少规则证据乱码。"""
    for encoding in ["utf-8", "utf-8-sig", "gb18030", "gbk", "big5", "latin-1"]:
        try:
            with open(full_path, "r", encoding=encoding) as fh:
                return fh.read()
        except UnicodeDecodeError:
            continue
    with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()

def _flatten_files(tree: list) -> list:
    """Flatten the tree into a list of file nodes."""
    files = []
    for node in tree:
        if node["type"] == "file":
            files.append(node)
        elif node["type"] == "directory" and "children" in node:
            files.extend(_flatten_files(node["children"]))
    return files


def _build_project_files(project_dir: str, file_tree: list, rule_hits: list | None = None) -> list[dict]:
    """§9.3 project_files：每源文件一行结构化索引（path/size/extension/role/risk_score/content_hash）。

    - role：``_infer_file_role``（目录名 + 内容头注解，如 controller/service/model/config）。
    - risk_score：按 file_path 聚合 rule_hits 的 risk_score（该文件全部规则命中之和）。
    - content_hash：读内容 sha256[:16]（供变更检测/去重）。

    纯解析（读 fs），不引 models/database——DB 写入集中在 ``project_index``（见该模块分层说明）。
    读内容失败（权限等）→ role/content_hash 留空，不中断整批。
    """
    risk_by_path: dict[str, int] = {}
    for hit in rule_hits or []:
        if not isinstance(hit, dict):
            continue
        file_path = str(hit.get("file_path") or hit.get("chunk_path") or "").strip()
        if not file_path:
            continue
        try:
            score = int(hit.get("risk_score") or 0)
        except (TypeError, ValueError):
            score = 0
        risk_by_path[file_path] = risk_by_path.get(file_path, 0) + score

    rows: list[dict] = []
    for node in _flatten_files(file_tree or []):
        rel_path = str(node.get("path") or "")
        role = ""
        content_hash = ""
        try:
            text = _read_source_text(os.path.join(project_dir, rel_path))
            if text:
                role = _infer_file_role(rel_path, text[:2000]) or ""
                content_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]
        except OSError:
            pass
        rows.append({
            "path": rel_path,
            "size": int(node.get("size") or 0),
            "extension": str(node.get("extension") or ""),
            "role": role,
            "risk_score": int(risk_by_path.get(rel_path, 0)),
            "content_hash": content_hash,
        })
    return rows


__all__ = [
    '_infer_file_role',
    '_build_project_fingerprint',
    '_build_tree',
    '_read_project_file',
    '_read_source_text',
    '_flatten_files',
    '_build_project_files',
]
