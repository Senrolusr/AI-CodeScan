"""Centralized runtime configuration.

M1 改造：可由环境变量（前缀 ``CODE_SCAN_``）与 ``.env`` 覆盖的运行参数，
其余静态常量（code_parser 的分块/截断阈值、规则指纹等）保持为普通模块常量。

为保持向后兼容，所有原常量名（``MAX_CONCURRENT_AGENTS`` 等）仍在本模块顶层导出，
现有 ``from services.config import ...`` 用法无需修改。
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """运行参数。环境变量前缀 ``CODE_SCAN_``，例如 ``CODE_SCAN_MAX_UPLOAD_MB``。"""

    model_config = SettingsConfigDict(
        env_prefix="CODE_SCAN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── 数据库 / 运行目录 ──
    db_url: str | None = None  # None 时回退到 backend/data/audit.db
    data_dir: str = ""          # 空 → backend/data
    uploads_dir: str = ""       # 空 → backend/uploads
    reports_dir: str = ""       # 空 → backend/reports

    # ── 网络 / 安全 ──
    # 用字符串存储（逗号分隔或 JSON 数组），避免 pydantic-settings 对 list 强制 JSON 解析；
    # 通过 cors_origins_list 属性解析成列表。
    cors_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173"
    )
    secret_key: str = "change-me-in-production"

    # ── M6：管理员引导 / token 过期 ──
    admin_username: str = "admin"
    admin_password: str = ""  # 空 → 首启随机生成并打印日志
    token_expire_hours: int = 168

    @property
    def cors_origins_list(self) -> list[str]:
        return _parse_cors_origins(self.cors_origins)

    # ── 上传 / 解压限制（防 zip bomb）──
    max_upload_mb: int = 200
    max_extracted_mb: int = 1024
    max_extracted_file_count: int = 20_000
    max_member_file_mb: int = 50
    max_compression_ratio: int = 200

    # ── 审计运行参数 ──
    max_concurrent_agents: int = 3
    worker_poll_interval_seconds: float = 2.0
    worker_task_timeout_seconds: int = 7200
    llm_timeout_seconds: float = 180.0
    # §4.8 LLM 重试策略：瞬时错误（限流 / 上游 5xx / 网络抖动 / 超时）的额外重试次数
    # 与线性退避基准秒数。永久错误（鉴权 / 模型 / 客户端 4xx）不重试。
    llm_max_retries: int = 2
    llm_retry_base_delay_seconds: float = 1.0

    # ── M5b：增量提交试点（默认关闭 = 零行为变化）──
    # 逗号分隔的阶段号（如 "8"）。开启后，这些阶段的子 Agent 可在响应中以
    # ``actions:[{type:"submit_finding",payload:{...}}]`` 提前提交 finding，
    # 在响应尾部被截断前已落盘。默认空 → 完全走 legacy ``vulnerabilities[]`` 路径。
    incremental_submit_stages: str = ""

    @property
    def incremental_submit_stage_nums(self) -> set[int]:
        return _parse_stage_nums(self.incremental_submit_stages)


@lru_cache
def get_settings() -> Settings:
    """返回进程级单例配置。测试中可 ``get_settings.cache_clear()`` 重置。"""
    return Settings()


_SECRET_REF_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def _parse_cors_origins(value: Any) -> list[str]:
    """把 CORS 配置解析成列表：支持逗号分隔字符串、JSON 数组字符串、列表。"""
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
            except Exception:
                pass
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return ["*"]


def _parse_stage_nums(value: Any) -> set[int]:
    """把增量提交阶段配置解析成 int 集合：支持逗号分隔字符串 / JSON 数组 / 列表。"""
    if isinstance(value, (list, tuple)):
        items = value
    elif isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    items = parsed
                else:
                    items = []
            except Exception:
                items = []
        else:
            items = stripped.split(",") if stripped else []
    else:
        items = []
    nums: set[int] = set()
    for item in items:
        try:
            nums.add(int(str(item).strip()))
        except (TypeError, ValueError):
            continue
    return nums


_settings = get_settings()

# ── 向后兼容：原常量名继续从 settings 导出 ──
MAX_CONCURRENT_AGENTS = _settings.max_concurrent_agents
WORKER_POLL_INTERVAL_SECONDS = _settings.worker_poll_interval_seconds
WORKER_TASK_TIMEOUT_SECONDS = _settings.worker_task_timeout_seconds
DEFAULT_LLM_TIMEOUT_SECONDS = _settings.llm_timeout_seconds
LLM_MAX_RETRIES = _settings.llm_max_retries
LLM_RETRY_BASE_DELAY_SECONDS = _settings.llm_retry_base_delay_seconds

# ── 上传 / 解压限制（供 routers/projects.py 使用）──
MAX_UPLOAD_BYTES = _settings.max_upload_mb * 1024 * 1024
MAX_EXTRACTED_BYTES = _settings.max_extracted_mb * 1024 * 1024
MAX_EXTRACTED_FILE_COUNT = _settings.max_extracted_file_count
MAX_MEMBER_FILE_BYTES = _settings.max_member_file_mb * 1024 * 1024
MAX_COMPRESSION_RATIO = _settings.max_compression_ratio

# ── code_parser 静态阈值（不进环境变量，保持稳定指纹）──
MAX_FILE_SIZE = 500 * 1024        # 500KB per source file
MAX_TREE_FILES = 10_000           # max source/config files to index in the project tree
MAX_AUDIT_SOURCE_FILES = 1_200    # max prioritized files to read into audit chunks
MAX_CODE_CHUNKS = 2_000           # max chunks cached for staged audit selection
TOTAL_CHARS_LIMIT = 2_000_000     # total character budget
CACHE_SCHEMA_VERSION = 8
OVERSIZED_HEAD_CHARS = 1400
OVERSIZED_TAIL_CHARS = 1000
OVERSIZED_MAX_WINDOWS = 6
OVERSIZED_WINDOW_RADIUS = 18


def resolve_secret(value: str | None) -> str:
    """解析密钥引用。

    支持以 ``${ENV_VAR}`` 形式引用环境变量（避免明文写入数据库）；其余值原样返回。
    当引用的变量不存在时返回空串（由调用方决定如何处理）。
    """
    if not value:
        return ""
    match = _SECRET_REF_RE.match(value.strip())
    if match:
        return os.environ.get(match.group(1), "")
    return value
