"""认证服务（M6 最小鉴权，零依赖）。

- 密码：标准库 ``hashlib.pbkdf2_hmac``（sha256），存储格式
  ``pbkdf2_sha256$<iter>$<salt_hex>$<hash_hex>``；校验用 ``hmac.compare_digest`` 防时序攻击。
- Token：``secrets.token_urlsafe`` 生成不透明 token，存 ``User`` 表（含过期），可主动失效（清空/删行）。
- ``verify_token``：FastAPI 依赖，``HTTPBearer`` 取 Bearer → 查 User 表。
- ``ensure_admin_user``：lifespan 启动时保证管理员存在（config 密码或随机生成 + log）。
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session, get_db
from models import User
from services.config import get_settings

logger = logging.getLogger(__name__)

_PBKDF2_ITERATIONS = 200_000
_ALGO = "pbkdf2_sha256"

# fastapi.security 随 fastapi 自带，无需新增依赖。
# auto_error=False：无/错误 Authorization 头时由 verify_token 统一 raise 401
# （HTTPBearer 默认返 403，前端拦截器只判 401，故禁用自动报错）。
bearer_scheme = HTTPBearer(auto_error=False)


def _utcnow_naive() -> datetime:
    """ naive UTC，用于与 SQLite 读回的 naive datetime 安全比较。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_password(password: str, iterations: int = _PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGO}${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    try:
        algo, iter_str, salt_hex, hash_hex = stored.split("$", 3)
    except ValueError:
        return False
    if algo != _ALGO:
        return False
    try:
        iterations = int(iter_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expected)


async def issue_token(user: User, db: AsyncSession) -> str:
    """生成并写入不透明 token（flush 不 commit，由调用方统一提交）。"""
    hours = get_settings().token_expire_hours
    token = secrets.token_urlsafe(32)
    user.token = token
    user.token_expires_at = _utcnow_naive() + timedelta(hours=hours)
    db.add(user)
    await db.flush()
    return token


async def _resolve_user_by_token(token: str | None, db: AsyncSession) -> User:
    """按 token 查 User 并校验过期。无/无效/过期 token → 401。

    被 ``verify_token``（Bearer 头）与 ``verify_token_query``（query 参数,
    供 SSE EventSource，因其无法发送 Authorization 头）共用，确保两路同口径。
    """
    if not token:
        raise HTTPException(status_code=401, detail="未提供认证令牌")
    result = await db.execute(
        select(User).where(User.token == token, User.status == "active")
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="无效或过期的令牌")
    expires = user.token_expires_at
    if expires is not None:
        exp = expires.replace(tzinfo=None) if expires.tzinfo else expires
        if exp < _utcnow_naive():
            raise HTTPException(status_code=401, detail="令牌已过期")
    return user


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    return await _resolve_user_by_token(credentials.credentials if credentials else None, db)


async def verify_token_query(
    token: str = Query(default=None, description="访问令牌（用于 SSE EventSource，原生 EventSource 无法发送 Authorization 头）"),
    db: AsyncSession = Depends(get_db),
) -> User:
    """SSE 鉴权依赖：从 ``?token=`` 取 token，复用与 ``verify_token`` 完全相同的校验逻辑。

    ``default=None``：缺 token 返 401（而非 422），与 ``verify_token`` 同口径；
    任何非 200（含 401）都会让浏览器 EventSource 失败关闭、触发前端降级。
    """
    return await _resolve_user_by_token(token, db)


async def ensure_admin_user() -> None:
    """启动时确保管理员用户存在（config 密码或随机生成 + 日志提示）。"""
    settings = get_settings()
    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == settings.admin_username))
        if result.scalar_one_or_none():
            return
        password = settings.admin_password or secrets.token_urlsafe(12)
        db.add(
            User(
                username=settings.admin_username,
                password_hash=hash_password(password),
                role="admin",
                status="active",
            )
        )
        await db.commit()
        if not settings.admin_password:
            logger.warning(
                "已创建管理员用户 %r，随机密码：%s（请尽快登录后修改，或用环境变量 CODE_SCAN_ADMIN_PASSWORD 固定）",
                settings.admin_username,
                password,
            )
        else:
            logger.info("已创建管理员用户 %r", settings.admin_username)
