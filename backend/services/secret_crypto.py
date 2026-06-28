"""API Key 对称加密存储（cryptography Fernet）。

入库前用 Fernet（AES-128-CBC + HMAC）加密，密文带 ``enc:`` 前缀落库；
读出时按前缀解密。兼容三种历史/引用形态：

- ``enc:<token>``：加密密文，解密后得明文 key；
- ``${ENV_VAR}``：环境变量引用（M0 机制），原样保留、不加密、交 ``resolve_secret``；
- 旧明文：无前缀，原样返回（启动迁移会逐步加密成 ``enc:``）。

主密钥派生自 ``settings.secret_key``；``secret_key`` 变更后旧密文不可解（MVP 接受，
故 secret_key 部署后应固定，不要随意更换）。
"""

from __future__ import annotations

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from services.config import get_settings, resolve_secret

logger = logging.getLogger(__name__)

_PREFIX = "enc:"
# config.py 的默认 secret_key（公开已知）。部署不改则 Fernet 主密钥可被任何人推算，
# 加密形同未加密——启动时据此告警。
_INSECURE_DEFAULT_SECRET_KEY = "change-me-in-production"
_fernet: Fernet | None = None


def _is_env_ref(value: str) -> bool:
    return value.startswith("${") and value.endswith("}")


def _get_fernet() -> Fernet:
    """从 settings.secret_key 派生 Fernet key（进程级缓存）。"""
    global _fernet
    if _fernet is None:
        secret = get_settings().secret_key.encode("utf-8")
        key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
        _fernet = Fernet(key)
    return _fernet


def encrypt_api_key(value: str) -> str:
    """加密明文 key 为 ``enc:<token>``。

    - 空 → 空；
    - ``${ENV}`` 引用 → 原样（不落库加密，保留引用语义）；
    - 已 ``enc:`` → 幂等原样；
    - 其余 → 加密。
    """
    if not value:
        return ""
    if _is_env_ref(value) or value.startswith(_PREFIX):
        return value
    token = _get_fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt_api_key(stored: str) -> str:
    """解密 ``enc:`` 密文；其余（旧明文 / ``${ENV}`` 引用）原样返回。"""
    if not stored:
        return ""
    if stored.startswith(_PREFIX):
        try:
            return (
                _get_fernet()
                .decrypt(stored[len(_PREFIX):].encode("ascii"))
                .decode("utf-8")
            )
        except InvalidToken:
            logger.warning("API Key 密文解密失败（secret_key 已变更？），返回空串")
            return ""
    return stored


def resolve_stored_api_key(stored: str) -> str:
    """统一解析入口：先解密 ``enc:``，再过 ``resolve_secret``（处理 ``${ENV}`` 引用）。"""
    return resolve_secret(decrypt_api_key(stored))


def _warn_if_insecure_secret_key() -> None:
    """``secret_key`` 为默认值或空时告警：Fernet 主密钥公开已知，加密形同未加密。

    与 ``ensure_admin_user`` 对默认管理员密码的告警同理——部署侧必须设置高熵
    ``CODE_SCAN_SECRET_KEY``（且部署后固定；变更后旧 ``enc:`` 密文不可解）。
    不 hard-fail，避免破坏未配置环境的数据迁移；仅 loud warning 由运维决定。
    """
    secret = get_settings().secret_key
    if not secret or secret == _INSECURE_DEFAULT_SECRET_KEY:
        logger.warning(
            "secret_key 仍为默认值或为空——API Key 的 Fernet 加密使用公开已知密钥，"
            "形同未加密。生产环境请用环境变量 CODE_SCAN_SECRET_KEY 设置高熵随机值"
            "（部署后须固定；变更后旧 enc: 密文不可解）。"
        )


async def migrate_encrypt_api_keys() -> None:
    """启动迁移：把无 ``enc:`` 前缀的明文 api_key 加密回写（幂等）。

    ``${ENV}`` 引用不加密（保留引用语义）。仅在存在明文残留时 commit。
    """
    _warn_if_insecure_secret_key()
    from sqlalchemy import select

    from database import async_session
    from models import LlmConfig

    async with async_session() as db:
        result = await db.execute(select(LlmConfig))
        changed = 0
        for cfg in result.scalars().all():
            key = cfg.api_key or ""
            if key and not key.startswith(_PREFIX) and not _is_env_ref(key):
                cfg.api_key = encrypt_api_key(key)
                changed += 1
        if changed:
            await db.commit()
            logger.info("已加密 %d 条明文 API Key", changed)
