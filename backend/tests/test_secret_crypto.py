"""API Key 加密存储：Fernet 加解密、enc: 前缀、兼容性、密文失效。"""

from __future__ import annotations

import base64
import hashlib
import logging

from cryptography.fernet import Fernet

from services import secret_crypto
from services.config import get_settings
from services.secret_crypto import decrypt_api_key, encrypt_api_key, resolve_stored_api_key


def test_encrypt_decrypt_roundtrip():
    enc = encrypt_api_key("sk-test-123")
    assert enc.startswith("enc:")
    assert "sk-test-123" not in enc
    assert decrypt_api_key(enc) == "sk-test-123"


def test_encrypt_empty():
    assert encrypt_api_key("") == ""
    assert decrypt_api_key("") == ""


def test_encrypt_idempotent():
    enc = encrypt_api_key("sk-test")
    assert encrypt_api_key(enc) == enc  # 已 enc: 幂等原样


def test_env_ref_not_encrypted():
    ref = "${OPENAI_API_KEY}"
    assert encrypt_api_key(ref) == ref  # 引用不加密
    assert decrypt_api_key(ref) == ref  # 引用原样返回


def test_decrypt_legacy_plaintext_passthrough():
    assert decrypt_api_key("sk-legacy-plaintext") == "sk-legacy-plaintext"


def test_resolve_stored_api_key_enc():
    enc = encrypt_api_key("sk-real")
    assert resolve_stored_api_key(enc) == "sk-real"


def test_resolve_stored_api_key_env_ref(monkeypatch):
    monkeypatch.setenv("MY_LLM_KEY", "sk-from-env")
    assert resolve_stored_api_key("${MY_LLM_KEY}") == "sk-from-env"


def test_resolve_stored_api_key_legacy_plaintext():
    assert resolve_stored_api_key("sk-legacy") == "sk-legacy"


def test_decrypt_invalid_token_returns_empty():
    """secret_key 变更后旧密文不可解 → 空串（不抛异常）。"""
    def fernet_for(secret):
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
        return Fernet(key)

    enc = "enc:" + fernet_for("key-one").encrypt(b"sk-x").decode()
    secret_crypto._fernet = fernet_for("key-two-different")
    try:
        assert decrypt_api_key(enc) == ""
    finally:
        secret_crypto._fernet = None  # 还原，后续测试重新用默认 secret_key 初始化


def test_warn_insecure_default_secret_key(caplog, monkeypatch):
    """默认/空 secret_key 时，启动告警必须触发（加密形同未加密）。"""
    monkeypatch.delenv("CODE_SCAN_SECRET_KEY", raising=False)
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="services.secret_crypto"):
            secret_crypto._warn_if_insecure_secret_key()
        assert any(
            "默认值" in rec.message or "为空" in rec.message for rec in caplog.records
        )
    finally:
        get_settings.cache_clear()
        secret_crypto._fernet = None  # 还原，避免污染后续加解密测试


def test_warn_silent_when_secret_key_set(caplog, monkeypatch):
    """设置了高熵 secret_key 时，启动告警必须静默。"""
    monkeypatch.setenv("CODE_SCAN_SECRET_KEY", "a-strong-deployment-secret-xyz")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="services.secret_crypto"):
            secret_crypto._warn_if_insecure_secret_key()
        assert not caplog.records
    finally:
        get_settings.cache_clear()
        secret_crypto._fernet = None
