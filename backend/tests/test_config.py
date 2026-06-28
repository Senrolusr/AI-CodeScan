import os

import pytest

from services.config import Settings, get_settings, resolve_secret


def test_default_settings_sanity():
    s = Settings()
    # M6：Bearer 鉴权不允许通配源，默认收紧到本地 dev 源（env 可覆盖）
    assert "*" not in s.cors_origins_list
    assert any("localhost" in o for o in s.cors_origins_list)
    assert s.admin_username == "admin"
    assert s.token_expire_hours >= 1
    assert s.max_concurrent_agents >= 1
    assert s.max_upload_mb > 0
    assert s.max_extracted_file_count > 0


def test_env_override(monkeypatch):
    monkeypatch.setenv("CODE_SCAN_MAX_UPLOAD_MB", "5")
    monkeypatch.setenv("CODE_SCAN_MAX_CONCURRENT_AGENTS", "7")
    s = Settings()
    assert s.max_upload_mb == 5
    assert s.max_concurrent_agents == 7


def test_cors_origins_from_comma_separated_env(monkeypatch):
    monkeypatch.setenv("CODE_SCAN_CORS_ORIGINS", "https://a.example, https://b.example")
    s = Settings()
    assert s.cors_origins_list == ["https://a.example", "https://b.example"]


def test_cors_origins_from_json_env(monkeypatch):
    monkeypatch.setenv("CODE_SCAN_CORS_ORIGINS", '["https://x.example"]')
    s = Settings()
    assert s.cors_origins_list == ["https://x.example"]


def test_resolve_secret_env_reference(monkeypatch):
    monkeypatch.setenv("MY_TEST_KEY", "secret-value-123")
    assert resolve_secret("${MY_TEST_KEY}") == "secret-value-123"


def test_resolve_secret_missing_env_returns_empty(monkeypatch):
    monkeypatch.delenv("MISSING_KEY_VAR", raising=False)
    assert resolve_secret("${MISSING_KEY_VAR}") == ""


def test_resolve_secret_plaintext_passthrough():
    assert resolve_secret("sk-plain-key") == "sk-plain-key"
    assert resolve_secret("") == ""
    assert resolve_secret(None) == ""


def test_get_settings_is_cached():
    a = get_settings()
    b = get_settings()
    assert a is b
