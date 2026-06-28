"""llm_configs CRUD：api_key 加密落库 + 不回显明文 + 启动迁移。"""

from __future__ import annotations

from sqlalchemy import select

from models import LlmConfig
from services.secret_crypto import decrypt_api_key, migrate_encrypt_api_keys

VALID_PAYLOAD = {
    "name": "test-cfg",
    "provider": "openai",
    "api_key": "sk-test-123",
    "base_url": "https://api.openai.com/v1",
    "api_mode": "chat_completions",
    "model_name": "gpt-4",
}


async def test_create_encrypts_api_key_in_db(db_client):
    client, Session = db_client
    resp = await client.post("/api/llm-configs", json=VALID_PAYLOAD)
    assert resp.status_code == 200
    cfg_id = resp.json()["id"]
    async with Session() as s:
        cfg = (await s.execute(select(LlmConfig).where(LlmConfig.id == cfg_id))).scalar_one()
        assert cfg.api_key.startswith("enc:")
        assert "sk-test-123" not in cfg.api_key
        assert decrypt_api_key(cfg.api_key) == "sk-test-123"


async def test_list_does_not_leak_plaintext(db_client):
    client, _ = db_client
    await client.post("/api/llm-configs", json=VALID_PAYLOAD)
    resp = await client.get("/api/llm-configs")
    assert resp.status_code == 200
    assert "sk-test-123" not in resp.text
    assert resp.json()[0]["has_api_key"] is True


async def test_update_replaces_with_encrypted(db_client):
    client, Session = db_client
    cfg_id = (await client.post("/api/llm-configs", json=VALID_PAYLOAD)).json()["id"]
    resp = await client.put(f"/api/llm-configs/{cfg_id}", json={"api_key": "sk-new-456"})
    assert resp.status_code == 200
    async with Session() as s:
        cfg = (await s.execute(select(LlmConfig).where(LlmConfig.id == cfg_id))).scalar_one()
        assert cfg.api_key.startswith("enc:")
        assert decrypt_api_key(cfg.api_key) == "sk-new-456"


async def test_update_blank_api_key_keeps_existing(db_client):
    client, Session = db_client
    cfg_id = (await client.post("/api/llm-configs", json=VALID_PAYLOAD)).json()["id"]
    async with Session() as s:
        before = (await s.execute(select(LlmConfig).where(LlmConfig.id == cfg_id))).scalar_one().api_key
    await client.put(f"/api/llm-configs/{cfg_id}", json={"api_key": ""})
    async with Session() as s:
        after = (await s.execute(select(LlmConfig).where(LlmConfig.id == cfg_id))).scalar_one().api_key
    assert before == after  # 空串不覆盖


async def test_migrate_encrypts_legacy_plaintext(db_client, monkeypatch):
    """迁移：旧明文 → enc:；${ENV} 引用保持不变。"""
    client, Session = db_client
    import database

    monkeypatch.setattr(database, "async_session", Session)  # 让 migrate 操作测试内存库

    async with Session() as s:
        s.add(LlmConfig(
            name="legacy", provider="openai", api_key="sk-legacy-plain",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        ))
        s.add(LlmConfig(
            name="ref", provider="openai", api_key="${ENV_REF}",
            base_url="http://x", api_mode="chat_completions", model_name="m",
        ))
        await s.commit()

    await migrate_encrypt_api_keys()

    async with Session() as s:
        rows = {c.name: c.api_key for c in (await s.execute(select(LlmConfig))).scalars().all()}
    assert rows["legacy"].startswith("enc:")  # 明文已加密
    assert decrypt_api_key(rows["legacy"]) == "sk-legacy-plain"
    assert rows["ref"] == "${ENV_REF}"  # 引用不加密

    # 二次迁移幂等（不再改动）
    await migrate_encrypt_api_keys()
    async with Session() as s:
        rows2 = {c.name: c.api_key for c in (await s.execute(select(LlmConfig))).scalars().all()}
    assert rows2["legacy"] == rows["legacy"]
