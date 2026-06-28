"""M6 鉴权：密码哈希、login/logout/me/password、token 有效性。"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from models import User
from services.auth import _utcnow_naive, hash_password, verify_password


# ── 密码哈希（纯单元，零依赖）──
def test_hash_and_verify_password_roundtrip():
    h = hash_password("s3cret-pass")
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password("s3cret-pass", h)
    assert not verify_password("wrong", h)


def test_hash_salts_differ():
    assert hash_password("same") != hash_password("same")


def test_verify_password_rejects_malformed():
    assert not verify_password("x", "")
    assert not verify_password("x", "no-dollar-sign")
    assert not verify_password("x", "other$1$ab$cd")  # 未知 algo
    assert not verify_password("x", "pbkdf2_sha256$1$zz$cd")  # 损坏的 hex


# ── login / me / logout / password 端点 ──
async def test_login_success_returns_token(db_client):
    client, _ = db_client
    client.headers.pop("Authorization", None)
    resp = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "test-pass-123"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["token"]
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"


async def test_login_wrong_password_401(db_client):
    client, _ = db_client
    client.headers.pop("Authorization", None)
    resp = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "nope"}
    )
    assert resp.status_code == 401


async def test_login_unknown_user_401(db_client):
    client, _ = db_client
    client.headers.pop("Authorization", None)
    resp = await client.post(
        "/api/auth/login", json={"username": "ghost", "password": "x"}
    )
    assert resp.status_code == 401


async def test_me_with_injected_token(db_client):
    client, _ = db_client
    # db_client fixture 已注入 admin token
    resp = await client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"


async def test_logout_invalidates_token(db_client):
    client, _ = db_client
    resp = await client.post("/api/auth/logout")
    assert resp.status_code == 200
    # logout 清空 token，再用同一 token 访问 → 401
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_change_password_flow(db_client):
    client, _ = db_client
    resp = await client.patch(
        "/api/auth/password",
        json={"old_password": "test-pass-123", "new_password": "new-pass-456"},
    )
    assert resp.status_code == 200
    client.headers.pop("Authorization", None)
    # 旧密码登录失败
    assert (
        await client.post(
            "/api/auth/login", json={"username": "admin", "password": "test-pass-123"}
        )
    ).status_code == 401
    # 新密码登录成功
    assert (
        await client.post(
            "/api/auth/login", json={"username": "admin", "password": "new-pass-456"}
        )
    ).status_code == 200


async def test_change_password_wrong_old_400(db_client):
    client, _ = db_client
    resp = await client.patch(
        "/api/auth/password",
        json={"old_password": "bad", "new_password": "new-pass-456"},
    )
    assert resp.status_code == 400


async def test_change_password_too_short_400(db_client):
    client, _ = db_client
    resp = await client.patch(
        "/api/auth/password",
        json={"old_password": "test-pass-123", "new_password": "12345"},
    )
    assert resp.status_code == 400


# ── verify_token：无效 / 过期 / 禁用 ──
async def test_verify_token_invalid_returns_401(db_client):
    client, _ = db_client
    client.headers["Authorization"] = "Bearer not-a-real-token"
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_verify_token_expired_401(db_client):
    client, Session = db_client
    async with Session() as s:
        user = (await s.execute(select(User).where(User.username == "admin"))).scalar_one()
        user.token_expires_at = _utcnow_naive() - timedelta(hours=1)
        await s.commit()
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_verify_token_disabled_user_401(db_client):
    client, Session = db_client
    async with Session() as s:
        user = (await s.execute(select(User).where(User.username == "admin"))).scalar_one()
        user.status = "disabled"
        await s.commit()
    assert (await client.get("/api/auth/me")).status_code == 401


# ── ensure_admin_user：首启创建 + 幂等不覆盖 ──
async def test_ensure_admin_user_creates_then_idempotent(monkeypatch):
    import services.auth as auth_mod
    from database import Base
    from models import User
    from services.auth import ensure_admin_user
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)
    monkeypatch.setattr(auth_mod, "async_session", Session)

    await ensure_admin_user()
    async with Session() as s:
        users = (await s.execute(select(User))).scalars().all()
        assert len(users) == 1
        assert users[0].username == "admin"
        assert users[0].role == "admin"
        assert users[0].status == "active"
        first_hash = users[0].password_hash

    # 二次调用应幂等：不新建、不覆盖密码
    await ensure_admin_user()
    async with Session() as s:
        users = (await s.execute(select(User))).scalars().all()
        assert len(users) == 1
        assert users[0].password_hash == first_hash
    await eng.dispose()
