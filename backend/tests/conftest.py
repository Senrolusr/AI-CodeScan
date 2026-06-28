"""共享 pytest fixtures。

- ``engine`` / ``session``：内存 SQLite + aiosqlite，函数级隔离，建全部表。
- ``app`` / ``client``：FastAPI 应用（worker 关闭），用 httpx ASGITransport 做集成测试。
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import database  # noqa: F401  ensure module import side-effects
from database import Base
import models  # noqa: F401  register all models on Base


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session(engine):
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as s:
        yield s


@pytest_asyncio.fixture
async def app():
    """构造 FastAPI app，但把后台 worker 替换为 no-op，避免拾取测试任务。"""
    import main as main_module

    # 用一个立即返回的假 worker，避免启动真实轮询。
    original_lifespan = main_module.app.router.lifespan_context

    async def _noop_worker(stop_event):
        return

    main_module.audit_worker_loop = _noop_worker  # type: ignore[attr-defined]
    # 重新绑定 lifespan 中引用的名字（lifespan 内 from services.audit_worker import 是模块级）
    import services.audit_worker as aw

    aw.audit_worker_loop = _noop_worker  # type: ignore[attr-defined]
    yield main_module.app


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def db_client(app):
    """覆盖 get_db 指向内存库的 client，并返回 (client, SessionFactory) 便于预置数据。

    ASGITransport 不触发 lifespan，因此不会触碰真实 audit.db。
    """
    from database import get_db
    from models import User
    from services.auth import hash_password, issue_token
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    async def _override():
        async with Session() as s:
            yield s

    app.dependency_overrides[get_db] = _override

    # M6：seed 管理员并签发 token，默认注入 Authorization header，既有测试零改动。
    async with Session() as s:
        admin = User(
            username="admin",
            password_hash=hash_password("test-pass-123"),
            role="admin",
            status="active",
        )
        token = await issue_token(admin, s)
        await s.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.headers["Authorization"] = f"Bearer {token}"
        yield ac, Session
    app.dependency_overrides.clear()
    await eng.dispose()
