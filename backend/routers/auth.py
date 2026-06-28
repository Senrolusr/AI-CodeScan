"""认证路由（M6 最小鉴权）：login / logout / me / password。

login 不要求已登录；logout / me / password 各自单独标 ``verify_token`` 依赖。
本 router 在 main.py 挂载时**不**带全局 dependencies（区别于业务 router）。
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from errors import ApiError
from models import User
from services.auth import (
    hash_password,
    issue_token,
    verify_password,
    verify_token,
)

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


def _user_brief(user: User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/login")
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()
    if (
        not user
        or user.status != "active"
        or not verify_password(payload.password, user.password_hash)
    ):
        raise ApiError("INVALID_CREDENTIALS", "用户名或密码错误", status_code=401)
    token = await issue_token(user, db)
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    return {"token": token, "user": _user_brief(user)}


@router.post("/logout")
async def logout(user: User = Depends(verify_token), db: AsyncSession = Depends(get_db)):
    user.token = ""
    user.token_expires_at = None
    await db.commit()
    return {"message": "已登出"}


@router.get("/me")
async def me(user: User = Depends(verify_token)):
    return _user_brief(user)


@router.patch("/password")
async def change_password(
    payload: PasswordChangeRequest,
    user: User = Depends(verify_token),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(payload.old_password, user.password_hash):
        raise HTTPException(status_code=400, detail="原密码错误")
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密码至少 6 位")
    user.password_hash = hash_password(payload.new_password)
    await db.commit()
    return {"message": "密码已修改"}
