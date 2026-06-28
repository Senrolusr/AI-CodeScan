"""统一错误响应（§11.4 文档行 1013-1020）。

所有 API 错误经 main.py 注册的全局 exception_handler 转成 ``ErrorOut``
（``{code, message, details}``）。业务端点 ``raise ApiError(...)`` 携带语义化
code；历史裸 ``HTTPException`` 由 HTTPException handler 自动包成通用 code
（``HTTP_<status>``），无需逐个改路由（存量 raise 自动获得统一格式）。
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ErrorOut(BaseModel):
    """统一错误响应体（§11.4）。"""

    code: str
    message: str
    details: dict[str, Any] = {}


class ApiError(Exception):
    """业务异常：携带语义化 code + HTTP status。

    用法：``raise ApiError("AUDIT_NOT_FOUND", "审计任务不存在", status_code=404)``
    → 全局 handler 输出 ``{"code":"AUDIT_NOT_FOUND","message":"审计任务不存在","details":{}}``。
    """

    def __init__(
        self,
        code: str,
        message: str = "",
        *,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.status_code = status_code
        self.details = details or {}
