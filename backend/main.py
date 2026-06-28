from contextlib import asynccontextmanager
import asyncio
import logging
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from starlette.exceptions import HTTPException as StarletteHTTPException
import os

from database import init_db
from errors import ApiError, ErrorOut
from routers import projects, llm_configs, audits, vulnerabilities, reports, auth
from services.audit_worker import audit_worker_loop, recover_incomplete_audits
from services.auth import ensure_admin_user, verify_token
from services.secret_crypto import migrate_encrypt_api_keys
from services.config import get_settings

_settings = get_settings()

BACKEND_ROOT = os.path.dirname(__file__)
DATA_DIR = _settings.data_dir or os.path.join(BACKEND_ROOT, "data")
UPLOADS_DIR = _settings.uploads_dir or os.path.join(BACKEND_ROOT, "uploads")
REPORTS_DIR = _settings.reports_dir or os.path.join(BACKEND_ROOT, "reports")
os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(DATA_DIR, "audit.log"), encoding="utf-8"),
        logging.StreamHandler(),
    ],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await ensure_admin_user()
    await migrate_encrypt_api_keys()
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    stop_event = asyncio.Event()
    await recover_incomplete_audits()
    worker_task = asyncio.create_task(audit_worker_loop(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        await worker_task


app = FastAPI(title="AI Code Audit Platform", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# §11.4 统一错误响应：所有 API 错误转成 ErrorOut {code, message, details}。
# ApiError 携带语义化 code；历史裸 HTTPException 由第二层自动包成通用 code（HTTP_<status>），
# 故存量 86 处 raise 无需逐个改即获得统一格式。
@app.exception_handler(ApiError)
async def _api_error_handler(_request, exc: ApiError):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorOut(code=exc.code, message=exc.message, details=exc.details).model_dump(),
    )


@app.exception_handler(HTTPException)
async def _http_exception_handler(_request, exc: StarletteHTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        # FastAPI 允许 detail 是 dict（如 {"code": ..., "message": ...}）——保留其字段。
        # §11.4：除标准 code/message/details 外的平铺诊断字段也归入 details，避免被统一错误包装吞掉。
        code = str(detail.get("code") or f"HTTP_{exc.status_code}")
        message = str(detail.get("message") or detail)
        details = detail.get("details") if isinstance(detail.get("details"), dict) else {}
        details = dict(details)
        for key, value in detail.items():
            if key not in {"code", "message", "details"} and key not in details:
                details[key] = value
    else:
        code = f"HTTP_{exc.status_code}"
        message = str(detail) if detail is not None else ""
        details = {}
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorOut(code=code, message=message, details=details).model_dump(),
    )


# starlette 原生 HTTPException（如路由不匹配的 NotFound）与 fastapi.HTTPException 不同源，
# 默认返回 {"detail": ...}；复用同一 handler 覆盖之，统一成 ErrorOut。
# 注解用 starlette 基类（fastapi.HTTPException 是其子类，两者兼容）。
app.add_exception_handler(StarletteHTTPException, _http_exception_handler)


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(_request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=ErrorOut(
            code="VALIDATION_ERROR",
            message="请求参数校验失败",
            details={"errors": jsonable_encoder(exc.errors())},
        ).model_dump(),
    )

# M6：所有业务接口要求登录。auth.router 自身管理鉴权（login 放行、其余单独标依赖），不挂全局依赖。
_auth_deps = [Depends(verify_token)]
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(projects.router, prefix="/api/projects", tags=["Projects"], dependencies=_auth_deps)
app.include_router(llm_configs.router, prefix="/api/llm-configs", tags=["LLM Configs"], dependencies=_auth_deps)
app.include_router(audits.router, prefix="/api/audits", tags=["Audits"], dependencies=_auth_deps)
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilities"], dependencies=_auth_deps)
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"], dependencies=_auth_deps)

# M6：/uploads 与 /reports 不再静态公开挂载（§17.6）。
# 源码读取走 GET /api/projects/{id}/file，报告下载走 GET /api/reports/download/{task_id}/{filename}，
# 二者均在上方鉴权路由树内。


@app.get("/api/stats")
async def get_stats(_user=Depends(verify_token)):
    from database import async_session
    from models import AuditStage, Project, AuditTask, Vulnerability
    from sqlalchemy import select, func

    async with async_session() as session:
        project_count = (await session.execute(select(func.count(Project.id)))).scalar() or 0
        audit_count = (await session.execute(select(func.count(AuditTask.id)))).scalar() or 0
        vuln_count = (
            await session.execute(
                select(func.count(Vulnerability.id))
                .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
                .where(AuditStage.stage_num.between(2, 9))
            )
        ).scalar() or 0
        crit_count = (
            await session.execute(
                select(func.count(Vulnerability.id))
                .join(AuditStage, Vulnerability.stage_id == AuditStage.id)
                .where(
                    AuditStage.stage_num.between(2, 9),
                    Vulnerability.severity.in_(["Critical", "High"]),
                )
            )
        ).scalar() or 0

        return {
            "project_count": project_count,
            "audit_count": audit_count,
            "vuln_count": vuln_count,
            "critical_count": crit_count,
        }
