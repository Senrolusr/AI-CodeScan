from contextlib import asynccontextmanager
import asyncio
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from database import init_db
from routers import projects, llm_configs, audits, vulnerabilities, reports
from services.audit_worker import audit_worker_loop, recover_incomplete_audits

BACKEND_ROOT = os.path.dirname(__file__)
DATA_DIR = os.path.join(BACKEND_ROOT, "data")
UPLOADS_DIR = os.path.join(BACKEND_ROOT, "uploads")
REPORTS_DIR = os.path.join(BACKEND_ROOT, "reports")
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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router, prefix="/api/projects", tags=["Projects"])
app.include_router(llm_configs.router, prefix="/api/llm-configs", tags=["LLM Configs"])
app.include_router(audits.router, prefix="/api/audits", tags=["Audits"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])

# Serve uploaded files and reports for download
if os.path.exists(UPLOADS_DIR):
    app.mount("/uploads", StaticFiles(directory=UPLOADS_DIR), name="uploads")
if os.path.exists(REPORTS_DIR):
    app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")


@app.get("/api/stats")
async def get_stats():
    from database import async_session
    from models import Project, AuditTask, Vulnerability
    from sqlalchemy import select, func

    async with async_session() as session:
        project_count = (await session.execute(select(func.count(Project.id)))).scalar() or 0
        audit_count = (await session.execute(select(func.count(AuditTask.id)))).scalar() or 0
        vuln_count = (await session.execute(select(func.count(Vulnerability.id)))).scalar() or 0
        crit_count = (
            await session.execute(
                select(func.count(Vulnerability.id)).where(Vulnerability.severity.in_(["Critical", "High"]))
            )
        ).scalar() or 0

        return {
            "project_count": project_count,
            "audit_count": audit_count,
            "vuln_count": vuln_count,
            "critical_count": crit_count,
        }
