from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
import os
from sqlalchemy import text

DB_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "audit.db")

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False, "timeout": 30})
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with async_session() as session:
        yield session


async def init_db():
    async with engine.connect() as conn:
        await conn.execute(text("PRAGMA journal_mode=WAL"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _run_migrations(conn)


async def _run_migrations(conn):
    columns = await conn.execute(text("PRAGMA table_info(llm_configs)"))
    column_names = {row[1] for row in columns.fetchall()}
    if "api_mode" not in column_names:
        await conn.execute(
            text("ALTER TABLE llm_configs ADD COLUMN api_mode VARCHAR(50) DEFAULT 'chat_completions'")
        )

    stage_columns = await conn.execute(text("PRAGMA table_info(audit_stages)"))
    stage_column_names = {row[1] for row in stage_columns.fetchall()}
    if "compressed_summary" not in stage_column_names:
        await conn.execute(
            text("ALTER TABLE audit_stages ADD COLUMN compressed_summary JSON DEFAULT '{}' ")
        )
    if "artifact_path" not in stage_column_names:
        await conn.execute(
            text("ALTER TABLE audit_stages ADD COLUMN artifact_path VARCHAR(512) DEFAULT ''")
        )

    vuln_columns = await conn.execute(text("PRAGMA table_info(vulnerabilities)"))
    vuln_column_names = {row[1] for row in vuln_columns.fetchall()}
    if "poc_validation_status" not in vuln_column_names:
        await conn.execute(
            text("ALTER TABLE vulnerabilities ADD COLUMN poc_validation_status VARCHAR(50) DEFAULT 'unknown'")
        )
    if "poc_validation_note" not in vuln_column_names:
        await conn.execute(
            text("ALTER TABLE vulnerabilities ADD COLUMN poc_validation_note TEXT DEFAULT ''")
        )
    if "dedupe_key" not in vuln_column_names:
        await conn.execute(
            text("ALTER TABLE vulnerabilities ADD COLUMN dedupe_key VARCHAR(128) DEFAULT ''")
        )
    if "diff_status" not in vuln_column_names:
        await conn.execute(
            text("ALTER TABLE vulnerabilities ADD COLUMN diff_status VARCHAR(50) DEFAULT 'new'")
        )
    if "confidence" not in vuln_column_names:
        await conn.execute(
            text("ALTER TABLE vulnerabilities ADD COLUMN confidence VARCHAR(20) DEFAULT 'medium'")
        )
    await conn.execute(
        text("CREATE INDEX IF NOT EXISTS ix_vulnerabilities_dedupe_key ON vulnerabilities (dedupe_key)")
    )

    await conn.execute(
        text(
            """
            DELETE FROM vulnerabilities
            WHERE task_id NOT IN (SELECT id FROM audit_tasks)
               OR stage_id NOT IN (SELECT id FROM audit_stages)
            """
        )
    )
    await conn.execute(
        text(
            """
            DELETE FROM audit_stages
            WHERE task_id NOT IN (SELECT id FROM audit_tasks)
            """
        )
    )
    await conn.execute(
        text(
            """
            DELETE FROM audit_tasks
            WHERE project_id NOT IN (SELECT id FROM projects)
            """
        )
    )

    await conn.execute(
        text("UPDATE audit_tasks SET total_stages = 9 WHERE total_stages IS NULL OR total_stages < 9")
    )

    task_columns = await conn.execute(text("PRAGMA table_info(audit_tasks)"))
    task_column_names = {row[1] for row in task_columns.fetchall()}
    if "audit_mode" not in task_column_names:
        await conn.execute(
            text("ALTER TABLE audit_tasks ADD COLUMN audit_mode VARCHAR(20) DEFAULT 'multi_agent'")
        )

    stage_columns = await conn.execute(text("PRAGMA table_info(audit_stages)"))
    stage_column_names = {row[1] for row in stage_columns.fetchall()}
    if "agent_role" not in stage_column_names:
        await conn.execute(
            text("ALTER TABLE audit_stages ADD COLUMN agent_role VARCHAR(50) DEFAULT ''")
        )
