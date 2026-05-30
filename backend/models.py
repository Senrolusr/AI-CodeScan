from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, JSON
from sqlalchemy.sql import func
from database import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    upload_path = Column(String(512), nullable=False)
    file_tree = Column(JSON, default=list)
    tech_stack = Column(String(255), default="")
    created_at = Column(DateTime, server_default=func.now())


class LlmConfig(Base):
    __tablename__ = "llm_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    provider = Column(String(100), default="openai")
    api_key = Column(String(512), nullable=False)
    base_url = Column(String(512), default="https://api.openai.com/v1")
    api_mode = Column(String(50), default="chat_completions")
    model_name = Column(String(255), default="gpt-4")
    temperature = Column(Float, default=0.1)
    max_tokens = Column(Integer, default=4096)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())


class AuditTask(Base):
    __tablename__ = "audit_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), default="")
    project_id = Column(Integer, nullable=False, index=True)
    llm_config_id = Column(Integer, nullable=False, index=True)
    status = Column(String(50), default="pending")  # pending/running/completed/failed
    current_stage = Column(Integer, default=0)
    total_stages = Column(Integer, default=9)
    audit_mode = Column(String(20), default="multi_agent")
    summary = Column(JSON, default=dict)
    error_message = Column(Text, default="")
    created_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)


class AuditStage(Base):
    __tablename__ = "audit_stages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, nullable=False, index=True)
    stage_num = Column(Integer, nullable=False)
    stage_name = Column(String(255), nullable=False)
    agent_role = Column(String(50), default="")  # supervisor_plan/sub_agent/supervisor_review/report/qa
    status = Column(String(50), default="pending")  # pending/running/completed/failed
    prompt_used = Column(Text, default="")
    llm_response = Column(Text, default="")
    findings = Column(JSON, default=list)
    compressed_summary = Column(JSON, default=dict)
    artifact_path = Column(String(512), default="")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, nullable=False, index=True)
    stage_id = Column(Integer, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    severity = Column(String(50), nullable=False)  # Critical/High/Medium/Low/Info
    vuln_type = Column(String(100), nullable=False)
    file_path = Column(String(512), default="")
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, default="")
    endpoint = Column(String(512), default="")
    poc_raw = Column(Text, default="")
    poc_validation_status = Column(String(50), default="unknown")
    poc_validation_note = Column(Text, default="")
    description = Column(Text, default="")
    fix_suggestion = Column(Text, default="")
    dedupe_key = Column(String(128), default="", index=True)
    confidence = Column(String(20), default="medium")  # high/medium/low
