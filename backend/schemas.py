from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime


# ===== Project =====
class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    upload_path: str
    file_tree: list | dict
    tech_stack: str
    created_at: datetime


# ===== LLM Config =====
class LlmConfigCreate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    name: str
    provider: str = "openai"
    api_key: str
    base_url: str = "https://api.openai.com/v1"
    api_mode: str = "chat_completions"
    model_name: str = "gpt-4"
    temperature: float = 0.1
    max_tokens: int = 4096
    is_default: bool = False


class LlmConfigUpdate(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    name: Optional[str] = None
    provider: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    api_mode: Optional[str] = None
    model_name: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    is_default: Optional[bool] = None


class LlmConfigOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: int
    name: str
    provider: str
    base_url: str
    api_mode: str
    model_name: str
    temperature: float
    max_tokens: int
    is_default: bool
    has_api_key: bool
    created_at: datetime


# ===== Audit =====
class AuditCreate(BaseModel):
    project_id: int
    llm_config_id: int


class AuditTaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    llm_config_id: int
    status: str
    current_stage: int
    total_stages: int
    audit_mode: str = "multi_agent"
    summary: dict | list
    error_message: str
    created_at: datetime
    completed_at: Optional[datetime]


class AuditStageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    task_id: int
    stage_num: int
    stage_name: str
    agent_role: str = ""
    status: str
    prompt_used: str
    findings: list | dict
    llm_response: str
    compressed_summary: dict | list
    artifact_path: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


# ===== Vulnerability =====
class VulnStatusUpdate(BaseModel):
    confirmed_status: str  # pending/confirmed/false_positive/fixed


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    task_id: int
    stage_id: int
    title: str
    severity: str
    vuln_type: str
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    code_snippet: str
    endpoint: str
    poc_raw: str
    poc_validation_status: str
    poc_validation_note: str
    description: str
    fix_suggestion: str
    dedupe_key: str
    diff_status: str
    confirmed_status: str
    verification_state: str = "candidate"
    confidence: str = "medium"


# ===== Report =====
class ReportExport(BaseModel):
    task_id: int
    format: str  # md / pdf
