from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime


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
    name: Optional[str] = None
    project_id: int
    llm_config_id: int


class AuditRerunRequest(BaseModel):
    """GAP4 部分 stage 重跑请求体（§12.2）。

    ``stage_nums`` 为空/缺省 → 重跑全部可重试阶段（向后兼容旧 /retry 无 body 调用）。
    非空 → 仅重跑指定的子集（必须 ⊆ 可重试阶段，否则 400）。
    """

    model_config = ConfigDict(extra="ignore")
    stage_nums: Optional[list[int]] = None


class AuditTaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
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
    confidence: str = "medium"
    # M5：人工复核状态
    review_status: str = "unreviewed"
    status: str = "open"
    review_note: str = ""
    reviewed_at: Optional[datetime] = None
    reviewer: str = ""
    cwe: str = ""
    # M4a：route_id 关联
    route_id: str = ""
    route_method: str = ""
    route_path: str = ""
    route_handler: str = ""


# ===== Project Index（M4b：结构化项目索引）=====
class ProjectRouteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    route_id: str = ""
    method: str = ""
    path: str = ""
    handler: str = ""
    file_path: str = ""
    auth: str = ""
    line_start: Optional[int] = None
    source_kind: str = ""
    params: str = ""
    notes: str = ""


class ProjectRuleHitOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    label: str = ""
    title: str = ""
    file_path: str = ""
    chunk_path: str = ""
    chunk_type: str = ""
    risk_score: int = 0
    keyword_hit_count: int = 0
    weighted_score: float = 0.0
    stage_nums: str = ""
    evidence: str = ""


class ProjectSourceSinkHintOut(BaseModel):
    """M4b 三联之 source-sink 线索（与 ProjectRouteOut/ProjectRuleHitOut 并列）。"""

    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    label: str = ""
    title: str = ""
    file_path: str = ""
    chunk_path: str = ""
    stage_nums: str = ""
    source_types: str = ""
    sink_keywords: str = ""
    route_paths: str = ""
    risk_score: int = 0
    evidence: str = ""


class ProjectFileOut(BaseModel):
    """§9.3 项目源文件结构化索引（与 ProjectRouteOut/ProjectRuleHitOut/ProjectSourceSinkHintOut 并列）。"""

    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    path: str = ""
    size: int = 0
    extension: str = ""
    role: str = ""
    risk_score: int = 0
    content_hash: str = ""


# ===== Report =====
class ReportExport(BaseModel):
    task_id: int
    format: str = "html"


# ===== §10.2 阶段输出 schema（quality gate，宽容 LLM 漂移）=====
# 全部 extra="ignore" + 默认值：容忍 LLM 漂移，仅在结构严重错乱时 validate 失败（调用方降级不阻断）。
class AgentSpecOutput(BaseModel):
    """Supervisor 规划的单个 agent 规格（selected_agents 元素）。"""
    model_config = ConfigDict(extra="ignore")
    stage_num: int
    focus_guidance: str = ""
    focus_files: list = []
    focus_routes: list = []
    focus_functions: list = []
    focus_data_flows: list = []


class Stage1ArchitectureOutput(BaseModel):
    """阶段一（架构）输出。architecture_info 内部宽松（dict），顶层 schema 提供边界。"""
    model_config = ConfigDict(extra="ignore")
    stage_summary: str = ""
    architecture_info: dict = {}
    risk_hints: list = []
    vulnerabilities: list = []


class VulnerabilityStageOutput(BaseModel):
    """阶段 2-9（漏洞审计）输出。"""
    model_config = ConfigDict(extra="ignore")
    stage_summary: str = ""
    vulnerabilities: list = []
    risk_hints: list = []
    architecture_info: dict = {}


class SupervisorPlanOutput(BaseModel):
    """阶段二（Supervisor 规划）输出。selected_agents 的 stage_num 集合由后端确定性主导（§10.3）。"""
    model_config = ConfigDict(extra="ignore")
    analysis_summary: str = ""
    selected_agents: list[AgentSpecOutput] = []
    skipped_agents: list = []


class SupervisorReviewOutput(BaseModel):
    """阶段四（Supervisor 复核）输出。"""
    model_config = ConfigDict(extra="ignore")
    review_summary: str = ""
    request_rerun: bool = False
    rerun_agents: list = []
    findings_assessment: dict = {}
