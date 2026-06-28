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
    # ── M5：人工复核状态（additive，旧数据默认 unreviewed/open）──
    review_status = Column(String(30), default="unreviewed")  # unreviewed/confirmed/rejected/needs_review
    status = Column(String(20), default="open")  # open/accepted_risk/fixed
    review_note = Column(Text, default="")
    reviewed_at = Column(DateTime, nullable=True)
    reviewer = Column(String(100), default="")  # M6 鉴权前为自由文本
    cwe = Column(String(20), default="")
    # ── M4a：route_id 关联（additive，旧数据默认空；与 dedupe_key 正交）──
    route_id = Column(String(32), default="", index=True)
    route_method = Column(String(16), default="")
    route_path = Column(String(512), default="")
    route_handler = Column(String(256), default="")


# ──────────────────────────────────────────────────────────────────────────
# 运行时状态机（M2 新增，影子写入；不改动上面任何旧表/旧字段）
# 一次 AuditTask 可有多次 run（首次审计 / 失败重试 / 指定阶段重跑）。
# ──────────────────────────────────────────────────────────────────────────
class AuditRun(Base):
    """一次审计运行。"""

    __tablename__ = "audit_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, nullable=False, index=True)
    status = Column(String(50), default="pending")  # pending/running/paused/completed/failed/cancelled
    mode = Column(String(50), default="full")  # full/rerun/review_rerun
    selected_stage_nums = Column(JSON, default=list)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, default="")
    created_at = Column(DateTime, server_default=func.now())


class AuditSubtask(Base):
    """一个阶段子任务（阶段在一次 run 内的执行计划项）。"""

    __tablename__ = "audit_subtasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, nullable=False, index=True)
    task_id = Column(Integer, nullable=False, index=True)
    stage_num = Column(Integer, nullable=False)
    role = Column(String(50), default="")  # architecture/supervisor_plan/sub_agent/supervisor_review
    status = Column(String(50), default="pending")  # pending/blocked/running/completed/failed/skipped/cancelled
    depends_on = Column(JSON, default=list)
    attempt_count = Column(Integer, default=0)
    blocked_reason = Column(Text, default="")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class AuditAgentRun(Base):
    """某个 Agent 的一次执行尝试。"""

    __tablename__ = "audit_agent_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    subtask_id = Column(Integer, nullable=True, index=True)
    run_id = Column(Integer, nullable=True, index=True)
    task_id = Column(Integer, nullable=False, index=True)
    stage_num = Column(Integer, nullable=True)
    agent_role = Column(String(50), default="")  # supervisor/sub_agent/validator/architecture
    attempt = Column(Integer, default=1)
    llm_config_id = Column(Integer, nullable=True)
    status = Column(String(50), default="running")  # running/completed/failed
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    finish_reason = Column(String(100), default="")
    error_message = Column(Text, default="")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class AuditEvent(Base):
    """关键状态变化事件（活动流 / 审计追溯）。"""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, nullable=False, index=True)
    run_id = Column(Integer, nullable=True, index=True)
    stage_num = Column(Integer, nullable=True)
    event_type = Column(String(64), nullable=False)
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, server_default=func.now())


# ──────────────────────────────────────────────────────────────────────────
# 项目结构化索引（M4b 新增，影子写入；不依赖 AuditTask.summary）。
# warm_project_cache 产出的 static_routes / rule_hits 全量同步进这两张表，
# 供前端项目页独立消费，并作为 vulnerabilities.route_id 的可 JOIN 主表。
# ──────────────────────────────────────────────────────────────────────────
class ProjectRoute(Base):
    """项目静态路由清单（route_id 与 vulnerabilities.route_id 同源）。"""

    __tablename__ = "project_routes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    route_id = Column(String(32), default="", index=True)  # rt_<sha1[:12]>
    method = Column(String(16), default="")
    path = Column(String(512), default="")
    handler = Column(String(256), default="")
    file_path = Column(String(512), default="")
    auth = Column(String(64), default="")
    line_start = Column(Integer, nullable=True)
    source_kind = Column(String(32), default="")  # flask/spring/gin/django/fastapi...
    params = Column(Text, default="")  # JSON
    notes = Column(Text, default="")


class ProjectRuleHit(Base):
    """项目规则命中明细（消除前端对 task.summary.rule_hits_preview 的依赖）。"""

    __tablename__ = "project_rule_hits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    label = Column(String(64), default="", index=True)
    title = Column(String(256), default="")
    file_path = Column(String(512), default="", index=True)
    chunk_path = Column(String(512), default="")
    chunk_type = Column(String(32), default="")
    risk_score = Column(Integer, default=0)
    keyword_hit_count = Column(Integer, default=0)
    weighted_score = Column(Float, default=0.0)
    stage_nums = Column(Text, default="")  # JSON，如 [3,4]
    evidence = Column(Text, default="")


class ProjectSourceSinkHint(Base):
    """项目 source-sink 线索（M4b 三联补齐：与 project_routes/project_rule_hits 并列）。

    code_parser_pkg 产出的 source_sink_hints 影子写入；不依赖 AuditTask.summary。
    """

    __tablename__ = "project_source_sink_hints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    label = Column(String(64), default="", index=True)  # rce/injection/xss/auth/file/business
    title = Column(String(256), default="")
    file_path = Column(String(512), default="", index=True)
    chunk_path = Column(String(512), default="")
    stage_nums = Column(Text, default="")  # JSON，如 [2,3]
    source_types = Column(Text, default="")  # JSON，如 ["query","db_input"]
    sink_keywords = Column(Text, default="")  # JSON
    route_paths = Column(Text, default="")  # JSON
    risk_score = Column(Integer, default=0)
    evidence = Column(Text, default="")


class ProjectFile(Base):
    """项目源文件结构化索引（§9.3：与 project_routes/project_rule_hits/project_source_sink_hints 并列）。

    每源文件一行：path/size/extension/role/risk_score/content_hash。
    warm_project_cache 产出 project_files 影子写入；不依赖 AuditTask.summary。
    """

    __tablename__ = "project_files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, nullable=False, index=True)
    path = Column(String(512), default="", index=True)
    size = Column(Integer, default=0)
    extension = Column(String(32), default="", index=True)
    role = Column(String(32), default="", index=True)  # controller/service/model/config/middleware/route/auth/dao
    risk_score = Column(Integer, default=0)
    content_hash = Column(String(32), default="", index=True)


# ──────────────────────────────────────────────────────────────────────────
# 用户与鉴权（M6 最小鉴权：单管理员 + 不透明 token）。
# organization_id 留空字段，备 M6 完整版多租户扩展（本轮不用）。
# ──────────────────────────────────────────────────────────────────────────
class User(Base):
    """平台用户（本轮：单管理员；token 为不透明串，存表可主动失效）。"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False, default="")
    role = Column(String(20), default="admin")  # admin（留 enum 扩展）
    status = Column(String(20), default="active")  # active/disabled
    token = Column(String(64), default="", index=True)  # 不透明 token
    token_expires_at = Column(DateTime, nullable=True)
    organization_id = Column(Integer, nullable=True)  # 留空，备多租户扩展
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
