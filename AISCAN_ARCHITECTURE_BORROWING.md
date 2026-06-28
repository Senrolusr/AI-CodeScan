# AISCAN 架构借鉴与 codescan 后续改造技术文档

## 1. 文档目标

本文用于指导后续 codescan 改造：在不直接照搬 AISCAN 技术栈的前提下，提炼 AISCAN 中适合迁移到 codescan 的前端与后端架构能力，并拆成可执行的阶段性任务。

当前假设：

- AISCAN 是参考项目，目录位于 `D:\111\AISCAN`。
- codescan 是目标项目，目录位于 `D:\111\codescan`。
- codescan 后端以 Python/FastAPI 为主，前端以 Vue + Element Plus 为主。
- AISCAN 后端以 Go 服务为主，前端也是 Vue，但 UI 组织和运行态诊断能力比 codescan 更完整。
- 后续改造优先保持 codescan 现有技术栈，不引入 Go 后端，也不大规模重写前端。

## 2. codescan 当前基础

codescan 已经具备一部分 AISCAN 风格能力，后续应在这些基础上继续演进，而不是推倒重做。

### 2.1 已具备的后端能力

- `backend/services/execution_events.py`
  - 使用 `execution_events.jsonl` 记录审计执行事件。
  - 提供 `record_execution_event` 记录轻量事件。
  - 提供 `call_llm_with_events` 包装 LLM 调用，记录 `llm_start`、`llm_success`、`llm_error`。
  - 支持按 `stage_num`、`phase`、`event_type`、`after`、`limit` 查询事件。

- `backend/routers/audits.py`
  - 已增加 `GET /api/audits/{task_id}/events`。
  - 已有稳定提交相关接口：
    - `POST /api/audits/{task_id}/submit-routes`
    - `POST /api/audits/{task_id}/stages/{stage_num}/submit-findings`
    - `POST /api/audits/{task_id}/stages/{stage_num}/submit-reviews`
    - `GET /api/audits/{task_id}/query-routes`
    - `GET /api/audits/{task_id}/stages/{stage_num}/query-output`

- `backend/services/stable_submission.py`
  - 已有 `stable_submissions` 概念。
  - 支持 routes/findings/reviews 的规范化、去重、合并。

- `backend/services/audit_engine.py`
  - 阶段一架构分析、阶段三并发审计已接入部分 LLM 调用事件。
  - 已有 `stage_artifacts`、阶段 pass 产物、压缩摘要和稳定提交合并逻辑。

### 2.2 已具备的前端能力

- `frontend/src/views/ExecutionEvents.vue`
  - 已有执行事件页面。
  - 支持筛选阶段、事件类型、阶段一/阶段三/错误分组。
  - 展示 prompt 长度、响应长度、token、耗时、模型、预览、meta。

- `frontend/src/views/StableWorkbench.vue`
  - 已有稳定提交工作台雏形。
  - 能查询 routes、stage output，提交 routes/findings/reviews。

- `frontend/src/views/AuditDetail.vue`
  - 已增加进入执行过程和稳定提交工作台的入口。
  - 详情页已有阶段、漏洞、报告等内容，但信息仍偏集中，后续需要继续拆分。

## 3. AISCAN 中值得借鉴的前端架构

### 3.1 把“详情页”拆成多个工作台视图

AISCAN 的任务详情不是把所有内容堆在一个页面，而是拆成不同视图：

- 总览：只展示任务状态、关键指标、最近事件。
- 编排工作台：展示队列、依赖、角色负载、活动流、诊断。
- 阶段视图：聚焦某一个阶段的结果、控制台、日志和产物。
- 报告/结果视图：聚合漏洞和导出结果。

codescan 后续应继续把 `AuditDetail.vue` 拆薄。详情页只保留导航、状态摘要和关键入口，把重型内容迁移到独立页面或组件中。

建议目标路由：

- `/audits/:id`：审计总览。
- `/audits/:id/stages`：阶段总览。
- `/audits/:id/stages/:stageNum`：单阶段详情。
- `/audits/:id/execution`：执行过程。
- `/audits/:id/stable-workbench`：稳定提交工作台。
- `/audits/:id/orchestration`：编排/并发审计工作台。
- `/audits/:id/report`：报告与漏洞结果。

### 3.2 借鉴 AISCAN 的编排工作台

AISCAN 的 `TaskOrchestrationWorkbench.vue` 是最值得借鉴的前端模块。它不是简单展示日志，而是把运行状态拆成可诊断结构：

- 当前运行状态。
- 阶段流转图。
- active/ready/waiting/blocked 四类队列。
- planner/worker/integrator/validator/persistence 角色负载。
- 当前焦点阶段和焦点角色。
- 长时间无进展、阻塞原因、失败原因。
- 活动流和 raw payload。
- 单阶段过滤和跳转到阶段日志。

codescan 目前没有真正的编排层，但阶段三“并发审计”已经有多阶段并发执行特征。后续可以先做轻量版：

- active：正在调用 AI 或正在处理的阶段/任务。
- ready：待执行但已满足依赖的阶段。
- waiting：等待上游产物、等待重试、等待并发槽位的阶段。
- blocked：缺少路由、缺少阶段一摘要、LLM 连续失败、输出无法解析等阻塞项。

第一版不需要完整复制 AISCAN 的多角色模型，可先映射为 codescan 的本地角色：

- `planner`：阶段规划、阶段一架构分析、路由/资产梳理。
- `worker`：阶段三并发审计单元。
- `validator`：结果校验、补全、重试、二次解析。
- `persistence`：漏洞、稳定提交、报告、artifact 持久化。

### 3.3 阶段控制台和结果分离

AISCAN 的 `AuditStageView.vue` 将阶段结果与 console 分离，并对不同日志做视觉区分：

- `AI:` 日志使用高亮。
- `Executing tool` 使用工具执行高亮。
- 错误/失败日志突出显示。
- console 自动滚动。
- 每个阶段可以独立查看结果和日志。

codescan 目前 `ExecutionEvents.vue` 已有事件页面，但和阶段详情的关系还不够紧。建议后续：

- 单阶段详情页增加 `结果 / 执行过程 / Artifact / 稳定提交` tabs。
- `执行过程` tab 复用 `ExecutionEvents.vue` 的事件列表能力，但默认按当前 stage 过滤。
- 阶段三并发审计中，每个并发单元都应能点开对应 AI 调用、prompt 预览、response 预览、错误堆栈和重试记录。

### 3.4 活动流比纯日志更适合排查问题

AISCAN 的活动流将事件转成可读记录，同时保留 raw payload。codescan 后续也应避免只显示长文本日志，建议每条事件包含：

- `sequence`：递增序号。
- `ts`：时间。
- `event_type`：事件类型。
- `level`：info/success/warning/error。
- `status`：running/completed/failed/skipped/blocked。
- `stage_num`、`stage_name`。
- `phase`：例如 `stage1.architecture`、`stage3.concurrent.audit`。
- `title`、`message`。
- `duration_ms`、`model`、`token_usage`。
- `prompt_preview`、`response_preview`。
- `meta`：原始调试信息。

这样前端可同时提供“人能快速读懂的过程”和“排查问题需要的原始数据”。

## 4. AISCAN 中值得借鉴的后端架构

### 4.1 编排快照 Snapshot

AISCAN 后端有明确的 orchestration snapshot 概念，典型字段包括：

- run summary。
- diagnostics。
- subtasks。
- agents。
- routes。
- findings。
- events。
- updated_at。

codescan 当前是按审计任务、阶段、事件分散查询。建议新增一个聚合接口，供前端工作台一次拿到运行态视图。

建议接口：

```http
GET /api/audits/{task_id}/orchestration
```

建议返回：

```json
{
  "run": {
    "task_id": 1,
    "status": "running",
    "mode": "audit",
    "started_at": "2026-06-17T10:00:00Z",
    "updated_at": "2026-06-17T10:05:00Z"
  },
  "diagnostics": {
    "focus_status": "running",
    "focus_reason": "active_llm_call",
    "current_stage_num": 3,
    "current_phase": "stage3.concurrent.audit",
    "blocked_reason": "",
    "error_message": "",
    "last_progress_at": "2026-06-17T10:04:55Z",
    "silence_seconds": 5,
    "stalled": false
  },
  "stage_progress": [
    {
      "stage_num": 1,
      "stage_name": "架构分析",
      "status": "completed",
      "active_count": 0,
      "ready_count": 0,
      "waiting_count": 0,
      "blocked_count": 0,
      "completed_count": 1,
      "failed_count": 0
    }
  ],
  "queues": {
    "active": [],
    "ready": [],
    "waiting": [],
    "blocked": []
  },
  "role_loads": {
    "planner": 0,
    "worker": 3,
    "validator": 1,
    "persistence": 0
  },
  "latest_events": [],
  "updated_at": "2026-06-17T10:05:00Z"
}
```

第一版可以从数据库里的 audit task/stage 状态和 `execution_events.jsonl` 聚合，不需要新增复杂数据库模型。

### 4.2 事件总线与增量事件

AISCAN 有事件发布和订阅机制，并支持按 sequence 增量消费。codescan 当前是 JSONL 持久化 + HTTP 轮询，这对第一阶段足够，但需要统一增量语义。

建议保留当前 JSONL 实现，增强为：

- 所有事件必须有稳定递增 `sequence`。
- 所有查询都支持 `after`。
- 前端轮询默认传 `after=lastSequence`。
- 后续再增加 SSE：

```http
GET /api/audits/{task_id}/events/stream?after=123
```

迁移顺序：

1. 先把 HTTP 轮询和 `after` 做稳定。
2. 再做 SSE，不影响现有页面。
3. SSE 断线后回退到 HTTP 轮询。

### 4.3 工具/动作执行层

AISCAN 的 scanner 里有明确的工具执行层，例如：

- `search_files`
- `grep_files`
- `read_file`
- `query_routes`
- `query_stage_output`
- `submit_routes`
- `submit_findings`
- `submit_reviews`

这些工具不是普通函数调用，而是有统一计划、参数规范化、缓存、错误处理、结果落盘和日志输出。这个设计很适合 codescan 后续改造。

codescan 当前很多阶段逻辑集中在 `audit_engine.py`，文件很大，阶段逻辑、LLM 调用、解析、稳定提交、artifact 合并混在一起。建议逐步抽出动作层：

```text
backend/services/audit_actions/
  __init__.py
  base.py
  llm.py
  routes.py
  findings.py
  artifacts.py
  validators.py
```

建议核心抽象：

```python
class AuditActionContext:
    task_id: int
    stage_num: int | None
    phase: str
    role: str
    run_id: str | None

class AuditActionResult:
    status: str
    message: str
    data: dict
    artifact_refs: list[str]

class AuditAction:
    name: str
    async def run(self, ctx: AuditActionContext, args: dict) -> AuditActionResult:
        ...
```

第一批动作可以只覆盖：

- `llm_call`：统一记录 prompt/response/token/error。
- `submit_routes`：复用 `stable_submission.py`。
- `submit_findings`：复用 `stable_submission.py`。
- `submit_reviews`：复用 `stable_submission.py`。
- `save_artifact`：统一保存 stage artifact。
- `parse_and_validate_json`：统一解析 AI 输出。

### 4.4 稳定提交作为“运行中产物”，不是最终 JSON 的附属品

AISCAN 中 `submit_routes`、`submit_findings`、`submit_reviews` 是运行过程中的显式工具动作。这个设计比“等 AI 最后输出完整 JSON”更可靠。

codescan 已经通过 `stable_submissions` 开始接近这个方向，但还应继续推进：

- 阶段一发现路由时，允许边审计边提交 routes。
- 阶段三发现漏洞时，允许边验证边提交 findings。
- 复核阶段提交 reviews，而不是只覆盖原始 finding。
- 最终报告从稳定提交和阶段结果中合并，而不是只依赖最终 LLM JSON。

后端目标：

- stable submission 是一等运行产物。
- 每次提交都记录事件。
- 前端可查看提交历史、去重结果、合并来源。
- 报告生成优先读取稳定提交，再回退到阶段输出。

### 4.5 诊断层 Diagnostics

AISCAN 的 diagnostics 会计算当前焦点、阻塞、长时间无进展、失败原因。codescan 后续应增加轻量诊断服务：

```text
backend/services/orchestration_diagnostics.py
```

输入：

- audit task。
- stages。
- execution events。
- stage artifacts。
- stable submission stats。

输出：

- 当前最需要关注的阶段。
- 最近一次有效进展时间。
- 是否 stalled。
- blocked reason。
- error message。
- 建议用户排查入口。

典型阻塞原因：

- 阶段一未完成，阶段三不能开始。
- 阶段一没有路由/资产结果，阶段三缺少审计目标。
- LLM 调用失败超过阈值。
- AI 输出无法解析，重试仍失败。
- 并发审计有子任务失败。
- artifact 写入失败。

## 5. codescan 目标架构

### 5.1 后端目标模块

建议新增或演进以下模块：

```text
backend/services/
  execution_events.py             # 已有，继续增强
  stable_submission.py            # 已有，继续增强
  orchestration_snapshot.py        # 新增：聚合任务运行态
  orchestration_diagnostics.py     # 新增：诊断当前焦点/阻塞/停滞
  audit_actions/                  # 新增：抽出动作执行层
    base.py
    llm.py
    stable.py
    artifacts.py
    validators.py
```

`audit_engine.py` 不建议一次性拆完。正确做法是：

1. 新增服务，不改变现有主流程。
2. 把新服务插入现有流程记录更多结构化数据。
3. 稳定后再逐步迁移大函数内部逻辑。

### 5.2 后端 API 目标

保留现有接口，并新增：

```http
GET /api/audits/{task_id}/orchestration
GET /api/audits/{task_id}/orchestration/events?after=0&limit=100
GET /api/audits/{task_id}/orchestration/diagnostics
GET /api/audits/{task_id}/stages/{stage_num}/events?after=0&limit=100
```

可选增强：

```http
GET /api/audits/{task_id}/events/stream?after=0
POST /api/audits/{task_id}/stages/{stage_num}/rerun
POST /api/audits/{task_id}/orchestration/rerun
```

### 5.3 前端目标组件

建议新增或拆分：

```text
frontend/src/views/
  AuditOverview.vue               # 从 AuditDetail 拆出的轻量总览
  AuditStages.vue                 # 阶段总览
  AuditStageDetail.vue            # 单阶段详情
  AuditOrchestration.vue          # 编排/并发工作台
  ExecutionEvents.vue             # 已有，继续增强
  StableWorkbench.vue             # 已有，继续增强

frontend/src/components/audit/
  AuditStatusHeader.vue
  StageProgressTimeline.vue
  StageQueueBoard.vue
  ExecutionEventFeed.vue
  ExecutionEventDrawer.vue
  DiagnosticsPanel.vue
  RoleLoadPanel.vue
  ArtifactExplorer.vue
```

后续 UI 原则：

- 总览页只显示摘要和入口。
- 调试类信息放到执行过程、编排工作台、阶段详情。
- 原始 JSON、prompt/response 预览默认折叠。
- 队列、事件、诊断、artifact 独立成组件。
- 移动端优先纵向堆叠，桌面端使用 2-3 栏工作台布局。

## 6. 阶段一和阶段三的实时 AI 数据增强方案

用户当前最关心的是：阶段一架构分析和阶段三并发审计能查看实时 AI 调用过程，方便排查问题。

建议事件 taxonomy：

```text
llm_start
llm_success
llm_error
pass_start
pass_complete
stage_start
stage_complete
stage_error
worker_start
worker_complete
worker_error
artifact_saved
stable_submit
parse_error
retry_scheduled
retry_start
retry_complete
blocked
```

阶段一建议记录：

- 架构分析开始/结束。
- 每次 LLM 调用开始/成功/失败。
- prompt 字符数、response 字符数、token 用量。
- 架构摘要解析成功/失败。
- 路由/资产稳定提交数量。
- artifact 保存路径。
- 重试原因和重试结果。

阶段三建议记录：

- 并发审计批次开始/结束。
- 每个并发 worker 的 stage、phase、目标文件/路由/漏洞类型。
- 每个 worker 的 LLM 调用过程。
- 每个 worker 输出解析结果。
- finding 稳定提交数量。
- worker 失败原因。
- 并发队列 active/waiting/blocked 状态变化。

前端展示建议：

- `ExecutionEvents.vue` 增加“实时跟随”开关。
- 增加阶段一/阶段三快捷筛选。
- 每条 LLM 事件可展开 prompt/response/meta。
- 增加按 worker/run_id 分组。
- `AuditOrchestration.vue` 显示队列状态，点击队列项打开对应事件抽屉。

## 7. 分阶段改造计划

### P0：巩固现有事件能力

目标：让现有 `ExecutionEvents.vue` 成为稳定可用的排查页面。

任务：

- 统一所有事件字段，补齐 `sequence`、`phase`、`status`、`role`、`run_id`。
- 阶段一和阶段三所有 LLM 调用都走 `call_llm_with_events`。
- 所有重试、解析失败、artifact 保存、稳定提交都记录事件。
- 前端轮询严格使用 `after=lastSequence` 增量拉取。
- 增加“仅错误”“仅 LLM”“阶段一”“阶段三”快速筛选。

验收：

- 运行一次审计后，能看到阶段一和阶段三每次 AI 调用的开始、结束、耗时、token、预览和错误。
- 事件不会重复显示。
- 审计失败时能从事件页定位最后一次失败原因。

### P1：新增编排快照接口和轻量工作台

目标：借鉴 AISCAN 的工作台，但先实现 codescan 可用的轻量版。

任务：

- 新增 `backend/services/orchestration_snapshot.py`。
- 新增 `GET /api/audits/{task_id}/orchestration`。
- 从 stages + events 聚合 active/ready/waiting/blocked。
- 新增 `frontend/src/views/AuditOrchestration.vue`。
- 增加阶段进度、队列、诊断、活动流。

验收：

- 用户可以在一个工作台中看到当前哪个阶段/worker 正在跑、哪个阻塞、哪个失败。
- 点击队列项能跳到对应执行事件。

### P2：拆分详情页

目标：解决“所有东西堆在一个页面太多”的 UI 问题。

任务：

- 把 `AuditDetail.vue` 拆成总览页和多个子视图。
- 新增阶段详情页。
- 把稳定提交和执行过程从详情页中移成独立入口。
- 总览页只保留状态、进度、关键统计、最近错误和快捷按钮。

验收：

- 详情页首屏不再堆满日志、漏洞、阶段、稳定提交、执行过程。
- 用户可以通过顶部/侧边导航进入不同工作台。

### P3：动作执行层

目标：降低 `audit_engine.py` 复杂度，为后续稳定迭代打基础。

任务：

- 新增 `audit_actions` 模块。
- 先迁移 LLM 调用包装、artifact 保存、稳定提交、JSON 解析校验。
- 每个 action 自动记录 execution event。
- 保持原有审计流程行为不变。

验收：

- 新增 action 单元测试。
- 审计输出与改造前保持兼容。
- 事件记录更完整。

### P4：SSE 实时流和高级诊断

目标：让执行过程接近 AISCAN 的实时体验。

任务：

- 新增 `/events/stream`。
- 前端优先 SSE，失败回退轮询。
- 增加 stalled 检测。
- 增加阻塞原因分类。
- 增加可复制的 raw payload。

验收：

- 审计运行中无需手动刷新即可看到 AI 调用过程。
- 网络断开重连后能从 `after=lastSequence` 补齐事件。

## 8. 风险与取舍

- 不建议直接复制 AISCAN 的 Go 后端编排服务。codescan 当前是 Python/FastAPI，直接迁移成本高，收益不明显。
- 不建议一次性重写 `audit_engine.py`。该文件承担核心审计流程，先围绕它增加事件、快照和 action，再逐步拆。
- 不建议前端完全复制 AISCAN 的 Tailwind 风格。codescan 已使用 Element Plus，应保持统一组件体系，只借鉴布局和信息架构。
- JSONL 事件存储适合第一阶段，但长期需要考虑事件量过大、并发写入、清理策略和查询性能。
- prompt/response 预览可能包含敏感代码，应默认截断，并考虑后续增加脱敏和权限控制。

## 9. 后续修改优先级建议

建议下一轮代码修改从 P0 开始，顺序如下：

1. 补齐 `execution_events.py` 的统一事件字段和 helper。
2. 梳理 `audit_engine.py` 中阶段一、阶段三所有 LLM 调用，确保都记录事件。
3. 给 artifact 保存、解析失败、重试、稳定提交补事件。
4. 增强 `ExecutionEvents.vue` 的实时跟随、分组、抽屉详情。
5. 新增 `orchestration_snapshot.py` 和 `/orchestration` 接口。
6. 新增 `AuditOrchestration.vue`，先做轻量版队列和诊断。
7. 再拆 `AuditDetail.vue`。

这条路线能最短路径解决当前排查问题，同时逐步把 codescan 的架构向 AISCAN 的“可观测、可诊断、可编排”方向推进。
