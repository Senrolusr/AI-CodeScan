# CodeScan - AI 代码安全审计平台

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Vue](https://img.shields.io/badge/Vue-3.5-4FC08D?logo=vue.js)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-8.0-646CFF?logo=vite)](https://vite.dev/)

CodeScan 是一个基于大语言模型的多 Agent 代码安全审计平台，采用前后端分离架构。用户上传源码 ZIP 后，系统会先完成项目解析、静态规则预筛、路由抽取和审计缓存构建，再自动执行完整审计流程，最终输出漏洞列表和 HTML 审计报告。

## 核心能力

- 自动审计：创建审计任务后由后台 Worker 自动执行完整流程。
- 多 Agent 协同：Supervisor 负责任务规划与复核，子 Agent 按安全领域并行审计。
- 分阶段可视化：展示 Phase 进度、阶段产物、调试信息、覆盖摘要、风险线索和质量提示。
- 路由与架构提取：识别技术栈、入口点、路由、认证边界和关键数据流。
- 风险线索传递：阶段一只输出未验证风险线索，后续专项 Agent 会按 `stage_nums` / `suggested_stage_nums` 强制复核。
- 正式漏洞质量门槛：候选发现需通过字段完整性、服务端证据和源码反证检查后才进入正式漏洞列表。
- 风险排序：漏洞列表默认按风险等级排序，优先展示 Critical 和 High。
- 流程异常可观测：Worker 超时、Supervisor 降级、子 Agent 失败会写入任务详情。
- HTML 报告导出：报告按漏洞类型分组，每组内部按风险等级展示。

## 审计流程

平台按四个 Phase 自动串行推进：

1. Phase 1：架构分析
   识别技术栈、路由、认证机制、模块边界、关键数据流和高价值审计范围；本阶段只产出架构事实和未验证风险线索，不写入正式漏洞。
2. Phase 2：Supervisor 规划
   基于阶段一结果、静态规则命中和 source-sink 线索决定执行哪些子 Agent。规划响应被截断时，系统会尽量恢复已完整输出的 Agent，并按静态证据和基线阶段补齐可执行计划。
3. Phase 3：子 Agent 并行审计
   按 8 个漏洞方向执行深度审计，默认最多 3 个子 Agent 并发；兜底计划最多选择 7 个子 Agent，并强制保留配置与依赖安全、业务逻辑安全两个基线阶段。
4. Phase 4：Supervisor 复核
   汇总结果、检查覆盖缺口、评估发现质量，并在需要时自动重跑指定阶段。

任务完成后进度保持在 `9/9`。如果 Worker 超时或执行异常，任务会被标记为失败，错误原因会展示在审计详情页的质量提示中。

## 结果质量控制

- 阶段一的 `risk_hints` 是未验证风险线索，不计入漏洞总数，也不会导出为正式漏洞。
- 后续阶段会把阶段一风险线索注入上下文，并要求专项 Agent 对相关线索给出 `confirmed`、`ruled_out` 或 `insufficient_context` 判断。
- 正式漏洞入库前会过滤缺少标题、类型、入口证据、`file_path` 与 `endpoint` 的候选项。
- 认证和授权类漏洞不能只引用前端 API 封装，必须提供服务端控制器、配置或服务层证据。
- 已知源码反证会被质量门槛拦截，例如源码已启用方法级安全、验证码 token 已标记使用、登录流程已有 IP 失败次数限制等。
- 阶段详情会显示候选数量、正式入库数量和过滤说明；全局漏洞列表、任务摘要和 HTML 报告只统计正式漏洞。

## 9 个审计阶段

| Stage | 名称 | 审计范围 |
|---|---|---|
| 1 | 项目架构理解与映射 | 技术栈、路由、认证、数据流、入口点 |
| 2 | RCE 与危险执行审计 | `exec` / `eval` / 反序列化 / 模板注入 / 代码执行 |
| 3 | 注入类漏洞审计 | SQL / NoSQL / 命令 / LDAP / 模板注入 |
| 4 | XSS 与输出编码审计 | 反射型 / 存储型 / DOM 型 XSS |
| 5 | 认证与会话安全审计 | JWT / Session / OAuth / CSRF / 暴力破解 |
| 6 | 授权与访问控制审计 | 水平越权 / 垂直越权 / IDOR / 权限绕过 |
| 7 | 配置与依赖安全审计 | 硬编码密钥 / CORS / Debug 模式 / 危险依赖 |
| 8 | 文件操作安全审计 | 任意上传 / 下载 / 路径遍历 / Zip Slip |
| 9 | 业务逻辑安全审计 | 状态机缺陷 / 竞争条件 / 金额或流程滥用 |

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.11+、FastAPI、SQLAlchemy Async、SQLite |
| 前端 | Vue 3、Vite、Element Plus、Pinia、Vue Router |
| LLM | OpenAI 兼容 API，支持 Chat Completions 和 Responses 接口模式 |
| 报告 | HTML |

## 项目结构

```text
codescan/
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── routers/
│   │   ├── audits.py
│   │   ├── llm_configs.py
│   │   ├── projects.py
│   │   ├── reports.py
│   │   └── vulnerabilities.py
│   ├── services/
│   │   ├── audit_engine.py
│   │   ├── audit_worker.py
│   │   ├── code_parser.py
│   │   ├── json_repair.py
│   │   ├── llm_client.py
│   │   ├── report_generator.py
│   │   └── supervisor.py
│   ├── prompts/
│   ├── scripts/
│   ├── data/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── composables/
│   │   ├── utils/
│   │   ├── views/
│   │   └── i18n.js
│   ├── package.json
│   └── vite.config.js
├── start-platform.ps1
├── start-platform.bat
└── README.md
```

## 快速开始

### 环境要求

- Python 3.11+
- Node.js 20+
- Windows / Linux / macOS

### Windows 一键启动

仓库根目录提供启动脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1
```

脚本会：

- 检查 `python` 和 `npm.cmd`
- 在依赖缺失时安装后端和前端依赖
- 启动后端 `http://127.0.0.1:8000`
- 启动前端 `http://127.0.0.1:3000`

预演模式：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1 -DryRun
```

### 手动启动

安装依赖：

```bash
cd backend
pip install -r requirements.txt

cd ../frontend
npm install
```

启动后端：

```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

启动前端：

```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 3000
```

访问地址：

- 前端：`http://127.0.0.1:3000`
- 后端：`http://127.0.0.1:8000`
- API 文档：`http://127.0.0.1:8000/docs`

## 使用流程

1. 启动前后端。
2. 进入“模型配置”页面，添加 LLM 配置并测试连通性。
3. 进入“项目”页面，上传源码 ZIP。
4. 打开项目详情，点击“开始审计”，可按需填写审计名称。
5. 审计任务会自动执行完整流程，无需手动推进阶段。
6. 在审计详情页查看 Phase 进度、质量提示、阶段结果、阶段一风险线索、漏洞列表和规则命中预览。
7. 审计完成后导出 HTML 报告。

## API 模块

### 项目管理 `/api/projects`

- `POST /upload`
- `GET /`
- `GET /{project_id}`
- `POST /{project_id}/rebuild-cache`
- `GET /{project_id}/file`
- `DELETE /{project_id}`

### 模型配置 `/api/llm-configs`

- `POST /`
- `GET /`
- `GET /{config_id}`
- `PUT /{config_id}`
- `DELETE /{config_id}`
- `POST /{config_id}/test`

### 审计任务 `/api/audits`

- `POST /`
- `GET /`
- `GET /{task_id}`
- `POST /{task_id}/cancel`
- `POST /{task_id}/retry`
- `GET /{task_id}/stages`
- `GET /{task_id}/stages/{stage_num}`
- `GET /{task_id}/stages/{stage_num}/artifact`
- `GET /{task_id}/vulns`
- `DELETE /{task_id}`

说明：

- 创建审计任务后会自动入队并执行完整流程。
- 创建审计任务支持可选 `name` 字段；为空时自动生成审计名称。
- `GET /{task_id}/stages` 和 `GET /{task_id}/stages/{stage_num}` 会返回阶段候选漏洞数、正式漏洞数、过滤数量、阶段一风险线索和调试摘要。
- `GET /{task_id}/vulns` 默认按风险等级排序，同等级按较新的记录优先。
- `GET /{task_id}/vulns` 只返回 Stage 2-9 入库后的正式漏洞，不包含阶段一风险线索和 Supervisor 阶段产物。
- 不再提供手动“执行下一阶段”的接口。

### 漏洞管理 `/api/vulnerabilities`

- `GET /`
- `GET /{vuln_id}`
- `DELETE /{vuln_id}`

说明：

- 全局漏洞列表默认按风险等级排序，同等级按较新的记录优先。
- 全局漏洞列表只包含通过质量门槛的正式漏洞。

### 报告管理 `/api/reports`

- `POST /export`
- `GET /download/{task_id}/{filename}`
- `GET /list/{task_id}`
- `DELETE /{task_id}/{filename}`

说明：

- `POST /export` 仅支持 `format: "html"`。
- HTML 报告会按漏洞类型分组输出，每个类型内按风险等级和标题排序。

## 关键配置

配置位于 `backend/services/config.py`。

| 参数 | 默认值 | 含义 |
|---|---:|---|
| `MAX_CONCURRENT_AGENTS` | 3 | 子 Agent 最大并发数 |
| `WORKER_TASK_TIMEOUT_SECONDS` | 3600 | 单次审计任务超时时间 |
| `WORKER_POLL_INTERVAL_SECONDS` | 2.0 | Worker 轮询间隔 |
| `MAX_FILE_SIZE` | 500KB | 单个源码文件大小上限 |
| `MAX_TREE_FILES` | 10,000 | 单项目最大索引源码和配置文件数 |
| `MAX_AUDIT_SOURCE_FILES` | 1,200 | 进入审计切片的高优先级文件上限 |
| `MAX_CODE_CHUNKS` | 2,000 | 缓存给阶段选择器使用的代码块上限 |
| `TOTAL_CHARS_LIMIT` | 2,000,000 | 总字符预算 |

## 仓库清理状态

仓库只保留源码、依赖清单和必要占位文件，不提交本地依赖、构建产物、数据库、日志、上传源码或导出报告。运行时目录包括：

- `frontend/node_modules/`
- `frontend/dist/`
- `backend/data/audit.db`
- `backend/data/audit.log`
- `backend/data/project_cache/`
- `backend/data/stage_artifacts/`
- `backend/uploads/`
- `backend/reports/`

如需清空本地运行数据，可删除以上目录或文件；应用启动时会自动创建必要目录和 SQLite 数据库。

## 注意事项

- Windows 下如果 `npm` 执行策略受限，请使用 `npm.cmd`。
- 默认数据库为 SQLite，路径为 `backend/data/audit.db`。
- LLM 配置、项目记录、审计任务和漏洞结果存储在本地 SQLite 数据库中。
- 大项目上传后会先做预扫描和缓存构建，首次分析可能需要几十秒。
- 多 Agent 模式默认最多 3 个子 Agent 并发调用 LLM，请确认模型服务端允许足够并发。
- 规划兜底会限制子 Agent 数量，并优先保留 Stage 7 和 Stage 9 两个基线阶段；如果预算不足，低优先级非基线阶段会被标记为 skipped。
- Supervisor 规划或复核失败时，系统会尽量使用默认计划或保留已有结果继续收口，但这类降级会展示在“质量提示”中，建议人工复核。
