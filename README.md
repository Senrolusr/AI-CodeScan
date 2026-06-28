# CodeScan - AI 代码安全审计平台

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Vue](https://img.shields.io/badge/Vue-3.5-4FC08D?logo=vue.js)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-8.0-646CFF?logo=vite)](https://vite.dev/)

CodeScan 是一个基于大语言模型的多 Agent 代码安全审计平台，采用 FastAPI + Vue 前后端分离架构。用户上传源码 ZIP 后，系统会完成项目解析、静态规则预筛、路由抽取、审计缓存构建和多阶段 LLM 审计，最终输出漏洞列表、审计过程事件、覆盖摘要和 HTML 报告。

## 核心能力

- 自动审计：创建审计任务后由后台 Worker 执行完整流程，支持暂停、恢复、取消和重跑。
- 多 Agent 协同：Supervisor 负责任务规划与复核，子 Agent 按安全领域并行审计。
- 静态上下文增强：提取项目结构、技术栈、入口点、路由、认证边界、Source-Sink 线索和规则命中。
- 路由覆盖闭环：静态路由清单作为覆盖基准，模型阶段回填 `route_coverage`，缺口会进入强制补审批次。
- 过程可观测：审计快照、运行记录、子任务、Agent 调用、JSON 事件和 SSE 事件流统一暴露。
- 质量门槛：候选发现需通过字段完整性、服务端证据、源码反证和去重检查后才进入正式漏洞列表。
- 风险排序与复核：漏洞按风险等级排序，支持复核状态更新和按严重级别筛选。
- 报告导出：按漏洞类型和风险等级生成 HTML 审计报告。

## 审计流程

平台按多阶段自动推进：

1. Stage 1 架构分析：识别技术栈、认证机制、入口点、路由、模块边界、数据流和未验证风险线索。
2. Supervisor 规划：结合阶段一结果、静态规则命中、Source-Sink 线索和路由清单选择要执行的子 Agent。
3. Stage 2-9 子 Agent 审计：按漏洞方向并行审计，默认最多 3 个子 Agent 并发。
4. 路由补审：汇总各阶段 `route_coverage` 后，对仍未覆盖的路由按阶段归属拆批，强制要求模型逐条回填覆盖证明。
5. Supervisor 复核：汇总结果、检查覆盖缺口、评估发现质量，并在需要时重跑指定阶段。

任务完成后进度保持在 `9/9`。如果 Worker 超时、模型响应截断、Supervisor 降级或子 Agent 失败，异常信息会写入审计详情页的质量提示和运行事件。

## 路由覆盖口径

路由覆盖指“大模型审计过程中被实际审计并回填证明的路由”，不是单纯的静态路由扫描数量。

- 静态扫描会先生成路由清单，作为审计覆盖基准和路由调度池。
- 常规 Stage 不会把全部静态路由原样塞给每一次 LLM 调用，而是按阶段主题、文件切片和优先级选择焦点路由。
- 当任务摘要发现缺口时，系统会启动路由补审批次，把缺失路由作为强制目标交给对应 Stage。
- 补审响应必须为本批每个 `route_id` 返回 `route_coverage`，否则会触发最小化证明重试或记录缺口。
- 认证类路由优先归入 Stage 5，授权/访问控制类路由归入 Stage 6，其余路由按关键词、文件和风险线索归属到对应阶段。

关键覆盖字段：

| 字段 | 含义 |
|---|---|
| `inventory_route_count` | 静态路由清单中的路由数 |
| `scan_reported_route_count` | 扫描与阶段一报告出的路由数 |
| `model_derived_route_count` | 模型发现但不在静态清单中的路由数 |
| `canonical_route_count` | 归一化后的覆盖基准路由数 |
| `audited_route_count` | 已被模型标记为审计过的路由数 |
| `attested_route_count` | 已提供逐条覆盖证明的路由数 |
| `missing_route_count` | 仍未被覆盖的基准路由数 |
| `missing_routes` | 缺失路由明细，供补审批次使用 |

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

## 结果质量控制

- Stage 1 的 `risk_hints` 是未验证风险线索，不计入漏洞总数，也不会导出为正式漏洞。
- 后续阶段会把风险线索注入上下文，并要求专项 Agent 对相关线索给出确认、排除或证据不足的判断。
- 正式漏洞入库前会过滤缺少标题、类型、入口证据、`file_path` 与 `endpoint` 的候选项。
- 认证和授权类漏洞不能只引用前端 API 封装，必须提供服务端控制器、配置或服务层证据。
- 已知源码反证会被质量门槛拦截，例如源码已启用方法级安全、验证码 token 已消费、登录流程已有 IP 失败次数限制等。
- 全局漏洞列表、任务摘要和 HTML 报告只统计通过质量门槛的正式漏洞。

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.11+、FastAPI、SQLAlchemy Async、SQLite |
| 前端 | Vue 3、Vite、Element Plus、Pinia、Vue Router |
| LLM | OpenAI 兼容 API，支持 Chat Completions 与 Responses 接口模式 |
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
│   ├── services/
│   │   ├── ai_engine/
│   │   ├── code_parser_pkg/
│   │   ├── audit_worker.py
│   │   ├── audit_runtime.py
│   │   ├── report_generator.py
│   │   └── supervisor.py
│   ├── prompts/
│   ├── tests/
│   ├── data/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── composables/
│   │   ├── stores/
│   │   ├── utils/
│   │   └── views/
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

```powershell
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1
```

脚本会检查 Python 和 npm，按需安装依赖，并启动：

- 后端：`http://127.0.0.1:8000`
- 前端：`http://127.0.0.1:3000`

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

### 首次登录

系统启动时会确保存在管理员账号：

- 默认用户名：`admin`
- 建议通过环境变量 `CODE_SCAN_ADMIN_PASSWORD` 指定初始密码
- 如果未指定密码，系统会生成随机密码并写入后端启动日志

登录后可在前端修改管理员密码。业务接口默认要求 Bearer Token，SSE 事件流使用 `?token=` 传递同一令牌。

## 使用流程

1. 启动前后端。
2. 使用管理员账号登录。
3. 在“模型配置”页面添加 LLM 配置并测试连通性。
4. 在“项目”页面上传源码 ZIP。
5. 打开项目详情，查看路由、规则命中和 Source-Sink 线索。
6. 点击“开始审计”，可按需填写审计名称。
7. 在审计详情页查看 Phase 进度、事件流、覆盖摘要、质量提示、阶段结果、风险线索和漏洞列表。
8. 审计完成后导出 HTML 报告。

## API 模块

### 认证 `/api/auth`

- `POST /login`
- `POST /logout`
- `GET /me`
- `PATCH /password`

### 项目管理 `/api/projects`

- `POST /upload`
- `GET /`
- `GET /{project_id}`
- `POST /{project_id}/rebuild-cache`
- `GET /{project_id}/routes`
- `GET /{project_id}/rule-hits`
- `GET /{project_id}/source-sink-hints`
- `GET /{project_id}/files`
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
- `GET /{task_id}/snapshot`
- `GET /{task_id}/events`
- `GET /{task_id}/events/stream`
- `GET /{task_id}/runs`
- `GET /{task_id}/runs/{run_id}`
- `POST /{task_id}/pause`
- `POST /{task_id}/resume`
- `POST /{task_id}/cancel`
- `POST /{task_id}/retry`
- `GET /{task_id}/stages`
- `GET /{task_id}/stages/{stage_num}`
- `GET /{task_id}/stages/{stage_num}/artifact`
- `GET /{task_id}/vulns`
- `DELETE /{task_id}`

说明：

- `snapshot` 返回前端审计详情页使用的稳定视图模型，包含阶段、漏洞、覆盖、事件、运行诊断和报告列表。
- `events` 支持 `after_id` 增量轮询，`events/stream` 提供 SSE 实时事件。
- `retry` 支持全量重跑或按 `stage_nums` 重跑指定阶段。
- `pause` / `resume` 为协作式暂停与恢复，已完成阶段不会被无故重置。

### 漏洞管理 `/api/vulnerabilities`

- `GET /`
- `GET /{vuln_id}`
- `PATCH /{vuln_id}`
- `DELETE /{vuln_id}`

### 报告管理 `/api/reports`

- `POST /export`
- `GET /download/{task_id}/{filename}`
- `GET /list/{task_id}`
- `DELETE /{task_id}/{filename}`

## 关键配置

配置位于 `backend/services/config.py`，支持环境变量和 `backend/.env` / 进程工作目录 `.env` 覆盖。环境变量前缀为 `CODE_SCAN_`。

| 配置 | 默认值 | 含义 |
|---|---:|---|
| `CODE_SCAN_ADMIN_USERNAME` | `admin` | 初始管理员用户名 |
| `CODE_SCAN_ADMIN_PASSWORD` | 空 | 初始管理员密码；为空时首启随机生成 |
| `CODE_SCAN_TOKEN_EXPIRE_HOURS` | `168` | 登录令牌有效小时数 |
| `CODE_SCAN_SECRET_KEY` | `change-me-in-production` | 服务端密钥，生产环境必须替换 |
| `CODE_SCAN_CORS_ORIGINS` | 本地开发地址 | 允许跨域来源，支持逗号分隔或 JSON 数组 |
| `CODE_SCAN_DB_URL` | 空 | 数据库连接；为空时使用 `backend/data/audit.db` |
| `CODE_SCAN_DATA_DIR` | 空 | 数据目录；为空时使用 `backend/data` |
| `CODE_SCAN_UPLOADS_DIR` | 空 | 上传目录；为空时使用 `backend/uploads` |
| `CODE_SCAN_REPORTS_DIR` | 空 | 报告目录；为空时使用 `backend/reports` |
| `CODE_SCAN_MAX_CONCURRENT_AGENTS` | `3` | 子 Agent 最大并发数 |
| `CODE_SCAN_WORKER_TASK_TIMEOUT_SECONDS` | `7200` | 单次审计任务超时时间 |
| `CODE_SCAN_LLM_TIMEOUT_SECONDS` | `180` | 单次 LLM 请求超时时间 |
| `CODE_SCAN_LLM_MAX_RETRIES` | `2` | 瞬时 LLM 错误额外重试次数 |
| `CODE_SCAN_INCREMENTAL_SUBMIT_STAGES` | 空 | 启用增量提交的阶段号，逗号分隔 |

## 测试与构建

后端测试：

```bash
python -m pytest backend/tests
```

前端测试：

```bash
cd frontend
npm run test:run
```

前端构建：

```bash
cd frontend
npm run build
```

## 仓库清理

仓库只提交源码、测试、依赖清单、文档和必要占位文件。本地运行数据、上传源码、导出报告、依赖缓存、构建产物、日志和本地环境配置不应提交。

已忽略的常见运行路径：

- `frontend/node_modules/`
- `frontend/dist/`
- `backend/data/audit.db`
- `backend/data/audit.db-*`
- `backend/data/audit.log`
- `backend/data/project_cache/`
- `backend/data/stage_artifacts/`
- `backend/services/data/project_cache/`
- `backend/uploads/`
- `backend/reports/`
- `test_logs/`
- `.env`
- `backend/.env`
- `frontend/.env`

保留的占位文件：

- `backend/data/.gitkeep`
- `backend/uploads/.gitkeep`
- `backend/reports/.gitkeep`
- `reports/.gitkeep`

## 注意事项

- Windows 下如果 `npm` 执行策略受限，请使用 `npm.cmd` 或项目启动脚本。
- LLM 配置、项目记录、审计任务和漏洞结果默认存储在本地 SQLite 数据库中。
- 大项目上传后会先做预扫描和缓存构建，首次分析可能需要几十秒。
- 多 Agent 模式默认最多 3 个子 Agent 并发调用 LLM，请确认模型服务端允许足够并发。
- Supervisor 规划或复核失败时，系统会尽量使用默认计划或保留已有结果继续收口，但这类降级会展示在质量提示中，建议人工复核。
