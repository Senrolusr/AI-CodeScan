# CodeScan — AI 代码安全审计平台

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Vue](https://img.shields.io/badge/Vue-3.5-4FC08D?logo=vue.js)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-8.0-646CFF?logo=vite)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

CodeScan 是一个基于大语言模型（LLM）的**多 Agent 协同代码安全审计平台**，采用前后端分离架构。用户上传项目源码 ZIP，系统自动解析项目结构、执行静态规则预筛，然后由 Supervisor 智能规划 → 子 Agent 并行审计 → Supervisor 审核，最终输出漏洞列表和 Markdown/PDF 安全审计报告。

## ✨ 核心特性

### 🧠 多 Agent 协同审计

采用 **Supervisor-Agent 架构**，四阶段流水线：

```
Phase 1: 架构 Agent 多轮扫描 → 识别技术栈、路由、数据流、认证机制
Phase 2: Supervisor 智能规划   → 基于静态证据决定运行哪些子 Agent，输出聚焦指导
Phase 3: 子 Agent 并行审计      → 最多 3 并发，跨 9 个安全领域深度审计
Phase 4: Supervisor 审核       → 审查覆盖缺口、误报、跨阶段攻击链，可选触发补充审计
```

### 📋 9 大审计阶段

| 阶段 | 名称 | 审计范围 |
|------|------|----------|
| Stage 1 | 架构理解与入口梳理 | 技术栈、路由、认证、数据流、入口点 |
| Stage 2 | RCE 与危险执行 | exec/eval、反序列化、模板注入、代码注入 |
| Stage 3 | 注入类漏洞 | SQL/NoSQL/命令/LDAP 注入 |
| Stage 4 | XSS 与输出编码 | 反射型/存储型/DOM 型 XSS |
| Stage 5 | 认证与会话安全 | JWT/Session/OAuth/CSRF/暴力破解 |
| Stage 6 | 授权与访问控制 | 水平/垂直越权、IDOR、权限提升 |
| Stage 7 | 配置与依赖安全 | 硬编码密钥、CORS、调试模式、危险依赖 |
| Stage 8 | 文件操作安全 | 任意上传/下载、路径遍历、Zip Slip |
| Stage 9 | 业务逻辑安全 | 竞态条件、状态机缺陷、金额篡改 |

### 🔬 静态代码预筛

- **400+ 关键词** 覆盖 7 大风险类别
- 注释和文档字符串自动过滤，减少无效命中
- 源-汇（source → sink）数据流线索识别
- 超大文件智能切片补偿（500KB/文件）
- 体量控制：500 文件上限 / 2M 总字符预算

### 📊 漏洞生命周期管理

- **置信度评分**：High（完整触发链）/ Medium（证据存在但不完整）/ Low（仅静态线索）
- **状态流转**：待处理 → 已确认 / 误报 / 已修复
- **跨任务去重**：基于 SHA256（title + type + file + endpoint + 行号）
- **POC 格式校验**：自动检测 raw HTTP 请求完整性
- **差异追踪**：区分新增问题与历史已存在（diff_status）

### 📄 报告导出

- Markdown 格式（可直接用于文档/PR）
- PDF 格式（WeasyPrint 优先，Pillow 降级，自动中文字体适配）

### 🌐 前端体验

- Vue 3 + Element Plus 组件库
- **中英双语**（i18n），自动检测浏览器语言
- **暗色模式**支持
- 文件树浏览 / 阶段进度可视化 / 调试信息面板

## 🏗 技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| 后端框架 | Python 3.11+ / FastAPI | 异步 Web 框架 |
| ORM | SQLAlchemy 2.0 (Async) | 异步数据库操作 |
| 数据库 | SQLite (WAL 模式) | 轻量级本地部署 |
| LLM 调用 | OpenAI Python SDK | 兼容 OpenAI API 格式 |
| 前端框架 | Vue 3 + Vite 8 | 组合式 API |
| UI 组件 | Element Plus 2.13 | 企业级 UI 组件库 |
| 状态管理 | Pinia 3.0 | Vue 官方状态管理 |
| 路由 | Vue Router 4.6 | SPA 路由 |
| PDF 生成 | WeasyPrint / Pillow | Markdown → PDF，含中文字体回退 |
| 数据校验 | Pydantic 2.10 | 请求/响应模型校验 |

## 📁 项目结构

```text
codescan/
├── backend/
│   ├── main.py                      # FastAPI 入口，CORS，静态文件挂载
│   ├── database.py                  # 数据库引擎，异步会话，自动迁移
│   ├── models.py                    # ORM 模型（Project/LlmConfig/AuditTask/AuditStage/Vulnerability）
│   ├── schemas.py                   # Pydantic 请求/响应模型
│   ├── routers/
│   │   ├── projects.py              # 项目管理（上传/详情/文件查看/缓存重建/删除）
│   │   ├── llm_configs.py           # 模型配置（CRUD/连通性测试/严格探测）
│   │   ├── audits.py                # 审计任务（创建/Phase执行/取消/重试/产物查看）
│   │   ├── vulnerabilities.py       # 漏洞管理（列表/详情/状态更新/删除）
│   │   └── reports.py               # 报告导出（MD/PDF）
│   ├── services/
│   │   ├── audit_engine.py          # 核心引擎（分块/提示构建/重试恢复/漏洞存储）
│   │   ├── supervisor.py            # Supervisor 编排器（Phase 1-4 流程控制）
│   │   ├── audit_worker.py          # 异步 Worker（队列轮询/任务领取/超时保护）
│   │   ├── llm_client.py            # LLM 调用客户端（支持 chat/completions 与 responses 模式）
│   │   ├── llm_pool.py              # LLM 连接池（按配置 ID 复用 AsyncOpenAI 实例）
│   │   ├── code_parser.py           # 源码解析、静态规则预筛、项目缓存管理
│   │   ├── report_generator.py      # Markdown/PDF 报告生成
│   │   └── config.py                # 运行时常量（并发数/超时/文件限制等）
│   ├── prompts/
│   │   ├── stage_prompts.py         # 9 阶段审计提示模板（含 System Prompt 与通用规则）
│   │   └── supervisor_prompts.py    # Supervisor 规划/审核提示模板
│   ├── scripts/                     # 调试/恢复脚本
│   └── data/                        # 运行时数据（audit.db/缓存/产物）
├── frontend/
│   ├── src/
│   │   ├── main.js                  # Vue 应用入口（组件注册/I18n/暗色模式）
│   │   ├── App.vue                  # 根组件（侧栏/导航/面包屑）
│   │   ├── router/index.js          # 路由配置（8 个页面）
│   │   ├── api/index.js             # Axios API 封装
│   │   ├── i18n.js                  # 中英双语（700+ 词条）
│   │   ├── composables/             # 组合式函数（轮询/主题切换）
│   │   ├── views/                   # 页面组件
│   │   │   ├── Dashboard.vue        # 仪表盘
│   │   │   ├── Projects.vue         # 项目列表
│   │   │   ├── ProjectDetail.vue    # 项目详情 + 审计
│   │   │   ├── LlmConfigs.vue       # 模型配置管理
│   │   │   ├── AuditDetail.vue      # 审计详情
│   │   │   ├── StageOneDetail.vue   # 阶段一扫描明细
│   │   │   ├── StageArtifactDetail.vue # 阶段产物详情
│   │   │   └── VulnDetail.vue       # 漏洞详情
│   │   └── components/              # 复用组件（FileTree/StageProgress/VulnCard）
│   ├── vite.config.js               # Vite 配置（代理/代码分包）
│   └── package.json
├── code_aduit.md                    # AI 审计任务框架文档（阶段划分与审计规范）
├── requestements.txt                # Python 依赖清单
├── .gitignore
└── README.md
```

## 🚀 快速开始

### 环境要求

- **Python** 3.11+
- **Node.js** 20+ / npm
- Windows / Linux / macOS

### 1. 安装依赖

```bash
# Python 后端依赖
pip install -r requestements.txt

# 前端依赖
cd frontend && npm install
```

### 2. 启动后端

```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

后端地址：`http://127.0.0.1:8000`，API 文档自动生成于 `/docs`

### 3. 启动前端

```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 3000
```

前端地址：`http://127.0.0.1:3000`（Vite 已配置 `/api` 代理到后端）

### PDF 导出（可选系统依赖）

PDF 通过 WeasyPrint 生成，如 WeasyPrint 不可用则自动降级为 Pillow 方案：

**Ubuntu/Debian**
```bash
apt install libpango-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev
```
**CentOS/RHEL**
```bash
yum install pango cairo gdk-pixbuf2 libffi
```
**Windows** — 通常安装 Python 包即可，建议安装中文字体（如微软雅黑）。

## 📡 API 模块

| 模块 | 前缀 | 主要端点 |
|------|------|----------|
| 项目管理 | `/api/projects` | `POST /upload` · `GET /` · `GET /{id}` · `GET /{id}/file` · `POST /{id}/rebuild-cache` · `DELETE /{id}` |
| 模型配置 | `/api/llm-configs` | `GET /` · `POST /` · `PUT /{id}` · `DELETE /{id}` · `POST /{id}/test` |
| 审计任务 | `/api/audits` | `POST /` · `GET /` · `GET /{id}` · `POST /{id}/run-phase` · `POST /{id}/cancel` · `POST /{id}/retry` · `GET /{id}/stages` · `GET /{id}/stages/{n}/artifact` · `DELETE /{id}` |
| 漏洞管理 | `/api/vulnerabilities` | `GET /` · `GET /{id}` · `PATCH /{id}` · `DELETE /{id}` |
| 报告导出 | `/api/reports` | `POST /export` · `GET /download/{filename}` · `DELETE /download/{filename}` |
| 统计数据 | `/api/stats` | `GET /` — 项目/审计/漏洞/高危计数 |

## 📋 使用流程

1. 启动后端和前端
2. 进入 **模型配置** 页面，添加 LLM 连接（支持 OpenAI 兼容 API），测试连通性
3. 进入 **项目** 页面，上传源码 ZIP（自动解压、解析、静态预筛）
4. 在项目详情页点击 **开始代码审计**，选择多 Agent 协同模式
5. 按 **Phase 1-4** 逐步执行，每步可检查中间结果：
   - Phase 1: 架构分析 → 检查路由、技术栈识别是否正确
   - Phase 2: Supervisor 规划 → 查看哪些 Agent 被选中/跳过
   - Phase 3: 并行审计 → 观察各子 Agent 执行进度
   - Phase 4: Supervisor 审核 → 查看审核结论，确认是否有补充审计
6. 在审计详情页查看阶段结果、漏洞详情、Token 用量、代码覆盖率
7. 对漏洞进行**确认 / 误报 / 已修复**状态更新
8. 导出 **Markdown** 或 **PDF** 报告

## ⚙ 配置说明

关键参数见 `backend/services/config.py`：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `MAX_CONCURRENT_AGENTS` | 3 | 子 Agent 最大并发数 |
| `WORKER_TASK_TIMEOUT_SECONDS` | 3600 | 单个审计任务超时（1 小时） |
| `WORKER_POLL_INTERVAL_SECONDS` | 2 | Worker 轮询间隔 |
| `MAX_FILE_SIZE` | 500KB | 单文件大小上限 |
| `MAX_FILES` | 500 | 单项目最多解析文件数 |
| `TOTAL_CHARS_LIMIT` | 2,000,000 | 总字符预算 |

## ⚠️ 注意事项

- Windows 下如遇 npm 执行策略限制，请使用 `npm.cmd` 替代 `npm`
- 默认数据库为 SQLite（WAL 模式），文件位于 `backend/data/audit.db`
- 多 Agent 模式最多 3 个子 Agent 并发调用 LLM，请确保 API Key 的并发限制足够（建议 ≥ 3）
- 审计 Worker 内置 1 小时超时保护，超大项目可能需分批审计
- 项目上传后自动执行静态规则预筛和代码缓存，大型项目可能需要几秒到几十秒
- PDF 导出依赖 WeasyPrint / Pillow，如中文乱码请安装中文字体
- 前端 Vite 开发服务器默认代理 `/api` 到 `http://127.0.0.1:8000`

## 🤝 贡献

欢迎提交 Issue 和 Pull Request。

## 📄 许可

[MIT](LICENSE)
