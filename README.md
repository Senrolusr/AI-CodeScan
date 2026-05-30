# CodeScan - AI 代码安全审计平台

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Vue](https://img.shields.io/badge/Vue-3.5-4FC08D?logo=vue.js)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-8.0-646CFF?logo=vite)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

CodeScan 是一个基于大语言模型的多 Agent 代码安全审计平台，采用前后端分离架构。用户上传源码 ZIP 后，系统会先做项目解析、静态规则预筛和缓存构建，再自动进入完整审计流程，最终输出漏洞列表以及 Markdown/PDF 报告。

## 核心能力

- 自动审计：点击“开始审计”后自动完成全流程，不需要再手动执行下一阶段
- 多 Agent 协同：Supervisor 负责规划与复核，子 Agent 按安全领域并行审计
- 分阶段可视化：可查看 Phase 进度、阶段产物、调试信息、漏洞统计
- 路由与架构提取：自动识别技术栈、入口点、路由、认证边界和关键数据流
- 漏洞生命周期管理：支持确认、误报、已修复、验证状态和跨任务去重
- 报告导出：支持 Markdown 和 PDF

## 审计流程

平台内部仍按四个 Phase 执行，但已经改为自动串行执行：

1. Phase 1: 架构分析
   识别技术栈、路由、认证机制、模块边界和高价值审计范围。
2. Phase 2: Supervisor 规划
   基于静态证据决定运行哪些子 Agent，并给出聚焦文件、函数、路由。
3. Phase 3: 子 Agent 并行审计
   按 9 个安全方向执行深度审计，默认最多 3 个子 Agent 并发。
4. Phase 4: Supervisor 复核
   汇总结果、审查覆盖缺口、处理补充审计建议并生成最终结论。

## 9 个审计阶段

| Stage | 名称 | 审计范围 |
|---|---|---|
| 1 | 架构理解与入口梳理 | 技术栈、路由、认证、数据流、入口点 |
| 2 | RCE 与危险执行 | `exec` / `eval` / 反序列化 / 模板注入 / 代码执行 |
| 3 | 注入类漏洞 | SQL / NoSQL / 命令 / LDAP 注入 |
| 4 | XSS 与输出编码 | 反射型 / 存储型 / DOM 型 XSS |
| 5 | 认证与会话安全 | JWT / Session / OAuth / CSRF / 暴力破解 |
| 6 | 授权与访问控制 | 水平越权 / 垂直越权 / IDOR / 权限绕过 |
| 7 | 配置与依赖安全 | 硬编码密钥 / CORS / 调试模式 / 危险依赖 |
| 8 | 文件操作安全 | 任意上传 / 下载 / 路径遍历 / Zip Slip |
| 9 | 业务逻辑安全 | 状态机缺陷 / 竞态 / 金额或流程滥用 |

## 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Python 3.11+, FastAPI, SQLAlchemy Async, SQLite |
| 前端 | Vue 3, Vite 8, Element Plus, Pinia, Vue Router |
| LLM | OpenAI 兼容 API |
| 报告 | Markdown, WeasyPrint, Pillow |

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
│   │   ├── config.py
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

### 方式一：Windows 一键启动

仓库根目录提供了启动脚本：

- `start-platform.ps1`
- `start-platform.bat`

PowerShell 用法：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1
```

脚本会：

- 检查 `python` 和 `npm.cmd`
- 在依赖缺失时自动安装后端和前端依赖
- 分别启动后端 `http://127.0.0.1:8000`
- 分别启动前端 `http://127.0.0.1:3000`

预演模式：

```powershell
powershell -ExecutionPolicy Bypass -File .\start-platform.ps1 -DryRun
```

### 方式二：手动启动

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

## 仓库清理状态

仓库只保留源码、依赖清单和必要占位文件，不提交本地依赖、构建产物、数据库、日志、上传源码或导出报告。首次运行或拉取到新环境后需要重新安装依赖。

已忽略的运行时目录和文件包括：

- `frontend/node_modules/`
- `frontend/dist/`
- `backend/data/audit.db`
- `backend/data/audit.log`
- `backend/data/project_cache/`
- `backend/data/stage_artifacts/`
- `backend/uploads/`
- `backend/reports/`

如需清空本地运行数据，可删除以上目录或文件；应用启动时会自动创建必要目录和 SQLite 数据库。

## 使用流程

1. 启动前后端
2. 进入“模型配置”页面，添加 LLM 配置并测试连通性
3. 进入“项目”页面，上传源码 ZIP
4. 打开项目详情，点击“开始审计”
5. 审计任务会自动进入完整流程，无需手动推进 Phase
6. 在审计详情页查看：
   - Phase 进度
   - Stage 1 架构明细
   - 各阶段漏洞结果
   - Token 用量、规则命中、覆盖摘要
7. 对漏洞执行状态更新：待处理、已确认、误报、已修复
8. 导出 Markdown 或 PDF 报告

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

- 创建审计任务后会自动入队并执行完整流程
- 不再提供手动“执行下一阶段”的接口

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

配置位于 `backend/services/config.py`。

| 参数 | 默认值 | 含义 |
|---|---:|---|
| `MAX_CONCURRENT_AGENTS` | 3 | 子 Agent 最大并发数 |
| `WORKER_TASK_TIMEOUT_SECONDS` | 3600 | 单次审计任务超时时间 |
| `WORKER_POLL_INTERVAL_SECONDS` | 2.0 | Worker 轮询间隔 |
| `MAX_FILE_SIZE` | 500KB | 单个源码文件大小上限 |
| `MAX_TREE_FILES` | 10,000 | 单项目最多索引源码/配置文件数 |
| `MAX_AUDIT_SOURCE_FILES` | 1,200 | 进入审计切片的高优先级文件上限 |
| `MAX_CODE_CHUNKS` | 2,000 | 缓存给阶段选择器使用的代码块上限 |
| `TOTAL_CHARS_LIMIT` | 2,000,000 | 总字符预算 |

## PDF 导出依赖

PDF 优先通过 WeasyPrint 生成，失败时回退到 Pillow。

Ubuntu / Debian:

```bash
apt install libpango-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev
```

CentOS / RHEL:

```bash
yum install pango cairo gdk-pixbuf2 libffi
```

Windows:

- 通常安装 Python 包即可
- 如需更稳定的中文渲染，建议安装中文字体，例如微软雅黑

## 注意事项

- Windows 下如果 `npm` 执行策略受限，请使用 `npm.cmd`
- 默认数据库为 SQLite，位于 `backend/data/audit.db`
- LLM 配置、项目记录、审计任务和漏洞状态存储在本地 SQLite 数据库中；清理 `backend/data/audit.db` 会重置这些配置数据
- 大项目上传后会先做预扫描和缓存构建，首次分析可能需要几十秒
- 多 Agent 模式默认最多 3 个子 Agent 并发调用 LLM，请确保模型服务端允许足够并发
- 审计 Worker 内置超时保护，超大项目建议分批审计

## 许可证

[MIT](LICENSE)
