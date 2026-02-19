# 后端架构总览

## 1. 技术选型

| 组件 | 技术 | 选型理由 |
|------|------|----------|
| Web 框架 | **FastAPI** (async) | 原生 async/await，自动 OpenAPI 文档，Pydantic 校验开箱即用 |
| 数据库 | **SQLAlchemy 2.0** (ORM + Core 混用) + asyncpg | 简单 CRUD 用 ORM，复杂查询用 Core 显式编写，asyncpg 是目前最快的 PostgreSQL async 驱动 |
| 数据库迁移 | **Alembic** | SQLAlchemy 官方迁移工具，支持自动生成和手动编辑 |
| 认证 | **PyJWT** + **bcrypt** | JWT 无状态认证，bcrypt 密码哈希，轻量且安全 |
| 任务调度 | **APScheduler** | 进程内调度器，支持 cron / interval 触发，无需额外基础设施 |

**不引入的技术（及原因）：**
- Celery / Redis — 当前规模不需要分布式任务队列，APScheduler 进程内调度足够
- GraphQL — 前端数据需求已明确，REST cursor 分页更简单直接

---

## 2. 项目结构

`vulnsentinel/` 作为独立顶层 Python 包，与 `z_code_analyzer/` 平级：

```
vulnsentinel/
├── core/                   # 基础设施层
│   ├── config.py           # Pydantic Settings，读取 .env
│   ├── database.py         # async engine / session factory
│   ├── auth.py             # JWT 签发 / 验证，密码哈希
│   └── dependencies.py     # FastAPI 依赖注入（get_db, get_current_user）
│
├── models/                 # SQLAlchemy 表定义（declarative base，仅做结构映射）
│   ├── user.py
│   ├── library.py
│   ├── project.py
│   ├── project_dependency.py
│   ├── snapshot.py
│   ├── event.py
│   ├── upstream_vuln.py
│   └── client_vuln.py
│
├── dao/                    # 数据访问层（SQLAlchemy Core 查询）
│   ├── base.py             # 通用 CRUD + cursor 分页
│   ├── user_dao.py
│   ├── library_dao.py
│   ├── project_dao.py
│   ├── project_dependency_dao.py
│   ├── snapshot_dao.py
│   ├── event_dao.py
│   ├── upstream_vuln_dao.py
│   └── client_vuln_dao.py
│
├── schemas/                # Pydantic request / response schemas
│   ├── auth.py
│   ├── library.py
│   ├── project.py
│   ├── event.py
│   ├── upstream_vuln.py
│   ├── client_vuln.py
│   └── pagination.py       # CursorPage[T] 通用分页响应
│
├── services/               # 业务逻辑层
│   ├── auth_service.py
│   ├── library_service.py
│   ├── project_service.py
│   ├── snapshot_service.py  # 构建调度、查询、激活
│   ├── event_service.py
│   ├── upstream_vuln_service.py
│   ├── client_vuln_service.py
│   └── stats_service.py    # 主页统计卡片聚合
│
├── api/                    # FastAPI 路由
│   ├── router.py           # 汇总所有子路由
│   ├── auth.py             # POST /login, POST /refresh
│   ├── libraries.py        # /api/libraries
│   ├── projects.py         # /api/projects
│   ├── events.py           # /api/events
│   ├── upstream_vulns.py   # /api/upstream-vulns
│   ├── client_vulns.py     # /api/client-vulns
│   └── stats.py            # /api/stats
│
├── engines/                # 后台引擎（由调度器触发，每个引擎可为子包）
│   ├── scheduler.py        # APScheduler 配置与引擎注册
│   ├── monitor/            # 依赖库监控（轮询 commit / PR / tag）
│   │   ├── __init__.py
│   │   ├── engine.py       # 引擎入口
│   │   ├── github.py       # GitHub API 适配
│   │   └── gitlab.py       # GitLab API 适配
│   ├── classifier/         # LLM 分类（is_bugfix 判定）
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   └── prompts.py      # prompt 模板
│   ├── analyzer/           # 漏洞分析（upstream_vuln 创建与 AI 分析）
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── prompts.py
│   │   └── poc_collector.py # 上游 PoC 收集（oss-fuzz 等）
│   └── impact/             # 客户影响评估（path_searching → poc_generating）
│       ├── __init__.py
│       ├── engine.py
│       ├── version_check.py # 版本比对逻辑
│       ├── path_search.py   # 调用图可达性分析（对接 z_code_analyzer）
│       └── poc_gen.py       # PoC 生成（对接 FuzzingBrain）
│
├── main.py                 # FastAPI app 入口，lifespan 管理
└── alembic/                # 数据库迁移
    ├── alembic.ini
    └── versions/
```

### 分层职责

| 层 | 职责 | 规则 |
|----|------|------|
| **core** | 配置、数据库连接、安全工具、依赖注入 | 不依赖任何业务层 |
| **models** | 表结构映射，1:1 对应 schema.sql 的 8 张表 | declarative base 定义 Column / Type / Index，不使用 relationship |
| **dao** | 数据访问层，ORM + Core 混用 | 简单 CRUD 用 ORM（`session.get()` / `session.add()`），复杂查询用 Core（`select()` / `join()` / `func.count()`） |
| **schemas** | 请求校验与响应序列化 | 纯 Pydantic 模型，不依赖 ORM |
| **services** | 业务编排，调用一到多个 dao 完成一次业务操作 | 事务边界在此层管理 |
| **api** | HTTP 路由，参数解析，调用 service，返回 schema | 薄层，不含业务逻辑 |
| **engines** | 后台定时任务，独立于 API 请求生命周期 | 通过 service 层操作数据 |

**调用方向：** `api → services → dao → models`，`engines → services → dao → models`。禁止反向依赖或跨层调用（如 api 直接调 dao）。

---

## 3. 核心场景

以下按数据流梳理后端在每个业务场景中的角色，对应十步流程的 step 3–10。

### 3.1 客户接入（Step 1–3）

```
POST /api/projects { repo_url, name, ... }
        │
        ▼
  ProjectService.create()
        │
        ├── 1. 写入 projects 表
        ├── 2. 调用依赖提取（解析 conanfile.txt / CMakeLists.txt 等）
        │       → 对每个发现的库：
        │         ├── libraries 表 upsert（如果该库是首次出现）
        │         └── project_dependencies 表 insert
        └── 3. 创建 snapshot 记录（等待引擎接管）
                → snapshots 表 insert (status=building, trigger_type=manual)
                → ImpactEngine 下次轮询时发现 building 状态，调度 z_code_analyzer 构建调用图
```

**关键表：** `projects` → `libraries`（upsert） → `project_dependencies` → `snapshots`

### 3.2 依赖监控（Step 4–5）

```
MonitorEngine (定时触发，interval)
        │
        ▼
  遍历 libraries 表中所有被监控的库
        │
        ▼
  对每个库，轮询 GitHub/GitLab API：
    - 新 commit（自 latest_commit_sha 之后）
    - 新 PR merge
    - 新 tag（自 latest_tag_version 之后）
    - 新 bug issue
        │
        ▼
  写入 events 表（classification=NULL, is_bugfix=FALSE）
  更新 libraries.latest_commit_sha / latest_tag_version / last_activity_at
```

**关键表：** `libraries`（读 + 更新指针） → `events`（写入，classification=NULL）

### 3.3 LLM 分类（Step 6）

```
ClassifierEngine (定时触发，interval)
        │
        ▼
  查询：events WHERE classification IS NULL
  （使用 idx_events_unclassified 索引）
        │
        ▼
  对每个未分类事件：
    1. 从 GitHub 拉取 diff
    2. 构造 prompt，调用 LLM
    3. 解析 LLM 响应 → (classification, confidence)
        │
        ▼
  更新 events 表：
    - classification = 'security_bugfix' | 'normal_bugfix' | ...
    - confidence = 0.0~1.0
    - is_bugfix = (classification == 'security_bugfix')
```

**关键表：** `events`（读未分类 → 更新分类结果）

### 3.4 漏洞分析（Step 7）

```
AnalyzerEngine (定时触发，interval)
        │
        ▼
  查询：events WHERE is_bugfix = TRUE
         AND NOT EXISTS (SELECT 1 FROM upstream_vulns WHERE event_id = events.id)
  （尚未创建 upstream_vuln 的安全修复事件）
        │
        ▼
  对每个事件：
    1. 创建 upstream_vulns 记录 (status=analyzing)
    2. AI 分析漏洞详情：
       - vuln_type（CWE 编号 + 名称）
       - severity（critical / high / medium / low）
       - affected_versions
       - summary / reasoning
    3. 收集上游 PoC（如 oss-fuzz reproducer）→ upstream_poc (JSONB)
    4. 更新 status → published, 设置 published_at
        │
        ▼
  ImpactEngine 下次轮询时发现 published 状态，自动启动 3.5 客户影响评估
```

**关键表：** `events`（读 is_bugfix=TRUE） → `upstream_vulns`（创建 + 更新）

### 3.5 客户影响评估（Step 8–10）

```
ImpactEngine (由 AnalyzerEngine 发布触发，或定时轮询 pending pipeline)
        │
        ▼
  upstream_vuln 发布后：
    查询 project_dependencies WHERE library_id = vuln.library_id
    → 获取所有使用该库的项目
        │
        ▼
  对每个潜在受影响项目：
    1. 创建 client_vulns 记录 (pipeline_status=pending)
    2. 版本比对：resolved_version vs affected_versions
       → 如果明确不受影响 → pipeline_status=not_affect, 结束
        │
        ▼
    3. pipeline_status → path_searching
       调用 z_code_analyzer / Neo4j 搜索调用图
       → 找到可达路径 → reachable_path (JSONB)
       → 未找到 → pipeline_status=not_affect, 结束
        │
        ▼
    4. pipeline_status → poc_generating
       调用 FuzzingBrain 生成 PoC
       → 成功 → poc_results (JSONB)
        │
        ▼
    5. pipeline_status → verified
       设置 status=recorded, is_affected=TRUE
       记录 recorded_at, analysis_completed_at
```

**Pipeline 状态机：**

```
pending → path_searching → poc_generating → verified
   │            │                │
   └────────────┴────────────────┘
         任一阶段判定不受影响：
         → not_affect (status=not_affect, is_affected=FALSE)
```

**关键表：** `project_dependencies`（查关联项目） → `client_vulns`（创建 + pipeline 推进） → `snapshots`（定位活跃快照供分析使用）

### 3.6 前端查询（贯穿所有步骤）

```
前端 → GET /api/xxx?cursor=...&page_size=20&filters...
        │
        ▼
  AuthMiddleware: 验证 JWT
        │
        ▼
  API 层: 解析参数 → 调用 Service
        │
        ▼
  Service 层: 调用 DAO 查询 + 聚合
        │
        ▼
  DAO 层: SQLAlchemy Core 分页查询，联表聚合
        │
        ▼
  返回 CursorPage[T]:
  {
    "data": [...],
    "next_cursor": "...",
    "has_more": true,
    "total": 8731
  }
```

各页面对应的核心查询：

| 页面 | 主表 | 关联 | 聚合 |
|------|------|------|------|
| 主页统计卡片 | `client_vulns` | — | COUNT by status（向前包含） |
| Monitored Libraries | `libraries` | `project_dependencies` → `projects` | used_by 列表 |
| Recent Activity | `events` | `libraries` | — |
| 项目列表 | `projects` | `project_dependencies`, `client_vulns` | deps_count, vuln_count |
| 漏洞列表 | `client_vulns` | `upstream_vulns` → `libraries`, `projects` | 统计摘要（向前包含计数） |
| 库详情 | `libraries` | `upstream_vulns`, `events`, `project_dependencies` | — |
| 项目详情 | `projects` | `client_vulns`, `project_dependencies`, `snapshots` | 统计摘要 |
| 事件详情 | `events` | `upstream_vulns` → `client_vulns` | — |
| 上游漏洞详情 | `upstream_vulns` | `client_vulns` → `projects` | — |
| 客户漏洞详情 | `client_vulns` | `upstream_vulns`, `projects` | — |

---

## 4. 认证方案

### 基本设计

- 全站强制认证，未登录请求一律返回 `401 Unauthorized`
- 当前版本：**单用户**，凭证通过 `.env` 配置
- 密码存储：服务启动时将 `.env` 中的明文密码用 bcrypt 哈希后写入 `users` 表（如果不存在）

```
# .env
VULNSENTINEL_USERNAME=admin
VULNSENTINEL_PASSWORD=<强密码>
VULNSENTINEL_JWT_SECRET=<随机生成的 256-bit 密钥>
VULNSENTINEL_JWT_EXPIRE_MINUTES=30
VULNSENTINEL_JWT_REFRESH_EXPIRE_DAYS=7
```

### Token 流程

```
POST /api/auth/login  { username, password }
  → 验证密码（bcrypt.checkpw）
  → 签发 access_token (exp=30min) + refresh_token (exp=7d)
  → 返回 { access_token, refresh_token, token_type: "bearer" }

POST /api/auth/refresh  { refresh_token }
  → 验证 refresh_token 有效性
  → 签发新的 access_token (exp=30min)
  → 返回 { access_token, token_type: "bearer" }
```

### Token 刷新策略

- **access_token**：短生命周期（30 分钟），携带于 `Authorization: Bearer <token>` header
- **refresh_token**：长生命周期（7 天），仅用于换取新 access_token
- 前端在 access_token 过期前（或收到 401 后）自动调用 `/api/auth/refresh`
- refresh_token 过期后需重新登录
- JWT payload 包含：`sub`（user_id）、`role`、`exp`、`iat`、`type`（access / refresh）

---

## 5. 分页方案

### 设计原则

所有列表接口统一使用 **cursor-based pagination**，禁止 `OFFSET`。

`OFFSET` 在数据量大时会全表扫描，页数越深越慢；cursor 基于索引列做范围查询，性能恒定。

### 游标编码

游标基于 `(created_at, id)` 复合排序（与数据库索引一致）：

```python
# 编码：将 (created_at, id) 打包为 base64 字符串
cursor = base64url_encode(f"{created_at.isoformat()}|{id}")

# 解码：从 cursor 还原 (created_at, id)
created_at, id = base64url_decode(cursor).split("|")
```

### SQL 查询模式

```sql
-- 首页（无 cursor）
SELECT * FROM events
WHERE library_id = :lib_id        -- 可选过滤
ORDER BY created_at DESC, id DESC
LIMIT :page_size + 1;             -- 多取一条判断 has_more

-- 翻页（有 cursor）
SELECT * FROM events
WHERE library_id = :lib_id
  AND (created_at, id) < (:cursor_created_at, :cursor_id)
ORDER BY created_at DESC, id DESC
LIMIT :page_size + 1;
```

### 响应格式

```json
{
  "data": [ ... ],
  "next_cursor": "MjAyNS0wMS0xNVQxMDozMDowMHxldnRfMTAwNDI=",
  "has_more": true,
  "total": 8731
}
```

| 字段 | 说明 |
|------|------|
| `data` | 当前页数据（最多 page_size 条） |
| `next_cursor` | 下一页游标，前端透传即可；最后一页为 `null` |
| `has_more` | 是否还有下一页 |
| `total` | 总记录数，使用缓存 COUNT（定时刷新，非实时） |

### page_size 限制

允许值：20（默认）、50、100。超出范围返回 `422`。

### total 缓存策略

`total` 不在每次查询时执行 `COUNT(*)`（大表代价高），而是：

1. 每个列表接口的 total 按过滤条件组合缓存（内存字典，key = 接口 + 过滤条件 hash）
2. 缓存 TTL = 60 秒
3. 首次请求或缓存失效时执行一次 `COUNT(*)`，后续请求直接返回缓存值
4. 数据写入时主动失效对应缓存

---

## 6. 引擎编排

### 架构概览

四个引擎作为后台任务运行在 FastAPI 进程内，由 APScheduler 调度：

```
FastAPI lifespan startup
        │
        ▼
  APScheduler 启动
        │
        ├── MonitorEngine     (interval: 5min)
        ├── ClassifierEngine  (interval: 2min)
        ├── AnalyzerEngine    (interval: 2min)
        └── ImpactEngine      (interval: 1min)
```

### 引擎职责与触发方式

| 引擎 | 触发方式 | 轮询条件 | 处理逻辑 |
|------|----------|----------|----------|
| **MonitorEngine** | interval 5min | `libraries` 全表 | 对每个库轮询 GitHub API，写入新 events |
| **ClassifierEngine** | interval 2min | `events WHERE classification IS NULL` | 拉 diff → LLM 分类 → 更新 events |
| **AnalyzerEngine** | interval 2min | `events WHERE is_bugfix AND no upstream_vuln` | AI 分析 → 创建/更新 upstream_vulns |
| **ImpactEngine** | interval 1min | `client_vulns WHERE pipeline_status IN (pending, path_searching, poc_generating)` | 推进 pipeline 状态机 |

### 同步 vs 异步

| 操作 | 执行方式 | 说明 |
|------|----------|------|
| 数据库读写 | async (asyncpg) | 所有 dao 方法均为 async |
| GitHub API 调用 | async (httpx) | MonitorEngine 批量轮询时并发请求 |
| LLM API 调用 | async (httpx) | ClassifierEngine / AnalyzerEngine |
| z_code_analyzer 调用 | sync → run_in_executor | 静态分析工具为同步代码，包装到线程池执行 |
| FuzzingBrain 调用 | sync → run_in_executor | PoC 生成为同步代码，包装到线程池执行 |

### 并发控制

- 每个引擎实例持有一个 `asyncio.Lock`，防止同一引擎的两次调度重叠执行
- 引擎内部使用 `asyncio.Semaphore` 限制并发数：
  - MonitorEngine：最多 10 个库并发轮询
  - ClassifierEngine：最多 5 个事件并发分类（受 LLM API rate limit 约束）
  - AnalyzerEngine：最多 3 个漏洞并发分析
  - ImpactEngine：最多 5 个 pipeline 并发推进

### 错误处理与重试

```
引擎执行某条记录
        │
        ├── 成功 → 更新状态，继续下一条
        │
        └── 失败
             │
             ├── 可重试错误（网络超时、API 限流、临时故障）
             │     → 记录 warning 日志
             │     → 不更新记录状态，下次轮询自动重试
             │
             └── 不可重试错误（LLM 返回无法解析、分析逻辑异常）
                   → 记录 error 日志
                   → 写入 error_message 字段（events 无此字段则跳过）
                   → upstream_vulns: error_message 记录错误
                   → client_vulns: error_message 记录错误，pipeline 暂停
                   → 需人工介入处理
```

**重试策略要点：**

- 不使用显式重试计数器 — 依赖轮询机制天然重试（每次调度都会捞出未完成的记录）
- GitHub API 429 → 读取 `Retry-After` header，引擎整体暂停对应时间
- LLM API 限流 → 指数退避，单次引擎执行内最多重试 3 次
- 任何引擎 crash → APScheduler 下次调度照常触发，不影响其他引擎
