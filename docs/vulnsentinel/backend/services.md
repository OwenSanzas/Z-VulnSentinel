# Service 层设计

> 业务逻辑层，编排 DAO 调用，执行业务规则。Service 是 API 层和 Engine 层的共享底层，两者通过 Service 操作数据库，不直接调用 DAO。

## 设计约定

### 事务管理

- 每个 service 方法接收 `AsyncSession` 作为第一个参数
- **事务由调用方管理**（API 的依赖注入中间件 / Engine 的调度器），Service 不创建、不提交、不回滚事务
- 一个 API 请求 = 一个事务 = 一个 session，覆盖该请求中所有 service 调用
- Engine 每次轮询 = 一个事务，覆盖该轮询中的批量操作

### DAO 与 Service 的职责边界

| 职责 | 归属 | 示例 |
|------|------|------|
| SQL 查询构建 | DAO | WHERE / JOIN / ORDER BY / LIMIT |
| 数据写入 | DAO | INSERT / UPDATE / ON CONFLICT |
| 业务规则校验 | **Service** | 状态流转合法性、is_bugfix 计算 |
| 多 DAO 编排 | **Service** | ProjectService.create 涉及 4 张表 |
| ORM Model → Pydantic Schema | **Service** | DAO 返回 Model，Service 转换后返回 Schema |
| 404 / 422 业务异常 | **Service** | get_by_id 为 None → 抛 NotFoundError |
| display name 补充 | **Service** | 列表中补充 library_name、project_name |
| 过滤 JOIN | DAO | ClientVuln 按 severity 过滤时 JOIN upstream_vulns |

### Service 间依赖

```
StatsService ──→ ClientVulnService, ProjectDAO
ProjectService ──→ LibraryService
其余 6 个 Service ──→ 无 service 依赖
```

> 无循环依赖。ProjectService 是依赖最多的 service（客户接入涉及多表操作），但它只单向依赖 LibraryService。

### 异常体系

```python
class ServiceError(Exception):
    """Base service exception."""

class NotFoundError(ServiceError):
    """Resource not found (→ HTTP 404)."""

class ConflictError(ServiceError):
    """Business rule conflict (→ HTTP 409)."""

class ValidationError(ServiceError):
    """Input validation or state transition error (→ HTTP 422)."""

class AuthenticationError(ServiceError):
    """Authentication failure (→ HTTP 401)."""
```

API 层捕获 ServiceError 子类，映射到对应 HTTP 状态码。Engine 层捕获后记录日志或写入 error_message 字段。

### 实例化

Service 为无状态类，每个 Service 在构造时接收依赖的 DAO 实例（依赖注入）：

```python
class EventService:
    def __init__(self, event_dao: EventDAO, upstream_vuln_dao: UpstreamVulnDAO):
        self._event_dao = event_dao
        self._upstream_vuln_dao = upstream_vuln_dao
```

应用启动时创建单例，注入到 API 路由和 Engine 调度器中。

---

## 1. AuthService

**依赖 DAO：** UserDAO

### 方法

| 方法 | 签名 | 说明 |
|------|------|------|
| `ensure_admin_exists` | `(session) → None` | 启动时确保 admin 用户存在，不存在则用环境变量创建 |
| `login` | `(session, username: str, password: str) → TokenPair` | 验证密码，签发 access_token + refresh_token |
| `refresh` | `(refresh_token: str) → AccessToken` | 验证 refresh_token，签发新 access_token |
| `get_current_user` | `(session, token: str) → User` | 解码 JWT，查询用户（FastAPI 依赖注入） |

### 业务逻辑

**ensure_admin_exists:**

```
读取环境变量: VULNSENTINEL_ADMIN_USERNAME, VULNSENTINEL_ADMIN_EMAIL, VULNSENTINEL_ADMIN_PASSWORD
  → 任一缺失 → 跳过（非强制）
  → bcrypt.hash(password)
  → UserDAO.upsert(username, email, password_hash, role='admin')
  → 已存在 → 静默返回（ON CONFLICT DO NOTHING）
```

**login:**

```
UserDAO.get_by_username(username)
  → 不存在 → AuthenticationError("invalid credentials")
  → bcrypt.checkpw(password, user.password_hash)
  → 不匹配 → AuthenticationError("invalid credentials")
  → 签发 access_token:
      payload = { sub: str(user.id), type: "access" }
      exp = now + 30min
  → 签发 refresh_token:
      payload = { sub: str(user.id), type: "refresh" }
      exp = now + 7d
  → 返回 TokenPair { access_token, refresh_token, token_type: "bearer" }
```

> 安全要点：登录失败不区分"用户不存在"和"密码错误"，统一返回 "invalid credentials"。

**refresh:**

```
解码 refresh_token (验证签名 + 过期时间)
  → 无效或过期 → AuthenticationError("invalid refresh token")
  → payload.type != "refresh" → AuthenticationError("invalid token type")
  → 签发新 access_token (exp=30min, sub=payload.sub)
  → 返回 AccessToken { access_token, token_type: "bearer" }
```

> refresh 不查数据库。如需支持 token 吊销，后续可加 Redis blacklist。

**get_current_user:**

```
解码 access_token
  → 无效或过期 → AuthenticationError
  → payload.type != "access" → AuthenticationError
  → UserDAO.get_by_id(UUID(payload.sub))
  → 不存在 → AuthenticationError("user not found")
  → 返回 User
```

### JWT 配置

| 参数 | 值 | 来源 |
|------|-----|------|
| 算法 | HS256 | 固定 |
| 密钥 | `VULNSENTINEL_JWT_SECRET` | 环境变量，必须配置 |
| access_token 有效期 | 30 分钟 | 可配置 |
| refresh_token 有效期 | 7 天 | 可配置 |

---

## 2. LibraryService

**依赖 DAO：** LibraryDAO, ProjectDAO, ProjectDependencyDAO, EventDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id: UUID) → LibraryDetailSchema` | 库详情（含 used_by、event 计数） | API |
| `list` | `(session, cursor?: str, page_size?: int) → CursorPage[LibraryListSchema]` | 库列表 | API |
| `count` | `(session) → int` | 库总数 | API |
| `upsert` | `(session, *, name, repo_url, platform?, default_branch?) → Library` | 幂等入库（客户接入） | ProjectService |

### 业务逻辑

**get:**

```
LibraryDAO.get_by_id(id)
  → None → NotFoundError("library not found")
  → ProjectDependencyDAO.list_by_library(library.id)
     → 组装 used_by: [{ project_id, constraint_expr, resolved_version, constraint_source }]
  → EventDAO.count(library_id=library.id)
     → events_tracked
  → 返回 LibraryDetailSchema
```

> used_by 中的 project_name 需要查 projects 表。v1 通过循环 `ProjectDAO.get_by_id` 获取；v2 优化为批量查询。

**list:**

```
LibraryDAO.list_paginated(cursor, page_size)
LibraryDAO.count()
  → 返回 CursorPage[LibraryListSchema]（total 由独立 count 查询提供）
```

> v1 列表不含 used_by，保持简洁。详情页才展示 used_by。

**upsert:**

```
LibraryDAO.upsert_by_name(name, repo_url, platform, default_branch)
  → 新插入 → 返回新 Library
  → 已存在且 repo_url 一致 → 返回已有 Library
  → 已存在但 repo_url 不一致 → 抛 LibraryConflictError（同名异 repo，防止 fork 覆盖）
```

> `repo_url` 不设 UNIQUE 约束（monorepo 场景：一个 repo 可出多个库），去重仅靠 `name` UNIQUE。

---

## 3. ProjectService

**依赖 DAO：** ProjectDAO, ProjectDependencyDAO, ClientVulnDAO
**依赖 Service：** LibraryService

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id: UUID) → ProjectDetailSchema` | 项目详情 | API |
| `list` | `(session, cursor?: str, page_size?: int) → CursorPage[ProjectListSchema]` | 项目列表（含 deps_count, vuln_count） | API |
| `count` | `(session) → int` | 项目总数 | API / StatsService |
| `create` | `(session, *, name, repo_url, dependencies: list[DependencyInput], ...) → Project` | 创建项目 + 注册依赖 | API |

### 业务逻辑

**get:**

```
ProjectDAO.get_by_id(id)
  → None → NotFoundError("project not found")
  → ProjectDependencyDAO.count_by_project(project.id) → deps_count
  → ClientVulnDAO.active_count_by_project(project.id) → vuln_count
  → 返回 ProjectDetailSchema
```

**list:**

```
ProjectDAO.list_paginated(cursor, page_size)
ProjectDAO.count() → total
  → 对当前页每个 project:
     ProjectDependencyDAO.count_by_project(project.id) → deps_count
     ClientVulnDAO.active_count_by_project(project.id) → vuln_count
  → 返回 CursorPage[ProjectListSchema]
```

> **v2 优化：** deps_count 和 vuln_count 可通过 DAO 层子查询一次完成，避免 N+1。

**create（核心流程，单事务）：**

```
1. ProjectDAO.create(name=name, repo_url=repo_url, organization=..., contact=..., ...)
   → project

2. 对每个 dependency in dependencies:
   library = LibraryService.upsert(session,
       name=dep.library_name,
       repo_url=dep.library_repo_url,
       platform=dep.platform,
       default_branch=dep.default_branch,
   )
   → 收集 { project_id: project.id, library_id: library.id,
              constraint_expr, resolved_version, constraint_source }

3. ProjectDependencyDAO.batch_create(deps_list)
   → ON CONFLICT (project_id, library_id, constraint_source) DO UPDATE
   → 幂等：重复接入同一项目不会报错

4. 返回 project
```

> Snapshot 的创建不在 ProjectService.create 中完成。Snapshot 由前端或 Engine 独立触发创建（通过 SnapshotService.create），保持关注点分离。

---

## 4. SnapshotService

**依赖 DAO：** SnapshotDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id: UUID) → Snapshot` | 快照详情 | API |
| `list_by_project` | `(session, project_id: UUID, cursor?: str, page_size?: int) → CursorPage[Snapshot]` | 项目快照列表 | API |
| `create` | `(session, *, project_id, repo_url, repo_name, version, backend, trigger_type) → Snapshot` | 创建快照记录 | API / Engine |
| `get_active` | `(session, project_id: UUID) → Snapshot \| None` | 获取活跃快照 | ImpactEngine |
| `list_building` | `(session) → list[Snapshot]` | 构建中快照列表 | ImpactEngine |
| `update_status` | `(session, id: UUID, *, status, error?, node_count?, edge_count?, analysis_duration_sec?, storage_path?, fuzzer_names?, language?, size_bytes?) → None` | 更新构建状态和元数据 | ImpactEngine |
| `activate` | `(session, id: UUID) → None` | 设为活跃快照 | ImpactEngine |

### 业务逻辑

**get:**

```
SnapshotDAO.get_by_id(id)
  → None → NotFoundError("snapshot not found")
  → 返回 Snapshot
```

**update_status:**

```
SnapshotDAO.update_status(id, status=status, error=error, node_count=node_count, ...)
  → 仅更新传入的非 None 字段，不影响其他字段
```

**activate:**

```
SnapshotDAO.activate(id)
  → 事务内两步：
     1. UPDATE snapshots SET is_active=FALSE WHERE project_id=:pid AND is_active=TRUE
     2. UPDATE snapshots SET is_active=TRUE, status='completed' WHERE id=:id
  → 快照不存在 → ValueError（DAO 层抛出）
```

### Snapshot 状态机

```
building ──→ completed
                │
                └──→ is_active=TRUE（同 project 仅一个）
```

> 无 "failed" 状态。失败通过 `error` 字段表达（非 NULL = 当前阶段失败），保留 status 信息。

---

## 5. EventService

**依赖 DAO：** EventDAO, UpstreamVulnDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id: UUID) → EventDetailSchema` | 事件详情（含关联漏洞） | API |
| `list` | `(session, cursor?: str, page_size?: int, library_id?: UUID) → CursorPage[Event]` | 事件列表（可按库过滤） | API |
| `count` | `(session, library_id?: UUID) → int` | 事件数量 | API |
| `batch_create` | `(session, events: list[dict]) → int` | 批量写入事件（幂等） | MonitorEngine |
| `list_unclassified` | `(session, limit: int) → list[Event]` | 待分类事件 | ClassifierEngine |
| `list_bugfix_without_vuln` | `(session, limit: int) → list[Event]` | 已确认 bugfix 但未创建 upstream_vuln 的事件 | AnalyzerEngine |
| `update_classification` | `(session, id: UUID, *, classification: str, confidence: float) → None` | 写入 LLM 分类结果 | ClassifierEngine |

### 业务逻辑

**get:**

```
EventDAO.get_by_id(id)
  → None → NotFoundError("event not found")
  → if event.is_bugfix:
       UpstreamVulnDAO.list_by_event(event.id)
       → related_vulns
  → 返回 EventDetailSchema { event, related_vulns }
```

**batch_create:**

```
EventDAO.batch_create(events)
  → ON CONFLICT (library_id, type, ref) DO NOTHING
  → 返回实际插入行数（rowcount）
```

> 幂等：MonitorEngine 重复轮询不会产生重复事件。

**update_classification（核心业务规则）：**

```
is_bugfix = (classification == "security_bugfix")
EventDAO.update_classification(id,
    classification=classification,
    confidence=confidence,
    is_bugfix=is_bugfix,
)
```

> **关键规则：** `is_bugfix` 完全由 `classification` 值决定。Service 层计算，DAO 层只写入。这确保了 is_bugfix 与 classification 的一致性。

**list_bugfix_without_vuln:**

```
EventDAO.list_bugfix_without_vuln(limit)
  → SQL: WHERE is_bugfix=TRUE AND NOT EXISTS (SELECT 1 FROM upstream_vulns WHERE event_id=events.id)
  → 使用 idx_events_bugfix 部分索引
```

### Event 分类流

```
事件创建 (classification=NULL, is_bugfix=FALSE)
    │
    ▼ ClassifierEngine 轮询 (idx_events_unclassified)
分类完成 (classification=?, is_bugfix=?)
    │
    ├─ security_bugfix → is_bugfix=TRUE → AnalyzerEngine 接管
    └─ 其他 → is_bugfix=FALSE → 流程结束
```

---

## 6. UpstreamVulnService

**依赖 DAO：** UpstreamVulnDAO, ClientVulnDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id: UUID) → UpstreamVulnDetailSchema` | 漏洞详情（含 client impact 列表） | API |
| `list` | `(session, cursor?: str, page_size?: int, library_id?: UUID) → CursorPage[UpstreamVuln]` | 漏洞列表 | API |
| `count` | `(session, library_id?: UUID) → int` | 漏洞数量 | API |
| `create` | `(session, *, event_id, library_id, commit_sha) → UpstreamVuln` | 创建分析记录 | AnalyzerEngine |
| `update_analysis` | `(session, id: UUID, *, vuln_type, severity, affected_versions, summary, reasoning, upstream_poc?) → None` | 写入分析结果 | AnalyzerEngine |
| `publish` | `(session, id: UUID) → None` | 发布漏洞 | AnalyzerEngine |
| `set_error` | `(session, id: UUID, error_message: str) → None` | 记录分析错误 | AnalyzerEngine |

### 业务逻辑

**get:**

```
UpstreamVulnDAO.get_by_id(id)
  → None → NotFoundError("upstream vulnerability not found")
  → ClientVulnDAO.list_by_upstream_vuln(vuln.id)
     → client_impact: [{ project_id, status, pipeline_status, is_affected }]
  → 返回 UpstreamVulnDetailSchema { vuln, client_impact }
```

**create:**

```
UpstreamVulnDAO.create(event_id=event_id, library_id=library_id, commit_sha=commit_sha)
  → 默认 status='analyzing'（server_default）
  → 返回新建的 UpstreamVuln
```

**update_analysis:**

```
UpstreamVulnDAO.update_analysis(id,
    vuln_type=vuln_type,
    severity=severity,
    affected_versions=affected_versions,
    summary=summary,
    reasoning=reasoning,
    upstream_poc=upstream_poc,  # 可选，JSONB
)
```

**publish:**

```
UpstreamVulnDAO.publish(id)
  → SET status='published', published_at=now()
```

> Service 只改 upstream_vulns 状态，**不主动创建 client_vulns**。ImpactEngine 下次轮询时发现 published 状态，负责创建 client_vulns（通过 DB 状态解耦）。

**set_error:**

```
UpstreamVulnDAO.set_error(id, error_message)
  → 记录错误，不改变 status
  → Engine 可根据 error_message 是否非 NULL 决定是否重试
```

### UpstreamVuln 状态机

```
analyzing ──→ published
    │
    └──→ error_message (非 NULL = 当前阶段失败，status 不变)
```

---

## 7. ClientVulnService

**依赖 DAO：** ClientVulnDAO, UpstreamVulnDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id: UUID) → ClientVulnDetailSchema` | 完整漏洞详情 | API |
| `list` | `(session, cursor?: str, page_size?: int, filters?: ClientVulnFilters) → ClientVulnListResult` | 漏洞列表 + 统计摘要 | API |
| `list_by_project` | `(session, project_id: UUID, cursor?: str, page_size?: int) → CursorPage[ClientVuln]` | 项目漏洞列表 | API |
| `get_stats` | `(session, project_id?: UUID) → VulnStats` | 向前包含计数 | API / StatsService |
| `create` | `(session, *, upstream_vuln_id, project_id, constraint_expr?, constraint_source?, resolved_version?, fix_version?, verdict?) → ClientVuln` | 创建客户漏洞 | ImpactEngine |
| `list_pending_pipeline` | `(session, limit: int) → list[ClientVuln]` | 待推进 pipeline 列表 | ImpactEngine |
| `update_pipeline` | `(session, id: UUID, *, pipeline_status, is_affected?, reachable_path?, poc_results?, error_message?, clear_error?) → None` | 推进 pipeline 状态 | ImpactEngine |
| `finalize` | `(session, id: UUID, *, is_affected: bool) → None` | pipeline 终态 | ImpactEngine |
| `update_status` | `(session, id: UUID, *, status: str, msg?: str) → None` | 维护者反馈 | API |

### 业务逻辑

**get:**

```
ClientVulnDAO.get_by_id(id)
  → None → NotFoundError("client vulnerability not found")
  → UpstreamVulnDAO.get_by_id(cv.upstream_vuln_id)
     → upstream vuln 信息（severity, vuln_type, summary, library_id）
  → 返回 ClientVulnDetailSchema:
     { cv 全字段, upstream_summary, severity,
       timeline, version_analysis, reachable_path, poc_results, report }
```

**list（含统计摘要）：**

```
ClientVulnDAO.list_paginated(cursor, page_size, filters)
  → 分页数据 Page[ClientVuln]
ClientVulnDAO.count(filters=filters)
  → total
ClientVulnDAO.count_by_status(project_id=filters.project_id)
  → stats: { total_recorded, total_reported, total_confirmed, total_fixed }
  → 返回 ClientVulnListResult { page, stats }
```

> ClientVulnFilters 支持: status, severity (JOIN upstream_vulns), library_id (JOIN upstream_vulns), project_id, date_from, date_to。DAO 层 `_apply_filters()` 仅在 severity/library_id 过滤时 JOIN，按需 JOIN。

**update_pipeline:**

```
ClientVulnDAO.update_pipeline(id,
    pipeline_status=pipeline_status,
    is_affected=is_affected,           # 可选
    reachable_path=reachable_path,     # 可选，JSONB
    poc_results=poc_results,           # 可选，JSONB
    error_message=error_message,       # 可选
    clear_error=clear_error,           # 可选，True 时重置 error_message 为 NULL
)
```

> `clear_error=True` 用于重试逻辑：Engine 重新尝试时清除上次的错误信息。`error_message` 优先级高于 `clear_error`（两者同时传入时写入 error_message）。

**finalize（pipeline 终态）：**

```
if is_affected:
    ClientVulnDAO.finalize(id,
        pipeline_status='verified',
        status='recorded',
        is_affected=True,
    )
    → 设置 analysis_completed_at=now(), recorded_at=now()
else:
    ClientVulnDAO.finalize(id,
        pipeline_status='not_affect',
        status='not_affect',
        is_affected=False,
    )
    → 设置 analysis_completed_at=now(), not_affect_at=now()
```

**update_status（维护者反馈，状态流转校验）：**

```
VALID_TRANSITIONS = {
    "recorded":  ["reported"],
    "reported":  ["confirmed"],
    "confirmed": ["fixed"],
}

cv = ClientVulnDAO.get_by_id(id)
  → None → NotFoundError
  → cv.status not in VALID_TRANSITIONS → ValidationError("terminal status")
  → status not in VALID_TRANSITIONS[cv.status] → ValidationError("invalid transition")

ClientVulnDAO.update_status(id, status=status, msg=msg)
  → status="reported"  → 设置 reported_at=now()
  → status="confirmed" → 设置 confirmed_at=now(), confirmed_msg=msg
  → status="fixed"     → 设置 fixed_at=now(), fixed_msg=msg
```

### ClientVuln 双状态机

**Pipeline 状态机**（ImpactEngine 驱动）：

```
pending ──→ path_searching ──→ poc_generating ──→ verified
                                                     │
                    ├─────────────────────────────→ not_affect
                    │（任意阶段可短路到 not_affect）
```

**Vuln 状态机**（维护者反馈驱动，仅 is_affected=true 时进入）：

```
recorded ──→ reported ──→ confirmed ──→ fixed
```

> 两个状态机独立运行。pipeline_status 由 Engine 推进，status 由人工反馈推进。

### 向前包含计数

`count_by_status` 返回的是**向前包含**计数，不是独立计数：

| 字段 | 包含的状态 |
|------|-----------|
| total_recorded | recorded + reported + confirmed + fixed |
| total_reported | reported + confirmed + fixed |
| total_confirmed | confirmed + fixed |
| total_fixed | fixed |

> 用于 dashboard 漏斗图：recorded → reported → confirmed → fixed 的转化率。

---

## 8. StatsService

**依赖 Service：** ClientVulnService
**依赖 DAO：** ProjectDAO, LibraryDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get_dashboard` | `(session) → DashboardStats` | 主页统计面板 | API |

### 业务逻辑

**get_dashboard:**

```
1. ProjectDAO.count()
   → projects_count

2. LibraryDAO.count()
   → libraries_count

3. ClientVulnService.get_stats(session, project_id=None)
   → { total_recorded, total_reported, total_confirmed, total_fixed }

4. 返回 DashboardStats {
     projects_count,
     libraries_count,
     vuln_recorded: total_recorded,
     vuln_reported: total_reported,
     vuln_confirmed: total_confirmed,
     vuln_fixed: total_fixed,
   }
```

---

## 调用关系总览

```
┌─────────────────────────────┐     ┌──────────────────────────────────┐
│         API 层 (FastAPI)     │     │        Engine 层 (APScheduler)    │
│                             │     │                                  │
│  AuthService                │     │  MonitorEngine (5min)            │
│  LibraryService.get/list    │     │    → EventService.batch_create   │
│  ProjectService.get/list    │     │    → LibraryDAO.update_pointers  │
│  ProjectService.create      │     │                                  │
│  SnapshotService.list       │     │  ClassifierEngine (2min)         │
│  EventService.get/list      │     │    → EventService.list_unclassified │
│  UpstreamVulnService.get    │     │    → EventService.update_classification │
│  ClientVulnService.get/list │     │                                  │
│  ClientVulnService          │     │  AnalyzerEngine (2min)           │
│    .update_status           │     │    → EventService.list_bugfix_without_vuln │
│  StatsService.get_dashboard │     │    → UpstreamVulnService.create  │
│                             │     │    → UpstreamVulnService.update_analysis │
└──────────┬──────────────────┘     │    → UpstreamVulnService.publish │
           │                        │                                  │
           │                        │  ImpactEngine (1min)             │
           │                        │    → SnapshotService.list_building │
           │                        │    → SnapshotService.update_status │
           │                        │    → SnapshotService.activate    │
           │                        │    → ClientVulnService.create    │
           │                        │    → ClientVulnService           │
           │                        │        .list_pending_pipeline    │
           │                        │    → ClientVulnService           │
           │                        │        .update_pipeline          │
           │                        │    → ClientVulnService.finalize  │
           │                        └──────────┬───────────────────────┘
           │                                   │
           └───────────┬───────────────────────┘
                       │
              ┌────────▼─────────┐
              │   Service 层      │
              │                  │
              │  8 个 Service    │
              │  (无状态，DI)    │
              └────────┬─────────┘
                       │
              ┌────────▼─────────┐
              │    DAO 层         │
              │                  │
              │  8 个 DAO        │
              │  (251 tests)     │
              └────────┬─────────┘
                       │
              ┌────────▼─────────┐
              │  PostgreSQL      │
              │  + Neo4j (图)    │
              │  + Disk (文件)   │
              └──────────────────┘
```

## Service 间依赖图

```
StatsService ──→ ClientVulnService
               ──→ ProjectDAO (直接)
               ──→ LibraryDAO (直接)

ProjectService ──→ LibraryService

AuthService         ──→ (无 service 依赖)
LibraryService      ──→ (无 service 依赖)
SnapshotService     ──→ (无 service 依赖)
EventService        ──→ (无 service 依赖)
UpstreamVulnService ──→ (无 service 依赖)
ClientVulnService   ──→ (无 service 依赖)
```

> 依赖关系为 DAG（有向无环图），无循环依赖。

---

## 设计原则总结

1. **事务由调用方管理** — Service 不创建事务，API 中间件和 Engine 调度器负责 session 生命周期
2. **Service 无状态** — 通过构造函数注入 DAO，应用级单例
3. **DAO 返回 Model，Service 返回 Schema** — ORM 对象不穿透到 API 层
4. **业务规则在 Service** — 状态流转校验、is_bugfix 计算、404/422 判断
5. **Engine 与 Service 通过 DB 状态解耦** — AnalyzerEngine publish 后，ImpactEngine 通过轮询发现
6. **幂等写入** — batch_create/upsert 使用 ON CONFLICT，重复执行安全
7. **异常分层** — ServiceError → NotFoundError / ConflictError / ValidationError / AuthenticationError
8. **无循环依赖** — Service 间依赖为 DAG
9. **v2 优化预留** — N+1 查询标注为优化点，v1 用循环实现功能正确性
