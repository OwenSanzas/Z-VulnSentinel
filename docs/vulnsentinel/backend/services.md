# Service 层设计

> 业务逻辑层，编排 DAO 调用，管理事务边界。Service 是 api 和 engines 的共享底层。

## 设计约定

- 每个 service 方法接收 `AsyncSession` 作为第一个参数，事务由调用方（api 依赖注入 / engine 调度器）管理
- Service 调用一到多个 DAO 完成一次业务操作，DAO 返回的 Row 在 service 层转换为 Pydantic schema
- Service 之间可以互相调用（如 ProjectService 调用 LibraryService.upsert），但不形成循环依赖
- Service 不直接导入 Engine，也不被 Engine 直接导入（通过 DB 状态解耦）

---

## 1. AuthService

**依赖 DAO：** UserDAO

### 方法

| 方法 | 签名 | 说明 |
|------|------|------|
| `ensure_admin_exists` | `(session) → None` | 启动时检查 admin 用户是否存在，不存在则用 .env 配置创建 |
| `login` | `(session, username: str, password: str) → TokenPair` | 验证密码，签发 access_token + refresh_token |
| `refresh` | `(refresh_token: str) → AccessToken` | 验证 refresh_token，签发新 access_token |
| `get_current_user` | `(session, token: str) → UserSchema` | 解码 JWT，查询用户（用于依赖注入） |

### 业务逻辑

**ensure_admin_exists:**

```
读取 .env: VULNSENTINEL_USERNAME, VULNSENTINEL_PASSWORD
  → bcrypt.hash(password)
  → UserDAO.upsert(username, email, password_hash, role='admin')
```

**login:**

```
UserDAO.get_by_username(username)
  → 用户不存在 → 401
  → bcrypt.checkpw(password, user.password_hash)
  → 不匹配 → 401
  → 签发 access_token (exp=30min, type='access', sub=user.id, role=user.role)
  → 签发 refresh_token (exp=7d, type='refresh', sub=user.id)
  → 返回 { access_token, refresh_token, token_type: 'bearer' }
```

**refresh:**

```
解码 refresh_token
  → 过期或 type != 'refresh' → 401
  → 签发新 access_token (exp=30min)
  → 返回 { access_token, token_type: 'bearer' }
```

---

## 2. LibraryService

**依赖 DAO：** LibraryDAO, ProjectDependencyDAO, EventDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id) → LibraryDetailSchema` | 库详情（含 used_by、commit 计数） | API |
| `list` | `(session, cursor?, page_size?) → CursorPage[LibraryListSchema]` | 库列表（含 used_by） | API |
| `upsert` | `(session, name, repo_url, platform?, default_branch?) → LibrarySchema` | 新库入库 | ProjectService |

### 业务逻辑

**get:**

```
LibraryDAO.get_by_id(id)
  → 不存在 → 404
  → ProjectDependencyDAO.list_by_library(library_id)
     → 组装 used_by 列表（project_id, project_name, constraint, resolved_version）
  → EventDAO.count(library_id=id)
     → total_commits_tracked
  → 返回 LibraryDetailSchema
```

**list:**

```
LibraryDAO.list_paginated(cursor, page_size)
  → 对每个库：
     ProjectDependencyDAO.list_by_library(library.id)
     → 组装 used_by
  → 返回 CursorPage[LibraryListSchema]
```

> **优化点：** list 中的 used_by 可通过一次批量查询获取（`WHERE library_id IN (:ids)`），避免 N+1 问题。此优化在 DAO 层用 `list_by_libraries(library_ids)` 方法实现。

---

## 3. ProjectService

**依赖 DAO：** ProjectDAO, ProjectDependencyDAO, SnapshotDAO, ClientVulnDAO
**依赖 Service：** LibraryService

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id) → ProjectDetailSchema` | 项目详情 | API |
| `list` | `(session, cursor?, page_size?) → CursorPage[ProjectListSchema]` | 项目列表（含 deps_count, vuln_count） | API |
| `create` | `(session, name, repo_url, ...) → ProjectSchema` | 创建项目 + 提取依赖 + 创建 snapshot | API |

### 业务逻辑

**get:**

```
ProjectDAO.get_by_id(id)
  → 不存在 → 404
  → 返回 ProjectDetailSchema
```

**list:**

```
ProjectDAO.list_paginated(cursor, page_size)
  → 对当前页的 project_ids 批量查：
     ProjectDependencyDAO.count_by_project(project_id) → deps_count
     ClientVulnDAO.active_count_by_project(project_id) → vuln_count
  → 返回 CursorPage[ProjectListSchema]
```

> **优化点：** deps_count 和 vuln_count 可通过子查询在 DAO 层一次完成，避免多次往返。

**create（核心流程，单事务）：**

```
1. ProjectDAO.create(name, repo_url, ...)
   → 新建项目记录

2. 依赖提取（解析 conanfile.txt / CMakeLists.txt / ...）
   → 得到 [(library_name, repo_url, constraint_expr, resolved_version, source_file), ...]

3. 对每个依赖：
   LibraryService.upsert(name, repo_url, ...)
   → 得到 library.id

4. ProjectDependencyDAO.batch_create([
     { project_id, library_id, constraint_expr, resolved_version, constraint_source },
     ...
   ])

5. SnapshotDAO.create(
     project_id, repo_url, repo_name, version,
     backend='svf', trigger_type='manual'
   )
   → 创建 status=building 的快照记录（Engine 轮询后接管构建）

6. 返回 ProjectSchema
```

---

## 4. SnapshotService

**依赖 DAO：** SnapshotDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `list_by_project` | `(session, project_id, cursor?, page_size?) → CursorPage[SnapshotSchema]` | 项目详情 - Snapshots tab | API |
| `get_active` | `(session, project_id) → SnapshotSchema \| None` | 获取活跃快照 | ImpactEngine |
| `create` | `(session, project_id, repo_url, repo_name, version, backend, trigger_type) → SnapshotSchema` | 创建快照记录 | ProjectService |
| `update_status` | `(session, id, status, error?, node_count?, edge_count?, ...) → None` | 更新构建状态 | Engine |
| `activate` | `(session, id) → None` | 激活快照（取消同项目其他活跃快照） | Engine |

### 业务逻辑

**activate:**

```
SnapshotDAO.activate(id)
  → 事务内：
     1. 取消同 project 其他活跃快照 (is_active = FALSE)
     2. 设置当前快照 (is_active = TRUE, status = 'completed')
```

---

## 5. EventService

**依赖 DAO：** EventDAO, UpstreamVulnDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id) → EventDetailSchema` | 事件详情（含关联 upstream_vulns） | API |
| `list` | `(session, cursor?, page_size?, library_id?) → CursorPage[EventListSchema]` | 事件列表 | API |
| `batch_create` | `(session, events: list[dict]) → int` | 批量写入事件 | MonitorEngine |
| `get_unclassified` | `(session, limit) → list[EventSchema]` | 未分类事件 | ClassifierEngine |
| `update_classification` | `(session, id, classification, confidence) → None` | 更新分类结果 | ClassifierEngine |

### 业务逻辑

**get:**

```
EventDAO.get_by_id(id)
  → 不存在 → 404
  → if event.is_bugfix:
       UpstreamVulnDAO.list_by_event(event_id)
       → 关联漏洞列表
  → 返回 EventDetailSchema
```

**update_classification:**

```
is_bugfix = (classification == 'security_bugfix')
EventDAO.update_classification(id, classification, confidence, is_bugfix)
```

> 业务规则：`is_bugfix` 的值完全由 classification 决定，service 层负责计算，DAO 只做写入。

---

## 6. UpstreamVulnService

**依赖 DAO：** UpstreamVulnDAO, ClientVulnDAO, ProjectDependencyDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id) → UpstreamVulnDetailSchema` | 漏洞详情（含 client impact） | API |
| `list` | `(session, cursor?, page_size?, library_id?) → CursorPage[UpstreamVulnListSchema]` | 漏洞列表 | API |
| `create` | `(session, event_id, library_id, commit_sha) → UpstreamVulnSchema` | 创建分析记录 | AnalyzerEngine |
| `update_analysis` | `(session, id, vuln_type, severity, ...) → None` | 写入分析结果 | AnalyzerEngine |
| `publish` | `(session, id) → None` | 发布漏洞 | AnalyzerEngine |
| `set_error` | `(session, id, error_message) → None` | 记录错误 | AnalyzerEngine |

### 业务逻辑

**get:**

```
UpstreamVulnDAO.get_by_id(id)
  → 不存在 → 404
  → ClientVulnDAO.list_by_upstream_vuln(upstream_vuln_id)
     → 组装 client impact 列表（project_name, version_used, analysis_status, ...）
  → 返回 UpstreamVulnDetailSchema
```

**list（含 affected_clients）：**

```
UpstreamVulnDAO.list_paginated(cursor, page_size, library_id)
  → 对当前页的 upstream_vuln_ids 批量查：
     ClientVulnDAO.list_by_upstream_vulns(ids)
     → 按 upstream_vuln_id 分组，组装 affected_clients
  → 返回 CursorPage[UpstreamVulnListSchema]
```

**publish:**

```
UpstreamVulnDAO.publish(id)
  → status → published, published_at = now()
  → ImpactEngine 下次轮询时发现 published 状态，自动创建 client_vulns
```

> Service 只改 upstream_vulns 状态，不主动创建 client_vulns。client_vulns 的创建由 ImpactEngine 负责。

---

## 7. ClientVulnService

**依赖 DAO：** ClientVulnDAO, UpstreamVulnDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get` | `(session, id) → ClientVulnDetailSchema` | 完整漏洞详情 | API |
| `list` | `(session, cursor?, page_size?, filters?) → CursorPage[ClientVulnListSchema]` | 漏洞列表（多条件筛选 + 统计摘要） | API |
| `list_by_project` | `(session, project_id, cursor?, page_size?) → CursorPage[ClientVulnListSchema]` | 项目详情 - Vulnerabilities tab | API |
| `get_stats` | `(session, project_id?) → VulnStatsSchema` | 向前包含计数 | API / StatsService |
| `create` | `(session, upstream_vuln_id, project_id, constraint_expr?, ...) → ClientVulnSchema` | 创建客户漏洞 | ImpactEngine |
| `update_pipeline` | `(session, id, pipeline_status, ...) → None` | 推进 pipeline 状态 | ImpactEngine |
| `finalize` | `(session, id, status, is_affected) → None` | pipeline 终态 | ImpactEngine |
| `update_status` | `(session, id, status, msg?) → None` | 维护者反馈 | API |

### 业务逻辑

**get:**

```
ClientVulnDAO.get_by_id(id)
  → 不存在 → 404
  → UpstreamVulnDAO.get_by_id(cv.upstream_vuln_id)
     → 拼装 upstream_vuln_summary, severity, library_name
  → 返回 ClientVulnDetailSchema（含 timeline, version_analysis, reachable_path, poc_results, report）
```

**list（含统计摘要）：**

```
ClientVulnDAO.list_paginated(cursor, page_size, filters)
  → 分页数据
ClientVulnDAO.count_by_status(filters.project_id)
  → 统计摘要（total_recorded, total_reported, total_confirmed, total_fixed）
  → 返回 CursorPage[ClientVulnListSchema] + stats
```

**update_status（维护者反馈）：**

```
校验状态流转合法性：
  recorded → reported → confirmed → fixed（只能前进，不能后退）
  → 非法流转 → 422

ClientVulnDAO.update_status(id, status, msg)
```

**finalize（pipeline 终态，由 ImpactEngine 调用）：**

```
if is_affected:
    ClientVulnDAO.finalize(id, pipeline_status='verified', status='recorded', is_affected=TRUE)
else:
    ClientVulnDAO.finalize(id, pipeline_status='not_affect', status='not_affect', is_affected=FALSE)
```

---

## 8. StatsService

**依赖 Service：** ClientVulnService
**依赖 DAO：** ProjectDAO

### 方法

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get_dashboard` | `(session) → DashboardStatsSchema` | 主页统计面板 | API |

### 业务逻辑

**get_dashboard:**

```
1. ProjectDAO.count()
   → projects_count

2. ClientVulnService.get_stats(project_id=None)
   → vuln_recorded_count, vuln_reported_count, vuln_confirmed_count, vuln_fixed_count

3. 读取磁盘使用情况（os.statvfs）
   → disk_total_bytes, disk_used_bytes, disk_usage_percent

4. 返回 DashboardStatsSchema
```

---

## 调用关系总览

```
API 层                          Engine 层
  │                                │
  ├── AuthService                  │
  ├── LibraryService ◄─────────────┤ (MonitorEngine 通过 EventService 写数据)
  ├── ProjectService               │
  ├── SnapshotService ◄────────────┤ (Engine 更新构建状态)
  ├── EventService ◄───────────────┤ (MonitorEngine / ClassifierEngine)
  ├── UpstreamVulnService ◄────────┤ (AnalyzerEngine)
  ├── ClientVulnService ◄──────────┤ (ImpactEngine)
  └── StatsService                 │
                                   │
所有 Service                       │
  └──→ DAO 层 ──→ 数据库 ◄─────────┘ (Engine 通过 Service 读写)
```

## Service 间依赖

```
StatsService → ClientVulnService, ProjectDAO
ProjectService → LibraryService, SnapshotService
LibraryService → (无 service 依赖)
EventService → (无 service 依赖)
UpstreamVulnService → (无 service 依赖)
ClientVulnService → (无 service 依赖)
SnapshotService → (无 service 依赖)
AuthService → (无 service 依赖)
```

> 无循环依赖。ProjectService 是依赖最多的 service（客户接入涉及多表操作），但它只单向依赖 LibraryService 和 SnapshotService。
