# DAO 层设计

> 数据访问层，SQLAlchemy ORM + Core 混用。简单 CRUD 用 ORM，复杂查询用 Core。每个 DAO 对应一张表，提供该表的全部数据库操作。
>
> **风格划分：**
> | 场景 | 风格 | 原因 |
> |------|------|------|
> | get_by_id / create / update / delete | ORM (`session.get()` / `session.add()`) | 一行搞定 |
> | cursor 分页 | Core (`select()` + `tuple_()`) | 需要复合比较 + LIMIT |
> | 多表 JOIN 列表 | Core | 显式控制 JOIN 和返回字段 |
> | 聚合统计 | Core (`func.count()` + `filter()`) | ORM 不擅长 |
> | ON CONFLICT upsert | Core (`insert().on_conflict_do_update()`) | ORM 不原生支持 |

## 1. BaseDAO — 通用基类

所有 DAO 继承 `BaseDAO`，获得通用 CRUD 和 cursor 分页能力。

### 类型约定

```python
from sqlalchemy import Table
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from datetime import datetime

# 游标类型
@dataclass
class Cursor:
    created_at: datetime
    id: UUID

# 分页结果
@dataclass
class Page[T]:
    data: list[T]
    next_cursor: str | None
    has_more: bool
    total: int
```

### BaseDAO 方法

| 方法 | 签名 | 说明 |
|------|------|------|
| `get_by_id` | `(session, id: UUID) → Model \| None` | ORM — `session.get(Model, id)` |
| `create` | `(session, **values) → Model` | ORM — `session.add(Model(**values))` |
| `update` | `(session, id: UUID, **values) → Model \| None` | ORM — 获取对象后直接赋值 |
| `delete` | `(session, id: UUID) → bool` | ORM — `session.delete(obj)` |
| `paginate` | `(session, query, cursor, page_size) → Page[Row]` | Core — 通用 cursor 分页 |
| `count` | `(session, query) → int` | Core — 执行 COUNT 查询 |

### cursor 分页实现

```python
async def paginate(
    self,
    session: AsyncSession,
    query: Select,           # 已包含 WHERE 过滤的查询
    cursor: str | None,      # base64 编码的游标
    page_size: int = 20,
) -> Page[Row]:
    if cursor:
        created_at, id = decode_cursor(cursor)
        query = query.where(
            tuple_(self.table.c.created_at, self.table.c.id)
            < (created_at, id)
        )

    query = query.order_by(
        self.table.c.created_at.desc(),
        self.table.c.id.desc(),
    ).limit(page_size + 1)

    rows = (await session.execute(query)).fetchall()
    has_more = len(rows) > page_size
    data = rows[:page_size]
    next_cursor = encode_cursor(data[-1]) if has_more else None

    return Page(data=data, next_cursor=next_cursor, has_more=has_more, total=...)
```

### total 缓存

`paginate` 方法不自带 total 计算。调用方（service 层）通过独立的 `count()` 方法获取总数，配合内存缓存（TTL 60s）使用。

---

## 2. UserDAO

**表：** `users`

| 方法 | 签名 | 说明 |
|------|------|------|
| `get_by_username` | `(session, username: str) → Row \| None` | 登录时按用户名查找 |
| `get_by_id` | `(session, id: UUID) → Row \| None` | JWT 验证时按 ID 查找（继承 BaseDAO） |
| `upsert` | `(session, username, email, password_hash, role) → Row` | 启动时创建初始管理员（ON CONFLICT DO NOTHING） |

### 关键查询

```sql
-- get_by_username
SELECT * FROM users WHERE username = :username;

-- upsert（启动初始化）
INSERT INTO users (username, email, password_hash, role)
VALUES (:username, :email, :password_hash, :role)
ON CONFLICT (username) DO NOTHING
RETURNING *;
```

---

## 3. LibraryDAO

**表：** `libraries`

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get_by_id` | `(session, id) → Row \| None` | 库详情 | API |
| `list_paginated` | `(session, cursor, page_size) → Page[Row]` | 库列表 | API |
| `count` | `(session) → int` | 总数 | API |
| `upsert_by_name` | `(session, name, repo_url, platform, default_branch) → Row` | 新库入库（去重） | 客户接入 |
| `get_all_monitored` | `(session) → list[Row]` | 全量监控列表 | MonitorEngine |
| `update_pointers` | `(session, id, latest_commit_sha?, latest_tag_version?, last_activity_at?) → None` | 更新监控指针 | MonitorEngine |

### 关键查询

```sql
-- upsert_by_name
INSERT INTO libraries (name, repo_url, platform, default_branch)
VALUES (:name, :repo_url, :platform, :default_branch)
ON CONFLICT (name) DO UPDATE SET
    repo_url = EXCLUDED.repo_url,
    updated_at = now()
RETURNING *;

-- get_all_monitored（MonitorEngine 全量拉取，无需分页）
SELECT * FROM libraries ORDER BY name;

-- update_pointers
UPDATE libraries
SET latest_commit_sha = COALESCE(:sha, latest_commit_sha),
    latest_tag_version = COALESCE(:tag, latest_tag_version),
    last_activity_at = COALESCE(:activity_at, last_activity_at)
WHERE id = :id;
```

---

## 4. ProjectDAO

**表：** `projects`

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get_by_id` | `(session, id) → Row \| None` | 项目详情 | API |
| `list_paginated` | `(session, cursor, page_size) → Page[Row]` | 项目列表 | API |
| `count` | `(session) → int` | 项目总数 | API / StatsService |
| `create` | `(session, name, repo_url, organization?, contact?, ...) → Row` | 创建项目 | 客户接入 |

### 关键查询

```sql
-- list_paginated（基础查询，service 层负责补充 deps_count / vuln_count）
SELECT * FROM projects
WHERE (created_at, id) < (:cursor_created_at, :cursor_id)
ORDER BY created_at DESC, id DESC
LIMIT :page_size + 1;
```

---

## 5. ProjectDependencyDAO

**表：** `project_dependencies`

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `list_by_project` | `(session, project_id, cursor, page_size) → Page[Row]` | 项目详情 - Dependencies tab | API |
| `list_by_library` | `(session, library_id) → list[Row]` | 库详情 - Used By | API |
| `find_projects_by_library` | `(session, library_id) → list[Row]` | 查找使用某库的全部项目 | ImpactEngine |
| `batch_create` | `(session, deps: list[dict]) → list[Row]` | 批量创建依赖关系 | 客户接入 |
| `count_by_project` | `(session, project_id) → int` | 项目依赖数 | API（deps_count） |

### 关键查询

```sql
-- list_by_library（库详情 Used By，数据量小无需分页）
SELECT pd.*, p.name AS project_name
FROM project_dependencies pd
JOIN projects p ON p.id = pd.project_id
WHERE pd.library_id = :library_id;

-- find_projects_by_library（ImpactEngine 用，只需 project_id + 版本信息）
SELECT pd.project_id, pd.constraint_expr, pd.resolved_version, pd.constraint_source
FROM project_dependencies pd
WHERE pd.library_id = :library_id;

-- batch_create
INSERT INTO project_dependencies (project_id, library_id, constraint_expr, resolved_version, constraint_source)
VALUES (:project_id, :library_id, :constraint_expr, :resolved_version, :constraint_source)
ON CONFLICT (project_id, library_id, constraint_source) DO UPDATE SET
    constraint_expr = EXCLUDED.constraint_expr,
    resolved_version = EXCLUDED.resolved_version
RETURNING *;
```

---

## 6. SnapshotDAO

**表：** `snapshots`

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get_by_id` | `(session, id) → Row \| None` | 快照详情 | API |
| `list_by_project` | `(session, project_id, cursor, page_size) → Page[Row]` | 项目详情 - Snapshots tab | API |
| `create` | `(session, project_id, repo_url, repo_name, version, backend, trigger_type) → Row` | 创建快照记录 | 客户接入 |
| `get_active_by_project` | `(session, project_id) → Row \| None` | 获取活跃快照 | ImpactEngine |
| `list_building` | `(session) → list[Row]` | 查找构建中的快照 | Engine 轮询 |
| `update_status` | `(session, id, status, error?, node_count?, edge_count?, ...) → None` | 更新构建状态 | Engine |
| `activate` | `(session, id) → None` | 设为活跃快照（同时取消同 project 其他活跃快照） | Engine |

### 关键查询

```sql
-- get_active_by_project
SELECT * FROM snapshots
WHERE project_id = :project_id AND is_active = TRUE;

-- list_building（Engine 轮询）
SELECT * FROM snapshots WHERE status = 'building';

-- activate（事务内执行两条）
UPDATE snapshots SET is_active = FALSE
WHERE project_id = :project_id AND is_active = TRUE;

UPDATE snapshots SET is_active = TRUE, status = 'completed'
WHERE id = :id;
```

---

## 7. EventDAO

**表：** `events`

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get_by_id` | `(session, id) → Row \| None` | 事件详情 | API |
| `list_paginated` | `(session, cursor, page_size, library_id?) → Page[Row]` | 事件列表（可按库过滤） | API |
| `count` | `(session, library_id?) → int` | 总数 | API |
| `create` | `(session, library_id, type, ref, title, ...) → Row` | 写入事件 | MonitorEngine |
| `batch_create` | `(session, events: list[dict]) → int` | 批量写入（ON CONFLICT 跳过） | MonitorEngine |
| `list_unclassified` | `(session, limit: int) → list[Row]` | 查找未分类事件 | ClassifierEngine |
| `list_bugfix_without_vuln` | `(session, limit: int) → list[Row]` | 查找已分类为 bugfix 但未创建 upstream_vuln 的事件 | AnalyzerEngine |
| `update_classification` | `(session, id, classification, confidence, is_bugfix) → None` | 更新分类结果 | ClassifierEngine |

### 关键查询

```sql
-- batch_create（MonitorEngine 批量插入，重复跳过）
INSERT INTO events (library_id, type, ref, source_url, author, title, message,
                    related_issue_ref, related_issue_url, related_pr_ref,
                    related_pr_url, related_commit_sha)
VALUES (:library_id, :type, :ref, :source_url, :author, :title, :message,
        :related_issue_ref, :related_issue_url, :related_pr_ref,
        :related_pr_url, :related_commit_sha)
ON CONFLICT (library_id, type, ref) DO NOTHING;

-- list_unclassified（ClassifierEngine 轮询，走 idx_events_unclassified 索引）
SELECT * FROM events
WHERE classification IS NULL
ORDER BY created_at DESC
LIMIT :limit;

-- list_bugfix_without_vuln（AnalyzerEngine 轮询）
SELECT e.* FROM events e
WHERE e.is_bugfix = TRUE
  AND NOT EXISTS (
      SELECT 1 FROM upstream_vulns uv WHERE uv.event_id = e.id
  )
ORDER BY e.created_at DESC
LIMIT :limit;

-- update_classification
UPDATE events
SET classification = :classification,
    confidence = :confidence,
    is_bugfix = :is_bugfix
WHERE id = :id;
```

---

## 8. UpstreamVulnDAO

**表：** `upstream_vulns`

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get_by_id` | `(session, id) → Row \| None` | 漏洞详情 | API |
| `list_paginated` | `(session, cursor, page_size, library_id?) → Page[Row]` | 漏洞列表（可按库过滤） | API |
| `count` | `(session, library_id?) → int` | 总数 | API |
| `list_by_event` | `(session, event_id) → list[Row]` | 事件详情页关联漏洞 | API |
| `create` | `(session, event_id, library_id, commit_sha) → Row` | 创建分析记录 | AnalyzerEngine |
| `update_analysis` | `(session, id, vuln_type, severity, affected_versions, summary, reasoning, upstream_poc?) → None` | 写入分析结果 | AnalyzerEngine |
| `publish` | `(session, id) → None` | 发布漏洞（status → published） | AnalyzerEngine |
| `set_error` | `(session, id, error_message) → None` | 记录错误 | AnalyzerEngine |

### 关键查询

```sql
-- create
INSERT INTO upstream_vulns (event_id, library_id, commit_sha, status)
VALUES (:event_id, :library_id, :commit_sha, 'analyzing')
RETURNING *;

-- update_analysis
UPDATE upstream_vulns
SET vuln_type = :vuln_type,
    severity = :severity,
    affected_versions = :affected_versions,
    summary = :summary,
    reasoning = :reasoning,
    upstream_poc = :upstream_poc
WHERE id = :id;

-- publish
UPDATE upstream_vulns
SET status = 'published', published_at = now()
WHERE id = :id;
```

---

## 9. ClientVulnDAO

**表：** `client_vulns`

| 方法 | 签名 | 说明 | 调用方 |
|------|------|------|--------|
| `get_by_id` | `(session, id) → Row \| None` | 漏洞详情 | API |
| `list_paginated` | `(session, cursor, page_size, filters: ClientVulnFilters) → Page[Row]` | 漏洞列表（多条件筛选） | API |
| `count` | `(session, filters: ClientVulnFilters) → int` | 筛选后总数 | API |
| `count_by_status` | `(session, project_id?) → dict` | 按状态分组计数（向前包含） | API / StatsService |
| `list_by_upstream_vuln` | `(session, upstream_vuln_id) → list[Row]` | 上游漏洞详情 - Client Impact | API |
| `list_by_project` | `(session, project_id, cursor, page_size) → Page[Row]` | 项目详情 - Vulnerabilities tab | API |
| `active_count_by_project` | `(session, project_id) → int` | 活跃漏洞数（排除 fixed / not_affect） | API（项目列表 vuln_count） |
| `create` | `(session, upstream_vuln_id, project_id, constraint_expr?, ...) → Row` | 创建客户漏洞 | ImpactEngine |
| `list_pending_pipeline` | `(session, limit: int) → list[Row]` | 查找需要推进的 pipeline | ImpactEngine |
| `update_pipeline` | `(session, id, pipeline_status, is_affected?, reachable_path?, poc_results?, error_message?) → None` | 推进 pipeline 状态 | ImpactEngine |
| `finalize` | `(session, id, status, recorded_at?) → None` | pipeline 完成，设置终态 | ImpactEngine |
| `update_status` | `(session, id, status, msg?) → None` | 维护者反馈（confirmed / fixed） | API |

### ClientVulnFilters

```python
@dataclass
class ClientVulnFilters:
    status: client_vuln_status | None = None
    severity: severity_level | None = None     # 需 JOIN upstream_vulns
    library_id: UUID | None = None             # 需 JOIN upstream_vulns
    project_id: UUID | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
```

### 关键查询

```sql
-- list_paginated（带筛选，需 JOIN upstream_vulns 获取 severity / library_id）
SELECT cv.*, uv.summary, uv.severity, uv.library_id,
       l.name AS library_name, p.name AS project_name
FROM client_vulns cv
JOIN upstream_vulns uv ON uv.id = cv.upstream_vuln_id
JOIN libraries l ON l.id = uv.library_id
JOIN projects p ON p.id = cv.project_id
WHERE (:status IS NULL OR cv.status = :status)
  AND (:severity IS NULL OR uv.severity = :severity)
  AND (:library_id IS NULL OR uv.library_id = :library_id)
  AND (:project_id IS NULL OR cv.project_id = :project_id)
  AND (:date_from IS NULL OR cv.created_at >= :date_from)
  AND (:date_to IS NULL OR cv.created_at <= :date_to)
  AND (cv.created_at, cv.id) < (:cursor_created_at, :cursor_id)
ORDER BY cv.created_at DESC, cv.id DESC
LIMIT :page_size + 1;

-- count_by_status（向前包含计数）
-- recorded 包含 recorded + reported + confirmed + fixed
-- reported 包含 reported + confirmed + fixed
-- 等等
SELECT
    COUNT(*) FILTER (WHERE status IN ('recorded','reported','confirmed','fixed')) AS total_recorded,
    COUNT(*) FILTER (WHERE status IN ('reported','confirmed','fixed'))            AS total_reported,
    COUNT(*) FILTER (WHERE status IN ('confirmed','fixed'))                       AS total_confirmed,
    COUNT(*) FILTER (WHERE status = 'fixed')                                      AS total_fixed
FROM client_vulns
WHERE (:project_id IS NULL OR project_id = :project_id);

-- list_pending_pipeline（ImpactEngine 轮询，走 idx_clientvulns_pipeline 索引）
SELECT * FROM client_vulns
WHERE pipeline_status IN ('pending', 'path_searching', 'poc_generating')
ORDER BY created_at ASC
LIMIT :limit;

-- finalize（pipeline 终态）
UPDATE client_vulns
SET pipeline_status = :pipeline_status,
    status = :status,
    is_affected = :is_affected,
    analysis_completed_at = now(),
    recorded_at = CASE WHEN :status = 'recorded' THEN now() ELSE NULL END,
    not_affect_at = CASE WHEN :status = 'not_affect' THEN now() ELSE NULL END
WHERE id = :id;

-- update_status（维护者反馈）
UPDATE client_vulns
SET status = :status,
    confirmed_at = CASE WHEN :status = 'confirmed' THEN now() ELSE confirmed_at END,
    confirmed_msg = CASE WHEN :status = 'confirmed' THEN :msg ELSE confirmed_msg END,
    fixed_at = CASE WHEN :status = 'fixed' THEN now() ELSE fixed_at END,
    fixed_msg = CASE WHEN :status = 'fixed' THEN :msg ELSE fixed_msg END
WHERE id = :id;
```

---

## 设计原则总结

1. **一表一 DAO** — 8 张表对应 8 个 DAO，不跨表
2. **简单用 ORM，复杂用 Core** — get/create/update/delete 用 ORM；分页、JOIN、聚合、upsert 用 Core
3. **JOIN 在 DAO 内完成** — 需要联表的查询（如 client_vulns 列表需要 library_name）在 DAO 的 SQL 中直接 JOIN，service 层不做二次查询拼装
4. **过滤条件参数化** — 使用 `COALESCE` 或 `CASE WHEN :param IS NULL` 模式处理可选过滤
5. **幂等写入** — 所有 Engine 写入使用 `ON CONFLICT` 保证重复执行安全
6. **DAO 不管事务** — 事务由 service 层管理，DAO 只接收 session 执行查询
7. **ORM 方法返回 Model，Core 方法返回 Row** — service 层统一转换为 Pydantic schema
