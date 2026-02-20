# API 层设计

> REST API 层，基于 FastAPI，连接前端与 Service 层。负责认证、请求校验、响应序列化、错误映射。

## 设计约定

### URL 规范

- 前缀：`/api/v1`
- 风格：kebab-case（`/upstream-vulns`，`/client-vulns`）
- 资源名复数（`/libraries`，`/projects`）
- 嵌套资源最多一层（`/projects/{id}/snapshots`）

### 认证

- Bearer token：`Authorization: Bearer <access_token>`
- 使用 `HTTPBearer(auto_error=False)` 提取 token，OpenAPI UI 自动支持认证按钮
- 通过 `Depends(get_current_user)` 声明需要认证的端点
- `POST /auth/login` 和 `POST /auth/refresh` 无需认证

### 分页

列表端点统一使用 cursor-based 分页：

```
GET /api/v1/libraries?cursor=xxx&page_size=20
```

响应格式：

```json
{
  "data": [...],
  "meta": {
    "next_cursor": "abc...",
    "has_more": true,
    "total": 42
  }
}
```

- `next_cursor`：下一页游标，末页为 `null`
- `has_more`：是否有下一页
- `total`：总数（部分端点无 total 则省略）

### 单资源响应

扁平返回，不包裹在 `data` 字段中：

```json
{
  "id": "...",
  "name": "curl",
  "repo_url": "https://github.com/curl/curl"
}
```

### 错误响应

```json
{
  "detail": "library not found"
}
```

ServiceError 子类 → HTTP 状态码映射（通过 `__mro__` 遍历，支持子类匹配）：

| Exception | HTTP Status |
|-------------|-------------|
| NotFoundError | 404 |
| ConflictError | 409 |
| ValidationError | 422 |
| AuthenticationError | 401 |
| InvalidCursorError | 422 |
| RequestValidationError | 422 |

所有错误统一返回 `{"detail": str}` 格式，包括 FastAPI 自身的请求校验错误。

### 序列化

- Pydantic v2 schemas，`model_config = ConfigDict(from_attributes=True)`
- ORM Model → Pydantic Schema 转换在 router 层完成
- Service 返回 ORM Model 或 dict，API 层负责序列化

---

## 目录结构

```
vulnsentinel/api/
  __init__.py          # create_app()
  deps.py              # get_session, get_current_user, get_*_service
  errors.py            # ServiceError → HTTP exception handler
  schemas/
    __init__.py
    common.py          # PageMeta, PaginatedResponse
    auth.py
    library.py
    project.py
    snapshot.py
    event.py
    upstream_vuln.py
    client_vuln.py
    stats.py
  routers/
    __init__.py
    auth.py
    libraries.py
    projects.py
    snapshots.py
    events.py
    upstream_vulns.py
    client_vulns.py
    stats.py
```

---

## DI 容器设计

### 生命周期

```
应用启动 (lifespan)
  │
  ├─ 创建 AsyncEngine + async_sessionmaker（含连接池配置）
  ├─ 实例化 8 个 DAO（模块级单例）
  ├─ 实例化 8 个 Service（注入 DAO）
  ├─ AuthService.ensure_admin_exists()
  │
  ▼
请求处理
  │
  ├─ Depends(get_session) → AsyncSession（per-request）
  ├─ Depends(get_current_user) → User（HTTPBearer + 认证端点）
  ├─ Depends(get_*_service) → Service（模块级单例）
  │
  ▼
应用关闭
  │
  └─ await dispose_engine()  # 关闭连接池，防止连接泄漏
```

### 事务管理

每个请求一个 session，通过 `get_session` 依赖注入：

```python
async def get_session():
    if _session_factory is None:
        raise RuntimeError("call init_session_factory() before handling requests")
    async with _session_factory() as session:
        async with session.begin():
            yield session
```

自动 commit（正常退出）或 rollback（异常退出）。

### 连接池配置

```python
_engine = create_async_engine(
    url,
    pool_pre_ping=True,    # 防止连接池中的死连接
    pool_size=10,           # 常驻连接数
    max_overflow=20,        # 突发最大额外连接
    pool_recycle=1800,      # 30 分钟回收，防止数据库侧超时
)
```

### Service 依赖注入

Service 为无状态单例，在 `deps.py` 中以模块级变量实例化：

```python
# deps.py
_user_dao = UserDAO()
_library_dao = LibraryDAO()
...

_auth_service = AuthService(_user_dao)
_library_service = LibraryService(_library_dao, _project_dao, _project_dependency_dao, _event_dao)
...

def get_auth_service() -> AuthService:
    return _auth_service
```

---

## 错误处理

`errors.py` 注册三类 exception handler：

```python
# 1. ServiceError — 通过 __mro__ 遍历匹配子类，比 type() 精确匹配更健壮
_STATUS_MAP = {
    NotFoundError: 404,
    ConflictError: 409,
    ValidationError: 422,
    AuthenticationError: 401,
}

async def _service_error_handler(_request, exc):
    status = 500
    for cls in type(exc).__mro__:
        if cls in _STATUS_MAP:
            status = _STATUS_MAP[cls]
            break
    return JSONResponse(status_code=status, content={"detail": str(exc)})

# 2. RequestValidationError — 覆盖 FastAPI 默认行为，统一为 {"detail": str} 格式
async def _validation_error_handler(_request, exc):
    errors = exc.errors()
    messages = [f"{' → '.join(str(p) for p in e['loc'])}: {e['msg']}" for e in errors]
    return JSONResponse(status_code=422, content={"detail": "; ".join(messages)})

# 3. InvalidCursorError — 非法分页游标 → 422
async def _invalid_cursor_handler(_request, exc):
    return JSONResponse(status_code=422, content={"detail": str(exc)})
```

---

## 端点总览（21 个）

### 1. Auth (`/api/v1/auth`)

| Method | URL | Handler | 认证 | Service 方法 |
|--------|-----|---------|------|-------------|
| POST | `/login` | `login` | ✗ | AuthService.login |
| POST | `/refresh` | `refresh` | ✗ | AuthService.refresh |
| GET | `/me` | `me` | ✓ | AuthService.get_current_user |

### 2. Libraries (`/api/v1/libraries`)

| Method | URL | Handler | Service 方法 |
|--------|-----|---------|-------------|
| GET | `/` | `list_libraries` | LibraryService.list |
| GET | `/{id}` | `get_library` | LibraryService.get |

### 3. Projects (`/api/v1/projects`)

| Method | URL | Handler | Service 方法 |
|--------|-----|---------|-------------|
| GET | `/` | `list_projects` | ProjectService.list |
| GET | `/{id}` | `get_project` | ProjectService.get |
| POST | `/` | `create_project` | ProjectService.create |
| GET | `/{id}/snapshots` | `list_project_snapshots` | SnapshotService.list_by_project |
| POST | `/{id}/snapshots` | `create_project_snapshot` | SnapshotService.create |
| GET | `/{id}/vulnerabilities` | `list_project_vulns` | ClientVulnService.list_by_project |

### 4. Snapshots (`/api/v1/snapshots`)

| Method | URL | Handler | Service 方法 |
|--------|-----|---------|-------------|
| GET | `/{id}` | `get_snapshot` | SnapshotService.get |

### 5. Events (`/api/v1/events`)

| Method | URL | Handler | Service 方法 |
|--------|-----|---------|-------------|
| GET | `/` | `list_events` | EventService.list |
| GET | `/{id}` | `get_event` | EventService.get |

### 6. Upstream Vulns (`/api/v1/upstream-vulns`)

| Method | URL | Handler | Service 方法 |
|--------|-----|---------|-------------|
| GET | `/` | `list_upstream_vulns` | UpstreamVulnService.list |
| GET | `/{id}` | `get_upstream_vuln` | UpstreamVulnService.get |

### 7. Client Vulns (`/api/v1/client-vulns`)

| Method | URL | Handler | Service 方法 |
|--------|-----|---------|-------------|
| GET | `/` | `list_client_vulns` | ClientVulnService.list |
| GET | `/stats` | `get_client_vuln_stats` | ClientVulnService.get_stats |
| GET | `/{id}` | `get_client_vuln` | ClientVulnService.get |
| PATCH | `/{id}/status` | `update_client_vuln_status` | ClientVulnService.update_status |

> 注意：`/stats` 必须定义在 `/{id}` 之前，否则 FastAPI 会把 "stats" 当作 UUID 参数解析。

### 8. Stats (`/api/v1/stats`)

| Method | URL | Handler | Service 方法 |
|--------|-----|---------|-------------|
| GET | `/dashboard` | `get_dashboard` | StatsService.get_dashboard |

---

## Pydantic Schema 定义

### common.py

```python
class PageMeta(BaseModel):
    next_cursor: str | None
    has_more: bool
    total: int | None = None

class PaginatedResponse(BaseModel, Generic[T]):
    data: list[T]
    meta: PageMeta
```

### auth.py

```python
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenPairResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    role: str
    created_at: datetime
```

### library.py

```python
class LibraryListItem(BaseModel):
    id: uuid.UUID
    name: str
    repo_url: str
    platform: str
    default_branch: str
    latest_tag_version: str | None
    latest_commit_sha: str | None
    monitoring_since: datetime
    last_activity_at: datetime | None
    created_at: datetime

class LibraryUsedBy(BaseModel):
    project_id: uuid.UUID
    project_name: str | None  # None when project deleted (FK SET NULL)
    constraint_expr: str | None
    resolved_version: str | None
    constraint_source: str

class LibraryDetail(LibraryListItem):
    used_by: list[LibraryUsedBy]
    events_tracked: int
```

### project.py

```python
class DependencyInputSchema(BaseModel):
    library_name: str
    library_repo_url: str
    constraint_expr: str | None = None
    resolved_version: str | None = None
    constraint_source: str = "manifest"
    platform: str = "github"
    default_branch: str = "main"

class CreateProjectRequest(BaseModel):
    name: str
    repo_url: str
    organization: str | None = None
    contact: str | None = None
    platform: str = "github"
    default_branch: str = "main"
    dependencies: list[DependencyInputSchema] | None = None

class ProjectResponse(BaseModel):
    """Base project fields (used for create response)."""
    id: uuid.UUID
    name: str
    organization: str | None
    repo_url: str
    platform: str
    default_branch: str
    contact: str | None
    current_version: str | None
    monitoring_since: datetime
    last_update_at: datetime | None
    created_at: datetime

class ProjectListItem(ProjectResponse):
    """Project with computed counts (used in list/detail)."""
    deps_count: int
    vuln_count: int

class ProjectDetail(ProjectListItem):
    pass
```

### snapshot.py

```python
class CreateSnapshotRequest(BaseModel):
    repo_url: str
    repo_name: str
    version: str
    backend: str
    trigger_type: str | None = None

class SnapshotResponse(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID | None
    repo_url: str
    repo_name: str
    version: str
    backend: str
    status: str
    trigger_type: str | None
    is_active: bool
    storage_path: str | None
    node_count: int
    edge_count: int
    fuzzer_names: list[str]
    analysis_duration_sec: float
    language: str
    size_bytes: int
    error: str | None
    created_at: datetime
```

### event.py

```python
class EventListItem(BaseModel):
    id: uuid.UUID
    library_id: uuid.UUID
    type: str
    ref: str
    source_url: str | None
    author: str | None
    title: str
    message: str | None
    classification: str | None
    confidence: float | None
    is_bugfix: bool
    created_at: datetime

class EventDetail(EventListItem):
    related_issue_ref: str | None
    related_issue_url: str | None
    related_pr_ref: str | None
    related_pr_url: str | None
    related_commit_sha: str | None
    related_vulns: list[UpstreamVulnListItem]
```

### upstream_vuln.py

```python
class UpstreamVulnListItem(BaseModel):
    id: uuid.UUID
    event_id: uuid.UUID
    library_id: uuid.UUID
    commit_sha: str
    vuln_type: str | None
    severity: str | None
    status: str
    summary: str | None
    detected_at: datetime
    published_at: datetime | None
    created_at: datetime

class ClientImpactItem(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    status: str | None
    pipeline_status: str
    is_affected: bool | None

class UpstreamVulnDetail(UpstreamVulnListItem):
    affected_versions: str | None
    reasoning: str | None
    error_message: str | None
    upstream_poc: dict[str, Any] | None
    client_impact: list[ClientImpactItem]
```

### client_vuln.py

```python
class ClientVulnListItem(BaseModel):
    id: uuid.UUID
    upstream_vuln_id: uuid.UUID
    project_id: uuid.UUID
    pipeline_status: str
    status: str | None
    is_affected: bool | None
    created_at: datetime

class ClientVulnDetail(ClientVulnListItem):
    constraint_expr: str | None
    constraint_source: str | None
    resolved_version: str | None
    fix_version: str | None
    verdict: str | None
    reachable_path: dict[str, Any] | None
    poc_results: dict[str, Any] | None
    report: dict[str, Any] | None
    error_message: str | None
    recorded_at: datetime | None
    reported_at: datetime | None
    confirmed_at: datetime | None
    confirmed_msg: str | None
    fixed_at: datetime | None
    fixed_msg: str | None
    upstream_vuln: UpstreamVulnListItem

class VulnStatsResponse(BaseModel):
    total_recorded: int
    total_reported: int
    total_confirmed: int
    total_fixed: int

class UpdateStatusRequest(BaseModel):
    status: str
    msg: str | None = None

class ClientVulnListResponse(BaseModel):
    data: list[ClientVulnListItem]
    meta: PageMeta
    stats: VulnStatsResponse
```

### stats.py

```python
class DashboardResponse(BaseModel):
    projects_count: int
    libraries_count: int
    vuln_recorded: int
    vuln_reported: int
    vuln_confirmed: int
    vuln_fixed: int
```

---

## App Factory

```python
# vulnsentinel/api/__init__.py

@asynccontextmanager
async def _lifespan(app: FastAPI):
    factory = init_session_factory()  # 创建连接池
    async with factory() as session:
        async with session.begin():
            await get_auth_service().ensure_admin_exists(session)
    yield
    await dispose_engine()  # 关闭连接池，防止连接泄漏

def create_app() -> FastAPI:
    app = FastAPI(
        title="VulnSentinel",
        docs_url="/api/v1/docs",
        openapi_url="/api/v1/openapi.json",
        lifespan=_lifespan,
    )

    register_error_handlers(app)

    app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(libraries_router, prefix="/api/v1/libraries", tags=["libraries"])
    app.include_router(projects_router, prefix="/api/v1/projects", tags=["projects"])
    app.include_router(snapshots_router, prefix="/api/v1/snapshots", tags=["snapshots"])
    app.include_router(events_router, prefix="/api/v1/events", tags=["events"])
    app.include_router(upstream_vulns_router, prefix="/api/v1/upstream-vulns", tags=["upstream-vulns"])
    app.include_router(client_vulns_router, prefix="/api/v1/client-vulns", tags=["client-vulns"])
    app.include_router(stats_router, prefix="/api/v1/stats", tags=["stats"])

    return app
```

---

## 设计决策汇总

| 决策 | 选择 | 理由 |
|------|------|------|
| URL 风格 | kebab-case `/upstream-vulns` | REST 惯例 |
| 认证 | `HTTPBearer(auto_error=False)` + `Depends(get_current_user)` | OpenAPI 自动支持认证按钮，缺 token 返回 401 |
| 分页响应 | `{ data, meta: { next_cursor, has_more, total } }` | 列表统一格式 |
| 单资源响应 | 扁平返回 | 避免无意义嵌套 |
| Count | 合并到 list 的 meta.total | 减少冗余端点 |
| Snapshot 创建 | 仅 `POST /projects/{id}/snapshots` | snapshot 必属于 project |
| Status 更新 | PATCH | 部分更新 |
| DI | 模块级单例 DAO/Service + `Depends()` | 无状态，构造一次 |
| ORM → Schema | `from_attributes=True` + router 层转换 | Service 不变 |
| Schema 继承 | Detail 继承 ListItem（DRY） | `ProjectDetail(ProjectListItem)`, `ClientVulnDetail(ClientVulnListItem)` |
| 错误处理 | `__mro__` 遍历 + 3 handler | 支持子类匹配，统一 `{"detail": str}` 格式 |
| 唯一约束保护 | Service 层预检查 → ConflictError (409) | 防止 IntegrityError 泄漏为 500 |
| 连接池 | `pool_pre_ping=True`, size=10, overflow=20, recycle=1800 | 生产级配置 |
| 安全退出 | `assert` → `RuntimeError`; lifespan 中 `dispose_engine()` | `-O` 安全，防连接泄漏 |
| OpenAPI | `/api/v1/docs` | 版本化文档 |
| `/stats` 路由顺序 | 定义在 `/{id}` 之前 | 防止 FastAPI 将 "stats" 解析为 UUID |
