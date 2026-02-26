# Refactor: MongoDB → PostgreSQL (Snapshot 归属 zca)

## 背景

z_code_analyzer 用 MongoDB 存 snapshot 元数据，vulnsentinel 用 PostgreSQL 且维护了一套重复的 Snapshot 模型/DAO/Service。两套数据库存同样的东西，增加运维复杂度。

**目标**：去掉 MongoDB，snapshot 全归 zca 管（模型、DAO、读写），sentinel 通过单向依赖调 zca 的公开接口。

---

## 设计决策

| 决策 | 结论 |
|---|---|
| snapshot 归属 | 模型 + DAO + 读写全在 zca，sentinel 不维护 |
| 依赖方向 | sentinel → zca（单向），zca 不知道 sentinel 存在 |
| 是否建 shared 层 | 不建。等 agent/LLM 共享时再建 |
| Snapshot 表字段 | 去掉 `project_id` FK、`is_active`、`trigger_type`、`storage_path` |
| status enum | 加 `"failed"` 值 |
| 表隔离 | zca 用独立 `ZCABase`，`create_all` 只建 snapshots 表 |
| PG 实例生命周期 | 启动时创建一次，全局复用 |
| sentinel 查 snapshot | 调 zca 的 `SnapshotManager.find_snapshot()` / `list_snapshots()` |
| sentinel 查调用图 | 调 zca 的 `GraphStore` 方法 |
| project ↔ snapshot 关联 | 通过 `repo_url` join，不用 FK |

---

## 实施步骤

### Step 1: 新建 zca 的 Snapshot ORM 模型

**新建文件**：
- `z_code_analyzer/models/__init__.py`
- `z_code_analyzer/models/snapshot.py`

内容：
- `ZCABase(DeclarativeBase)` — zca 专用 Base
- `TimestampMixin` — created_at / updated_at
- `Snapshot(TimestampMixin, ZCABase)` — 字段从 MongoDB 1:1 映射

字段清单：

```
id                    UUID PK (gen_random_uuid)
repo_url              TEXT NOT NULL
repo_name             TEXT NOT NULL
version               TEXT NOT NULL
backend               ENUM (svf, joern, introspector, prebuild)
status                ENUM (building, completed, failed)
node_count            INT DEFAULT 0
edge_count            INT DEFAULT 0
fuzzer_names          TEXT[] DEFAULT '{}'
analysis_duration_sec DOUBLE DEFAULT 0
language              TEXT DEFAULT ''
size_bytes            BIGINT DEFAULT 0
error                 TEXT (nullable)
last_accessed_at      TIMESTAMPTZ (nullable)
access_count          INT DEFAULT 0
created_at            TIMESTAMPTZ DEFAULT now()
updated_at            TIMESTAMPTZ DEFAULT now()

UNIQUE (repo_url, version, backend)
INDEX  (last_accessed_at)
```

---

### Step 2: 重写 SnapshotManager

**重写**：`z_code_analyzer/snapshot_manager.py`

构造函数变更：

```python
# 旧
def __init__(self, mongo_uri, db_name, graph_store, log_store)
# 新
def __init__(self, session_factory, graph_store, log_store)
```

方法 1:1 迁移，接口和逻辑不变：

| 方法 | MongoDB 操作 | SQLAlchemy 对应 |
|---|---|---|
| `list_snapshots()` | `find().sort()` | `select().where().order_by()` |
| `find_snapshot()` | `find_one()` | `select().where().first()` |
| `acquire_or_wait()` | `insert_one` + `DuplicateKeyError` | `insert` + `IntegrityError` |
| `_wait_for_ready()` | `find_one` 轮询 | `select` 轮询 |
| `mark_completed()` | `update_one($set)` | `update().values()` |
| `mark_failed()` | `update_one($set)` | `update().values()` |
| `on_snapshot_accessed()` | `$set + $inc` | `values(access_count=access_count+1)` |
| `evict_by_version_limit()` | `find().sort()` + 删除 | `select().order_by()` + 删除 |
| `evict_by_ttl()` | `find({$lt})` | `select().where(<)` |
| `evict_by_disk_pressure()` | 同上 | 同上 |
| `_delete_snapshot()` | `delete_one` | `delete().where()` |
| `close()` | `client.close()` | `engine.dispose()` |

关键变更：
- `_id` (ObjectId str) → `id` (UUID)
- dict 操作 `snap["status"]` → ORM 属性 `snap.status`
- 并发控制：`DuplicateKeyError` → `IntegrityError`

---

### Step 3: 更新 orchestrator.py

**修改**：`z_code_analyzer/orchestrator.py`

约 4 处改动，dict 取值 → ORM 属性：
- `snapshot_doc["_id"]` → `snapshot.id`
- `snapshot_doc["status"]` → `snapshot.status`
- `snapshot_doc.get("backend", "svf")` → `snapshot.backend`
- `snapshot_doc.get("node_count", 0)` → `snapshot.node_count`
- 其余 `snapshot_doc.get(...)` → `snapshot.xxx`

---

### Step 4: 更新 CLI

**修改**：`z_code_analyzer/cli.py`

- `--mongo-uri` 选项 → `--pg-url`
- `_DEFAULT_MONGO_URI` → `_DEFAULT_PG_URL`
- 环境变量 `MONGO_URI` → `ZCA_DATABASE_URL`
- CLI 启动时自建 engine：
  ```python
  engine = create_engine(pg_url)
  ZCABase.metadata.create_all(engine)
  session_factory = sessionmaker(engine)
  ```
- `SnapshotManager(mongo_uri=...)` → `SnapshotManager(session_factory=...)`
- `str(snap["_id"])` → `str(snap.id)`
- `snap.get(...)` → `snap.xxx`

PG 实例创建场景：

| 场景 | 谁建 engine | 谁连 Neo4j |
|---|---|---|
| z-analyze CLI 独立运行 | CLI 入口自己建 | CLI 入口自己连 |
| vulnsentinel 整体运行 | app 启动时统一建 | ReachabilityEngine lazy init |

---

### Step 5: 删除 vulnsentinel 的 snapshot 体系

**删除文件**（7 个）：
- `vulnsentinel/models/snapshot.py`
- `vulnsentinel/dao/snapshot_dao.py`
- `vulnsentinel/services/snapshot_service.py`
- `vulnsentinel/api/schemas/snapshot.py`
- `vulnsentinel/api/routers/snapshots.py`
- `tests/vulnsentinel/test_snapshot_dao.py`
- `tests/vulnsentinel/test_snapshot_service.py`

**修改 `vulnsentinel/models/__init__.py`**：
- 移除 `from vulnsentinel.models.snapshot import Snapshot`
- 移除 `__all__` 中的 `"Snapshot"`

**修改 `vulnsentinel/api/__init__.py`**：
- 移除 `snapshots` import（line 20）
- 移除 `app.include_router(snapshots.router, ...)` (line 81)

**修改 `vulnsentinel/api/deps.py`**：
- 删除 `SnapshotDAO` / `SnapshotService` import
- 删除 `_snapshot_dao = SnapshotDAO()`
- 删除 `_snapshot_service = SnapshotService(_snapshot_dao)`
- 删除 `def get_snapshot_service()`

**修改 `vulnsentinel/api/routers/projects.py`**：
- 删除 `/{project_id}/snapshots` 相关端点（GET / POST）
- 等前端需要时再加（调 zca 接口）

---

### Step 6: 更新 schema.sql

**修改**：`docs/vulnsentinel/database/schema.sql`

- snapshots 表：去掉 `project_id`、`is_active`、`trigger_type`、`storage_path` 列
- `snapshot_status` enum 加 `'failed'`
- 去掉 `snapshot_trigger` enum 定义
- 去掉 `idx_snapshots_project`、`idx_snapshots_active` 索引
- 注释标明 snapshots 表归 z_code_analyzer 管

---

### Step 7: 更新 pyproject.toml

**修改**：`pyproject.toml`

- 去掉 `"pymongo>=4.0"` 依赖

---

### Step 8: 更新 z_code_analyzer/__init__.py

**修改**：`z_code_analyzer/__init__.py`

- SnapshotManager 导出不变（构造函数签名变了但公开方法不变）

---

### Step 9: 重写测试

**重写**：`tests/test_snapshot_manager.py`

- MongoDB fixture → SQLite in-memory（`aiosqlite`，已在 dev deps）
- `ZCABase.metadata.create_all(engine)` 建 snapshots 表
- 测试逻辑不变，assert 从 dict → ORM 属性
- 去掉 `needs_mongo` skip marker

---

## 涉及文件清单

| 操作 | 文件 |
|---|---|
| **新建** | `z_code_analyzer/models/__init__.py` |
| **新建** | `z_code_analyzer/models/snapshot.py` |
| **重写** | `z_code_analyzer/snapshot_manager.py` |
| **修改** | `z_code_analyzer/orchestrator.py` |
| **修改** | `z_code_analyzer/cli.py` |
| **修改** | `z_code_analyzer/__init__.py` |
| **删除** | `vulnsentinel/models/snapshot.py` |
| **删除** | `vulnsentinel/dao/snapshot_dao.py` |
| **删除** | `vulnsentinel/services/snapshot_service.py` |
| **删除** | `vulnsentinel/api/schemas/snapshot.py` |
| **删除** | `vulnsentinel/api/routers/snapshots.py` |
| **删除** | `tests/vulnsentinel/test_snapshot_dao.py` |
| **删除** | `tests/vulnsentinel/test_snapshot_service.py` |
| **修改** | `vulnsentinel/models/__init__.py` |
| **修改** | `vulnsentinel/api/__init__.py` |
| **修改** | `vulnsentinel/api/deps.py` |
| **修改** | `vulnsentinel/api/routers/projects.py` |
| **修改** | `docs/vulnsentinel/database/schema.sql` |
| **修改** | `pyproject.toml` |
| **重写** | `tests/test_snapshot_manager.py` |

---

## 验证

1. `python -c "from z_code_analyzer import SnapshotManager"` — import 成功
2. `pytest tests/test_snapshot_manager.py -v` — 全部通过（无需 MongoDB）
3. `pytest tests/ -v` — 全量测试通过
4. `ruff check .` — lint 通过
5. `grep -r "from vulnsentinel.*snapshot" vulnsentinel/` — 无残留引用
