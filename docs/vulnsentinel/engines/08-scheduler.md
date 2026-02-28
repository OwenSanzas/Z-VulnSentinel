# 调度层设计文档

## 1. 动机

7 个引擎已全部实现，每个都有批处理方法，但**没有任何东西调用它们**。

当前状态：

- `_lifespan` 只做 DB 初始化 + admin 创建，不启动后台任务
- `deps.py` 只实例化了 `EventCollectorRunner`，其余 runner 甚至没有被 wire up
- 没有 CLI 入口、没有 `asyncio.create_task`、没有定时循环
- 引擎之间的数据流靠数据库状态隐式传递（上游写 status → 下游 poll），但没人触发 poll

**结果：系统有完整的零件，但没有发动机。注册一个项目后什么都不会发生。**

需要一个统一的调度层把所有引擎串成活的流水线：

- 定期轮询每个引擎的 batch 方法
- 上游产出结果后立即唤醒下游，降低端到端延迟
- 统一管理生命周期（启动 / 停止 / 异常恢复）

---

## 2. 服务启动流程

```
                          uvicorn main:app
                                │
                                ▼
                    ┌───────────────────────┐
                    │     create_app()      │
                    │  setup_logging()      │
                    │  register routers     │
                    │  register middleware  │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   _lifespan(app)      │
                    │                       │
                    │  1. init_session_factory()
                    │     └─ 创建 AsyncEngine + session_factory
                    │                       │
                    │  2. ensure_admin_exists()
                    │     └─ 首次启动创建 admin 用户
                    │                       │
                    │  3. create_scheduler(factory)  ← 新增
                    │     ├─ 实例化所有 Runner
                    │     ├─ 构建 EngineLoop 链
                    │     └─ 创建 asyncio.Event 信号链
                    │                       │
                    │  4. scheduler.start()           ← 新增
                    │     └─ asyncio.create_task × 7
                    │                       │
                    │  ─── yield ───  (服务运行中)
                    │                       │
                    │  5. scheduler.stop()            ← 新增
                    │     └─ cancel 所有 task
                    │                       │
                    │  6. dispose_engine()
                    │     └─ 关闭连接池
                    └───────────────────────┘
```

---

## 3. 端到端业务流程

### 3.1 完整 Pipeline 总览

```
用户注册项目
POST /api/v1/projects/
        │
        ▼
┌──────────────────┐  library +          ┌──────────────────┐  event             ┌──────────────────┐
│  Dependency      │  project_dependency │  Event           │  (unclassified)    │  Event           │
│  Scanner         │ ──────────────────→ │  Collector       │ ─────────────────→ │  Classifier      │
│                  │                     │                  │                    │                  │
│ 扫描 manifest    │                     │ 拉取 commit/PR/  │                    │ LLM 判断是否为   │
│ 发现依赖         │                     │ tag/issue        │                    │ security_bugfix  │
└──────────────────┘                     └──────────────────┘                    └────────┬─────────┘
                                                                                         │
                                                            security_bugfix event        │
                    ┌────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────┐  upstream_vuln      ┌──────────────────┐  client_vuln       ┌──────────────────┐
│  Vuln            │  (published)        │  Impact          │  (pending)         │  Reachability    │
│  Analyzer        │ ──────────────────→ │  Engine          │ ─────────────────→ │  Runner          │
│                  │                     │                  │                    │                  │
│ LLM 分析漏洞类型 │                     │ 版本约束比对      │                    │ 调用图 BFS       │
│ 严重度/影响版本  │                     │ 判断受影响项目    │                    │ 可达性分析       │
└──────────────────┘                     └──────────────────┘                    └────────┬─────────┘
                                                                                         │
                                                           verified client_vuln          │
                    ┌────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────┐
│  Notification    │
│  Runner          │
│                  │
│ 发送邮件预警      │
│ 包含漏洞详情 +   │
│ 调用路径 + 修复   │
│ 建议             │
└──────────────────┘
```

### 3.2 各引擎写入与下游轮询条件

| 上游 | 写入 | 下游轮询条件 |
|------|------|-------------|
| DependencyScanner | `library` 记录 + `project_dependency` 关联 | EventCollector: `LibraryService.list_due_for_collect()` |
| EventCollector | `event` 记录 (`classification = NULL`) | Classifier: `EventService.list_unclassified()` |
| Classifier | `event.classification = security_bugfix`, `is_bugfix = true` | VulnAnalyzer: `EventService.list_bugfix_without_vuln()` |
| VulnAnalyzer | `upstream_vuln` (`status = published`) | ImpactEngine: `UpstreamVulnService.list_published_without_impact()` |
| ImpactEngine | `client_vuln` (`pipeline_status = pending`) | Reachability: `ClientVulnService.list_pending_pipeline()` |
| Reachability | `client_vuln` (`pipeline_status = verified`, `status = recorded`) | Notification: `ClientVulnService.list_verified_unnotified()` |

---

## 4. 状态转移图

### 4.1 Event 生命周期

```
EventCollector 创建
        │
        ▼
┌───────────────┐     EventClassifier (LLM)
│ classification│ ─────────────────────────────┐
│    = NULL     │                              │
│ (unclassified)│                              ▼
└───────────────┘                    ┌─────────────────────┐
                                     │ classification = ?   │
                                     │                     │
                                     ├─ security_bugfix ──→ is_bugfix = true  ──→ VulnAnalyzer 消费
                                     ├─ normal_bugfix   ──→ is_bugfix = false
                                     ├─ refactor        ──→ is_bugfix = false
                                     ├─ feature         ──→ is_bugfix = false
                                     └─ other           ──→ is_bugfix = false
```

只有 `security_bugfix` 会进入后续漏洞分析流程，其余分类归档不再处理。

### 4.2 UpstreamVuln 生命周期

```
VulnAnalyzer 创建
        │
        ▼
┌───────────────┐                      ┌──────────────────┐
│    status     │   分析完成 + publish  │     status       │
│  = analyzing  │ ───────────────────→ │   = published    │
│               │                      │                  │
│ 填充中：       │                      │ published_at 打戳 │
│ vuln_type     │                      │                  │
│ severity      │                      │ ImpactEngine 消费 │
│ affected_ver  │                      └──────────────────┘
│ affected_func │
│ upstream_poc  │         分析失败
│ summary       │ ─────────────────→ error_message 记录
│ reasoning     │                    status 仍为 analyzing
└───────────────┘                    下一轮重试
```

### 4.3 ClientVuln 生命周期（双状态机）

ClientVuln 有两个独立的状态字段：

- **`pipeline_status`**：系统自动分析流程（引擎驱动）
- **`status`**：业务状态（引擎 finalize 设初始值，后续由维护者手动推进）

```
ImpactEngine 创建
        │
        ▼
 pipeline_status                              status
 ═══════════════                              ══════

 ┌─────────┐                                   NULL
 │ pending  │                                    │
 └────┬─────┘                                    │
      │ ReachabilityRunner 开始分析               │
      ▼                                          │
 ┌──────────────┐                                │
 │path_searching│                                │
 └────┬─────────┘                                │
      │ 调用图 BFS 分析完成                        │
      │                                          │
      ├─── 路径可达 ──→ ┌──────────┐    finalize  │     ┌──────────┐   维护者   ┌───────────┐   维护者   ┌───────┐
      │                │ verified │ ──────────→  ├───→ │ recorded │ ────────→ │ reported  │ ────────→ │ confirmed │
      │                └──────────┘              │     └──────────┘           └───────────┘           └─────┬─────┘
      │                                         │        Notification                                      │ 维护者
      │                                         │        Runner 发送邮件                                    ▼
      │                                         │                                                    ┌───────┐
      └─── 路径不可达 → ┌────────────┐  finalize │                                                    │ fixed │
                       │ not_affect │ ────────→ └───→ not_affect                                     └───────┘
                       └────────────┘                 (终态)
```

**时间戳打点：**

| 转移 | 时间戳字段 |
|------|-----------|
| → `recorded` | `recorded_at`, `analysis_completed_at` |
| → `reported` | `reported_at` (NotificationRunner 发送邮件后) |
| → `confirmed` | `confirmed_at`, `confirmed_msg` (维护者确认) |
| → `fixed` | `fixed_at`, `fixed_msg` (维护者标记修复) |
| → `not_affect` | `not_affect_at`, `analysis_completed_at` |

**状态转移约束（Service 层强制）：**

```python
_VALID_TRANSITIONS = {
    "recorded":  ["reported"],
    "reported":  ["confirmed"],
    "confirmed": ["fixed"],
}
# fixed 和 not_affect 是终态，无法再转移
```

### 4.4 Library 与 Project（无状态枚举，靠时间戳驱动）

```
Library:
  monitoring_since ──── 创建时打戳
  last_activity_at ──── EventCollector 每次采集后更新
  latest_commit_sha ─── EventCollector 更新（最新 commit）
  latest_tag_version ── EventCollector 更新（最新 tag）

  调度判断：last_activity_at 距今 > 75 分钟 → 列入本轮采集

Project:
  monitoring_since ──── 创建时打戳
  last_scanned_at ───── DependencyScanner 每次扫描后更新
  auto_sync_deps ────── true: 定时扫描 / false: 跳过

  调度判断：auto_sync_deps = true AND (last_scanned_at IS NULL OR 距今 > 1 小时) → 列入本轮扫描
```

---

## 5. 调度触发流程

### 5.1 双层调度机制

```
                    ┌─────────────────────────────────────────────┐
                    │              EngineLoop                     │
                    │                                             │
                    │   ┌─────────────────────────────────┐      │
                    │   │  await wait_for(                │      │
                    │   │    trigger.wait(),              │      │
                    │   │    timeout=interval             │      │
                    │   │  )                              │      │
                    │   │                                 │      │
                    │   │  ┌──────────┐   ┌───────────┐  │      │
                    │   │  │ 上游唤醒  │   │ 超时到期   │  │      │
                    │   │  │ (链式)   │   │ (兜底)    │  │      │
                    │   │  └────┬─────┘   └─────┬─────┘  │      │
                    │   │       └───────┬────────┘        │      │
                    │   └──────────────┬──────────────────┘      │
                    │                  │                          │
                    │                  ▼                          │
                    │          run_fn() → processed               │
                    │                  │                          │
                    │         processed > 0?                      │
                    │          ┌───┴───┐                          │
                    │         Yes     No                          │
                    │          │       │                          │
                    │          ▼       └──→ (回到等待)             │
                    │   downstream.set()                          │
                    │   (唤醒下游引擎)                              │
                    │          │                                  │
                    │          └──→ (回到等待)                     │
                    └─────────────────────────────────────────────┘
```

### 5.2 引擎链式唤醒拓扑

```
  asyncio.Event 信号链：

  DepScanner ──trigger_collect──→ EventCollector ──trigger_classify──→ Classifier
                                                                         │
                                                              trigger_analyze
                                                                         │
  Notification ←──trigger_notify── Reachability ←──trigger_reach── Impact ←──┘
                                                                  Engine    trigger_impact
                                                                              │
                                                                     VulnAnalyzer
```

每个箭头是一个 `asyncio.Event`，上游 `processed > 0` 时 `.set()`，下游 `.wait()` 被唤醒。

### 5.3 典型场景时序

**场景：用户注册新项目 → 端到端漏洞预警**

```
Time ─────────────────────────────────────────────────────────────────────→

T+0     POST /api/v1/projects/  (用户注册项目)
        │
T+600s  DepScanner 轮询 → 发现 last_scanned_at IS NULL → 扫描 manifest
        │ 产出: 3 个 library + project_dependency
        │ trigger_collect.set()
        │
T+600s  EventCollector 被唤醒 → 3 个 library 都是新的 → 拉取各自 commit/PR/tag
        │ 产出: 150 个 event (classification=NULL)
        │ trigger_classify.set()
        │
T+600s  Classifier 被唤醒 → 取 10 个 unclassified event → LLM 分类
        │ 其中 2 个 → security_bugfix (is_bugfix=true)
        │ trigger_analyze.set()
        │
T+600s  VulnAnalyzer 被唤醒 → 取 2 个 bugfix event → LLM 分析漏洞
        │ 产出: 2 个 upstream_vuln (status=published)
        │ trigger_impact.set()
        │
T+600s  ImpactEngine 被唤醒 → 版本约束比对 → 1 个项目受影响
        │ 产出: 1 个 client_vuln (pipeline_status=pending)
        │ trigger_reach.set()
        │
T+600s  Reachability 被唤醒 → BFS 搜索调用路径 → 路径可达
        │ client_vuln → verified, status=recorded
        │ trigger_notify.set()
        │
T+600s  Notification 被唤醒 → 发送邮件预警
        │ client_vuln → status=reported, reported_at 打戳
        │
        ▼ 完成 — 从注册到预警，链式触发全程秒级流转
          （最坏情况：首次 DepScanner 轮询等待最多 3600s）
```

---

## 6. 现有引擎清单 + 批处理接口

所有引擎的 batch 方法接口已统一，均接受 `session_factory` 并返回处理数量。

| Runner | 方法 | 签名 |
|--------|------|------|
| `DependencyScanner` | `run` | `(session, project_id) → ScanResult` |
| `EventCollectorRunner` | `run_all` | `(session_factory, client) → list[CollectResult]` |
| `EventClassifierRunner` | `classify_batch` | `(session_factory, limit=10, concurrency=3) → list[tuple[Event, ClassificationResult]]` |
| `VulnAnalyzerRunner` | `analyze_batch` | `(session_factory, limit=10, concurrency=3) → list[tuple[Event, list[VulnAnalysisResult]]]` |
| `ImpactRunner` | `run_batch` | `(session_factory, limit=20) → int` |
| `ReachabilityRunner` | `run_batch` | `(session_factory, limit=20) → int` |
| `NotificationRunner` | `run_batch` | `(session_factory, limit=20) → int` |

**注意：** `DependencyScanner` 没有全局 batch 方法，而是 per-project 的 `run(session, project_id)`。调度层需要自行查询待扫描的项目列表并逐个调用。

---

## 7. 调度策略

采用两层机制：

- **定时轮询（兜底）**：每个引擎有独立的 interval，到时间调用 batch 方法。保证即使链式触发丢失（进程重启、异常中断），也不会有任务卡住。
- **链式触发（低延迟）**：上游 batch 返回 processed > 0 时，立即唤醒下游。大多数情况下数据秒级流转。

### 技术方案

纯 `asyncio`，不引入 APScheduler / Celery / 任何新依赖：

- 每个引擎一个 `asyncio.Task`，运行无限循环
- 用 `asyncio.Event` 做链式唤醒信号
- `asyncio.wait_for(event.wait(), timeout=interval)` 实现"等触发或超时"

选择理由：
- 所有引擎已经是 async 的，天然适配
- 不需要分布式调度（单进程足够）
- 零额外依赖，部署简单

---

## 8. 调度器核心设计

### EngineLoop — 单个引擎的调度循环

```python
class EngineLoop:
    """单个引擎的调度循环。"""

    def __init__(
        self,
        name: str,
        run_fn: Callable[[], Awaitable[int]],
        interval: float,
        downstream: asyncio.Event | None = None,
    ):
        self.name = name
        self.run_fn = run_fn          # async callable，返回 processed count
        self.interval = interval       # 秒，定时兜底
        self.trigger = asyncio.Event() # 被上游唤醒
        self.downstream = downstream   # 下游的 trigger Event

    async def loop(self) -> None:
        while True:
            # 等 trigger 或 timeout（二者取先）
            try:
                await asyncio.wait_for(self.trigger.wait(), timeout=self.interval)
                self.trigger.clear()
            except asyncio.TimeoutError:
                pass

            try:
                processed = await self.run_fn()
                if processed > 0 and self.downstream:
                    self.downstream.set()  # 唤醒下游
            except Exception:
                logger.exception("engine %s failed", self.name)
                # 不崩溃，等下一轮重试
```

### Scheduler — 统一调度所有引擎

```python
class Scheduler:
    """统一调度所有引擎。"""

    def __init__(self, session_factory, settings, ...):
        # 创建 asyncio.Event 链
        # 构建 EngineLoop 列表，将上游的 downstream 指向下游的 trigger

    async def start(self) -> None:
        """启动所有引擎循环。"""
        self._tasks = [
            asyncio.create_task(loop.loop(), name=f"engine-{loop.name}")
            for loop in self._loops
        ]

    async def stop(self) -> None:
        """取消所有引擎循环并等待退出。"""
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
```

### DependencyScanner 适配

DependencyScanner 是 per-project 的，需要一个适配函数将其包装成统一的 batch 接口：

```python
async def _scan_all_due_projects(
    scanner: DependencyScanner,
    session_factory: async_sessionmaker,
    project_service: ProjectService,
) -> int:
    """查询所有待扫描项目，逐个执行 scan，返回处理数量。"""
    async with session_factory() as session:
        projects = await project_service.list_due_for_scan(session)

    processed = 0
    for project in projects:
        async with session_factory() as session:
            async with session.begin():
                await scanner.run(session, project.id)
                processed += 1
    return processed
```

---

## 9. 生命周期集成

Scheduler 在 FastAPI lifespan 中启动/停止：

```python
@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    factory = init_session_factory()
    auth_svc = get_auth_service()
    async with factory() as session:
        async with session.begin():
            await auth_svc.ensure_admin_exists(session)

    scheduler = create_scheduler(factory)
    await scheduler.start()
    yield
    await scheduler.stop()
    await dispose_engine()
```

当前 `_lifespan`（在 `vulnsentinel/api/__init__.py`）只做 DB 初始化，需要扩展为上述形式。

### 优雅停机流程

```
  SIGTERM / SIGINT
        │
        ▼
  FastAPI 退出 lifespan yield
        │
        ▼
  scheduler.stop()
  ├─ cancel 所有 EngineLoop task
  ├─ 等待当前正在执行的 run_fn 完成（或被 cancel）
  └─ 清理资源
        │
        ▼
  dispose_engine()
  └─ 关闭 SQLAlchemy 连接池
```

---

## 10. 配置

环境变量控制各引擎的轮询间隔：

| 环境变量 | 默认值（秒） | 说明 |
|---------|-------------|------|
| `VULNSENTINEL_SCAN_INTERVAL` | 3600 | DependencyScanner 轮询间隔（per-project 扫描节奏由 `last_scanned_at` 1 小时窗口控制） |
| `VULNSENTINEL_COLLECT_INTERVAL` | 600 | EventCollector 轮询间隔（library 级采集节奏由 `list_due_for_collect` 的 75 分钟窗口控制） |
| `VULNSENTINEL_CLASSIFY_INTERVAL` | 60 | Classifier 兜底间隔 |
| `VULNSENTINEL_ANALYZE_INTERVAL` | 60 | VulnAnalyzer 兜底间隔 |
| `VULNSENTINEL_IMPACT_INTERVAL` | 60 | ImpactEngine 兜底间隔 |
| `VULNSENTINEL_REACHABILITY_INTERVAL` | 120 | Reachability 兜底间隔 |
| `VULNSENTINEL_NOTIFY_INTERVAL` | 60 | Notification 兜底间隔 |

设计原则：

- 上游引擎（Scanner / Collector）间隔较长，因为受 GitHub API rate limit 限制（2 个 token，各 5000 req/hr，合计 10000 req/hr）
- EventCollector 的调度间隔（600s）与 library 级采集间隔（75 分钟）是两层：调度层每 10 分钟查一次有哪些 library 到期，library 自身的 `last_collected_at` 保证同一个 library 不会在 75 分钟内重复采集
- 下游引擎间隔较短，以链式触发为主、定时为辅
- 所有间隔可通过环境变量覆盖，无需重启即可调整（未来可支持热加载）

---

## 11. 渐进实现计划

不一次全链接，分阶段对接验证：

| 阶段 | 链接 | 验证标准 |
|------|------|---------|
| **Phase 1** | Scheduler 框架 + DependencyScanner + EventCollector | 注册项目 → 自动扫描依赖 → library 开始收集事件 |
| **Phase 2** | + Classifier + VulnAnalyzer | 事件被分类 → security_bugfix 产出 UpstreamVuln |
| **Phase 3** | + ImpactEngine + Reachability + Notification | 完整 pipeline 端到端：UpstreamVuln → ClientVuln → 可达性分析 → 邮件通知 |

每个阶段独立可验证，出问题时 blast radius 可控。

---

## 12. 涉及文件

实现时需要修改/新建的文件：

| 文件 | 操作 | 说明 |
|------|------|------|
| `vulnsentinel/scheduler.py` | **新建** | `EngineLoop`、`Scheduler`、`create_scheduler()` |
| `vulnsentinel/api/__init__.py` | **修改** | `_lifespan` 中集成 Scheduler 启动/停止 |
| `vulnsentinel/api/deps.py` | **修改** | 实例化所有 runner（当前只有 EventCollectorRunner） |
| `vulnsentinel/core/settings.py` | **修改** | 添加调度间隔的环境变量配置 |
