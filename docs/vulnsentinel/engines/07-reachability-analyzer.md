# Reachability Analyzer

> **初级设计文档** — 正式实现之前可随时修改。

> 判断客户项目是否能通过调用图到达上游漏洞函数。对应十步流程中的**步骤 8-9（可达性分析）**。

## 概述

Reachability Analyzer 是流水线中紧跟 Impact Engine 的第六个 Engine。Impact Engine 解决了"哪些项目依赖了存在漏洞的库"，Reachability Analyzer 解决"项目代码能否真正调用到漏洞函数"。

这是 VulnSentinel 的核心竞争力：不靠版本号猜测，而是通过调用图分析客户代码是否能真正到达漏洞函数。

**职责：**

- 从 `client_vulns` 表中拉取 `pipeline_status = 'pending'` 的记录
- 确定搜索目标：上游漏洞影响了哪些函数（`affected_functions`）
- 在 Neo4j 调用图中查询：客户项目入口函数 → ... → 漏洞函数是否可达
- 根据可达性结果更新 `client_vulns` 的 `pipeline_status` 和 `is_affected`

**特点：**

- 无 LLM — 纯图查询 + DB 操作
- 核心逻辑实现在 `z_code_analyzer/reachability/`，VulnSentinel 侧只有轻量 Runner 调用其接口
- 双模式设计 — 独立纯函数（z_code_analyzer 暴露）+ 集成 Runner（vulnsentinel 侧）
- 幂等 — 重复处理同一 ClientVuln 不会产生副作用

---

## 模拟业务流程

用一个端到端场景理解 Reachability Analyzer 在流水线中的位置和职责。

**场景设定：** 客户 ACME Corp 有一个 C 项目 `acme-server`，依赖 libcurl。curl 仓库提交了一个 commit，修复了 `lib/urlapi.c` 中 `Curl_parseurl()` 的 heap buffer overflow。

### Step 1 — Event Collector 捕获事件

```
Event {
  type: "commit",
  ref: "a21f318992e7...",
  title: "urlapi: fix heap buffer overflow",
  library: "curl"
}
```

### Step 2 — Event Classifier 判定

```
classification: "security_bugfix", confidence: 0.92
```

### Step 3 — VulnAnalyzer 分析漏洞

```
UpstreamVuln {
  library: curl,
  vuln_type: "buffer_overflow",
  severity: "high",
  summary: "Heap buffer overflow in Curl_parseurl() ...",
  affected_functions: ["Curl_parseurl"],
  commit_sha: "a21f318992e7...",
  status: "published"
}
```

### Step 4 — Impact Engine 创建 ClientVuln

```
acme-server 依赖 curl → 创建 ClientVuln {
  upstream_vuln_id: <上面的 vuln>,
  project_id: <acme-server>,
  pipeline_status: "pending"
}
```

### Step 5 — Reachability Analyzer 开始工作（本文档重点）

**5a. 轮询到 pending 的 ClientVuln**

`ClientVulnService.list_pending_pipeline(session, limit)` 拉取待处理记录。

**5b. 确定分析目标**

- 漏洞在哪？→ curl 库的 `Curl_parseurl()` 函数（在 `lib/urlapi.c`）
- 谁可能受影响？→ `acme-server` 项目

**5c. 获取 acme-server 的 Snapshot（调用图）**

调用 `SnapshotManager.find_snapshot(repo_url, version, backend)` 查找已完成的 snapshot。

**5d. 在 Neo4j 中查询可达性**

`GraphStore.shortest_path(snapshot_id, entry_func, "Curl_parseurl")`

**5e. 结果 A — 可达：**

```
acme-server: main() → handle_request() → download_file() → curl_easy_perform()
   → Curl_http() → Curl_parseurl()   [depth=5, 可达]

ClientVuln.is_affected = true
ClientVuln.reachable_path = { paths: [...], depth: 5 }
ClientVuln.pipeline_status = "verified"
```

**5f. 结果 B — 不可达：**

```
acme-server 只使用了 curl_easy_setopt() 和 curl_easy_getinfo()，
调用图中没有任何路径到达 Curl_parseurl()。

ClientVuln.is_affected = false
ClientVuln.pipeline_status = "not_affect"
```

### Step 6 — Notification Engine（后续引擎）

- 如果 `verified` → 通知 ACME Corp
- 如果 `not_affect` → 不通知

---

## 漏洞函数从哪来

Reachability Analyzer 需要知道"在调用图中搜什么函数"。当前 `UpstreamVuln` 模型只有自然语言的 `summary` 和 `reasoning`，没有结构化的漏洞函数名。

### 方案对比

| 方案 | 描述 | 优点 | 缺点 |
|------|------|------|------|
| A: VulnAnalyzer 输出 | 在 `VulnAnalysisResult` 中新增 `affected_functions: list[str]`，让 LLM 分析时提取 | 信息在分析时确定，无额外工作 | LLM 提取可能不准确 |
| B: Diff 解析提取 | 从 `commit_sha` 调 GitHub API 获取 diff，解析修改的函数名 | 不依赖 LLM，直接从代码提取 | 增加 API 调用，C/C++ 函数名解析不简单 |
| C: 两者结合 | VulnAnalyzer best-effort 提取，Reachability Analyzer 兜底从 diff 解析 | 可靠性最高 | 两套逻辑 |

**推荐方案 C：两者结合。**

VulnAnalyzer 在分析时尽量提取 `affected_functions`（成本极低，只是在 prompt 中多加一个字段要求）。Reachability Analyzer 检查：如果 `affected_functions` 非空则直接使用，为空时从 commit diff 解析修改的函数名作为兜底。

---

## 双模式设计

### 独立模式（Standalone）

纯函数式，不依赖数据库。

```python
# vulnsentinel/engines/reachability/checker.py

@dataclass
class ReachabilityResult:
    """单次可达性检查结果。"""
    is_reachable: bool
    paths: list[dict] | None        # Neo4j shortest_path 结果
    searched_functions: list[str]    # 搜索了哪些漏洞函数
    snapshot_id: str                 # 使用的 snapshot
    depth: int | None               # 最短路径深度

def check_reachability(
    graph_store: GraphStore,
    snapshot_id: str,
    target_functions: list[str],
) -> ReachabilityResult
```

流程：
1. 对每个 `target_function`，调用 `GraphStore.shortest_path(snapshot_id, entry_func, target_function)`
2. 任一函数可达 → `is_reachable=True`，记录路径和深度
3. 全部不可达 → `is_reachable=False`
4. 返回 `ReachabilityResult`

用途：
- 单元测试
- CLI 调试
- 独立于 DB 的可达性验证

### 集成模式（Integrated）

通过 Service 层读写数据库，由调度器触发。

**核心设计决策：Sentinel 通过 zca 高层接口调用，不直接操作 GraphStore / SnapshotManager。**

zca 暴露一个高层 async API，Sentinel 只需传入 `(repo_url, version, upstream_vuln_dict)`，zca 内部处理 snapshot 查找/构建、target function 提取、图查询，返回 `(is_reachable, paths)`。

```python
# z_code_analyzer 暴露的高层接口
result = await zca.check_reachability(
    repo_url=project.repo_url,
    version="main",
    vuln={...upstream_vuln 的 dict 表示...},  # commit_sha, summary, reasoning, etc.
)
# result.is_reachable: bool
# result.paths: list[list[str]] | None
```

Sentinel 侧的 Runner 只负责轮询 + DB 读写：

```python
# vulnsentinel/engines/reachability/runner.py

class ReachabilityRunner:
    def __init__(
        self,
        client_vuln_service: ClientVulnService,
        upstream_vuln_service: UpstreamVulnService,
        project_service: ProjectService,
        zca_reachability,              # zca 的高层接口，不是 GraphStore/SnapshotManager
    ) -> None: ...

    async def analyze_one(
        self, session: AsyncSession, client_vuln: ClientVuln
    ) -> ReachabilityResult

    async def run_batch(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        limit: int = 20,
        concurrency: int = 5,
    ) -> list[tuple[ClientVuln, ReachabilityResult]]
```

`run_batch` 接收 `session_factory`（不是 session），保持与 VulnAnalyzerRunner / ImpactRunner 一致的模式。

**调用边界：** Sentinel 不 import GraphStore、SnapshotManager、orchestrator。所有分析逻辑（snapshot 管理、函数提取、图查询）封装在 zca 内部。Sentinel 传 dict，收结果。

---

## 数据流

```
ClientVuln(pipeline_status='pending')
        │
        │  ClientVulnService.list_pending_pipeline(session, limit)
        │
        ▼
  读取关联的 UpstreamVuln → 转为 dict
  读取关联的 Project → 获取 repo_url
        │
        ▼
  await zca.check_reachability(
      repo_url=project.repo_url,
      version=project.current_version or "main",
      vuln=upstream_vuln.__dict__,
  )
        │
        │  zca 内部（对 Sentinel 透明）：
        │    1. 查找/构建 Snapshot
        │    2. 从 vuln.commit_sha diff 提取 target functions
        │    3. GraphStore 查询可达性
        │
   ┌────┴────┐
   │         │
 可达        不可达（或 zca 返回错误）
   │         │
   ▼         ▼
 finalize(             finalize(is_affected=False)
   is_affected=True,     → pipeline_status='not_affect'
   reachable_path=...    → status='not_affect'
 )
   → pipeline_status='verified'
   → status='recorded'
```

---

## 入口函数问题

在 Neo4j Snapshot 中查询可达性时，需要确定"从哪里开始搜"。

### 入口函数来源

- **Fuzzer 入口**：z_code_analyzer 已解析 `LLVMFuzzerTestOneInput`，创建 `:Fuzzer` 节点和 `:REACHES` 边
- **main() 函数**：如果项目有 `main()`
- **公开 API 函数**：导出的库函数

### 查询策略

| 策略 | 方式 | 复杂度 |
|------|------|--------|
| Fuzzer 可达性 | 用 `:REACHES` 边（z_code_analyzer 已预计算） | O(1) 查询 |
| 通用可达性 | 用 `GraphStore.shortest_path()` 从 `main()` 或其他入口搜索 | O(路径深度) |

首选 Fuzzer 可达性（`:REACHES` 边已预计算）。如果无 Fuzzer 节点，退回通用可达性搜索。

---

## Snapshot 依赖

Reachability Analyzer 依赖客户项目的 Snapshot（Neo4j 调用图）。

### Snapshot 来源

z_code_analyzer 的 6 阶段流水线：

```
客户项目代码 → 项目探测 → 构建检测 → Bitcode 生成 → SVF 分析 → Neo4j 导入
```

### Snapshot 生命周期

- 新项目注册时触发首次构建
- 定时重建（版本更新时）
- Reachability Analyzer 按需检查：有就用，没有就标记 error 等待重试

### 关键设计决策：Snapshot Builder 是否为 Reachability Analyzer 的一部分？

**否。** Snapshot Builder 是独立引擎（#6），负责构建和缓存。Reachability Analyzer 只是消费者：

- 调用 `SnapshotManager.find_snapshot(repo_url, version, backend)` 获取 snapshot
- 如果 snapshot 不存在 → 标记 `error_message="snapshot not ready"`，保持 `pending`
- 等待 Snapshot Builder 完成后，下次轮询自然重试

---

## 轮询策略

### 已有基础设施

`ClientVulnDAO.list_pending_pipeline(session, limit)` — 轮询 `pipeline_status IN ('pending', 'path_searching', 'poc_generating')`。

**不需要新增轮询方法**。已有的 `list_pending_pipeline` 完全满足需求。Reachability Analyzer 只处理 `pipeline_status = 'pending'` 的记录，其他状态（`path_searching`、`poc_generating`）由后续引擎处理。

### 幂等性保障

重复处理同一 ClientVuln 不会产生副作用：
- `update_pipeline` 和 `finalize` 都是 SET 操作，重复执行结果相同
- 不创建新记录，只更新已有记录的字段

---

## 错误处理

| 错误场景 | 处理策略 | ClientVuln 状态 |
|---------|---------|----------------|
| Snapshot 不存在 | `update_pipeline(error_message="snapshot not ready")`，保持 pending | pending |
| Snapshot 构建失败 | `update_pipeline(error_message="snapshot build failed")`，保持 pending | pending |
| Neo4j 查询超时 | 重试，最终 `update_pipeline(error_message=...)` | pending |
| affected_functions 为空 + diff 解析失败 | `update_pipeline(error_message="cannot determine target functions")` | pending |
| Neo4j 连接失败 | 不更新 ClientVuln 状态，下次轮询自然重试 | pending（不变） |

### 事件级隔离

每个 ClientVuln 独立处理。单个 ClientVuln 处理失败不影响其他记录。失败记录保持 `pending` 状态，下次轮询自动重试。

---

## 代码结构

```
vulnsentinel/engines/reachability/
├── __init__.py
├── checker.py              # check_reachability() 纯函数 + ReachabilityResult
├── function_extractor.py   # 从 commit diff 提取修改的函数名
└── runner.py               # ReachabilityRunner (analyze_one + run_batch)

tests/vulnsentinel/
└── test_reachability.py
```

- `checker.py` — 独立模式核心。接收 `GraphStore`、`snapshot_id`、`target_functions`，返回 `ReachabilityResult`。
- `function_extractor.py` — 兜底机制。当 `affected_functions` 为空时，从 commit diff 解析被修改的 C/C++ 函数名。
- `runner.py` — 集成模式。轮询 `list_pending_pipeline`，调用 `check_reachability`，更新 `client_vulns`。

---

## 需要新增/修改的基础设施

### VulnAnalyzer 输出扩展

| 层 | 变更 | 说明 |
|----|------|------|
| Agent | `VulnAnalysisResult` 新增 `affected_functions: list[str]` | 分析时提取被修复的函数名 |
| Model | `UpstreamVuln` 新增 `affected_functions` 列（JSONB） | 存储结构化函数列表 |
| Prompt | Analyzer system prompt 更新 | 要求 LLM 提取函数名 |
| Service | `UpstreamVulnService.update_analysis()` 新增 `affected_functions` 参数 | 写入 DB |

### Reachability Engine 新增

| 层 | 组件 | 说明 |
|----|------|------|
| Engine | `check_reachability()` | 纯函数，图查询逻辑 |
| Engine | `ReachabilityRunner` | 集成模式，轮询 + DB 更新 |
| Engine | `function_extractor.py` | diff 解析工具，提取 C/C++ 函数名 |

---

## PoC 生成预留

十步流程第 9 步。当 `is_reachable=true` 时，`pipeline_status` 从 `path_searching` → `poc_generating` → `verified`。

PoC 生成是独立的子步骤，暂不在本文档详细设计。Runner 中预留接口：如果启用 PoC 生成，`analyze_one` 在确认可达后不直接 `finalize`，而是将 `pipeline_status` 设为 `poc_generating`，交给后续引擎处理。

---

## 未来演进

- **PoC 生成集成**（FuzzingBrain）— 可达路径 + 自动生成 fuzzer harness
- **增量分析** — snapshot 更新时只重新检查受影响的路径
- **多后端支持** — Joern、Introspector 作为 SVF 的降级方案
- **缓存优化** — 同一 snapshot 的多个 ClientVuln 共享查询结果
