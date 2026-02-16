## 1. 系统概览

### 1.1 定位

静态分析系统是 FuzzingBrain-V2 的**代码理解引擎**。它从源代码中提取函数元信息和调用图，供下游 AI Agent 做漏洞发现、方向规划和 POV 生成。

当前系统与 fuzz-introspector 强耦合——所有静态分析数据要么来自 LLVM Pass（需要 Docker + OSS-Fuzz 编译），要么来自预计算 JSON。本设计将其重构为**架构独立的多后端分析引擎**，支持多语言、多精度后端的可插拔组合。

### 1.2 核心目标

本系统目前只做两件事：

1. **函数元信息提取** — 项目中有哪些函数（名称、文件、行号、源码、复杂度）
2. **调用图构建** — 函数之间的调用关系（谁调用了谁）

所有下游能力（可达性判断、BFS 距离、reached_by_fuzzers）都是从这两个数据**派生**出来的，不是分析后端的职责。

**准确性要求：**

- 函数提取必须完整 — 漏掉一个函数意味着 Agent 无法分析到它
- 调用图必须完整 — 漏掉一条边意味着可达性分析断裂，Agent 可能错过整条攻击路径
- **宁可多报，不能漏报** — 多一条假边只是让 Agent 多探索一个分支，少一条真边则可能错过漏洞

这决定了我们的后端选择策略：**始终选择能力最强的后端**，确保虚函数、函数指针、宏展开、模板等场景下的调用边不被遗漏。

### 1.3 核心能力

| 能力 | 说明 |
|------|------|
| **多后端可插拔** | SVF（LLVM IR 指针分析，v1 主力）、Joern（CPG 非编译级，v2 降级方案）、Introspector/Prebuild（兼容预留） |
| **降级链（v2）** | SVF（最强精度，需编译）→ Joern（中等精度，不需编译）。v1 仅实现 SVF |
| **Neo4j 图存储** | 调用图 + 函数元数据存 Neo4j，原生图遍历，实时路径查询（百万节点毫秒级） |
| **项目级持久化** | 以 `(repo_url, version, backend)` 为 key，脱离 task 生命周期，跨 task 复用 |
| **多语言支持** | 通过 LanguageDetector 自动检测，ToolchainSelector 选择最优后端 |
| **AI 辅助精化** | LLM 解析间接调用、虚函数分派、冲突裁决（可选、异步、可降级） |
| **增量分析** | 仅分析 git diff 变更的文件，与 delta scan 模式集成 |
| **独立使用** | CLI / REST API，脱离 FuzzingBrain 管道也能运行 |

### 1.4 系统边界图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FuzzingBrain Pipeline                            │
│                                                                         │
│  TaskProcessor → WorkspaceSetup → FuzzerDiscovery → AnalysisServer     │
│                                                        │                │
│                                                   ┌────┴────┐          │
│                                                   │ Phase 1 │ 构建     │
│                                                   │ (不变)  │          │
│                                                   ├─────────┤          │
│                                                   │ Phase 2 │◄── 改造  │
│                                                   │ _analysis_phase()  │
│                                                   ├─────────┤          │
│                                                   │ Phase 3 │ 查询服务 │
│                                                   │ (不变)  │          │
│                                                   └────┬────┘          │
│                                                        │                │
│  WorkerDispatcher → AgentPipeline → MCP tools ─────────┘                │
│    (DirectionPlanning / SPGenerator / SPVerifier / POVAgent)            │
└─────────────────────────────────────────────────────────────────────────┘
                                 ▲
                                 │ Phase 2 调用
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     Static Analysis System（本设计）                     │
│                                                                         │
│  ┌──────────────────┐    ┌───────────────────┐    ┌─────────────────┐  │
│  │ LanguageDetector  │───▶│ToolchainSelector  │───▶│ Orchestrator    │  │
│  │ 语言检测          │    │ 工具链选择        │    │ 编排执行        │  │
│  └──────────────────┘    └───────────────────┘    └────────┬────────┘  │
│                                                            │           │
│                    ┌───────────────────────────────────────┤           │
│                    ▼               ▼              ▼        ▼           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐               │
│  │   SVF    │ │  Joern   │ │Introspect│ │ Prebuild │               │
│  │(LLVM IR) │ │  (CPG)   │ │  (兼容)  │ │ (导入)   │               │
│  │ ★ v1主力 │ │  v2降级  │ │  预留    │ │  预留    │               │
│  └─────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘               │
│        │            │            │             │                      │
│        └────────────┴─────┬──────┴─────────────┘                      │
│                            ▼                                           │
│                    ┌──────────────┐     ┌──────────────┐              │
│                    │ResultMerger  │────▶│ AI Refiner   │              │
│                    │ 结果合并     │     │ (可选)       │              │
│                    └──────┬───────┘     └──────┬───────┘              │
│                           │                    │                      │
│                           └────────┬───────────┘                      │
│                                    ▼                                   │
│                           ┌──────────────┐                            │
│                           │ GraphImporter │                            │
│                           │   → Neo4j    │                            │
│                           └──────────────┘                            │
└─────────────────────────────────────────────────────────────────────────┘
                                 ▲
                                 │ 独立使用
                                 │
┌─────────────────────────────────────────────────────────────────────────┐
│  独立入口                                                               │
│  ├── CLI: fuzzingbrain-analyze /path/to/project                        │
│  ├── REST API: POST /api/analyze                                       │
│  └── Python API: StaticAnalysisOrchestrator.analyze()                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.5 数据存储：Neo4j 图数据库

**设计决策：** 静态分析结果全部存储在 Neo4j 中，不再使用 MongoDB 的 `functions` / `callgraph_nodes` 集合。

**为什么不用 MongoDB：**
- `_id = {task_id}_{name}` 把项目级事实绑死在 task 上，无法跨 task 复用
- 调用图存为邻接数组（`callers[]` / `callees[]`）是反模式 — 加边要两端 `$push`，一致性靠应用层保证
- `reached_by_fuzzers` 冗余存储可达性，实时计算不可行（需应用层 BFS + 全量加载）
- 百万行项目（50K+ 节点 / 500K+ 边），MongoDB 做路径查询完全不可行

**为什么选 Neo4j：**
- 调用图 = 天然的图结构，节点是函数，边是调用关系
- `shortestPath`、可达性、BFS 深度 — 全部原生支持，百万节点毫秒级
- 边的方向就是 caller → callee，不需要维护双向数组
- 函数元数据（源码、复杂度等）作为节点属性存储，单一数据源

#### 1.5.1 图数据模型

```
(:Snapshot {
    id: "abc123",                    // = MongoDB snapshot _id
    repo_name: "curl",
    repo_url: "https://github.com/curl/curl",
    version: "curl-8_5_0",          // tag / commit hash
    backend: "svf",                  // 产出此快照的后端
    created_at: datetime
})
  │
  ├──[:CONTAINS]──→ (:Function {
  │                     name: "dict_do",
  │                     snapshot_id: "abc123",       // 冗余，便于索引查询
  │                     file_path: "lib/dict.c",
  │                     start_line: 142,
  │                     end_line: 210,
  │                     content: "void dict_do(...) { ... }",
  │                     cyclomatic_complexity: 15,
  │                     language: "c"
  │                 })
  │                     │
  │                     ├──[:CALLS {call_type: "direct", confidence: 1.0, backend: "svf"}]──→ (:Function)
  │                     └──[:CALLS {call_type: "fptr", confidence: 0.95, backend: "svf"}]──→ (:Function)
  │
  ├──[:CONTAINS]──→ (:Function:External {name: "malloc", snapshot_id: "abc123"})
  │
  └──[:CONTAINS]──→ (:Fuzzer {
                        name: "curl_fuzzer",
                        snapshot_id: "abc123",
                        entry_function: "LLVMFuzzerTestOneInput",
                        focus: "HTTP",
                        files: [{path: "fuzz/fuzz_http.c", source: "user"}]
                    })
                        │
                        ├──[:ENTRY]──→ (:Function {name: "LLVMFuzzerTestOneInput", ...})
                        │
                        └──[:REACHES {depth: 4}]──→ (:Function {name: "dict_do", ...})
```

#### 1.5.2 节点类型

| 标签 | 属性 | 说明 |
|------|------|------|
| `:Snapshot` | `id`, `repo_name`, `repo_url`, `version`, `backend`, `created_at` | 一次分析快照，`id` = MongoDB snapshot `_id`，唯一约束: `(repo_url, version, backend)` |
| `:Function` | `name`, `snapshot_id`, `file_path`, `start_line`, `end_line`, `content`, `cyclomatic_complexity`, `language` | 用户代码函数，`snapshot_id` 冗余便于索引 |
| `:Function:External` | `name`, `snapshot_id` | 外部函数（`malloc`, `printf` 等），SVF 无法分析内部，作为叶节点 |
| `:Fuzzer` | `name`, `snapshot_id`, `entry_function`, `focus`, `files` | Fuzzer 入口，`files` = [{path, source}]，source 为 "user" 或 "auto_detect" |

#### 1.5.3 边类型

| 关系 | 方向 | 属性 | 说明 |
|------|------|------|------|
| `:CONTAINS` | Snapshot → Function/Fuzzer | — | 快照包含哪些节点，可视化时展开 Snapshot 即可看到全部内容 |
| `:CALLS` | Function → Function | `call_type`, `confidence`, `backend` | 调用关系（方向即 caller → callee） |
| `:ENTRY` | Fuzzer → Function | — | Fuzzer 的入口函数 |
| `:REACHES` | Fuzzer → Function | `depth: int` | Fuzzer 可达关系 + 调用深度，导入时 BFS 一次性计算 |

`call_type` 枚举: `"direct"` / `"fptr"`（v1 只有这两种，SVF 分析结果）

**索引：**
```cypher
CREATE INDEX FOR (f:Function) ON (f.snapshot_id)
CREATE INDEX FOR (f:Fuzzer) ON (f.snapshot_id)
CREATE INDEX FOR (s:Snapshot) ON (s.id)
```

#### 1.5.4 关键查询示例

```cypher
// 最短路径：从函数 A 到函数 B（同一 Snapshot 内）
MATCH path = shortestPath(
  (a:Function {snapshot_id: $sid, name: "LLVMFuzzerTestOneInput"})
  -[:CALLS*]->
  (b:Function {snapshot_id: $sid, name: "dict_do"})
)
WHERE ALL(n IN nodes(path) WHERE n.snapshot_id = $sid)
RETURN [n IN nodes(path) | n.name] AS path_names

// 某函数被哪些 fuzzer 可达（通过 REACHES 边直接查，O(1)）
MATCH (fz:Fuzzer)-[r:REACHES]->(f:Function {snapshot_id: $sid, name: "dict_do"})
RETURN fz.name, r.depth

// fuzzer 直接调用的库函数（depth=1，即 LLVMFuzzerTestOneInput 的直接 callee）
MATCH (fz:Fuzzer {snapshot_id: $sid, name: "curl_fuzzer"})-[r:REACHES {depth: 1}]->(f)
RETURN f.name

// fuzzer 可达的 depth ≤ 3 的函数（depth=0 是 LLVMFuzzerTestOneInput 自身）
MATCH (fz:Fuzzer {snapshot_id: $sid, name: "curl_fuzzer"})-[r:REACHES]->(f)
WHERE r.depth <= 3
RETURN f.name, r.depth ORDER BY r.depth

// 未被任何 fuzzer 覆盖的函数
MATCH (s:Snapshot {id: $sid})-[:CONTAINS]->(f:Function)
WHERE NOT (f)<-[:REACHES]-(:Fuzzer)
RETURN f.name, f.file_path

// 某函数的所有 callers / callees
MATCH (caller:Function {snapshot_id: $sid})-[:CALLS]->(f:Function {snapshot_id: $sid, name: "dict_do"})
RETURN caller.name

MATCH (f:Function {snapshot_id: $sid, name: "curl_do"})-[:CALLS]->(callee:Function {snapshot_id: $sid})
RETURN callee.name
```

#### 1.5.5 存储估算

| 项目规模 | 节点 | 边 | Neo4j 存储 |
|---------|------|-----|-----------|
| 小型 (libpng, 150K行) | ~640 | ~2K | < 1 MB |
| 中型 (curl, 150K行) | ~2.3K | ~18K | ~5 MB |
| 大型 (1M行) | ~50K | ~500K | ~110 MB |
| 超大型 (Chromium, 25M行) | ~200K | ~2M | ~500 MB |

函数源码是主要体积来源（~1.2KB/函数），调用图边极轻量（~150B/边）。

#### 1.5.6 与 task 的关系

```
Task（MongoDB，生命周期短）          Snapshot（Neo4j，持久化）
┌──────────────────────┐           ┌──────────────────────┐
│ task_id: ObjectId    │           │ repo_url + version   │
│ repo_url: "curl..."  │──引用──→  │ backend: "svf"       │
│ snapshot_id: "xxx"   │           │ 函数 + 调用图 + Fuzzer│
│ status: "running"    │           │ （项目级，可复用）     │
└──────────────────────┘           └──────────────────────┘
```

- Task 创建时检查 Neo4j 是否已有匹配的 Snapshot（同 repo_url + version + backend）
- 有 → 直接引用，跳过分析（秒级启动）
- 无 → 运行分析后端，结果写入 Neo4j，Task 引用新 Snapshot
- Task 结束时不删除 Snapshot — 下次复用

#### 1.5.7 多 Fuzzer 处理（Library-Only 架构）

一个项目通常有多个 fuzzer（如 curl 的 `curl_fuzzer_http` / `curl_fuzzer_ftp` / `curl_fuzzer_smtp`）。
所有 fuzzer 共享同一份**库代码调用图**（SVF 只跑一次 library.bc），各自有独立的入口连接和 REACHES 子树。

**每个 fuzzer 有自己的 LLVMFuzzerTestOneInput 节点**（通过 `file_path` 区分）：

```cypher
// curl_fuzzer_http: 自己的入口 → 自己调用的库函数 → 共享的库调用图
(:Fuzzer {name: "curl_fuzzer_http", focus: "HTTP"})
  └──[:ENTRY]──→ (:Function {name: "LLVMFuzzerTestOneInput", file_path: "fuzz/fuzz_http.c"})
                      │ [:CALLS]
                      ▼
                 curl_easy_init, curl_easy_setopt, ...（Phase 4b 源码解析）

// curl_fuzzer_ftp: 自己的入口 → 不同的库函数子集
(:Fuzzer {name: "curl_fuzzer_ftp", focus: "FTP"})
  └──[:ENTRY]──→ (:Function {name: "LLVMFuzzerTestOneInput", file_path: "fuzz/fuzz_ftp.c"})
                      │ [:CALLS]
                      ▼
                 curl_easy_init, curl_url_set, ...（Phase 4b 源码解析）
```

**模板 Fuzzer 特殊情况：** 多个 fuzzer 共用同一个源文件（如 `fuzzer_template.c`），通过 `#define` 或配置分化：
- 工单 JSON 中每个 fuzzer 列出各自的源文件集合
- Phase 4b 分别解析每个 fuzzer 的源文件，提取各自调用的库函数
- 即使源文件相同，不同 `#define` 可能导致不同的库函数调用（此精度依赖源码解析能力，v1 保守处理：取所有可见调用的并集）

**AnalysisServer 查询 API（25 个 RPC 方法，接口不变，底层改为 Neo4j 查询）：**

- 函数查询：`get_function_metadata`, `list_function_info_by_file`, `search_functions`
- 调用图查询：`get_callers`, `get_callees`, `shortest_path`, `get_all_paths`, `get_subtree`
- 可达性查询：`reachable_functions_by_one_fuzzer`, `unreached_functions_by_all_fuzzers`
- Fuzzer 信息：`list_fuzzer_info_no_code`, `get_fuzzer_metadata`
- 概览：`list_external_function_names`, `get_snapshot_statistics`
- 扩展：`raw_query`
- 状态管理：`analyzer_status`, `create_suspicious_point`, `update_suspicious_point`, `list_suspicious_points`, `create_direction`, `claim_direction`, `complete_direction` 等

> **注**: 状态管理类 RPC（suspicious_point, direction 等）仍使用 MongoDB，因为它们是 task 级别的可变状态，不属于静态分析结果。

### 1.6 GraphStore 接口

`GraphStore` 是 Neo4j 的统一 CRUD 层，所有图操作都经过它。

```python
# graph_store.py

class GraphStore:
    """
    Neo4j 图存储层。
    所有查询都以 snapshot_id 为作用域，隔离不同版本的图。
    """

    # ── 连接管理 ──

    def connect(self, uri: str, auth: tuple[str, str]) -> None: ...
    def close(self) -> None: ...
    def health_check(self) -> bool: ...

    # ── 写入（Phase 6 数据导入用） ──

    def create_snapshot_node(
        self, snapshot_id: str, repo_url: str, version: str, backend: str
    ) -> None:
        """创建 :Snapshot 节点"""

    def import_functions(
        self, snapshot_id: str, functions: list[FunctionRecord]
    ) -> int:
        """
        批量创建 :Function 节点 + (:Snapshot)-[:CONTAINS]->(:Function) 边。
        使用 UNWIND 批量写入。返回写入数量。
        """

    def import_edges(
        self, snapshot_id: str, edges: list[CallEdge]
    ) -> int:
        """批量创建 (:Function)-[:CALLS]->(:Function) 边。返回写入数量。"""

    def import_fuzzers(
        self, snapshot_id: str, fuzzers: list[FuzzerInfo]
    ) -> int:
        """
        对每个 FuzzerInfo：
        1. 创建 :Fuzzer 节点 + (:Snapshot)-[:CONTAINS]->(:Fuzzer) 边
        2. 创建该 fuzzer 专属的 LLVMFuzzerTestOneInput :Function 节点（file_path 区分）
        3. 创建 (:Fuzzer)-[:ENTRY]->(:Function) 边
        4. 创建 (:Function {LLVMFuzzerTestOneInput})-[:CALLS]->(:Function {库函数}) 边
           （来自 FuzzerInfo.called_library_functions，Phase 4b 源码解析结果）
        返回写入的 Fuzzer 数量。
        """

    def import_reaches(
        self, snapshot_id: str, reaches: list[dict]
    ) -> int:
        """
        批量创建 (:Fuzzer)-[:REACHES {depth}]->(:Function) 边。
        reaches: [{fuzzer_name, function_name, depth}, ...]
        导入时对每个 fuzzer 做 BFS 计算 depth，一次性写入。
        """

    def delete_snapshot(self, snapshot_id: str) -> None:
        """删除整个 Snapshot 子图（:Snapshot 节点 + 所有关联节点和边）。淘汰时调用。"""

    # ── 查询 — 单函数 ──

    def get_function_metadata(
        self, snapshot_id: str, name: str, file_path: str | None = None
    ) -> dict | None:
        """
        精确获取单个函数的完整元信息。
        name 唯一时无需 file_path；同名多个时必须传 file_path 消歧。
        Raises: AmbiguousFunctionError
        """

    def list_function_info_by_file(self, snapshot_id: str, file_path: str) -> list[dict]:
        """获取某文件中的所有函数（不含 content，浏览场景）"""

    def search_functions(self, snapshot_id: str, pattern: str) -> list[dict]:
        """模糊搜索函数名（支持通配符），返回定位信息"""

    # ── 查询 — 调用关系 ──

    def get_callees(
        self, snapshot_id: str, name: str, file_path: str | None = None
    ) -> list[dict]:
        """获取该函数调用的所有下游函数"""

    def get_callers(
        self, snapshot_id: str, name: str, file_path: str | None = None
    ) -> list[dict]:
        """获取调用该函数的所有上游函数"""

    def shortest_path(
        self, snapshot_id: str,
        from_name: str, to_name: str,
        from_file_path: str | None = None, to_file_path: str | None = None,
        max_depth: int = 10, max_results: int = 10,
    ) -> dict | None:
        """
        两个函数之间的最短调用路径。返回所有同长度最短路径。
        max_depth: 最大搜索深度，-1 = 无限制
        max_results: 最多返回条数，-1 = 无限制
        不可达返回 None。
        """

    def get_all_paths(
        self, snapshot_id: str,
        from_name: str, to_name: str,
        from_file_path: str | None = None, to_file_path: str | None = None,
        max_depth: int = 10, max_results: int = 100,
    ) -> dict | None:
        """两点间所有路径，按 length 升序。-1 = 无限制。无路径返回 None。"""

    # ── 查询 — 可视化 ──

    def get_subtree(
        self, snapshot_id: str, name: str,
        file_path: str | None = None, depth: int = 3,
    ) -> dict:
        """从某函数出发 N 层子图，返回 {nodes, edges}。用于局部调用图可视化。"""

    # ── 查询 — Fuzzer 可达性 ──

    def reachable_functions_by_one_fuzzer(
        self, snapshot_id: str, fuzzer_name: str,
        depth: int | None = None, max_depth: int | None = None,
    ) -> list[dict]:
        """某 fuzzer 可达的函数列表，附带 depth，按 depth 升序"""

    def unreached_functions_by_all_fuzzers(self, snapshot_id: str) -> list[dict]:
        """未被任何 fuzzer 覆盖的函数列表"""

    # ── 查询 — 概览 ──

    def list_fuzzer_info_no_code(self, snapshot_id: str) -> list[dict]:
        """获取所有 fuzzer 信息（不含源码）"""

    def get_fuzzer_metadata(self, snapshot_id: str, fuzzer_name: str) -> dict | None:
        """获取单个 fuzzer 完整元信息（含源码）"""

    def list_external_function_names(self, snapshot_id: str) -> list[str]:
        """获取外部函数名列表（malloc、printf 等叶节点）"""

    def get_snapshot_statistics(self, snapshot_id: str) -> dict:
        """快速概览：节点数、边数、fuzzer 数、平均/最大 depth 等"""

    # ── 扩展 ──

    def raw_query(self, cypher: str, params: dict = None) -> list[dict]:
        """执行任意 Cypher 查询，用于未封装的自定义需求"""
```

### 1.7 Snapshot 版本管理

#### 1.7.1 MongoDB 快照目录

MongoDB 作为 Neo4j 的**元数据索引**，存储所有 Snapshot 的概览信息，支持快速检索和生命周期管理。

**数据库名：** `z_code_analyzer`（固定，不与 FBv2 的 `fuzzingbrain` 库混用）

**`snapshots` 集合：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `_id` | ObjectId | 自动生成，`str(_id)` 即为全局唯一的 `snapshot_id`，Neo4j 和所有 API 统一使用此字符串 |
| `repo_url` | str | 仓库地址 |
| `repo_name` | str | 仓库名（便于展示） |
| `version` | str | tag / commit hash（不允许 branch name） |
| `backend` | str | 产出后端（`"svf"` / `"joern"` / `"introspector"` / `"prebuild"`） |
| `node_count` | int | 函数节点数 |
| `edge_count` | int | 调用边数 |
| `fuzzer_names` | list[str] | 包含的 Fuzzer 列表 |
| `language` | str | 主要语言 |
| `analysis_duration_sec` | float | 分析耗时 |
| `status` | str | `"building"` → `"completed"` / `"failed"` |
| `created_at` | datetime | 创建时间 |
| `last_accessed_at` | datetime | 最后被 task 引用的时间 |
| `access_count` | int | 被 task 引用的总次数 |
| `size_bytes` | int | 预估 Neo4j 存储大小 |

**唯一索引：** `(repo_url, version, backend)`

#### 1.7.2 Snapshot 查找与复用

```python
class SnapshotManager:
    """
    Snapshot 生命周期管理器。
    MongoDB 做目录索引，Neo4j 存图本体。
    """

    def find_snapshot(self, repo_url: str, version: str,
                      preferred_backend: str = None) -> Optional[SnapshotMeta]:
        """
        查找可复用的 Snapshot。

        查找策略：
        1. 精确匹配 (repo_url, version, preferred_backend)
        2. 同版本但不同后端 — 按精度降序: svf > joern > introspector > prebuild
        3. 未命中 → 返回 None，调用方触发新分析
        """
        ...

    def on_snapshot_accessed(self, snapshot_id: str):
        """更新 last_accessed_at 和 access_count"""
        ...
```

**FBv2 集成流程：**

```
Task 启动 (repo_url, version)
  │
  ├── SnapshotManager.find_snapshot(repo_url, version)
  │     │
  │     ├── 命中 (status="completed")
  │     │     → 更新 last_accessed_at
  │     │     → 返回 snapshot_id（= str(_id)）
  │     │     → 跳过分析，秒级启动
  │     │
  │     └── 未命中
  │           → 运行 SVF 分析
  │           → 写入 Neo4j 图 + MongoDB 目录
  │           → 返回新 snapshot_id
  │
  └── AnalysisServer 用 snapshot_id 做所有 RPC 查询
```

#### 1.7.3 并发控制与错误恢复

**问题：** 两个 task 同时分析同一个 `(repo_url, version)`，会重复分析。

**方案：** MongoDB 唯一索引作为分布式锁，占位即加锁。

```python
async def acquire_or_wait(self, repo_url: str, version: str, backend: str) -> SnapshotMeta:
    """
    获取或等待 Snapshot。

    1. 查 MongoDB 是否已有
       - status="completed" → 直接返回
       - status="building" → 轮询等待
       - status="failed" → 删除旧记录，重新占位
    2. 无记录 → 插入占位 (status="building")
       - 成功 → 我来分析
       - DuplicateKeyError → 别人抢先了，转等待
    """
    # 检查已有记录
    snap = db.snapshots.find_one({
        "repo_url": repo_url, "version": version, "backend": backend
    })

    if snap:
        if snap["status"] == "completed":
            self.on_snapshot_accessed(snap["_id"])
            return snap
        if snap["status"] == "building":
            # 超时保护：analyzing 超过 30 分钟 → 视为进程异常死亡
            if (datetime.now() - snap["created_at"]) > timedelta(minutes=30):
                db.snapshots.update_one(
                    {"_id": snap["_id"]},
                    {"$set": {"status": "failed", "error": "timeout: analyzer process died"}}
                )
            else:
                return await self._wait_for_ready(repo_url, version, backend)
        if snap["status"] == "failed":
            db.snapshots.delete_one({"_id": snap["_id"]})

    # 占位
    try:
        db.snapshots.insert_one({
            "repo_url": repo_url, "version": version, "backend": backend,
            "status": "building", "created_at": datetime.now(),
        })
        return None  # 调用方开始分析
    except DuplicateKeyError:
        return await self._wait_for_ready(repo_url, version, backend)


async def _wait_for_ready(self, repo_url, version, backend, timeout=1800):
    """轮询等待 Snapshot 就绪，每 5 秒查一次 MongoDB"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = db.snapshots.find_one({
            "repo_url": repo_url, "version": version, "backend": backend
        })
        if snap and snap["status"] == "completed":
            self.on_snapshot_accessed(snap["_id"])
            return snap
        if not snap or snap["status"] == "failed":
            return None  # 失败了，调用方可重试
        await asyncio.sleep(5)
    raise TimeoutError("Waiting for snapshot analysis timed out")
```

**错误恢复：** 分析过程用 try/finally 保证状态一致性。

```python
async def analyze_with_snapshot(self, repo_url, version, backend, ...):
    snapshot_doc = self._create_snapshot(repo_url, version, backend, status="building")
    try:
        result = await self._run_backend(...)
        self._write_to_neo4j(result)
        db.snapshots.update_one(
            {"_id": snapshot_doc["_id"]},
            {"$set": {
                "status": "completed",
                "node_count": len(result.functions),
                "edge_count": len(result.edges),
                "analysis_duration_sec": result.analysis_duration_sec,
            }}
        )
    except Exception as e:
        db.snapshots.update_one(
            {"_id": snapshot_doc["_id"]},
            {"$set": {"status": "failed", "error": str(e)}}
        )
        raise
```

**两层保护：**
1. **正常异常**（SVF 失败、Neo4j 写入错误等）→ try/except 立即标记 `"failed"`
2. **进程异常死亡**（OOM kill 等）→ 超时兜底（30 分钟未完成 → 自动标记 `"failed"`）

#### 1.7.4 版本淘汰策略

三层淘汰机制，按优先级执行：

**策略 1：同仓库版本上限（默认保留最近 5 个）**

```python
MAX_VERSIONS_PER_REPO = 5

def evict_by_version_limit(self, repo_url: str):
    """
    同一个 repo_url 的 Snapshot 超过上限时，
    淘汰 last_accessed_at 最早的版本。
    """
    snapshots = db.snapshots.find(
        {"repo_url": repo_url, "status": "completed"}
    ).sort("last_accessed_at", -1)

    to_delete = list(snapshots)[MAX_VERSIONS_PER_REPO:]
    for snap in to_delete:
        self._delete_snapshot(snap)
```

**策略 2：磁盘水位淘汰（80% 阈值）**

```python
DISK_THRESHOLD = 0.80  # 80%

def evict_by_disk_pressure(self):
    """
    Neo4j 数据目录磁盘使用率超过阈值时，
    按 LRU (last_accessed_at) 淘汰最不常用的 Snapshot，
    直到使用率降到 70% 以下。
    """
    while get_disk_usage() > DISK_THRESHOLD:
        oldest = db.snapshots.find_one(
            {"status": "completed"},
            sort=[("last_accessed_at", 1)]
        )
        if not oldest:
            break
        self._delete_snapshot(oldest)
```

**策略 3：TTL 过期（默认 90 天未访问）**

```python
TTL_DAYS = 90

def evict_by_ttl(self):
    """
    超过 TTL 天数未被任何 task 引用的 Snapshot 自动清除。
    """
    cutoff = datetime.now() - timedelta(days=TTL_DAYS)
    expired = db.snapshots.find({
        "status": "completed",
        "last_accessed_at": {"$lt": cutoff}
    })
    for snap in expired:
        self._delete_snapshot(snap)
```

**淘汰执行顺序：**

```
定时任务（每小时 / 每次 task 启动时）
  │
  ├── 1. evict_by_disk_pressure()    ← 最优先，防止磁盘满
  ├── 2. evict_by_version_limit()    ← 控制同仓库版本膨胀
  └── 3. evict_by_ttl()              ← 清理长期无用数据
```

**删除操作：**

```python
def _delete_snapshot(self, snap: dict):
    """
    删除一个 Snapshot：
    1. Neo4j: 删除该 Snapshot 下所有节点和边
       MATCH (s:Snapshot {id: $sid})-[:CONTAINS]->(n)
       DETACH DELETE s, n
    2. MongoDB: 删除目录记录
       db.snapshots.delete_one({"_id": snap["_id"]})
    """
```

#### 1.7.5 版本对比（远期）

```python
def diff_snapshots(self, snap_a_id: str, snap_b_id: str) -> SnapshotDiff:
    """
    对比两个 Snapshot（通常是同 repo 不同 version）：
    - 新增的函数
    - 删除的函数
    - 变更的函数（content 不同）
    - 新增/删除的调用边
    用于增量分析和变更追踪。
    """
```

#### 1.7.6 配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `SNAPSHOT_MAX_VERSIONS_PER_REPO` | `5` | 同仓库最多保留版本数 |
| `SNAPSHOT_DISK_THRESHOLD` | `0.80` | 磁盘水位淘汰阈值 |
| `SNAPSHOT_DISK_TARGET` | `0.70` | 淘汰后目标水位 |
| `SNAPSHOT_TTL_DAYS` | `90` | 未访问过期天数 |
| `SNAPSHOT_EVICTION_INTERVAL` | `3600` | 淘汰检查间隔（秒） |

---

