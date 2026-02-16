## 8. 与 FuzzingBrain 管道集成

### 8.1 集成改造点

**核心改动：`AnalysisServer._import_phase()` → `_analysis_phase()`**

当前 `AnalysisServer.start()` 的三阶段流程中，只改 Phase 2：

```python
# analyzer/server.py — 改造后

async def start(self):
    # Phase 1: 构建 fuzzer 二进制（不变）
    build_success = await self._build_phase()

    # Phase 2: 静态分析（改造）
    await self._analysis_phase()    # ← 新方法

    # Phase 3: 启动查询服务（不变）
    await self._start_server()


async def _analysis_phase(self):
    """Phase 2: 静态分析导入（可插拔后端）"""
    config = Config.from_env()
    backend_name = config.analysis_backend  # "auto" | "svf" | "joern" | ...

    # 兼容路径：introspector 或 prebuild 走旧逻辑
    if self._should_use_legacy_path(backend_name):
        await self._import_phase_legacy()
        return

    # 新路径：用 StaticAnalysisOrchestrator
    graph_store = GraphStore(neo4j_uri=config.neo4j_uri)
    orchestrator = StaticAnalysisOrchestrator(
        snapshot_manager=SnapshotManager(mongo_uri=config.mongo_uri, graph_store=graph_store),
        graph_store=graph_store,
    )

    result = await orchestrator.analyze(
        project_path=str(self.task_path / "repo"),
        repo_url=self.repo_url,
        version=self.version or "latest",
        fuzzer_sources=self.fuzzer_sources,
        language=self.language,
        backend=backend_name if backend_name != "auto" else None,
        diff_files=self.diff_files,         # delta 模式
    )
    # 结果已写入 Neo4j，保存 snapshot_id 供后续查询
    self.snapshot_id = result.snapshot_id

    self._log(f"Analysis completed: {result.function_count} functions, "
              f"{result.edge_count} edges ({result.backend})")


def _should_use_legacy_path(self, backend_name: str) -> bool:
    """判断是否走旧的 introspector/prebuild 路径"""
    if backend_name == "introspector":
        return True
    if backend_name == "prebuild":
        return True
    if backend_name == "auto":
        # 有 introspector 输出 → 用旧路径
        if self.introspector_path and self.introspector_path.exists():
            return True
        # 有 prebuild 数据 → 用旧路径
        if self.prebuild_dir and self.work_id:
            return True
    return False


async def _import_phase_legacy(self):
    """旧的导入路径（保持不变，重命名自 _import_phase）"""
    # 原有 _import_phase 的全部代码，不改
    ...
```

### 8.2 Config 新增字段

```python
# core/config.py — 新增字段

@dataclass
class Config:
    # === 现有字段（不变）===
    # ... task_type, scan_mode, repo_url, prebuild_dir, work_id ...

    # === 静态分析后端（新增）===

    # 后端选择
    # "auto" → 自动（有 introspector 用 introspector，否则 svf → joern）
    # "svf" → SVF Andersen 指针分析（需要 Docker + 编译成功）
    # "joern" → Joern CPG 分析（不需要编译）
    # "introspector" → fuzz-introspector（需要 Docker build）
    # "prebuild" → 预计算数据
    analysis_backend: str = "auto"

    # AI 精化
    ai_refine_enabled: bool = False               # AI 精化开关（默认关闭）
    ai_refine_budget_usd: float = 1.0             # 预算限制
```

**环境变量映射：**

| 环境变量 | Config 字段 | 默认值 |
|---------|------------|--------|
| `ANALYSIS_BACKEND` | `analysis_backend` | `"auto"` |
| `AI_REFINE_ENABLED` | `ai_refine_enabled` | `False` |
| `AI_REFINE_BUDGET` | `ai_refine_budget_usd` | `1.0` |

### 8.3 向后兼容保证矩阵

| 场景 | 行为 | 变化 |
|------|------|------|
| 不传任何新配置（默认） | `auto` → 检测到 introspector 输出 → 走旧路径 | **无变化** |
| 不传任何新配置 + 无 introspector | `auto` → 无旧数据 → 走新路径（SVF） | 新行为，兼容 |
| `analysis_backend="introspector"` | 走旧 `_import_phase_legacy()` | **无变化** |
| `prebuild_dir` + `work_id` 已设置 | 走旧 `import_from_prebuild()` | **无变化** |
| `analysis_backend="svf"` | 新路径，SVF 后端 | 新行为 |
| `analysis_backend="joern"` | 新路径，Joern 后端 | 新行为 |

**关键保证：**
1. AnalysisServer 的 25 个 RPC 方法**签名不变**
2. `tools/analyzer.py` 的 MCP tools 接口不变
3. Worker/Agent 流程不变
4. 默认配置行为不变
5. 静态分析数据改为从 Neo4j 查询（底层变化，接口不变）
6. 状态管理类数据（suspicious_point, direction）仍在 MongoDB

### 8.4 对下游 Agent/MCP tools 完全透明

```
Agent Pipeline                    MCP Tools                AnalysisServer
                                  (tools/analyzer.py)      (analyzer/server.py)

DirectionPlanning ──▶ get_reachable_functions() ──▶ Neo4j Cypher（原生图遍历）
SPGenerator      ──▶ get_function_source()     ──▶ Neo4j 节点属性查询
SPVerifier       ──▶ check_reachability()      ──▶ Neo4j shortestPath
POVAgent         ──▶ get_call_graph()          ──▶ Neo4j 子图查询

Agent 不感知数据来自哪个后端，也不感知底层是 Neo4j。
RPC 方法的输入输出格式完全不变。
```

### 8.5 独立仓库与 FBv2 集成方式

静态分析引擎作为**独立 GitHub 仓库**，FBv2 通过 pip 包引用：

```
# 独立仓库（static-analysis-engine）提供：
from z_code_analyzer import StaticAnalysisOrchestrator
from z_code_analyzer import GraphStore, SnapshotManager

# FBv2 的 analyzer/server.py 中：
graph_store = GraphStore(neo4j_uri="bolt://localhost:7687")
orchestrator = StaticAnalysisOrchestrator(
    snapshot_manager=SnapshotManager(graph_store=graph_store),
    graph_store=graph_store,
)
result = await orchestrator.analyze(...)
# result.snapshot_id 供 RPC 方法查询时使用
```

```
# FBv2 的 requirements.txt 或 pyproject.toml：
z-code-analyzer >= 0.1.0
```

---
