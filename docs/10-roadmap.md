## 10. 实施路线图

### 阶段 1：独立仓库 + Neo4j 图存储（~2 周）

| 任务 | 产出 |
|------|------|
| 创建独立 GitHub 仓库 | `z-code-analyzer`（独立于 FBv2） |
| Neo4j Docker Compose | 开发/生产环境配置 |
| `graph_store.py` | Neo4j 连接管理 + Snapshot CRUD + 图写入/查询 |
| 图数据模型 | Snapshot / Function / Fuzzer 节点 + CALLS / ENTRY / CONTAINS 边 |
| `backends/base.py` | 抽象基类 + 数据类（FunctionRecord, CallEdge, AnalysisResult） |
| `backends/registry.py` | BackendRegistry + 降级链逻辑 |
| `backends/merger.py` | ResultMerger（函数合并 + 边合并） |
| 单元测试 | 图存储、数据类、合并逻辑的测试 |

### 阶段 2：SVF 后端（~2 周）

| 任务 | 产出 |
|------|------|
| 创建 `backends/svf_backend.py` | Docker 编排 + wllvm + SVF 分析 |
| 集成 `svf_pipeline.sh` | 通用 bitcode 提取器（三种构建模式） |
| 集成 `svf_dot_parser.py` | SVF callgraph DOT 解析 → AnalysisResult |
| Case 配置体系 | `cases/*.sh` 项目特定构建配置 |
| 端到端测试 | libpng / lcms / curl 分析 → Neo4j 写入 → Cypher 查询验证 |

### 阶段 3：Joern 后端 + CLI（~2 周）

| 任务 | 产出 |
|------|------|
| 创建 `backends/joern_backend.py` | Joern CPG 构建 + 调用图提取 |
| CPG 查询脚本 | 函数提取 + 调用边提取的 Scala/CPGQL 脚本 |
| 降级链集成 | SVF 失败 → 自动切换 Joern |
| CLI 入口 | `z-analyze run work.json` — 工单驱动的独立使用（见 §9.1） |
| 精度对比 | 与 SVF 基线对比，量化差距 |

### 阶段 4：FBv2 集成（~1 周）

| 任务 | 产出 |
|------|------|
| 发布 pip 包 | `pip install z-code-analyzer` |
| 重构 `analyzer/server.py` | RPC 方法底层从 MongoDB → Neo4j Cypher 查询 |
| 扩展 `core/config.py` | 新增 `neo4j_uri`, `analysis_backend` 等字段 |
| 兼容后端包装 | introspector / prebuild 数据导入 Neo4j 的适配器 |
| Docker Compose 更新 | FBv2 加 Neo4j 服务 |
| 向后兼容测试 | 验证 RPC 方法输出格式不变 |

### 阶段 5：AI 精化（~2 周）

| 任务 | 产出 |
|------|------|
| 创建 `ai_refiner.py` | LLM 精化处理器 + prompt 模板 |
| 间接调用解析 | 函数指针目标推断 prompt + 验证逻辑 |
| 集成测试 | AI 精化端到端验证 |
| 成本控制 | 预算限制 + 模型选择策略 |

### 阶段 6：扩展（远期）

| 任务 | 产出 |
|------|------|
| 更多 SVF Case 配置 | wireshark, mongoose, libxml2, ... |
| Snapshot 生命周期管理 | 版本更新、过期清理、磁盘管理 |
| REST API | 异步分析接口（给非 Python 客户端用） |
| 多语言后端 | 预留 `AnalysisBackend` 接口，按需实现 |

---
