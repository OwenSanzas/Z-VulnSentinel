## 11. 关键设计决策记录

### 11.1 为什么选择 SVF 而非 Clang AST 作为主力

**决策：** SVF（LLVM IR Andersen 分析）替代 Clang AST 作为 C/C++ 主力引擎。

**理由（来自 2025-02 实验验证）：**
- Clang AST 的函数指针分析是**单翻译单元**的——无法追踪跨文件的赋值传播
- 实际项目中的函数指针模式（回调注册、协议 handler 表、tag 类型处理器）都是跨翻译单元的
- SVF 在 LLVM IR 上做**全程序**指针分析，天然支持跨文件追踪
- 实验中，SVF 100% 发现了 introspector 遗漏的间接调用路径
- 速度完全可接受：最复杂的 curl 也只需 73s

**Clang AST 的定位调整：**
- 不再作为独立后端，其能力被 SVF 包含（SVF 的输入就是 clang 编译产物）
- 宏展开、模板实例化等 Clang 原生支持的场景，在 bitcode 中同样被保留
- 如果未来需要 Clang AST 特有的能力（如 source location mapping），可作为辅助后端

### 11.2 为什么保留 Introspector 后端

**决策：** Introspector 作为 `introspector_backend.py` 保留，不删除。

**理由：**
- 许多 OSS-Fuzz 项目已有成熟的 Docker 构建配置
- 向后兼容需要——现有用户无感迁移
- Introspector 数据可作为精度基线对照

**折中：**
- 默认 `auto` 模式不再优先 introspector，而是 SVF（v1 仅 SVF，v2 加 Joern 降级）
- 显式指定 `analysis_backend="introspector"` 时仍可使用

### 11.3 为什么用并集而非投票（保守过近似原则）

**决策：** 多后端函数和边取并集，而非多数投票。

**理由（与准确性哲学一致）：**
- **核心原则：漏报 = 错过漏洞，误报 = 多探索一个分支。** 代价不对称，必须最大化召回率。
- 投票要求 ≥3 个后端确认才保留一条边，这会系统性丢弃**只有一个高精度后端能发现的真实边**（如只有 SVF 能发现的函数指针分派）
- 不同后端的能力矩阵差异大——低精度后端无法检测函数指针，让它"投票否决"SVF 发现的间接调用边是错误的
- 并集策略保证：**任何一个后端发现的真实调用关系都不会被丢弃**

**风险缓解：**
- 每条边/每条记录都带 `confidence` 和 `source_backend` 标注
- 仅单后端产出且 confidence < 0.5 的边，在结果中标记为低置信度（但不删除）
- Agent 在做决策时可以参考 confidence 排序，优先探索高置信度路径
- 最终验证由 fuzzer 的实际执行完成——Agent 会在运行时确认路径是否可达

### 11.4 AI 只辅助不替代

**决策：** LLM 不做主要分析，只在静态结果基础上做精化。

**理由：**
- LLM 的代码分析不可重复、不确定
- 成本不可控（大项目可能有数万函数）
- 速度受 API 延迟限制
- 幻觉风险——LLM 可能发明不存在的调用关系

**设计约束：**
- AI 精化默认关闭（`ai_refine_enabled=False`）
- AI 只处理静态后端标记为不确定的边（`fptr` 类型，置信度较低的间接调用）
- AI 输出必须经过验证（引用的函数必须存在）
- 预算硬限制，超限自动停止

### 11.5 为什么用 Neo4j 替代 MongoDB 存储静态分析数据

**决策：** 静态分析结果（函数 + 调用图）从 MongoDB 迁移到 Neo4j 图数据库。

**旧方案的问题：**
- `_id = {task_id}_{name}` 把项目级事实绑死在 task 上，无法跨 task 复用
- 调用图存为 `callers[]` / `callees[]` 数组是反模式 — 加边要两端 `$push`，一致性靠应用层保证
- `reached_by_fuzzers` 冗余存储可达性，无法实时计算（需全量加载 + 应用层 BFS）
- 百万行项目（50K+ 节点），路径查询完全不可行

**Neo4j 的优势：**
- 调用图 = 天然图结构，边的方向就是 caller → callee
- `shortestPath`、可达性、BFS 深度 — 原生支持，百万节点毫秒级
- `reached_by_fuzzers` 不用存，实时查询 `(Fuzzer)-[:ENTRY]->()-[:CALLS*]->(f)` 即可
- 以 `(repo_url, version, backend)` 为 key 的 Snapshot 模型，项目级持久化，跨 task 复用

**迁移策略：**
- AnalysisServer RPC 方法签名不变，底层实现从 MongoDB 查询改为 Cypher 查询
- 状态管理类数据（suspicious_point, direction）仍在 MongoDB（可变状态，不属于静态分析结果）
- 静态分析引擎作为独立仓库，Neo4j 是其内部存储，FBv2 通过 pip 包 + RPC 方法访问

---
