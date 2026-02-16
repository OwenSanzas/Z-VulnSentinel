## 附录 A: 文件结构

**独立仓库 `z-code-analyzer`：**

```
z-code-analyzer/                            # 独立 GitHub 仓库
├── pyproject.toml                      # pip 包配置
├── docker-compose.yml                  # Neo4j 服务
│
├── z_code_analyzer/
│   ├── __init__.py                     # 公开 API
│   ├── graph_store.py                  # GraphStore — Neo4j 连接管理 + 图读写
│   ├── snapshot_manager.py             # SnapshotManager — MongoDB 快照目录 + 并发控制 + 淘汰
│   ├── orchestrator.py                 # StaticAnalysisOrchestrator（核心编排器）
│   ├── ai_refiner.py                   # AIRefiner + prompt 模板
│   ├── cli.py                          # CLI 入口: z-analyze
│   │
│   ├── build/                          # 构建命令提取 + Bitcode 生成
│   │   ├── __init__.py
│   │   ├── detector.py                 # BuildCommandDetector — 三层降级（用户脚本→自动检测→LLM）
│   │   ├── bitcode.py                  # BitcodeGenerator — wllvm 注入 + library-only llvm-link
│   │   ├── fuzzer_parser.py            # FuzzerEntryParser — 源码解析 fuzzer→库函数调用（Phase 4b）
│   │   └── llm_inferrer.py             # LLMBuildInferrer — 读 README 推断构建命令
│   │
│   ├── logging/                        # 日志存储
│   │   ├── __init__.py
│   │   ├── base.py                     # LogStore 抽象接口
│   │   └── local.py                    # LocalLogStore — 本地文件存储（v1 默认）
│   │
│   ├── backends/                       # 分析后端
│   │   ├── __init__.py
│   │   ├── base.py                     # AnalysisBackend + FunctionRecord + CallEdge + AnalysisResult
│   │   ├── registry.py                 # BackendRegistry + BackendDescriptor + BackendCapability
│   │   ├── merger.py                   # ResultMerger（预留）
│   │   ├── svf_backend.py              # SVFBackend — .bc → SVF → DOT → AnalysisResult
│   │   ├── joern_backend.py            # JoernBackend — CPG 分析（预留）
│   │   ├── introspector_backend.py     # IntrospectorBackend（兼容包装，预留）
│   │   └── prebuild_backend.py         # PrebuildBackend（JSON 导入 → Neo4j，预留）
│   │
│   ├── svf/                            # SVF Pipeline 资源
│   │   ├── svf_pipeline.sh             # Docker 内运行的通用 bitcode 提取器
│   │   ├── svf_dot_parser.py           # SVF callgraph DOT 解析器
│   │   └── cases/                      # 项目特定构建配置
│   │       ├── libpng.sh
│   │       ├── lcms.sh
│   │       └── curl.sh
│   │
│   └── models/                         # 数据模型
│       ├── __init__.py
│       ├── snapshot.py                 # Snapshot 数据类
│       ├── function.py                 # FunctionRecord（后端输出格式）
│       └── callgraph.py                # CallEdge（后端输出格式）
│
└── tests/
    ├── test_graph_store.py
    ├── test_svf_backend.py
    ├── test_joern_backend.py
    └── test_orchestrator.py
```

**FBv2 集成侧（改动最小化）：**

```
fuzzingbrain/
├── analyzer/
│   ├── server.py                       # RPC 方法底层改为调 z_code_analyzer 查 Neo4j
│   ├── importer.py                     # 保留旧 StaticAnalysisImporter（兼容）
│   ├── protocol.py                     # 不变
│   ├── client.py                       # 不变
│   ├── builder.py                      # 不变
│   ├── models.py                       # 不变
│   └── tasks.py                        # 不变
│
├── core/
│   ├── config.py                       # 新增 neo4j_uri, analysis_backend 等
│   ├── models/
│   │   ├── function.py                 # 保留（兼容旧路径）
│   │   └── callgraph.py                # 保留（兼容旧路径）
│   └── ...
│
└── tools/
    └── analyzer.py                     # 不变（接口不变，底层走 Neo4j）
```
