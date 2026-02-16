## 7. 分析管道

### 7.1 分析流水线

```
Phase 1          Phase 2            Phase 3              Phase 4a        Phase 4b          Phase 5        Phase 6
项目探测    →    构建命令提取    →    Bitcode生成      →   SVF分析     →  Fuzzer入口解析  →  AI 精化   →   数据导入
                (三层降级)         (library-only)       (库调用图)      (源码级)         (预留接口)     (Neo4j)
```

> **v1 范围**：只实现 SVF 后端，Phase 5 (AI) 预留接口不实现。
> 多后端并行/串行、结果合并（`ResultMerger`）为未来扩展，预留接口。

### 7.2 Phase 1: 项目探测

```python
class ProjectProbe:
    """
    探测项目基本信息：
    - 语言检测（LanguageDetector）
    - 源文件列表
    - 构建系统识别（CMakeLists.txt / configure / Makefile / meson.build / build.sh）
    - 项目规模估算（文件数、代码行数）
    - Git 信息（如果有 diff 则识别变更文件）
    """

    def probe(self, project_path: str, diff_files: Optional[List[str]] = None) -> ProjectInfo:
        ...

@dataclass
class ProjectInfo:
    project_path: str
    language_profile: LanguageProfile
    source_files: List[str]              # 所有源文件路径
    build_system: str                    # "cmake" | "autotools" | "meson" | "make" | "custom" | "unknown"
    estimated_loc: int                   # 代码行数估算
    diff_files: Optional[List[str]]      # delta 模式下的变更文件
    git_root: Optional[str]              # git 根目录
```

### 7.3 Phase 2: 构建命令提取

**核心问题**：如何从任意 C/C++ 项目得到正确的构建命令？

**三层降级策略（能用就停）：**

```
1. 工单 JSON 中指定 build_script → 直接用
        │ (未提供)
        ▼
2. 自动检测构建系统 → 生成默认构建命令
        │ (构建失败)
        ▼
3. LLM 读 README/INSTALL/BUILD.md → 推断构建步骤
```

**层 1：用户显式提供（最可靠）**

```bash
# 工单 JSON 中指定 build_script
{
  "path": "./curl-src",
  "build_script": "./my_build.sh",
  "repo_url": "https://github.com/curl/curl",
  "version": "curl-8_5_0",
  "fuzzer_sources": {"curl_fuzzer": ["fuzz/curl_fuzzer.cc"]}
}

# OSS-Fuzz 项目天然有 build.sh
{
  "build_script": "./ossfuzz/build.sh",
  ...
}
```

**层 2：自动检测构建系统**

```python
class BuildCommandDetector:
    """
    根据项目中的构建系统标记文件，生成默认构建命令。
    """

    DETECTION_RULES = [
        # (标记文件, 构建系统, 默认命令)
        ("CMakeLists.txt",  "cmake",     "cmake -B build && cmake --build build"),
        ("configure",       "autotools", "./configure && make"),
        ("configure.ac",    "autotools", "autoreconf -fi && ./configure && make"),
        ("meson.build",     "meson",     "meson setup build && ninja -C build"),
        ("Makefile",        "make",      "make"),
    ]

    def detect(self, project_path: str) -> Optional[BuildCommand]:
        """
        按优先级检测构建系统，返回构建命令。
        未检测到返回 None → 降级到层 3。
        """
```

**层 3：LLM 读项目文档（降级兜底）**

```python
class LLMBuildInferrer:
    """
    读取项目的 README.md / INSTALL / BUILD.md / CONTRIBUTING.md，
    让 LLM 提取构建步骤。
    """

    async def infer(self, project_path: str) -> Optional[BuildCommand]:
        """
        1. 查找文档文件（README*, INSTALL*, BUILD*, CONTRIBUTING*）
        2. 提交给 LLM，提取构建命令
        3. 返回推断的命令（可能不完美，但比没有强）
        """
```

**输出：**

```python
@dataclass
class BuildCommand:
    commands: list[str]          # 构建命令列表 ["cmake -B build", "cmake --build build"]
    source: str                  # "user" | "auto_detect" | "llm"
    build_system: str            # "cmake" | "autotools" | "meson" | "make" | "custom"
    confidence: float            # 1.0 (user) / 0.8 (auto) / 0.5 (llm)
```

### 7.4 Phase 3: Bitcode 生成 + 函数元数据提取

拿到构建命令后，注入 wllvm 环境变量执行构建，提取 **library-only** bitcode 和函数元数据。

**核心设计：Library-Only Bitcode**

一个项目可能有多个 fuzzer，每个都定义了 `LLVMFuzzerTestOneInput`（全局符号）。
`llvm-link` 无法合并多个同名全局函数（只有 `static` 函数会自动重命名）。

解决方案：**只链接库代码，排除 fuzzer 源文件**。

```
所有 .o 文件
  ├── 库代码 .o（src/*.o, lib/*.o, ...）  ──┐
  │                                          ├── llvm-link → library.bc（无 LLVMFuzzerTestOneInput）
  │                                          │
  └── fuzzer 源文件 .o（fuzz/*.o）  ────────── 排除（由工单 fuzzer_sources 标识）
```

SVF 只分析 `library.bc`，得到完整的库内调用图（含函数指针分析）。
Fuzzer → 库函数的连接由 Orchestrator 通过源码解析完成（见 Phase 4）。

**关键设计：`-g` 强制注入**

使用薄包装脚本 `z-wllvm` / `z-wllvm++` 替代 wllvm，在编译器层面强制追加 `-g`：

```bash
#!/bin/bash
# z-wllvm — 永远追加 -g，保证 .bc 包含 debug info
exec wllvm -g "$@"
```

这样无论 build.sh 如何设置 CFLAGS，`-g` 都会注入。`-g` 只增加调试信息，不影响代码生成、优化级别和运行时行为。与软件自带的 `-g` 也不冲突（`-g -g` 等于 `-g`）。

```python
class BitcodeGenerator:
    """
    注入 z-wllvm 环境 → 执行构建 → 排除 fuzzer .o → llvm-link 库代码 → library.bc
    """

    def generate(
        self,
        project_path: str,
        build_cmd: BuildCommand,
        fuzzer_source_files: List[str],   # 工单中所有 fuzzer 的源文件（扁平列表）
    ) -> BitcodeOutput:
        """
        步骤：
        1. 设置环境: CC=z-wllvm, CXX=z-wllvm++, LLVM_COMPILER=clang
        2. 执行 build_cmd.commands（工作目录 = project_path）
        3. 收集所有编译产出的 .o 对应的 .bc 文件
           （wllvm 为每个 .o 记录了 .bc manifest）
        4. 排除 fuzzer 源文件对应的 .bc
           （fuzzer_source_files 中的文件路径 → 对应的 .o → 排除其 .bc）
        5. llvm-link 剩余的库代码 .bc → library.bc
           （不含任何 LLVMFuzzerTestOneInput，无符号冲突）
        6. llvm-dis library.bc → library.ll
        7. 解析 .ll 中的 DISubprogram 元数据 → 函数元数据表
        8. 用 file_path + line 从源文件读取函数 content
        9. 返回 BitcodeOutput

        失败场景：
        - 编译错误 → 抛异常，上层可尝试降级 build_cmd
        - llvm-link 失败 → 检查 LLVM 版本匹配
        """


@dataclass
class FunctionMeta:
    """从 LLVM IR debug info 提取的函数元数据"""
    ir_name: str                 # LLVM IR 中的名字（可能是 init.1）
    original_name: str           # 源码中的原始名字（init）
    file_path: str               # 源文件路径（lib/ftp.c）
    line: int                    # 起始行号
    content: str                 # 从源文件读取的函数源码


@dataclass
class BitcodeOutput:
    bc_path: str                 # library.bc 文件路径（仅库代码）
    function_metas: list[FunctionMeta]  # 库函数的元数据（不含 fuzzer 函数）
```

**函数元数据提取流程：**

```
library.bc → llvm-dis → library.ll → 解析 DISubprogram → {ir_name, original_name, file_path, line}
                                                                    ↓
                                                          源文件读 content（file_path:line → 找到函数结尾 '}'）
```

> **注意**：此阶段在 Docker 容器内执行（`svftools/svf` 或自定义镜像），
> 包含 wllvm、clang、llvm-link、llvm-dis 等工具链。

### 7.5 Phase 4: SVF 分析 + Fuzzer 入口解析

分为两个并行子步骤：SVF 分析库调用图 + 源码解析 fuzzer 入口调用。

**4a: SVF 分析（库代码调用图）**

拿到 `library.bc` 后，完全通用，不需要任何项目特定配置。
输出中**不含** `LLVMFuzzerTestOneInput`（因为 fuzzer 源文件已排除）。

```python
class SVFBackend(AnalysisBackend):
    """
    library.bc → SVF Andersen 分析 → DOT 调用图 → AnalysisResult（仅库代码）
    """

    def analyze(self, project_path: str, language: str, *, bc_path: str, function_metas: list[dict]) -> AnalysisResult:
        """
        步骤：
        1. wpa -ander -dump-callgraph library.bc → callgraph DOT
        2. 解析 DOT → 调用边列表（caller_ir_name → callee_ir_name, call_type）
        3. 合并 BitcodeOutput.function_metas（debug info 元数据）+ DOT 调用边
           → FunctionRecord 列表（含 file_path, line, content）
           → CallEdge 列表（含 call_type: direct/fptr）
        4. 返回 AnalysisResult(functions, edges)

        注意：
        - SVF 只分析库代码，输出中没有 LLVMFuzzerTestOneInput
        - 函数指针分析（Andersen）在库代码范围内完整执行
        - REACHES 由 Orchestrator 在 Neo4j 导入后计算
        """
```

**4b: Fuzzer 入口解析（源码级）**

从 fuzzer 源文件中解析 `LLVMFuzzerTestOneInput` 及其 helper 函数调用的库函数。
Fuzzer harness 代码通常很薄（直接调用为主），不需要 SVF 级别的函数指针分析。

```python
class FuzzerEntryParser:
    """
    解析 fuzzer 源文件，提取 fuzzer → 库函数的调用关系。

    为什么不用 SVF 分析 fuzzer 代码：
    - 多个 fuzzer 的 LLVMFuzzerTestOneInput 同名，无法 llvm-link
    - Fuzzer harness 代码简单，直接调用为主，不需要函数指针分析
    - 函数指针分析只在库代码中关键（protocol handler、回调注册等）
    """

    def parse(
        self,
        fuzzer_sources: Dict[str, List[str]],  # {fuzzer_name: [source_files]}
        library_functions: Set[str],            # SVF 输出的所有库函数名
        project_path: str,
    ) -> Dict[str, List[str]]:
        """
        返回: {fuzzer_name: [被调用的库函数名列表]}

        步骤（对每个 fuzzer）：
        1. 读取该 fuzzer 的所有源文件
        2. 提取所有函数定义（包括 LLVMFuzzerTestOneInput 和 helper 函数）
        3. 提取所有函数调用
        4. 递归展开 fuzzer 内部 helper 调用，收集最终调用的库函数
           （只保留 library_functions 中存在的函数名）
        5. 返回该 fuzzer 直接或间接调用的所有库函数

        实现方式：tree-sitter（C/C++ 解析）或正则匹配
        精度足够：fuzzer 代码几乎不用函数指针做内部分派
        """
```

**为什么这个 tradeoff 可行：**

| | 库代码 | Fuzzer 代码 |
|---|---|---|
| 分析工具 | SVF（LLVM IR Andersen） | tree-sitter / 正则 |
| 函数指针 | ✅ 完整解析 | ❌ 不需要（harness 不用函数指针） |
| 精度要求 | 高（核心价值） | 低（只需找到入口调用了哪些库函数） |
| 数量 | 1 次 SVF（所有 fuzzer 共享） | N 个 fuzzer 各自源码解析（极快） |

### 7.6 Phase 5: AI 精化（预留接口）

v1 不实现，预留接口：

```python
class AIRefiner:
    """
    异步 AI 精化处理器（预留接口）。
    v1 直接返回原始 result，不做任何修改。
    """

    async def refine(self, result: AnalysisResult, config: AIRefinerConfig) -> AnalysisResult:
        if not config.enabled:
            return result
        # TODO: 间接调用解析、虚函数分派推断、冲突裁决、语义分析
        return result
```

### 7.7 Phase 6: 数据导入（Neo4j）

数据导入由 Orchestrator 在 `analyze_with_snapshot()` 中统一管理（参见 §1.7），不再是独立的 Importer 类。

流程：
1. **MongoDB 建目录**：`SnapshotManager.acquire_or_wait()` → 创建 Snapshot 元信息（`status: "building"`）→ 拿到 `snapshot_id`
2. **Neo4j 建图**：`GraphStore` 将 `AnalysisResult` 写入 Neo4j
   - 创建 `:Snapshot` 节点（关联 `snapshot_id`）
   - 批量创建 `:Function` 节点（`FunctionRecord` → `:Function`）
   - 批量创建 `:CALLS` 边（`CallEdge` → `:CALLS`）
   - 创建 `:Fuzzer` 节点 + `:ENTRY` 边
3. **MongoDB 更新状态**：`status: "completed"`，写入 `node_count`、`edge_count`、`fuzzer_names`

```python
# 伪代码（实际逻辑在 orchestrator.analyze_with_snapshot 中）

snapshot_doc = snapshot_manager.acquire_or_wait(repo_url, version, backend)
snapshot_id = str(snapshot_doc["_id"])

try:
    # Phase 1-4a: 探测 → 构建命令 → library-only bitcode → SVF 库调用图
    result = await self._run_pipeline(...)

    # Phase 4b: 解析 fuzzer 源码 → fuzzer_calls {fuzzer_name: [库函数名]}
    fuzzer_calls = FuzzerEntryParser().parse(fuzzer_sources, ...)

    # Phase 6: 写入 Neo4j
    graph_store.create_snapshot_node(snapshot_id, repo_url, version, backend)
    func_count = graph_store.import_functions(snapshot_id, result.functions)
    edge_count = graph_store.import_edges(snapshot_id, result.edges)

    # 导入 fuzzer 节点 + LLVMFuzzerTestOneInput + fuzzer→库函数 CALLS 边
    fuzzer_infos = self._assemble_fuzzer_infos(fuzzer_sources, fuzzer_calls)
    graph_store.import_fuzzers(snapshot_id, fuzzer_infos)

    # BFS 计算 REACHES 边
    reaches = self._compute_reaches(snapshot_id, fuzzer_infos)
    graph_store.import_reaches(snapshot_id, reaches)

    # 更新 MongoDB 目录
    fuzzer_names = [f.name for f in fuzzer_infos]
    snapshot_manager.mark_completed(snapshot_id, func_count, edge_count, fuzzer_names)

except Exception as e:
    snapshot_manager.mark_failed(snapshot_id, str(e))
    raise
```

**FuzzerInfo 组装逻辑：**

```python
@dataclass
class FuzzerInfo:
    """写入 Neo4j :Fuzzer 节点的完整信息"""
    name: str                              # fuzzer 名（工单 JSON key）
    entry_function: str                    # 固定为 "LLVMFuzzerTestOneInput"
    files: List[Dict[str, str]]            # [{path, source}]，source = "user"
    called_library_functions: List[str]    # 该 fuzzer 调用的库函数名列表（Phase 4b 输出）
    focus: Optional[str] = None            # 可选标注

def _assemble_fuzzer_infos(
    self,
    fuzzer_sources: Dict[str, List[str]],     # 工单 JSON 输入
    fuzzer_calls: Dict[str, List[str]],       # Phase 4b 输出 {fuzzer_name: [库函数名]}
) -> List[FuzzerInfo]:
    """
    合并工单 fuzzer_sources 和 FuzzerEntryParser 结果 → FuzzerInfo 列表。

    流程：
    1. 遍历 fuzzer_sources 中的每个 fuzzer
    2. 从 fuzzer_calls 获取该 fuzzer 调用的库函数列表
    3. 组装 FuzzerInfo
    """
    infos = []
    for fuzzer_name, source_files in fuzzer_sources.items():
        infos.append(FuzzerInfo(
            name=fuzzer_name,
            entry_function="LLVMFuzzerTestOneInput",
            files=[{"path": f, "source": "user"} for f in source_files],
            called_library_functions=fuzzer_calls.get(fuzzer_name, []),
        ))
    return infos
```

**Neo4j 导入 Fuzzer 节点 + 连接边：**

```
对每个 FuzzerInfo：
1. 创建 :Fuzzer 节点（name, entry_function, files）
2. 创建 :Function 节点 — LLVMFuzzerTestOneInput（该 fuzzer 专属，file_path 取 fuzzer 主源文件）
3. 创建 (:Fuzzer)-[:ENTRY]->(:Function {name: "LLVMFuzzerTestOneInput"}) 边
4. 对 called_library_functions 中的每个库函数：
   创建 (:Function {name: "LLVMFuzzerTestOneInput"})-[:CALLS {call_type: "direct"}]->(:Function {name: lib_func}) 边
```

> **每个 fuzzer 有自己的 LLVMFuzzerTestOneInput 节点**：
> 虽然函数名相同，但 `file_path` 不同（各自的 fuzzer 主源文件），在 Neo4j 中是不同节点。
> 这样每个 fuzzer 的可达子树是独立的。

**REACHES 计算：**

```python
def _compute_reaches(
    self,
    snapshot_id: str,
    fuzzer_infos: List[FuzzerInfo],
) -> List[dict]:
    """
    对每个 fuzzer，从其 LLVMFuzzerTestOneInput 出发 BFS，计算 REACHES 边 + depth。
    利用 Neo4j 中已导入的 :CALLS 边进行图遍历。

    前提：此时 Neo4j 中已经有：
    - 所有库函数的 :Function 节点 + :CALLS 边（Phase 4a SVF 输出）
    - 每个 fuzzer 的 LLVMFuzzerTestOneInput 节点 + 到库函数的 :CALLS 边（Phase 4b 输出）

    返回: [{fuzzer_name, function_name, file_path, depth}, ...]
    depth=1 是 LLVMFuzzerTestOneInput 的直接 callee，不含 entry 自身。
    """
    reaches = []
    for fuzzer in fuzzer_infos:
        # BFS from this fuzzer's LLVMFuzzerTestOneInput (identified by file_path)
        fuzzer_main_file = fuzzer.files[0]["path"]  # 主源文件区分同名节点
        bfs_result = self.graph_store.raw_query(
            """
            MATCH path = (entry:Function {snapshot_id: $sid,
                                          name: "LLVMFuzzerTestOneInput",
                                          file_path: $fpath})
                         -[:CALLS*1..50]->(f:Function {snapshot_id: $sid})
            WITH f.name AS func_name, f.file_path AS file_path, min(length(path)) AS depth
            RETURN func_name, file_path, depth
            """,
            {"sid": snapshot_id, "fpath": fuzzer_main_file}
        )
        for row in bfs_result:
            reaches.append({
                "fuzzer_name": fuzzer.name,
                "function_name": row["func_name"],
                "depth": row["depth"],
            })
    return reaches
```

> **Library-only 架构**：SVF 只分析 `library.bc`（不含 fuzzer 代码），输出纯库调用图。
> Fuzzer 入口通过源码解析连接到库函数。所有 fuzzer 共享同一份库调用图，SVF 只跑一次。

**注意**：`reached_by_fuzzers` 不再存储，通过 Neo4j Cypher 实时查询：
```cypher
MATCH (fz:Fuzzer)-[:ENTRY]->()-[:CALLS*]->(func:Function)
WHERE fz.snapshot_id = $snapshot_id
RETURN func.name, collect(DISTINCT fz.name) AS reached_by
```

### 7.8 StaticAnalysisOrchestrator

编排器是分析管道的统一入口。

```python
# analysis/orchestrator.py

@dataclass
class AnalysisOutput:
    """Orchestrator 的返回值，面向调用方。"""
    snapshot_id: str          # MongoDB Snapshot 目录的 _id
    repo_url: str
    version: str
    backend: str
    function_count: int
    edge_count: int
    fuzzer_names: list[str]
    cached: bool              # True = 命中已有 Snapshot，False = 新分析


class StaticAnalysisOrchestrator:
    """
    静态分析编排器。统一管理 6 阶段管道。
    """

    def __init__(
        self,
        snapshot_manager: SnapshotManager,
        graph_store: GraphStore,
        registry: Optional[BackendRegistry] = None,
        ai_config: Optional[AIRefinerConfig] = None,
    ):
        self.snapshot_manager = snapshot_manager
        self.graph_store = graph_store
        self.registry = registry or BackendRegistry()
        self.ai_config = ai_config or AIRefinerConfig()
        self.progress = ProgressTracker()

    async def analyze(
        self,
        project_path: str,
        repo_url: str,
        version: str,
        build_script: Optional[str] = None,       # 用户提供的构建脚本路径
        fuzzer_sources: Dict[str, List[str]],            # 必传，{fuzzer_name: [source_files]}
        language: Optional[str] = None,           # 覆盖自动检测
        backend: Optional[str] = None,            # 覆盖自动选择
        diff_files: Optional[List[str]] = None,   # 增量分析
    ) -> AnalysisOutput:
        """
        完整分析流水线入口。

        流程：
        0. 查询 Snapshot 缓存（MongoDB）
           命中 → 直接返回 AnalysisOutput(cached=True)
        1. Phase 1: 项目探测
        2. Phase 2: 构建命令提取（三层降级）
        3. Phase 3: Bitcode 生成（library-only，排除 fuzzer 源文件）
        4a. Phase 4a: SVF 分析（库代码调用图）
        4b. Phase 4b: Fuzzer 入口解析（源码级）
        5. Phase 5: AI 精化（预留）
        6. Phase 6: 数据导入（Neo4j + fuzzer 连接 + REACHES 计算）
        """

        # Snapshot 查询/占位
        snapshot_doc = await self.snapshot_manager.acquire_or_wait(
            repo_url, version, backend or "auto"
        )

        # 缓存命中
        if snapshot_doc["status"] == "completed":
            return AnalysisOutput(
                snapshot_id=str(snapshot_doc["_id"]),
                repo_url=repo_url, version=version,
                backend=snapshot_doc["backend"],
                function_count=snapshot_doc["node_count"],
                edge_count=snapshot_doc["edge_count"],
                fuzzer_names=snapshot_doc.get("fuzzer_names", []),
                cached=True,
            )

        # 缓存未命中 → 执行完整分析
        snapshot_id = str(snapshot_doc["_id"])
        try:
            # Phase 1: 项目探测
            self.progress.start_phase("probe")
            info = ProjectProbe().probe(project_path, diff_files)
            self.progress.complete_phase("probe")

            # Phase 2: 构建命令提取（三层降级）
            self.progress.start_phase("build_cmd")
            build_cmd = BuildCommandDetector().detect_or_infer(
                project_path, info, build_script=build_script
            )
            self.progress.complete_phase("build_cmd",
                detail=f"{build_cmd.build_system} (source: {build_cmd.source})")

            # Phase 3: Bitcode 生成（library-only，排除 fuzzer 源文件）
            self.progress.start_phase("bitcode")
            all_fuzzer_files = [f for files in fuzzer_sources.values() for f in files]
            bitcode_output = BitcodeGenerator().generate(
                project_path, build_cmd, fuzzer_source_files=all_fuzzer_files
            )
            self.progress.complete_phase("bitcode",
                detail=f"{bitcode_output.bc_path}, {len(bitcode_output.function_metas)} lib functions")

            # Phase 4a: SVF 分析（库代码调用图，不含 fuzzer）
            self.progress.start_phase("svf")
            result = SVFBackend().analyze(project_path, detected_lang,
                bc_path=bitcode_output.bc_path, function_metas=[...])
            self.progress.complete_phase("svf",
                detail=f"{len(result.functions)} functions, {len(result.edges)} edges")

            # Phase 4b: Fuzzer 入口解析（源码级，提取 fuzzer → 库函数调用）
            self.progress.start_phase("fuzzer_parse")
            library_func_names = {f.name for f in result.functions}
            fuzzer_calls = FuzzerEntryParser().parse(
                fuzzer_sources, library_func_names, project_path
            )
            self.progress.complete_phase("fuzzer_parse",
                detail=f"{len(fuzzer_sources)} fuzzers parsed")

            # Phase 5: AI 精化（预留）
            if self.ai_config.enabled:
                self.progress.start_phase("ai_refine")
                result = await AIRefiner(self.ai_config).refine(result)
                self.progress.complete_phase("ai_refine")

            # Phase 6: 写入 Neo4j + 更新 MongoDB 目录
            self.progress.start_phase("import")
            self.graph_store.create_snapshot_node(snapshot_id, repo_url, version, "svf")
            func_count = self.graph_store.import_functions(snapshot_id, result.functions)
            edge_count = self.graph_store.import_edges(snapshot_id, result.edges)

            # 组装 FuzzerInfo：合并工单 fuzzer_sources + Phase 4b 的 fuzzer_calls
            fuzzer_infos = self._assemble_fuzzer_infos(fuzzer_sources, fuzzer_calls)
            self.graph_store.import_fuzzers(snapshot_id, fuzzer_infos)

            # BFS 计算每个 fuzzer 的 REACHES 边
            reaches = self._compute_reaches(snapshot_id, fuzzer_infos)
            self.graph_store.import_reaches(snapshot_id, reaches)

            fuzzer_names = [f.name for f in fuzzer_infos]
            self.snapshot_manager.mark_completed(
                snapshot_id, func_count, edge_count, fuzzer_names
            )
            self.progress.complete_phase("import",
                detail=f"{func_count} functions, {edge_count} edges")

            return AnalysisOutput(
                snapshot_id=snapshot_id,
                repo_url=repo_url, version=version,
                backend="svf",
                function_count=func_count,
                edge_count=edge_count,
                fuzzer_names=fuzzer_names,
                cached=False,
            )

        except Exception as e:
            self.snapshot_manager.mark_failed(snapshot_id, str(e))
            raise
```

### 7.9 增量分析（Delta）支持

当 `scan_mode="delta"` 时，只分析 git diff 变更的文件。

```python
class IncrementalAnalyzer:
    """
    增量分析策略：
    1. 从 diff 中提取变更文件列表
    2. 后端只分析变更文件 + 直接依赖文件
    3. 合并时：变更函数用新结果覆盖，未变更函数保留 Neo4j 中旧 Snapshot 的结果
    4. 调用图：重新计算变更函数的边，未变更边保留
    5. 写入新 Snapshot（新版本号），旧 Snapshot 保留可回溯
    """

    def get_affected_files(self, diff_files: List[str], edges: List[CallEdge]) -> List[str]:
        """扩展变更范围：变更文件 + 被变更文件中函数直接调用的文件"""
        ...

    def merge_with_existing(
        self,
        snapshot_id: str,
        new_result: AnalysisResult,
        diff_files: List[str],
    ) -> AnalysisResult:
        """
        从 Neo4j 旧 Snapshot 读取数据，与新分析结果合并：
        - 变更文件中的函数：用新结果
        - 未变更文件中的函数：从旧 Snapshot 复制
        - 调用边：重新计算所有涉及变更函数的边
        - 写入新 Snapshot，旧 Snapshot 不删除
        """
```

### 7.10 日志存储

每个 Snapshot 的分析过程产生日志，按 Phase 分文件存储。

**目录结构：**

```
logs/snapshots/{snapshot_id}/
  ├── probe.log          # Phase 1: 语言检测、文件数、构建系统
  ├── build_cmd.log      # Phase 2: 哪层降级命中、生成的命令
  ├── bitcode.log        # Phase 3: wllvm 编译输出、llvm-link 输出
  ├── svf.log            # Phase 4a: wpa 输出、DOT 解析统计
  ├── fuzzer_parse.log   # Phase 4b: fuzzer 源码解析、库函数匹配
  ├── ai_refine.log      # Phase 5: (预留)
  └── import.log         # Phase 6: Neo4j 写入统计
```

**LogStore 抽象接口：**

```python
class LogStore(ABC):
    """日志存储抽象层，v1 用本地文件，未来可切换 S3。"""

    @abstractmethod
    def get_writer(self, snapshot_id: str, phase: str) -> IO:
        """获取某个 phase 的日志写入句柄"""

    @abstractmethod
    def read_log(self, snapshot_id: str, phase: str) -> str:
        """读取日志内容（排查失败用）"""

    @abstractmethod
    def delete_logs(self, snapshot_id: str) -> None:
        """删除 Snapshot 的所有日志（随 Snapshot 淘汰一起删）"""


class LocalLogStore(LogStore):
    """本地文件日志存储（v1 默认）"""

    def __init__(self, base_dir: str = "logs/snapshots"):
        self.base_dir = Path(base_dir)


class S3LogStore(LogStore):
    """S3 日志存储（未来扩展）"""
    ...
```

**生命周期：**
- 日志与 Snapshot 绑定，Snapshot 淘汰时日志一起删
- 分析失败时日志保留，方便排查构建/分析错误
- ProgressTracker 的每个 phase 回调自动写入对应日志文件

**与 FBv2 兼容：**
- FBv2 使用 loguru 写 per-task 日志，本系统不依赖 loguru
- 合入 FBv2 后，`LocalLogStore` 的 `base_dir` 可指向 FBv2 的 task 日志目录

### 7.11 进度跟踪与可观测性

```python
@dataclass
class PhaseProgress:
    phase: str
    status: str              # "pending" | "running" | "completed" | "failed" | "skipped"
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    detail: str = ""
    error: Optional[str] = None


class ProgressTracker:
    """
    分析管道进度跟踪。
    支持回调通知和日志记录。
    """
    phases: List[PhaseProgress]
    callbacks: List[Callable[[PhaseProgress], None]]

    def start_phase(self, phase: str): ...
    def complete_phase(self, phase: str, detail: str = ""): ...
    def fail_phase(self, phase: str, error: str): ...
    def skip_phase(self, phase: str, reason: str): ...
    def get_summary(self) -> Dict[str, Any]:
        """返回所有阶段的状态摘要，含耗时统计"""
        ...
```

---
