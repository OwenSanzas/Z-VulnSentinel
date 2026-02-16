## 3. 后端注册与能力声明

### 3.1 BackendRegistry

插件式后端注册中心，所有后端通过注册表发现和管理。

```python
# analysis/backends/registry.py

class BackendCapability(Enum):
    """分析能力枚举"""
    FUNCTION_EXTRACTION = "function_extraction"   # 提取函数元信息
    DIRECT_CALLS = "direct_calls"                 # 直接调用边
    VIRTUAL_DISPATCH = "virtual_dispatch"         # 虚函数分派解析
    FUNCTION_POINTERS = "function_pointers"       # 函数指针目标解析
    MACRO_EXPANSION = "macro_expansion"           # 宏展开后分析
    TEMPLATE_INSTANTIATION = "template_instantiation"  # 模板实例化
    TYPE_RESOLUTION = "type_resolution"           # 类型解析
    COMPLEXITY_METRICS = "complexity_metrics"      # 复杂度度量
    DATA_FLOW = "data_flow"                       # 数据流分析


@dataclass
class BackendDescriptor:
    """后端能力声明"""
    name: str                                # 唯一标识
    supported_languages: Set[str]            # {"c", "cpp", "java", ...}
    capabilities: Set[BackendCapability]     # 支持的分析能力
    precision_score: float                   # 精度评分 0.0-1.0
    speed_score: float                       # 速度评分 0.0-1.0（越高越快）
    prerequisites: List[str]                 # 前置条件描述
    factory: Callable[[], AnalysisBackend]   # 后端工厂函数


class BackendRegistry:
    """后端注册中心（实例化使用，避免全局状态，方便测试）"""

    def __init__(self):
        self._backends: Dict[str, BackendDescriptor] = {}

    def register(self, descriptor: BackendDescriptor):
        self._backends[descriptor.name] = descriptor

    def get(self, name: str) -> Optional[BackendDescriptor]:
        return self._backends.get(name)

    def list_all(self) -> List[BackendDescriptor]:
        return list(self._backends.values())

    def find_by_language(self, language: str) -> List[BackendDescriptor]:
        """按语言过滤，按 precision_score 降序排列"""
        return sorted(
            [d for d in self._backends.values() if language in d.supported_languages],
            key=lambda d: d.precision_score,
            reverse=True,
        )

    def find_by_capability(self, cap: BackendCapability) -> List[BackendDescriptor]:
        return [d for d in self._backends.values() if cap in d.capabilities]

    def find_best_backend(self, language: str, project_path: str) -> Optional[AnalysisBackend]:
        """按精度降序尝试后端，检查前置条件，返回第一个可用的。"""
        for desc in self.find_by_language(language):
            backend = desc.factory()
            if not backend.check_prerequisites(project_path):
                return backend
        return None
```

### 3.2 核心接口

```python
# analysis/backends/base.py

class CallType(Enum):
    """函数调用类型（v1 只有 DIRECT 和 FPTR，其余为未来扩展预留）"""
    DIRECT = "direct"           # foo() 直接调用
    FPTR = "fptr"               # callback(x) 函数指针（SVF 分析结果）


@dataclass
class FunctionRecord:
    """
    后端产出的函数记录。
    这是后端输出格式，不是存储模型。
    GraphStore 负责 FunctionRecord → Neo4j :Function 节点的写入。
    """
    name: str
    file_path: str              # 相对于项目根目录
    start_line: int
    end_line: int
    content: str                # 完整源码
    language: str               # "c", "cpp", "java", "go", "rust", ...
    cyclomatic_complexity: int = 0
    return_type: str = ""
    parameters: List[str] = field(default_factory=list)
    is_entry_point: bool = False  # v1 library-only 下 SVF 不产出此标记，预留给 v2 后端
    confidence: float = 1.0     # 提取置信度 0.0-1.0
    source_backend: str = ""    # 产出此记录的后端名


@dataclass
class CallEdge:
    """
    两个函数之间的调用关系。
    携带调用类型和可信度，供 ResultMerger 做合并决策。
    """
    caller: str
    callee: str
    call_type: CallType = CallType.DIRECT    # SVF 标记为 DIRECT 或 FPTR
    call_site_file: str = ""    # 调用发生的文件
    call_site_line: int = 0     # 调用发生的行号
    caller_file: str = ""       # caller 所在文件（消歧用）
    callee_file: str = ""       # callee 所在文件（消歧用）
    confidence: float = 1.0     # 可信度 0.0-1.0
    source_backend: str = ""    # 产出此边的后端名


@dataclass
class AnalysisResult:
    """
    静态分析后端的完整输出。所有后端都产出这个结构。
    注意：后端只负责库代码分析，不包含 fuzzer 入口信息。
    Fuzzer 入口由 FuzzerEntryParser（Phase 4b）单独处理。
    """
    functions: List[FunctionRecord]         # 提取的库函数列表
    edges: List[CallEdge]                   # 库代码调用图边
    language: str                           # 主要语言
    backend: str                            # 哪个后端产出的，如 "svf"
    analysis_duration_seconds: float = 0.0
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)  # 后端特有元数据


class AnalysisBackend(ABC):
    """
    静态分析后端的抽象基类。
    每个后端知道如何从项目中提取函数元信息和调用图。
    所有后端产出 AnalysisResult。
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """后端标识，如 'svf', 'joern', 'introspector'"""
        ...

    @property
    @abstractmethod
    def supported_languages(self) -> Set[str]:
        """支持的语言集合，如 {'c', 'cpp'}"""
        ...

    @abstractmethod
    def analyze(
        self,
        project_path: str,
        language: str,
        **kwargs,
    ) -> AnalysisResult:
        """
        对项目执行静态分析（仅库代码）。

        Args:
            project_path: 项目源码根目录
            language: 目标语言
            **kwargs: 后端特有选项
                SVF: bitcode_output: BitcodeOutput（Phase 3 产出）
                Joern(v2): 直接使用 project_path 源码

        Returns:
            AnalysisResult（仅库代码，不含 fuzzer 入口）

        注意：后端不需要知道 fuzzer 信息。
        Fuzzer → 库函数的连接由 FuzzerEntryParser（Phase 4b）完成。
        """
        ...

    def check_prerequisites(self, project_path: str) -> List[str]:
        """
        检查前置条件。
        返回缺失项列表（空 = 可以运行）。
        """
        return []

    def get_descriptor(self) -> Optional[BackendDescriptor]:
        """返回本后端的能力声明描述符。未注册时返回 None。"""
        return None
```

### 3.3 后端能力矩阵

| 后端 | 定位 | 函数提取 | 直接调用 | 虚函数 | 函数指针 | 精度 | 速度 | 前置条件 |
|------|------|---------|---------|--------|---------|------|------|---------|
| **SVF** | C/C++ 主力 (**v1**) | Y | Y | Y (CHA) | **Y (Andersen)** | **0.98** | 0.60 | Docker + 编译成功 + wllvm |
| **Joern** | C/C++ 降级 (**v2**) | Y | Y | Y (CHA) | **❌** | 0.85 | 0.50 | joern-cli |
| **Introspector** | 兼容 (预留) | Y | Y | Y | Y | 0.90 | 0.20 | Docker + OSS-Fuzz |
| **Prebuild** | 兼容 (预留) | Y | Y | 取决于源 | 取决于源 | 取决于源 | 0.99 | JSON 文件 |

**C/C++ 两套方案：**

```
SVF（主力）──── 编译级分析, LLVM IR Andersen 指针分析
 │               函数指针 ✅, 和 fuzzer 视角完全一致
 │
 │ 降级条件: Docker 不可用 / 编译失败 / bitcode 提取失败
 ▼
Joern（降级）── 非编译级分析, CPG 代码属性图
                 函数指针 ❌, 但直接调用 + 函数提取仍可用
                 不需要编译, 给源码就能跑
```

> **为什么不用 Tree-sitter？** C/C++ 有 Joern 就够了。Joern 做不到的（函数指针），Tree-sitter 更做不到。
>
> **其他语言？** 预留后端接口（`AnalysisBackend` ABC），当前只实现 C/C++。

**编译级 vs 非编译级的根本差异（实验验证）：**

| | SVF（编译级） | Joern（非编译级） |
|---|---|---|
| 分析对象 | 编译后的 LLVM IR（.bc bitcode） | 源码文本 |
| 和 fuzzer 视角一致 | ✅ 完全一致 | ❌ 会多扫到 `#ifdef` 未编译代码 |
| 函数指针解析 | ✅ Andersen 全程序指针分析 | ❌ 断在间接调用处 |
| 函数数量 | 精确（只含 binary 中的） | 偏多（含头文件、test、未编译分支） |
| 前置条件 | Docker + 编译成功 | 只需源码 |

### 3.4 SVF 后端：LLVM IR 级指针分析（C/C++ 主力引擎）

SVF 是 C/C++ 项目的**主力分析引擎**。基于 LLVM IR 的 Andersen 指针分析，是当前开源工具中解析函数指针最强的方案。

> **实验验证**（2025-02）: 在 libpng / lcms / curl 三个项目上验证，SVF 成功解析了 introspector 漏掉的所有函数指针调用路径。

#### 3.4.1 核心原理

SVF（Static Value-Flow Analysis）在 LLVM IR 上执行全程序 Andersen 包含分析（inclusion-based pointer analysis），追踪所有指针的可能指向目标：

```
源代码 → clang 编译 → LLVM IR (.bc) → SVF Andersen 分析 → 调用图
```

Andersen 分析建立约束系统：
- `p = &x` → `{x} ⊆ pts(p)`（p 可能指向 x）
- `p = q` → `pts(q) ⊆ pts(p)`（p 继承 q 的指向）
- `*p = q` → 对所有 `o ∈ pts(p)`, `pts(q) ⊆ pts(o)`
- `p = *q` → 对所有 `o ∈ pts(q)`, `pts(o) ⊆ pts(p)`

通过求解约束的不动点，确定每个函数指针变量可能指向的函数集合，从而构建精确调用图。

#### 3.4.2 已验证的间接调用场景

**场景 1: 回调注册（libpng）**
```c
// 用户注册自定义读取函数
png_set_read_fn(png_ptr, io_ptr, user_read_data);
// ...
png_read_data(png_ptr, data, length);
//   ↓ SVF 解析为
//   png_read_data → user_read_data (通过 png_ptr->read_data_fn 指针)
```
- introspector: **漏掉** `user_read_data`
- SVF: **正确发现** depth=2

**场景 2: Tag 类型处理表（lcms）**
```c
// 类型处理器通过全局表注册
static cmsTagTypeHandler SupportedTagTypes[] = {
    { cmsSigTextDescriptionType, Type_Text_Description_Read, ... },
    ...
};
// cmsReadTag 通过表查找调用对应的 Read 函数
cmsReadTag(hProfile, sig);
//   ↓ SVF 解析为
//   cmsReadTag → ... → Type_Text_Description_Read → convert_utf16_to_utf32
```
- introspector: **漏掉** `convert_utf16_to_utf32`（reached_by_fuzzers 为空）
- SVF: **正确发现** depth=5

**场景 3: 协议处理器函数指针表（curl）**
```c
// 每个协议注册处理函数
static const struct Curl_handler Curl_handler_dict = {
    .curl_do = dict_do,
    .curl_done = dict_done,
    ...
};
// 通过 conn->handler->curl_do() 调用
multi_runsingle(multi, &now, data);
//   ↓ SVF 解析为
//   multi_runsingle → dict_do (通过 conn->handler->curl_do 指针)
```
- introspector: **漏掉** `dict_do` 的调用路径
- SVF: **正确发现** depth=4, 路径: `LLVMFuzzerTestOneInput → fuzz_handle_transfer → curl_multi_perform → multi_runsingle → dict_do`

#### 3.4.3 Bitcode 提取流程（Library-Only）

SVF 需要 whole-program LLVM bitcode。通过 **wllvm**（Whole-program LLVM）透明包装，构建后选择性链接库代码：

```bash
# 1. wllvm 作为编译器包装，透明记录每个 .o 对应的 .bc
export CC=z-wllvm CXX=z-wllvm++   # 薄包装，自动追加 -g
export LLVM_COMPILER=clang

# 2. 正常构建项目（build.sh / configure / cmake 均可）
#    build.sh 会编译库代码 + fuzzer 代码，全部通过 wllvm 追踪
./build.sh

# 3. 收集所有 .o 对应的 .bc，排除 fuzzer 源文件的 .bc
#    fuzzer 源文件由工单 JSON 的 fuzzer_sources 指定
#    例如排除 fuzz/fuzz_http.o.bc, fuzz/fuzz_ftp.o.bc 等

# 4. llvm-link 剩余库代码 .bc → library.bc（无 LLVMFuzzerTestOneInput 符号冲突）
llvm-link lib/*.bc src/*.bc -o library.bc
```

**为什么不用 `extract-bc binary`：** 一个项目有多个 fuzzer binary，每个都含 `LLVMFuzzerTestOneInput`（全局符号），`llvm-link` 无法合并同名全局函数。Library-only 方案排除所有 fuzzer .bc，只链接库代码，SVF 跑一次，所有 fuzzer 共享。

**关键实现细节（从实验中总结）：**

| 问题 | 解决方案 |
|------|---------|
| LLVM 版本不匹配 | 自动检测 clang 版本，安装匹配的 `llvm-link-N` |
| `libFuzzingEngine.a` 缺失 | 使用 stub engine（只提供 `main()`，不实际 fuzz） |
| 动态库链接失败 | `--disable-shared` 强制静态链接 |
| 非必要依赖编译失败 | 禁用非核心功能（如 `--without-nghttp2`） |

#### 3.4.4 三种构建模式

根据项目特征和 harness 位置，分三种模式：

**模式 A: intree-autotools（harness 在项目内 + autotools）**

适用项目: libpng, lcms, ...
```
项目源码/
├── src/          # 项目代码
├── configure.ac  # autotools 构建
└── fuzzers/      # harness 在项目内
    └── fuzz.c
```

流程: `autoreconf → configure → make`（wllvm 追踪所有 .o → .bc）→ 收集库代码 .bc → llvm-link → library.bc

**模式 B: intree-cmake（harness 在项目内 + cmake）**

适用项目: libxml2, ...
```
项目源码/
├── src/
├── CMakeLists.txt
└── fuzz/
    └── fuzz_xml.c
```

流程: `cmake → make`（wllvm 追踪所有 .o → .bc）→ 收集库代码 .bc → llvm-link → library.bc

**模式 C: ossfuzz-script（harness 在外部 oss-fuzz 仓库）**

适用项目: curl, wireshark, ...
```
oss-fuzz Docker 容器:
├── $SRC/curl/           # 项目源码
├── $SRC/curl_fuzzer/    # 外部 harness 仓库
└── build.sh             # oss-fuzz 构建脚本
```

流程: 复用 oss-fuzz Dockerfile（依赖已装好）→ 注入 wllvm 环境 → build.sh → 收集库代码 .bc → llvm-link → library.bc

**这是最复杂的模式**，因为每个 oss-fuzz 项目的构建脚本、依赖、harness 结构都不同，需要项目特定的 case 配置。

#### 3.4.5 Docker 编排

SVF 分析涉及两个 Docker 容器：

```
┌─────────────────────────────┐     ┌──────────────────────┐
│  项目构建容器                │     │  SVF 分析容器         │
│  (oss-fuzz base / 自定义)   │     │  (svftools/svf)      │
│                             │     │                      │
│  1. apt install wllvm       │     │  4. wpa -ander       │
│  2. CC=z-wllvm build.sh    │ .bc │     -dump-callgraph  │
│  3. 收集库 .bc → llvm-link ─┼────▶│  5. 输出 .dot        │
│                             │     │                      │
└─────────────────────────────┘     └──────────────────────┘
          挂载: 源码 + 脚本               挂载: .bc 文件
```

### 3.5 Joern 后端：CPG 非编译级分析（v2 降级方案，v1 不实现）

> **v1 不实现此后端。** 以下为 v2 降级方案的设计参考。
> 当 SVF 的前置条件不满足时（Docker 不可用、编译失败），自动降级到 Joern。

**核心原理：** Joern 构建代码属性图（Code Property Graph），结合 AST、CFG、PDG，通过数据流分析提取调用关系。不需要编译，直接解析源码。

```bash
# CPG 构建 (~10s)
joern-parse /path/to/src -o cpg.bin

# 调用图提取 (~8s)
joern --script callgraph.sc --param cpgPath=cpg.bin --param outputPath=result.json
```

**优势：**
- 不需要编译成功，给源码就能跑
- CPG 构建速度快（lcms ~10s，curl ~12s）
- 直接调用关系的发现基本完整

**局限（实验验证）：**
- **函数指针调用完全断裂** — 非编译分析的根本限制，不是 Joern 的 bug
- 会多扫到不在 binary 中的函数（头文件、test、`#ifdef` 未编译分支）
- 和 fuzzer 实际执行的 binary 视角不一致

> **实验验证**（2025-02）: 在 lcms 和 curl 上对比 SVF vs Joern：

| 项目 | | SVF | Joern | 差异 |
|------|---|-----|-------|------|
| **lcms** | 函数数 | 1,301 | 2,428 | Joern 多 86%（含头文件/test 噪声） |
| | 调用边 | 15,226 | 22,423 | Joern 边更多但含 operator 节点 |
| | `convert_utf16_to_utf32` 可达 | ✅ depth=5 | **❌ 不可达** | 断在 tag type handler 函数指针表 |
| **curl** | 函数数 | 2,334 | 3,581 | Joern 多 53% |
| | 调用边 | 18,540 | 21,020 | |
| | `dict_do` 可达 | ✅ depth=4 | **❌ 不可达** | 断在 `conn->handler->curl_do` 函数指针 |

**结论：Joern 函数更多但关键调用边断裂。多了不该有的（噪声），少了最该有的（函数指针边）。**
作为降级方案仍有价值 — 直接调用关系和函数元信息提取仍然可用，总比没有强。

### 3.6 Tree-sitter 的定位

Tree-sitter **不是 SAST 后端**（不注册到 `BackendRegistry`），但在两个场景中使用：

1. **FuzzerEntryParser（Phase 4b）**：解析 fuzzer 源文件，提取函数调用关系。Fuzzer harness 代码简单，tree-sitter 的精度足够。
2. **FBv2 MCP 工具**：实时函数源码提取（`get_function_source` RPC），与 SAST 引擎无关。

库代码的调用图分析由 SVF 完成，tree-sitter 不参与。

### 3.7 兼容后端

| 后端 | 说明 |
|------|------|
| **Introspector** | 封装现有 fuzz-introspector 逻辑，向后兼容 |
| **Prebuild** | 从 `prebuild/{work_id}/mongodb/` 导入预计算数据 |

### 3.8 未来后端规划

| 后端 | 语言 | 工具 | 核心能力 | 预估精度 |
|------|------|------|---------|---------|
| **JavaBackend** | java | Soot / WALA | 字节码分析，完整类层次，虚分派解析 | 0.90 |
| **GoBackend** | go | go/analysis (SSA) | SSA 形式分析，接口方法解析 | 0.90 |
| **RustBackend** | rust | rust-analyzer / MIR | trait 解析，泛型单态化 | 0.85 |

---
