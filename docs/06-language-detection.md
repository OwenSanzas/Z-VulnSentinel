## 6. 语言检测与工具链自动选择

### 6.1 ProjectProbe（语言检测 + 构建系统识别）

> **v1 实现**: `LanguageDetector` 和 `ToolchainSelector` 设计合并为 `ProjectProbe` 类。
> 文件: `z_code_analyzer/probe.py`

自动检测项目的主要编程语言和构建系统。

```python
# z_code_analyzer/probe.py

@dataclass
class LanguageProfile:
    """项目的语言分布"""
    primary_language: str                         # 主要语言
    file_counts: dict[str, int] = field(default_factory=dict)  # {语言: 文件数}，如 {"c": 70, "cpp": 30}
    confidence: float = 1.0                       # 检测置信度
    detected_features: list[str] = field(default_factory=list)  # 特征列表


class ProjectProbe:
    """
    项目探测器：语言检测 + 构建系统识别。
    三层检测策略，按优先级递减：
    """

    # 层 1：扩展名统计
    _EXTENSION_TO_LANGUAGE = {
        ".c": "c", ".h": "c",
        ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
        ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".py": "python",
        ".js": "javascript", ".ts": "typescript",
    }

    # 层 2：构建系统推断
    # 注: .h 文件若有更多 .cpp 源文件会被重新归类为 cpp
    _BUILD_SYSTEM_MARKERS = [
        ("CMakeLists.txt", "cmake"),
        ("configure.ac", "autotools"),
        ("configure.in", "autotools"),
        ("configure", "autotools"),
        ("meson.build", "meson"),
        ("build.sh", "custom"),
        ("Makefile", "make"),
        ("build.gradle", "gradle"),
        ("pom.xml", "maven"),
        ("go.mod", "go_modules"),
        ("Cargo.toml", "cargo"),
        ("package.json", "npm"),
    ]

    # 层 3：特征文件检测
    FEATURE_INDICATORS = {
        "compile_commands.json": "has_compile_commands",
        ".clang-format": "uses_clang_tools",
        "compile_flags.txt": "has_compile_flags",
    }

    def probe(self, project_path: str, diff_files: list[str] | None = None) -> ProjectInfo:
        """
        执行项目探测。

        返回 ProjectInfo（含 language_profile, build_system, source_files）。
        步骤：
        1. 遍历所有源文件，按扩展名统计语言分布
        2. 检测构建系统文件，交叉验证
        3. 检测特征文件
        4. 确定主要语言（文件数最多的）
        5. 排除 vendor/、third_party/、build/、.git/ 等目录
        """
```

### 6.2 ToolchainSelector（v2 设计，未实现）

> **v1 状态**: 后端选择在 `orchestrator.py` 中内联处理（v1 硬编码 SVF）。
> 以下为 v2 预留设计。

根据语言检测结果和运行环境，自动选择最优后端组合。

```python
# analysis/backends/toolchain_selector.py  （v2 计划）

@dataclass
class ToolchainDecision:
    """工具链选择结果"""
    mode: str                                     # "single" | "serial" | "parallel"
    backends: List[str]                           # 有序后端列表
    rationale: str                                # 选择理由
    estimated_duration_seconds: float             # 预估耗时
    warnings: List[str] = field(default_factory=list)


class ToolchainSelector:
    """
    根据项目特征自动选择最优后端组合。
    """

    def select(
        self,
        profile: LanguageProfile,
        registry: BackendRegistry,
        preferences: Optional[Dict] = None,
    ) -> ToolchainDecision:
        """
        选择逻辑：

        C/C++ 项目：
          有 Docker + 可编译 → 单后端（SVF）
          编译失败 → 单后端（Joern）
          有 introspector 数据 → 单后端（Introspector）

        Java 项目：
          v1 不支持，预留 JavaBackend 接口

        Go 项目：
          v1 不支持，预留 GoBackend 接口

        其他语言：
          v1 不支持，返回错误提示

        用户偏好 preferences 可覆盖自动选择。
        """
```

### 6.3 多语言项目处理策略

当项目包含多种语言时（如 C 核心 + Python 绑定 + Go 工具）：

```
检测结果: {"c": 0.6, "python": 0.25, "go": 0.15}
                    │
                    ▼
           按语言分组源文件
           ├── C/C++ 文件组 → SVF 后端（v1）
           ├── Python 文件组 → 预留
           └── Go 文件组 → 预留
                    │
                    ▼
           分别分析 → 各组产出 AnalysisResult
                    │
                    ▼
           合并所有 AnalysisResult → 统一导入 Neo4j
```

**跨语言调用处理：**
- FFI 调用（如 Python ctypes 调用 C 函数）暂不解析
- 只记录各语言内部的调用图
- 跨语言边可由 AI Refiner 尝试推断（未来增强）

---
