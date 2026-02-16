## 6. 语言检测与工具链自动选择

### 6.1 LanguageDetector

自动检测项目的主要编程语言和语言分布。

```python
# analysis/backends/language_detector.py

@dataclass
class LanguageProfile:
    """项目的语言分布"""
    primary_language: str                    # 主要语言
    language_distribution: Dict[str, float]  # {语言: 占比}，如 {"c": 0.7, "cpp": 0.3}
    build_system: Optional[str]              # 检测到的构建系统
    detected_features: List[str]             # 特征列表


class LanguageDetector:
    """
    项目语言检测器。
    三层检测策略，按优先级递减：
    """

    # 层 1：扩展名统计
    EXTENSION_MAP = {
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
    BUILD_SYSTEM_INDICATORS = {
        "CMakeLists.txt": ("cmake", {"c", "cpp"}),
        "Makefile": ("make", {"c", "cpp"}),         # 需进一步检查
        "configure.ac": ("autotools", {"c", "cpp"}),
        "meson.build": ("meson", {"c", "cpp"}),
        "build.gradle": ("gradle", {"java"}),
        "pom.xml": ("maven", {"java"}),
        "go.mod": ("go_modules", {"go"}),
        "Cargo.toml": ("cargo", {"rust"}),
        "package.json": ("npm", {"javascript", "typescript"}),
    }

    # 层 3：特征文件检测
    FEATURE_INDICATORS = {
        "compile_commands.json": "has_compile_commands",
        ".clang-format": "uses_clang_tools",
        "compile_flags.txt": "has_compile_flags",
    }

    def detect(self, project_path: str) -> LanguageProfile:
        """
        执行语言检测。

        步骤：
        1. 遍历所有源文件，按扩展名统计语言分布
        2. 检测构建系统文件，交叉验证
        3. 检测特征文件
        4. 确定主要语言（占比最高的）
        5. 排除 vendor/、third_party/、build/、.git/ 等目录
        """
```

### 6.2 ToolchainSelector

根据语言检测结果和运行环境，自动选择最优后端组合。

```python
# analysis/backends/toolchain_selector.py

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
