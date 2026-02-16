## 2. 多后端编排

系统支持三种编排模式，由 `StaticAnalysisOrchestrator` 根据配置和项目特征自动选择。

### 2.1 单后端模式

最简单的模式——指定或自动选择一个后端，直接执行。

```
项目 ──▶ [选择后端] ──▶ Backend.analyze() ──▶ AnalysisResult ──▶ Neo4j
```

**使用场景：**
- 用户显式指定 `analysis_backend="svf"` / `"joern"` / `"introspector"`
- 自动模式下只有一个后端满足前置条件
- 速度优先的场景（如 CI/CD 集成）

**自动选择逻辑——三层降级链：**
```python
def auto_select_single(project_path, language) -> AnalysisBackend:
    """
    始终选择当前可用的最强后端，最大化分析准确率和召回率。

    三层降级链（精度从高到低）：

    1. SVF（C/C++）— 需要 Docker + 编译成功 + wllvm bitcode 提取
       精度最高：Andersen 指针分析，能解析函数指针、回调、协议处理表
       已验证：libpng(1.4s), lcms(7s), curl(73s) 全部正确

    2. Joern（C/C++/Java/Python/Go/...）— 只需源码，不需要编译
       精度中等：CPG（代码属性图）+ 数据流分析
       兼容性强：编译失败时自动降级到这里

    Introspector / Prebuild 仅在显式指定或检测到已有数据时使用。

    降级触发条件：
    - SVF → Joern: Docker 不可用 / 编译失败 / bitcode 提取失败
    """
```

### 2.2 串行增强模式

多个后端按精度递增顺序串行执行，后一个在前一个结果基础上**补全和修正**。

```
项目 ──▶ SVF（编译级分析, 分钟级）
              │
              ▼ base_result（函数 + 直接调用边 + 函数指针边）
         AI Refiner（精化, 可选, v1 预留）
              │
              ▼ final_result ──▶ Neo4j
```

> **v1 只实现 SVF 单后端。** 串行增强模式为 v2 预留，届时可在 SVF 基础上叠加 Joern 等后端。

**增强规则（v2）：**
- 函数记录：后端产出并集，相同函数用高精度后端的字段覆盖
- 调用边：并集，SVF 产出的边优先于 Joern
- AI 精化只处理标记为 `FPTR` 的未解析边

**使用场景：**
- C/C++ 项目 + Docker 环境可用
- 用户配置 `orchestration_mode="serial"`

### 2.3 并行融合模式

多个后端并行执行，结果通过 `ResultMerger` 合并。

```
         ┌──▶ SVF ──────────▶ Result A ──┐
项目 ────┤                                ├──▶ ResultMerger ──▶ merged ──▶ Neo4j
         └──▶ Joern ─────────▶ Result B ──┘
```

> **v1 不实现并行模式。** 为 v2 预留，届时可并行运行 SVF + Joern 后合并。

**使用场景（v2）：**
- 需要最大覆盖率
- 用户配置 `orchestration_mode="parallel"`

**并行执行：**
```python
async def run_parallel(backends: List[AnalysisBackend], ...) -> AnalysisResult:
    tasks = [
        asyncio.get_event_loop().run_in_executor(
            None, backend.analyze, project_path, language
        )
        for backend in backends
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    # 过滤异常，合并成功结果
    valid_results = [r for r in results if not isinstance(r, Exception)]
    return ResultMerger.merge(valid_results)
```
> **注意**: `backend.analyze()` 只接受 `project_path` 和 `language`，不接受 `fuzzer_sources`。
> Fuzzer 的处理在 Phase 4b 中单独进行（`FuzzerEntryParser`）。

### 2.4 编排模式选择矩阵

**原则：自动模式下始终选择能达到最高准确率的编排方式。**

| 条件 | 自动选择的模式 | 理由 |
|------|--------------|------|
| C/C++ 项目 + Docker 可用 | 单后端（SVF） | 最大化准确率：Andersen 指针分析 |
| C/C++ 项目 + 编译失败 | 单后端（Joern） | 降级：CPG 数据流分析，不需要编译 |
| 有 introspector 输出或 prebuild 数据 | 单后端（兼容路径） | 向后兼容 |
| `analysis_backend` 显式指定单个后端 | 单后端 | 用户意图优先 |
| 用户配置 `orchestration_mode="parallel"` | 并行融合 | 用户意图优先 |

---
