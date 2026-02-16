## 4. 结果合并策略

> **v1 不实现 ResultMerger。** 以下为 v2 多后端合并策略的设计参考。
> v1 只有 SVF 单后端，`call_type` 只有 `DIRECT` 和 `FPTR`。下文中的 `INDIRECT`、`VIRTUAL`、`FUNCTION_POINTER` 等类型为 v2 扩展。

当使用串行增强或并行融合模式时，需要将多个后端的 `AnalysisResult` 合并为一个。

### 4.1 ResultMerger

```python
# analysis/backends/merger.py

class ResultMerger:
    """
    多后端 AnalysisResult 合并器。
    核心策略：并集 + 精度优先覆盖。
    """

    @staticmethod
    def merge(
        results: List[AnalysisResult],
        priority_order: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """
        合并多个 AnalysisResult。

        Args:
            results: 待合并的分析结果列表
            priority_order: 后端优先级（越靠前精度越高），
                           默认按 BackendDescriptor.precision_score 排序

        Returns:
            合并后的 AnalysisResult
        """
```

### 4.2 函数记录合并

**策略：并集 + 字段优先级覆盖**

同名函数出现在多个后端结果中时，按后端优先级合并字段：

```python
def merge_functions(all_functions: List[List[FunctionRecord]],
                    priority: List[str]) -> List[FunctionRecord]:
    """
    合并规则：
    1. 所有后端产出的函数取并集（按 name 去重）
    2. 同名函数的字段按优先级覆盖：
       - file_path, start_line, end_line, content: 取最高优先级后端的值
       - cyclomatic_complexity: 取最高优先级后端的非零值
       - parameters, return_type: 取最高优先级后端的非空值
       - is_entry_point: 任一后端标记为 True 则为 True
       - confidence: 取最大值
    3. 仅出现在单个后端的函数直接保留
    """
```

**字段覆盖优先级矩阵：**

| 字段 | 优先级规则 | 说明 |
|------|-----------|------|
| `name` | 合并键 | 用于匹配同一函数 |
| `file_path` | SVF > Joern > Introspector | SVF 有完整路径解析 |
| `start_line` / `end_line` | Joern > SVF > Introspector | Joern 直接解析源码 |
| `content` | Joern > SVF > Introspector | Joern 直接从源码提取 |
| `cyclomatic_complexity` | Joern > SVF | Joern 算 CPG 级复杂度 |
| `return_type` / `parameters` | SVF > Joern > Introspector | 类型信息精度 |
| `is_entry_point` | OR 合并 | 任一后端认定即可 |
| `confidence` | max() | 取最高置信度 |

### 4.3 调用图边合并

**策略：并集 + 可信度标注 + 调用类型细化**

```python
def merge_edges(all_edges: List[List[CallEdge]],
                priority: List[str]) -> List[CallEdge]:
    """
    合并规则：
    1. 所有后端产出的边取并集（按 (caller, callee) 去重）
    2. 同一 (caller, callee) 对出现在多个后端时：
       - call_type: 取最精确后端的值
         DIRECT < INDIRECT < FUNCTION_POINTER < VIRTUAL
         如果高精度后端说是 DIRECT，低精度后端说是 INDIRECT，取 DIRECT
       - confidence: 多后端确认的边，confidence 提升
         单后端: 原始 confidence
         双后端确认: min(confidence_a, confidence_b) + 0.1
         三后端确认: min(all) + 0.2
       - call_site_file/line: 取最高优先级后端的值
    3. 仅出现在单个后端的边直接保留
    """
```

**调用类型细化规则：**

| 低精度后端认为 | 高精度后端认为 | 最终类型 | 说明 |
|--------------|--------------|---------|------|
| DIRECT | DIRECT | DIRECT | 一致 |
| DIRECT | VIRTUAL | VIRTUAL | 高精度修正 |
| 无此边 | VIRTUAL | VIRTUAL | 高精度新增 |
| INDIRECT | DIRECT | DIRECT | 高精度解析了间接调用 |
| INDIRECT | 无此边 | INDIRECT (保留，标记低置信度) | 可能误报但不能删除，Agent 决定是否探索 |

### 4.4 冲突解决矩阵

当后端结果产生**不可自动解决**的冲突时：

| 冲突类型 | 自动规则 | AI 裁决降级 |
|---------|---------|------------|
| 同名函数不同文件 | 取有 content 的那个；都有则取高精度后端 | 若都有 content 且不同，交 LLM 裁决 |
| 同一 (caller, callee) 边类型矛盾 | 取高精度后端 | — |
| 循环调用检测 | 保留（调用图允许环） | — |
| 函数签名不一致 | 取高精度后端的签名 | 若差异过大，记入 warnings |
| 入口点判定不一致 | OR 合并（宁多勿少） | — |

**冲突处理流水线：**

```
冲突检测 ──▶ 自动规则 ──▶ [解决?] ──Yes──▶ 合并结果
                              │
                              No
                              ▼
                      AI 裁决（可选）──▶ [解决?] ──Yes──▶ 合并结果
                              │
                              No
                              ▼
                      取高优先级后端 + 记入 warnings
```

---
