## 5. AI 集成点

LLM 辅助分析是**可选**的——系统在没有 LLM 的情况下必须完全可用。AI 精化异步执行，超时或失败时自动降级为纯静态结果。

### 5.1 架构原则

```
AI Refiner 设计原则：
1. 非必需：所有分析必须先有静态基线结果
2. 异步执行：不阻塞分析管道主路径
3. 可降级：LLM 超时/错误/不可用时，静默降级为静态结果
4. 成本可控：预算限制 + token 计数 + 批量合并请求
5. 确定性兜底：LLM 输出经过验证，不合格则丢弃
```

### 5.2 间接调用解析

**场景：** SVF 发现了间接调用边但置信度较低，或 Joern 无法解析函数指针目标。LLM 根据上下文推断最可能的目标函数。

**Prompt 模板：**

```
你是一个 C/C++ 静态分析专家。请分析以下代码中的间接调用，推断函数指针可能指向的目标函数。

## 调用上下文

调用位置: {call_site_file}:{call_site_line}
调用代码:
```{language}
{call_site_context}  // 调用点前后 10 行
```

函数指针变量: {pointer_variable}
指针类型签名: {pointer_type_signature}  // 如 "int (*)(const char *, size_t)"

## 候选目标函数

以下函数的签名与指针类型匹配：
{candidate_functions_json}

## 项目上下文

项目名: {project_name}
相关的初始化/注册代码（如果有）:
```{language}
{initialization_context}
```

## 任务

分析代码逻辑，判断 `{pointer_variable}` 最可能指向哪些候选函数。
考虑：
- 变量赋值路径
- 初始化/注册模式
- 命名约定
- 项目结构

以 JSON 格式回复。
```

**输入 JSON Schema：**
```json
{
  "type": "object",
  "required": ["call_site", "pointer_variable", "candidates"],
  "properties": {
    "call_site": {
      "type": "object",
      "properties": {
        "file": {"type": "string"},
        "line": {"type": "integer"},
        "context_code": {"type": "string", "description": "调用点前后 10 行代码"},
        "language": {"type": "string", "enum": ["c", "cpp"]}
      }
    },
    "pointer_variable": {"type": "string"},
    "pointer_type_signature": {"type": "string"},
    "candidate_functions": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "file": {"type": "string"},
          "signature": {"type": "string"}
        }
      }
    },
    "initialization_context": {"type": "string", "description": "相关初始化代码（可选）"}
  }
}
```

**输出 JSON Schema：**
```json
{
  "type": "object",
  "required": ["resolved_targets"],
  "properties": {
    "resolved_targets": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["function_name", "confidence", "reasoning"],
        "properties": {
          "function_name": {"type": "string"},
          "confidence": {"type": "number", "minimum": 0, "maximum": 1},
          "reasoning": {"type": "string", "description": "推断依据（1-2 句）"}
        }
      }
    },
    "unresolvable": {
      "type": "boolean",
      "description": "如果无法推断，设为 true"
    },
    "unresolvable_reason": {"type": "string"}
  }
}
```

### 5.3 虚函数分派推断

**场景：** SVF 已列举了所有 override，但项目中某些虚函数有大量子类实现，需要 LLM 根据上下文缩小实际可能的分派目标。

**Prompt 模板：**

```
你是一个 C++ 静态分析专家。请分析以下虚函数调用，推断运行时最可能的分派目标。

## 调用上下文

```cpp
{call_site_context}
```

调用表达式: {call_expression}  // 如 "parser->parse(input)"
基类方法: {base_class}::{method_name}

## 所有 override 实现

{overrides_json}

## 对象创建/传递上下文

以下代码中出现了与调用对象相关的类型信息：
```cpp
{object_creation_context}
```

## 任务

根据对象的创建和传递路径，判断运行时最可能调用哪些 override。
如果无法确定，返回所有 override（保守策略）。

以 JSON 格式回复。
```

**输入 JSON Schema：**
```json
{
  "type": "object",
  "required": ["call_site", "base_method", "overrides"],
  "properties": {
    "call_site": {
      "type": "object",
      "properties": {
        "file": {"type": "string"},
        "line": {"type": "integer"},
        "context_code": {"type": "string"},
        "call_expression": {"type": "string"}
      }
    },
    "base_method": {
      "type": "object",
      "properties": {
        "class_name": {"type": "string"},
        "method_name": {"type": "string"},
        "signature": {"type": "string"}
      }
    },
    "overrides": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "class_name": {"type": "string"},
          "method_name": {"type": "string"},
          "file": {"type": "string"},
          "line": {"type": "integer"}
        }
      }
    },
    "object_creation_context": {"type": "string", "description": "对象创建/工厂/传递代码"}
  }
}
```

**输出 JSON Schema：**
```json
{
  "type": "object",
  "required": ["likely_targets"],
  "properties": {
    "likely_targets": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["class_name", "confidence", "reasoning"],
        "properties": {
          "class_name": {"type": "string"},
          "confidence": {"type": "number", "minimum": 0, "maximum": 1},
          "reasoning": {"type": "string"}
        }
      }
    },
    "fall_back_to_all": {
      "type": "boolean",
      "description": "无法缩小范围时为 true，保留所有 override"
    }
  }
}
```

### 5.4 冲突裁决

**场景：** 多后端对同一函数/边产出矛盾结果，自动规则无法解决。

**Prompt 模板：**

```
你是一个静态分析专家。多个分析后端对以下代码产生了矛盾的分析结果，请帮助裁决。

## 冲突描述

冲突类型: {conflict_type}  // "function_location" | "call_edge" | "entry_point"

## 后端 A 的结果（{backend_a_name}，精度评分 {backend_a_precision}）

{backend_a_result_json}

## 后端 B 的结果（{backend_b_name}，精度评分 {backend_b_precision}）

{backend_b_result_json}

## 相关源代码

```{language}
{relevant_source_code}
```

## 任务

判断哪个后端的结果更准确，或者两者是否都有道理（例如函数重载）。

以 JSON 格式回复。
```

**决策格式：**
```json
{
  "type": "object",
  "required": ["decision", "chosen_backend", "confidence"],
  "properties": {
    "decision": {
      "type": "string",
      "enum": ["accept_a", "accept_b", "merge_both", "discard_both"]
    },
    "chosen_backend": {"type": "string", "description": "选择的后端名"},
    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    "reasoning": {"type": "string"},
    "merged_result": {
      "type": "object",
      "description": "当 decision=merge_both 时，提供合并后的结果"
    }
  }
}
```

### 5.5 复杂度语义分析

**场景：** 圈复杂度是语法层面的度量，对于漏洞发现不够精准。LLM 从安全角度评估函数的"攻击面复杂度"。

**Prompt 模板：**

```
你是一个安全审计专家。请从漏洞发现的角度评估以下函数的安全相关复杂度。

## 函数信息

函数名: {function_name}
文件: {file_path}:{start_line}-{end_line}
圈复杂度: {cyclomatic_complexity}
被 {num_fuzzers} 个 fuzzer 到达
调用深度: {call_depth}（从 fuzzer 入口）

## 函数源码

```{language}
{function_source}
```

## 评估维度

请从以下维度评分（0-10），并给出简要理由：

1. **输入控制度**: fuzzer 能多大程度控制这个函数的输入？
2. **内存操作密度**: 有多少内存分配、指针操作、缓冲区访问？
3. **边界检查完整性**: 数组越界、整数溢出等检查是否完善？
4. **错误处理鲁棒性**: 错误路径是否可能导致不安全状态？
5. **攻击面暴露度**: 综合评估漏洞可能性

以 JSON 格式回复。
```

**评分标准：**

| 维度 | 0 分 | 5 分 | 10 分 |
|------|------|------|-------|
| 输入控制度 | 无 fuzzer 可控输入 | 部分参数可控 | 所有参数直接来自 fuzzer 输入 |
| 内存操作密度 | 纯计算/逻辑 | 少量 malloc/指针 | 大量缓冲区操作、指针算术 |
| 边界检查完整性 | 所有操作有检查 | 部分缺失 | 无边界检查 |
| 错误处理鲁棒性 | 完善的错误处理 | 部分错误未处理 | 无错误处理或 silent fail |
| 攻击面暴露度 | 无已知攻击模式 | 存在潜在攻击模式 | 明显的已知漏洞模式 |

**输出 JSON Schema：**
```json
{
  "type": "object",
  "required": ["scores", "overall_risk", "summary"],
  "properties": {
    "scores": {
      "type": "object",
      "properties": {
        "input_controllability": {"type": "integer", "minimum": 0, "maximum": 10},
        "memory_operation_density": {"type": "integer", "minimum": 0, "maximum": 10},
        "bounds_checking": {"type": "integer", "minimum": 0, "maximum": 10},
        "error_handling": {"type": "integer", "minimum": 0, "maximum": 10},
        "attack_surface": {"type": "integer", "minimum": 0, "maximum": 10}
      }
    },
    "overall_risk": {
      "type": "string",
      "enum": ["low", "medium", "high", "critical"]
    },
    "summary": {"type": "string", "description": "1-2 句风险总结"},
    "notable_patterns": {
      "type": "array",
      "items": {"type": "string"},
      "description": "发现的具体风险模式，如 'unchecked memcpy at line 42'"
    }
  }
}
```

### 5.6 成本控制策略

```python
@dataclass
class AIRefinerConfig:
    """AI 精化配置"""
    enabled: bool = True                    # 总开关
    model: str = "claude-sonnet-4-5-20250929"  # 默认模型
    max_budget_usd: float = 1.0             # 单次分析最大预算（美元）
    max_concurrent_requests: int = 5        # 最大并发数
    timeout_seconds: int = 30               # 单次请求超时
    batch_size: int = 10                    # 批量合并请求大小

    # 各任务类型的模型选择（可覆盖默认）
    model_overrides: Dict[str, str] = field(default_factory=lambda: {
        "indirect_call_resolution": "claude-sonnet-4-5-20250929",  # 需要代码理解
        "virtual_dispatch": "claude-sonnet-4-5-20250929",
        "conflict_arbitration": "claude-haiku-4-5-20251001",       # 简单判断用小模型
        "complexity_analysis": "claude-haiku-4-5-20251001",
    })

    # 降级策略
    fallback_on_error: bool = True          # 出错时降级为静态结果
    fallback_on_timeout: bool = True        # 超时时降级
    fallback_on_budget_exceeded: bool = True # 预算超限时停止 AI 精化
```

**成本控制流水线：**
```
请求 ──▶ 预算检查 ──▶ [超限?] ──Yes──▶ 跳过，用静态结果
                          │
                          No
                          ▼
                   批量合并 ──▶ 限流器 ──▶ LLM 调用 ──▶ 结果验证
                                                           │
                                                    [合格?] ──No──▶ 丢弃，用静态结果
                                                           │
                                                          Yes
                                                           ▼
                                                      更新 token 计数 ──▶ 写入结果
```

---
