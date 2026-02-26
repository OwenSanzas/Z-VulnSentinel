# Agent 基础设施

> `vulnsentinel/agent/` — 所有需要 LLM 的 Engine 共享的 Agent 基础层。

## 概述

VulnSentinel 中多个 Engine 需要 LLM 能力：

- **Event Classifier** — tool-use loop 分析 diff，判断是否为安全修复
- **Vuln Analyzer** — tool-use loop 深入分析漏洞细节（计划中）

这些 Engine 共享相同的 Agent 模式：LLM call → tool use → LLM call → ... → final answer。

### 技术选型

| 组件 | 选择 | 理由 |
|------|------|------|
| LLM 统一层 | **LiteLLM** (`litellm.acompletion()`) | 一套 API 支持 Anthropic/OpenAI/DeepSeek/Gemini/Grok |
| 工具系统 | **FastMCP** (`@mcp.tool()`) | 从函数签名自动生成 JSON Schema，不需要手写 ToolDef |
| 基类 | **BaseAgent** (ABC) | 统一 lifecycle、context、compression、logging |
| 持久化 | **PostgreSQL** (`agent_runs` + `agent_tool_calls` 表) | 复用已有 PG |

不使用 LangChain / CrewAI / AutoGen — 需求明确（固定工具、固定 loop），自建 ~400 行完全可控。

---

## 架构

```
                         ┌─────────────────────────────┐
                         │       Engine (调用方)         │
                         │  e.g. EventClassifierRunner  │
                         └──────────┬──────────────────┘
                                    │ await agent.run()
                                    ▼
                         ┌──────────────────────────────┐
                         │         BaseAgent            │
                         │  · LLM ↔ Tool 循环           │
                         │  · AgentContext 管理          │
                         │  · 上下文压缩                 │
                         │  · Token budget guard        │
                         └───────┬──────────┬───────────┘
                                 │          │
                       ┌─────────▼──┐  ┌────▼──────────┐
                       │ LLMClient  │  │ FastMCP       │
                       │ (LiteLLM)  │  │ (in-process)  │
                       │ Anthropic  │  │ call_tool()   │
                       │ OpenAI     │  │               │
                       │ DeepSeek   │  │               │
                       │ Gemini     │  │               │
                       └────────────┘  └────┬──────────┘
                                            │
                                 ┌──────────▼──────────┐
                                 │  Per-Agent MCP Server │
                                 │  @mcp.tool()         │
                                 │  fetch_diff          │
                                 │  fetch_pr_body       │
                                 │  ...                 │
                                 └─────────────────────┘
```

### 并发安全

每次 `agent.run()` 的隔离保证：

1. **`messages` 列表** — `_run_loop()` 内局部变量，每次 run 独立
2. **`AgentContext`** — 每次 run 新建实例（独立 `run_id`、token 计数器、tool call 记录）
3. **`FastMCP` server** — 每次 run 调 `create_mcp_server()` 新建
4. **`LLMClient`** — 模块级单例，纯无状态（封装 `litellm.acompletion()`）

可安全并发 `asyncio.gather(agent1.run(...), agent2.run(...), ...)`。

---

## 核心组件

### BaseAgent

```
vulnsentinel/agent/base.py
```

子类**必须**实现：

| 方法 | 职责 |
|------|------|
| `create_mcp_server()` | 返回 `FastMCP` 实例，注册该 Agent 所需工具 |
| `get_system_prompt(**kwargs)` | 返回 system prompt |
| `get_initial_message(**kwargs)` | 返回第一条 user message |

子类**可选**覆盖：

| 方法 | 默认行为 |
|------|---------|
| `parse_result(content)` | 返回 `None`（纯文本模式） |
| `get_urgency_message()` | 返回 `None`（不催促） |
| `get_compression_criteria()` | `"Keep all tool results, key findings, and decisions."` |
| `should_stop(response)` | `False`（仅靠 max_turns 和 LLM stop） |

类级配置：

```python
class MyAgent(BaseAgent):
    agent_type = "my_agent"       # 标识符
    max_turns = 25                # 最大 LLM 调用轮次
    temperature = 0.0             # LLM temperature
    model = "deepseek/deepseek-chat"  # litellm model ID（None → 用默认）
    enable_compression = True     # 是否启用上下文压缩
    max_tool_output_tokens = 4000 # 单次工具返回截断上限
    max_context_tokens = 16000    # 累计 input token 上限
```

### LLMClient

```
vulnsentinel/agent/llm_client.py
```

Thin async wrapper around `litellm.acompletion()`。完全自包含，不依赖外部项目。

- 从环境变量读取 API key（`DEEPSEEK_API_KEY`、`ANTHROPIC_API_KEY`、`OPENAI_API_KEY`、`GEMINI_API_KEY`、`XAI_API_KEY`）
- 根据 model ID 前缀自动匹配 provider
- 返回标准化的 `LLMResponse`（content, tool_calls, stop_reason, tokens, latency）
- 提供 `get_context_window()` 和 `estimate_cost()` 工具函数

### AgentContext

```
vulnsentinel/agent/context.py
```

可变累计器，追踪单次 `agent.run()` 的全部状态：

- Token 累计（input + output）
- 成本估算
- Turn 计数
- Tool call 记录（`ToolCallRecord`）
- Timing（start/end）
- 取消机制（`cancel()` / `cancelled`）
- 持久化到 PG（`agent_runs` + `agent_tool_calls` 表）

### AgentResult

```
vulnsentinel/agent/result.py
```

`AgentContext.to_result()` 生成的不可变快照。包含 run_id, content, parsed, tool_calls, status, token 统计, cost, duration。

---

## 工具系统

使用 FastMCP `@mcp.tool()` 装饰器注册工具。函数签名自动生成 JSON Schema。

```python
mcp = FastMCP("my-tools")

@mcp.tool()
async def fetch_commit_diff(sha: str, file_path: str = "") -> str:
    """Fetch commit diff. Without file_path returns diffstat."""
    ...
```

### DeepSeek 兼容性

DeepSeek 对 tool schema 有额外限制：

1. **不支持 `anyOf`** — 不能用 `str | None`，改用 `str = ""`
2. **不支持 `title` 字段** — FastMCP/Pydantic 自动添加的 `title` 必须在发送前剥离

`BaseAgent._load_tools()` 自动处理：将 MCP tool list 转为 OpenAI function-calling 格式，并递归剥离 `title` key。

### 工具返回截断

`BaseAgent` 统一截断超长工具返回（`max_tool_output_tokens * 4` 字符），Engine 的工具实现不需要关心。

---

## 上下文压缩

对长对话的 Agent（如 Vuln Analyzer），`enable_compression = True` 时：

- **触发条件**：每 5 轮，或累计 input tokens 达到模型 context window 的 80%
- **策略**：保留首条 user message + 最后 4 条消息，中间消息用 Claude Haiku 总结
- **压缩 criteria**：由子类 `get_compression_criteria()` 提供

Event Classifier（5 轮）不需要压缩，默认关闭。

---

## 文件结构

```
vulnsentinel/agent/
├── __init__.py                 # 公开 API re-export
├── base.py                     # BaseAgent — 核心 LLM-tool 循环
├── context.py                  # AgentContext — 运行时状态累计器
├── result.py                   # AgentResult — 不可变结果快照
├── llm_client.py               # LLMClient — litellm wrapper（自包含）
├── agents/
│   ├── __init__.py
│   └── classifier.py           # EventClassifierAgent
├── prompts/
│   ├── __init__.py
│   └── classifier.py           # CLASSIFIER_SYSTEM_PROMPT + format_event_message
├── tools/
│   ├── __init__.py
│   └── github_tools.py         # 5 个 GitHub 只读 MCP 工具
└── pre_filter.py               # 规则引擎（零 LLM 调用）
```

---

## 持久化（PG 表）

### `agent_runs`

每次 `agent.run()` = 一行。记录 agent_type, model, target_id/type, turns, tokens, cost, duration, status, error。

### `agent_tool_calls`

每次工具调用 = 一行。记录 run_id, turn, seq, tool_name, tool_input (JSONB), output_chars, duration_ms, is_error。

通过 `AgentContext.save(session)` 一次 flush 写入两张表。

---

## 测试策略

- **单元测试**：Mock `GitHubClient`，直接测 MCP 工具返回、pre-filter 规则、JSON 解析、label 映射
- **Agent 配置测试**：验证类属性、MCP server 创建、prompt 内容
- **E2E 测试**：用真实 DeepSeek API + 真实 GitHub API 验证端到端分类（需要 API key）

当前覆盖：55 个测试（`tests/vulnsentinel/test_event_classifier.py`）。

---

## 配置

| 环境变量 | 说明 |
|---------|------|
| `DEEPSEEK_API_KEY` | DeepSeek API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `XAI_API_KEY` | xAI (Grok) API key |
| `GITHUB_TOKEN` | GitHub API token（工具使用） |

默认模型：`deepseek/deepseek-chat`。各 Agent 子类可通过 `model` 类属性覆盖。
