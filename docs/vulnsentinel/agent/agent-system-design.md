# Agent 系统设计

> 基于 LiteLLM + FastMCP 的多 Agent 系统。

---

## 目录

1. [架构总览](#1-架构总览)
2. [BaseAgent](#2-baseagent)
3. [AgentContext — 运行时隔离与持久化](#3-agentcontext--运行时隔离与持久化)
4. [MCP Tool Server — Per-Agent 隔离](#4-mcp-tool-server--per-agent-隔离)
5. [LLMClient — LiteLLM 封装](#5-llmclient--litellm-封装)
6. [Agent 实现](#6-agent-实现)
7. [成本控制与 Token 管理](#7-成本控制与-token-管理)
8. [可观测性](#8-可观测性)
9. [测试策略](#9-测试策略)
10. [文件结构](#10-文件结构)
11. [实施状态](#11-实施状态)

---

## 1. 架构总览

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
                       └────────────┘  └────┬──────────┘
                                            │ call_tool()
                                 ┌──────────▼──────────┐
                                 │  Per-Agent MCP Server │
                                 │  @mcp.tool() 注册    │
                                 └─────────────────────┘
```

### 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| LLM 统一层 | **LiteLLM** `acompletion()` | 一套 API 支持 5+ Provider，自带 cost 计算 |
| 工具系统 | **FastMCP** `@mcp.tool()` | 从函数签名自动生成 JSON Schema |
| MCP Server 模式 | **in-process** | Agent 和 Server 在同一 Python 进程，无 IPC 开销 |
| Per-Agent 隔离 | **每次 run() 新建 FastMCP** | 并发安全，无共享可变状态 |
| 持久化 | **PostgreSQL** (agent_runs + agent_tool_calls) | 复用已有 PG |
| 上下文压缩 | **Claude Haiku 总结中间消息** | 仅 > 5 轮 Agent 启用 |

---

## 2. BaseAgent

### 2.1 类定义

```python
# vulnsentinel/agent/base.py

class BaseAgent(ABC):
    # 子类覆盖的类级配置
    agent_type: str = ""          # "event_classifier", "vuln_analyzer", ...
    max_turns: int = 25           # 最大 LLM 调用轮次
    temperature: float = 0.0
    model: str | None = None      # None → 用 _DEFAULT_MODEL ("deepseek/deepseek-chat")
    enable_compression: bool = True
    max_tool_output_tokens: int = 4000
    max_context_tokens: int = 16000

    # 子类必须实现
    @abstractmethod
    def create_mcp_server(self) -> FastMCP: ...

    @abstractmethod
    def get_system_prompt(self, **kwargs) -> str: ...

    @abstractmethod
    def get_initial_message(self, **kwargs) -> str: ...

    # 子类可选覆盖
    def parse_result(self, content: str) -> Any: ...
    def get_urgency_message(self) -> str | None: ...
    def get_compression_criteria(self) -> str: ...
    def should_stop(self, response: LLMResponse) -> bool: ...

    # 主入口
    async def run(self, *, target_id, target_type, engine_name, session, **kwargs) -> AgentResult: ...
```

### 2.2 run() 生命周期

```python
async def run(self, **kwargs) -> AgentResult:
    # 1. 解析模型 ID
    resolved_model = _llm.resolve_model(self.model)

    # 2. 创建 AgentContext（独立 run_id、token 计数器）
    ctx = AgentContext(agent_type=self.agent_type, model=resolved_model, ...)

    # 3. 绑定 structlog 上下文
    structlog.contextvars.bind_contextvars(run_id=str(ctx.run_id), ...)

    try:
        # 4. 执行核心循环
        content = await self._run_loop(ctx, **kwargs)

        # 5. 解析结构化结果
        parsed = self.parse_result(content)
        ctx.finish("completed")
    except Exception:
        ctx.finish("failed", error=str(exc))

    # 6. 持久化到 PG（可选）
    if session is not None:
        await ctx.save(session)

    return ctx.to_result(content=content, parsed=parsed)
```

### 2.3 _run_loop() 核心循环

```python
async def _run_loop(self, ctx, **kwargs):
    mcp = self.create_mcp_server()
    tools = await self._load_tools(mcp)       # MCP → OpenAI function-calling 格式
    messages = [{"role": "user", "content": self.get_initial_message(**kwargs)}]
    system = self.get_system_prompt(**kwargs)

    while ctx.turn < self.max_turns:
        if ctx.cancelled:
            break

        ctx.increment_turn()

        # Token budget guard
        if ctx.total_input_tokens >= self.max_context_tokens:
            break

        # Urgency hint（倒数第 2 轮注入）
        if turn == self.max_turns - 2:
            urgency = self.get_urgency_message()
            if urgency:
                messages.append({"role": "user", "content": urgency})

        # LLM 调用
        response = await _llm.create(model=ctx.model, system=system,
                                      messages=messages, tools=tools, ...)
        ctx.add_usage(response)

        # 无工具调用 → 结束
        if not response.has_tool_calls:
            break

        # 自定义停止检查
        if self.should_stop(response):
            break

        # 执行工具
        messages.append({"role": "assistant", "content": response.content,
                         "tool_calls": response.tool_calls})
        for tc in response.tool_calls:
            result = await mcp.call_tool(tool_name, tool_input)
            # 截断超长返回
            output_text = truncate(extract_mcp_text(result))
            ctx.record_tool_call(...)
            messages.append({"role": "tool", "tool_call_id": tc["id"],
                             "content": output_text})

        # 上下文压缩
        if self.enable_compression and needs_compress:
            messages = await self._compress_context(ctx, system, messages)

    return last_content
```

---

## 3. AgentContext — 运行时隔离与持久化

### 3.1 职责

每次 `agent.run()` 创建一个新的 `AgentContext`，追踪：

| 字段 | 说明 |
|------|------|
| `run_id` | UUID，唯一标识此次运行 |
| `_input_tokens` / `_output_tokens` | 累计 token |
| `_cost` | 累计估算成本 (USD) |
| `_turn` | 当前 turn 数 |
| `_tool_calls` | `list[ToolCallRecord]` — 每次工具调用的详情 |
| `_status` | `running` → `completed` / `failed` / `cancelled` |
| `_cancelled` | 取消标志 |

### 3.2 两张 PG 表

#### `agent_runs`

每次 `agent.run()` = 一行。

| 列 | 类型 | 说明 |
|----|------|------|
| id | UUID PK | = ctx.run_id |
| agent_type | VARCHAR(50) | "event_classifier" 等 |
| status | VARCHAR(20) | running/completed/failed/cancelled |
| engine_name | VARCHAR(50) | 调用方 engine |
| model | VARCHAR(80) | litellm model ID |
| target_id / target_type | UUID / VARCHAR(30) | 关联业务对象 |
| total_turns / total_tool_calls | INT | 统计 |
| input_tokens / output_tokens | INT | token 累计 |
| estimated_cost | NUMERIC(10,6) | USD |
| duration_ms | INT | 耗时 |
| error | TEXT | 失败时的错误信息 |

#### `agent_tool_calls`

每次工具调用 = 一行。

| 列 | 类型 | 说明 |
|----|------|------|
| run_id | UUID FK → agent_runs | 所属 run |
| turn / seq | INT | 第几轮、第几个工具 |
| tool_name | VARCHAR(80) | 工具名 |
| tool_input | JSONB | 工具参数 |
| output_chars | INT | 返回值长度 |
| duration_ms | INT | 工具执行耗时 |
| is_error | BOOLEAN | 是否出错 |

通过 `AgentContext.save(session)` 一次 flush 写入两张表。

---

## 4. MCP Tool Server — Per-Agent 隔离

### 4.1 工厂模式

每个 Agent 子类实现 `create_mcp_server()`，返回独立 FastMCP 实例：

```python
class EventClassifierAgent(BaseAgent):
    def create_mcp_server(self) -> FastMCP:
        return create_github_mcp(self._client, self._owner, self._repo)
```

工具通过闭包绑定外部依赖（client, owner, repo），MCP tool 参数只暴露 LLM 可控部分。

### 4.2 工具转换

`BaseAgent._load_tools()` 将 MCP tool list 转为 OpenAI function-calling 格式：

```python
async def _load_tools(self, mcp: FastMCP) -> list[dict]:
    mcp_tools = await mcp.list_tools()
    for tool in mcp_tools:
        schema = _strip_titles(tool.inputSchema)  # DeepSeek 兼容
        openai_tools.append({
            "type": "function",
            "function": {"name": tool.name, "description": tool.description,
                         "parameters": schema},
        })
    return openai_tools
```

### 4.3 工具执行

直接调用 `mcp.call_tool(name, input)`，返回 `tuple(list[ContentBlock], dict)`。

`_extract_mcp_text()` 从 ContentBlock 列表中提取文本。

### 4.4 DeepSeek 兼容性

DeepSeek 对 tool schema 有额外限制：

1. **不支持 `anyOf`** — 不能用 `str | None` 参数类型，改用 `str = ""`
2. **不支持 `title` 字段** — `_strip_titles()` 递归剥离 FastMCP/Pydantic 自动添加的 title

---

## 5. LLMClient — LiteLLM 封装

```
vulnsentinel/agent/llm_client.py
```

完全自包含，不依赖外部项目。

### 5.1 API Key 管理

从环境变量读取，根据 model ID 前缀自动匹配 provider：

| Model 前缀 | Provider | 环境变量 |
|-----------|----------|---------|
| `claude` | Anthropic | `ANTHROPIC_API_KEY` |
| `deepseek` | DeepSeek | `DEEPSEEK_API_KEY` |
| `gpt` / `o3` / `o1` | OpenAI | `OPENAI_API_KEY` |
| `gemini` | Google | `GEMINI_API_KEY` |
| `grok` | xAI | `XAI_API_KEY` |

### 5.2 LLMResponse

```python
@dataclass
class LLMResponse:
    content: str = ""
    tool_calls: list[dict] = field(default_factory=list)  # OpenAI 格式
    stop_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)
```

### 5.3 辅助函数

- `get_context_window(model)` — 查询模型 context window 大小（litellm.get_model_info）
- `estimate_cost(model, input_tokens, output_tokens)` — 估算 USD 成本

默认模型：`deepseek/deepseek-chat`。

---

## 6. Agent 实现

### 6.1 EventClassifierAgent（已实现）

| 配置 | 值 |
|------|-----|
| `agent_type` | `"event_classifier"` |
| `max_turns` | 5 |
| `temperature` | 0.2 |
| `model` | `"deepseek/deepseek-chat"` |
| `enable_compression` | False |

**工具**：5 个 GitHub 只读工具（`create_github_mcp()`）

- `fetch_commit_diff` — diffstat 或单文件 patch
- `fetch_pr_diff` — PR diffstat 或单文件 patch
- `fetch_file_content` — 文件内容（base64 decode）
- `fetch_issue_body` — issue title + body + labels
- `fetch_pr_body` — PR title + body + labels

**Pre-filter**：规则引擎（零 LLM 调用），在 Agent 之前执行：

| 规则 | 分类 | 置信度 |
|------|------|--------|
| `type == "tag"` | `other` | 0.95 |
| Bot 作者 (dependabot, renovate, ...) | `other` | 0.90 |
| 安全关键词检查 | → 跳过 pre-filter，交给 LLM | — |
| Conventional commit prefix (`fix:`, `feat:`, ...) | 对应分类 | 0.70-0.85 |

**重要**：Pre-filter 永远不产出 `security_bugfix`。含安全关键词（CVE, buffer overflow, use-after-free 等）的事件即使匹配 `fix:` 也不会被 pre-filter，强制交给 LLM 判断。

**输出解析**：从 LLM 最终输出中 regex 提取 JSON → `ClassificationResult(classification, confidence, reasoning)`。LLM 输出的扩展 label（bugfix, documentation 等）映射到 DB 的 5 个枚举值。

**Early stop**：`should_stop()` 在 LLM 输出中检测到 JSON 时提前结束 loop。

### 6.2 VulnAnalyzerAgent（计划中）

分析 `security_bugfix` 事件的漏洞细节。预计配置：

- `max_turns = 15`，`enable_compression = True`
- 除 GitHub 工具外可能需要 CVE 数据库查询工具
- 输出：`vuln_type`, `severity`, `affected_versions`, `summary`, `reasoning`

---

## 7. 成本控制与 Token 管理

### 三层防线

```
Event 进入
    │
    ▼
┌──────────────┐   ~40% 事件在此过滤
│  Pre-filter   │ ── tag/bot/CI → 免费分类
└──────┬───────┘
       │
       ▼
┌──────────────┐   每事件 ≤ 16K input tokens
│  Token Budget │ ── diffstat-first + 工具截断 + max_turns
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  模型选择     │ ── DeepSeek (便宜) 为默认
└──────────────┘
```

### Token 预算

| 层级 | 限制 |
|------|------|
| 单次工具返回 | `max_tool_output_tokens * 4` chars (~4000 tokens) |
| 工具内部截断 | 15,000 chars (github_tools.py) |
| 累计 input tokens | `max_context_tokens` (默认 16,000) |
| 最大轮次 | `max_turns` (Classifier=5, Analyzer=15+) |

### 成本追踪

每次 LLM 调用自动累计到 `AgentContext._cost`（通过 `estimate_cost()` 计算）。完成后写入 `agent_runs.estimated_cost`。

---

## 8. 可观测性

### 结构化日志

使用 structlog contextvars 绑定 `run_id` 和 `agent_type`，所有日志自动附带。

关键日志点：
- Agent 启动/完成/失败（status, turns, cost）
- 每轮 LLM 响应（stop_reason, tool_calls 数, tokens）
- 工具执行错误
- 上下文压缩触发
- Token budget 超限

### PG 持久化

通过 `AgentContext.save(session)` 写入：
- `agent_runs` — 运行级统计
- `agent_tool_calls` — 工具调用明细

可通过 SQL 查询：
- 按 agent_type / engine_name 统计成本
- 按 target_id 查找所有 agent 运行
- 按 tool_name 统计工具使用频率和错误率

---

## 9. 测试策略

### 单元测试（不需要 API key）

- **MCP 工具测试**：Mock `GitHubClient`，直接调用 `mcp.call_tool()`，验证返回内容
- **Pre-filter 测试**：各种事件类型、安全关键词绕过、边界情况
- **Prompt 测试**：验证 system prompt 包含所有 label，format_event_message 格式正确
- **解析测试**：JSON 提取、label 映射、confidence 边界、异常输入
- **Agent 配置测试**：类属性、MCP server 创建

### E2E 测试（需要 API key）

用真实 DeepSeek API + GitHub API 验证：
- Pre-filter 路径（tag, bot）
- LLM 路径（真实 curl commit → 正确分类 security_bugfix / feature）

### 当前覆盖

55 个测试，全部通过 (`tests/vulnsentinel/test_event_classifier.py`)。

---

## 10. 文件结构

```
vulnsentinel/agent/
├── __init__.py                 # 公开 API re-export
├── base.py                     # BaseAgent — LLM-tool 循环 (~400 LOC)
├── context.py                  # AgentContext — 运行时状态
├── result.py                   # AgentResult — 不可变快照
├── llm_client.py               # LLMClient — litellm wrapper
├── pre_filter.py               # 规则引擎（安全关键词检测）
├── agents/
│   ├── __init__.py
│   └── classifier.py           # EventClassifierAgent + ClassificationResult
├── prompts/
│   ├── __init__.py
│   └── classifier.py           # CLASSIFIER_SYSTEM_PROMPT + format_event_message
└── tools/
    ├── __init__.py
    └── github_tools.py         # 5 个 GitHub 只读 MCP 工具

vulnsentinel/engines/event_classifier/
├── __init__.py
├── classifier.py               # classify() 纯函数（独立模式）+ EventInput
└── runner.py                   # EventClassifierRunner（集成模式 + DB 读写）

vulnsentinel/models/
├── agent_run.py                # AgentRun ORM model
└── agent_tool_call.py          # AgentToolCall ORM model

tests/vulnsentinel/
└── test_event_classifier.py    # 55 tests
```

---

## 11. 实施状态

| 组件 | 状态 | 备注 |
|------|------|------|
| BaseAgent | **已完成** | LLM-tool loop, compression, budget guard, urgency, cancel |
| AgentContext | **已完成** | Token 追踪, tool call 记录, PG 持久化 |
| LLMClient | **已完成** | 自包含 litellm wrapper, 5 provider |
| GitHub MCP Tools | **已完成** | 5 个只读工具, DeepSeek 兼容 |
| EventClassifierAgent | **已完成** | pre-filter + LLM agent + runner |
| classify() 独立函数 | **已完成** | 纯函数, 无 DB |
| EventClassifierRunner | **已完成** | session_factory 并发安全 |
| E2E 验证 | **已完成** | DeepSeek API + GitHub API |
| VulnAnalyzerAgent | **计划中** | Phase 3 |
