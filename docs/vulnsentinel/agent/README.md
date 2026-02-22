# Agent 基础设施

> `vulnsentinel/agent/` — 所有需要 LLM 的 Engine 共享的 Agent 基础层。

## 概述

VulnSentinel 中多个 Engine 需要 LLM 能力：

- **Event Classifier** — tool-use loop 分析 diff，判断是否为安全修复
- **Vuln Analyzer** — tool-use loop 深入分析漏洞细节

这些 Engine 共享相同的 Agent 模式：LLM call → tool use → LLM call → ... → final answer。将 Agent loop、LLM Client 抽象、工具系统抽取为共享基础层，避免每个 Engine 重复实现。

### 为什么自建而非用框架

LangChain / CrewAI / AutoGen 等框架引入大量依赖和抽象层。我们的 Agent 需求极其明确：

- 固定的几个工具（每个 Engine 各自定义）
- 固定的输入/输出格式
- 固定的 loop 逻辑（LLM call → tool use → LLM call → ... → final answer）
- 需要精确控制 token budget 和成本

自己写 ~200 行，完全可控，无外部依赖。

---

## 核心概念

| 抽象 | 职责 | 位置 |
|------|------|------|
| **AgentLoop** | 通用 tool-use 循环：管理 message 列表、执行工具、累计 token、强制 max_turns | `loop.py` |
| **ToolDef** | 工具定义（name + description + JSON Schema），对应 LLM API 的 tool schema | `tool.py` |
| **ToolExecutor** | 工具执行器 Protocol，每个 Engine 实现自己的 executor | `tool.py` |
| **LLMClient** | LLM provider 抽象 Protocol，统一 Anthropic/OpenAI 差异 | `llm_client.py` |

关系：

```
Engine (e.g. Classifier)
    │
    │  定义 tools: list[ToolDef]
    │  实现 executor: ToolExecutor
    │  构造 system prompt + initial messages
    │
    ▼
AgentLoop(llm_client, tools, executor, max_turns)
    │
    │  循环调用 LLMClient.create()
    │  解析 tool_calls → executor.execute()
    │  拼接 tool_result → 下一轮
    │
    ▼
AgentResult(content, tool_calls_log, total_usage)
```

---

## LLM Client 抽象

### 类型定义

```python
# vulnsentinel/agent/llm_client.py

@dataclass
class Message:
    role: str                          # "user" | "assistant" | "tool"
    content: str | list[ContentBlock]  # 文本或 content blocks
    tool_call_id: str | None = None    # tool result 时使用

@dataclass
class ToolCall:
    id: str       # provider 生成的唯一 ID
    name: str     # 工具名
    input: dict   # 工具输入参数

@dataclass
class TokenUsage:
    input_tokens: int
    output_tokens: int

@dataclass
class LLMResponse:
    content: str               # 最终文本输出
    tool_calls: list[ToolCall] # 本轮请求的工具调用（可能为空）
    stop_reason: str           # "end_turn" | "tool_use" | "max_tokens"
    usage: TokenUsage
```

### LLMClient Protocol

```python
class LLMClient(Protocol):
    """LLM provider 抽象。所有 provider 实现此接口。"""

    async def create(
        self,
        *,
        model: str,
        system: str,
        messages: list[Message],
        tools: list[ToolDef] | None = None,
        max_tokens: int = 1024,
    ) -> LLMResponse: ...
```

### 双 Provider 适配

```python
# vulnsentinel/agent/providers/anthropic.py
class AnthropicClient:
    """Anthropic Messages API (Claude)."""

    def __init__(self, api_key: str | None = None):
        # 从 ANTHROPIC_API_KEY 环境变量读取
        ...

    async def create(self, *, model, system, messages, tools, max_tokens) -> LLMResponse:
        # Anthropic 格式：
        #   - system 是顶层参数，不在 messages 中
        #   - tool_use 是 content block 类型（与 text block 并列）
        #   - tool_result 通过 role="user" + tool_use_id 关联
        ...
```

```python
# vulnsentinel/agent/providers/openai.py
class OpenAIClient:
    """OpenAI Chat Completions API."""

    def __init__(self, api_key: str | None = None):
        # 从 OPENAI_API_KEY 环境变量读取
        ...

    async def create(self, *, model, system, messages, tools, max_tokens) -> LLMResponse:
        # OpenAI 格式：
        #   - system 是 messages[0] 的 role="system"
        #   - tool_call 是 assistant message 的 tool_calls 字段（非 content block）
        #   - tool_result 通过 role="tool" + tool_call_id 关联
        ...
```

**关键差异对照：**

| 维度 | Anthropic | OpenAI |
|------|-----------|--------|
| System prompt | 顶层 `system` 参数 | `messages[0]` with `role="system"` |
| Tool call 位置 | content block (`type="tool_use"`) | `tool_calls` 字段 (非 content) |
| Tool result 传递 | `role="user"` + `tool_use_id` in content block | `role="tool"` + `tool_call_id` |
| Stop reason | `"end_turn"` / `"tool_use"` | `"stop"` / `"tool_calls"` |

两个 provider 各自处理 API 格式差异，统一输出 `LLMResponse`。

### Provider 工厂

```python
def create_llm_client(provider: str = "anthropic") -> LLMClient:
    match provider:
        case "anthropic":
            return AnthropicClient()
        case "openai":
            return OpenAIClient()
        case _:
            raise ValueError(f"unknown provider: {provider}")
```

---

## AgentLoop

### run() 流程

```python
class AgentLoop:
    def __init__(
        self,
        llm_client: LLMClient,
        tools: list[ToolDef],
        tool_executor: ToolExecutor,
        max_turns: int = 5,
    ): ...

    async def run(self, system: str, messages: list[Message]) -> AgentResult:
        total_usage = TokenUsage(0, 0)
        tool_calls_log = []

        for turn in range(self.max_turns):
            # 1. 调用 LLM
            response = await self.llm_client.create(
                model=self.model,
                system=system,
                messages=messages,
                tools=self.tools,
            )

            # 2. 累计 token
            total_usage.input_tokens += response.usage.input_tokens
            total_usage.output_tokens += response.usage.output_tokens

            # 3. 追加 assistant message
            messages.append(assistant_message_from(response))

            # 4. 检查 stop 条件
            if response.stop_reason != "tool_use":
                break  # LLM 决定停止，输出最终答案

            # 5. 执行工具调用
            for tool_call in response.tool_calls:
                result = await self.tool_executor.execute(
                    tool_call.name, tool_call.input
                )
                result = truncate_if_needed(result, max_chars=MAX_TOOL_RESULT_CHARS)
                tool_calls_log.append(tool_call)

                # 6. 追加 tool_result message
                messages.append(Message(
                    role="tool",
                    content=result,
                    tool_call_id=tool_call.id,
                ))

        return AgentResult(
            content=response.content,
            tool_calls_log=tool_calls_log,
            total_usage=total_usage,
        )
```

### Message 列表管理

AgentLoop 维护一个线性的 message 列表，严格遵循 LLM API 的消息交替规则：

```
[user]        → 初始事件信息
[assistant]   → LLM 思考 + tool_use
[tool]        → tool_result (可能有多个，对应多个 tool_use)
[assistant]   → LLM 继续思考 + tool_use 或 final answer
[tool]        → ...
[assistant]   → final answer (stop_reason=end_turn)
```

### Stop 条件

AgentLoop 在以下条件停止：

1. **LLM 主动停止** — `stop_reason == "end_turn"`，LLM 认为信息足够，输出最终答案
2. **达到 max_turns** — 防止无限循环，强制停止并使用当前 LLM 输出
3. **`stop_reason == "max_tokens"`** — 输出被截断，loop 停止（由调用方处理）

### Token 累计

每轮 LLM 调用的 `usage` 累加到 `total_usage`，最终返回给调用方用于成本追踪和日志。

---

## Tool 系统

### ToolDef

```python
@dataclass
class ToolDef:
    """工具定义，对应 LLM API 的 tool schema。"""
    name: str            # 工具名，LLM 通过此名调用
    description: str     # 工具描述，帮助 LLM 决定何时使用
    input_schema: dict   # JSON Schema，定义输入参数
```

示例：

```python
ToolDef(
    name="fetch_commit_diff",
    description="Fetch the diff of a commit. Returns diffstat by default. "
                "Pass file_path to get the full diff of a specific file.",
    input_schema={
        "type": "object",
        "properties": {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "sha": {"type": "string"},
            "file_path": {"type": "string", "description": "Optional: get diff for this file only"},
        },
        "required": ["owner", "repo", "sha"],
    },
)
```

### ToolExecutor Protocol

```python
class ToolExecutor(Protocol):
    """工具执行器接口。每个 Engine 实现自己的 executor。"""

    async def execute(self, tool_name: str, tool_input: dict) -> str:
        """执行工具，返回文本结果。

        - tool_name: 对应 ToolDef.name
        - tool_input: LLM 生成的参数 dict，符合 ToolDef.input_schema
        - 返回: 文本结果，会作为 tool_result 传回 LLM
        - 异常: 不抛出 — 执行失败时返回错误描述字符串
        """
        ...
```

每个 Engine 实现自己的 `ToolExecutor`。例如 Event Classifier 的 `ClassifierToolExecutor` 内部调用 `GitHubClient` 获取 diff/issue/PR 等。

### 工具返回值截断策略

工具结果可能很大（例如完整 diff），需要截断保护 token budget：

```python
MAX_TOOL_RESULT_CHARS = 15_000  # ~4,000 tokens

def truncate_if_needed(result: str, max_chars: int = MAX_TOOL_RESULT_CHARS) -> str:
    if len(result) <= max_chars:
        return result
    return (
        result[:max_chars]
        + f"\n\n[truncated: showing first {max_chars} chars of {len(result)}]"
    )
```

截断在 AgentLoop 内统一执行，Engine 的 ToolExecutor 不需要关心。

---

## 使用方式

Engine 接入 Agent 基础设施的步骤：

### 1. 定义工具

```python
# vulnsentinel/engines/event_classifier/tools.py

CLASSIFIER_TOOLS: list[ToolDef] = [
    ToolDef(name="fetch_commit_diff", description="...", input_schema={...}),
    ToolDef(name="fetch_pr_diff", description="...", input_schema={...}),
    ToolDef(name="fetch_file_content", description="...", input_schema={...}),
    ToolDef(name="fetch_issue_body", description="...", input_schema={...}),
    ToolDef(name="fetch_pr_body", description="...", input_schema={...}),
]
```

### 2. 实现 ToolExecutor

```python
# vulnsentinel/engines/event_classifier/tools.py

class ClassifierToolExecutor:
    """Event Classifier 的工具执行器。所有工具都是只读 GitHub API 调用。"""

    def __init__(self, github_client: GitHubClient, owner: str, repo: str):
        self._client = github_client
        self._owner = owner
        self._repo = repo

    async def execute(self, tool_name: str, tool_input: dict) -> str:
        match tool_name:
            case "fetch_commit_diff":
                return await self._fetch_commit_diff(**tool_input)
            case "fetch_pr_diff":
                return await self._fetch_pr_diff(**tool_input)
            case "fetch_file_content":
                return await self._fetch_file_content(**tool_input)
            case "fetch_issue_body":
                return await self._fetch_issue_body(**tool_input)
            case "fetch_pr_body":
                return await self._fetch_pr_body(**tool_input)
            case _:
                return f"Unknown tool: {tool_name}"
```

### 3. 调用 AgentLoop

```python
# vulnsentinel/engines/event_classifier/classifier.py

async def classify(
    event: EventMeta,
    github_client: GitHubClient,
    llm_client: LLMClient,
    *,
    model: str = "claude-sonnet-4-20250514",
) -> ClassificationResult:
    """独立模式核心函数。不涉及 DB。"""

    # 构造初始 user message
    user_msg = format_event_for_classification(event)

    # 构造工具执行器
    executor = ClassifierToolExecutor(github_client, event.owner, event.repo)

    # 运行 agent loop
    loop = AgentLoop(llm_client, CLASSIFIER_TOOLS, executor, max_turns=5)
    agent_result = await loop.run(
        system=CLASSIFIER_SYSTEM_PROMPT,
        messages=[Message(role="user", content=user_msg)],
    )

    # 从 LLM 最终输出中提取结构化结果
    return parse_classification_output(agent_result.content)
```

完整流程：Engine 定义工具 + 实现 executor → 构造 AgentLoop → 调用 run() → 解析结果。AgentLoop 处理所有 LLM 交互细节。

---

## 配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `VULNSENTINEL_LLM_PROVIDER` | `"anthropic"` | LLM provider: `anthropic` / `openai` |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `VULNSENTINEL_DEFAULT_MODEL` | `"claude-haiku-4-5-20251001"` | 默认模型（各 Engine 可覆盖） |

各 Engine 可在自己的配置中覆盖模型、max_turns 等参数。例如 Event Classifier 有 `CLASSIFIER_MODEL`、`CLASSIFIER_MAX_TURNS` 等。

---

## 文件结构

```
vulnsentinel/
└── agent/                           # 共享 Agent 基础设施
    ├── __init__.py                   # 公开 API re-export
    ├── loop.py                       # AgentLoop — 通用 tool-use 循环
    ├── tool.py                       # ToolDef, ToolExecutor Protocol
    ├── llm_client.py                 # LLMClient Protocol, Message, ToolCall, LLMResponse, TokenUsage
    └── providers/
        ├── __init__.py               # create_llm_client() 工厂
        ├── anthropic.py              # AnthropicClient
        └── openai.py                 # OpenAIClient
```

---

## 测试策略

### MockLLMClient

所有 LLM 调用通过 `LLMClient` Protocol 注入，测试时使用 mock：

```python
class MockLLMClient:
    """返回预设响应序列的 mock LLM client。"""

    def __init__(self, responses: list[LLMResponse]):
        self._responses = iter(responses)

    async def create(self, **kwargs) -> LLMResponse:
        return next(self._responses)
```

### AgentLoop 单元测试

```python
# tests/vulnsentinel/agent/test_loop.py

async def test_agent_loop_single_turn():
    """LLM 直接返回 end_turn，不调用工具。"""
    client = MockLLMClient([
        LLMResponse(content="answer", tool_calls=[], stop_reason="end_turn", usage=TokenUsage(100, 50)),
    ])
    loop = AgentLoop(client, tools=[], tool_executor=noop_executor, max_turns=5)
    result = await loop.run(system="test", messages=[Message(role="user", content="hi")])
    assert result.content == "answer"
    assert result.tool_calls_log == []

async def test_agent_loop_tool_use():
    """LLM 先调用工具，再输出最终答案。"""
    client = MockLLMClient([
        LLMResponse(
            content="",
            tool_calls=[ToolCall(id="1", name="fetch_diff", input={"sha": "abc"})],
            stop_reason="tool_use",
            usage=TokenUsage(100, 50),
        ),
        LLMResponse(content="final answer", tool_calls=[], stop_reason="end_turn", usage=TokenUsage(200, 80)),
    ])
    executor = mock_executor({"fetch_diff": "diff content"})
    loop = AgentLoop(client, tools=[...], tool_executor=executor, max_turns=5)
    result = await loop.run(system="test", messages=[Message(role="user", content="analyze")])
    assert result.content == "final answer"
    assert len(result.tool_calls_log) == 1

async def test_agent_loop_max_turns():
    """达到 max_turns 时强制停止。"""
    # 每轮都返回 tool_use，测试 max_turns=2 是否在 2 轮后停止
    ...

async def test_tool_result_truncation():
    """超长工具结果被截断。"""
    ...
```

### Provider 适配测试

```python
# tests/vulnsentinel/agent/test_providers.py

# 测试 Anthropic/OpenAI 消息格式转换
# 需要真实 API key，CI 中标记 @pytest.mark.skip_without_api_key
```

测试文件位置：

```
tests/
└── vulnsentinel/
    └── agent/
        ├── test_loop.py          # AgentLoop 单元测试（MockLLMClient）
        └── test_providers.py     # Provider 适配测试
```
