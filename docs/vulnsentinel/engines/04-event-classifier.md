# Event Classifier

> 对未分类的 Event 进行 LLM 语义分析，判断其是否为安全修复。对应十步流程中的**步骤 6（LLM 分类）**。

## 概述

Event Classifier 是流水线中紧跟 Event Collector 的第三个 Engine。Collector 解决了"发生了什么"，Classifier 解决"这是不是安全修复"。

**职责：**

- 从 `events` 表中拉取 `classification IS NULL` 的事件
- 通过 LLM Agent（tool-use loop）语义分析 diff，输出分类标签和置信度
- 将结果写入 `events.classification` / `events.confidence` / `events.is_bugfix`

**特点：**

- Agent 模式 — 不是简单的 prompt→response，而是 tool-use loop，LLM 自主决定需要哪些上下文
- 成本可控 — 三层防线：pre-filter 跳过无关事件、token budget 限制单次调用、模型分层降本
- 幂等 — 重复分类同一事件产生相同结果（覆盖写入，不重复创建）

---

## 双模式设计

所有 Engine 统一采用**双模式设计**：独立模式用于测试和调试，集成模式用于生产调度。

### 独立模式（Standalone）

纯函数式，不依赖数据库、不需要 Service 层。

```
输入: event 元数据 (type, title, message, source_url) + GitHubClient
输出: ClassificationResult (classification, confidence, reasoning, tool_calls_used)
```

用途：
- 单元测试、集成测试
- CLI 调试（`python -m vulnsentinel.engines.event_classifier <event_source_url>`）
- Prompt 调优 / golden test set 回归

### 集成模式（Integrated）

通过 Service 层读写数据库，由 Scheduler 调度。

```
输入: event_id（或 batch 的 event_id 列表）
输出: DB 中更新的 classification + confidence + is_bugfix
```

用途：
- Scheduler 定时调度 / Collector 完成后链式触发
- run_all() 批量处理

### 模式关系

Runner 调用 Engine 的独立模式分类逻辑，然后执行 DB 同步。Engine 本身不接触数据库：

```python
EventClassifierRunner.run(session, event_id):
    # ↓ Runner 负责：DB 读取
    event = EventService.get(event_id)

    # ↓ Engine 核心逻辑（Agent loop，不涉及 DB）
    result = await classify(event, client, llm_client)

    # ↓ Runner 负责：DB 写入
    EventService.update_classification(event.id,
        classification=result.classification,
        confidence=result.confidence,
    )
```

---

## Agent 架构

### 为什么用 Agent 而不是单次 prompt

单次 prompt 需要把所有上下文塞进去再让 LLM 判断。问题：

1. **diff 可能很大** — 一个 commit 可能改几十个文件，token 爆炸
2. **不是所有事件都需要 diff** — tag 事件、明显无关的 refactor commit 不需要看代码
3. **需要额外上下文** — 有时需要看关联 issue body 或 PR description 才能判断意图

Agent 让 LLM **自己决定需要什么信息**：先看 title/message，觉得可疑再调用工具拉 diff，diff 太大就先看 diffstat 再选择性看关键文件。

### Tool-Use Loop

```
┌──────────────────────────────────────────────────────┐
│  System Prompt + Event 元数据（title, message, url） │
└─────────────────────────┬────────────────────────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │    LLM 思考 + 决策   │ ◄──────────────────┐
               └─────────┬───────────┘                     │
                         │                                 │
              ┌──────────┴──────────┐                      │
              │                     │                      │
         tool_use               stop_reason=end_turn       │
              │                     │                      │
              ▼                     ▼                      │
     ┌────────────────┐   ┌──────────────────┐            │
     │  执行工具调用    │   │  提取结构化输出   │            │
     │  fetch_*()      │   │  ClassificationResult │       │
     └────────┬───────┘   └──────────────────┘            │
              │                                            │
              │  工具结果                                   │
              └────────────────────────────────────────────┘

最大循环次数: 5（防止无限 loop）
```

### 共享 Agent 基础设施

Agent loop 不是 Event Classifier 独有的 — Vuln Analyzer (Engine #3) 同样需要 tool-use loop。抽取可复用的 Agent 基础层到 `vulnsentinel/agent/`：

```python
# vulnsentinel/agent/loop.py

class AgentLoop:
    """通用 tool-use agent loop。

    职责：
    - 管理 message 列表（system + user + assistant + tool_result 交替）
    - 执行 tool-use 循环直到 LLM 停止调用工具
    - 强制最大轮次限制
    - 累计 token 使用量
    """

    def __init__(
        self,
        llm_client: LLMClient,
        tools: list[ToolDef],
        tool_executor: ToolExecutor,
        max_turns: int = 5,
    ):
        ...

    async def run(self, system: str, messages: list[Message]) -> AgentResult:
        """执行 agent loop，返回最终响应 + 工具调用记录 + token 统计。"""
        ...
```

```python
# vulnsentinel/agent/tool.py

@dataclass
class ToolDef:
    """工具定义，对应 LLM API 的 tool schema。"""
    name: str
    description: str
    input_schema: dict  # JSON Schema

class ToolExecutor(Protocol):
    """工具执行器接口。每个 Engine 实现自己的 executor。"""
    async def execute(self, tool_name: str, tool_input: dict) -> str: ...
```

### 为什么不用外部 Agent 框架

LangChain / CrewAI / AutoGen 等框架引入大量依赖和抽象层。我们的 Agent 需求极其明确：

- 固定的 5 个工具
- 固定的输入/输出格式
- 固定的 loop 逻辑（LLM call → tool use → LLM call → ... → final answer）
- 需要精确控制 token budget 和成本

自己写 ~200 行，完全可控，无外部依赖。

---

## Tool 设计

Agent 有 5 个工具，全部是**只读的 GitHub API 调用**：

| 工具 | 用途 | 调用时机 |
|------|------|---------|
| `fetch_commit_diff` | 获取 commit 的 diff | commit 类型事件，LLM 认为可能是安全修复时 |
| `fetch_pr_diff` | 获取 PR 的 diff | pr_merge 类型事件 |
| `fetch_file_content` | 获取指定文件的完整内容 | LLM 看完 diff 后需要更多上下文时 |
| `fetch_issue_body` | 获取关联 issue 的 body | event 有 related_issue_ref 时 |
| `fetch_pr_body` | 获取 PR description | 需要了解 PR 意图时 |

### Diff 大小控制策略

Diff 是 token 消耗的主要来源。策略：**diffstat-first**。

```
Step 1: 工具先返回 diffstat（文件列表 + 增删行数），不返回完整 diff
        例: "src/parse.c | 12 +++---\n src/util.h | 3 +\n 2 files changed, 8 insertions(+), 7 deletions(-)"

Step 2: LLM 看完 diffstat 后，如果想看具体文件的 diff，再次调用工具并指定 file_path 过滤
        例: fetch_commit_diff(sha="abc123", file_path="src/parse.c")

Step 3: 如果单文件 diff 仍然超大（>500 行），截断并附上提示
        "[truncated: showing first 500 lines of 2341. Full diff available at {url}]"
```

**好处：**
- 大部分 refactor commit 看 diffstat 就能排除，不需要拉完整 diff
- security fix 通常只改少数文件，选择性拉 diff 节省 token
- 截断保护兜底

### 工具定义

```python
CLASSIFIER_TOOLS = [
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
    ),
    ToolDef(
        name="fetch_pr_diff",
        description="Fetch the diff of a merged PR. Returns diffstat by default. "
                    "Pass file_path to get the full diff of a specific file.",
        input_schema={
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "pr_number": {"type": "integer"},
                "file_path": {"type": "string"},
            },
            "required": ["owner", "repo", "pr_number"],
        },
    ),
    ToolDef(
        name="fetch_file_content",
        description="Fetch the content of a file at a specific ref (commit SHA or branch).",
        input_schema={
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "path": {"type": "string"},
                "ref": {"type": "string"},
            },
            "required": ["owner", "repo", "path", "ref"],
        },
    ),
    ToolDef(
        name="fetch_issue_body",
        description="Fetch the title and body of a GitHub issue.",
        input_schema={
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "issue_number": {"type": "integer"},
            },
            "required": ["owner", "repo", "issue_number"],
        },
    ),
    ToolDef(
        name="fetch_pr_body",
        description="Fetch the title, body, and labels of a GitHub pull request.",
        input_schema={
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "pr_number": {"type": "integer"},
            },
            "required": ["owner", "repo", "pr_number"],
        },
    ),
]
```

### Token Budget

| 层级 | 限制 | 说明 |
|------|------|------|
| 单次工具返回 | ≤ 4,000 tokens | diffstat ~200 tokens；单文件 diff 截断到 ~3,800 tokens |
| 单个事件总上下文 | ≤ 16,000 tokens | system prompt ~1,500 + event 元数据 ~500 + 工具调用 ≤ 5 × 4,000 |
| 单个事件最大轮次 | 5 | 防止 LLM 无限探索 |

---

## LLM Client 抽象

Event Classifier 是第一个用 LLM 的 Engine。需要一个可复用的 LLM Client 抽象层，支持 Anthropic 和 OpenAI。

### Protocol 定义

```python
# vulnsentinel/agent/llm_client.py

@dataclass
class Message:
    role: str                          # "user" | "assistant" | "tool"
    content: str | list[ContentBlock]  # 文本或 content blocks
    tool_call_id: str | None = None    # tool result 时使用

@dataclass
class ToolCall:
    id: str
    name: str
    input: dict

@dataclass
class LLMResponse:
    content: str           # 最终文本输出
    tool_calls: list[ToolCall]
    stop_reason: str       # "end_turn" | "tool_use" | "max_tokens"
    usage: TokenUsage

@dataclass
class TokenUsage:
    input_tokens: int
    output_tokens: int

class LLMClient(Protocol):
    """LLM provider 抽象。"""
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

### 双 Provider 支持

```python
# vulnsentinel/agent/providers/anthropic.py
class AnthropicClient:
    """Anthropic Messages API (Claude)."""
    def __init__(self, api_key: str | None = None):
        # ANTHROPIC_API_KEY 环境变量
        ...

# vulnsentinel/agent/providers/openai.py
class OpenAIClient:
    """OpenAI Chat Completions API."""
    def __init__(self, api_key: str | None = None):
        # OPENAI_API_KEY 环境变量
        ...
```

两个 provider 各自处理 API 格式差异（tool_use content block vs function_call），统一输出 `LLMResponse`。

### Provider 选择

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

环境变量 `CLASSIFIER_LLM_PROVIDER` 控制默认 provider。

---

## 分类管线

单个事件的分类分三步：Pre-filter → Agent 分类 → Post-process。

### Step 1: Pre-filter

在调用 LLM 之前，用规则快速过滤明显不需要分类的事件：

| 规则 | 跳过条件 | 分类结果 |
|------|---------|---------|
| tag 事件 | `type == "tag"` | `classification="release", confidence=1.0` |
| merge commit | title 匹配 `^Merge (branch\|pull request)` | `classification="merge", confidence=1.0` |
| bot commit | author 匹配已知 bot 列表 (`dependabot`, `renovate`, `github-actions`) | `classification="dependency_update", confidence=0.9` |
| 明显 CI/doc | title 匹配 `^(ci|docs|chore|style):` (conventional commit) | `classification="other", confidence=0.8` |

**Pre-filter 不会把可能是 security fix 的事件过滤掉。** 只过滤 100% 不可能是安全修复的类型。有疑问的一律送 LLM。

### Step 2: Agent 分类（核心）

对通过 pre-filter 的事件，启动 Agent loop：

```python
async def classify(
    event: EventMeta,
    github_client: GitHubClient,
    llm_client: LLMClient,
    *,
    model: str = "claude-sonnet-4-20250514",
) -> ClassificationResult:
    """独立模式核心函数。"""

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

### Step 3: Post-process

对 Agent 的输出做后处理：

- **confidence 校准** — 如果 LLM 返回 `security_bugfix` 但 confidence < 0.6，降级为 `suspicious`，记录 `low_confidence_flag`
- **is_bugfix 推导** — `is_bugfix = (classification == "security_bugfix")`（已在 `EventService.update_classification` 中实现）
- **记录 reasoning** — Agent 的推理过程和工具调用记录存入日志，便于 review 和 prompt 调优

### ClassificationResult

```python
@dataclass
class ClassificationResult:
    classification: str     # "security_bugfix" | "bugfix" | "feature" | "refactor"
                            # | "documentation" | "test" | "dependency_update"
                            # | "performance" | "release" | "merge" | "other"
    confidence: float       # 0.0 ~ 1.0
    reasoning: str          # LLM 的推理说明
    tool_calls_used: int    # 消耗了几轮工具调用
    tokens_used: TokenUsage # token 消耗
```

### 分类标签

| 标签 | 含义 | 下游行为 |
|------|------|---------|
| `security_bugfix` | 安全漏洞修复 | → Vuln Analyzer 分析 |
| `bugfix` | 普通 bug 修复 | 记录，不触发分析 |
| `feature` | 新功能 | 记录 |
| `refactor` | 代码重构 | 记录 |
| `documentation` | 文档变更 | 记录 |
| `test` | 测试变更 | 记录 |
| `dependency_update` | 依赖更新 | 记录 |
| `performance` | 性能优化 | 记录 |
| `release` | 版本发布（tag） | 记录 |
| `merge` | merge commit | 记录 |
| `other` | 无法归类 | 记录 |

**只有 `security_bugfix` 会触发下游 Vuln Analyzer。** 这是整个系统最关键的判断。

---

## Prompt 策略

### System Prompt 结构

```
┌─────────────────────────────────────────────────────────┐
│ 1. 角色定义                                              │
│    "You are a security analyst classifying code changes" │
├─────────────────────────────────────────────────────────┤
│ 2. 分类标签说明                                          │
│    每个标签的定义 + 判断标准                              │
├─────────────────────────────────────────────────────────┤
│ 3. 安全关键词参考                                        │
│    buffer overflow, use-after-free, integer overflow,    │
│    null dereference, race condition, injection, ...      │
├─────────────────────────────────────────────────────────┤
│ 4. 工具使用指导                                          │
│    何时看 diff、何时看 issue body、diffstat-first 策略   │
├─────────────────────────────────────────────────────────┤
│ 5. 输出格式                                              │
│    JSON: {classification, confidence, reasoning}         │
├─────────────────────────────────────────────────────────┤
│ 6. Few-shot Examples (2-3 个)                            │
│    包含 security_bugfix 正例 + refactor 反例             │
└─────────────────────────────────────────────────────────┘
```

### 安全关键词

System prompt 中包含安全相关关键词参考列表，帮助 LLM 识别常见漏洞修复模式：

- 内存安全：`buffer overflow`, `heap overflow`, `stack overflow`, `use-after-free`, `double free`, `null pointer dereference`, `out-of-bounds read/write`
- 整数问题：`integer overflow`, `integer underflow`, `signedness error`, `truncation`
- 注入：`command injection`, `SQL injection`, `XSS`, `SSRF`, `path traversal`
- 认证/授权：`authentication bypass`, `privilege escalation`, `CSRF`
- 密码学：`weak cipher`, `hardcoded secret`, `timing attack`
- 竞态：`race condition`, `TOCTOU`

### Few-shot Examples

Prompt 中包含 2-3 个 few-shot 示例，展示完整的工具调用和判断过程：

```
Example 1 (security_bugfix):
  Event: commit "Fix crash on malformed input"
  → Agent 调用 fetch_commit_diff → 看到 bounds check 被添加
  → classification=security_bugfix, confidence=0.92

Example 2 (refactor):
  Event: commit "Refactor: extract helper function from parse_header"
  → Agent 调用 fetch_commit_diff → 看到纯结构重组，无逻辑变更
  → classification=refactor, confidence=0.95
```

### Prompt 版本管理

Prompt 存储为 Python 模块中的常量，随代码版本控制：

```
vulnsentinel/engines/event_classifier/prompts.py
├── CLASSIFIER_SYSTEM_PROMPT_V1  # 当前版本
├── CLASSIFIER_FEW_SHOT_EXAMPLES
└── SECURITY_KEYWORDS
```

每次 prompt 变更都走 golden test set 回归验证。

---

## 成本控制

### 三层防线

```
Event 进入
    │
    ▼
┌──────────────┐   ~40% 事件在此过滤
│  Pre-filter   │ ─── tag/merge/bot/CI → 免费分类，不调 LLM
└──────┬───────┘
       │ 剩余 ~60%
       ▼
┌──────────────┐   每事件 ≤ 16K tokens
│  Token Budget │ ─── diffstat-first + 截断 + max 5 轮
└──────┬───────┘
       │
       ▼
┌──────────────┐   日常用 Sonnet，可疑才升 Opus
│  模型分层     │ ─── confidence < 阈值 → 升级模型重试
└──────────────┘
```

### 模型分层策略

| 层级 | 模型 | 触发条件 | 预估成本/事件 |
|------|------|---------|-------------|
| L1 | Claude Haiku 4.5 | 默认首选（日常批量处理） | ~$0.001 |
| L2 | Claude Sonnet 4.6 | L1 返回 confidence < 0.7 的 security_bugfix | ~$0.01 |
| L3 | Claude Opus 4.6 | L2 仍不确定 + title 含安全关键词 | ~$0.05 |

大部分事件（refactor/feature/doc）在 L1 就能确定。只有可疑的安全修复才升级。

### 并发控制

```python
CLASSIFIER_CONCURRENCY = 3  # 同时分类的事件数
```

并发数低于 Collector 的 5，因为每个事件需要多次 LLM API + GitHub API 调用。

### 成本追踪

每次分类记录 token 消耗，写入日志：

```python
logger.info(
    "classified event %s: %s (%.2f) | tokens: %d in + %d out | tools: %d | model: %s",
    event_id, result.classification, result.confidence,
    result.tokens_used.input_tokens, result.tokens_used.output_tokens,
    result.tool_calls_used, model,
)
```

---

## Error Handling

### LLM 调用失败

| 错误类型 | 处理 |
|---------|------|
| 429 Rate Limit | 指数退避重试，最多 3 次 |
| 500/502/503 | 指数退避重试，最多 3 次 |
| 超时（60s） | 重试 1 次 |
| 输出格式错误 | 解析失败 → 重试 1 次（附加 "请严格输出 JSON" 提示） |
| API key 无效 | 不重试，记录错误 |
| Provider 不可用 | fallback 到备用 provider（如 Anthropic 挂了 → OpenAI） |

### 工具执行失败

| 错误类型 | 处理 |
|---------|------|
| GitHub API 404 | 返回 "Resource not found" 给 LLM，让它继续判断 |
| GitHub API 403 | 返回 "Access denied" 给 LLM |
| 超时 | 返回 "Request timed out" 给 LLM |

工具失败**不中断 Agent loop** — 错误信息作为 tool_result 返回给 LLM，LLM 可以根据已有信息继续判断或尝试其他工具。

### 事件级错误隔离

与 Event Collector 相同，每个事件的分类是独立的。单个事件分类失败不影响其他事件。失败的事件保持 `classification IS NULL`，下次轮询时重试。

---

## 代码结构

```
vulnsentinel/
├── agent/                           # 共享 Agent 基础设施
│   ├── __init__.py
│   ├── loop.py                      # AgentLoop — 通用 tool-use 循环
│   ├── tool.py                      # ToolDef, ToolExecutor Protocol
│   ├── llm_client.py                # LLMClient Protocol, Message, LLMResponse, TokenUsage
│   └── providers/
│       ├── __init__.py
│       ├── anthropic.py             # AnthropicClient
│       └── openai.py                # OpenAIClient
│
├── engines/
│   └── event_classifier/
│       ├── __init__.py
│       ├── classifier.py            # classify() 独立函数（Engine 核心）
│       ├── models.py                # ClassificationResult, EventMeta dataclass
│       ├── prompts.py               # System prompt, few-shot examples, 安全关键词
│       ├── tools.py                 # CLASSIFIER_TOOLS 定义 + ClassifierToolExecutor
│       ├── prefilter.py             # Pre-filter 规则
│       └── runner.py                # EventClassifierRunner（编排 Engine + DB 读写）
│
└── ...

tests/
├── vulnsentinel/engines/event_classifier/
│   ├── test_classifier.py           # classify() 核心逻辑（mock LLM）
│   ├── test_prefilter.py            # pre-filter 规则
│   ├── test_tools.py                # 工具执行器
│   ├── test_runner.py               # Runner 集成
│   └── golden/                      # Golden test set（真实事件 + 期望分类）
│       ├── security_bugfix_01.json
│       ├── refactor_01.json
│       └── ...
└── vulnsentinel/agent/
    ├── test_loop.py                 # AgentLoop 单元测试
    └── test_providers.py            # Provider 适配测试
```

---

## Runner 设计

遵循 `EventCollectorRunner` 模式：

```python
class EventClassifierRunner:
    """Orchestration layer: pure engine → Service-layer DB writes."""

    def __init__(
        self,
        event_service: EventService,
        github_client: GitHubClient,
        llm_client: LLMClient,
    ) -> None:
        self._event_service = event_service
        self._github_client = github_client
        self._llm_client = llm_client

    async def run(self, session: AsyncSession, event_id: uuid.UUID) -> ClassificationResult:
        """Classify a single event and persist result."""
        # Step 1: 读取事件
        event_data = await self._event_service.get(session, event_id)
        event = event_data["event"]

        # Step 2: Pre-filter
        prefilter_result = prefilter(event)
        if prefilter_result is not None:
            await self._event_service.update_classification(
                session, event.id,
                classification=prefilter_result.classification,
                confidence=prefilter_result.confidence,
            )
            return prefilter_result

        # Step 3: Agent 分类
        owner, repo = parse_repo_url(event.library.repo_url)
        meta = EventMeta(
            type=event.type, title=event.title, message=event.message,
            source_url=event.source_url, owner=owner, repo=repo,
            related_issue_ref=event.related_issue_ref,
            related_pr_ref=event.related_pr_ref,
        )
        result = await classify(meta, self._github_client, self._llm_client)

        # Step 4: 写入
        await self._event_service.update_classification(
            session, event.id,
            classification=result.classification,
            confidence=result.confidence,
        )
        return result

    async def run_all(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        batch_size: int = 50,
    ) -> list[ClassificationResult]:
        """Classify all unclassified events with bounded concurrency."""
        async with session_factory() as session:
            async with session.begin():
                events = await self._event_service.list_unclassified(session, limit=batch_size)

        if not events:
            return []

        sem = asyncio.Semaphore(CLASSIFIER_CONCURRENCY)
        results = []

        async def _run_one(event_id: uuid.UUID) -> ClassificationResult:
            async with sem:
                try:
                    async with session_factory() as session:
                        async with session.begin():
                            return await self.run(session, event_id)
                except Exception as exc:
                    logger.error("classify failed for %s: %s", event_id, exc)
                    return ClassificationResult(
                        classification="error",
                        confidence=0.0,
                        reasoning=str(exc),
                        tool_calls_used=0,
                        tokens_used=TokenUsage(0, 0),
                    )

        tasks = [_run_one(ev.id) for ev in events]
        return list(await asyncio.gather(*tasks))
```

---

## 测试策略

### 单元测试（mock LLM）

所有 LLM 调用通过 `LLMClient` Protocol 注入，测试时使用 mock：

```python
class MockLLMClient:
    """返回预设响应的 mock LLM client。"""

    def __init__(self, responses: list[LLMResponse]):
        self._responses = iter(responses)

    async def create(self, **kwargs) -> LLMResponse:
        return next(self._responses)
```

测试 Agent loop 的工具调用逻辑、pre-filter 规则、结构化输出解析等。

### Golden Test Set

真实事件的 snapshot 测试：

```json
{
  "event": {
    "type": "commit",
    "title": "Fix heap buffer overflow in parse_url",
    "message": "A heap buffer overflow could occur when parsing...",
    "source_url": "https://github.com/curl/curl/commit/abc123"
  },
  "expected_classification": "security_bugfix",
  "expected_confidence_min": 0.8,
  "mock_tool_responses": {
    "fetch_commit_diff": "... diffstat + diff content ..."
  }
}
```

每次 prompt 变更后跑 golden test set，确保不退化。

### 集成测试

- Runner 完整流程：mock DB + mock LLM + mock GitHub
- Provider 适配：真实 API call（需要 key，CI 中跳过或用 VCR cassette）

---

## 配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `CLASSIFIER_LLM_PROVIDER` | `"anthropic"` | LLM provider: `anthropic` / `openai` |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `CLASSIFIER_MODEL` | `"claude-haiku-4-5-20251001"` | 默认模型 |
| `CLASSIFIER_UPGRADE_MODEL` | `"claude-sonnet-4-6"` | 升级模型 |
| `CLASSIFIER_MAX_TURNS` | `5` | Agent 最大轮次 |
| `CLASSIFIER_CONCURRENCY` | `3` | 并发分类数 |
| `CLASSIFIER_BATCH_SIZE` | `50` | run_all 每批处理数 |
| `CLASSIFIER_CONFIDENCE_THRESHOLD` | `0.7` | 低于此值触发模型升级 |
| `GITHUB_TOKEN` | — | GitHub API token（复用 Collector 的） |

---

## 实施路线图

### Phase 1: Agent 基础设施

- `vulnsentinel/agent/` — LLMClient Protocol、Message/Response 类型、AgentLoop
- Anthropic provider 实现
- 单元测试

### Phase 2: Classifier Engine 核心

- `vulnsentinel/engines/event_classifier/` — classify()、tools、prompts、prefilter
- Mock LLM 单元测试
- Golden test set（5-10 个真实事件）

### Phase 3: Runner + 集成

- EventClassifierRunner — run() + run_all()
- 与已有 EventService.list_unclassified / update_classification 对接
- 端到端集成测试

### Phase 4: 成本优化

- 模型分层（L1/L2/L3）
- Token 统计与日志
- Pre-filter 规则细化

### Phase 5: OpenAI Provider + 运维

- OpenAI provider 实现
- Provider failover
- 监控 dashboard（分类分布、成本趋势、confidence 分布）

---

## 已有基础设施

Event Classifier 依赖的 DAO/Service 已全部实现，无需新增 schema 或方法：

| 层 | 类 | 方法 | 状态 |
|----|-----|------|------|
| DAO | `EventDAO` | `list_unclassified(session, limit) → list[Event]` | 已实现，走 `idx_events_unclassified` 索引 |
| DAO | `EventDAO` | `update_classification(session, pk, classification, confidence, is_bugfix)` | 已实现 |
| Service | `EventService` | `list_unclassified(session, limit)` | 已实现，直接委托 DAO |
| Service | `EventService` | `update_classification(session, event_id, classification, confidence)` | 已实现，自动推导 `is_bugfix = (classification == "security_bugfix")` |

---

## 与架构总览的对应关系

| 架构总览中的描述 | 本文档对应 |
|----------------|-----------|
| 步骤 6：LLM 分类 | 本 Engine 的全部职责 |
| Event Classifier 触发时机 | §Runner 设计 — run_all() 轮询 + 链式触发 |
| `EventService.list_unclassified()` | §已有基础设施 |
| `EventService.update_classification()` | §已有基础设施 |
| LLM 语义分析 diff | §Agent 架构 — tool-use loop |
| 只有 `security_bugfix` 触发下游 | §分类管线 — 分类标签 |
