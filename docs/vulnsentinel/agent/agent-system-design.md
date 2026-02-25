# Agent 系统设计

> 基于 MCP 架构的多 Agent 系统，参照 FuzzingBrain-V2 实现，适配 VulnSentinel 业务场景。

---

## 目录

1. [动机与升级路径](#1-动机与升级路径)
2. [架构总览](#2-架构总览)
3. [BaseAgent](#3-baseagent)
4. [AgentContext — 运行时隔离与持久化](#4-agentcontext--运行时隔离与持久化)
5. [MCP Tool Server — Per-Agent 隔离](#5-mcp-tool-server--per-agent-隔离)
6. [Agent 实现](#6-agent-实现)
7. [工具定义](#7-工具定义)
8. [Prompt 工程](#8-prompt-工程)
9. [Pipeline 编排](#9-pipeline-编排)
10. [成本控制与 Token 管理](#10-成本控制与-token-管理)
11. [可观测性](#11-可观测性)
12. [测试策略](#12-测试策略)
13. [文件结构](#13-文件结构)
14. [实施计划](#14-实施计划)

---

## 1. 动机与升级路径

### 1.1 现有方案

当前设计（`agent/README.md`）是一个 ~200 行的轻量 Agent loop：

```
Engine → ToolDef[] + ToolExecutor → AgentLoop(LLMClient) → AgentResult
```

优点：简单、无依赖、完全可控。

### 1.2 为什么升级到 MCP

随着 Engine 数量增加（Classifier → Vuln Analyzer → Reachability Analyzer → PoC Generator），轻量方案面临的问题：

| 问题 | 影响 |
|------|------|
| **每个 Engine 手写 ToolExecutor** | match/case 分发 + 错误处理重复代码 |
| **无状态隔离** | 并发 Agent 共享 executor 实例时可能串台 |
| **无持久化** | Agent 崩溃后无法恢复进度，无法查看历史 |
| **无上下文压缩** | 长对话（Vuln Analyzer 可能 15+ 轮）token 成本爆炸 |
| **无标准化工具发现** | 工具只是 dataclass，没有 schema 自动推导 |

### 1.3 升级策略

**保留**现有 `LLMClient` Protocol 和双 Provider 适配（不引入 FBv2 的 LiteLLM 多 Provider 方案——过于重量级）。

**引入** FastMCP 替代手写 ToolDef + ToolExecutor：

```
# Before (手写)
ToolDef(name="fetch_diff", description="...", input_schema={...})
class MyExecutor:
    async def execute(self, name, input): ...

# After (MCP)
@mcp.tool()
async def fetch_diff(sha: str, file_path: str | None = None) -> str:
    """Fetch the diff of a commit."""
    ...
```

MCP 自动从函数签名 + type hints 生成 JSON Schema，`@mcp.tool()` 注册到 FastMCP server，Agent 通过 MCP Client 调用——不需要手写 match/case。

**引入** BaseAgent 抽象（参照 FBv2）统一 lifecycle、context、compression、logging。

**引入** AgentContext 持久化到 PostgreSQL。

### 1.4 与现有设计的关系

| 现有抽象 | 保留/替换 | 说明 |
|---------|----------|------|
| `LLMClient` Protocol | **保留** | 继续使用，BaseAgent 内部调用 |
| `Message`, `ToolCall`, `LLMResponse` | **保留** | 消息类型不变 |
| `TokenUsage` | **保留** | 累计 token 追踪 |
| `ToolDef` | **替换** → FastMCP `@mcp.tool()` | 自动 schema 生成 |
| `ToolExecutor` Protocol | **替换** → MCP Client `call_tool()` | 不再需要手写 executor |
| `AgentLoop` | **替换** → `BaseAgent._run_loop()` | 更完整的 lifecycle |
| `AgentResult` | **演进** → `AgentContext.result_summary` | 持久化到 DB |

---

## 2. 架构总览

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
                           │  · Context 管理              │
                           │  · 上下文压缩                 │
                           │  · Logging                   │
                           └───────┬──────────┬───────────┘
                                   │          │
                         ┌─────────▼──┐  ┌────▼──────────┐
                         │ LLMClient  │  │ MCP Client    │
                         │ (Anthropic │  │ (FastMCP      │
                         │  /OpenAI)  │  │  in-process)  │
                         └────────────┘  └────┬──────────┘
                                              │ call_tool()
                                   ┌──────────▼──────────┐
                                   │  Isolated MCP Server │
                                   │  ┌────────────────┐ │
                                   │  │ @mcp.tool()    │ │
                                   │  │ fetch_diff     │ │
                                   │  │ fetch_pr_body  │ │
                                   │  │ query_neo4j    │ │
                                   │  │ ...            │ │
                                   │  └────────────────┘ │
                                   └─────────────────────┘
```

### 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| MCP Server 模式 | **in-process (stdio)** | 不需要跨进程通信，Agent 和 Server 在同一 Python 进程 |
| Per-Agent 隔离 | **每个 Agent 实例独立 FastMCP** | 并发安全，参照 FBv2 `create_isolated_mcp_server()` |
| 持久化 | **PostgreSQL** | VulnSentinel 已有 PostgreSQL，不引入新依赖 |
| LLM Client | **保留现有 Protocol** | 够用，不需要 FBv2 的多 Provider fallback 链 |
| 上下文压缩 | **仅对 > 10 轮的 Agent 启用** | Classifier 5 轮不需要，Vuln Analyzer 15 轮需要 |

---

## 3. BaseAgent

### 3.1 类定义

```python
class BaseAgent(ABC):
    """所有 VulnSentinel Agent 的基类。

    参照 FBv2 fuzzingbrain/agents/base.py，简化并适配 PostgreSQL。
    """

    # 子类覆盖
    agent_type: str                    # "event_classifier", "vuln_analyzer", ...
    max_turns: int = 10                # 最大 LLM 调用轮次
    temperature: float = 0.3           # 默认偏保守
    model: str = "claude-haiku-4-5-20251001"  # 子类覆盖
    enable_compression: bool = False   # 子类决定是否开启

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        session: AsyncSession | None = None,   # DB session (可选)
        log_dir: Path | None = None,           # 日志目录 (可选)
    ): ...

    # ── 子类实现 ──────────────────────────────────

    @abstractmethod
    def create_mcp_server(self) -> FastMCP:
        """创建此 Agent 的 MCP Server，注册所需工具。"""
        ...

    @abstractmethod
    def get_system_prompt(self) -> str:
        """返回 system prompt。"""
        ...

    @abstractmethod
    def get_initial_message(self, **kwargs) -> str:
        """返回初始 user message。kwargs 由 run() 透传。"""
        ...

    def parse_result(self, final_content: str) -> dict:
        """从 LLM 最终输出中提取结构化结果。子类覆盖。"""
        return {"raw": final_content}

    # ── 可选覆盖 ─────────────────────────────────

    def get_urgency_message(self, turn: int, remaining: int) -> str | None:
        """当剩余轮次不足 20% 时注入的催促消息。默认提供通用版本。"""
        ...

    def get_compression_criteria(self) -> str:
        """上下文压缩时保留什么、丢弃什么。子类可覆盖提供任务特定的标准。"""
        ...

    def should_stop(self, turn: int, context: AgentContext) -> bool:
        """额外的停止条件。默认 False（仅靠 max_turns 和 LLM 停止）。"""
        return False

    # ── 主入口 ────────────────────────────────────

    async def run(self, **kwargs) -> AgentResult:
        """执行 Agent 完整生命周期。"""
        ...
```

### 3.2 run() 生命周期

```python
async def run(self, **kwargs) -> AgentResult:
    # 1. 创建 AgentContext
    context = AgentContext(
        agent_type=self.agent_type,
        session=self._session,
    )

    # 2. 创建 Isolated MCP Server
    mcp_server = self.create_mcp_server()

    # 3. 通过 MCP Client 连接
    async with Client(mcp_server) as mcp_client:
        # 4. 获取工具列表
        tools = await self._load_tools(mcp_client)

        # 5. 构造初始消息
        messages = [
            Message(role="user", content=self.get_initial_message(**kwargs)),
        ]
        system = self.get_system_prompt()

        # 6. Agent Loop
        result = await self._run_loop(
            mcp_client, tools, messages, system, context
        )

    # 7. 持久化 context
    if self._session:
        await context.save(self._session)

    # 8. 保存对话日志
    self._save_conversation_log(messages, context)

    return result
```

### 3.3 _run_loop() 核心循环

```python
async def _run_loop(self, mcp_client, tools, messages, system, context):
    for turn in range(self.max_turns):
        context.current_turn = turn

        # ── 上下文压缩 ──
        if self.enable_compression and turn > 0 and turn % 5 == 0:
            messages = await self._compress_context(messages)

        # ── 催促消息 ──
        remaining = self.max_turns - turn
        if remaining <= max(2, self.max_turns // 5):
            urgency = self.get_urgency_message(turn, remaining)
            if urgency:
                messages.append(Message(role="user", content=urgency))

        # ── 调用 LLM ──
        response = await self._llm_client.create(
            model=self.model,
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=4096,
        )
        context.add_usage(response.usage)
        messages.append(self._assistant_message(response))

        # ── 检查停止条件 ──
        if response.stop_reason != "tool_use":
            break
        if self.should_stop(turn, context):
            break

        # ── 执行工具 ──
        for tool_call in response.tool_calls:
            result = await self._execute_tool(mcp_client, tool_call)
            context.increment_tool_calls()
            messages.append(Message(
                role="tool",
                content=truncate_result(result),
                tool_call_id=tool_call.id,
            ))

    # 提取结果
    parsed = self.parse_result(response.content)
    context.result_summary = parsed
    return AgentResult(
        content=response.content,
        parsed=parsed,
        context=context,
    )
```

### 3.4 与 FBv2 BaseAgent 的差异

| 方面 | FBv2 | VulnSentinel | 原因 |
|------|------|-------------|------|
| MCP 创建 | `create_isolated_mcp_server(agent_id, ...)` 工厂函数 | `agent.create_mcp_server()` 子类方法 | VulnSentinel 各 Agent 工具差异更大，子类控制更灵活 |
| 持久化 | PostgreSQL (UUID) | — | — |
| LLM Client | 自建多 Provider + fallback 链 | 保留现有 LLMClient Protocol | 不需要那么多 Provider |
| Compression | 每 5 轮 Claude Sonnet 压缩 | 相同策略，但仅 > 10 轮 Agent 启用 | Classifier 5 轮不值得压缩 |
| Max iterations | 100 (POV Agent) | 5~25 (视 Agent 类型) | VulnSentinel Agent 任务更聚焦 |
| Tool filtering | 按 flag 动态注册工具子集 | 子类 `create_mcp_server()` 只注册所需工具 | 更简洁 |
| Conversation log | JSON 文件 | JSON 文件 + 可选 DB 存储 | 保持一致 |
| Cancel 机制 | `_cancelled` flag | 相同 | — |

---

## 4. AgentContext — 运行时隔离与持久化

### 4.1 设计目标

Agent 执行的所有细节都要能事后查询。数据分两个地方存：

| 数据 | 存储 | 查询方式 |
|------|------|---------|
| **结构化统计**（turns, tokens, cost, result） | PostgreSQL | SQL |
| **工具调用明细**（tool_name, input, output, 耗时） | PostgreSQL | SQL |
| **完整对话内容**（LLM 思考 + 工具返回全文） | Loki（经 structlog → Alloy 采集） | LogQL: `{app="vulnsentinel"} \| json \| agent_id="xxx"` |

> 日志基础设施的完整设计见 [`docs/vulnsentinel/logging.md`](../logging.md)。

### 4.2 两张 PG 表

#### `agent_runs` — Agent 执行记录（一次 `agent.run()` = 一行）

```sql
CREATE TABLE agent_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_type      VARCHAR(50) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'running',
                    -- running → completed / failed / cancelled
    engine_name     VARCHAR(50) NOT NULL,
    model           VARCHAR(80),

    -- 关联到业务对象（多态 FK）
    target_id       UUID,
    target_type     VARCHAR(30),             -- "event" | "upstream_vuln" | "client_vuln"

    -- 运行统计
    total_turns     INT NOT NULL DEFAULT 0,
    total_tool_calls INT NOT NULL DEFAULT 0,
    input_tokens    INT NOT NULL DEFAULT 0,
    output_tokens   INT NOT NULL DEFAULT 0,
    estimated_cost  NUMERIC(10, 6) DEFAULT 0,
    duration_ms     INT,

    -- 结果（结构化，支持 GIN 索引查询）
    result_summary  JSONB,
    error           TEXT,

    -- 时间
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ

    -- 注意：不存 conversation 大字段，对话内容走 Loki
);

CREATE INDEX idx_agent_runs_target ON agent_runs(target_type, target_id);
CREATE INDEX idx_agent_runs_engine ON agent_runs(engine_name, created_at DESC);
CREATE INDEX idx_agent_runs_status ON agent_runs(status)
    WHERE status IN ('failed', 'cancelled');
CREATE INDEX idx_agent_runs_result ON agent_runs
    USING gin(result_summary jsonb_path_ops);
```

#### `agent_tool_calls` — 工具调用明细（一次 tool call = 一行）

```sql
CREATE TABLE agent_tool_calls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,

    turn            INT NOT NULL,
    seq             INT NOT NULL DEFAULT 0,
    tool_name       VARCHAR(80) NOT NULL,
    tool_input      JSONB NOT NULL,
    output_chars    INT,                     -- 原始返回值长度
    duration_ms     INT,
    is_error        BOOLEAN NOT NULL DEFAULT FALSE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()

    -- 注意：不存 tool_output 大字段，工具返回内容走 Loki
);

CREATE INDEX idx_tool_calls_run ON agent_tool_calls(run_id, turn, seq);
CREATE INDEX idx_tool_calls_name ON agent_tool_calls(tool_name, created_at DESC);
CREATE INDEX idx_tool_calls_error ON agent_tool_calls(run_id)
    WHERE is_error = TRUE;
```

### 4.3 对话内容去哪了

**不存 PG，走 Loki。** BaseAgent 在 `_run_loop()` 中通过 structlog 输出对话内容：

```python
# base.py — 每轮 LLM 交互后
self._log.debug("agent.message", role="assistant", content=response.content[:500])

# 每次工具调用后
self._log.debug("agent.message", role="tool", tool_call_id=tc.id,
                tool=tc.name, content=result[:500])
```

所有日志统一经 Alloy 采集 → Loki 存储 → MinIO 持久化。查询时：

```
LogQL: {app="vulnsentinel", module="agent"} | json | agent_id="ag-456"
```

→ 按时间顺序还原该 Agent 的完整对话。

**PG 不存大文本，Loki 专门干这个——压缩存储、按 label 秒查、S3 持久化。**

### 4.4 数据模型

```python
@dataclass
class AgentContext:
    """Agent 运行时上下文。BaseAgent 在 run() 中创建和管理。"""

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    agent_type: str = ""
    status: str = "running"
    created_at: datetime = field(default_factory=datetime.utcnow)
    ended_at: datetime | None = None

    # 运行统计
    current_turn: int = 0
    total_turns: int = 0
    total_tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    # 关联
    engine_name: str = ""
    model: str = ""
    target_id: str = ""
    target_type: str = ""

    # 结果
    result_summary: dict = field(default_factory=dict)
    error: str | None = None

    # 工具调用记录（BaseAgent 在每次 tool call 后追加）
    tool_calls: list[ToolCallRecord] = field(default_factory=list)

    # ── 方法 ──

    def add_usage(self, usage: TokenUsage) -> None: ...
    def increment_tool_calls(self) -> None: ...

    def record_tool_call(
        self, turn: int, seq: int,
        tool_name: str, tool_input: dict,
        output_chars: int,
        duration_ms: int, is_error: bool,
    ) -> None:
        """记录一次工具调用（不含 output 内容，output 走 Loki）。"""
        self.tool_calls.append(ToolCallRecord(...))

    async def save(self, session: AsyncSession) -> None:
        """Agent 结束时，一次性写入 agent_runs + agent_tool_calls。"""
        # 1. INSERT agent_runs（统计 + result_summary，无 conversation）
        # 2. BULK INSERT agent_tool_calls（明细，无 tool_output）
        ...

    @property
    def estimated_cost(self) -> float:
        """基于 model + token 计数估算 USD 成本。"""
        ...

@dataclass
class ToolCallRecord:
    turn: int
    seq: int
    tool_name: str
    tool_input: dict
    output_chars: int
    duration_ms: int
    is_error: bool
```

### 4.5 BaseAgent 写入流程

```python
# base.py — _run_loop() 中

for tool_call in response.tool_calls:
    t0 = time.monotonic()
    try:
        result = await self._execute_tool(mcp_client, tool_call)
        is_error = False
    except Exception as e:
        result = str(e)
        is_error = True

    duration_ms = int((time.monotonic() - t0) * 1000)
    raw_len = len(result)
    result = truncate_result(result)

    # 工具调用明细 → PG（不含 output 内容）
    context.record_tool_call(
        turn=turn, seq=seq,
        tool_name=tool_call.name,
        tool_input=tool_call.input,
        output_chars=raw_len,
        duration_ms=duration_ms,
        is_error=is_error,
    )

    # 工具返回内容 → structlog → Loki
    self._log.info("tool.result", tool=tool_call.name,
                   chars=raw_len, duration_ms=duration_ms, is_error=is_error)
    self._log.debug("agent.message", role="tool",
                    tool_call_id=tool_call.id, content=result[:500])

    messages.append(Message(role="tool", content=result, tool_call_id=tool_call.id))

# ... loop 结束后
await context.save(session)  # 只写 PG（统计 + 工具调用明细）
```

### 4.6 查询示例

#### PG 查询（结构化数据）

```sql
-- "哪些分类 confidence < 0.7？"
SELECT r.id, r.target_id,
       r.result_summary->>'classification' AS cls,
       (r.result_summary->>'confidence')::float AS conf
FROM agent_runs r
WHERE r.agent_type = 'event_classifier'
  AND (r.result_summary->>'confidence')::float < 0.7;

-- "这个月每个 Engine 花了多少钱？"
SELECT engine_name, COUNT(*) AS runs,
       SUM(input_tokens) AS input_tok,
       SUM(estimated_cost)::numeric(10,4) AS cost
FROM agent_runs
WHERE created_at >= date_trunc('month', now())
GROUP BY engine_name;

-- "哪些工具调用最慢？"
SELECT tool_name, COUNT(*) AS calls,
       AVG(duration_ms)::int AS avg_ms, MAX(duration_ms) AS max_ms
FROM agent_tool_calls
WHERE created_at >= now() - interval '7 days'
GROUP BY tool_name ORDER BY avg_ms DESC;

-- "某个漏洞从发现到 PoC 经过了几个 Agent？"
SELECT agent_type, status, total_turns, estimated_cost, created_at
FROM agent_runs
WHERE target_id = 'vuln-uuid-here'
   OR target_id IN (SELECT id FROM client_vulns WHERE upstream_vuln_id = 'vuln-uuid-here')
ORDER BY created_at;
```

#### Loki 查询（对话内容、运行时日志）

```yaml
# "这个 event 为什么被判定为 security_bugfix？" → 看完整对话
{app="vulnsentinel", module="agent"} | json | agent_id="ag-456"

# "Classifier 看了哪些文件的 diff？" → 看 tool.call 日志
{app="vulnsentinel", module="agent"} | json | agent_id="ag-456" event="tool.call"

# "PoC 生成为什么失败了？" → 看 error 级别日志
{app="vulnsentinel", module="agent"} | json | agent_id="ag-789" level="error"
```

### 4.7 数据保留

| 数据 | 存储 | 保留 |
|------|------|------|
| `agent_runs` 统计字段 | PG | **永久** |
| `agent_tool_calls` 明细 | PG | **90 天**（定期 DELETE） |
| 对话内容 + 运行时日志 | Loki → MinIO | **90 天**（Loki `retention_period`） |

```sql
-- 定期清理 PG 工具调用明细
DELETE FROM agent_tool_calls WHERE created_at < now() - interval '90 days';
```

### 4.8 AgentContext 设计要点

| 方面 | 方案 |
|------|------|
| ID | PostgreSQL UUID |
| 结构化存储 | PG `agent_runs` + `agent_tool_calls` |
| 对话内容 | Loki（structlog → Alloy → MinIO） |
| 业务关联 | `target_type` + `target_id`（多态，指向 event / upstream_vuln / client_vuln） |
| 保存时机 | Agent 结束时一次性写入 PG（轮次少，不需要定期保存） |

---

## 5. MCP Tool Server — Per-Agent 隔离

### 5.1 设计

每个 Agent 实例创建独立的 `FastMCP` server。Agent 子类通过 `create_mcp_server()` 决定注册哪些工具。

```python
class EventClassifierAgent(BaseAgent):
    agent_type = "event_classifier"

    def __init__(self, ..., github_client: GitHubClient, owner: str, repo: str):
        super().__init__(...)
        self._github = github_client
        self._owner = owner
        self._repo = repo

    def create_mcp_server(self) -> FastMCP:
        mcp = FastMCP(f"classifier-{self.context.id}")

        # 闭包捕获 self 的 GitHub client
        github = self._github
        owner, repo = self._owner, self._repo

        @mcp.tool()
        async def fetch_commit_diff(sha: str, file_path: str | None = None) -> str:
            """Fetch the diff of a commit. Returns diffstat by default.
            Pass file_path to get the full diff of a specific file."""
            return await _fetch_commit_diff(github, owner, repo, sha, file_path)

        @mcp.tool()
        async def fetch_pr_diff(pr_number: int, file_path: str | None = None) -> str:
            """Fetch the diff of a merged PR."""
            return await _fetch_pr_diff(github, owner, repo, pr_number, file_path)

        # ... 更多工具

        return mcp
```

### 5.2 工具函数注册模式

与 FBv2 的工厂函数模式（`create_isolated_mcp_server(agent_id, include_pov_tools=True, ...)`）不同，VulnSentinel 使用**子类方法模式**：

```
FBv2:       create_isolated_mcp_server(flags...) → FastMCP
VulnSentinel: agent.create_mcp_server() → FastMCP
```

原因：
- FBv2 的工具集相对固定（analyzer + code_viewer + pov + coverage + seed），通过 flag 组合即可
- VulnSentinel 各 Agent 工具差异大（GitHub API / Neo4j / FuzzingBrain RPC / 通知渠道），子类方法更灵活
- 子类可以通过闭包捕获自己的依赖（GitHubClient, Neo4j driver 等），不需要全局注册

### 5.3 工具实现位置

工具的**实际逻辑**不写在 `@mcp.tool()` 装饰函数里，而是抽到独立模块：

```
vulnsentinel/agent/tools/
├── github_tools.py      # fetch_commit_diff, fetch_pr_diff, ...
├── analysis_tools.py    # query_call_graph, find_path, ...
├── poc_tools.py         # run_poc, verify_crash, ...
└── __init__.py
```

`@mcp.tool()` 只做参数解包 + 调用实际函数。这样工具逻辑可以独立测试。

---

## 6. Agent 实现

### 6.1 Agent 总览

| Agent | Engine | 用途 | 工具 | 轮次 | 模型 |
|-------|--------|------|------|------|------|
| **EventClassifierAgent** | Event Classifier | 判断 commit/PR 是否为安全修复 | GitHub (5) | 5 | Haiku 4.5 |
| **VulnAnalyzerAgent** | Vuln Analyzer | 深入分析漏洞细节 | GitHub (5) + Analysis (3) | 15 | Sonnet |
| **ReachabilityAgent** | Reachability Analyzer | 静态分析路径搜索 | Analysis (5) + Code (3) | 10 | Sonnet |
| **PocGeneratorAgent** | Reachability Analyzer | 生成 PoC | PoC (4) + Code (3) | 25 | Sonnet |
| **ReportAgent** | Notification Engine | 生成漏洞报告 | Code (3) + GitHub (2) | 5 | Haiku 4.5 |

### 6.2 EventClassifierAgent

**职责**：判断一个 event（commit/PR/tag/issue）是否为 `security_bugfix`。

**输入**：EventMeta（type, ref, title, message, author, source_url）

**输出**：ClassificationResult（classification, confidence, reasoning）

**工具**：

| 工具 | 描述 | 调用时机 |
|------|------|---------|
| `fetch_commit_diff` | 获取 commit diff（diffstat → 按文件展开） | commit 事件 |
| `fetch_pr_diff` | 获取 PR diff | pr_merge 事件 |
| `fetch_file_content` | 获取指定文件内容 | 需要上下文理解 diff |
| `fetch_issue_body` | 获取 issue 标题 + 正文 | commit 关联了 issue |
| `fetch_pr_body` | 获取 PR 标题 + 正文 + labels | pr_merge 事件 |

**特殊机制**：

1. **Pre-filter 快速路径**（在 Agent 之前执行）：
   - tag → `release`
   - 合并 commit → `merge`
   - Bot 作者 → `dependency_update`
   - Conventional commit prefix → 对应分类
   - 命中 pre-filter 的事件不启动 Agent

2. **模型升级链**：
   - L1: Haiku 4.5（默认，~$0.001/event）
   - L2: Sonnet（L1 判定 `security_bugfix` 但 confidence < 0.7）
   - L3: Opus（L2 仍不确定 + 标题含安全关键词）

3. **Diffstat-first 策略**：
   - `fetch_commit_diff(sha)` 默认返回 diffstat（文件列表 + 行数统计）
   - LLM 可再调 `fetch_commit_diff(sha, file_path="src/parser.c")` 获取单文件完整 diff
   - 避免一次性发送巨大 diff 浪费 token

```python
class EventClassifierAgent(BaseAgent):
    agent_type = "event_classifier"
    max_turns = 5
    temperature = 0.2       # 判断任务，低温度
    model = "claude-haiku-4-5-20251001"
    enable_compression = False  # 5 轮不需要

    def __init__(
        self,
        llm_client: LLMClient,
        github_client: GitHubClient,
        owner: str,
        repo: str,
        **base_kwargs,
    ):
        super().__init__(llm_client, **base_kwargs)
        self._github = github_client
        self._owner = owner
        self._repo = repo

    def create_mcp_server(self) -> FastMCP: ...
    def get_system_prompt(self) -> str: ...
    def get_initial_message(self, *, event: EventMeta) -> str: ...

    def parse_result(self, content: str) -> ClassificationResult:
        """从 LLM JSON 输出提取分类结果。"""
        ...
```

### 6.3 VulnAnalyzerAgent

**职责**：对已确认的 `security_bugfix` 事件进行深入分析，提取漏洞类型、严重度、影响版本、修复方式。

**输入**：Event + 分类结果

**输出**：VulnAnalysis（vuln_type/CWE, severity, affected_versions, summary, reasoning, upstream_poc）

**工具**：

| 工具 | 描述 |
|------|------|
| `fetch_commit_diff` | 获取修复 diff |
| `fetch_pr_diff` | 获取 PR diff |
| `fetch_file_content` | 查看修复前后的代码 |
| `fetch_issue_body` | 关联 issue 中可能有 PoC 或 crash 信息 |
| `fetch_pr_body` | PR 描述可能有详细说明 |
| `search_code` | 在 repo 中搜索相关代码模式 |
| `list_tags` | 获取版本标签列表，帮助判断影响范围 |
| `fetch_commit_at_ref` | 查看特定版本的代码状态 |

**特殊机制**：

1. **上下文压缩** — 启用（max_turns=15，可能产生大量中间分析）
2. **Two-pass 分析**：
   - Pass 1: 理解 diff（做了什么修复）
   - Pass 2: 推断漏洞细节（修复前的代码有什么问题，CWE 分类，CVSS 估算）
3. **版本范围推断**：通过 git tag 和 blame 信息推断 `affected_versions`

```python
class VulnAnalyzerAgent(BaseAgent):
    agent_type = "vuln_analyzer"
    max_turns = 15
    temperature = 0.3
    model = "claude-sonnet-4-6-20250514"
    enable_compression = True

    def __init__(
        self,
        llm_client: LLMClient,
        github_client: GitHubClient,
        owner: str,
        repo: str,
        **base_kwargs,
    ):
        super().__init__(llm_client, **base_kwargs)
        self._github = github_client
        self._owner = owner
        self._repo = repo

    def create_mcp_server(self) -> FastMCP: ...
    def get_system_prompt(self) -> str: ...
    def get_initial_message(self, *, event: EventMeta, classification: ClassificationResult) -> str: ...
    def parse_result(self, content: str) -> VulnAnalysis: ...

    def get_compression_criteria(self) -> str:
        return """Keep:
        - Vulnerability type and CWE classification evidence
        - Affected code patterns (before/after fix)
        - Version range analysis
        - Severity assessment reasoning
        Discard:
        - Raw diff content already analyzed
        - Unrelated file changes
        - Duplicate reasoning"""
```

### 6.4 ReachabilityAgent

**职责**：在客户代码的 call graph 中搜索从入口到漏洞函数的可达路径。

**输入**：ClientVuln（关联的 UpstreamVuln + Project + Snapshot）

**输出**：ReachabilityResult（is_reachable, paths, reachable_functions, analysis）

**工具**：

| 工具 | 描述 |
|------|------|
| `query_call_graph` | 查询 Neo4j call graph（调用者/被调用者） |
| `find_paths` | BFS/DFS 路径搜索（入口 → 目标） |
| `get_function_source` | 获取函数源码 |
| `search_code` | 在客户代码中搜索模式 |
| `list_entry_points` | 列出客户代码的 fuzzer/test/main 入口 |
| `get_snapshot_info` | 获取 Snapshot 元信息 |
| `check_version_match` | 检查客户依赖版本是否在影响范围 |
| `get_import_chain` | 追踪 import/include 依赖链 |

**特殊机制**：

1. **Snapshot 依赖**：需要先有 Snapshot（call graph），否则 Agent 无法工作
2. **路径评分**：找到路径后，Agent 评估利用可行性（路径长度、条件约束、权限要求）
3. **函数指针感知**：参照 FBv2 的经验，提示 Agent 检查函数指针间接调用

```python
class ReachabilityAgent(BaseAgent):
    agent_type = "reachability_analyzer"
    max_turns = 10
    temperature = 0.2       # 分析任务，低温度
    model = "claude-sonnet-4-6-20250514"
    enable_compression = False  # 10 轮边界

    def __init__(
        self,
        llm_client: LLMClient,
        neo4j_driver: AsyncDriver,
        snapshot_id: uuid.UUID,
        **base_kwargs,
    ):
        super().__init__(llm_client, **base_kwargs)
        self._neo4j = neo4j_driver
        self._snapshot_id = snapshot_id

    def create_mcp_server(self) -> FastMCP: ...
    def get_system_prompt(self) -> str: ...
    def get_initial_message(self, *, client_vuln: ClientVulnInfo) -> str: ...
    def parse_result(self, content: str) -> ReachabilityResult: ...
```

### 6.5 PocGeneratorAgent

**职责**：对已确认可达的漏洞生成 PoC（概念验证利用）。

**输入**：ClientVuln + ReachabilityResult + UpstreamVuln

**输出**：PocResult（poc_code, poc_type, verification_result, crash_output）

**工具**：

| 工具 | 描述 |
|------|------|
| `get_function_source` | 获取目标函数和路径上函数的源码 |
| `get_reachable_path` | 获取 Reachability 阶段找到的路径 |
| `create_poc` | 生成 PoC 代码（Python/C/shell） |
| `compile_poc` | 编译 PoC（C/C++ 场景） |
| `run_poc` | 在沙箱中执行 PoC |
| `get_upstream_poc` | 获取上游已有的 PoC/reproducer（如果有） |
| `search_code` | 搜索代码辅助理解 |

**特殊机制**：

1. **Greedy 模式**（参照 FBv2 POVAgent）：
   - 前 3 次 PoC 尝试：禁用 `run_poc`，只让 Agent 生成代码
   - 第 4 次起：启用 `run_poc`，允许 Agent 迭代调试
2. **上游 PoC 参考**：如果 UpstreamVuln 已有 upstream_poc（如 OSS-Fuzz reproducer），作为上下文提供
3. **沙箱执行**：`run_poc` 在 Docker 容器内执行，超时 30 秒

```python
class PocGeneratorAgent(BaseAgent):
    agent_type = "poc_generator"
    max_turns = 25
    temperature = 0.5       # 需要一些创造性
    model = "claude-sonnet-4-6-20250514"
    enable_compression = True

    def __init__(
        self,
        llm_client: LLMClient,
        workspace_path: Path,
        **base_kwargs,
    ):
        super().__init__(llm_client, **base_kwargs)
        self._workspace = workspace_path

    def create_mcp_server(self) -> FastMCP: ...
    def get_system_prompt(self) -> str: ...
    def get_initial_message(self, *, client_vuln: ClientVulnInfo, reachability: ReachabilityResult) -> str: ...
    def parse_result(self, content: str) -> PocResult: ...

    def should_stop(self, turn: int, context: AgentContext) -> bool:
        """PoC 成功即停。"""
        return context.result_summary.get("verified", False)
```

### 6.6 ReportAgent

**职责**：汇总漏洞分析、可达路径、PoC 结果，生成人可读的报告。

**输入**：UpstreamVuln + ClientVuln + ReachabilityResult + PocResult

**输出**：ReportResult（title, markdown_content, severity_override）

**工具**：

| 工具 | 描述 |
|------|------|
| `get_function_source` | 获取关键函数源码用于报告引用 |
| `fetch_commit_diff` | 获取修复 diff 用于报告引用 |
| `get_cwe_info` | 查询 CWE 描述和修复建议 |

```python
class ReportAgent(BaseAgent):
    agent_type = "report_generator"
    max_turns = 5
    temperature = 0.3
    model = "claude-haiku-4-5-20251001"
    enable_compression = False
```

---

## 7. 工具定义

### 7.1 工具分类

```
vulnsentinel/agent/tools/
├── github_tools.py          # GitHub API 工具（5 个）
├── analysis_tools.py        # 静态分析 + Neo4j 工具（5 个）
├── code_tools.py            # 代码查看工具（3 个）
├── poc_tools.py             # PoC 生成/执行工具（4 个）
└── __init__.py
```

### 7.2 GitHub 工具（共享）

```python
# github_tools.py — EventClassifierAgent + VulnAnalyzerAgent 共享

async def fetch_commit_diff(
    client: GitHubClient, owner: str, repo: str,
    sha: str, file_path: str | None = None,
) -> str:
    """获取 commit diff。默认返回 diffstat，指定 file_path 返回单文件 diff。"""
    if file_path is None:
        # diffstat 模式：GET /repos/{o}/{r}/commits/{sha} → 提取 files[].filename/changes
        ...
    else:
        # 单文件 diff 模式：GET /repos/{o}/{r}/commits/{sha} → 找到对应 file → 返回 patch
        ...

async def fetch_pr_diff(
    client: GitHubClient, owner: str, repo: str,
    pr_number: int, file_path: str | None = None,
) -> str:
    """获取 PR diff。策略同 fetch_commit_diff。"""
    ...

async def fetch_file_content(
    client: GitHubClient, owner: str, repo: str,
    path: str, ref: str = "HEAD",
) -> str:
    """获取仓库中指定文件的内容。"""
    # GET /repos/{o}/{r}/contents/{path}?ref={ref}
    ...

async def fetch_issue_body(
    client: GitHubClient, owner: str, repo: str,
    issue_number: int,
) -> str:
    """获取 issue 的标题、正文和标签。"""
    # GET /repos/{o}/{r}/issues/{number}
    ...

async def fetch_pr_body(
    client: GitHubClient, owner: str, repo: str,
    pr_number: int,
) -> str:
    """获取 PR 的标题、正文和标签。"""
    # GET /repos/{o}/{r}/pulls/{number}
    ...
```

### 7.3 静态分析工具

```python
# analysis_tools.py — ReachabilityAgent 使用

async def query_call_graph(
    driver: AsyncDriver, snapshot_id: str,
    function_name: str, direction: str = "callees", depth: int = 3,
) -> str:
    """查询 call graph。direction: 'callers' | 'callees'。返回 JSON。"""
    ...

async def find_paths(
    driver: AsyncDriver, snapshot_id: str,
    source: str, target: str, max_depth: int = 10,
) -> str:
    """BFS 搜索 source → target 的所有路径。返回路径列表 JSON。"""
    ...

async def get_function_source(
    workspace: Path, file_path: str,
    start_line: int, end_line: int,
) -> str:
    """获取函数源码（带行号）。"""
    ...

async def search_code(
    workspace: Path, pattern: str,
    file_glob: str = "**/*", max_results: int = 20,
) -> str:
    """在代码中搜索模式（正则）。返回匹配行和上下文。"""
    ...

async def list_entry_points(
    driver: AsyncDriver, snapshot_id: str,
) -> str:
    """列出没有调用者的函数（候选入口点）。"""
    ...
```

### 7.4 PoC 工具

```python
# poc_tools.py — PocGeneratorAgent 使用

async def create_poc(
    workspace: Path, code: str, filename: str = "poc.py",
) -> str:
    """将 PoC 代码写入文件。返回文件路径。"""
    ...

async def compile_poc(
    workspace: Path, filename: str,
    compiler: str = "gcc", flags: str = "",
) -> str:
    """编译 C/C++ PoC。返回编译结果。"""
    ...

async def run_poc(
    workspace: Path, command: str, timeout: int = 30,
) -> str:
    """在 Docker 沙箱中执行 PoC。返回 stdout + stderr + exit code。"""
    ...

async def get_upstream_poc(
    upstream_vuln: dict,
) -> str:
    """获取上游已有的 PoC/reproducer（如果有）。"""
    ...
```

---

## 8. Prompt 工程

### 8.1 Prompt 文件结构

```
vulnsentinel/agent/prompts/
├── classifier/
│   ├── system.md                 # 分类器 system prompt
│   └── user_template.md          # 初始 user message 模板
├── vuln_analyzer/
│   ├── system.md
│   └── user_template.md
├── reachability/
│   ├── system.md
│   └── user_template.md
├── poc_generator/
│   ├── system.md
│   ├── user_template.md
│   └── greedy_hint.md            # Greedy 模式额外提示
├── report/
│   ├── system.md
│   └── user_template.md
└── shared/
    ├── compression.md            # 通用压缩标准
    └── urgency.md                # 通用催促模板
```

### 8.2 System Prompt 模式

参照 FBv2，每个 Agent 的 system prompt 包含：

```markdown
# Role Definition
你是 VulnSentinel 的 [角色名]。你的任务是 [一句话描述]。

# Available Tools
你可以使用以下工具：
- `tool_name`: [描述]
- ...

# Analysis Process
1. [步骤 1]
2. [步骤 2]
...

# Output Format
你的最终输出必须是以下 JSON 格式：
```json
{
    "field1": "...",
    "field2": "..."
}
```

# Important Rules
- [约束 1]
- [约束 2]
```

### 8.3 Classifier System Prompt 要点

```markdown
# Role
你是安全分析师。判断一个 Git commit/PR 是否为安全漏洞修复。

# Classification Labels
- `security_bugfix` — 修复了安全漏洞（buffer overflow, use-after-free, injection, etc.）
- `bugfix` — 修复了非安全 bug
- `feature` — 新功能
- `refactor` — 重构
- `documentation` / `test` / `performance` — 对应类型
- `dependency_update` — 依赖更新
- `other` — 其他

# Security Keywords (参考)
buffer overflow, heap overflow, stack overflow, use-after-free, double-free,
integer overflow, integer underflow, null pointer dereference, format string,
SQL injection, command injection, XSS, CSRF, path traversal, SSRF,
race condition, TOCTOU, uninitialized memory, out-of-bounds, ...

# Judgment Criteria
1. 看 diff：修复是否涉及边界检查、输入验证、内存安全、权限控制？
2. 看 commit message / PR body：是否提及 CVE、安全、漏洞、crash？
3. 看关联 issue：是否是安全报告？
4. 看修改的文件：是否在关键路径（parser, network, auth, crypto）？

# Tool Usage Guidance
- 先看 diffstat，判断修改范围
- 如果 diffstat 中有安全相关文件（parser, auth, crypto），获取完整 diff
- 如果 commit message 引用了 issue，获取 issue body
- 不要获取所有文件的 diff——只看可疑的文件

# Output Format
```json
{
    "classification": "security_bugfix|bugfix|feature|...",
    "confidence": 0.85,
    "reasoning": "简短解释判断理由"
}
```
```

### 8.4 Few-shot Examples

在 system prompt 中包含 2-3 个例子：

```markdown
# Examples

## Example 1: Security Bugfix
Commit message: "Fix heap buffer overflow in JPEG decoder"
Diff: Added bounds check in `decode_huffman()` before `memcpy()`
→ `{"classification": "security_bugfix", "confidence": 0.95, "reasoning": "..."}`

## Example 2: Regular Bugfix
Commit message: "Fix incorrect return value in config parser"
Diff: Changed `return 0` to `return -1` in error path
→ `{"classification": "bugfix", "confidence": 0.85, "reasoning": "..."}`

## Example 3: Refactor
Commit message: "Refactor: extract common validation logic"
Diff: Moved code to new function, no behavior change
→ `{"classification": "refactor", "confidence": 0.90, "reasoning": "..."}`
```

---

## 9. Pipeline 编排

### 9.1 Engine → Agent 集成模式

每个 Engine 的 Runner 负责：
1. 准备 Agent 所需的上下文（从 DB 读取业务对象）
2. 创建 Agent 实例
3. 调用 `agent.run()`
4. 处理结果（更新 DB 业务对象）

```python
class EventClassifierRunner:
    """Event Classifier 的集成模式运行器。"""

    def __init__(
        self,
        event_service: EventService,
        llm_client: LLMClient,
        github_client: GitHubClient,
    ): ...

    async def run(self, session: AsyncSession, event_id: uuid.UUID) -> ClassificationResult:
        # 1. 读取 event
        event = await self._event_service.get(session, event_id)

        # 2. Pre-filter 快速路径
        pre_result = pre_filter(event)
        if pre_result:
            await self._event_service.update_classification(session, event_id, pre_result)
            return pre_result

        # 3. 解析 repo URL
        owner, repo = parse_github_url(event.library.repo_url)

        # 4. 创建 Agent
        agent = EventClassifierAgent(
            llm_client=self._llm_client,
            github_client=self._github_client,
            owner=owner,
            repo=repo,
            session=session,
        )

        # 5. 执行
        result = await agent.run(event=EventMeta.from_model(event))

        # 6. 更新 DB
        await self._event_service.update_classification(
            session, event_id,
            classification=result.parsed.classification,
            confidence=result.parsed.confidence,
            is_bugfix=(result.parsed.classification == "security_bugfix"),
        )

        return result.parsed
```

### 9.2 端到端流水线

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Scheduler (APScheduler)                         │
│  · 轮询 DB 找到待处理对象                                                  │
│  · 每个 Engine 独立调度周期                                                │
└────────┬──────────┬──────────┬──────────┬──────────┬────────────────────┘
         │          │          │          │          │
         ▼          ▼          ▼          ▼          ▼
   ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌────────┐ ┌──────────┐
   │ Event    │ │ Event    │ │ Vuln    │ │Impact │ │Reachabi- │
   │Collector │ │Classifier│ │Analyzer │ │Engine │ │lity+PoC  │
   │ Runner   │ │ Runner   │ │ Runner  │ │Runner │ │ Runner   │
   └────┬─────┘ └────┬─────┘ └────┬────┘ └───┬───┘ └────┬─────┘
        │             │            │           │          │
        │        ┌────▼────┐  ┌───▼────┐      │    ┌─────▼─────┐
        │        │Classifier│  │ Vuln   │      │    │Reachability│
        │        │  Agent   │  │Analyzer│      │    │  Agent     │
        │        │          │  │ Agent  │      │    │     +      │
        │        └────┬─────┘  └───┬────┘      │    │PoC Agent  │
        │             │            │           │    └─────┬─────┘
        ▼             ▼            ▼           ▼          ▼
   ┌──────────────────────────────────────────────────────────┐
   │                     PostgreSQL                           │
   │  events → upstream_vulns → client_vulns → agent_runs    │
   └──────────────────────────────────────────────────────────┘
```

### 9.3 调度策略

| Engine | 触发条件 | 并发 | 间隔 |
|--------|---------|------|------|
| Event Collector | `library.last_activity_at < now - 75min` | 5 | 75min |
| Event Classifier | `event.classification IS NULL` | 3 | 实时（Collector 完成后触发） |
| Vuln Analyzer | `event.classification = 'security_bugfix'` + 无对应 upstream_vuln | 1 | 实时（Classifier 完成后触发） |
| Impact Engine | `upstream_vuln.status = 'published'` | 1 | 实时（Analyzer 完成后触发） |
| Reachability | `client_vuln.pipeline_status = 'pending'` | 2 | 实时（Impact 完成后触发） |
| PoC Generator | `client_vuln.pipeline_status = 'path_found'` | 1 | 实时 |

### 9.4 事件驱动 vs 轮询

- **Event Collector**：轮询（定时扫描所有 library）
- **其他 Engine**：事件驱动，由上游 Runner 在更新 DB 后直接触发下游

```python
# event_classifier_runner.py
async def run(self, session, event_id):
    result = await agent.run(event=...)
    await self._event_service.update_classification(session, event_id, result)

    # 触发下游
    if result.classification == "security_bugfix":
        await self._vuln_analyzer_runner.run(session, event_id)
```

---

## 10. 成本控制与 Token 管理

### 10.1 三层防御

```
Layer 1: Pre-filter  ────────────────── 跳过 ~40% events，零 LLM 成本
Layer 2: Token budget ───────────────── 每个 Agent 有 max_turns + 工具截断
Layer 3: Model stratification ───────── Haiku → Sonnet → Opus 升级链
```

### 10.2 预估成本

| Agent | 模型 | 平均轮次 | 预估 Input Tokens | 预估 Output Tokens | 每次成本 |
|-------|------|---------|------------------|-------------------|---------|
| Classifier (L1) | Haiku 4.5 | 3 | ~4,000 | ~500 | ~$0.001 |
| Classifier (L2) | Sonnet | 3 | ~4,000 | ~500 | ~$0.01 |
| Vuln Analyzer | Sonnet | 10 | ~30,000 | ~3,000 | ~$0.12 |
| Reachability | Sonnet | 7 | ~20,000 | ~2,000 | ~$0.08 |
| PoC Generator | Sonnet | 15 | ~50,000 | ~5,000 | ~$0.20 |
| Report | Haiku 4.5 | 3 | ~8,000 | ~2,000 | ~$0.003 |

**月成本估算**（1000 events/月，5% security_bugfix）：

```
1000 events × $0.001 (Classifier L1)    = $1.00
 50 events × $0.01 (Classifier L2 升级) = $0.50
 50 vulns × $0.12 (Vuln Analyzer)       = $6.00
 30 clients × $0.08 (Reachability)      = $2.40
 15 pocs × $0.20 (PoC Generator)        = $3.00
 15 reports × $0.003 (Report)           = $0.05
                                   ─────────────
                                   Total ≈ $13/月
```

### 10.3 Token Budget 规则

| 限制 | 值 | 位置 |
|------|---|------|
| 工具结果最大字符 | 15,000 chars (~4K tokens) | `truncate_result()` |
| Diff 单文件最大 | 15,000 chars | `fetch_commit_diff()` |
| 文件内容最大 | 10,000 chars | `fetch_file_content()` |
| Search 结果最大 | 5,000 chars | `search_code()` |

### 10.4 成本追踪

每个 AgentContext 累计 token 使用量，保存到 `agent_runs` 表。更多查询示例见 [第 4.6 节](#46-查询示例)。

---

## 11. 可观测性

> 完整日志架构设计见 [`docs/vulnsentinel/logging.md`](../logging.md)。本节只描述 Agent 相关部分。

### 11.1 总体方案

```
structlog (应用内) → stdout → Alloy (采集) → Loki (存储) → MinIO (持久化)
                                                              ↑
                                                         Grafana (查询 UI)
```

- **日志库**：统一 structlog，不引入 loguru
- **持久化**：Loki + MinIO（本地磁盘，以后可换 S3）
- **结构化查询**：PG `agent_runs` + `agent_tool_calls`（详见第 4 节）
- **对话 replay**：走 Loki（`{app="vulnsentinel"} | json | agent_id="xxx"`）
- **应用代码改动**：零（现有 structlog 代码不动）

### 11.2 Agent 日志写法

```python
import structlog

log = structlog.get_logger("vulnsentinel.agent")

# run() 中绑定上下文
log = log.bind(agent_type=self.agent_type, agent_id=str(context.id),
               target_id=context.target_id)

# INFO: 关键事件（始终记录）
log.info("agent.start", model=self.model, max_turns=self.max_turns)
log.info("agent.turn", turn=1, max_turns=5)
log.info("tool.call", tool="fetch_commit_diff", duration_ms=556)
log.info("agent.done", turns=2, input_tokens=3200, output_tokens=450, cost=0.0012)

# DEBUG: 对话内容（生产环境可关闭，需要 replay 时开启）
log.debug("agent.message", role="assistant", content=response.content[:500])
log.debug("agent.message", role="tool", tool_call_id="tc-1", content=result[:500])
```

### 11.3 PG + Loki 分工

| 查什么 | 去哪查 | 怎么查 |
|--------|--------|--------|
| "这个月花了多少 token？" | PG `agent_runs` | SQL `SUM(input_tokens)` |
| "哪些工具最慢？" | PG `agent_tool_calls` | SQL `AVG(duration_ms)` |
| "confidence < 0.7 的分类？" | PG `agent_runs` | SQL on `result_summary` JSONB |
| "漏洞从发现到 PoC 经过几个 Agent？" | PG `agent_runs` | SQL `WHERE target_id = ...` |
| "这个 event 为什么被判定为 security_bugfix？" | Loki | `{...} \| json \| agent_id="ag-456"` |
| "PoC Agent 第 15 轮 LLM 说了什么？" | Loki | 同上，按时间范围缩小 |
| "昨晚有什么错误？" | Loki | `{...} \| json \| level="error"` |

### 11.4 API Endpoints

```
GET /v1/agent-runs                             # 列表（分页、过滤）
GET /v1/agent-runs/{id}                        # 详情
GET /v1/agent-runs/{id}/tool-calls             # 工具调用明细
GET /v1/agent-runs/by-target/{type}/{id}       # 按业务对象查全部 agent 执行
GET /v1/stats/agents                           # 聚合统计
GET /v1/stats/agents/tools                     # 工具调用统计
```

#### AgentRunService

```python
class AgentRunService:
    async def list(self, session, *, agent_type=None, engine_name=None,
                   status=None, target_type=None, target_id=None,
                   since=None, cursor=None, limit=20) -> list[AgentRun]: ...
    async def get(self, session, run_id: uuid.UUID) -> AgentRun: ...
    async def get_tool_calls(self, session, run_id: uuid.UUID) -> list[AgentToolCall]: ...
    async def get_by_target(self, session, target_type: str, target_id: uuid.UUID) -> list[AgentRun]: ...
    async def get_agent_stats(self, session, *, since=None, group_by="engine_name") -> list[AgentStats]: ...
    async def get_tool_stats(self, session, *, since=None) -> list[ToolStats]: ...
```

#### 链路追踪示例

```
GET /v1/agent-runs/by-target/event/{event_id}
→ [{agent_type: "event_classifier", result_summary: {classification: "security_bugfix", confidence: 0.92}}]

GET /v1/agent-runs/by-target/client_vuln/{client_vuln_id}
→ [
    {agent_type: "reachability_analyzer", result_summary: {is_reachable: true}},
    {agent_type: "poc_generator", result_summary: {verified: true}},
  ]
```

---

## 12. 测试策略

### 12.1 分层测试

```
┌────────────────────────────────────────────┐
│ Layer 1: 工具函数单元测试                     │
│  · github_tools (mock httpx)              │
│  · analysis_tools (mock Neo4j)            │
│  · poc_tools (mock Docker)                │
│  · 不涉及 LLM，不涉及 MCP                   │
└────────────────────────────────────────────┘

┌────────────────────────────────────────────┐
│ Layer 2: Agent 单元测试 (MockLLMClient)     │
│  · 保留现有 MockLLMClient 模式               │
│  · 预设 LLM 响应序列                         │
│  · 验证 Agent 是否正确调用工具                  │
│  · 验证 parse_result 是否正确提取结果          │
└────────────────────────────────────────────┘

┌────────────────────────────────────────────┐
│ Layer 3: MCP 集成测试                       │
│  · 测试 create_mcp_server() 工具注册        │
│  · 测试 MCP Client ↔ Server 通信           │
│  · 不涉及真实 LLM                            │
└────────────────────────────────────────────┘

┌────────────────────────────────────────────┐
│ Layer 4: 端到端测试 (需 API key)             │
│  · 真实 LLM + mock GitHub API              │
│  · 验证完整 Agent loop                      │
│  · CI 中标记 @pytest.mark.requires_api_key  │
└────────────────────────────────────────────┘
```

### 12.2 MockLLMClient（保留现有设计）

```python
class MockLLMClient:
    """返回预设响应序列的 mock LLM client。"""

    def __init__(self, responses: list[LLMResponse]):
        self._responses = iter(responses)

    async def create(self, **kwargs) -> LLMResponse:
        return next(self._responses)
```

### 12.3 测试文件位置

```
tests/vulnsentinel/agent/
├── test_base_agent.py              # BaseAgent lifecycle
├── test_agent_context.py           # AgentContext 持久化
├── test_mcp_integration.py         # MCP Server/Client 通信
├── tools/
│   ├── test_github_tools.py        # GitHub 工具（mock httpx）
│   ├── test_analysis_tools.py      # 分析工具（mock Neo4j）
│   └── test_poc_tools.py           # PoC 工具（mock Docker）
├── agents/
│   ├── test_classifier_agent.py    # Classifier Agent（MockLLMClient）
│   ├── test_vuln_analyzer_agent.py
│   ├── test_reachability_agent.py
│   ├── test_poc_generator_agent.py
│   └── test_report_agent.py
└── e2e/
    └── test_classifier_e2e.py      # 端到端（真实 LLM + mock GitHub）
```

---

## 13. 文件结构

```
vulnsentinel/
└── agent/
    ├── __init__.py                  # 公开 API
    ├── base.py                      # BaseAgent 基类 (~300 LOC)
    ├── context.py                   # AgentContext + DB 持久化 (~150 LOC)
    ├── result.py                    # AgentResult dataclass
    │
    ├── llm_client.py                # LLMClient Protocol (保留现有)
    ├── providers/
    │   ├── __init__.py              # create_llm_client()
    │   ├── anthropic.py             # AnthropicClient
    │   └── openai.py                # OpenAIClient
    │
    ├── tools/                       # 工具实现（纯函数）
    │   ├── __init__.py
    │   ├── github_tools.py          # GitHub API 工具 (~200 LOC)
    │   ├── analysis_tools.py        # Neo4j + 静态分析 (~200 LOC)
    │   ├── code_tools.py            # 代码查看 (~100 LOC)
    │   └── poc_tools.py             # PoC 生成/执行 (~200 LOC)
    │
    ├── agents/                      # Agent 子类实现
    │   ├── __init__.py
    │   ├── classifier.py            # EventClassifierAgent (~200 LOC)
    │   ├── vuln_analyzer.py         # VulnAnalyzerAgent (~250 LOC)
    │   ├── reachability.py          # ReachabilityAgent (~200 LOC)
    │   ├── poc_generator.py         # PocGeneratorAgent (~250 LOC)
    │   └── report.py                # ReportAgent (~150 LOC)
    │
    └── prompts/                     # Prompt 模板
        ├── classifier/
        │   ├── system.md
        │   └── user_template.md
        ├── vuln_analyzer/
        │   ├── system.md
        │   └── user_template.md
        ├── reachability/
        │   ├── system.md
        │   └── user_template.md
        ├── poc_generator/
        │   ├── system.md
        │   ├── user_template.md
        │   └── greedy_hint.md
        ├── report/
        │   ├── system.md
        │   └── user_template.md
        └── shared/
            ├── compression.md
            └── urgency.md
```

预估总代码量：**~1,800 LOC**（不含 prompt 文件和测试）。

---

## 14. 实施计划

### Phase 1: 基础框架

1. **BaseAgent + AgentContext** — `base.py`, `context.py`, `result.py`
2. **MCP 集成** — `create_mcp_server()` 模式验证
3. **agent_runs 表** — SQLAlchemy model + migration
4. **测试** — `test_base_agent.py`, `test_agent_context.py`, `test_mcp_integration.py`

### Phase 2: Event Classifier Agent

1. **GitHub 工具** — `github_tools.py`（5 个工具实现）
2. **EventClassifierAgent** — `classifier.py`
3. **Prompt** — `classifier/system.md`, `classifier/user_template.md`
4. **Pre-filter** — 快速路径逻辑
5. **Runner 集成** — `EventClassifierRunner` 使用 Agent
6. **测试** — 工具单元测试 + Agent MockLLM 测试

### Phase 3: Vuln Analyzer Agent

1. **VulnAnalyzerAgent** — `vuln_analyzer.py`
2. **额外工具** — `search_code`, `list_tags`, `fetch_commit_at_ref`
3. **Prompt** + 上下文压缩
4. **Runner 集成**
5. **测试**

### Phase 4: Reachability + PoC

1. **分析工具** — `analysis_tools.py`（Neo4j 查询）
2. **ReachabilityAgent** — `reachability.py`
3. **PoC 工具** — `poc_tools.py`（沙箱执行）
4. **PocGeneratorAgent** — `poc_generator.py`
5. **Runner 集成**
6. **测试**

### Phase 5: Report + 优化

1. **ReportAgent** — `report.py`
2. **模型升级链** — L1 → L2 → L3 自动升级
3. **Dashboard 指标** — `stats_service` 扩展
4. **端到端测试**
