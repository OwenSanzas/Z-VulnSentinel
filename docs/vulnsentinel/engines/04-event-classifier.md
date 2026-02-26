# Event Classifier

> 对未分类的 Event 进行 LLM 语义分析，判断其是否为安全修复。对应十步流程中的**步骤 6（LLM 分类）**。

## 概述

Event Classifier 是流水线中紧跟 Event Collector 的第三个 Engine。Collector 解决了"发生了什么"，Classifier 解决"这是不是安全修复"。

**职责：**

- 从 `events` 表中拉取 `classification IS NULL` 的事件
- 先过规则引擎（pre-filter），能确定的直接写入
- 不确定的启动 LLM Agent（tool-use loop）语义分析 diff，输出分类标签和置信度
- 将结果写入 `events.classification` / `events.confidence` / `events.is_bugfix`

**特点：**

- Agent 模式 — 不是简单的 prompt→response，而是 tool-use loop，LLM 自主决定需要哪些上下文
- 成本可控 — 三层防线：pre-filter 跳过无关事件、token budget 限制、DeepSeek 降本
- 幂等 — 重复分类同一事件产生相同结果

---

## 双模式设计

### 独立模式（Standalone）

纯函数式，不依赖数据库。

```python
# vulnsentinel/engines/event_classifier/classifier.py

@dataclass
class EventInput:
    type: str           # "commit" | "pr_merge" | "tag" | "issue"
    ref: str
    title: str
    message: str | None = None
    author: str | None = None
    related_issue_ref: str | None = None
    related_pr_ref: str | None = None
    related_commit_sha: str | None = None

async def classify(
    client: GitHubClient, owner: str, repo: str, event: EventInput
) -> ClassificationResult:
    """独立模式核心函数。不涉及 DB。"""
```

流程：
1. 调用 `pre_filter(event)` — 命中则直接返回
2. 未命中 → 创建 `EventClassifierAgent` → `agent.run(event=event)` → 解析结果

用途：
- 单元测试、集成测试
- CLI 调试
- Prompt 调优

### 集成模式（Integrated）

通过 Service 层读写数据库，由调度器触发。

```python
# vulnsentinel/engines/event_classifier/runner.py

class EventClassifierRunner:
    async def classify_one(self, session: AsyncSession, event: Event) -> ClassificationResult
    async def classify_batch(self, session_factory, limit=10, concurrency=3) -> list[...]
```

`classify_batch` 接收 `session_factory`（不是 session），每个并发协程独立创建 session，避免 SQLAlchemy 并发访问问题。

---

## Agent 架构

### 为什么用 Agent 而不是单次 prompt

1. **diff 可能很大** — 一个 commit 可能改几十个文件
2. **不是所有事件都需要 diff** — tag 事件、明显的 refactor 不需要看代码
3. **需要额外上下文** — 有时需要看关联 issue body 或 PR description

Agent 让 LLM **自己决定需要什么信息**：先看 title/message，觉得可疑再调工具拉 diff。

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
         tool_use             no tool calls                │
              │                     │                      │
              ▼                     ▼                      │
     ┌────────────────┐   ┌──────────────────┐            │
     │  执行 MCP 工具   │   │  提取 JSON 输出   │            │
     │  via call_tool() │   │  → ClassResult   │            │
     └────────┬───────┘   └──────────────────┘            │
              │                                            │
              └────────────────────────────────────────────┘

最大循环次数: 5（防止无限 loop）
Early stop: LLM 输出中检测到 JSON → 立即结束
```

### EventClassifierAgent 配置

```python
class EventClassifierAgent(BaseAgent):
    agent_type = "event_classifier"
    max_turns = 5
    temperature = 0.2
    model = "deepseek/deepseek-chat"
    enable_compression = False   # 5 轮不需要压缩
```

---

## 工具设计

5 个 GitHub 只读 MCP 工具，通过 `create_github_mcp(client, owner, repo)` 工厂函数创建。

| 工具 | 参数 | 返回 |
|------|------|------|
| `fetch_commit_diff` | `sha`, `file_path=""` | diffstat 或单文件 patch |
| `fetch_pr_diff` | `pr_number`, `file_path=""` | diffstat 或单文件 patch |
| `fetch_file_content` | `path`, `ref="HEAD"` | 文件内容（base64 decode） |
| `fetch_issue_body` | `issue_number` | title + body + labels |
| `fetch_pr_body` | `pr_number` | title + body + labels |

### Diffstat-First 策略

1. 不传 `file_path` → 返回 diffstat（文件列表 + 增删行数），~200 tokens
2. LLM 选择感兴趣的文件 → 再次调用并传 `file_path` → 返回单文件完整 patch
3. 超长 patch → 截断到 15,000 chars

owner/repo 通过闭包绑定，LLM 只需控制 sha / pr_number / file_path。

### DeepSeek 兼容

- 参数用 `str = ""` 而非 `str | None`（DeepSeek 不支持 `anyOf`）
- `_strip_titles()` 递归剥离 JSON Schema 中的 `title` 字段

---

## 分类管线

### Pre-filter（规则引擎）

```
vulnsentinel/agent/pre_filter.py
```

在调用 LLM 之前，用规则快速过滤：

| 优先级 | 规则 | 分类 | 置信度 |
|--------|------|------|--------|
| 1 | `type == "tag"` | `other` | 0.95 |
| 2 | Bot 作者 (dependabot, renovate, snyk-bot, ...) | `other` | 0.90 |
| 3 | **安全关键词检测** — title 或 message 含安全词 | → **跳过，交给 LLM** | — |
| 4 | Conventional commit prefix (`fix:`, `feat:`, `refactor:`, `docs:`, ...) | 对应分类 | 0.70-0.85 |

**关键设计**：
- Pre-filter **永远不返回 `security_bugfix`**，避免误判跳过 LLM
- 安全关键词检查在 conventional commit 之前执行，确保 `fix: heap buffer overflow` 不会被误分为 `normal_bugfix`

安全关键词列表（正则匹配）：
- CVE-ID / CWE-ID
- vulnerability, exploit, security
- buffer overflow, heap overflow, stack overflow
- use-after-free, double free
- out-of-bounds, integer overflow/underflow
- null pointer dereference, uninitialized memory
- race condition, TOCTOU
- injection, XSS, CSRF, SSRF
- auth bypass, privilege escalation
- information leak, denial of service
- memory corruption, memory safety

### Agent 分类

对通过 pre-filter 的事件启动 EventClassifierAgent。LLM 输出 JSON：

```json
{"label": "security_bugfix", "confidence": 0.95, "reasoning": "Fixes heap overflow in parse_url"}
```

### 分类标签

LLM 可输出扩展 label，`parse_result()` 映射到 DB 的 5 个枚举值：

| LLM 输出 | → DB 枚举值 |
|----------|------------|
| `security_bugfix`, `security` | `security_bugfix` |
| `normal_bugfix`, `bugfix`, `bug_fix`, `bug` | `normal_bugfix` |
| `feature` | `feature` |
| `refactor`, `refactoring` | `refactor` |
| `documentation`, `test`, `ci`, `chore`, `build`, `performance`, `style`, `other` | `other` |

**只有 `security_bugfix` 会触发下游 VulnAnalyzer。**

### ClassificationResult

```python
@dataclass
class ClassificationResult:
    classification: str   # DB 枚举值 (5 种)
    confidence: float     # 0.0 ~ 1.0
    reasoning: str        # LLM 推理说明
```

---

## 成本控制

### 三层防线

| 层 | 机制 | 效果 |
|----|------|------|
| Pre-filter | 规则引擎零 LLM 调用 | ~40% 事件免费 |
| Token budget | diffstat-first + 截断 + max 5 轮 | 每事件 ≤ 16K tokens |
| 模型选择 | DeepSeek 为默认 | ~$0.001/事件 |

### 并发控制

`classify_batch(concurrency=3)` — Semaphore 限制同时分类数。每个协程独立 session。

---

## Error Handling

### LLM 调用失败

由 LiteLLM 处理重试（429, 500, 502, 503）。API key 无效不重试。

### 工具执行失败

工具失败**不中断 Agent loop**。错误信息作为 tool_result 返回给 LLM，LLM 可：
- 基于已有信息继续判断
- 尝试其他工具

例如：commit SHA 无效 → GitHub 返回 422 → LLM 收到错误 → 根据 title/message 直接判断。

### 事件级隔离

每个事件分类独立。单个事件失败不影响其他事件。失败事件保持 `classification IS NULL`，下次轮询重试。

---

## 代码结构

```
vulnsentinel/
├── agent/
│   ├── pre_filter.py               # 规则引擎 + 安全关键词检测
│   ├── agents/classifier.py        # EventClassifierAgent + ClassificationResult + _LABEL_MAP
│   ├── prompts/classifier.py       # CLASSIFIER_SYSTEM_PROMPT + format_event_message
│   └── tools/github_tools.py       # 5 个 GitHub 只读 MCP 工具
│
├── engines/event_classifier/
│   ├── classifier.py               # classify() 纯函数 + EventInput
│   └── runner.py                   # EventClassifierRunner (classify_one + classify_batch)
│
└── ...

tests/vulnsentinel/
└── test_event_classifier.py        # 55 tests (pre-filter, tools, parse, agent config, ...)
```

---

## 已有基础设施

Event Classifier 依赖的 DAO/Service 全部已实现：

| 层 | 方法 | 状态 |
|----|------|------|
| DAO | `EventDAO.list_unclassified(session, limit)` | 已实现，走 `idx_events_unclassified` 索引 |
| DAO | `EventDAO.update_classification(session, pk, ...)` | 已实现 |
| Service | `EventService.list_unclassified(session, limit)` | 已实现 |
| Service | `EventService.update_classification(session, event_id, ...)` | 已实现，自动推导 `is_bugfix = (classification == "security_bugfix")` |

---

## E2E 验证结果

使用真实 DeepSeek API + GitHub API 测试 4 个事件：

| 事件 | 路径 | 分类结果 | 置信度 |
|------|------|---------|--------|
| tag: curl 8.12.0 | pre-filter | `other` | 0.95 |
| dependabot bump | pre-filter | `other` | 0.90 |
| vtls: OCSP stapling bypass | LLM (2 turns) | `security_bugfix` | 0.98 |
| curl: add --ip-tos option | LLM (3 turns) | `feature` | 0.95 |

DeepSeek tool calling 正常工作。LLM 正确调用 `fetch_commit_diff` 获取 diff 后做出判断。
