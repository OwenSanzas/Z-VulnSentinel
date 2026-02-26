# Vuln Analyzer

> 对已确认的 security_bugfix 事件进行 LLM 深度分析，产出结构化漏洞报告。对应十步流程中的**步骤 7（漏洞分析）**。

## 概述

Vuln Analyzer 是流水线中紧跟 Event Classifier 的第四个 Engine。Classifier 解决了"这是不是安全修复"，Analyzer 解决"这个安全修复到底修了什么漏洞"。

**职责：**

- 从 `events` 表中拉取 `is_bugfix = TRUE` 且无对应 `upstream_vulns` 记录的事件
- 启动 LLM Agent（多轮 tool-use loop）深度分析漏洞细节
- 将结构化分析结果写入 `upstream_vulns` 表

**特点：**

- Agent 模式 — 多轮 tool-use，LLM 自主决定需要什么上下文（diff、issue、PR body 等）
- 深度分析 — 15 轮上限 + 上下文压缩，比 Classifier 的 5 轮更深入
- 结构化输出 — `vuln_type` / `severity` / `affected_versions` / `summary` / `reasoning` / `upstream_poc`

---

## 双模式设计

### 独立模式（Standalone）

纯函数式，不依赖数据库。

```python
# vulnsentinel/engines/vuln_analyzer/analyzer.py

@dataclass
class AnalyzerInput:
    type: str           # "commit" | "pr_merge" | "issue"
    ref: str            # commit SHA / PR number / issue number
    title: str
    message: str | None = None
    author: str | None = None
    related_issue_ref: str | None = None
    related_pr_ref: str | None = None
    related_commit_sha: str | None = None

async def analyze(
    client: GitHubClient, owner: str, repo: str, event: AnalyzerInput
) -> list[VulnAnalysisResult]:
    """独立模式核心函数。不涉及 DB。一个 event 可产出多个 vuln。"""
```

流程：
1. 创建 `VulnAnalyzerAgent` → `agent.run(event=event)` → 解析结果
2. 无 pre-filter（所有输入都是已确认的 security_bugfix，无需再过滤）

用途：
- 单元测试、集成测试
- CLI 调试
- Prompt 调优

### 集成模式（Integrated）

通过 Service 层读写数据库，由调度器触发。

```python
# vulnsentinel/engines/vuln_analyzer/runner.py

class VulnAnalyzerRunner:
    async def analyze_one(self, session: AsyncSession, event: Event) -> list[VulnAnalysisResult]
    async def analyze_batch(self, session_factory, limit=10, concurrency=3) -> list[...]
```

生命周期（1 event → N vulns）：

```
create(placeholder)  ──→  analyze()  ──→  对每个 vuln:
        │                                    create/reuse → update_analysis → publish
        │
        └──────── set_error(placeholder) ◄────── 分析失败
```

1. `UpstreamVulnService.create(event_id, library_id, commit_sha)` — 创建 placeholder 记录，防止事件被重复拉取
2. Agent 运行 → 返回 `list[VulnAnalysisResult]`（一个或多个漏洞）
3. 第一个结果复用 placeholder，后续结果各创建新的 upstream_vuln 记录
4. 对每个结果：`update_analysis(vuln_id, ...)` → `publish(vuln_id)`
5. 如果分析失败 → `set_error(placeholder_id, error_message)` — placeholder 保留，防止重复拉取

`analyze_batch` 接收 `session_factory`（不是 session），每个并发协程独立创建 session，避免 SQLAlchemy 并发访问问题。

---

## Agent 架构

### 为什么比 Classifier 需要更多轮次

Classifier 只需判断"是否是安全修复"（二分类），而 Analyzer 需要：

1. **读 diff** — 理解漏洞的技术细节
2. **关联 issue** — 获取漏洞描述和影响说明
3. **判断影响版本** — 需要查看 changelog、tag、或代码引入时间
4. **收集 PoC 线索** — 检查 test case、reproducer、exploit
5. **综合推理** — 从多个信息源推断 vuln_type、severity

因此 max_turns 从 5 提升到 15，并启用上下文压缩。

### Tool-Use Loop

```
┌──────────────────────────────────────────────────────────┐
│  System Prompt + Bugfix Event 元数据（title, message, url）│
└───────────────────────────┬──────────────────────────────┘
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
       │  via call_tool() │   │ → VulnAnalysis   │            │
       └────────┬───────┘   │    Result         │            │
                │           └──────────────────┘            │
                └────────────────────────────────────────────┘

最大循环次数: 15（深度分析）
上下文压缩: 每 5 轮 或 token 达到 80% 上限时触发
Early stop: LLM 输出中检测到完整 JSON → 立即结束

注意：Analyzer 输出 JSON array（支持多漏洞），且包含嵌套对象（upstream_poc）。
_extract_json() 优先尝试 [ 解析 array，fallback 到 { 解析单个 object 并包装为 list。
parse_result() 返回 list[VulnAnalysisResult]，空 list 代表解析失败。
```

### VulnAnalyzerAgent 配置

```python
class VulnAnalyzerAgent(BaseAgent):
    agent_type = "vuln_analyzer"
    max_turns = 15
    temperature = 0.2
    model = "deepseek/deepseek-chat"
    enable_compression = True   # 15 轮需要压缩
```

与 Classifier 对比：

| 配置项 | EventClassifierAgent | VulnAnalyzerAgent |
|--------|---------------------|-------------------|
| `max_turns` | 5 | 15 |
| `temperature` | 0.2 | 0.2 |
| `model` | `deepseek/deepseek-chat` | `deepseek/deepseek-chat` |
| `enable_compression` | `False` | `True` |

---

## 工具设计

复用 Classifier 的 5 个 GitHub 只读 MCP 工具，通过 `create_github_mcp(client, owner, repo)` 工厂函数创建。

| 工具 | 参数 | 返回 |
|------|------|------|
| `fetch_commit_diff` | `sha`, `file_path=""` | diffstat 或单文件 patch |
| `fetch_pr_diff` | `pr_number`, `file_path=""` | diffstat 或单文件 patch |
| `fetch_file_content` | `path`, `ref="HEAD"` | 文件内容（base64 decode） |
| `fetch_issue_body` | `issue_number` | title + body + labels |
| `fetch_pr_body` | `pr_number` | title + body + labels |

### Diffstat-First 策略

同 Classifier：

1. 不传 `file_path` → 返回 diffstat（文件列表 + 增删行数），~200 tokens
2. LLM 选择安全相关的文件 → 再次调用并传 `file_path` → 返回单文件完整 patch
3. 超长 patch → 截断到 15,000 chars

Analyzer 预期比 Classifier 更多地使用工具：Classifier 可能 1-2 次工具调用就能判断分类，Analyzer 需要详查多个文件的 diff、查看关联 issue/PR、检查 test case 等。

### 暂不添加 CVE 数据库查询工具

依赖库的安全修复通常在 CVE 披露前就已完成，此时 CVE 数据库中查不到对应记录。未来可作为增强功能添加。

### DeepSeek 兼容

同 Classifier：
- 参数用 `str = ""` 而非 `str | None`（DeepSeek 不支持 `anyOf`）
- `_strip_titles()` 递归剥离 JSON Schema 中的 `title` 字段

---

## 分析管线

### 无 Pre-filter

与 Classifier 不同，Analyzer **没有 pre-filter**。所有输入都是 Classifier 已确认的 `security_bugfix` 事件，每个都需要 LLM 深度分析。

### Agent 输出

LLM 输出 JSON **array** 格式。一个 event 可能包含多个独立的安全修复（维护者常将安全修复混入普通 commit 以避免在 CVE 披露前暴露攻击面），因此 Analyzer 必须能从单个 event 中提取多个漏洞：

```json
[
  {
    "vuln_type": "buffer_overflow",
    "severity": "high",
    "affected_versions": "< 8.12.0",
    "summary": "Heap buffer overflow in parse_url() when handling oversized hostname.",
    "reasoning": "The diff adds a length check before memcpy in lib/url.c:parse_url(). ...",
    "upstream_poc": {
      "has_poc": true,
      "poc_type": "test_case",
      "description": "Added test case test_long_hostname() reproduces the overflow."
    }
  }
]
```

只有一个漏洞时仍使用 array（单元素）。`_extract_json()` 同时支持 array 和单个 object（fallback 包装为 `[dict]`），保证向后兼容。

### VulnAnalysisResult

```python
@dataclass
class VulnAnalysisResult:
    """Structured output from the analyzer agent."""

    vuln_type: str                             # 漏洞类型
    severity: str                              # critical / high / medium / low
    affected_versions: str                     # 版本范围描述
    summary: str                               # 漏洞摘要
    reasoning: str                             # LLM 推理过程
    upstream_poc: dict[str, Any] | None = None # 上游 PoC 信息
```

### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `vuln_type` | `str` | 漏洞类型：`buffer_overflow` / `use_after_free` / `integer_overflow` / `null_deref` / `injection` / `auth_bypass` / `info_leak` / `dos` / `race_condition` / `memory_corruption` / `other`。**DB 列为 `Text`（非 enum）**，有意为之——CWE 体系因语言/平台差异大，LLM 生成不稳定，用 Text 更灵活。代码层通过 `_VULN_TYPE_MAP` 映射保证一致性，未识别的值映射到 `other`。 |
| `severity` | `str` | 严重程度，对齐 DB 枚举 `severity_level`：`critical` / `high` / `medium` / `low`。**DB 列为 enum，写入必须精确匹配**。`parse_result()` 中通过 `_SEVERITY_MAP` 做 `.lower().strip()` + 别名映射（如 `"High"` → `"high"`、`"moderate"` → `"medium"`），防止 DB 报错。 |
| `affected_versions` | `str` | 受影响版本范围，自然语言描述（如 `"< 8.12.0"` 或 `"1.0.0 - 2.3.4"`） |
| `summary` | `str` | 1-3 句漏洞摘要 |
| `reasoning` | `str` | LLM 完整推理过程 |
| `upstream_poc` | `dict \| None` | 可选 JSON，上游是否有 PoC（`has_poc`, `poc_type`: test_case / exploit / reproducer, `description`） |

### 与 DB 字段映射

`VulnAnalysisResult` 的字段直接对应 `upstream_vulns` 表列：

| Result 字段 | DB 列 | DB 类型 |
|-------------|-------|---------|
| `vuln_type` | `vuln_type` | `Text` |
| `severity` | `severity` | `severity_level` enum (`critical`/`high`/`medium`/`low`) |
| `affected_versions` | `affected_versions` | `Text` |
| `summary` | `summary` | `Text` |
| `reasoning` | `reasoning` | `Text` |
| `upstream_poc` | `upstream_poc` | `JSONB` |

---

## System Prompt 设计

```python
# vulnsentinel/agent/prompts/analyzer.py

ANALYZER_SYSTEM_PROMPT = """
You are a vulnerability analysis expert for open-source C/C++ libraries.

# Task
You are given a GitHub event (commit, PR merge, or issue) that has been confirmed
as a security bugfix. Your job is to produce a detailed vulnerability analysis.

# What to determine
1. **vuln_type** — the category of vulnerability being fixed
2. **severity** — how severe the vulnerability is
3. **affected_versions** — what versions are affected
4. **summary** — concise description of the vulnerability
5. **reasoning** — your full analysis chain
6. **upstream_poc** — whether there is a proof-of-concept, test case, or reproducer

# vuln_type values
Choose ONE:
- buffer_overflow — stack or heap buffer overflow/overread
- use_after_free — use-after-free or double-free
- integer_overflow — integer overflow/underflow leading to security impact
- null_deref — NULL pointer dereference
- injection — command injection, SQL injection, header injection, etc.
- auth_bypass — authentication or authorization bypass
- info_leak — information disclosure, uninitialized memory read
- dos — denial of service (infinite loop, excessive resource consumption)
- race_condition — TOCTOU, data race with security impact
- memory_corruption — other memory corruption not covered above
- other — vulnerability type not in above categories

# severity guidelines
- **critical** — remote code execution, no authentication needed
- **high** — RCE requiring specific conditions, or auth bypass, or info leak of
  sensitive data
- **medium** — DoS, limited info leak, requires local access or unusual config
- **low** — theoretical impact, requires very specific conditions, minor info leak

# Tool usage strategy
1. Start by fetching the diff overview (diffstat) to understand scope
2. Drill into security-relevant files (memory management, parsing, auth, crypto)
3. Fetch related issue/PR body for context on impact and affected versions
4. Check test files for PoC / reproducer test cases
5. If a related commit SHA is provided, fetch that diff too

# Output format
After your analysis, output a single JSON object (may span multiple lines, no markdown fences):
{"vuln_type": "<type>", "severity": "<level>", "affected_versions": "<range>",
 "summary": "<1-3 sentences>", "reasoning": "<analysis>",
 "upstream_poc": {"has_poc": <bool>, "poc_type": "<type>", "description": "<desc>"}}

If there is no PoC evidence, set upstream_poc to null.

# Examples

## Example 1 — buffer_overflow / high
Event: commit "fix heap buffer overflow in url parser"
After fetching diff → sees added bounds check in lib/url.c before memcpy.
→ {"vuln_type": "buffer_overflow", "severity": "high",
   "affected_versions": "< 8.12.0",
   "summary": "Heap buffer overflow in parse_url() when hostname exceeds 256 bytes.",
   "reasoning": "The diff adds a length check ... The fix was introduced in 8.12.0 ...",
   "upstream_poc": {"has_poc": true, "poc_type": "test_case",
                    "description": "test_long_hostname() added in tests/url_test.c"}}

## Example 2 — use_after_free / critical
Event: commit "transfer: fix UAF on connection reuse"
After fetching diff → sees nullification of freed pointer + use-after-free pattern.
→ {"vuln_type": "use_after_free", "severity": "critical",
   "affected_versions": "7.50.0 - 8.11.1",
   "summary": "Use-after-free when reusing HTTP/2 connection after auth negotiation.",
   "reasoning": "conn->data freed in Curl_disconnect() but pointer not nulled ...",
   "upstream_poc": null}

## Example 3 — dos / medium
Event: PR merge "Fix infinite loop in chunked encoding parser"
After fetching PR body + diff → sees loop termination condition fix.
→ {"vuln_type": "dos", "severity": "medium",
   "affected_versions": ">= 7.0.0, < 8.10.0",
   "summary": "Infinite loop in chunked transfer encoding parser on malformed input.",
   "reasoning": "Missing break condition when chunk size is 0 but trailer ...",
   "upstream_poc": {"has_poc": true, "poc_type": "reproducer",
                    "description": "Issue #12345 includes sample malformed HTTP response"}}
"""
```

### format_bugfix_message

```python
def format_bugfix_message(event: Event) -> str:
    """Format a bugfix Event into the initial user message for the analyzer."""
    parts = [f"Event type: {event.type}", f"Ref: {event.ref}"]

    if event.title:
        parts.append(f"Title: {event.title}")
    if event.message:
        msg = event.message if len(event.message) <= 2000 else event.message[:2000] + "…"
        parts.append(f"Message:\n{msg}")
    if event.author:
        parts.append(f"Author: {event.author}")

    refs = []
    if event.related_issue_ref:
        refs.append(f"related issue: #{event.related_issue_ref}")
    if event.related_pr_ref:
        refs.append(f"related PR: #{event.related_pr_ref}")
    if event.related_commit_sha:
        refs.append(f"related commit: {event.related_commit_sha}")
    if refs:
        parts.append(f"Cross-references: {', '.join(refs)}")

    parts.append("\nThis event has been confirmed as a security bugfix.")
    parts.append("Analyze the vulnerability in detail.")
    return "\n".join(parts)
```

---

## 成本控制

### 无 Pre-filter

与 Classifier 不同，Analyzer 没有 pre-filter 层。所有输入事件都是已确认的 security_bugfix，每个都需要 LLM 分析。

### Token Budget

| 机制 | 效果 |
|------|------|
| Diffstat-first | 首次 diff 调用 ~200 tokens，只在需要时拉完整 patch |
| Patch 截断 | 单文件 patch 超过 15,000 chars 截断 |
| Max 15 轮 | 防止无限循环 |
| 上下文压缩 | 每 5 轮或 token 达 80% 窗口时，中间消息压缩为摘要 |
| 工具输出截断 | 单个工具输出 > `max_tool_output_tokens * 4` chars 截断 |

### 模型选择

DeepSeek 为默认模型，成本约 $0.005-0.01/事件（比 Classifier 高，因为轮次更多、上下文更大）。

### 并发控制

`analyze_batch(concurrency=3)` — Semaphore 限制同时分析数。每个协程独立 session。

---

## Error Handling

### LLM 调用失败

由 LiteLLM 处理重试（429, 500, 502, 503）。API key 无效不重试。

### 工具执行失败

工具失败**不中断 Agent loop**。错误信息作为 tool_result 返回给 LLM，LLM 可：
- 基于已有信息继续分析
- 尝试其他工具获取上下文

例如：commit SHA 无效 → GitHub 返回 422 → LLM 收到错误 → 尝试通过 PR diff 获取信息。

### 事件级隔离

每个事件分析独立。单个事件失败不影响其他事件。

失败处理：
- Agent 运行抛异常 → `set_error(placeholder_id, error_message)` 记录错误
- JSON 解析失败 → `analyze()` 抛 `AnalysisError`，placeholder 保持 `analyzing` 状态
- 下次轮询时，这些记录不会被重复拉取（`list_bugfix_without_vuln` 查的是无 upstream_vuln 记录的事件，placeholder 已存在）
- 多漏洞场景：分析成功后，第一个 vuln 复用 placeholder，后续 vuln 各创建新记录。所有 vuln 要么全部 publish，要么 placeholder 保留 analyzing 状态

### Error 状态说明

`set_error()` 只写 `error_message`，**不改 status**（保持 `analyzing`）。这是有意的——DB 的 `upstream_vuln_status` enum 只有 `analyzing` / `published` 两个值，没有 `error` 状态。出错的记录通过 `analyzing` + `error_message IS NOT NULL` 区分。

### 重试策略

已 `set_error()` 的记录保持 `analyzing` 状态。是否重试由上层调度器决定（可基于 `error_message` 和重试次数）。

---

## 代码结构

```
vulnsentinel/
├── agent/
│   ├── agents/analyzer.py          # VulnAnalyzerAgent + VulnAnalysisResult
│   └── prompts/analyzer.py         # ANALYZER_SYSTEM_PROMPT + format_bugfix_message
│
├── engines/vuln_analyzer/
│   ├── analyzer.py                 # analyze() 纯函数 + AnalyzerInput
│   └── runner.py                   # VulnAnalyzerRunner (analyze_one + analyze_batch)
│
tests/vulnsentinel/
└── test_vuln_analyzer.py
```

工具层不新增文件，复用 `vulnsentinel/agent/tools/github_tools.py`。

---

## 已有基础设施

Vuln Analyzer 依赖的 DAO/Service 全部已实现：

| 层 | 方法 | 状态 |
|----|------|------|
| DAO | `EventDAO.list_bugfix_without_vuln(session, limit)` | 已实现，`WHERE is_bugfix = TRUE AND NOT EXISTS (...)` |
| DAO | `UpstreamVulnDAO.create(session, event_id, library_id, commit_sha)` | 已实现 |
| DAO | `UpstreamVulnDAO.update_analysis(session, vuln_id, ...)` | 已实现 |
| DAO | `UpstreamVulnDAO.publish(session, vuln_id)` | 已实现 |
| DAO | `UpstreamVulnDAO.set_error(session, vuln_id, error_message)` | 已实现 |
| Service | `EventService.list_bugfix_without_vuln(session, limit)` | 已实现 |
| Service | `UpstreamVulnService.create(session, event_id, library_id, commit_sha)` | 已实现，状态默认 `analyzing` |
| Service | `UpstreamVulnService.update_analysis(session, vuln_id, vuln_type, severity, affected_versions, summary, reasoning, upstream_poc)` | 已实现 |
| Service | `UpstreamVulnService.publish(session, vuln_id)` | 已实现，状态 → `published`，`published_at` → `now()` |
| Service | `UpstreamVulnService.set_error(session, vuln_id, error_message)` | 已实现 |
| Service | `LibraryService.get_by_id(session, library_id)` | 已实现 |
| 工具 | `create_github_mcp(client, owner, repo)` | 已实现，5 个 GitHub 只读 MCP 工具 |
| Agent | `BaseAgent` 抽象基类 | 已实现，tool-use loop + 上下文压缩 |
