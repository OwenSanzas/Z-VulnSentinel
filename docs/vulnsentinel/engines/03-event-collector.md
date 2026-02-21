# Event Collector

> 对已注册的 Library 通过 GitHub API 拉取 commit / PR / tag / issue 事件。对应十步流程中的**步骤 4-5（依赖监控 + 事件捕获）**。

## 概述

Event Collector 是流水线中紧跟 Dependency Scanner 的第二个 Engine。Dependency Scanner 解决了"我们监控哪些库"，Event Collector 解决"这些库最近发生了什么"。

**职责：**

- 对 `libraries` 表中每个 library，通过 GitHub API 增量拉取 commit、PR merge、tag、bug issue 四种事件
- 将事件写入 `events` 表，供下游 Event Classifier 做 LLM 语义分类

**特点：**

- 增量拉取 — 利用 `latest_commit_sha`、`latest_tag_version` 等游标，只拉上次采集之后的新事件
- 幂等 — `ON CONFLICT (library_id, type, ref) DO NOTHING`，重复执行不产生副作用
- rate limit 感知 — 自动读取 `X-RateLimit-Remaining`，剩余配额不足时暂停等待

---

## 双模式设计

所有 Engine 统一采用**双模式设计**：独立模式用于测试和调试，集成模式用于生产调度。

### 独立模式（Standalone）

纯函数式，不依赖数据库、不需要 Service 层。

```
输入: owner, repo, since (可选的增量起点)
输出: list[CollectedEvent]
```

用途：
- 单元测试、集成测试
- CLI 调试工具（`python -m vulnsentinel.engines.event_collector curl/curl`）
- 其他系统复用采集逻辑

### 集成模式（Integrated）

通过 DAO 层读写数据库，由 Scheduler 调度。

```
输入: library_id
输出: DB 中新增的 Event 记录 + 更新的 Library pointers
```

用途：
- Scheduler 定时调度
- Dependency Scanner 完成后链式触发

### 模式关系

集成模式内部调用独立模式的采集逻辑，然后额外执行 DB 同步：

```
集成模式(session, library_id):
    library = LibraryDAO.get_by_id(library_id)
    owner, repo = parse_repo_url(library.repo_url)

    # ↓ 独立模式的核心逻辑
    events = collect(owner, repo, since=library.latest_commit_sha, ...)

    # ↓ 集成模式独有：DB 同步
    inserted = EventDAO.batch_create(session, events)
    LibraryDAO.update_pointers(session, library.id, ...)
```

---

## 核心数据结构

### CollectedEvent

独立模式的输出单元，描述从 GitHub API 采集到的一条事件。

```python
@dataclass
class CollectedEvent:
    type: str                      # "commit" | "pr_merge" | "tag" | "bug_issue"
    ref: str                       # 唯一标识：commit SHA / PR number / tag name / issue number
    source_url: str                # GitHub 链接
    author: str | None             # 作者
    title: str                     # commit message 首行 / PR title / tag name / issue title
    message: str | None            # 完整 body
    related_issue_ref: str | None  # 从 commit message 提取的 issue 引用
    related_issue_url: str | None  # issue 链接
    related_pr_ref: str | None     # 从 commit message 提取的 PR 引用
    related_pr_url: str | None     # PR 链接
    related_commit_sha: str | None # PR merge commit SHA / tag 对应的 commit
    event_at: datetime | None      # 事件实际发生时间（commit date / merged_at / tag created / issue created_at）
```

### CollectResult

集成模式的汇总输出。

```python
@dataclass
class CollectResult:
    library_id: UUID
    fetched: int           # API 返回的事件总数
    inserted: int          # 实际入库数（去重后）
    by_type: dict[str, int]  # 按类型统计 {"commit": 12, "pr_merge": 3, ...}
    errors: list[str]      # 采集过程中的非致命错误
```

### 字段映射

GitHub API response → `CollectedEvent` → `Event` model 的字段映射：

| Event model 字段 | CollectedEvent 字段 | 来源 |
|------------------|-------------------|------|
| `library_id` | （集成模式注入） | 调用方传入 |
| `type` | `type` | 采集器固定值 |
| `ref` | `ref` | commit SHA / `str(pr_number)` / tag name / `str(issue_number)` |
| `source_url` | `source_url` | API response 中的 `html_url` |
| `author` | `author` | `commit.author.login` / `user.login` |
| `title` | `title` | commit message 首行 / PR title / tag name / issue title |
| `message` | `message` | commit message body / PR body / issue body |
| `related_issue_ref` | `related_issue_ref` | commit message 解析 `Fixes #123` |
| `related_issue_url` | `related_issue_url` | 从 ref 构造 URL |
| `related_pr_ref` | `related_pr_ref` | commit message 解析 `(#456)` |
| `related_pr_url` | `related_pr_url` | 从 ref 构造 URL |
| `related_commit_sha` | `related_commit_sha` | PR 的 merge_commit_sha / tag 对应的 commit |
| `event_at` | `event_at` | commit: `commit.author.date`；PR: `merged_at`；tag: tag 创建时间；issue: `created_at` |
| `classification` | — | 初始为 NULL，由 Event Classifier 填充 |
| `confidence` | — | 初始为 NULL，由 Event Classifier 填充 |
| `is_bugfix` | — | 初始为 false，由 Event Classifier 填充 |

---

## GitHub API 策略

四种事件类型的端点、增量游标、过滤逻辑：

### commit

```
GET /repos/{owner}/{repo}/commits?sha={branch}&since={since_iso}
```

| 项 | 说明 |
|-----|------|
| 增量游标 | `library.latest_commit_sha` — 上次采集的最新 commit SHA |
| 增量逻辑 | 传 `since` 参数（ISO 8601），API 返回该时间之后的 commit；首次采集时 `since` 不传，取最近 N 条 |
| ref 值 | commit SHA（40 字符） |
| title | commit message 首行 |
| message | commit message 完整内容 |
| 过滤 | 排除 merge commit（`parents.length > 1`） |
| 游标更新 | 采集完成后，取返回结果中最新的 SHA 更新 `library.latest_commit_sha` |

### pr_merge

```
GET /repos/{owner}/{repo}/pulls?state=closed&sort=updated&direction=desc
```

| 项 | 说明 |
|-----|------|
| 增量游标 | 无专用游标，使用 `since` 时间戳过滤 |
| 增量逻辑 | 遍历返回结果，只取 `merged_at is not None` 且 `merged_at > since` 的 PR |
| ref 值 | PR number（字符串形式，如 `"1234"`） |
| title | PR title |
| message | PR body |
| related_commit_sha | `merge_commit_sha` |
| 停止条件 | 遇到 `updated_at < since` 时停止翻页 |

### tag

```
GET /repos/{owner}/{repo}/tags
```

| 项 | 说明 |
|-----|------|
| 增量游标 | `library.latest_tag_version` — 上次采集的最新 tag name |
| 增量逻辑 | 遍历 tag 列表直到遇到 `latest_tag_version`，之前的都是新 tag |
| ref 值 | tag name（如 `"v8.5.0"`） |
| title | tag name |
| message | 无（tag API 不返回 annotation，轻量 tag 无 body） |
| related_commit_sha | tag 指向的 commit SHA |
| 游标更新 | 取返回结果中第一个 tag name 更新 `library.latest_tag_version` |
| 注意 | GitHub tags API 按创建时间倒序，无 `since` 参数 |

### bug_issue

```
GET /repos/{owner}/{repo}/issues?labels=bug&state=all&since={since_iso}&sort=updated&direction=desc
```

| 项 | 说明 |
|-----|------|
| 增量游标 | 使用 `since` 时间戳（与 commit 共享 `last_activity_at`） |
| 增量逻辑 | `since` 参数过滤 `updated_at > since` 的 issue |
| ref 值 | issue number（字符串形式，如 `"5678"`） |
| title | issue title |
| message | issue body |
| 过滤 | 排除 pull request（GitHub Issues API 会返回 PR，通过 `pull_request` 字段判断） |
| 注意 | 只采集带 `bug` label 的 issue，减少噪声 |

### 首次采集策略

library 首次被监控时（`latest_commit_sha = NULL`），游标为空。为避免拉取过多历史数据：

- commit: `since=now-30d, per_page=100, max_pages=1`，即最近 30 天内最多 100 条
- pr_merge: `since=now-30d`
- tag: `per_page=20, max_pages=1`，只取最近 20 个 tag
- bug_issue: `since=now-30d`

---

## 相关引用解析

从 commit message 中提取 issue / PR 引用，填充 `related_issue_ref` 和 `related_pr_ref` 字段。

### 提取规则

```python
# Fixes/Closes/Resolves + issue number → related_issue_ref
ISSUE_FIX_PATTERN = re.compile(
    r'(?:fix(?:es|ed)?|close[sd]?|resolve[sd]?)\s+#(\d+)',
    re.IGNORECASE,
)

# PR reference in commit message: (#123) → related_pr_ref
PR_REF_PATTERN = re.compile(r'\(#(\d+)\)')
```

### 示例

| commit message | related_issue_ref | related_pr_ref |
|---------------|-------------------|----------------|
| `"Fix buffer overflow in parse_header\n\nFixes #1234"` | `"1234"` | — |
| `"Improve error handling (#567)"` | — | `"567"` |
| `"Fix crash on invalid input\n\nCloses #89, fixes #90"` | `"89"` （取第一个） | — |

### URL 构造

提取到引用后，构造完整 URL：

```python
related_issue_url = f"https://github.com/{owner}/{repo}/issues/{ref}"
related_pr_url = f"https://github.com/{owner}/{repo}/pull/{ref}"
```

---

## GitHub Client 设计

封装 GitHub API 调用的通用逻辑，所有事件类型共用。

### 核心职责

```python
class GitHubClient:
    """GitHub REST API v3 客户端。"""

    def __init__(self, token: str | None = None):
        self._client = httpx.AsyncClient(
            base_url="https://api.github.com",
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
            timeout=30.0,
        )

    async def get_paginated(self, path: str, params: dict, max_pages: int = 10) -> AsyncIterator[dict]:
        """自动处理分页的 GET 请求。"""
        ...

    async def close(self) -> None:
        await self._client.aclose()
```

### Token 认证

```
优先级:
1. 构造函数传入的 token
2. 环境变量 GITHUB_TOKEN
3. 匿名访问（rate limit 60 req/hr）
```

### Rate Limit 处理

每次 API 响应后检查 rate limit header：

```python
async def _check_rate_limit(self, response: httpx.Response) -> None:
    remaining = int(response.headers.get("X-RateLimit-Remaining", 1))
    if remaining <= 0:
        reset_at = int(response.headers.get("X-RateLimit-Reset", 0))
        wait_seconds = max(reset_at - time.time(), 0) + 1
        logger.warning("GitHub rate limit hit, waiting %.0fs", wait_seconds)
        await asyncio.sleep(wait_seconds)
```

**策略：**

- `X-RateLimit-Remaining > 100` → 正常继续
- `X-RateLimit-Remaining <= 100` → 降低并发，逐个 library 处理
- `X-RateLimit-Remaining == 0` → sleep 至 `X-RateLimit-Reset` 时间

### 自动分页

GitHub API 分页通过 `Link` header 的 `rel="next"` 实现：

```python
async def get_paginated(self, path, params, *, max_pages=10):
    url = path
    for _ in range(max_pages):
        resp = await self._client.get(url, params=params)
        resp.raise_for_status()
        await self._check_rate_limit(resp)

        data = resp.json()
        if not data:
            break
        for item in data:
            yield item

        # 翻页
        next_url = self._parse_next_link(resp.headers.get("Link", ""))
        if not next_url:
            break
        url = next_url
        params = {}  # 后续页 URL 已包含参数
```

### repo_url 解析

```python
def parse_repo_url(repo_url: str) -> tuple[str, str]:
    """从 repo_url 提取 (owner, repo)。

    支持格式:
    - https://github.com/curl/curl
    - https://github.com/curl/curl.git
    - git@github.com:curl/curl.git
    """
    ...
```

---

## 集成模式完整流程

单个 library 的完整采集流程：

### Step 1: 获取 Library 信息

```
library = LibraryDAO.get_by_id(session, library_id)
  → None → 跳过（library 已删除）
  → platform != "github" → 跳过（v1 只支持 GitHub）
```

从 library 中取：`repo_url`、`default_branch`、`latest_commit_sha`、`latest_tag_version`、`last_activity_at`。

### Step 2: 解析 repo 信息

```
owner, repo = parse_repo_url(library.repo_url)
branch = library.default_branch
since = library.last_activity_at  # 增量起点
```

### Step 3: 采集四种事件

并发采集四种事件类型，每种返回 `list[CollectedEvent]`：

```python
commits, prs, tags, issues = await asyncio.gather(
    collect_commits(client, owner, repo, branch, since=since, last_sha=library.latest_commit_sha),
    collect_prs(client, owner, repo, since=since),
    collect_tags(client, owner, repo, latest_tag=library.latest_tag_version),
    collect_issues(client, owner, repo, since=since),
)
all_events = commits + prs + tags + issues
```

### Step 4: 解析相关引用

对每个 commit 类型的事件，从 message 中提取 issue / PR 引用：

```python
for event in all_events:
    if event.type == "commit":
        parse_refs(event, owner, repo)
```

### Step 5: 批量写入 Event 表

```python
rows = [
    {
        "library_id": library.id,
        "type": e.type,
        "ref": e.ref,
        "source_url": e.source_url,
        "author": e.author,
        "title": e.title,
        "message": e.message,
        "related_issue_ref": e.related_issue_ref,
        "related_issue_url": e.related_issue_url,
        "related_pr_ref": e.related_pr_ref,
        "related_pr_url": e.related_pr_url,
        "related_commit_sha": e.related_commit_sha,
        "event_at": e.event_at,
    }
    for e in all_events
]
inserted = await EventDAO.batch_create(session, rows)
```

`ON CONFLICT (library_id, type, ref) DO NOTHING` 保证幂等。

### Step 6: 更新 Library pointers

```python
await LibraryDAO.update_pointers(
    session,
    library.id,
    latest_commit_sha=new_latest_sha,       # commits 中最新的 SHA
    latest_tag_version=new_latest_tag,       # tags 中最新的 tag name
    last_activity_at=utcnow(),              # 本次采集时间
)
```

`update_pointers` 使用 `COALESCE` 跳过 `None` 值，只更新有变化的字段。

### Step 7: 返回结果

```python
return CollectResult(
    library_id=library.id,
    fetched=len(all_events),
    inserted=inserted,
    by_type=Counter(e.type for e in all_events),
    errors=errors,
)
```

### 完整伪代码

```python
async def collect(
    client: GitHubClient,
    owner: str,
    repo: str,
    *,
    branch: str = "main",
    since: datetime | None = None,
    last_sha: str | None = None,
    latest_tag: str | None = None,
) -> list[CollectedEvent]:
    """独立模式：纯 GitHub API 采集，不涉及数据库。"""
    commits, prs, tags, issues = await asyncio.gather(
        collect_commits(client, owner, repo, branch, since=since, last_sha=last_sha),
        collect_prs(client, owner, repo, since=since),
        collect_tags(client, owner, repo, latest_tag=latest_tag),
        collect_issues(client, owner, repo, since=since),
    )
    all_events = commits + prs + tags + issues
    for event in all_events:
        if event.type == "commit":
            parse_refs(event, owner, repo)
    return all_events


class EventCollector:
    """集成模式：读 DB → 采集 → 写 DB。

    GitHubClient 在 __init__ 中创建，所有 library 共享同一个 httpx 连接池。
    使用方通过 async with 或手动调用 close() 管理生命周期。
    """

    def __init__(self, token: str | None = None):
        self._library_dao = LibraryDAO()
        self._event_dao = EventDAO()
        self._client = GitHubClient(token=token or os.environ.get("GITHUB_TOKEN"))

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self): return self
    async def __aexit__(self, *exc): await self.close()

    async def run(self, session: AsyncSession, library_id: UUID) -> CollectResult:
        # Step 1
        library = await self._library_dao.get_by_id(session, library_id)
        if not library or library.platform != "github":
            return CollectResult.skipped(library_id)

        # Step 2
        owner, repo = parse_repo_url(library.repo_url)

        # Step 3 + 4 (独立模式核心逻辑)
        events = await collect(
            self._client, owner, repo,
            branch=library.default_branch,
            since=library.last_activity_at,
            last_sha=library.latest_commit_sha,
            latest_tag=library.latest_tag_version,
        )

        # Step 5: 批量写入
        rows = [self._to_row(library.id, e) for e in events]
        inserted = await self._event_dao.batch_create(session, rows)

        # Step 6: 更新游标
        new_sha = next((e.ref for e in events if e.type == "commit"), None)
        new_tag = next((e.ref for e in events if e.type == "tag"), None)
        await self._library_dao.update_pointers(
            session, library.id,
            latest_commit_sha=new_sha,
            latest_tag_version=new_tag,
            last_activity_at=utcnow(),
        )

        # Step 7
        return CollectResult(
            library_id=library.id,
            fetched=len(events),
            inserted=inserted,
            by_type=Counter(e.type for e in events),
            errors=[],
        )

    # run_all() 见 §调度与性能 — 并发控制
```

---

## 调度与性能

### Rate Limit 预算

| 模式 | rate limit | 估算 |
|------|-----------|------|
| 有 token | 5000 req/hr | 每 library ~4 req（4 种事件），~1250 library/hr |
| 无 token | 60 req/hr | 每 library ~4 req，~15 library/hr |

> 对于中小规模部署（< 500 library），有 token 的情况下一轮完整采集约 24 分钟。轮询周期 75 分钟，略长于 rate limit 重置周期（1 小时），确保每轮开始时额度已完全恢复。

### 并发控制

```python
# per-library 并发控制
CONCURRENCY = 5  # 同时采集的 library 数

async def run_all(self, session_factory: async_sessionmaker) -> list[CollectResult]:
    # 用一个 session 读 library 列表
    async with session_factory() as session:
        libraries = await self._library_dao.get_all_monitored(session)

    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def guarded(lib):
        async with semaphore:
            # 每个 library 独立 session + 独立事务
            async with session_factory() as session:
                return await self.run(session, lib.id)

    return await asyncio.gather(
        *(guarded(lib) for lib in libraries),
        return_exceptions=True,
    )
```

每个 library 使用独立的 `AsyncSession`，单个 library 失败不会污染其他 library 的事务状态。

### 触发条件

| 触发时机 | 条件 | 说明 |
|---------|------|------|
| 定时轮询 | 每 75 分钟 | 基于 `last_activity_at` |
| 链式触发 | Dependency Scanner 完成后 | 新发现的 library 立即采集一次 |

### Scheduler 查询

```sql
-- LibraryDAO.list_due_for_collect()
SELECT * FROM libraries
WHERE platform = 'github'
  AND (last_activity_at IS NULL OR last_activity_at < now() - interval '75 minutes');
```

---

## 错误处理

### 单 library 隔离

每个 library 的采集是独立的。单个 library 采集失败不影响其他 library。失败信息记录在 `CollectResult.errors` 中。

### HTTP 错误分类

| 状态码 | 处理方式 |
|--------|---------|
| 200 | 正常处理 |
| 304 Not Modified | 无新数据，跳过（配合 `If-None-Match` / `If-Modified-Since`） |
| 401 Unauthorized | token 无效，记录错误，不重试 |
| 403 Forbidden | rate limit 或 repo 无权限；rate limit → sleep & retry，无权限 → 记录错误 |
| 404 Not Found | repo 不存在或已删除，记录错误 |
| 422 Unprocessable | 参数错误，记录错误 |
| 5xx | 服务端错误，指数退避重试（最多 3 次） |
| 超时 | 30s 超时，重试 1 次 |

### 重试策略

```python
MAX_RETRIES = 3
BACKOFF_BASE = 2  # 指数退避基数（秒）

async def _request_with_retry(self, method, url, **kwargs):
    for attempt in range(MAX_RETRIES):
        try:
            resp = await self._client.request(method, url, **kwargs)
            if resp.status_code < 500:
                return resp
            # 5xx → retry
        except httpx.TimeoutException:
            if attempt == MAX_RETRIES - 1:
                raise
        await asyncio.sleep(BACKOFF_BASE ** attempt)
```

---

## 已有基础设施

Event Collector 依赖的 DAO/Model 已全部实现，无需新增 schema 或 DAO 方法：

| 层 | 类 | 方法 | 状态 |
|----|-----|------|------|
| Model | `Event` | — | 已实现，含 `(library_id, type, ref)` UNIQUE 约束 |
| DAO | `EventDAO` | `batch_create(session, events) → int` | 已实现，`ON CONFLICT DO NOTHING` |
| Model | `Library` | — | 已实现，含 `latest_commit_sha`、`latest_tag_version`、`last_activity_at` |
| DAO | `LibraryDAO` | `get_all_monitored(session) → list[Library]` | 已实现 |
| DAO | `LibraryDAO` | `update_pointers(session, pk, ...)` | 已实现，COALESCE 跳过 None |

### 待实现的缺口

| 层 | 类 | 变更 | 说明 |
|----|-----|------|------|
| Model | `Event` | 新增 `event_at: DateTime(timezone=True)` 列 | 事件实际发生时间（区别于 `created_at` 入库时间）。commit date / merged_at / issue created_at |
| DAO | `LibraryDAO` | 新增 `list_due_for_collect(session) → list[Library]` | 查询需要采集的 library（platform=github + last_activity_at 过期） |

---

## 代码结构预览

```
vulnsentinel/engines/event_collector/
├── __init__.py
├── collector.py       # collect() 独立函数 + EventCollector 集成类
├── models.py          # CollectedEvent, CollectResult dataclass
├── github_client.py   # GitHubClient (httpx 封装、rate limit、分页)
└── ref_parser.py      # commit message → issue/PR 引用提取
```

---

## 设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| HTTP 客户端 | httpx | 项目已用 httpx（FastAPI 生态），保持一致 |
| 独立入口 | `collect()` 函数 | 与 `dependency_scanner.scan()` 模式一致 |
| Token 来源 | `GITHUB_TOKEN` 环境变量 | 简单直接，不引入额外配置系统 |
| 事件获取方式 | 轮询 | v1 只做轮询；webhook 需要公网 endpoint + 注册流程，是后续优化 |
| 四类事件并发采集 | `asyncio.gather` | 同一 library 的 4 种事件互不依赖，并发加速 |

---

## 与架构总览的对应关系

| 架构总览中的描述 | 本文档对应 |
|----------------|-----------|
| 步骤 4：依赖监控 | §概述 — 对 libraries 表的 library 建立持续监控 |
| 步骤 5：事件捕获 | §GitHub API 策略 — 四种事件类型的端点和过滤 |
| Event Collector 触发时机 | §调度与性能 |
| `EventService.batch_create()` | §集成模式完整流程 Step 5 |
| `LibraryDAO.get_all_monitored()` + `update_pointers()` | §集成模式完整流程 Step 1, 6 |
| 每 N 分钟 per library，rate limit 感知 | §调度与性能 — Rate Limit 预算 |
| 幂等性（ON CONFLICT DO NOTHING） | §概述 + §集成模式完整流程 Step 5 |

---

## 端到端示例

以一个具体场景说明 Event Collector 在流水线中的位置和职责边界。

### 前置：Project 注册 → Dependency Scanner

```
1. 用户注册 Project "my-app"，repo 里的 requirements.txt 包含:
     curl >= 7.0
     libpng == 1.6.37

2. Dependency Scanner 扫描 manifest，写入:
     libraries:            curl (repo_url=github.com/curl/curl)
                           libpng (repo_url=github.com/pnggroup/libpng)
     project_dependencies: (my-app, curl, constraint_expr=">=7.0", resolved_version="8.4.0")
                           (my-app, libpng, constraint_expr="==1.6.37", resolved_version="1.6.37")
```

此时 `libraries` 表中有了 curl 和 libpng。Event Collector 的工作从这里开始。

### Event Collector 采集

```
3. T+75min: Collector 定时轮询 curl 仓库
   上次游标: latest_commit_sha=aaa111, latest_tag_version=v8.4.0, last_activity_at=T

   拉到 3 条新事件:
   Event A: commit abc123 "fix heap buffer overflow in parse_url"   event_at=T+20min
   Event B: commit def456 "refactor: rename internal helper"        event_at=T+40min
   Event C: tag    v8.5.0                                           event_at=T+60min

   → batch_create 写入 events 表（3 行）
   → update_pointers(latest_commit_sha=def456, latest_tag_version=v8.5.0, last_activity_at=T+75min)

4. T+150min: Collector 再次轮询 curl 仓库
   上次游标: last_activity_at=T+75min
   → 无新事件 → 跳过，不写入
   → update_pointers(last_activity_at=T+150min)
```

**Collector 到此结束。** 它不知道 my-app 用的是 curl 8.4.0，不知道 Event A 是不是安全修复，不关心任何版本匹配。它只负责把事件存下来。

### 下游消费（Collector 不参与）

```
4. Event Classifier (Engine #2):
     Event A → LLM 分析 diff → classification=security_bugfix, confidence=0.95
     Event B → classification=refactor
     Event C → classification=other (tag 不需要分类)

5. Vuln Analyzer (Engine #3):
     Event A 是 security_bugfix → 分析漏洞详情:
       类型: heap-buffer-overflow
       影响版本: curl < 8.5.0
       修复版本: 8.5.0

6. Impact Engine (Engine #4):
     curl < 8.5.0 影响谁？
       my-app: resolved_version=8.4.0 → 8.4.0 < 8.5.0 → 受影响 ✓
       （假设还有 other-app: resolved_version=8.5.0 → 不受影响 ✗）

7. 后续: Reachability Analyzer → PoC → Notification
```

### 解耦要点

| 关注点 | 负责引擎 | Collector 是否关心 |
|--------|---------|-------------------|
| 哪些 library 需要监控 | Dependency Scanner | 否 — 只读 `libraries` 表 |
| 事件是否为安全修复 | Event Classifier | 否 — 只存原始事件 |
| 漏洞影响哪些版本 | Vuln Analyzer | 否 |
| 哪些 project 受影响 | Impact Engine | 否 |

**Collector 的设计原则：尽量多采，下游按需过滤。** 采多了最多浪费存储，采少了会漏掉安全事件。
