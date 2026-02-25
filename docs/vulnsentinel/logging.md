# 日志与可观测性架构

> VulnSentinel 全局日志方案：structlog + Loki + Grafana + MinIO，一套架构覆盖所有模块。

---

## 目录

1. [你会看到什么](#1-你会看到什么)
2. [架构总览](#2-架构总览)
3. [数据流](#3-数据流)
4. [应用层：structlog](#4-应用层structlog)
5. [采集层：Alloy](#5-采集层alloy)
6. [存储层：Loki + MinIO](#6-存储层loki--minio)
7. [查询层：Grafana](#7-查询层grafana)
8. [Agent 专项：PG + Loki 分工](#8-agent-专项pg--loki-分工)
9. [部署：docker-compose](#9-部署docker-compose)
10. [日志规范](#10-日志规范)
11. [保留策略](#11-保留策略)
12. [上云迁移路径](#12-上云迁移路径)

---

## 1. 你会看到什么

### 开发环境（本地终端）

和现在一样，`docker compose logs -f` 看实时日志，人类可读：

```
vulnsentinel  | 2026-02-25T10:30:01Z [info] request.start  method=POST path=/v1/events request_id=req-abc
vulnsentinel  | 2026-02-25T10:30:01Z [info] event.created  event_id=evt-123 library=curl type=commit
vulnsentinel  | 2026-02-25T10:30:02Z [info] agent.turn     agent_type=event_classifier agent_id=ag-456 turn=1 max_turns=5
vulnsentinel  | 2026-02-25T10:30:03Z [info] tool.call      agent_id=ag-456 tool=fetch_commit_diff duration_ms=556
vulnsentinel  | 2026-02-25T10:30:04Z [info] agent.done     agent_id=ag-456 turns=2 tokens=3650 cost=0.0012
vulnsentinel  | 2026-02-25T10:30:04Z [info] request.end    request_id=req-abc status=200 duration_ms=3200
```

开发时用 `VULNSENTINEL_LOG_FORMAT=console`，不需要 Grafana。

### 生产环境（Grafana Web UI）

打开 `http://localhost:3000`，你能做这些事：

**场景 1："昨晚 classifier 出了什么错？"**

```
LogQL: {app="vulnsentinel", module="agent"} | json | agent_type="event_classifier" level="error"
时间范围: Last 12 hours
```

→ 直接看到错误日志 + 堆栈，点开可以看上下文。

**场景 2："这个 event 的 Agent 完整对话是什么？"**

```
LogQL: {app="vulnsentinel", module="agent"} | json | agent_id="ag-456"
```

→ 时间顺序展示该 Agent 的每一轮：LLM 调用、工具调用、工具返回、最终结果。完整 replay。

**场景 3："最近一小时有多少个 API 请求？"**

```
LogQL: rate({app="vulnsentinel", module="api"} | json | event="request.end" [5m])
```

→ Grafana 画出请求速率曲线。

**场景 4："GitHub API 被 rate limit 了吗？"**

```
LogQL: {app="vulnsentinel", module="engine"} | json |= "rate limit"
```

→ 搜出所有 rate limit 相关日志。

**场景 5：Dashboard 全局概览**

一个 Grafana Dashboard 页面上同时展示：
- 日志错误率趋势
- Agent 执行量（按类型分色）
- API 请求延迟 P95
- 工具调用耗时分布

全部从 Loki 数据源聚合，不需要写额外代码。

---

## 2. 架构总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Docker Compose 集群                          │
│                                                                     │
│  ┌──────────────────────────────────────────┐                       │
│  │          vulnsentinel (应用)              │                       │
│  │                                          │                       │
│  │   API Server ──┐                         │                       │
│  │   Engines ─────┤── structlog ──▶ stdout   │                       │
│  │   Agents ──────┘                         │                       │
│  └──────────────────────────┬───────────────┘                       │
│                             │ Docker log driver                     │
│                             ▼                                       │
│  ┌──────────────────────────────────────────┐                       │
│  │          Alloy (日志采集)                  │                       │
│  │                                          │                       │
│  │   读取容器 stdout ──▶ 提取 JSON 字段       │                       │
│  │   打上 label ──▶ 推送到 Loki              │                       │
│  └──────────────────────────┬───────────────┘                       │
│                             │ HTTP push                             │
│                             ▼                                       │
│  ┌──────────────────────────────────────────┐                       │
│  │          Loki (日志存储 + 索引)            │                       │
│  │                                          │                       │
│  │   label 索引 ──▶ 快速过滤                  │                       │
│  │   日志正文 ──▶ 压缩存储                    │                       │
│  │   存储后端 ──▶ MinIO (S3 API)             │                       │
│  └──────────────────────────┬───────────────┘                       │
│                             │                                       │
│                             ▼                                       │
│  ┌──────────────────────────────────────────┐                       │
│  │          MinIO (对象存储)                  │                       │
│  │                                          │                       │
│  │   Bucket: vulnsentinel-logs              │                       │
│  │   存储: 本地磁盘 /data                    │                       │
│  └──────────────────────────────────────────┘                       │
│                                                                     │
│  ┌──────────────────────────────────────────┐                       │
│  │          Grafana (查询 UI)                │                       │
│  │                                          │                       │
│  │   数据源 1: Loki ──▶ 日志查询              │                       │
│  │   数据源 2: PostgreSQL ──▶ 业务指标        │                       │
│  │                                          │                       │
│  │   http://localhost:3000                   │                       │
│  └──────────────────────────────────────────┘                       │
│                                                                     │
│  ┌────────────────┐  ┌────────────────┐                             │
│  │   PostgreSQL   │  │     Neo4j      │                             │
│  │  (业务数据)     │  │   (调用图)     │                             │
│  └────────────────┘  └────────────────┘                             │
└─────────────────────────────────────────────────────────────────────┘
```

### 组件职责

| 组件 | 职责 | 是否已有 |
|------|------|---------|
| **structlog** | 应用内日志格式化，输出 JSON 到 stdout | ✅ 已有 |
| **Alloy** | 从容器 stdout 采集日志，打 label，推给 Loki | 新增 |
| **Loki** | 日志存储 + 索引，提供 LogQL 查询接口 | 新增 |
| **MinIO** | S3 兼容对象存储，Loki 的存储后端 | 新增 |
| **Grafana** | Web UI，查询日志 + 画 Dashboard | 新增 |
| **PostgreSQL** | Agent 业务数据（agent_runs, agent_tool_calls） | ✅ 已有 |

---

## 3. 数据流

```
应用代码
  │
  │  structlog.info("tool.call", tool="fetch_diff", duration_ms=556)
  │
  ▼
stdout (JSON 行)
  │
  │  {"event":"tool.call","tool":"fetch_diff","duration_ms":556,"agent_id":"ag-456",...}
  │
  ▼
Alloy (采集)
  │
  │  提取 label: app=vulnsentinel, module=agent, level=info
  │  正文: 原始 JSON 行
  │
  ▼
Loki (存储)
  │
  │  索引: {app="vulnsentinel", module="agent", level="info"}
  │  正文: 压缩后存入 MinIO
  │
  ▼
MinIO (磁盘)
  │
  │  Bucket: vulnsentinel-logs/
  │  ├── chunks/     ← 压缩的日志块
  │  └── index/      ← label 索引
  │
  ▼
Grafana (查询)

  用户输入 LogQL → Loki 按 label 过滤 → 从 MinIO 读取日志块 → 返回结果
```

---

## 4. 应用层：structlog

### 现有代码不改

VulnSentinel 已有的 `core/logging.py` 和所有 `logging.getLogger(__name__)` 调用**不动**。

唯一变化：生产环境设环境变量 `VULNSENTINEL_LOG_FORMAT=json`，让 structlog 输出 JSON 行。开发环境保持 `console`。

### Agent 日志写法

新写的 Agent 代码统一用 structlog：

```python
import structlog

log = structlog.get_logger("vulnsentinel.agent")

# BaseAgent.run() 中
log = log.bind(agent_type=self.agent_type, agent_id=str(context.id),
               target_id=context.target_id)

log.info("agent.start", model=self.model, max_turns=self.max_turns)
log.info("agent.turn", turn=1, max_turns=5)
log.info("tool.call", tool="fetch_commit_diff", args={"sha": "abc123"})
log.info("tool.result", tool="fetch_commit_diff", chars=1523, duration_ms=556)
log.info("tool.error", tool="run_poc", error="timeout after 30s")
log.info("llm.response", stop_reason="tool_use", input_tokens=1200, output_tokens=300)
log.info("agent.done", turns=2, input_tokens=3200, output_tokens=450, cost=0.0012)

# 对话内容也可以写入日志（用于 Loki 查询 replay）
log.debug("agent.message", role="assistant", content=response.content[:500])
log.debug("agent.message", role="tool", tool_call_id="tc-1", content=result[:500])
```

JSON 输出：

```json
{"event":"tool.call","tool":"fetch_commit_diff","args":{"sha":"abc123"},"agent_type":"event_classifier","agent_id":"ag-456","target_id":"evt-789","timestamp":"2026-02-25T10:30:03Z","level":"info","logger":"vulnsentinel.agent"}
```

### module 命名规范

通过 logger name 区分模块，Alloy 提取为 label：

| Logger name | module label | 覆盖内容 |
|-------------|-------------|---------|
| `vulnsentinel.api` | `api` | API 请求、响应、中间件 |
| `vulnsentinel.agent` | `agent` | Agent 执行、工具调用、LLM 交互 |
| `vulnsentinel.engine` | `engine` | Engine 调度、Runner 执行 |
| `vulnsentinel.db` | `db` | 数据库操作（慢查询等） |
| 其他 | `app` | 兜底 |

---

## 5. 采集层：Alloy

### Alloy 做什么

1. 通过 Docker API 发现容器
2. 读取容器 stdout
3. 解析 JSON，提取 label 字段
4. 批量推送到 Loki

### 配置文件

```
config/alloy/config.alloy
```

关键逻辑：

```hcl
// 发现 Docker 容器
discovery.docker "containers" {
  host = "unix:///var/run/docker.sock"
}

// 只采集带 logging=loki label 的容器
discovery.relabel "filtered" {
  targets = discovery.docker.containers.targets

  rule {
    source_labels = ["__meta_docker_container_label_logging"]
    regex         = "loki"
    action        = "keep"
  }

  // 提取容器名作为 label
  rule {
    source_labels = ["__meta_docker_container_name"]
    target_label  = "container"
  }
}

// 采集日志
loki.source.docker "default" {
  host    = "unix:///var/run/docker.sock"
  targets = discovery.relabel.filtered.output

  forward_to = [loki.process.json.receiver]
}

// 解析 JSON，提取 label
loki.process "json" {
  stage.json {
    expressions = {
      level  = "level",
      module = "logger",
      event  = "event",
    }
  }

  // logger name → module label (取第二段)
  // "vulnsentinel.agent" → "agent"
  stage.regex {
    expression = "vulnsentinel\\.(?P<module>\\w+)"
    source     = "module"
  }

  stage.labels {
    values = {
      level  = "",
      module = "",
    }
  }

  stage.static_labels {
    values = {
      app = "vulnsentinel",
    }
  }

  forward_to = [loki.write.default.receiver]
}

// 推送到 Loki
loki.write "default" {
  endpoint {
    url = "http://loki:3100/loki/api/v1/push"
  }
}
```

### 哪些容器被采集

在 `docker-compose.yml` 中给需要采集的容器加 label：

```yaml
services:
  vulnsentinel:
    labels:
      logging: "loki"    # Alloy 看到这个才采集
```

不加 label 的容器（PostgreSQL、Neo4j 等）不采集。

---

## 6. 存储层：Loki + MinIO

### Loki 配置要点

```yaml
# config/loki/loki.yaml

auth_enabled: false

server:
  http_listen_port: 3100

common:
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory
  replication_factor: 1
  path_prefix: /loki

schema_config:
  configs:
    - from: "2026-01-01"
      store: tsdb
      object_store: s3
      schema: v13
      index:
        prefix: index_
        period: 24h

storage_config:
  tsdb_shipper:
    active_index_directory: /loki/index
    cache_location: /loki/cache
  aws:
    s3: http://minioadmin:minioadmin@minio:9000/vulnsentinel-logs
    s3forcepathstyle: true    # MinIO 必须用 path-style

limits_config:
  retention_period: 90d      # 90 天自动清理

compactor:
  working_directory: /loki/compactor
  retention_enabled: true
  delete_request_store: s3
```

### MinIO 配置

就一个容器，提供 S3 API：

```yaml
minio:
  image: minio/minio
  command: server /data --console-address ":9001"
  environment:
    MINIO_ROOT_USER: minioadmin
    MINIO_ROOT_PASSWORD: minioadmin
  volumes:
    - minio_data:/data
  ports:
    - "9001:9001"    # MinIO Console（Web 管理界面）
```

MinIO Console 在 `http://localhost:9001`，可以看到 bucket 里存了多少数据、磁盘用量等。

### Loki 存了什么

```
MinIO Bucket: vulnsentinel-logs/
├── index/                    ← label 索引（很小，按天分片）
│   ├── index_2026-02-25/
│   └── index_2026-02-26/
├── chunks/                   ← 压缩的日志正文（gzip/snappy）
│   ├── <tenant>/<fingerprint>/...
│   └── ...
└── compactor/                ← 压缩后的旧数据
```

日志正文被 Loki 压缩后存储。原始 1MB JSON 日志约压缩到 100-200KB。

---

## 7. 查询层：Grafana

### 预配置

Grafana 容器启动时自动配好数据源和 Dashboard（通过 provisioning）：

```
config/grafana/
├── provisioning/
│   ├── datasources/
│   │   └── datasources.yaml    # Loki + PostgreSQL 数据源
│   └── dashboards/
│       ├── dashboards.yaml     # Dashboard 加载配置
│       └── vulnsentinel.json   # 预置 Dashboard
└── grafana.ini                 # Grafana 配置（匿名访问等）
```

### 数据源配置

```yaml
# config/grafana/provisioning/datasources/datasources.yaml
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    url: http://loki:3100
    isDefault: true

  - name: PostgreSQL
    type: postgres
    url: postgres:5432
    database: vulnsentinel
    user: vulnsentinel
    secureJsonData:
      password: vulnsentinel
```

### 常用 LogQL 查询

```yaml
# 全部日志
{app="vulnsentinel"}

# 只看 Agent 日志
{app="vulnsentinel", module="agent"}

# 只看错误
{app="vulnsentinel"} | json | level="error"

# 某个 Agent 实例的完整日志（对话 replay）
{app="vulnsentinel", module="agent"} | json | agent_id="ag-456"

# 某个 event 相关的所有日志
{app="vulnsentinel"} | json |= "evt-789"

# 工具调用耗时 > 5 秒
{app="vulnsentinel", module="agent"} | json | event="tool.call" | duration_ms > 5000

# API 5xx 错误
{app="vulnsentinel", module="api"} | json | event="request.end" | status >= 500

# GitHub rate limit
{app="vulnsentinel", module="engine"} |= "rate limit"
```

---

## 8. Agent 专项：PG + Loki 分工

Agent 的数据分两个地方存，各管各的：

```
┌────────────────────────────────────┐  ┌──────────────────────────────┐
│         PostgreSQL                 │  │           Loki               │
│                                    │  │                              │
│  agent_runs                        │  │  structlog 日志流             │
│  ├─ id, agent_type, status         │  │  ├─ agent.start              │
│  ├─ target_type, target_id         │  │  ├─ agent.turn               │
│  ├─ total_turns, tokens, cost      │  │  ├─ tool.call (每次调用)      │
│  ├─ result_summary (JSONB)         │  │  ├─ tool.result              │
│  └─ duration_ms                    │  │  ├─ llm.response             │
│                                    │  │  ├─ agent.message (对话内容)  │
│  agent_tool_calls                  │  │  └─ agent.done               │
│  ├─ run_id, turn, seq              │  │                              │
│  ├─ tool_name, tool_input          │  │  全部带 agent_id label        │
│  ├─ duration_ms, is_error          │  │  → 按 agent_id 查 = 完整回放  │
│  └─ output_chars                   │  │                              │
│                                    │  │                              │
│  用途:                              │  │  用途:                        │
│  · API 查询 (GET /v1/agent-runs)   │  │  · 对话内容 replay            │
│  · SQL 聚合 (成本、成功率)          │  │  · 运行时排障                  │
│  · 前端 Dashboard                  │  │  · 跨模块关联查询              │
│  · JOIN 业务表                     │  │  · 错误堆栈查看                │
└────────────────────────────────────┘  └──────────────────────────────┘
```

**conversation 大字段不存 PG。** Agent 对话内容以 `agent.message` 日志形式写入 Loki，按 `agent_id` label 查询即可还原。PG 只存结构化摘要。

---

## 9. 部署：docker-compose

新增 4 个服务，加上已有的 3 个，完整 compose：

```yaml
services:
  # ── 已有服务 ────────────────────────────

  postgres:
    image: postgres:16
    ports: ["5432:5432"]
    environment:
      POSTGRES_USER: vulnsentinel
      POSTGRES_PASSWORD: vulnsentinel
      POSTGRES_DB: vulnsentinel
    volumes:
      - pg_data:/var/lib/postgresql/data

  neo4j:
    image: neo4j:5-community
    ports: ["7474:7474", "7687:7687"]
    environment:
      NEO4J_AUTH: none
      NEO4J_PLUGINS: '["apoc"]'
    volumes:
      - neo4j_data:/data

  # ── 新增：日志基础设施 ─────────────────

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - minio_data:/data
    ports:
      - "9001:9001"    # MinIO Console

  loki:
    image: grafana/loki:3.4
    command: -config.file=/etc/loki/loki.yaml
    volumes:
      - ./config/loki/loki.yaml:/etc/loki/loki.yaml:ro
      - loki_data:/loki
    ports:
      - "3100:3100"
    depends_on:
      - minio

  alloy:
    image: grafana/alloy:latest
    command: run /etc/alloy/config.alloy
    volumes:
      - ./config/alloy/config.alloy:/etc/alloy/config.alloy:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - loki

  grafana:
    image: grafana/grafana:11.5
    volumes:
      - ./config/grafana/provisioning:/etc/grafana/provisioning:ro
      - grafana_data:/var/lib/grafana
    environment:
      GF_AUTH_ANONYMOUS_ENABLED: "true"
      GF_AUTH_ANONYMOUS_ORG_ROLE: Admin
    ports:
      - "3000:3000"    # Grafana UI
    depends_on:
      - loki
      - postgres

volumes:
  pg_data:
  neo4j_data:
  minio_data:
  loki_data:
  grafana_data:
```

### 启动后访问

| 服务 | 地址 | 用途 |
|------|------|------|
| Grafana | http://localhost:3000 | 日志查询 + Dashboard |
| MinIO Console | http://localhost:9001 | 查看存储用量 |
| Loki API | http://localhost:3100 | 内部，不需要直接访问 |

---

## 10. 日志规范

### 事件命名

用 `.` 分隔的层级命名，方便 LogQL 过滤：

```
模块.动作

api.request.start       # API 请求开始
api.request.end         # API 请求结束
engine.scan.start       # Engine 扫描开始
engine.scan.done        # Engine 扫描完成
agent.start             # Agent 启动
agent.turn              # Agent 一轮 LLM 调用
agent.done              # Agent 完成
tool.call               # 工具调用
tool.result             # 工具返回
tool.error              # 工具报错
llm.request             # LLM API 调用
llm.response            # LLM API 返回
db.slow_query           # 慢查询 (> 500ms)
```

### 必带字段

| 字段 | 类型 | 说明 | 来自 |
|------|------|------|------|
| `event` | str | 事件名（如 `tool.call`） | structlog 自动 |
| `level` | str | 日志级别 | structlog 自动 |
| `timestamp` | str | ISO 时间戳 | structlog 自动 |
| `logger` | str | Logger name → module | structlog 自动 |

### Agent 专用字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `agent_type` | str | `event_classifier`, `vuln_analyzer`, ... |
| `agent_id` | str | Agent 实例 UUID |
| `target_id` | str | 关联业务对象 ID |
| `turn` | int | 当前轮次 |
| `tool` | str | 工具名 |
| `duration_ms` | int | 耗时 |

### API 专用字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `request_id` | str | 请求 ID（已有，通过 contextvars） |
| `method` | str | HTTP method |
| `path` | str | 请求路径 |
| `status` | int | 响应状态码 |

### 日志级别使用规则

| 级别 | 用途 | 示例 |
|------|------|------|
| `debug` | 对话内容、大文本 | `agent.message` (LLM 输出内容) |
| `info` | 正常业务流程 | `agent.turn`, `tool.call`, `request.end` |
| `warning` | 可恢复的异常 | rate limit, retry, 超时重试 |
| `error` | 不可恢复的错误 | Agent 失败, 工具崩溃, DB 连接丢失 |

**对话内容用 `debug` 级别**——生产环境可以通过 `VULNSENTINEL_LOG_LEVEL=INFO` 关闭，减少存储量。需要 replay 时临时改成 `DEBUG`。

---

## 11. 保留策略

| 数据 | 存储位置 | 保留时间 | 原因 |
|------|---------|---------|------|
| **日志流**（INFO 及以上） | Loki → MinIO | **90 天** | Loki `retention_period` 自动清理 |
| **对话内容**（DEBUG） | Loki → MinIO | **90 天** | 同上 |
| **Agent 统计** | PG `agent_runs` | **永久** | 成本分析需要长期趋势 |
| **工具调用明细** | PG `agent_tool_calls` | **90 天** | 定期 DELETE，统计在 `agent_runs` 里够用 |

### 存储预估（1000 events/月）

| 数据 | 原始大小 | 压缩后（Loki gzip） | 月增量 |
|------|---------|--------------------|----|
| INFO 日志 | ~50 MB/月 | ~5 MB/月 | 5 MB |
| DEBUG 日志（含对话） | ~200 MB/月 | ~30 MB/月 | 30 MB |
| **合计** | | | **~35 MB/月** |

一年 ~420 MB。MinIO 磁盘完全不是问题。

---

## 12. 上云迁移路径

现在全部本地运行。以后上云只需要改配置，代码零改动：

### Step 1：MinIO → AWS S3

```yaml
# loki.yaml — 改一行
storage_config:
  aws:
    # 原来: s3: http://minioadmin:minioadmin@minio:9000/vulnsentinel-logs
    s3: s3://ap-northeast-1/vulnsentinel-logs
    # AWS credentials 走 IAM role 或环境变量
```

删掉 MinIO 容器即可。

### Step 2：Grafana → Grafana Cloud（可选）

如果不想自己跑 Grafana，直接用 Grafana Cloud 免费版（10GB 日志/月免费）。改 Loki 推送地址即可。

### Step 3：Loki → 托管（可选）

AWS 上可以继续自己跑 Loki（ECS/EKS），也可以换成 Grafana Cloud Logs。

**关键点：因为全程用的是 S3 API + Loki API + Grafana 标准协议，每一层都可以独立替换。**

---

## 附：配置文件清单

```
Z-VulnSentinel/
├── config/
│   ├── alloy/
│   │   └── config.alloy         # Alloy 采集配置
│   ├── loki/
│   │   └── loki.yaml            # Loki 存储配置
│   └── grafana/
│       ├── grafana.ini           # Grafana 基础配置
│       └── provisioning/
│           ├── datasources/
│           │   └── datasources.yaml   # Loki + PG 数据源
│           └── dashboards/
│               ├── dashboards.yaml    # Dashboard 加载
│               └── vulnsentinel.json  # 预置 Dashboard
├── docker-compose.yml            # 更新：+minio, +loki, +alloy, +grafana
└── vulnsentinel/
    └── core/
        └── logging.py            # 不改（已有 structlog）
```
