# VulnSentinel 日志系统设计

> 基于 structlog + stdlib logging 的统一结构化日志方案，支持开发/生产双模式输出。

---

## 目录

1. [方案选型](#1-方案选型)
2. [双模式输出](#2-双模式输出)
3. [架构设计](#3-架构设计)
4. [stdlib 桥接](#4-stdlib-桥接)
5. [日志级别策略](#5-日志级别策略)
6. [结构化字段约定](#6-结构化字段约定)
7. [Request ID 中间件](#7-request-id-中间件)
8. [初始化位置](#8-初始化位置)
9. [依赖](#9-依赖)

---

## 1. 方案选型

### 1.1 为什么选 structlog + stdlib logging

VulnSentinel 后端技术栈中，uvicorn、SQLAlchemy、asyncpg、FastAPI 内部全部使用 Python stdlib `logging` 模块。日志方案必须与 stdlib 生态无缝整合，而不是另起炉灶。

**structlog** 的定位是 stdlib logging 的**结构化增强层**：

- 业务代码通过 `structlog.get_logger()` 写日志，获得结构化 key-value 绑定能力
- 通过 `structlog.stdlib.ProcessorFormatter` 桥接 stdlib，使所有第三方库的日志走统一的 processor chain
- 零侵入——不需要修改任何第三方库的代码

### 1.2 为什么不用其他方案

| 方案 | 问题 |
|------|------|
| **纯 stdlib logging** | 无原生结构化支持，JSON 输出需要自己写 formatter，context 绑定（如 request_id 传播）需要手动管理 |
| **loguru** | 完全替换 stdlib，与 uvicorn/SQLAlchemy 的 stdlib logger 存在两套体系；`intercept` 方案虽然可行但属于 hack；社区生产级采用率低于 structlog |
| **python-json-logger** | 只解决 JSON 输出，不提供 processor chain、context 绑定等能力 |

### 1.3 structlog 的核心优势

- **Processor chain**：日志经过可组合的 processor 管道，每个 processor 做一件事（加时间戳、加级别、格式化异常……）
- **Context 绑定**：`structlog.contextvars` 支持请求级上下文自动传播，天然适配 async
- **双模式输出**：开发用彩色 console，生产用 JSON，同一份代码零修改切换
- **stdlib 兼容**：不是替代 stdlib，而是增强 stdlib

---

## 2. 双模式输出

通过环境变量 `VULNSENTINEL_LOG_FORMAT` 切换输出格式：

### 2.1 开发模式 (`console`，默认)

```
VULNSENTINEL_LOG_FORMAT=console
```

使用 `structlog.dev.ConsoleRenderer` 输出彩色、人类可读的日志：

```
2026-02-20T10:30:15.123Z [info     ] scan started                   engine=cve_monitor library_id=lib_abc123
2026-02-20T10:30:15.456Z [debug    ] fetching CVE feed               source=nvd year=2026
2026-02-20T10:30:16.789Z [warning  ] rate limit approaching          remaining=12 reset_at=2026-02-20T10:31:00Z
2026-02-20T10:30:17.012Z [error    ] CVE fetch failed                source=nvd error=ConnectionTimeout
Traceback (most recent call last):
  File "vulnsentinel/engine/cve_monitor.py", line 42, in fetch_feed
    ...
TimeoutError: Connection timed out
```

特点：

- 时间戳、级别、事件名彩色高亮
- 结构化字段以 `key=value` 形式追加在事件后
- 异常 traceback 自动展开，开发调试友好

### 2.2 生产模式 (`json`)

```
VULNSENTINEL_LOG_FORMAT=json
```

使用 `structlog.processors.JSONRenderer` 输出 JSON 行：

```json
{"timestamp":"2026-02-20T10:30:15.123000Z","level":"info","logger":"vulnsentinel.engine.cve_monitor","event":"scan started","engine":"cve_monitor","library_id":"lib_abc123"}
{"timestamp":"2026-02-20T10:30:17.012000Z","level":"error","logger":"vulnsentinel.engine.cve_monitor","event":"CVE fetch failed","source":"nvd","error":"ConnectionTimeout","exc_info":"Traceback (most recent call last):\n  ..."}
```

特点：

- 每行一个 JSON 对象，可直接被 ELK / Loki / Datadog / CloudWatch 采集
- 所有字段（包括异常信息）序列化为 JSON 字段
- 无彩色 ANSI 转义字符

---

## 3. 架构设计

### 3.1 整体数据流

日志有两条入口路径，最终汇合到同一个 `ProcessorFormatter` 输出：

```
structlog 路径（业务代码）              stdlib 路径（uvicorn / SQLAlchemy / asyncpg）
        │                                       │
        │ structlog.get_logger()                 │ logging.getLogger()
        ▼                                       ▼
shared_processors                       foreign_pre_chain = shared_processors
  + wrap_for_formatter (链尾)             （同一组 processors，补齐 enrichment）
        │                                       │
        └───────────────┬───────────────────────┘
                        ▼
              ProcessorFormatter
                ├─ remove_processors_meta
                └─ renderer (Console 或 JSON)
                        │
                        ▼
              StreamHandler(sys.stdout)
```

两条路径共享同一组 `shared_processors`：

```python
shared_processors = [
    structlog.contextvars.merge_contextvars,    # 合并请求级 context
    structlog.stdlib.add_log_level,             # 添加 level 字段
    structlog.stdlib.add_logger_name,           # 添加 logger 名
    structlog.processors.TimeStamper(fmt="iso", utc=True),  # ISO 8601 UTC
    structlog.processors.StackInfoRenderer(),   # stack_info 支持
    structlog.processors.format_exc_info,       # 异常格式化
    structlog.processors.UnicodeDecoder(),      # 统一 unicode
]
```

- **structlog 路径**：`structlog.configure(processors=shared_processors + [wrap_for_formatter])`，`wrap_for_formatter` 作为链尾将 event_dict 传递给 `ProcessorFormatter`
- **stdlib 路径**：`ProcessorFormatter(foreign_pre_chain=shared_processors)`，stdlib 日志经过同样的 enrichment（时间戳、级别、logger name 等），不会缺字段

### 3.2 关键设计点

**所有日志输出到 stdout**。容器环境中，日志采集器（filebeat、fluentd、Docker log driver）从 stdout 读取即可。不写日志文件，避免磁盘管理、日志轮转等运维复杂度。

**双链路共享 processors**。structlog 自身的日志和 stdlib 来源的日志走不同的入口，但经过同一组 `shared_processors` 做 enrichment，确保输出格式完全一致。这是 structlog 桥接 stdlib 的标准模式。

**processor chain 顺序固定**。structlog 的 processor 按顺序执行，顺序不能随意调整：

1. `merge_contextvars` 必须最先——确保请求级 context 在其他 processor 之前合并
2. `add_log_level` / `add_logger_name` 在中间——填充元数据字段
3. `TimeStamper` 在中间——打时间戳
4. `format_exc_info` 靠后——在最终渲染前格式化异常
5. `wrap_for_formatter` 必须是 structlog configure chain 的最后一个——桥接到 `ProcessorFormatter`
6. Renderer（Console 或 JSON）由 `ProcessorFormatter` 内部处理，不在 shared chain 中

---

## 4. stdlib 桥接

### 4.1 问题

uvicorn、SQLAlchemy、asyncpg 内部使用 stdlib `logging.getLogger()` 输出日志。如果不做桥接，会出现两种格式的日志混在一起：structlog 的结构化输出和 stdlib 的传统文本输出。

### 4.2 方案

分两步配置：先 `structlog.configure()` 配置 structlog 自身，再 `logging.config.dictConfig()` 配置 stdlib。两者通过 `shared_processors` 共享同一组 enrichment processors（见第 3.1 节）。

**Step 1: structlog.configure()**

```python
structlog.configure(
    processors=shared_processors + [
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,  # 链尾：桥接到 ProcessorFormatter
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
```

**Step 2: logging.config.dictConfig()**

```python
{
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "structlog": {
            "()": structlog.stdlib.ProcessorFormatter,
            "foreign_pre_chain": shared_processors,  # ← 关键：stdlib 日志的 enrichment
            "processors": [
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                renderer,  # ConsoleRenderer 或 JSONRenderer
            ],
        },
    },
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "structlog",
        },
    },
    "root": {
        "handlers": ["default"],
        "level": "INFO",
    },
    "loggers": {
        # 见第 5 节日志级别策略
    },
}
```

`foreign_pre_chain` 是关键——没有它，stdlib 来源的日志会跳过 enrichment，直接进 renderer，导致缺少 timestamp、level 等字段。

### 4.3 效果

配置后，以下日志都走统一格式：

```
# structlog 业务日志
log.info("scan started", engine="cve_monitor")

# uvicorn 的 stdlib 日志
# SQLAlchemy 的 stdlib 日志
# asyncpg 的 stdlib 日志
```

全部统一输出为 console 或 JSON 格式，不再有格式混乱。

---

## 5. 日志级别策略

### 5.1 级别配置

| Logger | 开发模式 | 生产模式 | 说明 |
|--------|---------|---------|------|
| `vulnsentinel` | `DEBUG` | `INFO` | 业务日志，开发时看全量 |
| `uvicorn.access` | `WARNING` | `WARNING` | 请求访问日志噪音大，仅记录异常 |
| `uvicorn.error` | `INFO` | `INFO` | 保留启动信息和错误 |
| `sqlalchemy.engine` | `WARNING` | `WARNING` | 默认静默；调试 SQL 时临时改 `INFO` 可看到完整 SQL |
| `asyncpg` | `WARNING` | `WARNING` | 连接池噪音 |
| `httpx` | `WARNING` | `WARNING` | HTTP 客户端请求噪音 |

### 5.2 环境变量

```
VULNSENTINEL_LOG_LEVEL=INFO      # 控制 vulnsentinel logger 的级别
VULNSENTINEL_LOG_FORMAT=console   # console | json
```

- `LOG_LEVEL` 仅影响 `vulnsentinel` 命名空间下的 logger
- 第三方库的级别在 dictConfig 中硬编码为 `WARNING`，避免噪音
- 调试特定库时，可通过代码临时调整，不暴露为环境变量

---

## 6. 结构化字段约定

### 6.1 自动附带字段

每条日志由 processor chain 自动添加：

| 字段 | 来源 | 示例 |
|------|------|------|
| `timestamp` | `TimeStamper(fmt="iso", utc=True)` | `"2026-02-20T10:30:15.123000Z"` |
| `level` | `add_log_level` | `"info"`, `"warning"`, `"error"` |
| `logger` | `add_logger_name` | `"vulnsentinel.engine.cve_monitor"` |
| `event` | structlog 第一个位置参数 | `"scan started"` |

### 6.2 业务层手动绑定字段

各层在调用日志时绑定的上下文字段：

**Engine 层**：

```python
log = structlog.get_logger()
log.info("scan started", engine="cve_monitor", library_id="lib_abc123")
log.info("vulnerability found", vuln_id="CVE-2026-1234", severity="critical")
```

| 字段 | 说明 |
|------|------|
| `engine` | 引擎名称 (`cve_monitor`, `code_analyzer`, ...) |
| `library_id` | 当前处理的 library ID |
| `event_id` | 引擎事件 ID |
| `vuln_id` | 漏洞 ID（CVE 编号等） |

**API 层**（通过 Request ID 中间件自动绑定，见第 7 节）：

| 字段 | 说明 |
|------|------|
| `request_id` | 请求唯一标识（UUID v4，标准带连字符格式 `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`） |
| `method` | HTTP 方法 |
| `path` | 请求路径 |
| `status_code` | 响应状态码 |
| `duration_ms` | 请求处理耗时（毫秒） |

**Service 层**：

```python
log.info("library created", project_id="proj_123", operation="create_library")
```

| 字段 | 说明 |
|------|------|
| `project_id` | 项目 ID |
| `operation` | 操作名称 |

### 6.3 命名规范

- 字段名使用 `snake_case`
- 字段值避免嵌套对象，保持扁平——方便 JSON 日志的索引和查询
- 时间类字段统一 ISO 8601 UTC 格式
- ID 类字段保持原始格式（如 `CVE-2026-1234`，不做转换）

---

## 7. Request ID 中间件

### 7.1 目的

在分布式或异步环境中，一个 API 请求可能触发多层 Service / DAO 调用。通过 request_id 将同一请求链路的所有日志关联起来，方便问题排查。

### 7.2 工作流程

```
客户端请求
    │
    ▼
FastAPI Middleware
    ├─ 生成 UUID request_id（或从请求头 X-Request-ID 读取）
    ├─ structlog.contextvars.bind_contextvars(request_id=request_id)
    ├─ 记录请求开始日志
    │       │
    │       ▼
    │   路由 → Service → DAO（所有层的日志自动携带 request_id）
    │       │
    │       ▼
    ├─ 记录请求完成日志（含 status_code, duration_ms）
    ├─ 响应 header 设置 X-Request-ID
    └─ structlog.contextvars.reset_contextvars(**tokens)  ← 精确恢复
```

### 7.3 关键实现点

- 使用 `structlog.contextvars` 而非 `threading.local`——兼容 async/await
- `contextvars` 基于 Python `contextvars.ContextVar`，每个 asyncio Task 自动隔离
- 使用 `reset_contextvars(**tokens)` 精确恢复 context，而非 `unbind` 或 `clear`：

```python
tokens = bind_contextvars(request_id=rid, method=method, path=path)
try:
    response = await call_next(request)
finally:
    reset_contextvars(**tokens)  # 恢复到绑定前状态，不影响外层 context
```

- `reset_contextvars(**tokens)` 比 `clear_contextvars()` 更安全——它恢复到 `bind` 之前的精确状态，不会误清外层已绑定的 context
- `bind_contextvars()` 返回 `dict[str, Token]`，`reset_contextvars()` 接受 `**kw`，必须用 `**` 解包传入
- 客户端可通过 `X-Request-ID` 请求头传入自定义 request_id（便于跨服务追踪），如果未传则自动生成
- 传入的 `X-Request-ID` 必须验证为合法 UUID 格式，非法值（超长字符串、特殊字符等）直接忽略并自动生成，防止日志污染

### 7.4 日志效果

同一请求的所有日志共享 `request_id`：

```json
{"timestamp":"...","level":"info","event":"request started","request_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","method":"POST","path":"/api/v1/libraries"}
{"timestamp":"...","level":"info","event":"library created","request_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","project_id":"proj_123","operation":"create_library"}
{"timestamp":"...","level":"debug","event":"SQL executed","request_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","statement":"INSERT INTO libraries ..."}
{"timestamp":"...","level":"info","event":"request completed","request_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","status_code":201,"duration_ms":45}
```

---

## 8. 初始化位置

### 8.1 配置模块

```
vulnsentinel/core/logging.py
```

包含：

- `setup_logging(log_level: str, log_format: str)` — 配置 structlog 和 stdlib logging
- 从环境变量读取 `VULNSENTINEL_LOG_LEVEL` 和 `VULNSENTINEL_LOG_FORMAT`
- 设置 structlog processor chain
- 调用 `logging.config.dictConfig()` 配置 stdlib

### 8.2 调用时机

在 `create_app()` 函数顶部调用，**早于 FastAPI 实例化**：

```python
def create_app() -> FastAPI:
    setup_logging()              # ← 最先执行，早于一切
    app = FastAPI(lifespan=_lifespan)
    # ...
    return app
```

**为什么不放在 lifespan 里**：lifespan 是 uvicorn 启动后、应用 ready 前才执行的。如果放在 lifespan 里，uvicorn 自身的启动日志（`Started server process`、`Waiting for application startup`）不会走 structlog 格式化，导致启动阶段日志格式不统一。放在 `create_app()` 顶部确保：

- uvicorn 的启动日志也走 structlog formatter
- Engine 启动时自动继承同一配置（因为运行在同一进程中）
- 不需要在每个模块中重复配置

### 8.3 使用方式

初始化后，各模块直接使用 structlog：

```python
import structlog

log = structlog.get_logger()

# 在函数中使用
async def scan_library(library_id: str):
    log.info("scan started", library_id=library_id)
    # ...
    log.info("scan completed", library_id=library_id, vulns_found=3)
```

不需要传递 logger 实例，`structlog.get_logger()` 自动获取模块名作为 logger name。

---

## 9. 依赖

在 `pyproject.toml` 中添加：

```toml
[project]
dependencies = [
    # ... 现有依赖
    "structlog>=24.0",
]
```

structlog 24.0+ 要求：

- Python 3.8+（VulnSentinel 使用 3.12+，满足）
- 无其他外部依赖（structlog 本身是纯 Python 包）
