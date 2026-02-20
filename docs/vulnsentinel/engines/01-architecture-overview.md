# Vuln Sentinel - 企业级漏洞预警系统

## 项目目标

开源库的漏洞从被发现、修复，到 CVE 正式披露，通常存在至少一个月的窗口期。这段时间恰恰是漏洞被利用的高发期——补丁已经公开，攻击者可以逆向分析修复内容，而下游用户尚未意识到风险。

**VulnSentinel 的目标不是缩短 CVE 披露周期，而是在依赖库提交漏洞修复的那一刻，立即分析该漏洞，并检测客户代码中是否存在可被该漏洞影响的调用路径。如果存在，尝试生成 PoC 利用并向客户发出预警。**

## Motivation: 为什么是现在

漏洞预警不是新问题，但过去的自动化手段始终无法突破一个瓶颈：**无法从代码变更中判断"这是不是一个安全修复"。**

传统方法的局限：

- **关键词匹配** — commit message 写了 "buffer overflow" 才能捕获，开发者不写就完全漏掉。大量安全修复的 message 只是 "fix crash" 甚至 "cleanup"。
- **静态规则 / CVE 模式库** — 本质是事后追认，必须等人工审核分配 CVE 编号后才能匹配，天然滞后数周到数月。
- **diff 统计** — 知道改了哪些文件、多少行，但无法理解"为什么改"。一个加了边界检查的 one-liner 和一个无关的 refactor 在统计上没有区别。

这些方法都停留在语法层面，无法回答核心问题：**这个 commit 是在修安全漏洞，还是普通 bug、重构、性能优化？**

LLM 改变了这一点。它能在语义层面理解 diff：

- 看到边界检查被加上 → 可能是 buffer overflow 修复
- 看到 free 后指针被置空 → 可能是 use-after-free 修复
- 看到整数运算加了溢出保护 → 可能是 integer overflow 修复
- 看到输入验证被收紧 → 可能是注入类漏洞修复

这种语义理解能力使得**实时、自动、无需依赖 CVE 披露的漏洞检测**第一次成为可能。

## 核心工作流

```
客户代码 ──→ 提取第三方依赖 ──→ 持续监控依赖库
                                       │
                               依赖库产生新 commit / PR / tag / issue
                                       │
                                       ▼
                            LLM 语义分类：是否为安全修复？
                                       │
                              ┌────────┴────────┐
                              │                 │
                        security_bugfix       其他类型
                              │                 │
                              ▼            记录 & 继续监控
                    分析漏洞详情（类型、严重度、影响版本）
                    收集上游 PoC（如果有的话）
                              │
                              ▼
               对每个潜在受影响的客户项目：
                    搜索调用图中到达漏洞函数的路径
                              │
                     ┌────────┴────────┐
                     │                 │
                  路径可达           路径不可达
                     │                 │
                     ▼            标记 not_affect
               尝试生成 PoC 利用
                     │
            ┌────────┴────────┐
            │                 │
         PoC 成功          PoC 失败
            │                 │
      预警 + 报告          记录（路径可达但未能利用）
```

### 十步流程

| 步骤 | 阶段 | 说明 |
|------|------|------|
| 1 | **客户接入** | 与合作客户建立关系 |
| 2 | **代码托管** | 客户提供代码库访问 |
| 3 | **依赖提取** | 分析客户代码，提取所有第三方库和依赖（zlib、curl、openssl 等） |
| 4 | **依赖监控** | 对所有依赖库建立持续监控（commit feed / release watch） |
| 5 | **事件捕获** | 捕获依赖库的 commit、PR merge、tag、bug issue 等事件 |
| 6 | **LLM 分类** | LLM 语义分析 diff，判断是否为 security bugfix（核心能力） |
| 7 | **漏洞分析** | 分析 security bugfix 的具体漏洞：类型、严重度、影响版本、上游 PoC |
| 8 | **路径搜索** | 在客户代码的调用图中搜索从入口到漏洞函数的可达路径 |
| 9 | **PoC 生成** | 对路径可达的项目，尝试生成 PoC 利用 |
| 10 | **预警报告** | 向受影响客户发送预警，包含漏洞详情、调用路径、PoC 和修复建议 |

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                         Frontend                             │
│                    React (Dashboard)                          │
│           客户视图 · 监控面板 · 预警详情 · 报告               │
└──────────────────────────┬──────────────────────────────────┘
                           │ REST / WebSocket
┌──────────────────────────▼──────────────────────────────────┐
│                         Backend                              │
│                    FastAPI (API Server)                       │
│        认证 · 任务调度 · 引擎编排 · 推送通知                 │
└───────┬──────────────────┬──────────────────┬───────────────┘
        │                  │                  │
        ▼                  ▼                  ▼
┌────────────────┐ ┌──────────────┐   ┌──────────────────┐
│    Storage     │ │   Engines    │   │     Engines      │
│                │ │  (Python)    │   │    (Python)      │
│ PostgreSQL     │ │              │   │                  │
│ · 业务数据     │ │ · 依赖监控   │   │ · 静态分析       │
│ · 漏洞记录     │ │ · Commit 分析│   │   (z_code_analyzer)│
│ · 分析结果     │ │ · LLM 分类   │   │ · 调用图搜索     │
│                │ │              │   │ · PoC 生成       │
│ Neo4j          │ │              │   │   (FuzzingBrain) │
│ · 函数调用图   │ │              │   │                  │
│ · 可达性分析   │ │              │   │                  │
│                │ │              │   │                  │
│ Disk           │ │              │   │                  │
│ · Snapshot 文件│ │              │   │                  │
└────────────────┘ └──────────────┘   └──────────────────┘
```

四大层级：

| 层级 | 技术栈 | 职责 |
|------|--------|------|
| **Frontend** | React | 客户 Dashboard，监控状态，预警展示，报告查看 |
| **Backend** | FastAPI | API 网关，认证鉴权，任务调度，引擎编排，WebSocket 推送 |
| **Storage** | PostgreSQL + Neo4j + Disk | PostgreSQL：业务数据（客户、项目、依赖、漏洞、分析结果）；Neo4j：函数调用图与可达性分析；Disk：静态分析 snapshot 文件 |
| **Engines** | Python 模块 | 各独立引擎：依赖监控、commit 语义分析（LLM）、静态分析（z_code_analyzer）、调用图搜索、PoC 生成（FuzzingBrain） |

---

## 引擎定义

7 个引擎 + 1 个调度层，覆盖从"监控上游代码变更"到"通知下游项目负责人"的完整链路。

### 引擎流水线

```
Event Collector → Event Classifier → Vuln Analyzer → Impact Engine → Reachability Analyzer → Notification Engine
                                                                            ↑
                                                                     Snapshot Builder
```

### 引擎列表

| # | 引擎 | 对应十步流程 | 输入 | 输出 | 核心能力 |
|---|------|-------------|------|------|---------|
| 1 | **Event Collector** | 步骤 4-5 | Library 列表 | Event 记录 | GitHub API 拉取 commit / PR / tag / issue |
| 2 | **Event Classifier** | 步骤 6 | 未分类 Event | classification + confidence | LLM 语义分析 diff，判断是否为 security_bugfix |
| 3 | **Vuln Analyzer** | 步骤 7 | security_bugfix Event | UpstreamVuln 记录 | LLM 分析漏洞类型、严重度、影响版本、上游 PoC |
| 4 | **Impact Engine** | 步骤 8（版本匹配部分） | 已 publish 的 UpstreamVuln | ClientVuln 记录 | 版本约束比对，判断哪些项目受影响 |
| 5 | **Reachability Analyzer** | 步骤 8-9 | pending ClientVuln + Snapshot | 可达路径 + PoC 结果 | 调用图 BFS + PoC 生成 |
| 6 | **Snapshot Builder** | （基础设施） | Project 信息 | Snapshot 记录 | SVF/Joern 静态分析，构建调用图 |
| 7 | **Notification Engine** | 步骤 10 | verified ClientVuln | 通知记录 | 邮件 / Webhook / 站内消息 |

### 引擎间数据流

```
┌──────────────┐     Event      ┌──────────────────┐  security_bugfix  ┌────────────────┐
│    Event     │ ──────────────→│     Event        │ ────────────────→│     Vuln       │
│  Collector   │   batch_create │   Classifier     │ update_classif.  │   Analyzer     │
└──────────────┘                └──────────────────┘                  └───────┬────────┘
                                                                             │ create + publish
                                                                             ▼
┌──────────────┐                ┌──────────────────┐  create          ┌────────────────┐
│ Notification │ ←──────────────│  Reachability    │ ←────────────────│    Impact      │
│   Engine     │   finalize     │   Analyzer       │  ClientVuln      │    Engine      │
└──────────────┘                └────────┬─────────┘                  └────────────────┘
                                         │
                                         │ 依赖
                                         ▼
                                ┌──────────────────┐
                                │    Snapshot      │
                                │    Builder       │
                                └──────────────────┘
```

### Service 接口映射

每个引擎通过已有的 Service 层读写数据，不直接操作数据库：

| 引擎 | 读取 | 写入 |
|------|------|------|
| Event Collector | `LibraryService.list()` | `EventService.batch_create()` |
| Event Classifier | `EventService.list_unclassified()` | `EventService.update_classification()` |
| Vuln Analyzer | `EventService.list_bugfix_without_vuln()` | `UpstreamVulnService.create()` → `update_analysis()` → `publish()` |
| Impact Engine | 已 publish 的 UpstreamVuln + ProjectDependency | `ClientVulnService.create()` |
| Reachability Analyzer | `ClientVulnService.list_pending_pipeline()` | `ClientVulnService.update_pipeline()` → `finalize()` |
| Snapshot Builder | Project 信息 | `SnapshotService.create()` → `update_status()` → `activate()` |
| Notification Engine | 已 verified 未通知的 ClientVuln | 发送通知 + 更新 ClientVuln 状态 |

---

## 调度层

引擎不自行管理触发时机，由统一的 Scheduler 调度。

### 触发策略

| 引擎 | 触发方式 | 说明 |
|------|---------|------|
| Event Collector | 定时轮询 | 每 N 分钟 per library，GitHub API rate limit 感知 |
| Event Classifier | 链式触发 / 定时兜底 | Collector 完成后立即触发；定时兜底处理遗漏 |
| Vuln Analyzer | 链式触发 | Classifier 产出 security_bugfix 后触发 |
| Impact Engine | 链式触发 | Vuln publish 后触发 |
| Reachability Analyzer | 链式触发 | ClientVuln 创建后触发（需 Snapshot 就绪） |
| Snapshot Builder | 事件触发 + 定时 | 新项目注册 / 上游漏洞 / 手动 / 定时重建 |
| Notification Engine | 链式触发 / 定时兜底 | finalize(is_affected=True) 后触发；定时兜底 |

### 调度方案选择

具体技术方案（APScheduler / Celery / 简单 asyncio loop）在各引擎设计文档确定后再决定。核心原则：

- **链式触发为主**：上游引擎完成后直接触发下游，减少延迟
- **定时兜底为辅**：防止链式触发丢失（进程重启、异常中断等）
- **幂等性**：所有引擎必须支持重复执行不产生副作用（Service 层已保证 batch_create ON CONFLICT DO NOTHING）




# 逻辑示例

## 第一步：用户注册需要被监控的 Project

客户调用 `POST /api/v1/projects/`，提供项目信息。

- 必填：`name`、`repo_url`
- 可选：`organization`、`contact`、`dependencies[]`
- 默认：`auto_sync_deps=true`

两种情况：
- **带 dependencies**：依赖立刻写入，Libraries 自动 upsert
- **不带 dependencies**：等待 Dependency Scanner 扫描 repo 自动发现依赖

额外选项：
- `pinned_ref`：锁定某个 tag 或 commit SHA。设置后依赖只扫描一次，后续不再重扫。不设置则跟踪默认分支最新代码。

### 依赖扫描（Dependency Scanner）

| 项目 | 说明 |
|------|------|
| 做什么 | 扫描 Project 的 manifest 文件，同步依赖列表 |
| 触发 | 注册时立即扫一次 + per-project 每 6 小时重扫（基于 `last_scanned_at`） |
| 速度 | 快 — 只读文件，不需要编译 |

特殊情况：
- `pinned_ref` 设置时：只扫一次该 ref 的 manifest，后续不再重扫
- `auto_sync_deps=false` 时：跳过自动扫描，依赖只能手动管理

### Library 监控（Event Collector）

| 项目 | 说明 |
|------|------|
| 做什么 | 拉取依赖 Library repo 的新 commit / PR / tag |
| 触发 | 每几分钟轮询 |
| 速度 | 快 — GitHub API 调用 |

Library 监控是高频的 — 安全修复 commit 需要尽快捕获。这是整个 pipeline 的数据入口。

### Snapshot（按需构建，不在此步）

Snapshot 是 call graph 静态分析的产物，供 Reachability Analyzer 使用。不在注册时构建，等 pipeline 需要做可达性分析时才按需构建/查缓存。与依赖扫描完全独立。