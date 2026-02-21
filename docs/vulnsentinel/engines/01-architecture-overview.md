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

8 个引擎 + 1 个调度层，覆盖从"提取依赖"到"通知下游项目负责人"的完整链路。

### 引擎流水线

```
Dependency Scanner → Event Collector → Event Classifier → Vuln Analyzer → Impact Engine → Reachability Analyzer → Notification Engine
                                                                                                ↑
                                                                                         Snapshot Builder
```

### 引擎列表

| # | 引擎 | 对应十步流程 | 输入 | 输出 | 核心能力 | 状态 |
|---|------|-------------|------|------|---------|------|
| 0 | **Dependency Scanner** | 步骤 3 | Project repo | ScannedDependency + DB 同步 | 11 个 manifest parser，自动发现依赖 | **已实现** |
| 1 | **Event Collector** | 步骤 4-5 | Library 列表 | Event 记录 | GitHub API 拉取 commit / PR / tag / issue | 待实现 |
| 2 | **Event Classifier** | 步骤 6 | 未分类 Event | classification + confidence | LLM 语义分析 diff，判断是否为 security_bugfix | 待实现 |
| 3 | **Vuln Analyzer** | 步骤 7 | security_bugfix Event | UpstreamVuln 记录 | LLM 分析漏洞类型、严重度、影响版本、上游 PoC | 待实现 |
| 4 | **Impact Engine** | 步骤 8（版本匹配部分） | 已 publish 的 UpstreamVuln | ClientVuln 记录 | 版本约束比对，判断哪些项目受影响 | 待实现 |
| 5 | **Reachability Analyzer** | 步骤 8-9 | pending ClientVuln + Snapshot | 可达路径 + PoC 结果 | 调用图 BFS + PoC 生成 | 待实现 |
| 6 | **Snapshot Builder** | （基础设施） | Project 信息 | Snapshot 记录 | SVF/Joern 静态分析，构建调用图 | 待实现 |
| 7 | **Notification Engine** | 步骤 10 | verified ClientVuln | 通知记录 | 邮件 / Webhook / 站内消息 | 待实现 |

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
| Dependency Scanner | `ProjectDAO.get_by_id()` | `LibraryService.upsert()` → `ProjectDependencyDAO.batch_upsert()` → `delete_stale_scanner_deps()` |
| Event Collector | `LibraryDAO.get_all_monitored()` | `EventService.batch_create()` |
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
| Dependency Scanner | 定时轮询 | per-project 每 1 小时，基于 `last_scanned_at`；`auto_sync_deps=false` 跳过 |
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

**请求参数：**

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `name` | 是 | — | 项目名称 |
| `repo_url` | 是 | — | 项目 Git 仓库地址 |
| `organization` | 否 | `null` | 所属组织 |
| `contact` | 否 | `null` | 联系人 |
| `platform` | 否 | `"github"` | 代码托管平台 |
| `default_branch` | 否 | `"main"` | 默认分支 |
| `auto_sync_deps` | 否 | `true` | 是否自动扫描 manifest 同步依赖 |
| `pinned_ref` | 否 | `null` | 锁定某个 tag 或 commit SHA（Service 层校验是否存在） |
| `dependencies[]` | 否 | `null` | 手动提供依赖列表（见下方字段说明） |

**`dependencies[]` 每项字段：**

| 字段 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `library_name` | 是 | — | 库名，如 `libpng`、`requests`、`lodash` |
| `library_repo_url` | 否 | `null` | 库的 Git 仓库地址；不填则由 Engine 从包注册表（PyPI、npm 等）自动解析 |
| `constraint_expr` | 否 | `null` | 版本约束表达式，如 `>=1.6.0`、`^2.0.0` |
| `resolved_version` | 否 | `null` | 实际锁定的版本，如 `1.6.37` |
| `platform` | 否 | `"github"` | 库的代码托管平台 |
| `default_branch` | 否 | `"main"` | 库的默认分支 |

用户通过此字段手动添加的依赖，`constraint_source` 自动设为 `manual`（不由用户控制）。

**注册后依赖的来源（二选一）：**

- **带 `dependencies[]`**：依赖立刻写入，Libraries 自动 upsert
- **不带 `dependencies[]`**（更常见）：Dependency Scanner 异步扫描 repo manifest 自动发现

**注册后可修改（`PATCH /api/v1/projects/{id}`）：**

`name`、`organization`、`contact`、`auto_sync_deps`、`pinned_ref`（支持传 `null` 清空）

### 依赖扫描（Dependency Scanner）

扫描 Project repo 的 manifest 文件，同步依赖列表。详见 [02-dependency-scanner.md](./02-dependency-scanner.md)。

| 触发时机 | 条件 |
|---------|------|
| 注册时 | 立即异步触发一次 |
| 定时重扫 | per-project 每 1 小时（基于 `last_scanned_at`） |

**用户不能手动触发 scan。** Scan 只由系统定时自动执行。

**Scheduler 查询条件：**

```sql
WHERE auto_sync_deps = true
  AND (last_scanned_at IS NULL OR last_scanned_at < now() - interval '1 hour')
```

即：`auto_sync_deps=false` 的项目不会被定时重扫。设置了 `pinned_ref` 的项目仍然会扫描，但 clone 时使用 `pinned_ref` 指定的 tag/SHA。

### 手动 vs 自动依赖管理

两种来源的依赖通过 `constraint_source` 区分，互不干扰：

| `constraint_source` | 来源 | Scanner 行为 |
|---------------------|------|-------------|
| manifest 文件路径（如 `requirements.txt`、`pom.xml`） | Scanner 自动扫描写入 | Scanner 管理：manifest 里没有就删除 |
| `manual` | 用户通过 API 手动添加 | Scanner 不动：跳过 |

- **`auto_sync_deps=true`**：Scanner 每小时扫一次，只管 `constraint_source != 'manual'` 的记录。用户仍可通过 API 手动增删 `constraint_source=manual` 的依赖
- **`auto_sync_deps=false`**：Scanner 不扫，所有依赖由用户手动管理

**没有竞态问题** — 手动 CRUD 和 Scanner 操作不同 `constraint_source` 的记录，互不冲突。

### Manifest 检测策略

Scanner 使用可插拔的 Parser Registry，每个 parser 声明 `file_patterns` 和 `detection_method`，通过 glob 自动发现匹配的文件。

**已实现的 11 个 parser：**

| 生态 | Parser | 检测文件 | detection_method | 版本提取 |
|------|--------|---------|-----------------|---------|
| **Python** | PipRequirements | `requirements.txt`, `requirements/*.txt` | `pip-requirements` | `==x.y.z` 精确版本 |
| **Python** | PyprojectToml | `pyproject.toml` | `pyproject-toml` | PEP 508 约束 |
| **Java/Kotlin** | MavenPom | `**/pom.xml` | `maven-pom` | 支持 `${property}` 解析 |
| **Java/Kotlin** | GradleBuild | `**/build.gradle`, `**/build.gradle.kts` | `gradle` | Groovy / Kotlin DSL |
| **Go** | GoMod | `go.mod` | `go-mod` | GitHub/GitLab URL 自动推导 |
| **Rust** | CargoToml | `**/Cargo.toml` | `cargo-toml` | 支持 git 依赖 |
| **C/C++** | Conan | `conanfile.txt` | `conan` | `name/version` 格式 |
| **C/C++** | VcpkgJson | `vcpkg.json` | `vcpkg` | string 和 object 格式 |
| **C/C++** | CMakeFind | `**/CMakeLists.txt` | `cmake-find-package` | `find_package()` best-effort，~70-80% 精度 |
| **C/C++/通用** | GitSubmodule | `.gitmodules` | `git-submodule` | 提取 repo URL |
| **Solidity** | FoundryToml | `foundry.toml` | `foundry-soldeer` | Soldeer 依赖格式 |

**已知未覆盖（用户需手动添加）：**

- Python: `setup.py`、`Pipfile`
- JavaScript: `package.json`、`yarn.lock`、`pnpm-lock.yaml`
- C/C++: `conanfile.py`（Python DSL，解析复杂）、`CMakeLists.txt` 中的 `FetchContent`
- 其他语言的包管理器

**C/C++ 没有统一的包管理器**，Scanner 分层尝试：

1. 查包管理器配置：`conanfile.txt`（Conan）、`vcpkg.json`（vcpkg）
2. 查 git submodule：`.gitmodules`
3. 查 CMake：`**/CMakeLists.txt` 中的 `find_package()`（best-effort，有误报）
4. 都没有 → 用户需手动添加（`constraint_source=manual`）

### 第一步的产出

| 表 | 数据 |
|----|------|
| `projects` | 项目记录 |
| `libraries` | 所有依赖的 library（upsert） |
| `project_dependencies` | 项目 ↔ library 关联，含版本约束 |

此时系统知道了每个项目依赖哪些库、用的什么版本。下一步：监控这些 library 的代码变更。

### 注意：Snapshot 不在此步

Snapshot（call graph 静态分析）是独立的重量级操作，供 Reachability Analyzer 按需构建/查缓存。与依赖扫描完全解耦。