# 前端数据需求

> 从每个页面的每个区域出发，列出需要后端提供的数据。
> 数据基于三层模型：events → upstream_vulns → client_vulns。

## 登录 `/login`

| 数据 | 方向 | 类型 | 说明 |
|------|------|------|------|
| username | 请求 | string | 用户名 |
| password | 请求 | string | 密码 |
| token | 响应 | string | JWT token，登录成功后返回 |

---

## 主页 `/`

### 统计卡片（统计 client_vulns）

| 数据 | 类型 | 说明 |
|------|------|------|
| projects_count | int | 合作项目总数 |
| vuln_recorded_count | int | 已记录的客户漏洞数（含 reported / confirmed / fixed） |
| vuln_reported_count | int | 已上报的客户漏洞数（含 confirmed / fixed） |
| vuln_confirmed_count | int | 已确认的客户漏洞数（含 fixed） |
| vuln_fixed_count | int | 已修复的客户漏洞数 |

### Node Storage

| 数据 | 类型 | 说明 |
|------|------|------|
| disk_total_bytes | int | `/dev/root` 总容量 |
| disk_used_bytes | int | 已使用容量 |
| disk_usage_percent | float | 使用百分比 |

### Monitored Libraries（分页）

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | 库唯一标识 |
| name | string | 库名（如 `curl/curl`） |
| latest_version | string | 库最新版本 |
| used_by | list | 使用该库的项目列表，每项含 `project_id`, `project_name`, `constraint`, `resolved_version` |
| last_activity_at | datetime | 最后一次捕获到的事件时间 |

### Recent Activity（分页，数据来源：events 表）

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | 事件唯一标识 |
| type | enum | `commit` / `pr_merge` / `tag` / `bug_issue` |
| library_id | string | 所属库标识 |
| library_name | string | 所属库名 |
| title | string | commit message / PR 标题 / tag 名 / issue 标题 |
| ref | string | commit SHA / PR 编号 / tag 名 / issue 编号 |
| is_bugfix | bool | 是否被 AI 判定为安全修复 |
| created_at | datetime | 事件发生时间 |

---

## 项目列表 `/projects`（分页）

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | 项目唯一标识 |
| name | string | 项目名 |
| repo_url | string | 仓库地址 |
| current_version | string | 当前版本（tag 或 branch@commit） |
| deps_count | int | 依赖库数量 |
| vuln_count | int | 活跃客户漏洞数（client_vulns，不含 not_affect） |
| monitoring_since | date | 开始监控日期 |
| last_update_at | datetime | 最近一次代码更新时间 |

---

## 漏洞列表 `/vulnerabilities`（分页 + 筛选，数据来源：client_vulns 表）

### 筛选参数

| 参数 | 类型 | 说明 |
|------|------|------|
| status | enum | recorded / reported / confirmed / fixed / not_affect |
| severity | enum | critical / high / medium / low |
| library_id | string | 按上游库筛选 |
| project_id | string | 按客户项目筛选 |
| date_from | date | 起始时间 |
| date_to | date | 结束时间 |

### 返回数据

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | client_vuln 唯一标识 |
| upstream_vuln_id | string | 关联的上游漏洞标识 |
| detected_at | datetime | 首次检测时间 |
| library_id | string | 上游库标识（用于跳转） |
| library_name | string | 上游库名（来自 upstream_vuln → library） |
| project_id | string | 受影响的客户项目标识（用于跳转） |
| project_name | string | 受影响的客户项目名 |
| summary | string | 漏洞简要描述（来自 upstream_vuln） |
| severity | enum | critical / high / medium / low（来自 upstream_vuln） |
| status | enum | recorded / reported / confirmed / fixed / not_affect |
| recorded_at | datetime | 记录时间 |
| reported_at | datetime | 通知客户时间（可为空） |
| confirmed_at | datetime | PoC 确认时间（可为空） |
| fixed_at | datetime | 修复时间（可为空） |
| updated_at | datetime | 最后状态变更时间 |

### 统计摘要（筛选后）

| 数据 | 类型 | 说明 |
|------|------|------|
| total_recorded | int | 当前筛选条件下的 recorded 数 |
| total_reported | int | 当前筛选条件下的 reported 数 |
| total_confirmed | int | 当前筛选条件下的 confirmed 数 |
| total_fixed | int | 当前筛选条件下的 fixed 数 |

---

## 库详情 `/library/:id`

### 库信息头

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | 库唯一标识 |
| name | string | 库名 |
| repo_url | string | 仓库 URL |
| latest_version | string | 最新版本 |
| monitoring_since | date | 开始监控日期 |
| total_commits_tracked | int | 已追踪的 commit 数（events 表） |

### Used By

| 数据 | 类型 | 说明 |
|------|------|------|
| project_id | string | 项目标识 |
| project_name | string | 项目名 |
| constraint | string | 版本约束表达式（`>= 8.10, < 9.0`） |
| resolved_version | string | 实际使用版本 |
| constraint_source | string | 约束提取来源文件 |
| is_vulnerable | bool | 当前是否存在活跃 client_vuln |

### Upstream Vulnerabilities（分页，数据来源：upstream_vulns 表）

该库上检测到的上游漏洞列表：

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | upstream_vuln 唯一标识 |
| commit_id | string | 触发的 commit SHA |
| vuln_type | string | 漏洞类型（如 CWE-126 Buffer Over-read） |
| severity | enum | critical / high / medium / low |
| status | enum | analyzing / published / error |
| error_message | string | 错误原因（仅 status=error 时有值） |
| affected_clients | list[object] | 受影响的客户项目列表，每项含 `project_id`, `project_name`, `client_vuln_status` |
| detected_at | datetime | 首次检测时间 |
| published_at | datetime | 分析完成时间（status=published 时记录） |
| updated_at | datetime | 最后状态变更时间 |

### Recent Commits（分页，数据来源：events 表）

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | 事件标识 |
| sha | string | commit hash |
| message | string | commit message |
| is_bugfix | bool | 是否被判定为安全修复 |
| created_at | datetime | commit 时间 |

---

## 项目详情 `/project/:id`

### 项目信息头

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | 项目唯一标识 |
| name | string | 项目名 |
| repo_url | string | 仓库地址 |
| contact | string | 联系人（被通知人） |
| current_version | string | 当前版本 |
| monitoring_since | date | 开始监控日期 |
| last_update_at | datetime | 最近更新时间 |

### Vulnerabilities（分页，数据来源：client_vulns 表）

固定 `project_id` 筛选。含统计摘要：

| 数据 | 类型 | 说明 |
|------|------|------|
| total_recorded | int | 该项目的 recorded 数 |
| total_reported | int | 该项目的 reported 数 |
| total_confirmed | int | 该项目的 confirmed 数 |
| total_fixed | int | 该项目的 fixed 数 |

每条 client_vuln 的返回字段同漏洞列表。

### Dependencies（分页）

| 数据 | 类型 | 说明 |
|------|------|------|
| library_id | string | 库标识 |
| library_name | string | 库名 |
| constraint | string | 版本约束表达式 |
| resolved_version | string | 实际使用版本 |
| constraint_source | string | 约束来源文件 |
| vuln_count | int | 该库当前影响该项目的 client_vuln 数 |
| status | enum | clean / vulnerable / assumed |

### Snapshots（分页）

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | 快照标识 |
| version | string | 快照对应的版本 |
| trigger | enum | tag_push / manual / scheduled |
| is_active | bool | 是否为当前活跃快照 |
| created_at | datetime | 快照时间 |

---

## 事件详情 `/event/:id`

### 事件信息头（数据来源：events 表）

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | 事件标识 |
| type | enum | commit / pr_merge / tag / bug_issue |
| library_id | string | 所属库标识 |
| library_name | string | 所属库 |
| ref | string | commit SHA / PR 编号 / tag 名 |
| author | string | 作者 |
| message | string | 完整 message / 标题 |
| is_bugfix | bool | 是否被 AI 判定为安全修复（classification=security_bugfix 时为 true） |
| classification | enum | security_bugfix / normal_bugfix / refactor / feature / other |
| confidence | float | AI 置信度（0-1） |
| created_at | datetime | 事件时间 |

### Upstream Vuln（数据来源：upstream_vulns 表，仅 is_bugfix=true 时展示）

由该事件触发创建的上游漏洞（通常 1 个，极少数情况多个）：

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | upstream_vuln 标识 |
| vuln_type | string | 漏洞类型（如 CWE-126 Buffer Over-read） |
| severity | enum | critical / high / medium / low |
| affected_versions | string | 受影响版本范围 |
| status | enum | analyzing / published / error |
| error_message | string | 错误原因（仅 status=error 时有值） |
| reasoning | string | AI 对漏洞的详细分析推理 |
| detected_at | datetime | 首次检测时间 |
| published_at | datetime | 分析完成时间 |
| updated_at | datetime | 最后状态变更时间 |

### Diff（实时从 GitHub 拉取，不入库）

| 数据 | 类型 | 说明 |
|------|------|------|
| files | list | 变更文件列表 |
| files[].path | string | 文件路径 |
| files[].diff | string | diff 内容 |

### Client Impact（数据来源：分析流水线 + client_vulns 表）

每个使用该库的客户项目的分析状态：

| 数据 | 类型 | 说明 |
|------|------|------|
| project_id | string | 项目标识 |
| project_name | string | 项目名 |
| version_used | string | 使用版本 |
| is_affected | bool | 是否受影响 |
| analysis_status | enum | pending / path_searching / poc_generating / verified / not_affect / error |
| error_message | string | 错误原因（仅 analysis_status=error 时有值） |
| started_at | datetime | 开始分析时间 |
| completed_at | datetime | 分析结束时间（可为空） |
| client_vuln_id | string | 分析完成后生成的 client_vuln 标识（可为空） |
| client_vuln_status | enum | recorded / reported / confirmed / fixed / not_affect（可为空） |

### Upstream PoC（属于 upstream_vuln）

| 数据 | 类型 | 说明 |
|------|------|------|
| source | string | 来源（如 oss-fuzz issue 编号） |
| reproducer | string | 复现文件名 |
| collected | bool | 是否已收集 |

---

## 上游漏洞详情 `/upstream-vuln/:id`

### 漏洞信息头（数据来源：upstream_vulns 表）

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | upstream_vuln 标识 |
| library_id | string | 所属库标识 |
| library_name | string | 所属库名 |
| commit_id | string | 触发的 commit SHA |
| vuln_type | string | 漏洞类型（如 CWE-126 Buffer Over-read） |
| severity | enum | critical / high / medium / low |
| affected_versions | string | 受影响版本范围 |
| status | enum | analyzing / published / error |
| error_message | string | 错误原因（仅 status=error 时有值） |
| reasoning | string | AI 对漏洞的详细分析推理 |
| detected_at | datetime | 首次检测时间 |
| published_at | datetime | 分析完成时间 |
| updated_at | datetime | 最后状态变更时间 |

### Diff（实时从 GitHub 拉取）

同事件详情页 Diff 区域。

### Upstream PoC

同事件详情页。

### Client Impact（分页）

| 数据 | 类型 | 说明 |
|------|------|------|
| client_vuln_id | string | client_vuln 标识（可为空，分析中时无） |
| project_id | string | 项目标识 |
| project_name | string | 项目名 |
| version_used | string | 使用版本 |
| is_affected | bool | 是否受影响 |
| status | string | pipeline 状态或 client_vuln 状态 |
| updated_at | datetime | 最后更新时间 |

---

## 客户漏洞详情 `/client-vuln/:id`

### 漏洞信息头（数据来源：client_vulns + upstream_vulns 表）

| 数据 | 类型 | 说明 |
|------|------|------|
| id | string | client_vuln 标识 |
| project_id | string | 项目标识 |
| project_name | string | 项目名 |
| library_id | string | 上游库标识 |
| library_name | string | 上游库名 |
| upstream_vuln_id | string | 关联的上游漏洞标识 |
| upstream_vuln_summary | string | 上游漏洞摘要（类型 + CWE） |
| upstream_vuln_severity | enum | critical / high / medium / low |
| status | enum | recorded / reported / confirmed / fixed / not_affect |

### Status Timeline

| 数据 | 类型 | 说明 |
|------|------|------|
| recorded_at | datetime | 记录时间 |
| reported_at | datetime | 通知客户时间（可为空） |
| confirmed_at | datetime | PoC 确认时间（可为空） |
| fixed_at | datetime | 修复时间（可为空） |

### Version Analysis

| 数据 | 类型 | 说明 |
|------|------|------|
| constraint | string | 版本约束表达式 |
| constraint_source | string | 约束提取来源文件 |
| resolved_version | string | 客户实际使用版本 |
| fix_version | string | 修复版本（来自 upstream_vuln affected_versions） |
| verdict | string | 判定说明（如 "v1.3.1 < v1.3.2 — 客户版本在受影响范围内"） |

### Reachable Path

| 数据 | 类型 | 说明 |
|------|------|------|
| found | bool | 是否找到可达路径 |
| call_chain | list[object] | 调用链，每项含 `function_name`, `file_path`, `line_number` |

### PoC Results

| 数据 | 类型 | 说明 |
|------|------|------|
| poc_status | enum | pending / generating / success / failed / not_attempted |
| poc_type | string | 基于上游 PoC 改造 / 自动生成 |
| trigger_input | string | 触发漏洞的输入描述 |
| crash_info | string | sanitizer 输出 / crash backtrace |
| reproduce_command | string | 复现命令行 |

### Report（仅 status ≥ reported 时有值）

| 数据 | 类型 | 说明 |
|------|------|------|
| reported_to | string | 通知对象（邮箱） |
| reported_at | datetime | 通知时间 |
| method | enum | email / webhook / manual |
| content_summary | string | 通知内容摘要 |
