# Frontend - React Dashboard

> 当前版本：内部使用（O2Lab 团队）
> 全站强制登录，未认证不显示任何内容

## 页面索引

| 页面 | 路由 | 文档 |
|------|------|------|
| 登录 | `/login` | [page-login.md](page-login.md) |
| 主页 | `/` | [page-home.md](page-home.md) |
| 项目列表 | `/projects` | [page-projects.md](page-projects.md) |
| 漏洞列表 | `/vulnerabilities` | [page-vulnerabilities.md](page-vulnerabilities.md) |
| 库详情 | `/library/:id` | [page-library-detail.md](page-library-detail.md) |
| 项目详情 | `/project/:id` | [page-project-detail.md](page-project-detail.md) |
| 事件详情 | `/event/:id` | [page-event-detail.md](page-event-detail.md) |

## 数据需求

所有页面的数据字段定义见 [data-requirements.md](data-requirements.md)。

## 全局规范

- **所有表格必须分页**，默认每页 20 条，支持用户切换（20 / 50 / 100）
- 分页由后端实现，使用 cursor-based pagination（`cursor`, `page_size`, `next_cursor`, `has_more`, `total`），前端不做全量加载

## 三层数据模型

系统数据分为三层，每层有独立的状态：

```
events (所有捕获的 commit/PR/tag/issue)
  │
  │  AI 判定为 bugfix → 创建
  ▼
upstream_vulns (确认的上游安全修复)
  │
  │  检查每个客户项目 → 逐个创建
  ▼
client_vulns (客户×上游漏洞，业务核心)
```

### 事件（event）

原始监控数据，不设状态。仅记录 `is_bugfix` 标记（AI 判定结果）。

### 上游漏洞状态（upstream vuln status）

仅记录 AI 确认为安全修复的 commit，用于库详情页展示：

| 状态 | 含义 |
|------|------|
| `analyzing` | 已确认是 bugfix，正在分析漏洞类型、严重程度、影响版本范围 |
| `published` | 分析完成，已开始检查客户影响 |

### 客户漏洞状态（client vuln status）

上游漏洞 × 客户项目 = 一条 client_vuln，用于漏洞列表、项目详情的展示和筛选：

| 状态 | 含义 |
|------|------|
| `recorded` | 确认客户版本在受影响范围内，已记录 |
| `reported` | 已通知客户 |
| `confirmed` | PoC 验证成功，客户代码可被利用 |
| `fixed` | 客户已修复该漏洞 |
| `not_affect` | 分析完成，客户不受影响 |

**向前包含：** Fixed ⊇ Confirmed ⊇ Reported ⊇ Recorded。一个客户漏洞到达 `fixed`，意味着它一定经历过 `recorded → reported → confirmed → fixed` 全过程。

### 客户分析流水线状态（analysis pipeline status）

用于事件详情页，展示针对每个客户项目的分析进度（分析完成后生成 client_vuln）：

| 状态 | 含义 |
|------|------|
| `pending` | 等待分析 |
| `path_searching` | 在客户代码调用图中搜索到达漏洞函数的路径 |
| `poc_generating` | 找到可达路径，正在尝试生成 PoC |
| `verified` | PoC 成功，生成 client_vuln（status=recorded） |
| `not_affect` | 未找到可达路径或 PoC 失败，生成 client_vuln（status=not_affect） |
