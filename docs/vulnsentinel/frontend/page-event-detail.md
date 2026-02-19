# 事件详情页 — Event Detail

> 路由: `/event/:id`

从主页 Recent Activity 的条目点击进入。展示一个事件（commit/PR/tag）的完整信息，如果是 bugfix 则展示上游漏洞分析和客户影响。

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  ◉ VulnSentinel                                                O2Lab  │  Admin ▾ │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ← Back to Dashboard                                                             │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  EVENT: commit                                            2 min ago         │ │
│  │  Library: zlib/zlib                                                         │ │
│  │  Commit: a1b2c3d                                                            │ │
│  │  Author: madler                                                             │ │
│  │  Message: "fix: deflate buffer overread when input len > window"             │ │
│  │  Classification: ⚠ SECURITY BUGFIX  (92%)                                   │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│  ╔══════════════════════════════════════════════════════════════════════════════╗ │
│  ║  UPSTREAM VULNERABILITY #42                              status: published  ║ │
│  ╠══════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                            ║ │
│  ║  AI Analysis                                                               ║ │
│  ║  ──────────────────────────────────────────────────────────────────────     ║ │
│  ║                                                                            ║ │
│  ║  Vuln Type:       Buffer Over-read (CWE-126)                               ║ │
│  ║  Severity:        HIGH                                                     ║ │
│  ║  Affected Versions: < v1.3.2                                               ║ │
│  ║                                                                            ║ │
│  ║  Reasoning:                                                                ║ │
│  ║  该 commit 在 deflate.c 的 inflate_fast() 中增加了输入长度与窗口大小的       ║ │
│  ║  边界检查。修复前，当 input len 超过 window size 时，memcpy 会读取越界       ║ │
│  ║  内存。这是一个典型的 buffer over-read 漏洞。                                ║ │
│  ║                                                                            ║ │
│  ║  Upstream PoC                                                              ║ │
│  ║  ──────────────────────────────────────────────────────────────────────     ║ │
│  ║  Source: oss-fuzz issue #58234                                             ║ │
│  ║  Reproducer: clusterfuzz-testcase-minimized-zlib-deflate-58234             ║ │
│  ║  Status: collected ✅                                                      ║ │
│  ║                                                                            ║ │
│  ║  Client Impact                                                             ║ │
│  ║  ──────────────────────────────────────────────────────────────────────     ║ │
│  ║                                                                            ║ │
│  ║  ┌──────────────┬──────────────┬───────────────┬────────────────────────┐   ║ │
│  ║  │ Project      │ Version Used │ Affected?     │ Status                 │   ║ │
│  ║  ├──────────────┼──────────────┼───────────────┼────────────────────────┤   ║ │
│  ║  │ ProjA        │ v1.3.1       │ ⚠ YES         │ reported               │   ║ │
│  ║  ├──────────────┼──────────────┼───────────────┼────────────────────────┤   ║ │
│  ║  │ ProjC        │ v1.3.2       │ ✅ NO          │ not_affect             │   ║ │
│  ║  └──────────────┴──────────────┴───────────────┴────────────────────────┘   ║ │
│  ║                                                                            ║ │
│  ╚══════════════════════════════════════════════════════════════════════════════╝ │
│                                                                                  │
│  Diff                                                                            │
│  ────────────────────────────────────────────────────────────────────────────     │
│                                                                                  │
│  deflate.c                                                                       │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  @@ -1042,6 +1042,8 @@ local int inflate_fast(strm, start)                  │ │
│  │       if (copy > have) copy = have;                                          │ │
│  │  +    if (copy > wnext)                                                      │ │
│  │  +        copy = wnext;                                                      │ │
│  │       zmemcpy(put, next, copy);                                              │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## 三层结构在此页的体现

```
Event (events 表)                    ← 事件信息头 + Diff
  └── Upstream Vuln (upstream_vulns) ← AI Analysis + Upstream PoC
        ├── Client Vuln: ProjA       ← Client Impact 表中一行
        └── Client Vuln: ProjC       ← Client Impact 表中一行
```

## 区域说明

| 区域 | 数据来源 | 说明 |
|------|----------|------|
| **事件信息头** | events 表 | 事件类型、库名、commit/PR/tag 详情、时间、AI classification + confidence |
| **Upstream Vulnerability** | upstream_vulns 表 | 仅 `is_bugfix=true` 时展示，含漏洞分析、上游 PoC、客户影响 |
| **AI Analysis** | upstream_vulns 表 | 漏洞详细分析：漏洞类型、严重程度、受影响版本、推理过程 |
| **Upstream PoC** | upstream_vulns 表 | 从上游收集到的 PoC（oss-fuzz issue、regression test 等），如有 |
| **Client Impact** | client_vulns 表 + 分析流水线 | 每个客户项目的影响判定和当前状态 |
| **Diff** | 实时 GitHub API | 代码变更内容，高亮关键修复行 |

## Client Impact 状态

Client Impact 表中的 Status 列显示两种情况：

**分析进行中（尚未生成 client_vuln）：**

| 状态 | 含义 |
|------|------|
| `pending` | 等待分析 |
| `path_searching` | 在客户代码调用图中搜索到达漏洞函数的路径 |
| `poc_generating` | 找到可达路径，正在尝试生成 PoC |
| `verified` | PoC 成功，已生成 client_vuln |
| `not_affect` | 未找到可达路径或 PoC 失败，已生成 client_vuln |

**分析完成（已生成 client_vuln）：**

显示 client_vuln 的状态：`recorded` / `reported` / `confirmed` / `fixed` / `not_affect`

## 交互

| 操作 | 跳转 |
|------|------|
| 点击事件信息头中 Library 名 | [库详情页](page-library-detail.md) |
| 点击 Client Impact 表中 Project 名 | [项目详情页](page-project-detail.md) |
