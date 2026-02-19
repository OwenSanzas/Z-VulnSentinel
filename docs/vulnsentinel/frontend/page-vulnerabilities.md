# 漏洞列表页 — Vulnerabilities

> 路由: `/vulnerabilities`
> 数据来源：client_vulns 表（客户漏洞）

从主页 Vuln Recorded / Reported / Confirmed 卡片点击进入。卡片决定默认筛选状态。

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  ◉ VulnSentinel                                                O2Lab  │  Admin ▾ │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ← Back to Dashboard                                                             │
│                                                                                  │
│  Client Vulnerabilities                                                          │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐   │
│  │  Filters:                                                                 │   │
│  │                                                                           │   │
│  │  Status:   [ All ▾ ]    Severity: [ All ▾ ]    Library: [ All ▾ ]         │   │
│  │  Project:  [ All ▾ ]    Date:     [ Last 30 days ▾ ]                      │   │
│  └────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  Recorded: 47    Reported: 12    Confirmed: 9    Fixed: 5                        │
│                                                                                  │
│  ┌────┬──────────┬──────────────┬─────────────┬────────────────────┬──────┬─────────────┐
│  │ ## │ Date     │ Library      │ Project     │ Summary            │ Sev. │ Status      │
│  ├────┼──────────┼──────────────┼─────────────┼────────────────────┼──────┼─────────────┤
│  │  1 │ Feb 15   │ curl/curl    │ ProjA       │ HTTP/2 stream      │ HIGH │ confirmed   │
│  │    │          │              │             │ reset UAF          │      │             │
│  ├────┼──────────┼──────────────┼─────────────┼────────────────────┼──────┼─────────────┤
│  │  2 │ Feb 12   │ zlib         │ ProjA       │ deflate buffer     │ HIGH │ reported    │
│  │    │          │              │             │ overread           │      │             │
│  ├────┼──────────┼──────────────┼─────────────┼────────────────────┼──────┼─────────────┤
│  │  3 │ Feb 02   │ curl/curl    │ ProjA       │ TLS session ticket │ MED  │ reported    │
│  │    │          │              │             │ lifetime           │      │             │
│  ├────┼──────────┼──────────────┼─────────────┼────────────────────┼──────┼─────────────┤
│  │  4 │ Jan 28   │ openssl      │ ProjA       │ X.509 name         │ LOW  │ recorded    │
│  │    │          │              │             │ constraint bypass  │      │             │
│  ├────┼──────────┼──────────────┼─────────────┼────────────────────┼──────┼─────────────┤
│  │  5 │ Jan 28   │ openssl      │ ProjB       │ X.509 name         │ LOW  │ not affect  │
│  │    │          │              │             │ constraint bypass  │      │             │
│  ├────┼──────────┼──────────────┼─────────────┼────────────────────┼──────┼─────────────┤
│  │ ...│          │              │             │                    │      │             │
│  └────┴──────────┴──────────────┴─────────────┴────────────────────┴──────┴─────────────┘
│                                                                                  │
│                                          ← Prev  │  Next →     20 / page ▾            │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

> 注：每行是一条 client_vuln（一个客户项目 × 一个上游漏洞）。同一个上游漏洞影响多个项目时，会产生多行，各自有独立状态。如上表第 4、5 行共享同一个上游漏洞（openssl X.509），但 ProjA 为 recorded，ProjB 为 not affect。

## 筛选器

| 筛选项 | 选项 | 说明 |
|--------|------|------|
| **Status** | All / Recorded / Reported / Confirmed / Fixed / Not Affect | 客户漏洞状态 |
| **Severity** | All / Critical / High / Medium / Low | 严重程度（来自 upstream_vuln） |
| **Library** | 下拉选择监控中的库 | 按上游库筛选 |
| **Project** | 下拉选择合作项目 | 按客户项目筛选 |
| **Date** | Last 7 days / 30 days / 90 days / All time | 时间范围 |

从主页卡片跳转时自动设置筛选：
- 点 Vuln Recorded → Status = All
- 点 Vuln Reported → Status = Reported
- 点 Vuln Confirmed → Status = Confirmed
- 点 Vuln Fixed → Status = Fixed

## 列说明

| 列 | 说明 |
|----|------|
| **Date** | client_vuln 首次检测到的日期 |
| **Library** | 上游漏洞所在的依赖库（来自 upstream_vuln） |
| **Project** | 受影响的客户项目（每行一个） |
| **Summary** | 漏洞简要描述（来自 upstream_vuln） |
| **Sev.** | 严重程度：Critical / High / Medium / Low（来自 upstream_vuln） |
| **Status** | client_vuln 当前状态 |

## 交互

| 操作 | 跳转 |
|------|------|
| 点击漏洞行 | [事件详情页](page-event-detail.md)（定位到对应 upstream_vuln 的触发事件） |
| 点击 Library 名 | [库详情页](page-library-detail.md) |
| 点击 Project 名 | [项目详情页](page-project-detail.md) |
