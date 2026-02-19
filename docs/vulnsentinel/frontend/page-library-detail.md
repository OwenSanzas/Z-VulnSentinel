# 库详情页 — Library Detail

> 路由: `/library/:id`

从主页 Monitored Libraries 的 `view details →` 进入。

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  ◉ VulnSentinel                                                O2Lab  │  Admin ▾ │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ← Back to Dashboard                                                             │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │  curl/curl                                              latest: v8.12.1     │ │
│  │  https://github.com/curl/curl                                               │ │
│  │  Monitoring since: 2025-09-15           Total commits tracked: 1,247        │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│  Used By                                                                         │
│  ────────────────────────────────────────────────────────────────────────────     │
│                                                                                  │
│  ┌──────────────┬──────────────────┬──────────────┬────────────────┬───────────┐ │
│  │ Project      │ Constraint       │ Resolved     │ Source         │ Status    │ │
│  ├──────────────┼──────────────────┼──────────────┼────────────────┼───────────┤ │
│  │ ProjA →      │ >= 8.10, < 9.0   │ v8.10.0      │ conanfile.txt  │ ⚠ vuln    │ │
│  │ ProjB →      │ = 8.12.1         │ v8.12.1      │ CMakeLists.txt │ ✅ patched │ │
│  └──────────────┴──────────────────┴──────────────┴────────────────┴───────────┘ │
│                                                                                  │
│  Upstream Vulnerabilities                                                        │
│  ────────────────────────────────────────────────────────────────────────────     │
│                                                                                  │
│  ┌────┬──────────┬──────────────────────────────────┬──────────┬────────────┐    │
│  │ ## │ Date     │ Summary                          │ Severity │ Clients    │    │
│  ├────┼──────────┼──────────────────────────────────┼──────────┼────────────┤    │
│  │  1 │ Feb 15   │ HTTP/2 stream reset UAF          │ HIGH     │ ProjA ⚠    │    │
│  │    │          │ commit d4e5f6a                    │          │ ProjB ✅    │    │
│  ├────┼──────────┼──────────────────────────────────┼──────────┼────────────┤    │
│  │  2 │ Feb 02   │ TLS session ticket lifetime      │ MEDIUM   │ ProjA ⚠    │    │
│  │    │          │ PR #12847                        │          │            │    │
│  ├────┼──────────┼──────────────────────────────────┼──────────┼────────────┤    │
│  │  3 │ Jan 18   │ HSTS bypass via redirect         │ LOW      │ analyzing  │    │
│  │    │          │ commit c7d8e9f                    │          │            │    │
│  └────┴──────────┴──────────────────────────────────┴──────────┴────────────┘    │
│                                                                                  │
│  Recent Commits                                                                  │
│  ────────────────────────────────────────────────────────────────────────────     │
│                                                                                  │
│  ● 3 hours ago   d4e5f6a  "http2: fix stream reset handling"    ⚠ bugfix        │
│  ● 1 day ago     a2b3c4d  "docs: update RELEASE-NOTES"                          │
│  ● 1 day ago     e5f6a7b  "cmake: improve CURL_USE_PKGCONFIG"                   │
│  ● 2 days ago    b8c9d0e  "tls: fix session ticket lifetime"    ⚠ bugfix        │
│  ● 3 days ago    f1a2b3c  "test: add http3 connection reuse"                     │
│  ● 5 days ago    c4d5e6f  "url: remove redundant cast"                           │
│                                                                                  │
│  ...                                                          show all →         │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## 区域说明

| 区域 | 说明 |
|------|------|
| **库信息头** | 库名、仓库 URL、latest 版本、监控起始时间、已追踪 commit 数 |
| **Used By** | 使用该库的合作项目，显示版本约束、实际解析版本、约束来源、是否存在活跃 client_vuln |
| **Upstream Vulnerabilities** | 该库上检测到的上游漏洞（upstream_vulns 表），含严重程度、影响哪些客户项目 |
| **Recent Commits** | 该库的 commit 流（events 表），bugfix 类标注 ⚠ |

## 状态定义

参见 [README.md 三层数据模型](../frontend/README.md#三层数据模型)。

- Upstream Vulnerabilities 表的 Clients 列展示每个客户项目的 client_vuln 状态
- ⚠ 表示存在活跃 client_vuln（recorded / reported / confirmed）
- ✅ 表示 not_affect 或 fixed
- `analyzing` 表示 upstream_vuln 仍在分析中，尚未生成 client_vulns
- `error` 表示分析失败，显示错误原因

## 交互

| 操作 | 跳转 |
|------|------|
| 点击 `← Back to Dashboard` | [主页](page-home.md) |
| 点击 Used By 表中项目名 | [项目详情页](page-project-detail.md) |
| 点击 Upstream Vulnerabilities 表中漏洞行 | [上游漏洞详情页](page-upstream-vuln-detail.md) |
| 点击 Recent Commits 中 ⚠ bugfix 项 | [事件详情页](page-event-detail.md) |

## 版本约束模型

依赖版本从客户代码中智能提取，不同构建系统的来源不同：

| 来源文件 | 示例 | 提取出的约束 |
|----------|------|-------------|
| CMakeLists.txt | `find_package(CURL 8.10 REQUIRED)` | `>= 8.10` |
| configure.ac | `PKG_CHECK_MODULES([CURL], [libcurl >= 8.10.0])` | `>= 8.10.0` |
| conanfile.txt | `curl/[>=8.10.0 <9.0]` | `>= 8.10.0, < 9.0` |
| vcpkg.json | `"version>=": "8.10.0"` | `>= 8.10.0` |
| git submodule | commit SHA | `= commit:a1b2c3d` |
| 无显式声明 | 系统安装 / 无版本号 | `unknown` → **默认假设受影响** |

每个项目-库关系存储三个字段：

| 字段 | 说明 |
|------|------|
| **constraint** | 原始版本约束表达式（`>= 8.10, < 9.0`） |
| **resolved** | 实际解析/构建使用的版本（`v8.10.0`） |
| **source** | 约束的提取来源文件（`conanfile.txt`） |

**策略：无约束 = 假设受影响。** 当 constraint 为 `unknown` 时，系统默认该项目受所有该库漏洞影响。客户可在 Dashboard 上手动标注实际版本以消除误报。
