# Impact Engine

> 将已发布的上游漏洞（UpstreamVuln）与依赖该库的项目关联，创建 ClientVuln 记录。对应十步流程中的**步骤 8（版本匹配 / 影响评估）**。

## 概述

Impact Engine 是流水线中紧跟 Vuln Analyzer 的第五个 Engine。Analyzer 解决了"这个安全修复修了什么漏洞"，Impact Engine 解决"哪些项目可能受此漏洞影响"。

**职责：**

- 从 `upstream_vulns` 表中拉取 `status = 'published'` 且尚无对应 `client_vulns` 记录的漏洞
- 通过 `library_id` 查找所有依赖该库的项目（`project_dependencies` 表）
- 为每个依赖项目创建 `client_vulns` 记录（`pipeline_status = 'pending'`），等待 Reachability Analyzer 处理

**特点：**

- 无 LLM、无 Agent — 纯数据库操作
- Pass-through 策略 — 不做版本匹配，依赖了该 library 即创建记录
- 幂等 — unique constraint `(upstream_vuln_id, project_id)` 防止重复创建

---

## 为什么不做版本匹配

这是 Impact Engine 最关键的设计决策。按照流水线原始设计，步骤 8 应做"版本约束比较"——将 `affected_versions` 与 `constraint_expr` / `resolved_version` 进行语义版本匹配。但我们**有意不实现**这一步：

### affected_versions 不可靠

`affected_versions` 是 VulnAnalyzer 的 LLM 产出，本质上是自然语言字符串。格式不统一且不稳定：

```
"< 8.12.0"
"7.50.0 - 8.11.1"
">= 7.0.0, < 8.10.0"
"all versions before 3.2"
"1.x branch"
```

### 语义版本解析极其复杂

- semver（`^1.2.3`）、calver（`2024.01`）、自由文本（`"latest"`）
- C/C++ 生态没有统一的版本命名标准
- 范围组合（`>= 1.0 AND < 2.0 OR >= 3.0`）
- 要覆盖这些情况需要大量代码，且正确性难以保证

### 真正的影响判断应由代码可达性决定

版本号只是粗略的代理指标。真正有意义的问题是：**项目代码是否调用了漏洞相关的函数路径**。这正是 Reachability Analyzer 的职责。

### Pass-through 策略

```
依赖了该 library → 创建 client_vuln → 交给 Reachability Analyzer 判断
```

版本信息（`constraint_expr`, `resolved_version`, `constraint_source`）仍然从 `project_dependencies` 复制到 `client_vulns`，供人工参考，但**不参与自动化决策**。

---

## 双模式设计

### 独立模式（Standalone）

纯函数式，不依赖数据库。

```python
# vulnsentinel/engines/impact_engine/assessor.py

@dataclass
class ImpactResult:
    """单个 upstream_vuln + project_dependency 的匹配结果。"""
    upstream_vuln_id: uuid.UUID
    project_id: uuid.UUID
    constraint_expr: str | None       # 从 project_dependency 复制
    resolved_version: str | None      # 从 project_dependency 复制
    constraint_source: str | None     # 从 project_dependency 复制

def assess_impact(
    upstream_vuln_id: uuid.UUID,
    dependencies: list[ProjectDependency],
) -> list[ImpactResult]:
    """
    独立模式核心函数。不涉及 DB。

    对每个 dependency 生成一个 ImpactResult。
    当前为 pass-through：所有依赖项目都视为潜在受影响。
    未来可在此处加入版本匹配逻辑进行快速否定。
    """
```

流程：
1. 接收 `upstream_vuln_id` 和依赖列表
2. 对每个 dependency 生成 `ImpactResult`（当前全部通过，不做版本过滤）
3. 返回结果列表

用途：
- 单元测试
- CLI 调试
- 未来版本匹配逻辑的开发与测试

### 集成模式（Integrated）

通过 Service 层读写数据库，由调度器触发。

```python
# vulnsentinel/engines/impact_engine/runner.py

class ImpactRunner:
    async def process_one(
        self, session: AsyncSession, upstream_vuln: UpstreamVuln
    ) -> list[ClientVuln]

    async def run_batch(
        self, session_factory, limit: int = 20
    ) -> int
```

生命周期：

```
UpstreamVuln(status=published)
      │
      ▼
  list_published_without_impact()
      │
      ▼
  ProjectDependencyDAO.list_by_library(library_id)
      │
      ▼
  assess_impact(upstream_vuln_id, dependencies)
      │
      ▼
  对每个 ImpactResult:
    ClientVulnService.create(
        upstream_vuln_id, project_id,
        constraint_expr, resolved_version,
        constraint_source
    )
      │
      ▼
ClientVuln(pipeline_status='pending')
  → 等待 Reachability Analyzer 处理
```

`run_batch` 接收 `session_factory`（不是 session），保持与 VulnAnalyzerRunner 一致的模式。

---

## 数据流

```
UpstreamVuln(status='published')
        │
        │  UpstreamVulnDAO.list_published_without_impact(session, limit)
        │  SQL: WHERE status = 'published'
        │       AND NOT EXISTS (SELECT 1 FROM client_vulns
        │                       WHERE upstream_vuln_id = upstream_vulns.id)
        │
        ▼
  对每条 UpstreamVuln:
        │
        │  ProjectDependencyDAO.list_by_library(session, upstream_vuln.library_id)
        │
        ▼
  对每个 ProjectDependency:
        │
        │  assess_impact(upstream_vuln.id, [dep])
        │
        │  ClientVulnService.create(
        │      upstream_vuln_id = upstream_vuln.id,
        │      project_id      = dep.project_id,
        │      constraint_expr = dep.constraint_expr,       ← 从 project_dependency 复制
        │      resolved_version = dep.resolved_version,     ← 从 project_dependency 复制
        │      constraint_source = dep.constraint_source    ← 从 project_dependency 复制
        │  )
        │
        ▼
  ClientVuln(pipeline_status='pending')
    → 等待 Reachability Analyzer 处理
```

---

## 轮询策略

### 需要新增的查询方法

Impact Engine 需要一个新的轮询方法来查找"已发布但尚未进行影响评估的漏洞"。

**DAO 层：**

```python
# vulnsentinel/dao/upstream_vuln_dao.py

async def list_published_without_impact(
    self, session: AsyncSession, limit: int = 20
) -> list[UpstreamVuln]:
    """
    查找已发布但尚无 client_vuln 记录的 upstream_vuln。

    SQL 等价:
        SELECT uv.*
        FROM upstream_vulns uv
        WHERE uv.status = 'published'
          AND NOT EXISTS (
              SELECT 1 FROM client_vulns cv
              WHERE cv.upstream_vuln_id = uv.id
          )
        ORDER BY uv.published_at ASC
        LIMIT :limit
    """
```

**Service 层：**

```python
# vulnsentinel/services/upstream_vuln_service.py

async def list_published_without_impact(
    self, session: AsyncSession, limit: int = 20
) -> list[UpstreamVuln]:
    """透传 DAO 方法。"""
```

### 幂等性保障

即使轮询逻辑出现竞态（两个 runner 同时处理同一个 upstream_vuln），`client_vulns` 表的 unique constraint `(upstream_vuln_id, project_id)` 保证不会创建重复记录。

插入冲突处理：

```python
try:
    await ClientVulnService.create(session, ...)
except IntegrityError:
    await session.rollback()
    # 已存在，跳过
```

---

## 已有基础设施

Impact Engine 依赖的大部分 DAO/Service 已实现：

| 层 | 方法 | 状态 |
|----|------|------|
| Model | `UpstreamVuln.library_id` FK → `libraries.id` | 已实现 |
| Model | `UpstreamVuln.status` enum (`analyzing` / `published`) | 已实现 |
| Model | `ClientVuln` unique constraint `(upstream_vuln_id, project_id)` | 已实现 |
| Model | `ClientVuln.pipeline_status` 默认 `'pending'` | 已实现 |
| DAO | `ProjectDependencyDAO.list_by_library(session, library_id)` | 已实现，返回 `list[ProjectDependency]` |
| Service | `ClientVulnService.create(session, upstream_vuln_id, project_id, constraint_expr, constraint_source, resolved_version, ...)` | 已实现 |
| DAO | `ClientVulnDAO.list_by_upstream_vuln(session, upstream_vuln_id)` | 已实现，可用于检查 |

---

## 需要新增的基础设施

| 层 | 方法 | 说明 |
|----|------|------|
| DAO | `UpstreamVulnDAO.list_published_without_impact(session, limit)` | `WHERE status = 'published' AND NOT EXISTS (...)` |
| Service | `UpstreamVulnService.list_published_without_impact(session, limit)` | 透传 DAO |

两个方法都很简单，实现阶段添加。

---

## 错误处理

### DB unique violation

`client_vulns` 表的 unique constraint `(upstream_vuln_id, project_id)` 会在重复创建时抛出 `IntegrityError`。处理策略：捕获并跳过，记录 debug 日志。这保证了幂等性。

### library 无依赖项目

`ProjectDependencyDAO.list_by_library()` 返回空列表 → 跳过，不报错。该 upstream_vuln 的影响评估视为已完成（没有项目受影响）。

注意：这种情况下不会创建任何 `client_vulns` 记录，导致该 upstream_vuln 在下次轮询时**仍会被 `list_published_without_impact` 选中**。需要额外机制避免无限重复处理：

- 方案 A：在 `upstream_vulns` 表增加 `impact_assessed_at` 字段，处理完后标记
- 方案 B：修改查询，在 NOT EXISTS 中增加"library_id 无 project_dependency"的排除条件
- 方案 C：轮询查询改为 `NOT EXISTS (client_vulns) AND EXISTS (project_dependencies for library_id)`

推荐**方案 C**：语义清晰——只有当 library 有依赖项目时才需要处理。无依赖的 upstream_vuln 自然被排除。

更新后的 SQL：

```sql
SELECT uv.*
FROM upstream_vulns uv
WHERE uv.status = 'published'
  AND NOT EXISTS (
      SELECT 1 FROM client_vulns cv
      WHERE cv.upstream_vuln_id = uv.id
  )
  AND EXISTS (
      SELECT 1 FROM project_dependencies pd
      WHERE pd.library_id = uv.library_id
  )
ORDER BY uv.published_at ASC
LIMIT :limit
```

### 新增 project 注册已分析 library

轮询查询的 `NOT EXISTS (client_vulns)` 条件是"只要有任意一个 project 的 client_vuln 存在就排除该 upstream_vuln"。这意味着：

1. library X 有 project A 和 B 依赖 → Impact Engine 为 A、B 创建 client_vuln
2. 之后 project C 注册了对 library X 的依赖
3. 下次轮询时，该 upstream_vuln 已有 client_vulns 记录 → 被排除 → project C 不会自动获得 client_vuln

**这是已知约束**。新增 project 注册对已分析 library 的依赖时，需要由 project 注册流程或调度器触发一次补扫，Impact Engine 的轮询不会自动覆盖这种情况。

### 事件级隔离

每个 upstream_vuln 独立处理。单个 upstream_vuln 处理失败（如 DB 连接中断）不影响其他漏洞的处理。

失败的 upstream_vuln 保持原状（无 client_vulns 记录），下次轮询时会被重新选中。

---

## 代码结构

```
vulnsentinel/engines/impact_engine/
├── __init__.py
├── assessor.py      # assess_impact() 纯函数 + ImpactResult dataclass
└── runner.py        # ImpactRunner (process_one + run_batch)

tests/vulnsentinel/
└── test_impact_engine.py
```

- `assessor.py` — 独立模式核心。当前为 pass-through，未来版本匹配逻辑加在这里。
- `runner.py` — 集成模式。轮询 `list_published_without_impact`，调用 `assess_impact`，批量创建 `client_vulns`。

---

## 未来演进

### 版本匹配作为"快速否定"

当版本解析能力成熟后，可在 `assess_impact()` 中加入版本匹配逻辑：

```python
def assess_impact(
    upstream_vuln_id: uuid.UUID,
    affected_versions: str,            # 新增参数
    dependencies: list[ProjectDependency],
) -> list[ImpactResult]:
    results = []
    for dep in dependencies:
        if version_match(affected_versions, dep.resolved_version):
            results.append(ImpactResult(..., match_type="version_match"))
        else:
            # 版本不匹配 → 直接 finalize(is_affected=False)
            # 不创建 pending 状态的 client_vuln
            pass
    return results
```

演进路径：

1. **当前** — Pass-through，所有依赖项目创建 pending client_vuln
2. **中期** — 版本匹配做快速否定，减少 Reachability Analyzer 的负载
3. **长期** — 版本匹配 + 可达性分析双重判断，版本匹配作为预过滤

版本匹配只做否定（"肯定不受影响"），不做肯定（"肯定受影响"）。最终判断始终由 Reachability Analyzer 基于代码可达性做出。
