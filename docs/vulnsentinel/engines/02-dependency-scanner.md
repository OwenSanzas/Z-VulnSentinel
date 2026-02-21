# Dependency Scanner

> 扫描 Project repo 的 manifest 文件，提取第三方依赖列表并同步到数据库。对应十步流程中的**步骤 3（依赖提取）**。

## 概述

Dependency Scanner 是第一个实现的 Engine。它的职责很单一：读取 Project 仓库中的包管理器配置文件（`package.json`、`requirements.txt`、`CMakeLists.txt` 等），解析出依赖列表。

**特点：**

- 轻量操作 — 只读文件，不需要编译，不需要 Neo4j
- 幂等 — 重复执行不产生副作用（ON CONFLICT DO UPDATE）
- 用户手动添加的依赖不会被删除，只会被 manifest 数据更新

---

## 双模式设计

所有 Engine 统一采用**双模式设计**：独立模式用于测试和调试，集成模式用于生产调度。

### 独立模式（Standalone）

纯函数式，不依赖数据库、不需要 Service 层。

```
输入: repo 本地路径（或 repo_url + ref）
输出: list[ScannedDependency]
```

用途：
- 单元测试、集成测试
- CLI 调试工具（`python -m vulnsentinel.engines.dependency_scanner /path/to/repo`）
- 其他系统复用扫描逻辑

### 集成模式（Integrated）

通过 Service 层读写数据库，由 Scheduler 调度。

```
输入: project_id
输出: DB 中更新的 libraries + project_dependencies + last_scanned_at
```

用途：
- Scheduler 定时调度
- 注册时异步触发

### 模式关系

集成模式内部调用独立模式的扫描逻辑，然后额外执行 DB 同步：

```
集成模式(project_id):
    project = ProjectDAO.get_by_id(project_id)
    repo_path = clone_or_fetch(project.repo_url, project.pinned_ref or project.default_branch)

    # ↓ 独立模式的核心逻辑
    scanned_deps = scan(repo_path)

    # ↓ 集成模式独有：DB 同步
    sync_to_db(session, project_id, scanned_deps)
```

---

## 核心数据结构

### ScannedDependency

独立模式的输出单元，描述从 manifest 中扫描到的一条依赖。

```python
@dataclass
class ScannedDependency:
    library_name: str              # 库名，如 "libpng"、"requests"、"lodash"
    library_repo_url: str | None   # 库的 Git 仓库地址（从包注册表解析，可能为 None）
    constraint_expr: str | None    # 版本约束，如 ">=1.6.0"、"^2.0.0"
    resolved_version: str | None   # lock 文件中锁定的版本，如 "1.6.37"
    source_file: str               # 来源文件，如 "requirements.txt"、"package.json"
    detection_method: str           # 检测方式，如 "pip-requirements"、"npm-package-json"、"cmake-fetchcontent"
```

**字段说明：**

| 字段 | 来源 | 说明 |
|------|------|------|
| `library_name` | manifest 文件解析 | 始终存在 |
| `library_repo_url` | 包注册表查询（PyPI、npm）或 manifest 中直接指定 | C/C++ 项目通常为 None |
| `constraint_expr` | manifest 文件 | `requirements.txt` → `>=1.6.0`；`package.json` → `^2.0.0` |
| `resolved_version` | lock 文件（`package-lock.json`、`Pipfile.lock`） | 无 lock 文件则为 None |
| `source_file` | 扫描器记录 | 相对于 repo root 的路径 |
| `detection_method` | 扫描器记录 | 标识使用了哪种解析策略 |

---

## 检测策略

### 按语言/生态分类

每种语言实现为独立的 parser 模块，通过注册表模式注册到 Scanner 中。新增语言只需实现 parser 接口并注册，不改动 Scanner 核心逻辑。

| 语言 | 检测源 | detection_method | 难度 |
|------|--------|-----------------|------|
| **Python** | `requirements.txt` | `pip-requirements` | 简单 |
| | `pyproject.toml` (`[project.dependencies]`) | `pyproject-toml` | 简单 |
| | `setup.py` / `setup.cfg` | `setup-py` | 中等（需解析函数调用） |
| | `Pipfile` / `Pipfile.lock` | `pipfile` | 简单 |
| **JavaScript** | `package.json` (`dependencies` + `devDependencies`) | `npm-package-json` | 简单 |
| | `yarn.lock` / `package-lock.json` / `pnpm-lock.yaml` | `npm-lockfile` | 简单（可获取 resolved_version） |
| **Rust** | `Cargo.toml`, `Cargo.lock` | `cargo` | 简单（TOML 标准格式） |
| **Go** | `go.mod`, `go.sum` | `go-mod` | 简单（格式标准） |
| **Java** | `pom.xml` | `maven-pom` | 中等（XML + 变量替换） |
| | `build.gradle` / `build.gradle.kts` | `gradle-build` | 中等（Groovy/Kotlin DSL） |
| **C# / .NET** | `*.csproj`, `Directory.Packages.props` | `nuget-csproj` | 中等（XML） |
| **C/C++** | `conanfile.txt` / `conanfile.py` | `conan` | 中等 |
| | `vcpkg.json` | `vcpkg` | 简单 |
| | `.gitmodules` | `git-submodule` | 简单 |
| | `CMakeLists.txt` — `FetchContent` / `find_package` | `cmake-fetchcontent` / `cmake-find-package` | 困难 |

### Parser 注册表

```python
# 新增语言只需：1) 实现 ManifestParser 接口  2) 注册到 PARSER_REGISTRY

class ManifestParser(Protocol):
    """每种 manifest 格式的解析器接口。"""
    detection_method: str
    file_patterns: list[str]

    def parse(self, file_path: Path, content: str) -> list[ScannedDependency]: ...

PARSER_REGISTRY: dict[str, ManifestParser] = {
    "pip-requirements": PipRequirementsParser(),
    "pyproject-toml": PyprojectTomlParser(),
    "npm-package-json": NpmPackageJsonParser(),
    # ...
    # v2:
    # "cargo": CargoParser(),
    # "go-mod": GoModParser(),
    # "nuget-csproj": NugetCsprojParser(),
}
```

### C/C++ 分层策略

C/C++ 没有统一的包管理器，Scanner 按优先级分层尝试：

```
1. conanfile.txt / conanfile.py  → 有则解析 Conan 依赖
2. vcpkg.json                    → 有则解析 vcpkg 依赖
3. .gitmodules                   → 有则解析 git submodule
4. CMakeLists.txt                → 解析 FetchContent / find_package
5. [预留] LLM Agent              → 阅读源码、Makefile、构建脚本，推断依赖
6. 都没有                        → 标记"无法自动检测"
```

每层独立执行，结果合并（一个项目可能同时用 vcpkg 和 git submodule）。

**第 5 层 LLM Agent（预留）**：规则解析器只能处理已知格式的 manifest 文件。对于没有包管理器、没有标准构建系统的 C/C++ 项目（手写 Makefile、自定义构建脚本、vendor 目录直接包含源码等），LLM 可以通过阅读代码发现依赖关系：

- 读 `Makefile` / `configure.ac` 中的 `-l` 链接标志和 `pkg-config` 调用
- 读 `#include` 头文件路径推断第三方库
- 读 `vendor/` 或 `third_party/` 目录结构识别 vendored 依赖
- 读 `README` / `INSTALL` 文档中的构建说明

v1 不实现，接口预留。`detection_method = "llm-agent"`。

### library_repo_url 解析

| 生态 | 解析方式 |
|------|---------|
| Python (PyPI) | `https://pypi.org/pypi/{name}/json` → `project_urls.Source` 或 `home_page` |
| npm | `https://registry.npmjs.org/{name}` → `repository.url` |
| Maven Central | `pom.xml` 中 `<scm><url>` |
| Conan / vcpkg | 配置文件中直接包含 URL，或查 conan-center-index / vcpkg registry |
| git submodule | `.gitmodules` 中的 `url` 字段 |
| CMake FetchContent | `GIT_REPOSITORY` 参数 |
| CMake find_package | 无法直接解析 → `library_repo_url = None` |

**注意**：`library_repo_url` 解析是 best-effort 的。未能解析的依赖仍然会出现在扫描结果中，只是不会自动入库（见集成模式流程）。

### 实际案例

**案例 1：jq（C 项目，用 git submodule）**

```
repo: https://github.com/jqlang/jq
.gitmodules 包含:
  [submodule "modules/oniguruma"]
    url = https://github.com/kkos/oniguruma

扫描结果:
  ScannedDependency(
      library_name="oniguruma",
      library_repo_url="https://github.com/kkos/oniguruma",
      constraint_expr=None,       # submodule 锁定 commit，不是语义版本
      resolved_version=None,
      source_file=".gitmodules",
      detection_method="git-submodule",
  )
```

**案例 2：libpng（C 项目，用 CMake find_package）**

```
repo: https://github.com/pnggroup/libpng
CMakeLists.txt 包含:
  find_package(ZLIB REQUIRED)

扫描结果:
  ScannedDependency(
      library_name="zlib",
      library_repo_url=None,       # find_package 无法解析 repo URL
      constraint_expr=None,
      resolved_version=None,
      source_file="CMakeLists.txt",
      detection_method="cmake-find-package",
  )

→ 集成模式中，library_repo_url=None → 不入库，记录到扫描结果供用户查看
```

**案例 3：一个 Python Web 项目**

```
repo: https://github.com/example/webapp
requirements.txt:
  flask>=2.0.0
  requests==2.31.0
  sqlalchemy~=2.0

扫描结果:
  [
    ScannedDependency("flask", "https://github.com/pallets/flask", ">=2.0.0", None, "requirements.txt", "pip-requirements"),
    ScannedDependency("requests", "https://github.com/psf/requests", "==2.31.0", "2.31.0", "requirements.txt", "pip-requirements"),
    ScannedDependency("sqlalchemy", "https://github.com/sqlalchemy/sqlalchemy", "~=2.0", None, "requirements.txt", "pip-requirements"),
  ]
```

---

## constraint_source 与依赖生命周期

### 两种来源

每条 `project_dependencies` 记录有一个 `constraint_source` 字段，标识谁创建了它：

| `constraint_source` | 谁写入的 | 示例值 |
|---------------------|---------|--------|
| `"manual"` | 用户通过 API 手动添加 | 固定值 `"manual"` |
| 其他任何值 | Scanner 从 manifest 扫描写入 | `"requirements.txt"`、`"package.json"`、`".gitmodules"` |

用户通过 API 添加依赖时，**Service 层强制设 `constraint_source = "manual"`**，用户不能指定该字段。

### Scanner 对不同来源的行为

Scanner 每次扫描后，按以下规则处理 DB 中的已有记录：

| 已有记录来源 | manifest 中找到同一 library | manifest 中未找到 | 说明 |
|-------------|--------------------------|-------------------|------|
| **Scanner 添加的** | 更新 `constraint_expr`、`resolved_version`、`constraint_source` | **删除** | Scanner 全权管理自己创建的记录 |
| **用户手动添加的** | **用 manifest 数据覆盖** `constraint_expr`、`resolved_version` | **不碰** | manifest 是代码实际运行状态，比用户手动填的更准确 |

**为什么 manifest 覆盖用户手动填的版本？**

用户手动添加依赖时可能填了 `constraint_expr = ">=7.0"`，但代码里实际锁定的是 `8.5.0`。Scanner 检测到 manifest 里的真实版本后用它覆盖，确保我们的漏洞分析基于代码实际使用的版本，而不是用户的记忆。这反而能发现用户自己都不知道的版本偏差。

**为什么不删用户手动添加的？**

我们是风险预警系统，不能要求用户在开发过程中实时同步依赖变更到我们的系统。即使用户确实删除了某个依赖但忘了从我们系统移除，后续 Reachability Analyzer 会发现调用路径不可达，自然不会产生误报。多监控一个已经不用的库的成本极低，误删用户依赖的风险则高得多。

### UNIQUE 约束变更

为支持上述行为，`project_dependencies` 表的 UNIQUE 约束需要从：

```sql
-- 旧：同一 library 可能因 constraint_source 不同而有多行
UNIQUE (project_id, library_id, constraint_source)
```

改为：

```sql
-- 新：每个 project-library 对只有一行记录
UNIQUE (project_id, library_id)
```

原因：一个 project 对一个 library 只应该有一条依赖记录。`constraint_source` 是元数据（记录谁创建了这条记录），不是业务维度。

### 场景推演

**场景 A：用户注册时手动添加 curl，之后 Scanner 在 manifest 中也发现了 curl**

```
T0: 用户 POST /api/v1/projects/ 带 dependencies: [{library_name: "curl", constraint_expr: ">=7.0"}]
    → DB: (my-app, curl, constraint_source="manual", constraint_expr=">=7.0", resolved_version=NULL)

T1: Scanner 扫描 repo，CMakeLists.txt FetchContent 拉 curl 8.5.0
    → 发现 DB 中已有 (my-app, curl) 且 constraint_source="manual"
    → 覆盖版本信息: constraint_expr=NULL, resolved_version="8.5.0"
    → 保持 constraint_source="manual" 不变
    → DB: (my-app, curl, constraint_source="manual", constraint_expr=NULL, resolved_version="8.5.0")

结果：用户手动加的 curl 被保留，版本被更新为代码实际使用的版本。
```

**场景 B：纯 Scanner 管理，用户后来从 requirements.txt 中移除了 flask**

```
T0: Scanner 扫描 requirements.txt，发现 flask, requests, sqlalchemy
    → DB: 3 条记录，constraint_source 均为 "requirements.txt"

T1: 用户从 requirements.txt 中移除 flask

T2: Scanner 再次扫描，只发现 requests, sqlalchemy
    → Stale 清理: flask 的 constraint_source="requirements.txt" (非 manual) 且不在本次扫描结果中 → 删除
    → DB: 2 条记录

结果：Scanner 添加的记录随 manifest 变化自动清理。
```

**场景 C：用户手动添加了一个 C 库，Scanner 在 manifest 中找不到**

```
T0: 用户通过 API 手动添加 zlib (因为 find_package 无法解析 repo_url，Scanner 不会自动入库)
    → DB: (my-app, zlib, constraint_source="manual")

T1: Scanner 扫描 repo，manifest 中没有 zlib 的可解析记录
    → zlib 的 constraint_source="manual" → 跳过，不删

T2 ~ T∞: Scanner 每次扫描都跳过 zlib

结果：用户手动添加的依赖永远不会被 Scanner 删除。
```

**场景 D：用户删除了依赖但忘记从系统移除**

```
T0: Scanner 之前入库了 lodash (constraint_source="package.json")
T1: 用户从代码中移除 lodash，也从 package.json 中移除
T2: Scanner 扫描 → lodash 不在 manifest → constraint_source="package.json" → 删除 ✓

假设是手动添加的 lodash (constraint_source="manual"):
T0: 用户手动添加 lodash
T1: 用户从代码中移除 lodash，但忘了从我们系统移除
T2: Scanner 扫描 → lodash 是 manual → 不删，留着
T3: 某天 lodash 出漏洞 → Impact Engine 判定版本受影响
    → Reachability Analyzer 搜调用图 → 找不到 lodash 的调用路径 → 标记 not_affected → 不预警

结果：多余的记录不造成误报，下游 pipeline 天然兜底。
```

---

## 集成模式流程

集成模式在独立模式扫描结果的基础上，执行 DB 同步。单个 project 的完整流程：

### Step 1: 获取 Project 信息

```
project = ProjectDAO.get_by_id(session, project_id)
  → None → 跳过（项目已删除）
  → auto_sync_deps = false → 跳过
```

从 project 中取：`repo_url`、`pinned_ref`、`default_branch`。

### Step 2: 获取 Repo 文件

两种方式（按可用性选择）：

| 方式 | 条件 | 优点 | 缺点 |
|------|------|------|------|
| **GitHub API** | platform=github，public repo 或有 token | 无需磁盘，只读需要的文件 | API rate limit |
| **git clone/fetch** | 通用 | 无 API 限制 | 需要磁盘空间 |

v1 实现使用 **shallow clone**（`git clone --depth 1 --branch {ref}`），后续可优化为 GitHub API。

Clone 目标 ref：
- `pinned_ref` 存在 → clone 该 ref
- 否则 → clone `default_branch`

### Step 3: 检测语言，找 manifest 文件

扫描 repo root 目录，按语言/生态检测 manifest 文件存在性：

```python
MANIFEST_PATTERNS = {
    "pip-requirements": ["requirements.txt", "requirements/*.txt"],
    "pyproject-toml": ["pyproject.toml"],
    "setup-py": ["setup.py", "setup.cfg"],
    "pipfile": ["Pipfile"],
    "npm-package-json": ["package.json"],
    "npm-lockfile": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "maven-pom": ["pom.xml"],
    "gradle-build": ["build.gradle", "build.gradle.kts"],
    "conan": ["conanfile.txt", "conanfile.py"],
    "vcpkg": ["vcpkg.json"],
    "git-submodule": [".gitmodules"],
    "cmake-fetchcontent": ["CMakeLists.txt"],
    "cmake-find-package": ["CMakeLists.txt"],  # 同文件，不同解析逻辑
}
```

所有匹配到的 manifest 文件都进入 Step 4 解析。

### Step 4: 解析依赖

对每个匹配到的 manifest 文件，调用对应的 parser，汇总得到 `list[ScannedDependency]`。

这一步是**独立模式的核心逻辑**，不涉及任何 DB 操作。

### Step 5: 有 repo_url 的依赖 → 入库/更新

对 `library_repo_url is not None` 的每条 ScannedDependency：

```
library = LibraryService.upsert(session,
    name=dep.library_name,
    repo_url=dep.library_repo_url,
)

# ON CONFLICT (project_id, library_id) DO UPDATE
# 无论已有记录是 manual 还是 scanner 创建的，都更新版本信息
ProjectDependencyDAO.upsert(session, {
    project_id: project.id,
    library_id: library.id,
    constraint_expr: dep.constraint_expr,
    resolved_version: dep.resolved_version,
    constraint_source: dep.source_file,  # 仅当已有记录非 manual 时才覆盖 constraint_source
})
```

**upsert 逻辑：**

```sql
INSERT INTO project_dependencies (project_id, library_id, constraint_expr, resolved_version, constraint_source)
VALUES (:project_id, :library_id, :constraint_expr, :resolved_version, :source_file)
ON CONFLICT (project_id, library_id) DO UPDATE SET
    constraint_expr = EXCLUDED.constraint_expr,
    resolved_version = EXCLUDED.resolved_version,
    -- 保护 manual 标记：已有记录是 manual 时不覆盖 constraint_source
    constraint_source = CASE
        WHEN project_dependencies.constraint_source = 'manual' THEN 'manual'
        ELSE EXCLUDED.constraint_source
    END,
    updated_at = now();
```

### Step 6: 无 repo_url 的依赖 → 跳过入库

对 `library_repo_url is None` 的 ScannedDependency（典型：C/C++ 的 `find_package` 依赖）：

- 不调用 LibraryService，不写入 `libraries` 和 `project_dependencies`
- 记录到本次扫描结果中，集成模式返回值包含这些未入库的依赖
- 用户可在 Dashboard 中看到"已检测但无法追踪"的依赖，决定是否手动添加

**版本缺失时的处理**：用户手动添加依赖时可能不填版本（只给 name + repo_url），而 Scanner 也可能无法从 manifest 中解析出版本（如 `find_package` 不带版本约束）。此时 `constraint_expr` 和 `resolved_version` 均为 None。

下游 Impact Engine 做版本匹配时，按以下优先级解析版本：

| 优先级 | 来源 | 说明 |
|--------|------|------|
| 1 | `resolved_version` | lock 文件锁定的确切版本，最准确 |
| 2 | `constraint_expr` | manifest 中的约束表达式（如 `>=1.6.0`），做范围匹配 |
| 3 | library 最新已知版本 | 都没有时 fallback，假设用的是最新版 |

第 3 级 fallback 的依据：该 library 已被其他客户或系统监控，`libraries` 表中有 Event Collector 采集到的最新 tag 信息，直接取该版本。这在实际中是合理的 — 没有版本锁定的项目（如 `find_package` 不指定版本）大概率跟随系统或 CI 环境中的最新可用版本。

### Step 7: 删除 stale 依赖

仅删除 **Scanner 自己创建的**、且本次 manifest 中已不存在的记录。用户手动添加的记录永远不删。

```
scanned_library_ids = Step 5 中成功入库/更新的 library_id 集合

ProjectDependencyDAO.delete_stale_scanner_deps(
    session,
    project_id=project.id,
    keep_library_ids=scanned_library_ids,
)
```

```sql
-- delete_stale_scanner_deps
DELETE FROM project_dependencies
WHERE project_id = :project_id
  AND constraint_source != 'manual'
  AND library_id NOT IN (:keep_library_ids);
```

**`constraint_source = 'manual'` 的记录永远不会被这条 SQL 命中。**

### Step 8: 更新 last_scanned_at

```
ProjectDAO.update(session, project_id, last_scanned_at=now())
```

### 完整伪代码

```python
async def run_integrated(self, session: AsyncSession, project_id: UUID) -> ScanResult:
    # Step 1
    project = await self._project_dao.get_by_id(session, project_id)
    if not project or not project.auto_sync_deps:
        return ScanResult.skipped()

    ref = project.pinned_ref or project.default_branch

    # Step 2
    repo_path = await clone_or_fetch(project.repo_url, ref)

    # Step 3 + 4 (独立模式核心逻辑)
    scanned_deps = self.scan(repo_path)

    # Step 5: 有 repo_url → 入库/更新
    synced_library_ids = set()
    upsert_rows = []
    for dep in scanned_deps:
        if dep.library_repo_url is None:
            continue
        library = await self._library_service.upsert(
            session, name=dep.library_name, repo_url=dep.library_repo_url,
        )
        synced_library_ids.add(library.id)
        upsert_rows.append({
            "project_id": project.id,
            "library_id": library.id,
            "constraint_expr": dep.constraint_expr,
            "resolved_version": dep.resolved_version,
            "constraint_source": dep.source_file,
        })

    if upsert_rows:
        await self._dep_dao.batch_upsert(session, upsert_rows)

    # Step 7: 删除 stale (仅 Scanner 创建的)
    deleted = await self._dep_dao.delete_stale_scanner_deps(
        session, project_id=project.id, keep_library_ids=synced_library_ids,
    )

    # Step 8: 更新时间戳
    await self._project_dao.update(session, project.id, last_scanned_at=utcnow())

    return ScanResult(
        scanned=scanned_deps,
        synced_count=len(synced_library_ids),
        deleted_count=deleted,
        unresolved=[d for d in scanned_deps if d.library_repo_url is None],
    )
```

---

## 调度

### 触发条件

| 触发时机 | 条件 | 说明 |
|---------|------|------|
| 注册时 | `POST /api/v1/projects/` 且 `auto_sync_deps=true` | 立即异步触发一次 |
| 定时重扫 | per-project 每 1 小时 | 基于 `last_scanned_at` |

**用户不能手动触发 scan。** Scan 只由系统自动执行。

### Scheduler 查询

```sql
-- ProjectDAO.list_due_for_scan()
SELECT * FROM projects
WHERE auto_sync_deps = true
  AND pinned_ref IS NULL
  AND (last_scanned_at IS NULL OR last_scanned_at < now() - interval '1 hour');
```

即：
- `auto_sync_deps=false` → 不扫
- `pinned_ref` 已设置 → 不扫（锁定版本的项目依赖不变）
- `last_scanned_at` 未过期 → 不扫

### 调度器行为

```
每 5 分钟运行一次:
    projects = ProjectDAO.list_due_for_scan(session)
    for project in projects:
        await dependency_scanner.run_integrated(session, project.id)
```

> 每个 project 的扫描是独立事务。单个 project 扫描失败不影响其他 project。

---

## 待实现的 DAO/Service 缺口

当前 DAO 层尚未包含以下方法，需在实现 Scanner 时补充：

| 层 | 类 | 方法 | 签名 | 说明 |
|----|-----|------|------|------|
| DAO | `ProjectDependencyDAO` | `batch_upsert` | `(session, rows: list[dict]) → list[Row]` | 批量 upsert，ON CONFLICT (project_id, library_id) 更新版本信息，保护 manual 标记 |
| DAO | `ProjectDependencyDAO` | `delete_stale_scanner_deps` | `(session, project_id: UUID, keep_library_ids: set[UUID]) → int` | 删除 Scanner 创建的 stale 依赖（constraint_source != 'manual'），返回删除数量 |
| DAO | `ProjectDAO` | `list_due_for_scan` | `(session) → list[Project]` | 查询需要扫描的项目（auto_sync + 未锁定 + 已过期） |
| DAO | `ProjectDAO` | `update` | 已有 BaseDAO.update | 需确认支持 `last_scanned_at` 字段更新 |

### Schema 变更

`project_dependencies` 表 UNIQUE 约束需修改：

```sql
-- 旧
UNIQUE (project_id, library_id, constraint_source)

-- 新
UNIQUE (project_id, library_id)
```

原因：一个 project 对一个 library 只有一条记录。`constraint_source` 是元数据，不是业务维度。

同步需要修改的文档：`database/schema.sql`、`backend/dao.md`（batch_create → batch_upsert）、`backend/api.md`（DependencyInputSchema 删除 constraint_source 字段）。

---

## 与架构总览的对应关系

| 架构总览中的描述 | 本文档对应 |
|----------------|-----------|
| 步骤 3：依赖提取 | 本 Engine 的全部职责 |
| Dependency Scanner 触发时机 | §调度 |
| `constraint_source` 区分 manual / scanner | §constraint_source 与依赖生命周期 |
| C/C++ 分层检测策略 | §检测策略 - C/C++ 分层策略 |
| 第一步产出（projects + libraries + project_dependencies） | §集成模式流程 Step 5-8 |
| Scanner 不删 manual 依赖 | §集成模式流程 Step 7 |
