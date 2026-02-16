## GraphStore API 参考

> **函数标识约定**: 所有接受函数参数的方法，`name` 必传，`file_path` 可选。
> 若 `name` 在 snapshot 内唯一，无需 `file_path`；若有同名函数，必须传 `file_path` 消歧，否则抛 `AmbiguousFunctionError`。

### 连接管理

#### `connect(uri, auth)`
```
输入: uri: str, auth: tuple[str, str]
输出: None
```

#### `close()`
```
输入: 无
输出: None
```

#### `health_check()`
```
输入: 无
输出: bool
```

---

### 写入

#### `create_snapshot_node(snapshot_id, repo_url, version, backend)`
```
输入:
  snapshot_id: str    — MongoDB snapshot _id
  repo_url: str
  version: str
  backend: str
输出: None
```

#### `import_functions(snapshot_id, functions) -> int`
```
输入:
  snapshot_id: str
  functions: list[FunctionRecord]
输出: int — 写入数量
说明: 批量创建 :Function 节点 + (:Snapshot)-[:CONTAINS]->(:Function) 边
```

#### `import_edges(snapshot_id, edges) -> int`
```
输入:
  snapshot_id: str
  edges: list[CallEdge]
输出: int — 写入数量
说明: 批量创建 (:Function)-[:CALLS]->(:Function) 边
```

#### `import_fuzzers(snapshot_id, fuzzers) -> int`
```
输入:
  snapshot_id: str
  fuzzers: list[FuzzerInfo]  — 含 called_library_functions（Phase 4b 源码解析结果）
输出: int — 写入的 Fuzzer 数量
说明:
  对每个 FuzzerInfo：
  1. 创建 :Fuzzer 节点 + (:Snapshot)-[:CONTAINS]->(:Fuzzer) 边
  2. 创建该 fuzzer 专属的 LLVMFuzzerTestOneInput :Function 节点（file_path 区分不同 fuzzer）
  3. 创建 (:Fuzzer)-[:ENTRY]->(:Function {LLVMFuzzerTestOneInput}) 边
  4. 对 called_library_functions 中每个库函数，创建
     (:Function {LLVMFuzzerTestOneInput})-[:CALLS {call_type: "direct"}]->(:Function {库函数}) 边
```

#### `import_reaches(snapshot_id, reaches) -> int`
```
输入:
  snapshot_id: str
  reaches: list[dict]  — [{fuzzer_name: str, function_name: str, file_path: str?, depth: int}, ...]
输出: int — 写入数量
说明: 批量创建 (:Fuzzer)-[:REACHES {depth}]->(:Function) 边。导入时 BFS 一次性计算。
```

#### `delete_snapshot(snapshot_id)`
```
输入: snapshot_id: str
输出: None
说明: 删除整个 Snapshot 子图（:Snapshot 节点 + 所有关联节点和边）。淘汰时调用。
```

---

### 查询 — 单函数

#### `get_function_metadata(snapshot_id, name, file_path?)`
```
输入:
  snapshot_id: str
  name: str           — 精确匹配
  file_path: str?     — 可选，消歧用
输出:
  dict | None
  {
    "name": "dict_do",
    "file_path": "lib/dict.c",
    "start_line": 142,
    "end_line": 210,
    "content": "void dict_do(...) { ... }",
    "cyclomatic_complexity": 15,
    "language": "c",
    "is_external": false
  }
  未找到返回 None
  同名多个且未传 file_path 时抛 AmbiguousFunctionError
说明: 精确获取单个函数的完整元信息。模糊搜索用 search_functions。
```

#### `list_function_info_by_file(snapshot_id, file_path)`
```
输入:
  snapshot_id: str
  file_path: str      — 如 "lib/dict.c"
输出:
  list[dict]
  [
    {"name": "dict_do", "start_line": 142, "end_line": 210, "cyclomatic_complexity": 15, "is_external": false},
    {"name": "dict_init", "start_line": 10, "end_line": 30, "cyclomatic_complexity": 3, "is_external": false}
  ]
说明: 不返回 content（浏览场景），需要源码时单独调 get_function_metadata
```

#### `search_functions(snapshot_id, pattern)`
```
输入:
  snapshot_id: str
  pattern: str        — 模糊匹配，如 "dict_*" 或 "*init*"
输出:
  list[dict]
  [
    {"name": "dict_do", "file_path": "lib/dict.c", "start_line": 142, "is_external": false},
    {"name": "dict_init", "file_path": "lib/dict.c", "start_line": 10, "is_external": false}
  ]
说明: 轻量返回，只有定位信息
```

---

### 查询 — 调用关系

#### `get_callees(snapshot_id, name, file_path?)`
```
输入:
  snapshot_id: str
  name: str
  file_path: str?     — 可选，消歧用
输出:
  list[dict]
  [
    {"name": "malloc", "file_path": null, "call_type": "direct", "is_external": true},
    {"name": "dict_init", "file_path": "lib/dict.c", "call_type": "direct", "is_external": false},
    {"name": "handler_func", "file_path": "lib/handler.c", "call_type": "fptr", "is_external": false}
  ]
```

#### `get_callers(snapshot_id, name, file_path?)`
```
输入:
  snapshot_id: str
  name: str
  file_path: str?     — 可选，消歧用
输出:
  list[dict]
  [
    {"name": "curl_do", "file_path": "lib/url.c", "call_type": "direct", "is_external": false},
    {"name": "main_loop", "file_path": "lib/main.c", "call_type": "fptr", "is_external": false}
  ]
```

#### `shortest_path(snapshot_id, from_name, to_name, from_file_path?, to_file_path?, max_depth?)`
```
输入:
  snapshot_id: str
  from_name: str
  to_name: str
  from_file_path: str?  — 可选，消歧用
  to_file_path: str?    — 可选，消歧用
  max_depth: int = 10   — 最大搜索深度，超过则视为不可达；-1 = 无限制
  max_results: int = 10  — 同长度最短路径最多返回条数；-1 = 无限制
输出:
  dict | None
  {
    "length": 2,
    "paths_found": 2,
    "truncated": false,
    "paths": [
      {
        "path": [
          {"name": "LLVMFuzzerTestOneInput", "file_path": "harness.c"},
          {"name": "curl_do", "file_path": "lib/url.c"},
          {"name": "dict_do", "file_path": "lib/dict.c"}
        ],
        "edges": [
          {"from": "LLVMFuzzerTestOneInput", "to": "curl_do", "call_type": "direct"},
          {"from": "curl_do", "to": "dict_do", "call_type": "fptr"}
        ]
      },
      {
        "path": [
          {"name": "LLVMFuzzerTestOneInput", "file_path": "harness.c"},
          {"name": "http_do", "file_path": "lib/http.c"},
          {"name": "dict_do", "file_path": "lib/dict.c"}
        ],
        "edges": [
          {"from": "LLVMFuzzerTestOneInput", "to": "http_do", "call_type": "direct"},
          {"from": "http_do", "to": "dict_do", "call_type": "direct"}
        ]
      }
    ]
  }
  不可达返回 None
```

#### `get_all_paths(snapshot_id, from_name, to_name, from_file_path?, to_file_path?, max_depth?, max_results?)`
```
输入:
  snapshot_id: str
  from_name: str
  to_name: str
  from_file_path: str?  — 可选，消歧用
  to_file_path: str?    — 可选，消歧用
  max_depth: int = 10   — 最大路径长度；-1 = 无限制
  max_results: int = 100 — 最多返回条数；-1 = 无限制
输出:
  dict | None
  {
    "paths_found": 3,
    "truncated": false,
    "paths": [
      {
        "path": [
          {"name": "LLVMFuzzerTestOneInput", "file_path": "harness.c"},
          {"name": "curl_do", "file_path": "lib/url.c"},
          {"name": "dict_do", "file_path": "lib/dict.c"}
        ],
        "edges": [
          {"from": "LLVMFuzzerTestOneInput", "to": "curl_do", "call_type": "direct"},
          {"from": "curl_do", "to": "dict_do", "call_type": "fptr"}
        ],
        "length": 2
      },
      {
        "path": [
          {"name": "LLVMFuzzerTestOneInput", "file_path": "harness.c"},
          {"name": "http_do", "file_path": "lib/http.c"},
          {"name": "dict_do", "file_path": "lib/dict.c"}
        ],
        "edges": [
          {"from": "LLVMFuzzerTestOneInput", "to": "http_do", "call_type": "direct"},
          {"from": "http_do", "to": "dict_do", "call_type": "direct"}
        ],
        "length": 2
      },
      {
        "path": [
          {"name": "LLVMFuzzerTestOneInput", "file_path": "harness.c"},
          {"name": "curl_do", "file_path": "lib/url.c"},
          {"name": "parse_url", "file_path": "lib/urlapi.c"},
          {"name": "dict_do", "file_path": "lib/dict.c"}
        ],
        "edges": [
          {"from": "LLVMFuzzerTestOneInput", "to": "curl_do", "call_type": "direct"},
          {"from": "curl_do", "to": "parse_url", "call_type": "direct"},
          {"from": "parse_url", "to": "dict_do", "call_type": "fptr"}
        ],
        "length": 3
      }
    ]
  }
  无路径返回 None
说明: 按 length 升序排列
```

---

### 查询 — 可视化

#### `get_subtree(snapshot_id, name, file_path?, depth?)`
```
输入:
  snapshot_id: str
  name: str
  file_path: str?     — 可选，消歧用
  depth: int = 3      — 向下展开层数
输出:
  dict
  {
    "nodes": [
      {"name": "dict_do", "file_path": "lib/dict.c", "is_external": false},
      {"name": "dict_init", "file_path": "lib/dict.c", "is_external": false},
      {"name": "malloc", "file_path": null, "is_external": true}
    ],
    "edges": [
      {"from": "dict_do", "to": "dict_init", "call_type": "direct"},
      {"from": "dict_do", "to": "malloc", "call_type": "direct"}
    ]
  }
说明: 局部调用图，用于可视化。从指定函数出发向下 depth 层。
```

---

### 查询 — Fuzzer 可达性

#### `reachable_functions_by_one_fuzzer(snapshot_id, fuzzer_name, depth?, max_depth?)`
```
输入:
  snapshot_id: str
  fuzzer_name: str
  depth: int?
  max_depth: int?
输出:
  list[dict]
  [
    {"name": "curl_do", "file_path": "lib/url.c", "depth": 1, "is_external": false},
    {"name": "dict_do", "file_path": "lib/dict.c", "depth": 4, "is_external": false}
  ]
说明: 按 depth 升序。与 get_functions(fuzzer_name=xxx) 类似，但语义更明确。
```

#### `unreached_functions_by_all_fuzzers(snapshot_id, include_external?)`
```
输入:
  snapshot_id: str
  include_external: bool = False  — 可选，是否包含外部函数
输出:
  list[dict]
  [
    {"name": "unused_func", "file_path": "lib/old.c", "is_external": false},
    {"name": "deprecated_init", "file_path": "lib/compat.c", "is_external": false}
  ]
说明: 未被任何 fuzzer 覆盖的函数
```

---

### 查询 — 概览

#### `list_fuzzer_info_no_code(snapshot_id)`
```
输入:
  snapshot_id: str
输出:
  list[dict]
  [
    {
      "name": "curl_fuzzer_http",
      "entry_function": "LLVMFuzzerTestOneInput",
      "files": [
        {"path": "fuzz/fuzz_http.c", "source": "user"},
        {"path": "fuzz/fuzzer_template.c", "source": "user"}
      ],
      "focus": "HTTP"
    },
    {
      "name": "curl_fuzzer_ftp",
      "entry_function": "LLVMFuzzerTestOneInput",
      "files": [
        {"path": "fuzz/fuzz_ftp.c", "source": "auto_detect"}
      ],
      "focus": "FTP"
    }
  ]
说明: files.source — "user"(用户通过工单 JSON fuzzer_sources 传入) 或 "auto_detect"(从 debug info 检测到入口函数所在文件, v2)
```

#### `get_fuzzer_metadata(snapshot_id, fuzzer_name, project_path?)`
```
输入:
  snapshot_id: str
  fuzzer_name: str
  project_path: str?   — 可选，提供时在 files 中附带 code 字段（文件完整内容）
输出:
  dict | None
  {
    "name": "curl_fuzzer_http",
    "entry_function": "LLVMFuzzerTestOneInput",
    "files": [
      {"path": "fuzz/fuzz_http.c", "source": "user", "code": "int LLVMFuzzerTestOneInput(...) { ... }"},
      {"path": "fuzz/fuzzer_template.c", "source": "user", "code": "#include ..."}
    ],
    "focus": "HTTP"
  }
  未找到返回 None
说明: 与 list_fuzzer_info_no_code 相同结构，但 files 里附带 code 字段（文件完整内容）
```

#### `list_external_function_names(snapshot_id)`
```
输入:
  snapshot_id: str
输出:
  list[str]
  ["malloc", "free", "printf", "memcpy", ...]
说明: 外部函数（只有声明没有定义的函数），通常是 libc / 系统调用
```

#### `get_snapshot_statistics(snapshot_id)`
```
输入:
  snapshot_id: str
输出:
  dict
  {
    "function_count": 2334,
    "external_function_count": 128,
    "edge_count": 18540,
    "fuzzer_count": 10,
    "avg_depth": 3.2,
    "max_depth": 12,
    "unreached_count": 456
  }
```

---

### 扩展

#### `raw_query(cypher, params?)`
```
输入:
  cypher: str           — 任意 Cypher 查询
  params: dict?         — 查询参数
输出:
  list[dict]            — 查询结果
说明: 用于未封装的自定义需求。调用方负责正确性。
```
