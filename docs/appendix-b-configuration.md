## 附录 B: 配置示例

**独立使用（z-code-analyzer）：**

```json
{
  "neo4j_uri": "bolt://localhost:7687",
  "neo4j_auth": null,
  "mongo_uri": "mongodb://localhost:27017",
  "analysis_backend": "auto",
  "orchestration_mode": null,
  "svf_docker_image": null,
  "svf_case_config": null,
  "joern_path": null,
  "ai_refine_enabled": false,
  "ai_refine_budget_usd": 1.0
}
```

**FBv2 集成：**

```json
{
  "neo4j_uri": "bolt://neo4j:7687",
  "mongo_uri": "mongodb://mongo:27017",
  "analysis_backend": "auto",
  "orchestration_mode": null,
  "ai_refine_enabled": false
}
```

**`analysis_backend` 可选值：**
- `"auto"` — 自动选择（v1 默认使用 SVF）
- `"svf"` — 强制 SVF（失败则报错，不降级）
- `"joern"` — 强制 Joern
- `"introspector"` — 旧路径（向后兼容，数据导入 Neo4j）
- `"prebuild"` — 从预计算数据导入 Neo4j

等效环境变量：
```bash
# ── v1 已实现 ──
export NEO4J_URI=bolt://localhost:7687       # Neo4j 连接地址
export NEO4J_AUTH=none                        # Neo4j 认证（none / neo4j:password / neo4j_user+neo4j_password）
export MONGO_URI=mongodb://localhost:27017    # MongoDB 连接地址（SnapshotManager 用）

# ── v2 预留（代码中未读取） ──
export ANALYSIS_BACKEND=auto
export SVF_DOCKER_IMAGE=curl-fuzzer-base     # SVF 构建用的 Docker 镜像
export SVF_CASE_CONFIG=curl                   # SVF 构建配置名（对应 cases/ 下的文件）
export JOERN_PATH=/opt/joern/joern-cli        # Joern 安装路径
export AI_REFINE_ENABLED=false
export AI_REFINE_BUDGET=1.0
```

> **注意：** v1 不支持配置文件加载。所有配置通过 CLI 选项和环境变量传递。上方 JSON 格式仅为参考，实际代码中无对应的加载机制。

**Docker Compose（独立使用）：**

```yaml
services:
  neo4j:
    image: neo4j:5-community
    ports:
      - "7474:7474"   # Web UI
      - "7687:7687"   # Bolt 协议
    environment:
      NEO4J_AUTH: none
      NEO4J_PLUGINS: '["apoc"]'
    volumes:
      - neo4j_data:/data

  mongodb:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

volumes:
  neo4j_data:
  mongo_data:
```
