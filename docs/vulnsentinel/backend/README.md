# Backend - FastAPI

## 认证

- 全站强制认证，未登录不返回任何数据（API 和页面均返回 401）
- 当前版本：单用户，用户名密码通过环境变量配置
- 登录方式：用户名 + 密码 → 后端签发 JWT → 前端后续请求携带 token
- 凭证存放：`.env` 文件（已 gitignore），不进仓库

```
# .env
VULNSENTINEL_USERNAME=***
VULNSENTINEL_PASSWORD=***
VULNSENTINEL_JWT_SECRET=<随机生成>
```

## 分页

所有列表接口统一使用 **cursor-based pagination**，禁止 `OFFSET`。

- `OFFSET` 在数据量大时会全表扫描，页数越深越慢
- cursor 基于索引列（如 `id`、`created_at`）做范围查询，性能恒定

```
GET /api/events?cursor=<last_id>&page_size=20

Response:
{
  "data": [...],
  "next_cursor": "evt_10042",
  "has_more": true,
  "total": 8731
}
```

| 参数 | 说明 |
|------|------|
| `cursor` | 上一页最后一条记录的 ID，首页不传 |
| `page_size` | 每页条数，默认 20，允许 20 / 50 / 100 |
| `next_cursor` | 下一页起始游标，前端透传即可 |
| `has_more` | 是否还有下一页 |
| `total` | 总记录数（用 `COUNT` 缓存，不实时查） |
