# ShadowTrace 部署指南（ISSUE-088）

## 前置要求

| 依赖 | 最低版本 | 说明 |
|------|----------|------|
| Docker | 24+ | 含 docker compose 插件 |
| Python | 3.11+ | 仅 bootstrap 脚本编译/迁移时需要 |
| 内存 | 4 GB | 默认 mock 模式（不含 OpenSearch / Neo4j） |
| 磁盘 | 2 GB | 主要为 PostgreSQL 数据卷 |

**无需真实的 XDR、GPU 推理机或外部 LLM API key。**  
默认全栈以 **mock 模式** 运行，所有数据、推理与处置均在容器内闭环。

---

## 一键启动

```bash
# 1. 启动核心服务（postgres, redis, mock-xdr, backend, frontend）
make up

# 2. 数据库迁移 + 摄入演示数据 + 自动触发研判
make bootstrap

# 3. （可选）冒烟验证
make smoke-bootstrap

# 4. 打开浏览器访问前端看板
#    http://localhost:3000
```

启动后在前端 **事件看板** 可见 3 个演示事件；`make bootstrap` 会自动对 `new` 状态事件 POST `/investigate`，也可在前端手动再次触发。

---

## 常用命令

| 命令 | 说明 |
|------|------|
| `make up` | 启动核心服务（--build 构建镜像） |
| `make up WORKER=1` | 启动核心服务 + Celery worker（需同时设 `TASK_MODE=celery`） |
| `make bootstrap` | 迁移 + mock-xdr 种子 + SourceAdapter 摄取 + 自动触发研判 |
| `make bootstrap LOAD_KB=true` | 同上 + 加载知识库（约 30-60 秒） |
| `make smoke-bootstrap` | bootstrap 后冒烟：health + ≥3 事件 + 前端反代 |
| `make down` | 停止并移除容器（**数据卷保留**） |
| `make down-v` | 停止并移除容器 + **删除所有数据卷** |
| `make test` | 运行后端 pytest 健康检查测试 |

---

## 可选组件

```bash
# OpenSearch 全文搜索（ISSUE-084）
docker compose -f infra/docker-compose.yml --profile optional up -d opensearch

# Neo4j 图谱镜像（ISSUE-082）
docker compose -f infra/docker-compose.yml --profile optional up -d neo4j

# Celery worker（异步研判执行）
# 注意：需同时将 backend 的 TASK_MODE 改为 celery（默认 background）
docker compose -f infra/docker-compose.yml --profile worker up -d worker
```

启用 OpenSearch / Neo4j 后，需在 `.env` 中设置对应开关：
```ini
OPENSEARCH_ENABLED=true
NEO4J_ENABLED=true
```

---

## 端口约定

| 服务 | 端口 | 说明 |
|------|------|------|
| 前端（nginx） | 3000 | React SPA，自动反代 /api → backend |
| 后端（FastAPI） | 8000 | API + Socket.IO |
| Mock XDR | 8100 | 模拟外部数据源与处置端点 |
| PostgreSQL | 5432 | pgvector 扩展已启用 |
| Redis | 6379 | 缓存 + 事件总线 |
| OpenSearch | 9200 | 可选，需 `--profile optional` |
| Neo4j HTTP | 7474 | 可选，需 `--profile optional` |
| Neo4j Bolt | 7687 | 可选，需 `--profile optional` |

---

## 健康检查

```bash
curl http://localhost:8000/api/v1/health
```

Mock 模式下预期响应（符合 ISSUE-001 契约）：
```json
{
  "status": "ok",
  "postgres": "ok",
  "redis": "ok",
  "source_adapter": {
    "status": "ok",
    "mode": "mock_xdr",
    "capability": {
      "LOG_INGESTION": "SUPPORTED",
      "QUERY": "SUPPORTED",
      "EVENT_DISPOSITION": "UNSUPPORTED",
      "ENTITY_RESPONSE": "UNSUPPORTED"
    }
  },
  "disposition_adapter": {
    "status": "ok",
    "mode": "mock_xdr",
    "capability": {
      "LOG_INGESTION": "UNSUPPORTED",
      "QUERY": "UNKNOWN",
      "EVENT_DISPOSITION": "SUPPORTED",
      "ENTITY_RESPONSE": "SUPPORTED"
    }
  },
  "tool_provider": {
    "status": "ok",
    "mode": "mock",
    "capability": {
      "query": "SUPPORTED",
      "response": "SUPPORTED",
      "verification": "SUPPORTED",
      "rollback": "SUPPORTED"
    }
  },
  "simulation_enabled": true,
  "version": "0.1.0"
}
```

当 PostgreSQL 或 Redis 不可达时，顶层 `status` 变为 `"degraded"` 且 HTTP 状态码为 503。

---

## 切换到 Live 模式

Live 模式**不是** compose profile；通过可选 env 叠加文件启用。复制 `infra/.env.live.example` 为项目根目录 `.env.live` 并填入凭证，
然后重建 stack（compose 会自动叠加该文件，覆盖 mock 默认值）：

```bash
cp infra/.env.live.example .env.live
# 编辑 .env.live，填入 LLM_API_KEY 与 provider 凭证
make down && make up
```

也可手动修改根目录 `.env` / `.env.example` 中的关键开关：

```ini
SIMULATION_ENABLED=false
LLM_MODE=live
LLM_API_KEY=sk-your-key-here
SOURCE_MODE=live_crowdstrike    # 替换为实际 provider
TOOL_MODE=live
ALLOW_LIVE_SIDE_EFFECTS=true    # 显式授权
```

**安全栅栏**：`APP_ENV=production` 时，应用启动即拒绝任何 mock/simulation 模式组合（fail-closed）。  
Mock 模式下的 `ALLOW_*` 始终为 `false`。

---

## 故障排除

### 端口冲突

修改 `infra/.env`（复制自 `infra/.env.example`）中的端口映射，然后：

```bash
# 检查端口占用
# Linux / macOS:
lsof -i :3000 -i :8000 -i :5432 -i :6379 -i :8100
# Windows (PowerShell):
netstat -ano | findstr "3000 8000 5432 6379 8100"

# 修改 infra/.env 中的端口后重建
make down && make up
```

### 后端不健康

```bash
docker compose -f infra/docker-compose.yml logs backend
```

常见原因：数据库未就绪（等待 postgres healthy）、端口冲突。

### 前端无法加载数据

确认 nginx 能访问后端：`curl http://localhost:3000/api/v1/health`。  
如果返回 502，检查 backend 容器是否在运行。

### 重置所有数据

```bash
make down-v   # 删除容器 + 数据卷
make up       # 重新启动
make bootstrap
```

### Mock XDR 连接失败

```bash
curl http://localhost:8100/mock-xdr/v1/health
```

若不可达，检查 mock-xdr 容器状态：`docker compose -f infra/docker-compose.yml ps mock-xdr`

> **注意**：mock-xdr 为内存状态，容器重启后数据丢失。可通过 `make bootstrap` 重新播种。

### 前端构建失败

```bash
# 降级：仅启动 backend + 依赖（不含 frontend）
docker compose -f infra/docker-compose.yml up -d backend
make bootstrap
# 然后直接访问 API 文档：http://localhost:8000/docs
```

前端构建失败不影响后端 API 演示。

### 重复运行 bootstrap

`make bootstrap` 在数据卷上**幂等**：若已有 ≥3 个事件，会跳过 seed/ingest（alembic 仍运行）。
强制重新播种：`FORCE_BOOTSTRAP=true make bootstrap`。  
如需完全重置：`make down-v && make up && make bootstrap`。

## 可选：OpenTelemetry 可观测性（ISSUE-092）

默认关闭（`OTEL_ENABLED=false`），对业务零影响。启用时需同时配置 **API 进程**与 **Celery worker**（若使用 `--profile worker`）。

### 1. 启动 observability 栈

```bash
docker compose -f infra/observability/docker-compose.observability.yml up -d
```

- Grafana: http://localhost:3001 （admin / shadowtrace）
- Prometheus: http://localhost:9090
- OTLP HTTP: http://127.0.0.1:4318

### 2. 启用 backend / worker 导出

在 `.env` 或 shell 中设置（backend 与 worker 均需一致，worker 建议使用独立 service name）：

```bash
OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318   # 本机 backend
# Docker worker 默认 compose 已映射 host.docker.internal:4318
OTEL_SERVICE_NAME=shadowtrace-backend               # worker compose 内为 shadowtrace-worker
```

然后重启 stack：

```bash
make up
# 若使用 Celery worker：
docker compose -f infra/docker-compose.yml --profile worker up -d
```

### 3. 验证

```bash
cd backend && pytest tests/test_core/test_telemetry.py -v
make bootstrap   # 产生写回与研判流量
```

在 Grafana「ShadowTrace Writeback Observability」看板查看四面板（积压、确认率、重试/冲突、UNKNOWN）。

> Traces 当前由 collector 输出到 debug 日志；指标经 Prometheus 供 Grafana 使用。导出失败仅记日志，不阻塞业务。
