### ISSUE-107：Mock XDR 持续摄取调度器（Ingestion Scheduler）

优先级：
P1

目标：
在 **不引入真实 XDR、不改动 SourceIngester 核心语义** 的前提下，提供可常驻运行的 Mock 增量摄取能力：按配置间隔对 `MockXDRSourceAdapter` 执行 `SourceIngester.poll()`，将新 alert/incident 入库为 `status=new` 事件，为后续自动研判（ISSUE-108）提供事件源。

背景：
- ISSUE-016 已实现 `SourceIngester.poll()`、watermark、PushReceiver；但 **无默认 compose 常驻调度**。
- 当前 ingest 依赖 `seed_mock_xdr_and_ingest.py` / `bootstrap.sh` 手工触发。
- 工程方案 ISSUE-056 已预留 Celery Beat 承载 periodic scanner；本 Issue 复用同一模式，**不新建第二套 ingest 逻辑**。

前置依赖：
ISSUE-016、ISSUE-010（Mock XDR）、ISSUE-056（Celery，可选 Beat profile）

输入上下文：
- `SOURCE_MODE=mock_xdr`（本 Issue **仅验收 Mock**；live 模式不得启用此调度器）
- 现有 `SourceIngester`、`MockXDRSourceAdapter`、`get_settings()`

文件范围：
1. `backend/app/ingestion/ingestion_scheduler.py`（新建：封装 poll 一次循环）
2. `backend/app/tasks/ingestion_tasks.py`（新建：Celery task `shadowtrace.poll_sources`）
3. `backend/app/core/config.py`（新增 env，**默认关闭**）
4. `infra/docker-compose.yml`（可选 `--profile scheduler` 或扩展 worker Beat）
5. `backend/tests/test_ingestion/test_ingestion_scheduler.py`
6. `docs/deployment.md`（Mock 自动摄取说明）

统一命名：
1. Celery task：`shadowtrace.poll_sources`
2. Settings：`INGESTION_SCHEDULER_ENABLED`（default `false`）、`INGESTION_POLL_INTERVAL_S`（default `60`）
3. 锁：PostgreSQL advisory lock key `ingestion_poll`（实现为 SHA256 派生 stable int64；与 timeout scanner 模式一致）

实现步骤：
1. **`IngestionScheduler.run_once()`**：读取 settings → 若 `source_mode != mock_xdr` 则 no-op 并 log（**禁止** live/file 模式静默启用）。
2. 构造已有 `MockXDRSourceAdapter` + `SourceIngester`，调用 `poll(adapter, object_types, batch_size)`；**不得**复制 ingest 事务/watermark 逻辑。
3. Celery Beat 或 backend lifespan periodic task（二选一，优先 Beat 与 ISSUE-056 对齐）按 interval 触发；多实例用 advisory lock 保证单执行。
4. poll 结果写入 structured log + 可选 Redis 计数（accepted/duplicate/rejected）；**不**在此 Issue 触发 investigate（交给 ISSUE-108）。
5. Compose：`INGESTION_SCHEDULER_ENABLED=true` 时启动 Beat/worker profile；默认 compose **行为不变**（向后兼容）。
6. 测试：mock adapter 返回新 incident → scheduler run_once → DB 新增 `new` 事件；重复 poll → duplicate；非 mock_xdr mode → skip。

验收标准：
1. 默认部署（scheduler 关闭）零行为变化。
2. Mock 模式开启 scheduler 后，Mock XDR 新 seed 的数据在 ≤2×interval 内出现在 `GET /events`（无需手工 seed 脚本）。
3. watermark 正确推进，重启后无重复 accepted（duplicate 计数正确）。
4. `SOURCE_MODE=file|live` 时 scheduler 不执行 poll（fail-safe log）。
5. 单测 + 集成测试通过；不破坏 ISSUE-016 现有测试。

测试与验证：
`pytest backend/tests/test_ingestion/test_ingestion_scheduler.py -v`  
手工：`make up SCHEDULER=1`（或 `docker compose --profile scheduler up -d`），向 mock-xdr seed 新场景后观察 `scheduler-worker` ingest log。

降级策略：
scheduler 失败保留最后 watermark，标记 connector degraded；**不得**回退 file 模式或伪造 ingest success。

约束（防冲突）：
- **禁止**修改 `SourceIngester.poll()` 签名与 watermark 语义。
- **禁止**连接真实 XDR；live adapter 不在本 Issue 范围。
- **禁止**在 ingest 路径内直接调用 SuperAgent（见 ISSUE-108）。

---
