### ISSUE-117：真实 Celery Worker Health、Queue Smoke 与 Broker/Worker 语义分离

优先级：
P0（自主链基础设施）

GitHub 权威：
#622

## 目标

在纯 Mock 环境启动真实 Redis broker + Celery worker，验证 worker health、queue consumption、post-fork DB/OTel 初始化；broker publish 与 worker liveness 为两个独立信号。

## 前置依赖

#623 / ISSUE-118 SessionProvider Phase A（已完成）。

## Phase A（本 Issue 范围）

1. Compose worker healthcheck（短 timeout，运维 health，非 publish 前置）。
2. 真实 worker 消费 `investigation` queue；`shadowtrace.worker_ping` + `shadowtrace.run_investigation`。
3. 禁止 eager/memory broker 作为生产路径验证；post-fork SessionProvider + OTel `shadowtrace-worker`。
4. 固定 queue routing、`worker_prefetch_multiplier=1`、`visibility_timeout=900`。
5. Broker publish 失败 → 503；broker 接受但零 worker → 任务 queued、health worker degraded、**不**对 publish 返回 worker 503。
6. 禁止 inspect-before-publish 与静默同步执行。

## 文件范围

1. `backend/app/core/celery_app.py`
2. `backend/app/core/celery_health.py`
3. `backend/app/tasks/worker_tasks.py`
4. `backend/app/api/v1/health.py`
5. `infra/docker-compose.yml`
6. `Makefile`
7. `backend/tests/test_core/test_celery_health.py`
8. `backend/tests/test_api/test_celery_worker_health.py`
9. `backend/tests/test_tasks/test_worker_tasks.py`
10. `scripts/celery_worker_smoke.sh`

## 统一命名

- Queue: `investigation`
- Tasks: `shadowtrace.run_investigation`, `shadowtrace.worker_ping`
- Health keys: `celery.broker`, `celery.worker`（HTTP 响应中为嵌套对象 `celery: { broker, worker, task_mode }`）
- `TASK_MODE=celery` 且 `celery.broker=error` 时顶层 `status=degraded`（HTTP 仍为 200；publish 失败仍走 503）

## 测试与验证

```bash
cd backend
.venv/bin/pytest tests/test_core/test_celery_health.py -q
.venv/bin/pytest tests/test_api/test_celery_worker_health.py -q
.venv/bin/pytest tests/test_tasks/test_worker_tasks.py -q
.venv/bin/pytest tests/test_api/test_celery_investigation.py tests/test_tasks/test_investigation_tasks.py -q

# 本地真实 worker smoke（需 Docker）
make up WORKER=1
bash scripts/celery_worker_smoke.sh
# 可选：对已 bootstrap 的 event 验证 run_investigation 全链路
# SMOKE_EVENT_ID=evt-xxx bash scripts/celery_worker_smoke.sh
make worker-smoke-test
```

## Phase B（未做）

`task_reject_on_worker_lost`、redelivery matrix、crash before/after ack、lease fencing、nightly matrix。

## 降级

- CI 默认不启动 worker 容器；单元/集成测 mock inspect。
- 完整 queue smoke 通过 `make up WORKER=1` + `scripts/celery_worker_smoke.sh` 人工/ nightly 门禁。
