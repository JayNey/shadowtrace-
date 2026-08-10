<!-- ShadowTrace live-LLM audit ID-ORCH-002；main@34947d1；CONFIRMED（#288 已合入，可基于最新 main 实施） -->

### 类型

Bug 修复（Graph resume / Celery soft-timeout / 终态幂等）

### 优先级

P0

### 当前事实

- 真实 LLM 动态评测中，一次 `run_investigation` 600s soft timeout 后出现约 4,400 次 `graph resume failed`、4,404 次非法 `failed → failed` 转换，并占满 Celery worker。
- `_mark_graph_failed()` 无条件调用 `StateMachineService.transition(..., FAILED)`（`workflow_graph.py:402-417`）；事件已 FAILED 时仍重复尝试非法自转换，异常被吞掉。
- `graph_resume.py:55-62` 已禁止 FAILED/CLOSED 全图重启（ISSUE-247），`graph_resume_observability.py` 将 resume 重试限制为 3 次——但未解决失败幂等与 nested resume 分叉。
- `approval_node` 仍可能在 checkpoint 状态与 DB 权威状态不一致时触发 resume，放大热循环。

### 目标

确保 state mismatch、soft timeout 或 resume 失败最多产生一次有界失败处理；终态事件不再进入 checkpoint continuation；保留合法 `FAILED → REPORTING` 报告收尾能力。

### 推荐修复方案（工业级）

1. 使 `_mark_graph_failed()` 幂等：
   - 先读取数据库权威状态；
   - `FAILED` / `CLOSED` 时直接 no-op，并记录 bounded metric；
   - 只允许非终态事件执行一次 FAILED 转换。
2. 消除 approval 内的同步 nested resume：
   - `ApprovalEngine.evaluate_plan()` 返回 decision result；
   - durable intent dispatcher 在事务完成后调度 resume；
   - graph 内 evaluate 时禁止再次 invoke 同一 graph。
3. 对 `caller EventStatus does not match authoritative state` 标记为非瞬态状态错误，重新读取权威状态后路由到 terminal/report-only/halt。
4. soft-timeout 时 mark intent dead、释放 lease、推进 generation fence，由独立 reconciliation 决定 FAILED 或 report-only。
5. 所有重试只覆盖明确的瞬态基础设施错误，设置总 attempts 与 wall-clock 上界。

### 文件范围

- `backend/app/orchestration/workflow_graph.py`
- `backend/app/services/approval_engine.py`
- `backend/app/orchestration/graph_resume.py`
- `backend/app/orchestration/graph_resume_observability.py`
- `backend/app/tasks/investigation_tasks.py`
- 相关 orchestration / redelivery tests

### 验收标准

- [ ] 已 FAILED/CLOSED 的事件调用 `_mark_graph_failed()` 不写状态、不新增重复 audit。
- [ ] 同一 approval 调用栈不会 nested invoke 同一 event graph。
- [ ] state mismatch 不触发无界 node retry。
- [ ] 单次故障的 resume failure 与 failed-transition 日志均有严格上界。
- [ ] 合法 `FAILED → REPORTING` report-only 路径保留。
- [ ] 真实 Celery soft-timeout 场景中 worker 能退出，不出现日志/CPU 热循环。

### 测试与验证

```bash
cd backend
uv run --frozen pytest \
  tests/test_orchestration/test_graph_resume_observability.py \
  tests/test_tasks/test_investigation_tasks.py \
  tests/test_tasks/test_celery_redelivery_matrix.py \
  tests/test_orchestration/test_workflow_graph.py -q
```

另需 clean repro 动态验证，断言日志计数有界。

### 依赖/关联

- ISSUE-247 / ISSUE-288（#897，已 CLOSED）redelivery 与 disposition-only 修复已合入；本 Issue 补失败幂等与 nested resume。
- 建议在 ISSUE-301 fresh-stack matrix 上复现与验收。

### 禁止事项

- 禁止吞掉未知异常后伪造成功。
- 禁止允许 `FAILED → FAILED` 自循环。
- 禁止用更长 Celery timeout 代替状态机修复。
- 禁止在 approval transaction / graph node 内同步重入同一 graph。
