<!-- ShadowTrace live full-loop audit F-3；revalidated against main@44ff256；STATIC_RISK + PRE-ISSUE-296_HISTORICAL（post-fix recurrence needs reproduction） -->

### 类型

Bug 修复（Celery SoftTimeLimit 与事件/intent 原子终态；需讨论/需复现）

### 优先级

P1·需讨论

### 当前事实

- `run_investigation` 使用 Celery `soft_time_limit=600`。
- `SuperAgent.investigate` 的通用 `except Exception` 会发布 agent_failed，并将 event 转为 `FAILED`；`SoftTimeLimitExceeded` 可进入该路径。
- task 层随后另行捕获 soft-limit，处理 investigation intent 的 lease/fence/dead 语义。
- 2026-08-10 worker 日志曾直接证实：真实 LLM 长链命中 soft-limit 后走 SuperAgent FAILED 路径；该证据早于 #911（ISSUE-296）的 resume 热循环修复。
- 2026-08-11 首轮 `account_anomaly_fp` 快速显示 FAILED，但未保存对应 worker/audit，**不能断言同因**；当前 main 尚无 post-ISSUE-296 动态复现，本 issue 的现状等级是代码确认的双 owner 原子性风险，需先补复现。
- 当前两层分别决定 event 与 intent 终态，静态上仍存在状态分叉风险：
  - event 先 FAILED，但任务层后续若满足严格可恢复条件，也无法再原子选择受限 resume；
  - intent DEAD，但 event 留在非终态；
  - 简单移除 event FAILED 又可能留下永久悬挂；
  - 简单增加 timeout 只延迟问题。
- ISSUE-299 已明确 LLM timeout/unknown outcome 不可盲目重试；本 issue 不应恢复 provider 调用级盲重试。

### 需要确认的恢复合同

推荐由 task/intent 层成为 soft-limit 的唯一终态 owner，并默认保留 ISSUE-296 的 checkpoint invalidation + intent DEAD 安全语义：

1. 默认：task 层原子将 intent DEAD，并将 event 转 FAILED，reason=`soft_time_limit_exceeded`；
2. 只有 checkpoint 被显式证明可恢复、lease fence 有效、未超过 bounded attempts、且不存在 UNKNOWN/已提交副作用时，才允许一次受限 resume/redelivery；
3. UNKNOWN provider outcome 必须先走显式 reconciliation，不可直接重复副作用。

### 目标

保证 soft-limit 发生时 event、investigation intent、checkpoint/lease 的结果可恢复或明确终止，且三者不会分叉、热循环或重复副作用。

### 推荐修复方案（工业级）

1. **异常分层**
   - `SuperAgent.investigate` 显式捕获 `SoftTimeLimitExceeded`；
   - 记录 lifecycle/audit 后原样 re-raise，不在 agent 层决定 event FAILED；
   - 普通业务异常仍沿用当前 FAILED 语义。
2. **task 层单一决策**
   - 在 fenced transaction 内读取 intent attempt、checkpoint version、event revision；
   - 默认原子执行 `DEAD + event FAILED`；仅在上述严格可恢复条件全部满足时选择 `bounded resume`；
   - event transition 与 intent outcome 必须携带同一 correlation/reason。
3. **避免重复副作用**
   - 只有 checkpoint 标明可安全恢复的纯调查阶段才能 resume；
   - 已提交 provider/outbox 的阶段先 reconciliation，禁止重放 execute；
   - 延用 Action/Job idempotency 与 outbox delivery guarantees。
4. **可观测性**
   - 指标区分 `soft_limit_recovered`、`soft_limit_terminal`、`soft_limit_reconcile_required`；
   - eval 失败输出 intent status/error_class、event transition reason、最后 checkpoint/node。
5. **边界测试**
   - soft-limit before side effect：一次 bounded resume 后成功；
   - soft-limit after ambiguous submit：不重复投递，进入 reconciliation；
   - attempts exhausted：event FAILED 与 intent DEAD 原子一致；
   - worker redelivery/lease loss：旧 owner 不得覆盖新 owner。

### 文件范围

- `backend/app/agents/super_agent.py`
- `backend/app/tasks/investigation_tasks.py`
- investigation intent / lease / checkpoint service
- metrics/audit schemas（如需）
- `scripts/dynamic_eval_full_loop.py`（诊断输出）
- 对应 task、redelivery、state-transition integration tests

### 验收标准

- [ ] SuperAgent 不再把 SoftTimeLimit 当普通异常直接决定 event FAILED。
- [ ] 每次 soft-limit 最终只能得到一种原子结果：受限恢复，或 intent DEAD + event FAILED。
- [ ] 不出现非终态 event + DEAD intent、FAILED event + 活跃 resume intent。
- [ ] ambiguous provider outcome 不自动重复副作用。
- [ ] bounded attempts 耗尽后明确失败，无无限 retry/failed→failed 热循环。
- [ ] 真实 LLM 慢调用下诊断包含 correlation、checkpoint/node、event/intent outcome。

### 测试与验证

```bash
cd backend
uv run --frozen pytest \
  tests/test_tasks/test_investigation_tasks.py \
  tests/test_tasks/test_celery_redelivery_matrix.py \
  tests/test_agents/test_super_agent.py -q
```

### 关联

- #914（ISSUE-299，LLM timeout 不盲重试）
- #896（ISSUE-287，Celery redelivery/checkpoint）
- #911（ISSUE-296，failed→failed 热循环）
- 相对 ISSUE-296 的增量：复核/统一 soft-limit 的 event 与 intent 终态 owner；不重新打开已修复的 resume 热循环结论。
- 审计报告：`深度问题调查报告-live-full-loop-20260811.md` F-3

### 禁止事项

- 禁止只把 `soft_time_limit` 调大。
- 禁止恢复 LLM/provider 调用级盲重试。
- 禁止 agent 层与 task 层分别写互相矛盾的终态。
- 禁止在 UNKNOWN 副作用结果下自动重放 execute。
