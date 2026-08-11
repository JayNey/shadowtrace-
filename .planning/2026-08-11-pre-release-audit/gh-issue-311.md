<!-- ShadowTrace live full-loop audit V-1/V-2/V-3；runtime@3c3e6e9；revalidated against main@44ff256；AUG11_OBSERVED + CODE_CONFIRMED -->

### 类型

Bug 修复（生产 DI 的 XDR_MANAGED execute→verify 集成缺口）

### 优先级

P0

### 当前事实

- 真实 LLM（`LLM_MODE=openai_compatible`）+ `mock_xdr` + Celery fresh-volume 复测：
  - `insider_data_exfiltration`（`evt-20240615-420918b5`）、`suspicious_domain_access`（`evt-20240615-a21c0948`）均完成 seed、investigate、脚本审批，最终连续 720s 停在 `verifying`；
  - entity outbox 为 `delivered`，receipt 为 `accepted/simulated`，Action 为 `success`，`ActionExecutionJob` 却为 `queued`，`verify_*` Action 为 `failed`；
  - Verify phase1 `UNVERIFIABLE` 后进入 manual hold，phase2 不激活 deferred `EVENT_STATUS_UPDATE`。
- 运行产物：`artifacts/live-eval-20260811-115115/`。
- `ActionExecutionService._execute_xdr_managed` 创建 RUNNING Job 并入队 outbox；`DispositionSyncService._apply_action_terminal_from_receipt` 只终态化 Action，不持久化 receipt→Job。
- 现有 `map_disposition_receipt_to_job` 只在测试使用，且合同明确：
  - `ACCEPTED` → `RUNNING`（或有 provider job 时 `QUEUED`）；
  - 仅 `CONFIRMED` → `SUCCESS`。
- production Verify 的 `check_*` 既要求 Job 终态，也要求独立 effect observation；XDR_MANAGED 路径不写 `MockEnvironmentState`，只有 DIRECT_TOOL 路径写。
- #746（ISSUE-204）修复的是 adversarial harness 的 DB 观测桥；#857（ISSUE-261）恢复了特定 production-DI smoke/测试尾链。当前 Compose + 自然 ResponseAgent/XDR_MANAGED 路径仍存在未覆盖残余，不能通过注入 adversarial adapter 宣称已修。

### 根因

```text
XDR_MANAGED submit
  → receipt=ACCEPTED + Action=SUCCESS
  → Job 仍 RUNNING/QUEUED
  → 无 provider applied-state observation
  → Verify phase1 UNVERIFIABLE
  → skip phase2
  → manual_hold / event=VERIFYING
```

问题不是 LLM 输出，也不是缺少 graph resume intent；manual hold 时空 resume 表符合现有人工解除边界。

### 目标

在不破坏 `ACCEPTED ≠ CONFIRMED`、不伪造 observation、不切换 DIRECT_TOOL 的前提下，让生产 DI 的 XDR_MANAGED mock_xdr 路径形成可审计的：

`submit → provider effect completion/readback → Job terminal → independent observation → Verify phase1 → terminal disposition CONFIRMED`

最终 CLOSED 还依赖 ISSUE-312 对 entity ACCEPTED receipt 的 convergence 合同作出决策。

### 推荐修复方案（工业级）

1. **持久化 Job 投影**
   - DSS 收据提交事务内，按 `action.execution_job_id` 锁定 Job；
   - 复用现有 mapper 写 Job 状态、provider_job_id、raw_result、receipt/writeback 关联；
   - 保留全局合同：ACCEPTED 仍是 RUNNING/QUEUED，UNKNOWN 不盲重试，CONFIRMED 才是 SUCCESS。
2. **新增 entity effect completion/readback**
   - 仅 `DISPOSITION_MODE=mock_xdr` 且 receipt `simulated=true` 启用；
   - MockXDR 根据 `entity_action_code + canonical_target` 更新并读取 provider-side applied state（例如 IP block、host isolation、account status、file quarantine）；
   - applied state 命中后产生独立 effect-completion evidence 并允许 Job 进入 SUCCESS；本 issue **不**把 entity receipt 从 ACCEPTED 提升为 CONFIRMED；
   - 禁止从 ACCEPTED 或 Action SUCCESS 直接推导成功。
3. **生成独立 observation**
   - 将 applied-state readback 结果映射到 `VERIFICATION_SPECS` 的 surface；
   - observation 必须携带 action_id、job_id、writeback_id、provider record/version，确保可追溯；
   - live provider 路径不得使用 mock observation bridge。
4. **恢复正常 Verify 两阶段**
   - 不改 `phase1 fail → skip phase2`；
   - phase1 真实 VERIFIED 后，再让现有 EDS 激活 deferred `EVENT_STATUS_UPDATE`；
   - 保留 terminal disposition 的 readback→CONFIRMED。
5. **补两层回归**
   - service：entity submit ACCEPTED 不可使 Job SUCCESS；provider effect readback 后才 Job SUCCESS + observation；
   - Compose production-DI：自然 ResponseAgent/XDR_MANAGED（无 adversarial DI）跑 insider 到 phase1 VERIFIED + terminal disposition CONFIRMED；联合 ISSUE-312 后再要求 CLOSED。

### 文件范围

- `backend/app/services/action_execution_service.py`
- `backend/app/services/disposition_sync_service.py`
- `backend/app/adapters/mock_xdr.py`
- `backend/app/mock_xdr/state.py` / `api.py`
- `backend/app/providers/tools/mock_provider.py`（共享 observation 映射 helper，勿改变 DIRECT_TOOL owner）
- `backend/app/tools/verify/_common.py`（仅测试/可观测，原则上不放宽）
- 相关 service / integration / production-DI tests

### 验收标准

- [ ] ACCEPTED 不能直接把 Job 或 effect 标为成功。
- [ ] provider applied-state readback 后 Job 达到 SUCCESS，observation 可由 action/job/writeback 反查。
- [ ] Verify phase1 containment actions 为 VERIFIED，不再因 `execution_job_not_terminal` / `observation_missing` 进入 manual hold。
- [ ] deferred `EVENT_STATUS_UPDATE` 仅在 phase1 成功后激活，并获得 `CONFIRMED + readback_verified`。
- [ ] 本 issue 独立验收：`insider_data_exfiltration` 在真实 LLM + mock_xdr + production DI 下达到 phase1 VERIFIED，且 terminal disposition 为 CONFIRMED。
- [ ] 联合 ISSUE-312 验收：事件自然 CLOSED，`external_unsynced=false`。
- [ ] 不使用 adversarial adapter、force_close、MockGPT 或预 seed verification 结果。

### 测试与验证

```bash
cd backend
uv run --frozen pytest \
  tests/test_services/test_action_execution.py \
  tests/test_services/test_disposition_sync.py \
  tests/test_agents/test_verify_agent.py -q

cd ..
make up WORKER=1 SCHEDULER=1
make eval-full-loop EVAL_SCENARIO=insider_data_exfiltration EVAL_MAX_EVENTS=1 EVAL_REQUIRE_CLOSED=1
```

### 关联

- 历史：#746（ISSUE-204，harness-only observation）、#857（ISSUE-261，测试尾链）
- 下游合同：#917（ISSUE-302，CLOSED side-effect convergence）
- 评测：#916（ISSUE-301）、#923（ISSUE-304）
- 审计报告：`深度问题调查报告-live-full-loop-20260811.md` V-1/V-2/V-3

### 禁止事项

- 禁止全局改为 `ACCEPTED → Job SUCCESS`。
- 禁止用 receipt/Action 自身循环证明 effect 已发生。
- 禁止把 adversarial `XdrManagedVerifyToolExecutor` 注入 live gold path。
- 禁止 force_close、降低 Verify/strict 断言或切回 MockGPT。
