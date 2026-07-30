### ISSUE-109：自动处置编排策略（Optional Auto-Response，Mock）

优先级：
P1

目标：
在自动研判路径上，按策略 **可选** 传入 `include_response_execution=true`，使 ResponseAgent → ApprovalEngine → Execute 链路启动；默认仍为 analysis-only（ISSUE-077），与手工 investigate 行为一致。**仅 Mock XDR + Mock Disposition** 验收。

背景：
- 当前默认 `defer_response_execution=true`，用户只见 `generate_report`。
- ISSUE-064 E2E 已验证 full response loop（Mock）。
- 商用需「高危自动出处置方案、L0/L1 可自动执行」的可配置能力。

前置依赖：
ISSUE-108、ISSUE-057（ResponseAgent）、ISSUE-064（E2E loop）、ISSUE-103（UX 可感知，推荐）

输入上下文：
- `AutoInvestigatePolicyService`（ISSUE-108）的 dispatch 参数
- `ActionLevel` L0-L5 自动批准规则（README §4）
- `disposition_policy=required` 事件的 halt-at-reporting 语义

文件范围：
1. `backend/app/services/auto_response_policy.py`（新建）
2. `backend/app/services/auto_investigate_policy.py`（扩展：传递 include_response 标志）
3. `backend/app/core/config.py`
4. `backend/tests/test_services/test_auto_response_policy.py`
5. `backend/tests/integration/test_auto_response_mock_loop.py`（扩展 ISSUE-064 模式）

统一命名：
1. Settings：
   - `AUTO_RESPONSE_ENABLED`（default `false`）
   - `AUTO_RESPONSE_MIN_SEVERITY`（default `high`）
   - `AUTO_RESPONSE_MAX_AUTO_LEVEL`（default `L1`，不超过 README 硬门禁）
   - `AUTO_RESPONSE_EVENT_TYPES`（optional allowlist）
2. Audit：`auto_response:policy_match` / `auto_response:skipped_approval_required`

实现步骤：
1. **Policy 独立于 auto-investigate**：即使 `AUTO_INVESTIGATE_ENABLED=true`，也仅当 `AUTO_RESPONSE_ENABLED=true` 且 severity/event_type 匹配时才 `include_response_execution=true`。
2. **级别门禁**：Policy 不得绕过 ApprovalEngine L2+ 规则；`AUTO_RESPONSE_MAX_AUTO_LEVEL` 只影响「是否进入 response 阶段」，不修改 ActionLevel 判定逻辑。
3. **required disposition 事件**：full-loop 后仍可在 `reporting`/`waiting_approval` halt——ISSUE-103 前端提示；本 Issue 不修改 state machine 矩阵。
4. **Mock 验收场景**：`malicious_process` + auto response → 产生 `isolate_host`/`block_process` 等 **候选** Action（在 allowed_actions 内），L0/L1 自动、L2+ waiting_approval。
5. **安全默认**：三者全 false 时与现网完全一致。
6. **与 ISSUE-093 fail-closed 一致**：writeback readiness 非 READY 时不得 auto-execute，仅生成 plan。

验收标准：
1. 默认配置下 dispatch 仍 `include_response_execution=false`。
2. 开启 auto-response 后 Mock malicious_process 产生 ≥1 条 security response action（非仅 generate_report）。
3. L3+ action 状态为 `waiting_approval`，未 bypass ApprovalEngine。
4. ISSUE-064 E2E 测试不回归；analysis-only 路径不回归。
5. `AUTO_RESPONSE_ENABLED=true` 且 Celery/worker 未起 → degraded 标记，ingest 不失败。

测试与验证：
`pytest backend/tests/test_services/test_auto_response_policy.py backend/tests/integration/test_auto_response_mock_loop.py -v`

降级策略：
ResponseAgent 失败走现有 degraded/reporting 路径；**禁止** silent 跳过 disposition plan。

约束（防冲突）：
- **禁止**修改 `route_after_risk` / `defer_response_execution` 全局默认。
- **禁止**自动批准 L4/L5 或绕过 writeback 门禁。
- **禁止** live tool/disposition；Mock 契约为准。
- 复用 `dispatch_investigation(include_response_execution=...)`，不新造 execute 入口。

---
