<!-- ShadowTrace live full-loop audit S-2；revalidated against main@44ff256；PRODUCT_CONTRACT_DECISION_REQUIRED -->

### 类型

产品合同决策 / Bug 修复（CLOSED side-effect convergence；需讨论）

### 优先级

P1·需讨论

### 当前事实

- ISSUE-302 已建立 fail-closed：`disposition_policy=required` 的事件在当前 revision 存在 in-flight Job、未确认 outbox 或未收敛 required effect 时不得 CLOSED。
- ResponseAgent 的 entity actions 使用 `entity_action_submit`，且 `writeback_applicable=false`；终态 source disposition 由独立 virtual Action / `EVENT_STATUS_UPDATE` 承担。
- MockXDR 对 entity submit 返回 `ACCEPTED`；现有自动 `confirm_readback` 只支持 `EVENT_STATUS_UPDATE` 的 `target_disposition`，不能确认实体 effect。
- ISSUE-311 明确保留 entity receipt=ACCEPTED，另用独立 provider applied-state proof 终态化 Job/验证 effect。在此方案下，required 场景仍可能出现：

```text
entity Job/effect 已由独立 readback 验证
terminal EVENT_STATUS_UPDATE 已 CONFIRMED
但 entity outbox receipt 仍 ACCEPTED
→ ISSUE-302 以 OUTBOX_NOT_CONFIRMED 拒绝 CLOSED
```

- 这是产品合同问题，不应靠全局“ACCEPTED 当 CONFIRMED”或删除 close gate 解决。
- 已关闭 #917（ISSUE-302）解决的是 CLOSED 与 side-effect 并存的通用 gate；本 issue 的新增问题是 **`writeback_applicable=false` entity effect 已独立验证后，ACCEPTED receipt 是否仍属于 gate-applicable 未收敛项**。

### 需要确认的产品合同

对 `writeback_applicable=false` 的 entity action，CLOSED 应采用哪种收敛证据：

1. **推荐**：`terminal Job SUCCESS + independent provider effect VERIFIED` 为 entity effect 的收敛条件；entity submit receipt 可保留 ACCEPTED。
2. 若 provider 支持 entity-specific readback：由 readback 产生 entity CONFIRMED receipt，再沿用 outbox confirmed gate。

两者都必须保留 `EVENT_STATUS_UPDATE` 的 `CONFIRMED + readback_verified`；不能让 terminal disposition 只凭 ACCEPTED 结案。

### 目标

让 ISSUE-302 按 side-effect 类型判断收敛，避免：

- 已有独立 effect proof 的 entity action 被 `ACCEPTED` 永久挡住；
- 将 terminal source disposition 的严格 readback 误放宽；
- NOT_REQUIRED quick-close 被全局严格化。

### 推荐修复方案（工业级）

1. **定义显式 convergence policy**
   - `EVENT_STATUS_UPDATE / writeback_applicable=true`：必须 CONFIRMED + readback_verified；
   - `entity_action_submit / writeback_applicable=false`：必须 Job terminal success + independent effect VERIFIED；如果 provider 支持 entity receipt confirmation，可进一步要求 CONFIRMED；
   - notification/audit/detached actions 不进入 required gate。
2. **基于当前 revision 与 owner 分类**
   - 仅 gate 当前 revision、非 superseded、非 detached 的 required response effects；
   - 不以 intent 字符串散落判断，使用枚举/策略函数输出结构化 reason。
3. **保留失败关闭**
   - Job 失败、effect UNVERIFIABLE/FAILED、UNKNOWN delivery、缺失 observation 都不得视为收敛；
   - force_close 保留 admin 逃生舱并标 `external_unsynced`，禁止 gold path 使用。
4. **API/审计可解释**
   - outstanding 列表区分 `job_in_flight`、`effect_unverified`、`terminal_writeback_unconfirmed`；
   - `background_side_effects_pending` 不得把 gate-applicable effect 隐藏成 detached。
5. **建立合同测试矩阵**
   - required entity effect 已验证 + terminal disposition confirmed → 可 CLOSED；
   - entity receipt accepted 但无 effect proof → 不可 CLOSED；
   - terminal disposition accepted 即使 entity 已验证 → 不可 CLOSED；
   - NOT_REQUIRED 保持 quick-close/background-detached 语义。

### 文件范围

- `backend/app/services/side_effect_convergence.py`
- `backend/app/models/workflow.py`（`validate_closed_gate`）
- `backend/app/api/v1/events.py` / schemas（reason/count 可观测面）
- `backend/app/services/event_disposition_service.py`
- 对应 unit / integration / contract tests

### 验收标准

- [ ] 产品合同在代码注释、API 字段 description 与测试中一致。
- [ ] entity ACCEPTED 不能单独满足 gate；必须有 terminal Job + independent effect proof。
- [ ] terminal `EVENT_STATUS_UPDATE` 仍必须 CONFIRMED + readback_verified。
- [ ] required insider 场景自然 CLOSED，且所有 gate-applicable effect 均有可追溯证据。
- [ ] NOT_REQUIRED domain/FP quick-close 合同无回归。
- [ ] force_close 仍绕 gate，但 `external_unsynced=true` 且不进入 gold-path 测试。

### 测试与验证

```bash
cd backend
uv run --frozen pytest \
  tests/test_services/test_side_effect_convergence.py \
  tests/test_models/test_state_machine.py \
  tests/integration/test_production_full_loop_disposition.py -q
```

### 关联

- 前置：ISSUE-311（production XDR_MANAGED effect completion/readback）
- 历史：#917（ISSUE-302）
- 安全边界：#927（ISSUE-308 force_close admin RBAC）
- 审计报告：`深度问题调查报告-live-full-loop-20260811.md` S-2 / 10.5

### 禁止事项

- 禁止全局将 ACCEPTED 提升为 CONFIRMED。
- 禁止删除 required CLOSED gate 或把所有 action 一刀切纳入 gate。
- 禁止让 terminal disposition 复用 entity effect proof。
- 禁止用 force_close 作为正常收敛路径。
