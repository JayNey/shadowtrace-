<!-- ShadowTrace pre-release audit ID-SEC-003/005；main@738c478；CONFIRMED -->

### 类型

Bug 修复（补偿写回交付期缺少 approval 再校验）

### 优先级

P1

### 当前事实

- `_DELIVERY_APPROVAL_RECHECK_INTENTS` 含 `ENTITY_ACTION_SUBMIT` / `EXECUTION_RESULT_RECORD` / `EVENT_STATUS_UPDATE`，**不含** `COMPENSATION_RECORD`。
- 交付路径对部分 intent 会 `_action_still_approved_for_delivery`；补偿 outbox 仅依赖入队快照。
- 若 rollback action 在投递前被 supersede/撤销，补偿写回仍可能出站。
- 交付期 OutboundGuard 调用未传 `approved_action_ids`，与入队路径不对称（相关但次要）。

### 目标

补偿写回与其他副作用 intent 一样，在交付前基于当前 action 行做 approval/supersede 再校验；失败则 fail-closed（不投递）。

### 推荐修复方案（工业级）

1. 将 `DispositionIntentKind.COMPENSATION_RECORD` 加入 `_DELIVERY_APPROVAL_RECHECK_INTENTS`。
2. 复用 `_action_still_approved_for_delivery`（或为 compensation 明确绑定的 rollback action 状态检查）；superseded / 非 approved 集合 → 不投递，记审计/degraded。
3. 补集成测试：入队后 supersede rollback → worker 投递被阻断。
4. （可选同 PR）交付期 guard 传入 `approved_action_ids`，与入队一致；若范围变大则拆 follow-up。
5. 不改变 UNKNOWN 禁止盲重试合同。

### 文件范围

- `backend/app/services/disposition_sync_service.py`
- `backend/tests/test_services/test_disposition_sync.py`（或 rollback/compensation 相关测试）

### 验收标准

- [ ] COMPENSATION 在交付前执行 approval/supersede 再校验。
- [ ] supersede 后不再出站；有可观测审计/错误码。
- [ ] 合法补偿路径仍可投递（回归测）。

### 测试与验证

```bash
cd backend && uv run --frozen pytest \
  tests/test_services/test_disposition_sync.py \
  tests/test_services/test_rollback_service.py -q --tb=short
```

### 关联

- 审计 ID-SEC-003、ID-SEC-005。

### 禁止事项

- 禁止为「方便补偿」跳过 supersede 检查。
- 禁止打开 live 开关做验收。
