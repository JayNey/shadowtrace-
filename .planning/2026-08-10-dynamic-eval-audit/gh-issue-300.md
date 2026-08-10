<!-- ShadowTrace live-LLM audit ID-WB-006；main@34947d1；CONFIRMED -->

### 类型

Bug 修复（Disposition outbox / 确定性 adapter 错误分类）

### 优先级

P1

### 当前事实

- Mock adapter 对不存在的 source object 返回显式 `error_code=not_found`。
- Adapter 将该 4xx 转为 `ShadowTraceValidationError(error_code="not_found")`。
- `OutboxWorker.run_once()` 除 Guardrail 外 catch 所有 Exception，并统一标记（`disposition_sync_service.py:2413-2422`）：
  - `delivery_status=paused`；
  - `latest_writeback_status=unknown`；
  - `error_code=delivery_outcome_unknown`。
- paused reconcile 看到 lookup NOT_FOUND 且 adapter 支持幂等安全重试时，会重新置为 READY。
- 动态评测中 5 个明确 `source object ... not found` 被反复 pause/lookup/retry；部分触发由跨场景 seed reset 引起，但同一错误分类也会出现在真实对象删除、租户/connector 漂移或 stale locator。

### 目标

只对“提交结果确实未知”的传输故障执行 pause + lookup；对明确的 adapter domain rejection 进入确定性终态，避免永久重试。

### 推荐修复方案（工业级）

1. 建立显式错误分类函数，不使用异常 message 字符串：
   - `not_found`、`unsupported_*`、确定性 validation rejection → terminal/dead-letter；
   - version/concurrency conflict → 现有 conflict/supersede 流程；
   - transport lost、5xx malformed outcome → paused/unknown + lookup；
   - guard violation → 现有 dead-letter。
2. `OutboxWorker.run_once()` 在 catch-all 前单独捕获 `ShadowTraceValidationError`：
   - 仅对 allowlist 中的确定性 code dead-letter；
   - 持久化原始 bounded `error_code`；
   - action/writeback 投影进入可解释的 FAILED/UNKNOWN 终态。
3. reconcile 只对“曾经可能已提交”的 outbox 执行 lookup/safe-retry；明确 submit 前 4xx rejection 不应进入 lookup。
4. 记录按 adapter/error_code 的 dead-letter metric，禁止高基数字符串标签。
5. 保持幂等 transport recovery 行为不变。

### 文件范围

- `backend/app/services/disposition_sync_service.py`
- `backend/app/adapters/disposition/base.py`（若增加共享分类 contract）
- `backend/app/adapters/mock_xdr.py`
- disposition sync / outbox worker tests

### 验收标准

- [ ] 显式 `not_found` 第一次投递后进入 terminal/dead-letter，不进入 PAUSED。
- [ ] reconcile 不会把该 outbox 重新置 READY。
- [ ] transport loss 仍进入 UNKNOWN/PAUSED，并可通过 lookup 或 safe retry 恢复。
- [ ] conflict 与 guardrail 分支语义不变。
- [ ] action、outbox、audit/metric 能区分 deterministic rejection 与 ambiguous outcome。
- [ ] 不依赖错误 message 文本匹配。

### 测试与验证

```bash
cd backend
uv run --frozen pytest \
  tests/test_services/test_disposition_sync.py \
  tests/test_services/test_disposition_sync_operator_retry_unit.py -q
```

增加 adapter `not_found`、transport-lost、5xx、conflict 四类矩阵测试。

### 依赖/关联

- 与 manual-resolution 安全语义正交。
- 与 disposition source selection/fallback issue 正交。
- 建议在 ISSUE-301 fresh-stack matrix 上验收写回终态。

### 禁止事项

- 禁止把所有 ValidationError 一律 dead-letter。
- 禁止对明确 not_found 继续幂等 retry。
- 禁止破坏 transport ambiguity 的 lookup 恢复。
- 禁止按异常 message 字符串分类。
