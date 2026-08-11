<!-- ShadowTrace pre-release audit ID-BLK-001..004；main@738c478；CONFIRMED -->

### 类型

Bug 修复（CI 门禁必红 / ISSUE-302·299 合入后遗债）

### 优先级

P0

### 当前事实

- `main@738c478` 本地复跑：`check_contract_drift.py` exit 1（`openapi/openapi.json` content_mismatch）。
- `EventDetailResponse` / `EventCloseResponse` 已在 `schemas.py` 增加 `background_side_effects_pending`、`outstanding_side_effect_count`、`gate_applicable_outstanding_count`，但 committed OpenAPI **无**这些字段。
- `mypy app`：10 errors（`side_effect_convergence.py` 类型赋值；`events.py` 将 `dict[str, int|bool]` 展开进响应模型）。
- `ruff check`：6 errors；`ruff format --check`：4 files would be reformatted。
- ISSUE-299 将 `LLMTimeoutError.default_retryable=False`，但 `test_llm_error_subclass_retry_rules` 仍断言 `is_retryable(...) is True` → pytest 失败。
- 上述对应 CI jobs：`contract-drift`、`backend-lint`、`backend-test`。

### 目标

在不改变 CLOSED / 写回 / timeout 产品语义的前提下，恢复 main 对 CI 门禁的绿色，并保证 ISSUE-302 API 字段进入契约。

### 推荐修复方案（工业级）

1. **契约**：运行 `make update-contracts`，提交刷新后的 `contracts/openapi/openapi.json`（及其他导出面若有漂移）；禁止手改 OpenAPI JSON。
2. **mypy**：
   - `_summarize_outbox_fields` 为 delivery / writeback 使用独立变量与正确类型；
   - side-effect API 字段用 `TypedDict` 或显式 kwargs 构造 `EventDetailResponse` / `EventCloseResponse`，禁止 `**dict[str, int|bool]` 吞类型。
3. **ruff**：`ruff check --fix` + `ruff format`；仅格式/import 整理，不夹带行为改动。
4. **LLM timeout 测试**：更新 `test_llm_error_subclass_retry_rules` 断言 timeout **不可**盲目重试，与 ISSUE-299 / `LLMTimeoutError.default_retryable=False` 一致；**禁止**为了绿测把 timeout 改回可重试。

### 文件范围

- `contracts/openapi/openapi.json`（及 `make update-contracts` 产出）
- `backend/app/api/v1/schemas.py`（若需 Field description，仅文档字段）
- `backend/app/api/v1/events.py`
- `backend/app/services/side_effect_convergence.py`
- `backend/tests/test_core/test_errors.py`
- 相关 ruff 触及的文件（import/format only）

### 验收标准

- [ ] `uv run --frozen python ../scripts/check_contract_drift.py` exit 0。
- [ ] `uv run --frozen mypy app` exit 0。
- [ ] `uv run --frozen ruff check app tests` 与 `ruff format --check app tests` exit 0。
- [ ] `pytest tests/test_core/test_errors.py::test_llm_error_subclass_retry_rules` 通过且断言 timeout 不可重试。
- [ ] OpenAPI `EventDetailResponse` / `EventCloseResponse` 含 ISSUE-302 三计数字段。
- [ ] 不改变 CLOSED gate / writeback / force_close / LLM timeout 运行时语义。

### 测试与验证

```bash
cd backend
uv run --frozen python ../scripts/check_contract_drift.py
uv run --frozen mypy app
uv run --frozen ruff check app tests
uv run --frozen ruff format --check app tests
uv run --frozen pytest tests/test_core/test_errors.py::test_llm_error_subclass_retry_rules tests/test_contracts/test_drift.py -q
```

### 关联

- 来源：发布前审计 `审计报告.md` ID-BLK-001～004；复核附录 C 确认属实。
- 前置：ISSUE-302 / ISSUE-299 已合入。

### 禁止事项

- 禁止为过 mypy 删除 side-effect API 字段或改回零值假成功语义。
- 禁止把 `LLMTimeoutError` 改回 `default_retryable=True`。
- 禁止手改 contracts 而不走 export 脚本。
