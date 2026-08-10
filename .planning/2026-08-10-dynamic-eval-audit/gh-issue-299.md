<!-- ShadowTrace live-LLM audit ID-LLM-005；main@34947d1；CONFIRMED -->

### 类型

Bug 修复（ReportAgent timeout / LLM 调用审计完整性）

### 优先级

P1

### 当前事实

- ReportAgent 使用独立 30 秒 timeout 并在失败时生成 `degraded_template`；该 SLA 与 fallback 是合理设计。
- ReportAgent 通过外层 `asyncio.wait_for()` 取消 `llm_client.chat()`（`report_agent.py:418-431`）。
- 运行日志记录 `report_generate` 的 `llm_timeout`，但 `llm_call_log` 中 `prompt_key=report_generate` 为 0 行。
- BaseLLMClient 已有 timeout 分类与审计能力；外层 cancellation 在 `_record_audit()` 前终止了该路径。
- 直接把报告 timeout 提高到全局 120 秒会增加墙钟并可能放大 Celery soft-timeout，不是推荐修法。

### 目标

保留 ReportAgent 30 秒 SLA 与模板 fallback，同时保证每次 provider 调用都产生完整、脱敏、可关联的 timeout 审计记录。

### 推荐修复方案（工业级）

1. 移除 ReportAgent 外层 `asyncio.wait_for()`。
2. 调用 `llm_client.chat(..., timeout=self.llm_timeout_seconds)`，让 BaseLLMClient 的统一 timeout/audit 边界负责：
   - provider timeout；
   - `status=llm_timeout`；
   - `error_class=timeout`；
   - fallback model 语义。
3. 保留 ReportAgent catch 与 `degraded_template` 生成逻辑。
4. 若 coroutine cancellation 仍可能来自 Celery/task shutdown，在 BaseLLMClient 增加 cancellation-safe 最小审计，但必须防止与正常 timeout 行重复。
5. 审计不得保存 prompt、completion 原文或凭据。

### 文件范围

- `backend/app/agents/report_agent.py`
- `backend/app/core/llm/base.py`（仅在需要 cancellation-safe 兜底时）
- `backend/tests/test_agents/test_report_agent.py`
- `backend/tests/test_core/test_llm_client.py`

### 验收标准

- [ ] ReportAgent 30 秒超时后仍生成 `degraded_template`。
- [ ] `llm_call_log` 恰好存在一条 `report_generate / llm_timeout / timeout` 行。
- [ ] 不重复记录 timeout。
- [ ] 不把 timeout 提高为 120 秒，不增加额外盲重试。
- [ ] 报告 warning/error_detail 保持脱敏。

### 测试与验证

```bash
cd backend
uv run --frozen pytest \
  tests/test_agents/test_report_agent.py \
  tests/test_core/test_llm_client.py -q
```

另需真实 OpenAI-compatible provider smoke，确认 DB 中出现 `report_generate` timeout audit。

### 依赖/关联

- 与报告预览/导出 UI（#293）不重复；本 Issue 只修 LLM timeout 与后端 ledger。
- 与 prompt invalid-rate 回归正交。

### 禁止事项

- 禁止删除模板 fallback。
- 禁止单纯增加 timeout 或 retry。
- 禁止在 ReportAgent 手写第二套与 BaseLLMClient 不一致的审计协议。
- 禁止写入 prompt/completion 原文。
