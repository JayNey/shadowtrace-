### ISSUE-106：本地 LLM 集成配置与可观测性（商用部署）

优先级：
P1

目标：
商用部署 OpenAI-compatible LLM（如火山 Ark）时，提供可验证的配置契约、启动自检、调用可观测性与失败诊断，避免「研判秒出但全走规则降级」或 silent LLM failure。

背景（本地实测）：
- 错误 base URL（`/api/coding` vs `/api/coding/v3`）导致全部 `llm_provider_error`，用户误判未走 LLM。
- 修正后 LLM success，但 ReportAgent 仍 silent fallback。
- `.env` 需被 compose `env_file` 注入 backend/worker（已本地修复，需产品化文档与校验）。

前置依赖：
ISSUE-027（LLMProvider）、ISSUE-097（Compose/CI）、ISSUE-104

文件范围：
1. `backend/app/core/llm/`、`backend/app/core/config.py`
2. `infra/docker-compose.yml`、`docs/deployment.md`
3. `backend/app/api/v1/health.py` 或 `connectors` 诊断端点
4. `scripts/llm_smoke_test.py`（新增）
5. `backend/tests/test_core/test_llm_config.py`

统一命名：
1. Health 子项：`llm: { mode, base_url_redacted, primary_model, last_probe_status }`
2. 环境变量：`LLM_MODE`、`LLM_API_BASE_URL`、`LLM_PRIMARY_MODEL`、`LLM_API_KEY`

实现步骤：
1. **启动自检（可选 fail）**：`LLM_MODE=openai_compatible` 时 startup probe `GET/POST .../models` 或 minimal chat；失败 log WARNING，生产可配置为 FATAL。
2. **Compose 契约**：document + test that backend/worker load root `.env` via `env_file`；禁止 compose environment 硬编码覆盖 `LLM_MODE=mock`。
3. **`make llm-smoke`**：脚本验证 chat/completions，输出 latency/status，不打印完整 API key。
4. **llm_call_log 仪表盘字段**：prometheus/otel 或 health 聚合 success rate（若 ISSUE-092 未覆盖）。
5. **部署文档**：火山 Ark / DeepSeek 示例配置表；常见 404/401 排查。
6. **Investigate 诊断**：decision_trace 中 LLM 失败展示 provider error class。

验收标准：
1. 错误 base URL 时 health/startup 报告 llm degraded。
2. 正确配置下 smoke test success，llm_call_log status=success。
3. compose 配置测试防止 LLM env 回归覆盖。
4. 文档含最小可复现步骤（不含真实 secret）。
5. API key 不出现在日志/health 明文。

测试与验证：
单元测试 + 可选 integration（mock httpx）；manual smoke 文档化。

降级策略：
probe 失败不阻断启动（dev），production 可配置 fail-closed。

---
