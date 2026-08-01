### ISSUE-105：Mock 场景商用 E2E 回归门禁（实体→证据→风险→处置）

优先级：
P1

目标：
为 8 个 system scenario pack 建立商用级端到端回归门禁：ingest → investigate（analysis + optional full response）→ 断言实体非空、证据≥阈值、风险区间、预期 verdict/severity、处置 Action 集合；防止 Triage/Evidence/Risk 链静默退化。

背景（本地实测）：
- `malicious_process` 期望 `expected_severity=HIGH`、`risk_min=70`，实测 45 / medium / 无证据。
- 现有 regression baseline 未覆盖「HTTP investigate + 真实 LLM 可选」路径。
- 问题多次重复出现，缺 CI 红灯。

前置依赖：
ISSUE-099–104（修复项）、ISSUE-010（Mock 场景）、ISSUE-064（response loop）、ISSUE-089（演示脚本，可选）

文件范围：
1. `backend/tests/regression/`（扩展）
2. `backend/app/data_generators/scenarios/_system_scenario_pack.py`（expected_* 字段对齐）
3. `scripts/` 或 `Makefile` 目标 `make regression-commercial`
4. `.github/workflows/ci.yml`（可选 nightly job）
5. `data/scenarios/*/expected_outcomes.json`（可选）

统一命名：
1. 测试模块：`test_commercial_regression.py`
2. Marker：`@pytest.mark.commercial_regression`
3. 环境变量：`REGRESSION_LLM_MODE=mock|openai_compatible|skip`

实现步骤：
1. **定义每场景期望矩阵**（沿用 spec 中 `expected_severity`、`risk_min/max`、`allowed_actions`、`expected_verdict`）。
2. **Analysis-only 路径断言**：
   - entities.hosts 或 accounts 非空（ISSUE-099 后）。
   - evidence_list length ≥ 1 或 gaps 全明确（ISSUE-101 后）。
   - risk_score 在 [risk_min, risk_max] 或 evidence_limited 标记存在（ISSUE-102 后）。
3. **Full-loop 路径断言**（`include_response_execution=true`）：
   - response actions ∩ allowed_actions ≠ ∅。
   - required policy 事件到达 waiting_approval 或 executing（非仅 reporting）。
4. **LLM 模式**：
   - CI 默认 `LLM_MODE=mock` 或 rule-only 可 deterministic 通过。
   - 可选 manual workflow `openai_compatible` 不阻断 PR。
5. **基线更新流程**：`--update-baseline` 需 CODEOWNERS 评审。
6. **文档**：README 增加「商用回归」章节。

验收标准：
1. 8 场景 analysis-only 回归本地可跑通（LLM mock 下）。
2. `malicious_process` 修复后 baseline 反映 HIGH/证据/实体。
3. CI 新增 job 或并入 integration-test，默认 PR 必跑 mock 版。
4. 故意注入 regression（如空实体）时测试失败。
5. 运行文档与 Makefile 目标齐全。

测试与验证：
`make regression-commercial` 或 `pytest -m commercial_regression`

降级策略：
外部 LLM 不可用时跳过 optional job，mock 路径不得跳过。

---
