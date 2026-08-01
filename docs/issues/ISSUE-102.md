### ISSUE-102：风险评分证据缺失语义分离与 Severity Floor（商用）

优先级：
P1

目标：
RiskAgent 必须区分「威胁信号强但证据不足」与「威胁信号弱」，避免高严重度告警在 pipeline 故障（实体/证据为空）时被静默压至 medium/low；商用场景需保留 alert/source 严重度底线并显式输出「证据不足降信」而非「低风险」。

背景（本地实测）：
- 源 normalized `risk_score=76`、severity=high。
- 零证据后 RiskAgent 输出 `risk_score=45`、severity=medium、confidence=0.21、verdict=none。
- 用户误判为「标准太松/太严」——实为 scoring 未表达 epistemic uncertainty。

前置依赖：
ISSUE-035（RiskAgent）、ISSUE-101（证据质量）、ISSUE-099

文件范围：
1. `backend/app/agents/risk_agent.py`
2. `backend/app/agents/risk_scoring_engine.py`
3. `backend/app/agents/prompts/risk_prompt.py`
4. `backend/app/models/agent_io.py`（`RiskAssessment` 扩展字段）
5. `contracts/schemas/RiskAssessment.json`（若对外暴露）
6. `backend/tests/test_agents/test_risk_agent.py`

统一命名：
1. 新字段（建议）：`evidence_limited: bool`、`severity_floor_applied: bool`、`source_risk_baseline: int | null`
2. Scoring mode 保持 `ScoringMode` 枚举，可增 `EVIDENCE_LIMITED` 或在 factors 中标记

实现步骤：
1. **引入 source baseline**：从 `EventContext.source_snapshot.normalized.risk_score` / incident level 读取 baseline，缺省 null。
2. **Severity floor 规则**：
   - 当 `collection_status in {FAILED, DEGRADED}` 且 source severity ≥ HIGH 时，输出 severity 不得低于 source severity 一档（HIGH 最低保持 HIGH 或 MEDIUM+flag，产品可配置）。
   - `risk_score` 可取 `max(rule_score, min(source_baseline, source_baseline * 0.85))` 等可测公式（实现时写死并单测）。
3. **LLM prompt 约束**：明确「无证据 ≠ 无威胁」；要求输出 `evidence_limited` 与 factor 解释。
4. **Confidence 校准**：证据为空时 confidence 上限 cap（如 0.35），与 severity floor 并存。
5. **Decision trace / 报告**：risk_factors 必含 `evidence_confidence` 与 `source_baseline` 说明。
6. **Verdict**：evidence_limited 时不应轻易 `false_positive`；维持 `none` 或 `suspicious` 策略写死。

验收标准：
1. `malicious_process` 零证据路径（模拟）severity 不低于 HIGH 或带 `evidence_limited=true` 且 UI 可感知。
2. 完整证据路径分数可高于 floor，不被 floor 错误抬高。
3. FP 场景（account_anomaly_fp）不被 floor 误伤。
4. LLM 失败时 rule-only 仍遵守 floor/cap。
5. OpenAPI/契约测试通过。

测试与验证：
`pytest backend/tests/test_agents/test_risk_agent.py`；regression baseline 更新需评审。

降级策略：
无 LLM 时 rule-only + floor；禁止因证据空而输出 LOW/FP 默认。

---
