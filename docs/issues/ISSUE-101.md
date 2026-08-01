### ISSUE-101：证据采集无效实体 fail-closed 与降级可观测（商用）

优先级：
P0

目标：
当 Triage 实体缺失、降级或校验失败时，EvidenceAgent 不得使用低质量实体发起查询；前端/API 必须清晰暴露「证据缺口」与 collection_status，避免 tool HTTP success 但 evidence_list 为空的 silent failure。

背景（本地实测）：
- `query_edr_process` / `query_asset_info` status=success，但 `records=[]`，parser 产出 0 条 Evidence。
- `collection_status=failed`，`overall_confidence=0`，UI 仍显示「无证据」且无解释。
- `success_sources` 计数逻辑与「可展示证据」脱节。

前置依赖：
ISSUE-033/034（EvidenceAgent）、ISSUE-099/100（实体质量）、ISSUE-096（投影）

文件范围：
1. `backend/app/agents/evidence_agent.py`
2. `backend/app/agents/evidence_parser.py`
3. `backend/app/models/agent_io.py`（`EvidenceGap` / `EvidenceOutput` 若需扩展）
4. `backend/app/api/v1/events.py`（证据列表端点，若缺失则新增 `GET /events/{id}/evidence`）
5. `frontend/src/` 事件详情证据区（最小展示 gaps）
6. `backend/tests/test_agents/test_evidence_agent.py`

统一命名：
1. Gap reason 扩展：`invalid_entity`、`source_skipped`、`no_records`（已有）、`triage_degraded`
2. API 响应：`EvidenceGapResponse` 对齐 `EvidenceGap` 模型

实现步骤：
1. **Triage 质量门控**：`triage_result.degraded=True` 且无 source-enriched 实体时，7 路 query 统一 skipped，gap reason=`triage_degraded`。
2. **实体前置校验**：`_build_params` 前调用 ISSUE-100 validator；无效 hostname/account 不发起 tool call。
3. **空 records 语义**：HTTP success + empty records → gap `no_records`，**不计入** `success_sources`（修复 silent success）。
4. **collection_status 规则调整**：区分 `FAILED`（0 有效源）、`DEGRADED`（1-2）、`PARTIAL_DONE`（3-4）、`COMPLETED`（≥5）；文档化阈值。
5. **API/前端**：事件详情可查看 `evidence_list` + `gaps` + 每路 tool 摘要；空态文案说明原因（非仅「暂无数据」）。
6. **Decision trace**：tool_call 条目增加 `records_count` / `gap_reason`。

验收标准：
1. 脏 hostname 场景不再产生 tool call，或 call 后 gaps 明确为 `invalid_entity`/`no_records`。
2. `malicious_process` 在 ISSUE-099 修复后，evidence_list ≥ 1，collection_status ≥ DEGRADED。
3. 前端/API 空证据时展示 gap 原因链（至少 triage → evidence 两级）。
4. 现有 concurrent/sequential 模式测试不回归。
5. `success_sources` 仅统计 parser 产出 ≥1 条 evidence 的源。

测试与验证：
`pytest backend/tests/test_agents/test_evidence_agent.py`；API 契约测试；可选 frontend 单测。

降级策略：
全局 evidence timeout 仍适用；不得伪造 evidence 填充 UI。

---
