### ISSUE-099：Triage 实体抽取 Source 感知增强（商用）

优先级：
P0

目标：
将 TriageAgent 的实体抽取从「仅读告警标题/描述纯文本」升级为「Source 结构化字段 + 告警文本 + 关联对象」的多源融合，确保 Mock/真实 XDR 场景在 ingest 后能稳定产出可用于证据查询的主机、账号、进程、IP 等实体，避免因文本缺失导致整条研判链空转。

背景（本地实测，2026-07-30）：
- 事件 `evt-20240615-ab480f7a`（`malicious_process`）源数据含 `hostname=DEV-WKS-012`、`account=dev-user-012`、`process=ransomware_stage.exe`，但 incident title/description 未携带这些字段。
- Triage LLM 返回空实体 → regex 兜底误将 `ransomware-like` 识别为 hostname → Evidence 查空 → Risk 从源 76 降至 45。
- 根因是 **ingest 富数据未注入 triage 输入**，而非 LLM 本身「放水」。

前置依赖：
ISSUE-032（TriageAgent）、ISSUE-013（SourceIngester / EventService）、ISSUE-096（证据投影隔离）

输入上下文：
- `EventContext.source_snapshot` / `source_reference_snapshots`
- `SourceRecord.normalized`（event_type、risk_score、description）
- Mock 场景 `_system_scenario_pack.py` 中 asset/alert/log 的 structured 字段
- `TriageAgentInput` / `TriageResult.entities` / `FIELD_OWNERSHIP.triage_result`

文件范围：
1. `backend/app/agents/triage_agent.py`
2. `backend/app/ingestion/`（alert/incident builder 若需 normalized entity 投影）
3. `backend/app/services/event_service.py` 或 ingest 路径（source → event 实体种子）
4. `backend/app/models/agent_io.py`（若扩展 triage 输入上下文）
5. `backend/tests/test_agents/test_triage_agent.py`、场景回归测试

统一命名：
1. 新增内部函数/模块名建议：`enrich_entities_from_source()` / `SourceEntityEnricher`（实现时二选一，Issue 内保持一致）
2. 产出仍写入 `TriageResult.entities`（`EntitySet`），owner 仍为 TriageAgent
3. 降级标记继续使用 `TriageResult.degraded` + `degraded_flags`，新增原因码 `source_enrichment_partial` / `text_extraction_empty`

实现步骤：
1. **定义 enrichment 优先级**：`source_snapshot.normalized` > impacted asset refs > related alert/log raw_payload > LLM/regex 文本抽取；后者不得覆盖前者已确认字段。
2. **在 Triage `_run` 入口** 读取 EventContext（working_memory 或 event_service），合并 source 已知 hostname/account/process/ip 到候选实体集。
3. **文本抽取为空时** 若 source enrichment 成功，不得标记 `degraded=True`（或仅标记 `text_extraction_empty` 子原因，overall 仍可 `completed`）。
4. **Mock 场景对齐**：`_system_scenario_pack` 的 incident/alert normalized 可选增加 `primary_hostname` / `primary_account`（或复用 asset ref），但场景包外代码禁止硬编码演示实体名。
5. **Decision trace** 记录 enrichment 来源摘要（不含敏感 payload）。

验收标准：
1. `malicious_process` 场景 ingest + investigate 后，`TriageResult.entities.hosts` 含 `DEV-WKS-012`（或 seed 对应 hostname），非空。
2. 告警 title 不含 hostname 时，仍能从 source  enrichment 得到实体；EvidenceAgent 对 `query_edr_process` 使用正确 `host_id`。
3. source 与文本冲突时，source 结构化字段优先，conflict 写入 reasoning/decision_trace。
4. 无 source 字段时行为与现网一致（LLM → regex），不回归 FP 场景。
5. 参数化测试覆盖 ≥3 个 system scenario pack 场景。

测试与验证：
`pytest backend/tests/test_agents/test_triage_agent.py`；新增 ingest→triage 集成测试；可选 `malicious_process` regression snapshot 更新。

降级策略：
source enrichment 失败时回退现有 LLM+regex 路径；不得 fail-open 写入捏造实体。

---
