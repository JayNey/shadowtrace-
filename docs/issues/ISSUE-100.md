### ISSUE-100：实体 Regex 兜底硬化与 LLM 输出校验（商用）

优先级：
P0

目标：
消除 Triage 实体 regex 兜底对自然语言短语的误匹配（如 `ransomware-like` → hostname），并对 LLM 结构化输出增加商用级校验与 reject 规则，避免脏实体进入 EvidenceAgent / RiskAgent。

背景（本地实测）：
- `entity_extraction_rules` 曾将标题中 `ransomware-like` 匹配为 hostname。
- Evidence 使用 `host_id=ransomware-like` 查询，HTTP success 但 `records=[]`，用户感知为「完全没证据」。
- LLM 返回空实体后 silent 触发 regex，无 quality gate。

前置依赖：
ISSUE-032、ISSUE-099（source enrichment 可减轻但不可替代 regex 硬化）

文件范围：
1. `backend/app/agents/rules/entity_extraction_rules.py`
2. `backend/app/agents/rules/entity_validation.py`（与 #602 共用 validator）
3. `backend/app/agents/triage_agent.py`（`_extract_entities`、LLM parsed 校验）
4. `backend/app/services/entity_validator.py`（re-export 兼容）
5. `backend/tests/test_agents/test_entity_extraction_rules.py`、`test_triage_agent.py`

统一命名：
1. 校验 API：`validate_host_entity()` / `validate_entity_set()`
2. 拒绝原因：`invalid_hostname_syntax`、`phrase_without_host_context`、`invalid_ip_literal` 等（通用，非 scenario blocklist）

实现步骤：
1. **收紧 hostname regex**：多模式抽取 + 语义校验；不以 Windows 前后缀为硬门槛。
2. **LLM 输出校验**：对 `TriageLLMResponse.entities` 跑 validator；全部无效才走 regex。
3. **Regex 结果二次校验**：`_regex_fallback` 与抽取层均过同一 validator。
4. **可观测性**：`TriageResult.entity_rejection_summary`（decision_trace 截断计数，无 raw payload）。
5. **负向测试集**：≥20 条 alert 标题/描述误报样例。

验收标准：
1. `"Malicious process spawned — ransomware-like behavior"` 不再产出任何 hostname 实体。
2. `"Host DEV-WKS-012 compromised"` / `"PC-FIN-023"` / `db01` / `ip-10-0-0-4` 仍正确抽取。
3. 误匹配率回归测试：负向样例 0 假阳。
4. EvidenceAgent：`query_edr_process` 在脏 hostname 被拒绝时 params 为 None。
5. 性能：4KB alert 线性扫描；CI 不使用脆弱固定毫秒门槛。

测试与验证：
`pytest backend/tests/test_agents/test_entity_extraction_rules.py backend/tests/test_agents/test_triage_agent.py`

降级策略：
校验失败 → 空实体 + degraded，**禁止**输出低置信度猜测实体。

---
