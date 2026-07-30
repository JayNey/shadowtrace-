### ISSUE-100：实体 Regex 兜底硬化与 LLM 输出校验（商用）

优先级：
P0

目标：
消除 Triage 实体 regex 兜底对自然语言短语的误匹配（如 `ransomware-like` → hostname），并对 LLM 结构化输出增加商用级校验与 reject 规则，避免脏实体进入 EvidenceAgent / RiskAgent。

背景（本地实测）：
- `entity_extraction_rules._HOSTNAME_PATTERN` 将标题中 `ransomware-like` 匹配为 hostname。
- Evidence 使用 `host_id=ransomware-like` 查询，HTTP success 但 `records=[]`，用户感知为「完全没证据」。
- LLM 返回空实体后 silent 触发 regex，无 quality gate。

前置依赖：
ISSUE-032、ISSUE-099（source enrichment 可减轻但不可替代 regex 硬化）

文件范围：
1. `backend/app/agents/rules/entity_extraction_rules.py`
2. `backend/app/agents/triage_agent.py`（`_extract_entities`、LLM parsed 校验）
3. 新增 `backend/app/agents/rules/entity_validation.py`（可选）
4. `backend/tests/test_agents/test_triage_agent.py`、新建 `test_entity_extraction_rules.py`

统一命名：
1. 校验 API：`validate_host_entity()` / `validate_entity_set()` 
2. 拒绝原因枚举或常量：`invalid_hostname_shape`、`english_phrase_false_positive`、`private_ip_format_invalid`

实现步骤：
1. **收紧 hostname regex**：
   - 排除纯英文形容词短语（含 `-like`、`-based` 等后缀）。
   - 要求匹配 Windows 主机命名特征（如含数字、已知 role 后缀 DEV/SRV/PC/WKS 等）或显式 IP/域名关联。
   - 维护 `HOSTNAME_BLOCKLIST`（动态短语，如 `ransomware-like`、`persistent-beacon`）。
2. **LLM 输出校验**：对 `TriageLLMResponse.entities` 每项跑 validator；无效项丢弃并计数，全部无效则才走 regex。
3. **Regex 结果二次校验**：`_regex_fallback` 输出必须过同一 validator，不通过则留空而非污染。
4. **可观测性**：triage reasoning 追加 `rejected_entities: [{value, reason}]`（decision_trace 摘要级）。
5. **负向测试集**：至少 20 条 alert 标题/描述误报样例（含实测 `ransomware-like`、`lateral movement`、`persistent beacon` 等）。

验收标准：
1. `"Malicious process spawned — ransomware-like behavior"` 不再产出任何 hostname 实体。
2. `"Host DEV-WKS-012 compromised"` / `"PC-FIN-023"` 仍正确抽取。
3. 误匹配率回归测试：负向样例 0 假阳。
4. EvidenceAgent 集成测试：脏 hostname 不会触发 `query_edr_process`（params None → skipped_missing_entity）。
5. 性能：validator 对 4KB alert 文本 < 5ms（单测粗测）。

测试与验证：
`pytest backend/tests/test_agents/test_entity_extraction_rules.py backend/tests/test_agents/test_triage_agent.py`

降级策略：
校验失败 → 空实体 + degraded，**禁止**输出低置信度猜测实体。

---
