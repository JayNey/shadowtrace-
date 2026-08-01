### ISSUE-104：ReportAgent 可靠性与空证据报告增强（商用）

优先级：
P1

目标：
ReportAgent LLM 路径失败时必须可观测（错误分类、重试、metrics），模板降级报告需包含证据缺口、实体抽取降级、risk evidence_limited 等结构化章节，避免商用场景输出「空报告」。

背景（本地实测）：
- 日志：`ReportAgent LLM path failed; using Jinja2 template event=evt-20240615-ab480f7a err=`（错误为空）。
- 用户感知：研判完成后报告区几乎无内容，与 medium 风险不匹配。
- 多次事件（e154404b、ab480f7a）均触发 template fallback。

前置依赖：
ISSUE-048/049（ReportAgent）、ISSUE-101/102（证据与风险语义）

文件范围：
1. `backend/app/agents/report_agent.py`
2. `backend/app/agents/report_section_builder.py`
3. `backend/app/agents/templates/report_template.md.j2`
4. `backend/app/core/llm/`（错误传播）
5. `backend/tests/test_agents/test_report_agent.py`

统一命名：
1. `generated_by`: `llm` | `template` | `template_enriched`（可选）
2. 报告 section id：`evidence_gaps`、`entity_extraction_summary`、`investigation_limitations`

实现步骤：
1. **LLM 失败可观测**：catch 时记录 `error_code`、`http_status`、truncated message 到 log + decision_trace；禁止空 err。
2. **有限重试**：对 transient LLMError 重试 1 次（可配置），仍失败再 template。
3. **Template 增强**：
   - 自动渲染 evidence gaps 列表（source/tool/reason）。
   - 渲染 triage degraded / entity count。
   - 渲染 risk factors 摘要与 evidence_limited 标记（ISSUE-102 字段）。
4. **空内容 guard**：若 sections 全空，至少输出「调查限制说明」+ 源告警摘要（来自 source_snapshot，非 LLM 编造）。
5. **report GET API**：确保 `GET /events/{id}/report` 返回完整 sections；前端渲染 markdown/structured sections。
6. **测试**：mock LLM 失败、空 evidence、degraded triage 三种 template 路径 snapshot。

验收标准：
1. LLM 失败日志含非空 error_code；decision_trace 可见 fallback 原因。
2. 零证据事件报告含「证据缺口」章节，列出 ≥1 条 gap。
3. template 报告 word count / section count 低于阈值时 CI 失败（防回归空报告）。
4. LLM 成功路径不回归。
5. `generated_by` 字段准确。

测试与验证：
`pytest backend/tests/test_agents/test_report_agent.py`

降级策略：
LLM 不可用 → template_enriched；禁止返回空 report 对象。

---
