### ISSUE-108：入库后自动研判策略（Auto-Investigate Policy）

优先级：
P1

目标：
当 ISSUE-107（或现有手工 ingest）产生 **`status=new`** 事件时，按可配置策略 **自动 enqueue 研判**，复用现有 `dispatch_investigation()` / SuperAgent 路径，实现「Mock XDR 告警 → 自动研判」；**不改变** HTTP `POST /investigate` 默认语义（ISSUE-077/566）。

背景：
- ingest 后事件停留 `new`，需人工或 bootstrap 调 investigate。
- Celery task `shadowtrace.run_investigation`（ISSUE-056）已存在。
- 用户期望商用链路：告警入库后无人值守开案。

前置依赖：
ISSUE-056、ISSUE-037（状态机）、ISSUE-107（推荐，非硬前置——手工 ingest 亦应可触发）

输入上下文：
- `EventService.ingest_source_object` / `SourceIngester` 成功创建或更新事件后的 hook 点
- `InvestigationInProgressError` 租约语义（并发去重）
- `InvestigateRequest.include_response_execution`（默认 false，本 Issue 默认亦 false）

文件范围：
1. `backend/app/services/auto_investigate_policy.py`（新建：规则评估）
2. `backend/app/services/event_service.py` 或 `source_ingester.py`（**最小** hook：仅调用 policy service）
3. `backend/app/core/config.py`（`AUTO_INVESTIGATE_ENABLED` 等，**默认 false**）
4. `backend/app/tasks/investigation_tasks.py`（复用 `dispatch_investigation`，不 fork）
5. `backend/tests/test_services/test_auto_investigate_policy.py`
6. `backend/tests/integration/test_auto_investigate_mock.py`

统一命名：
1. Service：`AutoInvestigatePolicyService`
2. Settings：
   - `AUTO_INVESTIGATE_ENABLED`（default `false`）
   - `AUTO_INVESTIGATE_MIN_SEVERITY`（default `medium`，可选 `high`）
   - `AUTO_INVESTIGATE_EVENT_TYPES`（optional allowlist CSV，空=全部）
   - `AUTO_INVESTIGATE_INCLUDE_RESPONSE`（default `false`，处置见 ISSUE-109）
3. Audit reason：`auto_investigate:policy_match`

实现步骤：
1. **Policy 规则（P1 最小集）**：
   - 事件 `status == NEW`
   - `severity >= AUTO_INVESTIGATE_MIN_SEVERITY`
   - 可选 event_type allowlist
   - 排除 `disposition_only_intent` 已设、已在 investiging 中、租约占用
2. **触发点**：在 ingest **事务提交成功后**异步 dispatch（Celery 或 BackgroundTasks，与现有 `task_mode` 一致）；**禁止**在 ingest 事务内同步跑 SuperAgent。
3. **幂等**：同一 `event_id` 仅 dispatch 一次 auto-investigate（Redis SETNX 或 DB 标记 `auto_investigate_enqueued_at`）；`InvestigationInProgressError` 视为 skip。
4. **与手工 investigate 共存**：手工 POST 仍可用；auto 仅补「未触发」的 new 事件。
5. **可观测**：decision_trace / audit_log 记录 `triggered_by=auto_investigate_policy`；health 暴露 `auto_investigate_enabled`。
6. **Mock 验收**：ingest `malicious_process` → 无需 curl → 事件进入 `triaging`/`reporting`（取决于 pipeline）。

验收标准：
1. `AUTO_INVESTIGATE_ENABLED=false`（默认）时零行为变化。
2. 开启后 Mock ingest 新 high 事件 ≤30s 内自动进入研判（Celery worker 运行）。
3. 低危 `account_anomaly_fp` 可被 min_severity=high 排除（可配置）。
4. 重复 ingest duplicate 不重复 dispatch investigate。
5. 不修改 `InvestigateRequest` 默认值；HTTP API 契约测试不回归。

测试与验证：
`pytest backend/tests/test_services/test_auto_investigate_policy.py backend/tests/integration/test_auto_investigate_mock.py -v`

降级策略：
Celery 不可用时记录 degraded flag，**不得**阻塞 ingest；可选 fallback BackgroundTasks（与现有 investigate 一致）。

约束（防冲突）：
- **禁止**替换或绕过 `SuperAgent.investigate()` / workflow graph。
- **禁止**默认 `include_response_execution=true`（ISSUE-109 管辖）。
- **禁止**对 live XDR 做特殊硬编码；policy 只读 Event 字段。
- hook 注入点须最小 diff，不改变 ISSUE-016 ingest 摘要结构。

---
