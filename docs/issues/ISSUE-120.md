### ISSUE-120：Canonical Detection Scope + FeatureSnapshot/Baseline（分阶段）

优先级：
P0

GitHub 权威：
#625

## Phase 0（本 Issue 当前交付范围）

目标：
定义 server-owned、versioned 的 canonical Detection Scope contract，供 #624/#626–#631 消费；不依赖 #624 observations，不与 Phase A 形成循环依赖。

核心约定：
1. `detection_scope_id` = `source_tenant_id` + `integration_instance_id` + `connector_set_version` + 可选 `environment`/`region`（确定性 hash，`dscope-{digest}`）。
2. upstream connector set 只含原始/upstream source connectors；#629 derived detection connector 被排除，仅引用已建立 scope。
3. scope revision 为 append-only；activation/retirement 由 server 驱动，rule/model/agent 不得自行拼 scope。
4. 同一 integration instance 同时最多一个 ACTIVE scope revision（connector set 升级时激活新版并退役旧版）。
5. `identity_hash` 仅 hash integration identity；与含 `connector_set_version` 的 `detection_scope_id` 语义分离。
6. **Operational contract**：同一 `(integration instance, connector_set_version)` 的 upstream 成员集合不可变；成员变更必须 bump `connector_set_version`，否则 `register_revision` 拒绝。

文件范围（Phase 0）：
1. `backend/app/models/detection_scope.py`
2. `backend/app/services/detection_scope_resolver.py`
3. `backend/app/services/detection_scope_service.py`
4. `backend/app/db/models.py` + `backend/migrations/versions/0013_detection_scope.py`
5. `contracts/schemas/DetectionScope*.json`
6. `backend/tests/test_services/test_detection_scope_resolver.py`
7. `backend/tests/test_services/test_detection_scope_service.py`

统一命名：
1. `detection_scope_id` — versioned scope 标识
2. `identity_hash` — upstream integration boundary hash（不含 connector set version）
3. `scope_revision_id` — 不可变 revision 主键
4. `ConnectorScopeRole`: `upstream_source` | `derived_detection`
5. `DetectionScopeLifecycleState`: `draft` | `active` | `retired`

实现步骤（Phase 0）：
1. Pydantic 契约 + JSON schema export。
2. Resolver：确定性 id/hash、upstream set 规范化、derived 排除断言。
3. Service：register（仅 DRAFT）、activate（按 integration instance 退役 predecessor）、retire、query、get_active。
4. Postgres 持久化 + 部分唯一索引（每 scope id 至多一个 ACTIVE）。
5. 单测 + 集成测（tenant 隔离、supersession、分页 latest）。

验收标准（Phase 0）：
1. 同输入重算 `detection_scope_id` / `content_hash` 一致。
2. 跨 tenant/integration instance 无污染。
3. derived connector 不改变 scope identity。
4. connector set version 升级激活后，旧 scope revision 被退役。
5. `register_revision` 不可直写 ACTIVE；`supersedes_scope_revision_id` 校验同 tenant/instance。
6. `query_revisions(latest_revision_only=True)` 分页 total 正确。

## Phase A（不在本分支范围）

依赖 Phase 0 + #624 observations。FeatureSnapshot/Baseline、event-time window、watermark/cutoff、cold-start — 见 #625 Phase A 段落。

## 测试与验证

```bash
cd backend
.venv/bin/pytest tests/test_services/test_detection_scope_resolver.py -q
.venv/bin/pytest tests/test_services/test_detection_scope_service.py -q   # 需 Postgres
.venv/bin/pytest tests/test_models/test_schema_export.py -q
```

## 依赖

Phase 0：#602/#603 connector identity contract（字段命名对齐，Phase 0 不做 FK 校验）。
Phase A：Phase 0 + #624。
