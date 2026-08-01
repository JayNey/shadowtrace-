### ISSUE-119：BehaviorObservation 稳定语义投影

优先级：
P0（Detection 基础）

GitHub 权威：
#624

## 目标

将 SourceIngester / EvidenceProjection 已持久化的 source objects 规范化为 durable、tenant-scoped、可重放的 `BehaviorObservation`；不复制 ingest/checkpoint/raw payload，不创建 Event/Detection/Alert，不写 Disposition。

## Identity 与 scope

Observation identity 至少包含：
- `source_tenant_id`
- source object type/id + `source_revision`（`current_state_version`）
- `projection_schema_version`
- `detection_scope_id`（消费 #625 Phase 0 contract，禁止仅靠全局 `connector_id`）

### Scope 绑定状态机（Phase 0）

1. **Tenant 级零 ACTIVE scope**：对该 connector 的 `integration_instance_id` 走 metadata fallback（`connector_metadata.integration_instance_id` + `connector_set_version` → 确定性 `detection_scope_id`）。
2. **该 instance 尚无 ACTIVE scope，但同 tenant 其他 instance 已有 ACTIVE scope**：仍对该 instance 走 metadata fallback（不因其他 instance 已注册而 fail-closed）。
3. **该 instance 已有 ACTIVE scope 且 connector 在 upstream set 中**：绑定 registered `detection_scope_id`。
4. **该 instance 已有 ACTIVE scope 但 connector 不在 upstream set 中**：fail-closed（`ValidationError`），写入 projection failure + DQE，ingest 本身不回滚；poll/push summary 标记 `degraded=true`。

部署 ISSUE-120 后，应逐步为每个 integration instance 注册并激活 scope；在过渡期内，未注册 instance 仍可通过 fallback 产生 observation。

## 字段

`observation_id`、`source_tenant_id`、`detection_scope_id`、`source_ref`、`observed_at`、`ingested_at`、`entity_refs`、`action`/`category`、`normalized_attributes`、`detection_score`（非 `risk_score`）、`schema_version`、`provenance`/`content_hash`。

敏感 raw payload 只通过 `provenance.source_record_id` / `raw_payload_hash` 引用既有 source store，不复制。

## 写入合同

- 唯一 writer：`SourceIngester` post-persistence semantic projection hook（push/poll/fixture 同路径）。
- 重放/upsert 幂等；`source_revision` 改变产生可追踪新 revision（`supersedes_observation_id`）。
- projection failure **不回滚**已持久化 source object；写入 `behavior_observation_projection_failure` + `data_quality_error`，支持 retry/dead-letter。
- 不创建 Event/Detection/Alert，不写 Disposition。
- **Phase 0 投影范围**：log/asset 及 incident/alert 等已持久化 source object 均可产生 observation（仅语义规范化，不写回事件链）；connector kind 明确排除。

## 文件范围

1. `backend/app/models/behavior_observation.py`
2. `backend/app/services/behavior_observation_resolver.py`
3. `backend/app/services/behavior_observation_service.py`
4. `backend/app/services/behavior_observation_projection.py`
5. `backend/app/ingestion/source_ingester.py`（hook 接线）
6. `backend/app/services/evidence_projection.py`（`on_persisted` 回调）
7. `backend/app/db/models.py` + `backend/migrations/versions/0014_behavior_observation.py`
8. `contracts/schemas/BehaviorObservation*.json`
9. `backend/tests/test_services/test_behavior_observation_resolver.py`
10. `backend/tests/test_services/test_behavior_observation_service.py`
11. `backend/tests/test_ingestion/test_behavior_observation_hook.py`

## 验收标准

1. 同 tenant/source revision 重放无重复；跨 tenant 相同 source_object_id 不冲突。
2. observation 可从 source refs 重建；时间/版本/provenance 完整。
3. projector failure/retry 有测试；不丢 raw evidence、不篡改 SourceLog/SourceAsset。
4. #625 Phase A / #626 只读取该表/contract。

## 测试与验证

```bash
cd backend
.venv/bin/pytest tests/test_services/test_behavior_observation_resolver.py -q
.venv/bin/pytest tests/test_services/test_behavior_observation_service.py -q   # 需 Postgres
.venv/bin/pytest tests/test_ingestion/test_behavior_observation_hook.py -q   # 需 Postgres
.venv/bin/pytest tests/test_models/test_schema_export.py -q
```

## 依赖

- #602 / #603 connector identity contract（五元组 identity）
- #625 Phase 0 Detection Scope contract（`detection_scope_id` 绑定）

## 未做 / 降级

- 无 HTTP API（Phase 0 内部 service + hook 供 #626/#625A 读取）
- 无独立 Celery worker；`retry_pending()` 供后续 task 接入
- 未对 incident/alert 做 detection 特征 enrich（仅 source object 语义投影）
