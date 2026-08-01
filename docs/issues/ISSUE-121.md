### ISSUE-121：Detection-as-Code 最小 Runtime（执行与治理生命周期分离）

优先级：
P0（最小 runtime）

GitHub 权威：
#626

## 目标

建立可版本化、确定性、tenant/scope-safe 的最小规则 runtime；不拥有 governance approval、production promotion 或 Event writeback。

## Runtime 生命周期（本 Issue）

`draft → validated → shadow_active → disabled`。这是可执行包状态，不代表治理批准（#630）或生产晋升（#629）。

## Governance 边界

1. #630 产生 immutable `DetectionGovernanceDecision(candidate_version → approved/rejected)`。
2. #629 消费 approved decision 执行 production promotion。
3. 禁止本 Issue 用 `enabled=true` 代替批准或晋升；`CandidateDetection.shadow_only` 必须为 `true`。

## Phase A operators

`event_match`、`event_count`、`value_count`；每条规则声明 rule_id/version、feature contract、detection_scope selector、event-time window、group key、threshold、severity mapping、required fields、missing-data policy。

## 文件范围

1. `backend/app/models/detection_rule.py`
2. `backend/app/detection/operators/`（base、registry、event_match、event_count、value_count）
3. `backend/app/services/detection_rule_resolver.py`
4. `backend/app/services/detection_rule_service.py`
5. `backend/app/services/detection_rule_runtime.py`
6. `backend/app/db/models.py` + `backend/migrations/versions/0016_detection_rule_runtime.py`
7. `contracts/schemas/DetectionRule*.json`、`CandidateDetection*.json`
8. `backend/tests/test_services/test_detection_rule_resolver.py`
9. `backend/tests/test_services/test_detection_rule_service.py`
10. `backend/tests/test_services/test_detection_rule_runtime.py`

## 统一命名

1. `DetectionRuleRuntimeState`: `draft` | `validated` | `shadow_active` | `disabled`
2. `RuleOperatorKind`: `event_match` | `event_count` | `value_count`
3. `MissingDataPolicy`: `skip` | `fail` | `treat_as_zero`
4. `package_id` (`drpkg-*`) / `candidate_detection_id` (`dcand-*`) / `error_id` (`drerr-*`)
5. `DetectionRulePackage` / `CandidateDetection` / `DetectionRuleRuntimeError`

## 实现步骤

1. Pydantic 契约 + JSON schema export（`MODEL_REGISTRY`）。
2. Operator registry（fail-closed unknown operator）+ Phase A 三算子。
3. Resolver：compile/validate、确定性 package/candidate hash、lifecycle transition guard。
4. Service：package 持久化、idempotency、lifecycle 转换（draft→validated→shadow_active→disabled）。
5. Runtime：仅 `shadow_active` 包执行，输出 `CandidateDetection`，typed runtime error，bounded scan。
6. Postgres 持久化 + 单测/集成测。

## 验收标准

1. operator golden tests、乱序/late/cold-start/missing field/tenant isolation/cost limit 通过。
2. package provenance/hash/author/review/test artifact 可追溯；同内容重注册 idempotent（`compiled_at` 不参与 content hash）。
3. runtime error 产生 typed error，不静默当 benign。
4. governance/promotion 在 schema 中不能被 runtime flag 绕过（无 `enabled` 生产路径，`shadow_only=true` 强制）。
5. 同 cutoff + rule version 输出稳定 candidate identity；evidence（provenance / matched_value）更新时 identity 不变，content_hash 可变化并通过 persist recompute 写回。

## Candidate identity 语义

1. `candidate_detection_id` / `idempotency_key` 由 `(tenant, scope, package, rule, cutoff, group_key, rule_version)` 决定，不含 provenance。
2. `content_hash` 含完整 evidence body；迟到数据重跑时同 idempotency_key 下更新 matched_value / provenance（in-place recompute）。
3. 同 tenant 允许多个 `shadow_active` package 并存；`execute_shadow` 无 `package_id` 时全部执行（Phase A 行为，#629 前不做互斥）。
4. `validate_package` 校验每条规则的 `detection_scope_id` 在该 tenant 下为 ACTIVE scope。
5. observation 算子（event_match/event_count）禁止 `missing_data_policy=treat_as_zero` 及 `required_fields` 含 `observation_count`。

## 测试与验证

```bash
cd backend
DATABASE_URL="postgresql+asyncpg://shadowtrace:shadowtrace@127.0.0.1:5432/shadowtrace" \
  .venv/bin/pytest tests/test_services/test_detection_rule_resolver.py -q
DATABASE_URL="postgresql+asyncpg://shadowtrace:shadowtrace@127.0.0.1:5432/shadowtrace" \
  .venv/bin/pytest tests/test_services/test_detection_rule_service.py -q   # 需 Postgres
DATABASE_URL="postgresql+asyncpg://shadowtrace:shadowtrace@127.0.0.1:5432/shadowtrace" \
  .venv/bin/pytest tests/test_services/test_detection_rule_runtime.py -q     # 需 Postgres
.venv/bin/pytest tests/test_models/test_schema_export.py -q
python ../scripts/export_schemas.py
```

## 依赖

#625（FeatureSnapshot / BehaviorObservation / DetectionScope）。

## 未做 / 降级

1. Governance approval（#630）与 production promotion（#629）不在本 Issue 范围。
2. 不创建 Event / SourceAlert；shadow output 仅供 #631 评估消费。
3. Phase B 扩展算子、API 路由、metrics 导出留后续 Issue。
