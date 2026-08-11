<!-- ShadowTrace pre-release audit ID-BYP-006；main@738c478；需讨论 -->

### 类型

Bug 修复（质量评估失败 fail-open → 质量门空转）

### 优先级

P1·需讨论

### 当前事实

- `OutputQualityEvaluator.evaluate_all` 在单 agent 评估异常时写入 `score=0.75`、`verdict=PASS`（代码注释：不阻断主链路）。
- 这是**故意 fail-safe**，避免评估器拖死 P0。
- **坏处**：评估器坏掉时 UI/审计仍显示 PASS，全链路「质量门」失去信号；与 fail-closed 立场在质量面上冲突。

### 目标

主链路仍不被评估器拖死，但失败不得伪装为 PASS；必须可观测且可配置是否阻断（默认不阻断 P0）。

### 推荐修复方案（工业级）

1. 异常时 verdict 改为 `FAIL` 或新增 `DEGRADED`/`ERROR`，score 不宣称达标；`reasons` 含 `eval_error_defaulted`。
2. 写 sticky `degraded_flags`（如 `output_quality_evaluator_unavailable`）。
3. 配置项（默认 false）：`OUTPUT_QUALITY_BLOCKING=true` 时才阻断后续节点；默认保持 P0 不因质量器失败而停。
4. 单测覆盖异常 → 非 PASS + degraded flag。

### 文件范围

- `backend/app/services/output_quality_evaluator.py`
- `backend/app/core/config.py`（若加开关）
- 相关测试

### 验收标准

- [ ] 评估异常不再产生 PASS/0.75 伪装成功。
- [ ] 默认不阻断 investigate 主链路。
- [ ] degraded 可从事件/健康或 flag 观察到。

### 测试与验证

```bash
cd backend && uv run --frozen pytest -k output_quality -q
```

### 关联

- 审计 ID-BYP-006；复核故意设计但坏处>好处（可观测性）。

### 禁止事项

- 禁止默认打开 blocking 导致 Mock 全链路大面积红。
- 禁止吞掉异常且不记 flag。
