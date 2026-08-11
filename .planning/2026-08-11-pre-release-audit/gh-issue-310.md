<!-- ShadowTrace pre-release audit ID-SEC-002；main@738c478；需讨论 -->

### 类型

Bug 修复（OTEL httpx span 可能导出 Authorization）

### 优先级

P1·需讨论

### 当前事实

- 日志有 `RedactingFormatter`；`HTTPXClientInstrumentor().instrument()` 未见等价请求头脱敏。
- Disposition HTTP adapter 使用 Authorization bearer/basic。
- `OTEL_ENABLED=true` 时凭据可能进入 OTLP。
- 本阶段默认 OTEL 常关，但是 demo-observability / up-demo 可能打开。

### 目标

开启 OTEL 时出站凭据不得进入 span/export；与日志红acted 策略对齐。

### 推荐修复方案（工业级）

1. 为 httpx instrumentation 增加 request/response hook：删除或哈希 `Authorization`、`Cookie`、`X-Api-Key` 等。
2. 单测/单元：构造带 Authorization 的 request 属性，断言导出前已脱敏。
3. 文档：未完成脱敏前，生产禁止 `OTEL_ENABLED=true` 对接不可信 collector。
4. 不改变 DispositionAdapter 真实发往对端的头（只影响 telemetry 导出）。

### 文件范围

- `backend/app/core/telemetry.py`
- 相关测试
- `docs/deployment.md`（可选警告）

### 验收标准

- [ ] OTEL 导出属性不含明文 Authorization。
- [ ] Adapter 实际 HTTP 调用仍带合法认证头。
- [ ] 默认 OTEL=false 行为不变。

### 测试与验证

```bash
cd backend && uv run --frozen pytest -k telemetry -q
```

### 关联

- 审计 ID-SEC-002。

### 禁止事项

- 禁止在 span 中写入 token/password/raw_payload。
- 禁止为脱敏而禁用全部 httpx 追踪导致无法排障（可保留 URL/status）。
