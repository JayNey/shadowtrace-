<!-- ShadowTrace live-LLM audit ID-HEALTH-004；main@34947d1；CONFIRMED -->

### 类型

Bug 修复（运行健康检查 / Socket.IO subscriber 可观测性）

### 优先级

P1

### 当前事实

- Socket.IO subscriber 因 schema 缺失进入 CRITICAL recovery backoff 时，`GET /api/v1/health` 仍返回 HTTP 200、`status=ok`（`health.py:119-286` 无 socketio component）。
- health payload 不包含 `socketio`/event-subscriber component。
- 保持 HTTP 200 对软依赖是合理设计；完全不暴露实时通道故障会让部署、监控与 smoke 误判健康。
- 即使修复 ISSUE-297 schema packaging，未来 Redis subscribe、schema validation 或 background task 崩溃仍会落入同一盲区。

### 目标

把 Socket.IO background subscriber 纳入脱敏健康状态，使软依赖故障可见但不错误升级为核心 HTTP 不可用。

### 推荐修复方案（工业级）

1. `SocketIOManager` 维护进程内只读 health snapshot：
   - `status`：ok / degraded / stopped；
   - `listener_running`；
   - `consecutive_failures`；
   - `last_success_at`；
   - `last_error_class`（禁止完整异常正文）。
2. 在 listener 成功消费与异常 backoff 边界原子更新 snapshot。
3. `/health` 增加 `socketio` component。
4. socket degraded 时 overall 改为 `degraded`；HTTP 仍返回 200。
5. 增加 monotonic counter/metric，避免只依赖日志。

### 文件范围

- `backend/app/core/socketio_manager.py`
- `backend/app/api/v1/health.py`
- `backend/tests/test_api/test_socketio.py`
- health API tests

### 验收标准

- [ ] subscriber 正常时 `socketio.status=ok`。
- [ ] 连续失败进入 backoff 时 `socketio.status=degraded`，overall degraded、HTTP 200。
- [ ] 恢复成功后状态自动回到 ok。
- [ ] health 中无 payload、token、频道内容或异常敏感正文。
- [ ] 核心 PostgreSQL/Redis HTTP 503 语义不变。

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/test_api/test_socketio.py tests/test_api/test_health.py -q
```

### 依赖/关联

- 建议与 ISSUE-297 分开发布。
- 采用与 state-projection health 相同的非 sticky 进程级指标模式（ISSUE-285）。

### 禁止事项

- 禁止把 Socket.IO 软依赖直接变为无条件 HTTP 503。
- 禁止在 health 返回完整异常、事件 ID 列表或消息正文。
- 禁止用单次历史失败永久 sticky-degrade。
