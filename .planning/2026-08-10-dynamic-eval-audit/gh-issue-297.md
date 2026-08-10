<!-- ShadowTrace live-LLM audit ID-IMG-003；main@34947d1；CONFIRMED -->

### 类型

Bug 修复（Backend runtime image / Socket.IO schema packaging）

### 优先级

P1

### 当前事实

- Builder stage 执行 `COPY contracts /contracts`（`backend/Dockerfile:36`）。
- Runtime stage 只复制 `/app` 与 entrypoint（`:60-65`），**没有**复制 `/contracts`。
- `SocketIOManager` 在运行时固定读取 `/contracts/socketio/events.schema.json`（`socketio_manager.py:51-53,68`）。
- 最终容器内文件不存在；Redis 事件到达后 subscriber 连续 `FileNotFoundError`、重试并进入 recovery backoff。
- 现有 Docker 测试只验证 build context 未排除 contracts，不验证最终镜像文件。

### 目标

保证生产/Compose backend 最终镜像始终包含 Socket.IO schema，并在 CI 构建阶段发现 packaging 回归。

### 推荐修复方案（工业级）

1. 保持当前运行约定，在 runtime stage 增加：

```dockerfile
COPY --from=builder /contracts /contracts
```

2. 不复制第二份可变 schema；builder `/contracts` 仍由仓库根 canonical contracts 产生。
3. 增加 final-image smoke：
   - `test -r /contracts/socketio/events.schema.json`；
   - Python 加载 JSON；
   - 发布一个最小合法 envelope，确认 subscriber 不崩溃。
4. 若未来改用 `/app/app/contracts`，必须一次性修改 `_SCHEMA_PATH`、Docker 注释和测试，禁止两个路径长期并存。

### 文件范围

- `backend/Dockerfile`
- `backend/tests/test_infra/test_docker_build_context.py`
- 新增 final-image smoke（建议 `backend/tests/test_infra/` 或 CI script）

### 验收标准

- [ ] 最终 backend/worker 镜像中 schema 可读且 JSON 合法。
- [ ] Backend 非 root 用户可读取 schema。
- [ ] Socket.IO subscriber 收到消息时不触发 FileNotFoundError。
- [ ] CI 对 final image 做检查，不只检查 build context。
- [ ] 不扩大镜像到复制完整仓库或测试目录。

### 测试与验证

```bash
docker build -f backend/Dockerfile -t shadowtrace-backend-schema-smoke .
docker run --rm --entrypoint sh shadowtrace-backend-schema-smoke \
  -c 'test -r /contracts/socketio/events.schema.json'
```

### 依赖/关联

- 与 ISSUE-298（health 可观测性）正交：本 Issue 修根因，298 修长期检测能力。
- 与前端轮询 fallback 正交。

### 禁止事项

- 禁止把 schema 校验关闭或捕获后静默丢消息。
- 禁止复制整个仓库作为修复。
- 禁止只改本地开发路径、不验证 final image。
