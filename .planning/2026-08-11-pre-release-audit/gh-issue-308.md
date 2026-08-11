<!-- ShadowTrace pre-release audit ID-SEC-004/BLK-005；main@738c478；需讨论但建议实施 -->

### 类型

Bug 修复（force_close 逃生舱保留，服务层 RBAC/审计加固）

### 优先级

P1·需讨论

### 当前事实

- 方案 ISSUE-037：**唯一** admin 强制本地关闭入口是 `StateMachineService.force_close`，应绕过写回门禁并写 `external_unsynced=true`——**故意设计，必须保留**。
- API `force_local_close` 有 `ROLE_ADMIN` 校验；`force_close(principal=...)` **服务层不校验角色**。
- compose `DEV_AUTH_TOKENS` 的 `bootstrap-token` 含 admin，非 production 即可 force-close 跳过 side-effect/writeback gate。
- **坏处大于「仅 API 校验」的好处**：Celery/脚本/未来路由直调服务可绕过角色；答辩环境令牌过宽易假闭环。

### 目标

保留 force_close 语义与 external_unsynced；补齐服务层角色校验与更明显审计；收紧 demo 令牌角色文档（不必删逃生舱）。

### 推荐修复方案（工业级）

1. 在 `force_close` 内校验 principal 具备 admin（与 API 一致）；缺角色 → `AuthorizationError` / 明确错误码。
2. 审计 reason 固定包含 `force_close` + subject；可选 metrics 计数。
3. 文档：demo 使用非 admin 日常 token；bootstrap-token 仅 bootstrap；生产必须 `APP_ENV=production` 禁用 DEV_AUTH。
4. 测试：非 admin 调服务层 force_close 失败；admin 成功且 `external_unsynced=true`。
5. **不**把 side-effect/writeback gate 加回 force_close。

### 文件范围

- `backend/app/services/state_machine_service.py`
- `backend/tests/test_services/test_state_machine_service.py`
- `docs/deployment.md`（令牌角色说明）
- （可选）`infra/docker-compose.yml` 注释，避免静默拆掉 e2e admin 能力

### 验收标准

- [ ] 服务层无 admin → force_close 失败。
- [ ] admin force_close 仍绕过 writeback/side-effect gate 并标记 external_unsynced。
- [ ] 普通 CLOSED 路径行为不变。

### 测试与验证

```bash
cd backend && uv run --frozen pytest \
  tests/test_services/test_state_machine_service.py -k force_close -q
```

### 关联

- 审计 ID-BLK-005、ID-SEC-001/002/004；复核：逃生舱保留，加固 RBAC。

### 禁止事项

- 禁止删除 force_close。
- 禁止让普通 transition 接受 force 标志。
- 禁止 REQUIRED 事件经非 force 路径跳过 CONFIRMED 写回。
