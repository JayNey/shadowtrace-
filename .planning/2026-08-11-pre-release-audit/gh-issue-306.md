<!-- ShadowTrace pre-release audit ID-CTR-005；main@738c478；CONFIRMED -->

### 类型

Bug 修复（前后端 investigate 契约漂移）

### 优先级

P1

### 当前事实

- 后端 `InvestigateResponse` 含必需 `task_id`、可选 `intent_id`（`schemas.py`）。
- 前端 `frontend/src/services/eventApi.ts` 类型省略上述字段，无 `GET /api/v1/tasks/{task_id}` 轮询客户端。
- `TASK_MODE=celery` 时 UI 无法展示/跟踪 durable task，全链路答辩时「点了调查却不知进度」。

### 目标

前端与 OpenAPI 对齐，在 celery 模式下可观察 task/intent 状态。

### 推荐修复方案（工业级）

1. 从 OpenAPI / `InvestigateResponse` 更新 TS 类型（优先 codegen 或手写对齐字段，禁止猜字段）。
2. investigate 成功后保存 `task_id`/`intent_id`；celery 模式提供最小轮询（现有 tasks API）。
3. background 模式可仅展示 accepted，不强制轮询。
4. 不改后端状态机。

### 文件范围

- `frontend/src/services/eventApi.ts`
- 相关 hooks/页面（investigate 入口）
- 如有：`frontend` 契约生成脚本

### 验收标准

- [ ] TS 类型含 `task_id`、`intent_id`。
- [ ] celery 模式下 UI 或 devtools 可关联 task。
- [ ] 不破坏现有 Vitest / 类型检查。

### 测试与验证

```bash
cd frontend && pnpm typecheck && pnpm test
```

### 关联

- 审计 ID-CTR-005；配合 ISSUE-304 全链路路径。

### 禁止事项

- 禁止前端伪造 task 成功状态。
- 禁止为对齐类型删除后端字段。
