<!-- ShadowTrace live-LLM audit ID-EVAL-007；main@34947d1；CONFIRMED -->

### 类型

Bug 修复（动态评测隔离 / 严格闭环门禁）

### 优先级

P1

### 当前事实

- `SUCCESSISH_EVENT_STATUSES` 接受 `reporting`、`contained`，适合作为兼容/进度剖面，但不能证明严格 CLOSED。
- Mock XDR 每次 `control/seed` 都会执行 `reset()`；前一场景尚未结束时再次 seed 会删除 source object、provider job 和 disposition 状态。
- 动态评测 batch 在单场景脚本失败后继续 seed，污染了 insider/manual-hold/writeback 证据。
- 固定 `COMPOSE_PROJECT_NAME` 会复用旧 volume；host port 手工探测存在 TOCTOU 竞态。
- 当前没有一个仓库内 runner 能保证：唯一 project、场景串行、异常清理、严格 CLOSED 断言。

### 目标

提供仓库官方、可重复、无跨场景污染的动态评测 matrix；兼容默认宽松剖面，同时增加严格全闭环验收。

### 推荐修复方案（工业级）

1. 新增 `scripts/dynamic_eval_matrix.py` 作为唯一 matrix orchestrator：
   - 每个场景生成唯一 `COMPOSE_PROJECT_NAME`；
   - 每场景创建 fresh volumes；
   - `try/finally` 执行 `docker compose down -v --remove-orphans`；
   - 任一场景失败即停止，不继续污染后续场景。
2. 避免 host port 探测竞态：
   - Compose eval override 使用随机发布端口（host port `0`），或完全不发布不需要的服务端口；
   - seed 与 harness 通过 `docker compose exec backend` 在 Compose network 内运行；
   - backend 内访问 `http://127.0.0.1:8000`，不依赖 host 端口。
3. seed 步骤返回明确 event IDs；matrix 将 IDs 显式传给 full-loop harness，禁止依赖共享 DB 中“最新事件”猜测。
4. 新增 strict profile：
   - 最终事件必须 CLOSED；
   - `GET /report` 必须成功；
   - 当前 revision 的 required/gate-applicable side effects 必须符合严格收敛断言；
   - 默认兼容 profile 继续允许 REPORTING/CONTAINED。
5. 每个场景输出独立 artifact 目录，记录 project、commit、event IDs、状态轨迹和脱敏 LLM 汇总。

### 文件范围

- 新增 `scripts/dynamic_eval_matrix.py`
- `scripts/dynamic_eval_full_loop.py`（strict profile 与显式 event IDs）
- 新增 `infra/docker-compose.eval.yml`（随机/无 host ports）
- `Makefile`（`eval-full-loop-matrix`）
- `backend/tests/test_infra/test_dynamic_eval_gold_path.py`
- `docs/deployment.md`

### 验收标准

- [ ] 三个场景使用三个不同 Compose project 与 fresh volumes。
- [ ] runner 不通过“先探测再释放”的方式分配 host ports。
- [ ] seed/event IDs 在场景间不串用。
- [ ] 任一失败或 SIGINT 后，对应 containers/network/volumes 均被清理。
- [ ] strict profile 不接受 reporting/contained/verifying。
- [ ] 默认 profile 行为保持兼容。
- [ ] 每场景 artifact 可独立审计且不含凭据。

### 测试与验证

```bash
(cd backend && uv run --frozen pytest tests/test_infra/test_dynamic_eval_gold_path.py -q)

python3 scripts/dynamic_eval_matrix.py \
  --scenarios insider_data_exfiltration,account_anomaly_fp,suspicious_domain_access \
  --fresh-volumes \
  --require-closed
```

### 关联

- 依赖 ISSUE-295 修复 detail response 解包。
- 不改变生产状态机；strict 是评测断言，不是 API 语义变更。

### 禁止事项

- 禁止在前一场景 in-flight 时覆盖同一 Mock XDR state。
- 禁止通过固定 project 名复用旧 volume。
- 禁止手工探测并释放 host port 后再启动 Compose。
- 禁止把默认兼容 profile 强制改为 strict。
- 禁止失败后继续运行下一场景。
