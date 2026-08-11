<!-- ShadowTrace pre-release audit ID-BYP-002/DEMO-001/002；main@738c478；CONFIRMED（故意设计，坏处>好处：阻全链路答辩效果） -->

### 类型

Bug 修复（官方全链路可跑路径 / Demo 假绿）

### 优先级

P1

### 当前事实

- 工程方案与 compose **故意**默认 `TASK_MODE=background`（本地无 worker 也能试）；生产 fail-closed 禁止 background。
- 文档「一键启动」写 `make up && make bootstrap`，该路径调查跑在进程内 BackgroundTasks，重启丢任务；三场景并行易卡住。
- `smoke_bootstrap.sh` 只断言 `event_count >= 3`，不验证终态（CLOSED / analysis_only_complete / 非 failed）。
- 默认 bootstrap `BOOTSTRAP_GENERATE_REPORT=false`、`BOOTSTRAP_INCLUDE_RESPONSE=false`，无法演示 required 写回→verify→CLOSED。
- 仓库已有正确路径：`make up-demo` / `bootstrap-demo` / `eval-full-loop` / `eval-full-loop-matrix`，但不是主文档入口。
- **坏处大于好处**：故意保留 background 默认可以，但把「一键启动」指向易失任务 + 冒烟假绿，导致修完功能也跑不出稳定全闭环效果。

### 目标

保证「官方推荐路径」在 Mock 栈上稳定跑出：seed → investigate →（审批脚本）→ writeback → verify → report → CLOSED（或明确的 analysis_only 终态），冒烟失败即失败。

### 推荐修复方案（工业级）

1. **不改生产状态机、不改 background 代码能力**；保留 `TASK_MODE=background` 作为显式开发开关。
2. 将 `docs/deployment.md` / README 快速开始的「一键」改为：
   - `make up-demo && make bootstrap-demo && make smoke-demo`；或
   - `make eval-full-loop` / `eval-full-loop-matrix --require-closed` 作为全闭环金路径。
3. 扩展 `smoke-demo` / `smoke_bootstrap`：
   - 每个场景事件在超时内达到约定终态（strict：CLOSED + report；compat：analysis_only_complete 或非 failed）；
   - 失败打印 event_id/status 轨迹。
4. 为全闭环演示提供 Makefile 目标或 env profile：`BOOTSTRAP_INCLUDE_RESPONSE=true` + `BOOTSTRAP_GENERATE_REPORT=true` + worker，并调用已有 `dynamic_eval_approve` / full_loop（禁止用 APPROVAL_TIMEOUT 空等）。
5. `make test` 文档注明仅 health；增加 `make test-ci-lite` 指向 contract+lint+关键单测（可选，勿把全 CI 塞进 make test）。

### 文件范围

- `docs/deployment.md`、`README.md`（快速开始）
- `scripts/smoke_bootstrap.sh` / `scripts/smoke_demo.sh`（或等价）
- `Makefile`（一键目标别名）
- `scripts/bootstrap.sh`（仅文档/默认 profile 注释，谨慎改默认以免破坏短路径分析演示）

### 验收标准

- [ ] 文档主路径明确要求 Celery worker（up-demo 或 WORKER=1）。
- [ ] smoke 在事件未达终态时 **非零退出**。
- [ ] 提供一条 Makefile/文档命令可在 Mock 下完成至少 1 个场景到 CLOSED（含脚本审批）。
- [ ] 不删除 `TASK_MODE=background` 能力；不把生产默认改成 background。
- [ ] 不引入「空等 APPROVAL_TIMEOUT」作为闭环手段。

### 测试与验证

```bash
make up-demo
make bootstrap-demo   # 或文档指定的 full-loop profile
make smoke-demo       # 必须因终态失败而红，或绿且终态正确
make eval-full-loop SCENARIO=insider_data_exfiltration
```

### 关联

- 审计：ID-BYP-002、ID-DEMO-001/002；复核 C.5 故意设计但坏处>好处。
- 依赖：ISSUE-301 matrix / gold path 已存在。

### 禁止事项

- 禁止把默认 `TASK_MODE` 强行改为 celery 而不更新生产 fail-closed 文档（可选改为 demo compose 默认 celery，但需讨论）。
- 禁止用真 XDR / 打开 ALLOW_LIVE_* 冒充闭环。
- 禁止 smoke 继续只数事件数量。
