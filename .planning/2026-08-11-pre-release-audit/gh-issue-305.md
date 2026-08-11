<!-- ShadowTrace pre-release audit ID-BYP-001；main@738c478；CONFIRMED（收窄） -->

### 类型

Bug 修复（Planner 派发未接线 Agent → 静默 no-op）

### 优先级

P1

### 当前事实

- `MemoryAgent` **有意**不作为 LangGraph P0 节点；ISSUE-080 规定结案后置 hook（`_schedule_memory_after_close`）。这不是漏接。
- `AGENT_INPUT_MODELS` / Planner `_VALID_AGENT_NAMES` 仍包含 `memory_agent`、`tool_agent`。
- `SuperAgent._execute_single_step` 对未知/未接线 `assigned_agent` 仅 warning（`case _`），计划步骤被吞。
- Tool 能力本应由 Evidence/Response 经 ToolExecutor 调用，而非独立 graph agent 节点。
- **坏处**：LLM/disposition-only 计划一旦写出这些名字，全链路「看起来跑完」但步骤空转，难排查。

### 目标

Planner / 执行层对「当前拓扑不可执行的 agent」fail-closed 或自动改写到合法 agent，禁止静默成功。

### 推荐修复方案（工业级）

1. 定义 `GRAPH_EXECUTABLE_AGENTS`（或从 `workflow_graph` / deps 注入集合），与 P0 实际节点一致。
2. Planner 校验：`assigned_agent` ∉ 可执行集合 → 校验失败并降级到规则计划 / 合法 agent（与现有 Planner 降级路径一致）。
3. SuperAgent 执行：未知 agent 在 production/graph 模式记 `degraded_flags` 且该 step 计为失败（或跳过并 fail 计划），禁止仅 warning。
4. 保留 Memory 后置 hook；**不要**为修本 Issue 强行把 Memory 塞进 P0 graph。
5. 单测：计划含 `memory_agent`/`tool_agent` → 被拒绝或改写；hook 路径仍可触发 Memory。

### 文件范围

- `backend/app/agents/planner_agent.py`
- `backend/app/agents/super_agent.py`
- `backend/app/models/agent_io.py`（若需导出可执行集合文档）
- `backend/tests/test_agents/test_planner_agent.py`、`test_super_agent.py`

### 验收标准

- [ ] Planner 不再把不可执行 agent 当合法输出（或输出后执行层硬失败）。
- [ ] Memory 后置 hook 行为不变。
- [ ] 无新的「缺节点所以加空 node」的假实现。

### 测试与验证

```bash
cd backend && uv run --frozen pytest \
  tests/test_agents/test_planner_agent.py \
  tests/test_agents/test_super_agent.py -q --tb=short
```

### 关联

- 审计 ID-BYP-001（复核收窄）；ISSUE-080 Memory 后置设计保留。

### 禁止事项

- 禁止为消告警把 Memory/Tool 伪节点加入 graph。
- 禁止影响 REQUIRED 写回 / CLOSED gate。
