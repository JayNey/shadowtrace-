### ISSUE-103：研判 analysis-only 默认可感知与处置阶段引导（商用）

优先级：
P1

目标：
解决 HTTP `POST /investigate` 默认 `include_response_execution=false` 导致用户只看到 `generate_report`、无隔离/封禁等处置 Action 的困惑；商用产品必须在 UI/API 明确「分析完成 vs 处置待启动」状态，并提供一键进入 Response/Approval 路径。

背景（本地实测）：
- 用户研判 `malicious_process` 后仅见 1 条 `generate_report`（system/L0），误以为系统未生成处置建议。
- Workflow：`defer_response_execution=true` → 跳过 ResponseAgent → `disposition_policy=required` → halt 在 `reporting`。
- 前端轮询 `waiting_approval` actions 为空，无引导文案。

前置依赖：
ISSUE-077（前端集成）、ISSUE-566/077（investigate 语义）、ISSUE-057（ResponseAgent）

文件范围：
1. `backend/app/api/v1/events.py`（investigate 响应扩展）
2. `backend/app/agents/super_agent.py`、`backend/app/orchestration/workflow_graph.py`
3. `backend/app/models/`（InvestigateResponse / Event 投影字段）
4. `frontend/src/` 事件详情：状态条、CTA 按钮
5. `contracts/schemas/` 相关响应
6. `backend/tests/test_api/test_contracts.py`

统一命名：
1. 字段：`analysis_phase_complete: bool`、`response_execution_deferred: bool`、`next_recommended_action`（enum: `start_response_execution` | `approve_actions` | `close` | `none`）
2. 系统 Action `generate_report` UI 文案固定为「自动生成分析报告」，与安全 response Action 分组展示

实现步骤：
1. **Investigate API 响应** 返回当前 defer 状态与推荐下一步（基于 event.status + disposition_policy）。
2. **Event GET 投影** 增加 `execution_substate` / `analysis_complete` / `pending_response_plan` 可读摘要。
3. **新增或文档化端点**：`POST /events/{id}/investigate` body `include_response_execution=true` 的前端封装按钮「生成处置方案并提交审批」。
4. **前端状态机**：
   - `reporting` + deferred → 展示 amber 提示条 + CTA。
   - Actions 分 Tab：`系统动作` vs `安全处置`。
5. **Decision trace** 记录 `workflow_path=analysis_only|full_loop`。
6. **文档**：README/部署文档说明默认 analyze-only 与商用 full-loop 切换。

验收标准：
1. 默认 investigate 后，前端明确提示「分析已完成，处置方案未生成」及操作入口。
2. 点击 CTA（或 API `include_response_execution=true`）可进入 ResponseAgent，产生 ≥1 条 security action（malicious_process 场景）。
3. `generate_report` 不再与安全处置混排为唯一动作。
4. 契约测试覆盖 investigate 响应新字段。
5. 不影响 ISSUE-064 E2E full-loop 路径。

测试与验证：
API 契约测试 + frontend e2e（可选 ISSUE-077 范围）。

降级策略：
ResponseAgent 不可用时 CTA 禁用并展示 degraded 原因。

---
