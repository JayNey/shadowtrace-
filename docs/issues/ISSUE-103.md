### ISSUE-103：Analysis-Only 状态可感知与启动前 Full-Loop 选择

> **权威规格以 GitHub #606 为准**；本地旧稿中 REPORTING 续跑 / CTA 描述已作废。

优先级：
P1

目标：
让用户在发起调查前明确选择「仅分析」或「分析并生成处置方案」，并在调查完成后清楚看到当前阶段、未执行原因和下一步提示（**不含** REPORTING 续跑）。

统一命名（#606）：
1. 复用 `analysis_only_complete` / `execution_substate`；派生 `response_phase_state`、`next_recommended_action`（`none` | `approve_actions` | `close`）
2. 禁止新增 `analysis_phase_complete` 等同义字段
3. `generate_report` UI 文案：「自动生成分析报告」；Actions 按 `action_category` 分组

不在范围：
- REPORTING→PLANNING_RESPONSE 续跑；禁止复用 `/investigate`

验收标准（#606）：
1. 默认调查仍为 analysis-only
2. NEW 状态选择 full-loop 走 `include_response_execution=true`
3. REPORTING + analysis-only 展示说明，**无失效 CTA**
4. `ORCHESTRATION_MODE=analysis_only` 拒绝/隐藏 full-loop
5. 契约与 frontend unit 覆盖两种启动方式

---
