### ISSUE-110：Mock 自主运营闭环集成验收（Ingest → Auto-Investigate → Optional Response）

优先级：
P1

目标：
为 ISSUE-107/108/109 提供 **端到端集成测试与 Makefile 入口**，在纯 Mock 环境证明「XDR 告警 → 自动研判 → 可选自动处置」可重复验收；作为商用自主运营链的 CI 门禁，**不依赖真实 XDR、不修改 Agent 业务逻辑**。

前置依赖：
ISSUE-107、ISSUE-108；ISSUE-109（optional response 用例子集）

文件范围：
1. `backend/tests/integration/test_autonomous_mock_pipeline.py`
2. `scripts/run_autonomous_mock_demo.sh`
3. `Makefile` target：`autonomous-mock-demo`
4. `docs/deployment.md`（自主运营 Mock 演示章节）

统一命名：
1. pytest marker：`@pytest.mark.autonomous_mock_pipeline`
2. Make target：`make autonomous-mock-demo`

实现步骤：
1. **场景 A（ingest only + auto investigate）**：
   - 启 scheduler + auto-investigate + worker
   - seed mock-xdr 新 scenario
   - 断言 ≤120s 内 event 离开 `new`，decision_trace 含 triage_agent
2. **场景 B（+ auto response）**：
   - 额外开启 AUTO_RESPONSE
   - malicious_process → actions 含 security response + generate_report 分组
3. **场景 C（回归：全关）**：
   - 所有 AUTO_* false → 与现 bootstrap 行为一致
4. CLI 脚本输出逐步状态（ingest summary / investigate dispatch / action counts）。
5. CI：mock 路径必跑；不引入 external LLM 硬依赖（LLM_MODE=mock）。

验收标准：
1. `make autonomous-mock-demo` 本地可一键跑通场景 A。
2. 场景 B 在 ISSUE-109 完成后纳入同一 target。
3. 故意关闭 scheduler 时场景 A 失败（证明测到真实链路）。
4. 不破坏现有 `make bootstrap` / `make integration-test`。
5. 文档说明所需 env（全 Mock，无 live）。

测试与验证：
`make autonomous-mock-demo`  
`pytest -m autonomous_mock_pipeline -v`

降级策略：
外部 LLM 不参与本门禁；研判可走 mock LLM / rule fallback。

约束（防冲突）：
- 测试只驱动 **公开 API + env**，不 import 私有 hack。
- 不与 ISSUE-105 commercial regression 重复断言实体质量细节——本 Issue 只验 **链路连通**；质量见 #608/#602。

---
