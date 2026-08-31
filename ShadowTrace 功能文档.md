# ShadowTrace 功能文档

> 按当前仓库代码写「现在能做什么」。架构与 ISSUE 完成度见 [ShadowTrace 项目总览.md](ShadowTrace 项目总览.md)。  
> 成熟度只用三档：**Mock 可演示**（默认金路径能跑）/ **可选或 feature-flag** / **未接线或未真机**。

默认演示栈：浏览器 `http://localhost:3000`，API `/api/v1`（`:8000`），Mock XDR `:8100`。

---

## 1. 产品一句话与边界

ShadowTrace 是独立部署的多 Agent 安全运营系统：把告警收成事件，自动分诊、取证、评分、出处置计划，经审批后执行并写回，再验证、出报告、关单。

**可演示闭环** = Mock XDR + Mock 工具 +（可选）真 LLM。分析正文、报告、Prompt、decision_trace **永不写回** XDR；只有获批的处置动作与最小结果摘要经 DispositionAdapter 写回。

可替换边界（LLM 另有 `LLMProvider` 统一模型调用，见 §8，合称四个）：

| 边界 | 职责 | 默认实现 | 不得越权 |
|------|------|----------|----------|
| SourceAdapter | 只读接入 Incident / Alert / 资产 / 日志 | `MockXDRSourceAdapter`、`FileSourceAdapter` | 不写回、不执行动作 |
| ToolProvider | 查询与 DIRECT_TOOL 实体处置 | `MockToolProvider` | 不得静默回退 Mock 后返回成功 |
| DispositionAdapter | 事件处置与最小结果同步 | `MockXDRDispositionAdapter` | 分析正文永不写回 |

每个 Action 只能选一个执行策略：`XDR_MANAGED` 或 `DIRECT_TOOL`，禁止双下发。

---

## 2. 给谁用

角色在 `backend/app/core/auth.py`。演示用 `DEV_AUTH_TOKENS`（如 `bootstrap-token`），不是完整 IdP / SSO。

| 角色 | 典型能力 |
|------|----------|
| `analyst` | 看事件、发起调查、改分类、看报告 |
| `approver` | 批准/驳回 L2+ 动作；晋升/驳回知识候选 |
| `disposition_operator` | 选处置来源、重检写回就绪、重试写回 |
| `admin` | 上述均可；强制关单、resolve 写回 |

租户字段只做隔离/追踪，没有完整多租户 IAM 控制台。

---

## 3. 分析员界面

导航：事件看板 · 审批中心 · 工具审计 · 知识审核 · SOC 大屏；顶栏全局搜索。实时进度走 Socket.IO（`/events`，Redis Pub/Sub）。

| 功能 | 做什么 | 入口 | 成熟度 |
|------|--------|------|--------|
| 事件看板 | 列表/筛选；发起调查（仅分析或含处置） | `/`、`/events` · `GET /events` · `POST /events/{id}/investigate` | Mock 可演示 |
| 事件详情 | 概述、待办、风险、实体、Agent 状态 | `/events/:eventId` | Mock 可演示 |
| 来源对象 | 只读来源快照与候选处置引用 | `#source` | Mock 可演示 |
| 攻击故事线 | 攻击时间线 | `#timeline` · `GET /events/{id}/timeline` | Mock 可演示 |
| 攻击图谱 | 实体关系图（Postgres 主路径） | `#graph` · `GET /events/{id}/graph` | Mock 可演示 |
| 证据 | 查询结果、冲突、缺口 | `#evidence` · `GET /events/{id}/evidence` | Mock 可演示 |
| 处置动作 | 计划步骤；L2+ 可在页内批准/驳回 | `#actions` · `GET /events/{id}/actions` | Mock 可演示 |
| 外部写回 | 写回义务/状态；Mock 带 `simulated=true` | `#writeback` | Mock 可演示 |
| 审计 | 工具调用与决策轨迹 | `#audit` · `GET …/tool-calls` · `GET …/decision-trace` | Mock 可演示 |
| 事件问答 | 基于事件上下文提问 | `#chat` · `POST /events/{id}/chat` | 可选：`EVENT_CHAT_ENABLED` / `VITE_EVENT_CHAT_ENABLED` |
| 报告 | 15 章报告预览与再生成 | `#report` · `GET/POST /events/{id}/report` | Mock 可演示 |
| 改分类 | 覆盖 `event_type`，可选再调查 | `PATCH /events/{id}/classification` | Mock 可演示 |
| 关单 | 正常关闭；`force_local_close` 可能外部未同步 | `POST /events/{id}/close` | Mock 可演示（force 是运维逃生舱） |
| 审批中心 | 待批 L2+ 队列 | `/approvals` · `POST /actions/{id}/approve\|reject` | Mock 可演示 |
| 工具审计 | 跨事件工具调用表 | `/tools-audit` · `GET /tool-calls` | Mock 可演示 |
| 知识审核 | 人工晋升/驳回记忆候选（不自动入库） | `/knowledge/reviews` · `POST /knowledge/reviews/{id}/promote\|reject` | Mock 可演示；需调查 CLOSED 后才有候选 |
| SOC 大屏 | 统计、严重度、趋势、高风险条 | `/dashboard` · `GET /stats` | 可选（P2 页面，失败不拖垮其它路由） |
| 全局搜索 | 搜事件/工具；无 OpenSearch 则 SQL ILIKE | 顶栏 · `GET /search` | 可选：OpenSearch 未起时降级 |

调查闭环要稳，请用 `make up-demo`（`TASK_MODE=celery`）。`make up` 默认进程内任务，重启会丢。RAG / 剧本命中依赖已 `make load-kb`。

---

## 4. 调查闭环

```mermaid
flowchart LR
  ingest[接入] --> triage[分诊]
  triage --> evidence[证据]
  evidence --> fp[FP裁决]
  fp --> rag[RAG]
  fp --> graph[图谱]
  rag --> risk[风险]
  graph --> risk
  risk --> response[处置计划]
  response --> approval[审批]
  approval --> execute[执行]
  execute --> verify[验证]
  verify --> report[报告]
  report --> closed[CLOSED]
  closed --> memory[记忆候选]
```

编排：`SuperAgent` + LangGraph。生产调查走 Celery worker。RAG 与图谱只依赖证据、互不依赖，同一 superstep 并行后汇入风险。

| 环节 | 做什么 | 成熟度 |
|------|--------|--------|
| 分诊 Triage | 抽实体、定 `event_type` / 严重度；误报只给建议 | Mock 可演示 |
| 证据 Evidence | 并发/串行 `query_*`；冲突检测 | Mock 可演示 |
| FP 裁决 | 证据后的误报关单路径 | Mock 可演示 |
| RAG | 五库检索 → `RAGOutput`（ATT&CK / 误报 / 历史 / 剧本 / 组织上下文） | Mock 可演示（须 load-kb） |
| 图谱 Graph | 实体关系；Neo4j 为可选镜像 | Mock 可演示；Neo4j 可选 |
| 风险 Risk | 六维评分 + `VerdictResolver` → `FinalVerdict`（与事件状态正交） | Mock 可演示 |
| 处置 Response | 按能力与剧本生成 L0–L5 计划；终态写回动作为 deferred | Mock 可演示 |
| 审批 | 硬门禁后 L0/L1 自动；L2+ 人工；L4/L5 永不自动 | Mock 可演示 |
| 执行 | 只执行 IMMEDIATE；Outbox 写回；幂等 | Mock 可演示 |
| 验证 Verify | 核效果；再激活 deferred 写回并确认 | Mock 可演示 |
| 重规划 | 验证失败最多 3 次 | Mock 可演示 |
| 写回恢复 | UNKNOWN/失败禁止盲重试 | Mock 可演示 |
| 报告 | 15 章结构化报告 | Mock 可演示；LLM 不可用可降级模板 |
| 记忆 Memory | CLOSED 后入审核队列，**不自动晋升** | Mock 可演示 |
| 只读 ReAct 补证 | 缺口时再查，不创建处置 | 可选：`REACT_ENABLED` 默认 false |

**判定** `FinalVerdict`（`none` / `possible_false_positive` / `false_positive` / `confirmed_threat`）不是事件状态。高置信误报仍走合法路径到 `CLOSED`。

---

## 5. 工具、剧本、写回

规范名走 `ToolRegistry` / `GET /tools`。Demo 设备后端是 `MockToolProvider`（`TOOL_MODE=mock`），不是另一套假工具。

| 类 | 规范名 | 成熟度 |
|----|--------|--------|
| 查询 | `query_account_login`、`query_edr_process`、`query_file_access`、`query_network_flow`、`query_dns`、`query_asset_info`、`query_vuln_info`、`query_threat_intel`、`query_history_cases` | Mock 可演示 |
| 处置 | `block_ip`、`block_domain`、`isolate_host`、`quarantine_file`、`block_process`、`scan_host_for_virus`、`disable_account`、`force_logout`、`reset_password`、`revoke_token`、`create_ticket`、`notify_security_team`；deferred `update_source_event_disposition` | Mock 可演示 |
| 核验 | `check_ip_block_status`、`check_domain_block_status`、`check_host_isolation_status`、`check_file_quarantine_status`、`check_process_block_status`、`check_virus_scan_status`、`check_account_status`、`check_new_alerts`、`check_traffic_drop` | Mock 可演示 |
| 回滚目录 | `unblock_ip` / `unblock_domain`、`cancel_host_isolation`、`restore_file`、`restore_account`、`close_false_positive_ticket` | 目录在；Saga **未接线**（见 §10） |

**剧本：** compose 可种 playbook release（`SEED_PLAYBOOK_RELEASE`）；`make load-kb` 含 `load_playbook_release`。Response 绑定检索到的 `playbook_refs[0]`。`PLAYBOOK_REQUIRED` 时未就绪会让 `/health` 503。

**写回：** 业务义务 `writeback_required` 与能否提交 `writeback_readiness` 正交。`disposition_policy=required` 时，闭环周期须有一条终态 `EVENT_STATUS_UPDATE` 为 CONFIRMED 才算写回完成。UNKNOWN 禁止盲重试；`POST /writebacks/{id}/retry`（处置员）、`/resolve`（admin）。

---

## 6. 知识与 RAG 五库

入口：`make load-kb`；浏览 `GET /knowledge`。

| 库 | 作用 | 种子 | 成熟度 |
|----|------|------|--------|
| `attack_kb` | ATT&CK 技术（约 79 条 + STIX release） | `data/knowledge/attack_techniques.json` | Mock 可演示 |
| `fp_case_kb` | 误报相似案例 | `fp_cases.json` | Mock 可演示 |
| `history_case_kb` | 已结历史案 | `history_cases.json` | Mock 可演示 |
| `playbook_kb` | 遏制/调查剧本 | playbook release | Mock 可演示 |
| `org_context_kb` | 批准源/域、变更窗、角色等，约束检索 | `org_context_seed` | Mock 可演示；**仅 Mock 源模式种种子**，生产种子为空 |

`data/knowledge/policy_controls.json` 是合规映射，**不在五库里**。  
检索：关键词 + 向量 + 融合；先查组织上下文再约束其余库。真向量演示见 `make up-embedding-remote`，**不是**评测默认（评测锁 `EMBEDDING_MODE=mock`）。

---

## 7. 事件类型与场景包

8 种 `EventType`：`account_anomaly`、`host_compromise`、`data_exfiltration`、`insider_threat`、`malicious_process`、`suspicious_domain`、`lateral_movement`、`other`。

场景包由 `seed_mock_xdr_and_ingest` 注入，**不是**手搓 `POST /events` 金路径。

3 条 Demo 金路径和 8 条 EventType 套件**不是同一质量门**：

| | Demo 3 条 | EventType 8 条 |
|--|----------|----------------|
| 场景 | 内鬼外泄、改密误报、可疑域名 | 上列 3 条 + 失陷、特权、恶意进程、横向、未分类 |
| 列表 | `GOLD_SCENARIOS`（锁死 3，勿把 8 条塞进去） | `EVENTTYPE8_SCENARIOS` |
| 入口 | `make demo-full-loop` / `eval-full-loop` | `make eval-eventtype-8` |
| CLOSED | `demo-full-loop` 强制；`eval-full-loop` 默认可不强制 | 永远 `--require-closed` |
| 报告 | Demo 不强制 `generated_by=llm` | 强制 llm 报告；拒绝 MockLLM |
| 矩阵 | `eval-full-loop-matrix` 默认 3 条；ISSUE-313 下误报/域名可为 analysis-only | 8× `full_loop_strict`，禁止 `--analysis-only` |
| 主索 | Demo 偏闭环 CLOSED | 另加 persist：误报案例 id、剧本、攻击技术、相似历史等（按场景，深度不齐） |

误报与 `other` 按产品跳过实体封禁（禁止 isolate 成功过门），不能拿内鬼的「隔离 SUCCESS」去比这两条。

8 条 A 档（Mock XDR）骨架：真 LLM、种子 ingest、Worker full_loop、脚本审批、CLOSED、能执行的主处置必须 Job SUCCESS。B 档 live 深信服是另一列，隔离/禁用/杀进程可 `owner=None`，**未真机验收**。

---

## 8. 接入与安全开关

| 能力 | 入口 / 配置 | 成熟度 |
|------|-------------|--------|
| Mock XDR 读写契约 | `/mock-xdr/v1` · `SOURCE_MODE=mock_xdr` · `DISPOSITION_MODE=mock_xdr` | Mock 可演示 |
| 文件源 | `SOURCE_MODE=file` | Mock 可演示（回退） |
| 深信服 Adapter | `backend/app/adapters/sangfor/` · `contracts/vendor/sangfor_xdr` | 未接线或未真机：Cutover-Ready ≠ 现场验证 |
| HTTP Disposition | `DISPOSITION_ADAPTER_KIND=http` | 未接线或未真机（能力默认 UNKNOWN） |
| CrowdStrike | — | 未接线：无 `adapters/crowdstrike/` |
| LLM | `LLM_MODE=mock` / `openai_compatible` / custom factory | Mock 可演示；custom 需自备 factory |
| 活体侧效保险 | `ALLOW_LIVE_SIDE_EFFECTS`、`BLOCK_LIVE_ACTION_EXECUTION`、`ALLOW_XDR_WRITEBACK` 默认 false | Mock 可演示 |

Live 源模式禁止 `TOOL_MODE=mock`（fail-closed）。无厂商创建 URI 时保留 isolate 等 Action 并允许 `execution_owner=None`（待人工），不是产品取消隔离。

---

## 9. 运维与评测入口

| 入口 | 做什么 | 成熟度 |
|------|--------|--------|
| `make up` | Postgres+pgvector、Redis、前后端、MockXDR；默认无 worker | 短路径分析，**不是** CLOSED 金路径 |
| `make up-demo` | 上项 + Celery worker + scheduler + 可选可观测 | Mock 可演示（官方栈） |
| `make bootstrap` | 三场景 seed + investigate（无 worker 易丢） | 可选；非官方闭环 |
| `make bootstrap-demo` | 分析种子，默认不含 response | 可选；**非 CLOSED** |
| `make bootstrap-demo-full-loop` | 含 response + 报告，停在 `waiting_approval` | Mock 可演示 |
| `make demo-full-loop` | 种子 → 调查 → 脚本审批 → 写回 → 验证 → CLOSED | Mock 可演示（官方单场景金路径） |
| `make eval-full-loop` | 同上脚本；无 `EVAL_REQUIRE_CLOSED` 则为 compat | 可选（闸门更松） |
| `make eval-full-loop-matrix` | 默认 3 场景；可开 ISSUE-313 profile | 可选 |
| `make eval-eventtype-8` | 8 类型严格 CLOSED + persist 列 | Mock 可演示（套件入口；勿与 Demo 3 条混称） |
| `make load-kb` | 五库 + playbook release | Mock 可演示 |
| `make smoke-demo` | health + compat 终态 | 可选；非 strict CLOSED |
| `make up-observability` | OTel / Prometheus / Grafana | 可选 |
| `make up-embedding-remote` | 真向量演示轨 | 可选；**禁止**当 8 条评测证据 |
| `POST /ingestion/source-records` | 摄入源记录 | Mock 可演示 |
| `POST /investigation-intents/dispatch` | 自动调查派发 | 可选：`AUTO_INVESTIGATE_ENABLED` |
| 检测治理 API | 资格/决策/撤销/晋升门 | 可选（无独立 UI 页） |
| `GET /health`、`/tools`、`/connectors` | 健康与目录 | Mock 可演示 |

脚本审批用 `dynamic_eval_approve`；**禁止**空等 `APPROVAL_TIMEOUT` 收尾。CJK 路径 compose 需 `COMPOSE_BAKE=0 DOCKER_BUILDKIT=0`。

---

## 10. 明确没有 / 未接线

| 项 | 说明 |
|----|------|
| Rollback Saga 进产品环 | 服务与单测在，未进 LangGraph / UI / 面向分析员的 REST |
| 上下文压缩进生产依赖 | 测试有，未注入正式 deps |
| 生产 org_context 种子 | 有意留空；只 Mock 源模式种演示记录 |
| CrowdStrike Adapter | 不存在 |
| 深信服真机闭环 | Adapter 合同在；本仓库未对生产 XDR 跑通，不得用 Mock 绿声称已对接 |
| 8 条与 Demo 3 条同等厚 | 入口、报告强制、persist 主索均不同；矩阵 analysis-only 更弱 |
| 分析正文写回 XDR | 永久禁止 |
| 完整 IdP / SSO UI | 仅 dev token 与可信反向代理头 |
| K8s 扩展演示脚本 | 未作为官方入口 |

---

**怎么用这份文档：** 给分析员看 §3–§5；给演示运维看 §7 与 §9；对接厂商时看 §8 与 §10。默认能对外演示的是 **Mock CLOSED 金路径**，不是现场 XDR。
