# 8 条 EventType 真 LLM 金路径评测计划

> 施工合同。按 §8 分期**依次执行**；未绿禁止宣称 8 条同等强度。  
> **默认验收只认 Mock XDR**（没有现场 XDR 也必须 8 条全绿）。live XDR 是可插拔第二档，接不上不挡默认验收，也不得用默认绿声称已对接生产。  
> 禁止发明厂商 URI。分析正文永不写回 XDR。timeline 500、health degraded、聊天、DSP、调查阶段重规划 **不进**本套件 DoD。

权威对照：README 八种 `EventType`；`docs/sangfor-xdr-alignment-plan.md` §1.8；`scripts/dynamic_eval_full_loop.py`；`scripts/seed_mock_xdr_and_ingest.py`；`backend/app/data_generators/scenarios/`；`backend/app/adapters/mock_xdr.py`（`MockXDRDispositionAdapter`）；`backend/app/tools/adapters/base.py`（`TOOL_MODE`）；`backend/app/providers/tools/mock_provider.py`。

---

## 0. 给负责人的结论

今天真 LLM 金路径只有 3 条场景包进 `GOLD_SCENARIOS`。另外 5 个包只在 MockLLM 系统测 / 回归里。要把 8 种 `EventType` 都做成**与现 insider 金路径同一质量门**的 closed-loop。

默认栈（**必须总能跑**）：

| 层 | 默认 | 说明 |
|----|------|------|
| LLM | 真模型（`openai_compatible`） | 禁止 MockLLM、禁止模板报告过门 |
| Agent / 审批 / AES / Verify / ToolRegistry | 生产代码 | 这就是「自己的 tool」 |
| 事件源与写回目标 | **只 Mock XDR**（`SOURCE_MODE=mock_xdr` + `DISPOSITION_MODE=mock_xdr`） | 夹具 `seed_mock_xdr_and_ingest` |
| 现场防火墙 / 深信服生产 | **不需要** | 没有 live XDR 也必须 8 条绿 |

接到 live XDR 时：同一 8 个 `scenario_id`、同一内核门；只换 Source/Disposition/Query Adapter。无 URI 的写（隔离创建等）改为人工，**不得**用 MockTool 给真事件盖章。

旧 `make demo-full-loop` 三场景入口**不改弱、不改默认跑 8 条**。8 条走新目标 `eval-eventtype-8`。

---

## 1. 先澄清：`TOOL_MODE=mock` 不是另一套假工具

仓库里工具分三层，不要混：

1. **内核工具（自己做的）**  
   `backend/app/tools/` 的规范名（`isolate_host`、`query_edr_process`、`block_ip`…）、`ToolRegistry`、`ToolExecutor`、Response/Evidence/Verify Agent。8 条评测**必须**走这条生产管线。

2. **执行落到哪**  
   每个处置 Action 只能有一个 owner：`XDR_MANAGED`（`DispositionAdapter` 打 XDR HTTP）或 `DIRECT_TOOL`（ToolProvider 打设备）。禁止双下发。

3. **`TOOL_MODE=mock` 是 Direct Tool 的 Provider 绑定**  
   没有现场 AF/EDR 时，`DIRECT_TOOL` 必须有后端，否则隔离/查询没有执行点。`MockToolProvider` 就是 Canonical Mock 设备后端，绑的仍是同一套内核工具名，不是评测降级通道。

**禁止**把 8 条默认改成 `TOOL_MODE=live`：live Adapter 目前只为 `KIND=sangfor_xdr` 注册，且要 `ALLOW_LIVE_SIDE_EFFECTS`。没接生产时 `TOOL_MODE=live` + 空 Adapter = 查询/直连全空，8 条会红。那不是「更真」，是没后端。

默认 8 条要的「别的都 live」= **真 LLM + 真 Agent + 真执行器 + 真 Disposition 管线**；唯一 Mock 的是 XDR 那一头（`MockXDRServer` + `MockXDRDispositionAdapter` 打 `/mock-xdr/v1`）。`MockToolProvider` 只承担 Canonical Mock 上 Direct Tool / `query_*` 的设备模拟，与「用 MockLLM 过门」不是一回事。

接到 live 时：`SOURCE_MODE=sangfor_xdr` **禁止** `TOOL_MODE=mock`（config 已 fail-closed）。真事件上出现 `provider` 含 `mock_tool_provider` 的查询/处置 → 该条失败。

---

## 2. 两档期望（同一套场景，不是两套测试）

| 档 | 何时跑 | 摄入 | 处置必过 | 查询 |
|----|--------|------|----------|------|
| **A. Mock XDR（默认，必须绿）** | 每次分期验收、nightly | `seed_mock_xdr_and_ingest` | Canonical Mock **能执行的**必须执行成功 + Verify（与现 insider 金路径同级：隔离/禁用/杀进程/`query_*`/封禁/工单按场景） | Mock `query_*` 允许 success |
| **B. live XDR（可选，接不上跳过）** | 有凭证 + 现场库存时 | 仍尽量用同一场景包语义；生产里没有这 8 个 Mock 种子，不挡 A | 只认开放列表**有创建 URI** 且现场配齐的写（封 IP/域名、扫描、工单、`dealStatus`）。isolate/disable/杀进程：计划可有，`execution_owner is None`，Verify `UNVERIFIABLE` | 按 `SangforQueryAdapter`：资产 success；进程/文件/DNS/流量/情报 degraded；登录/漏洞/历史 unavailable。Mock 查询戳失败 |

A 档不把 isolate 降成「owner=None 就算过」——那会让新 5 条弱于前 3 条。  
B 档不把 Mock 隔离成功抄过去——那会在无 URI 的厂商上假绿。

`GOLD_SCENARIOS` 仍是现在 3 元组（Demo 入口）。8 条另建 `EVENTTYPE8_SCENARIOS`。`SCENARIO_EVAL_PROFILES`（ISSUE-313 analysis_only）**不动**。8 条全部 `full_loop_strict`，禁止 `--analysis-only`。

期望模块新建 `scripts/eventtype8_suite_expectations.py`，每条两个 column：`mock_xdr` / `sangfor_xdr`。禁止一个 assert 混两档。

---

## 3. 同一质量门（8 条每条都要；新 5 条不得少任何一项）

与现 insider 的 `run_gold_loop` + `--require-closed` 对齐，并补现在没查的项：

1. `LLM_MODE` 非 `mock`。评测入口拒绝 MockLLM。
2. 事件来自 `seed_mock_xdr_and_ingest`。禁止手搓 `POST /events`。
3. Worker `full_loop`：`include_response_execution=true` 且 `generate_report=true`。8 条不得 `--analysis-only`。
4. 人工门只经 `dynamic_eval_approve`。禁止 `APPROVAL_TIMEOUT` 收尾。
5. `--require-closed`：`assert_strict_closed_acceptance`（`closed`、报告非 `incomplete_placeholder`、`writeback_required` 时写回 `ready` + `confirmed`）。
6. `GET /api/v1/events/{id}/report` 的 `report.generated_by == "llm"`。`generated_by=template` 失败。Demo 入口默认仍不强制这一条，避免无声收紧旧 3 条脚本；8 条套件强制。
7. traces / `llm_call_log` 至少一条成功 LLM 调用，`model_name` 不是 MockLLM 占位。
8. **主索 persist 命中**（§4）。只 CLOSED 不算覆盖。
9. **A 档必须有真实执行**（FP / `other` 按产品跳过实体响应除外）：计划里的主处置 Job SUCCESS + Verify，与 insider 的隔离执行同级。禁止「计划里有工具、owner=None」在 A 档过门。
10. 禁止用 ISSUE-086 系统测、回归快照、compat 冒充本套件。

入口：`EVAL_REQUIRE_CLOSED=1 make eval-full-loop` **已经是** full_loop（与 `--analysis-only` 互斥）。ISSUE-313 matrix 里 FP/域名的 `analysis_only_*` 是另一条入口，**不要**当成「今天 FP 没有 Worker」。第 0 期以 `EVAL_REQUIRE_CLOSED=1 EVAL_SCENARIO=account_anomaly_fp` 实测为准。

---

## 4. 主索矩阵（A 档与前 3 条同等；B 档可插拔）

原则：主索是 persist 字段。夹具/`allowed_actions`/KB 种子必须**逼出**主索，不赌 LLM。persist 读 API 的 `context_snapshot`（或 EventContext 的 `rag_output`），不要臆造 `event_context_snapshot`。  
`fp_similarity` 有 default factory，禁止断言「非空」；要 `matched_case_id` + `max_score` 过阈值。`OrgContextMatch` 用 `match_type == "exact"`，没有 `is_exact`。

| # | scenario_id | EventType | 产品主索（A/B 都要） | A 档 Mock XDR 必过（与前 3 条同级） | B 档 live（有库存才 SUCCESS） |
|---|-------------|-----------|----------------------|-------------------------------------|-------------------------------|
| 1 | `account_anomaly_fp` | `account_anomaly` | FP 裁决 + `fp_case_kb` | `final_verdict=false_positive`；`fp_similarity.matched_case_id` 对齐 `case-00000001` 且分数过阈值；`assert_fp_full_loop_gate`（不得进 `planning_response`）。误发 isolate SUCCESS → 失败 | 同左（无实体封禁）。写回仅当策略要求 |
| 2 | `suspicious_domain_access` | `suspicious_domain` | 域名研判 + `block_domain` | 改夹具：威胁路径要能规划并 **执行** `block_domain`（今日 pack 是 `not_required` + `expected_verdict=none`，A 档升格时必须改 policy/遥测，否则主索打不中）。Job SUCCESS + Verify | 有 AF：`XDR_MANAGED` + list `block success`。无 AF：`owner=None`，禁止假绿 |
| 3 | `insider_data_exfiltration` | `data_exfiltration` | 外泄 CLOSED + **隔离执行** + 写回 | 与现 Demo 金路径同级：`isolate_host`（及夹具里的 disable）执行 SUCCESS + Verify；`update_source_event_disposition` CONFIRMED。工单有则 SUCCESS | isolate/disable：`owner=None`。关单靠工单（配齐时）+ `dealStatus`。**产品必须让 pending-manual 不永久卡死 CLOSED**，否则 B 档标缺口而不是假绿 |
| 4 | `host_compromise` | `host_compromise` | `scan_host_for_virus` | pack 的 `allowed_actions` **加上** `scan_host_for_virus`（今日没有，会逼不出扫描）。A 档：扫描 Job SUCCESS + Verify；Canonical Mock 上 isolate 仍允许 SUCCESS（质量不降） | 扫描：有 EDR/`host_identifiers` 才 SUCCESS。isolate：`owner=None` |
| 5 | `insider_privilege_abuse` | `insider_threat` | `org_context_kb` + 账号处置 | 补 org 种子（`svc-admin-abuse` / `SRV-ADMIN-003`，`match_type=exact` ≥1）。A 档：`disable_account` **执行 SUCCESS**（Canonical Mock 有此能力，与 insider 隔离同级）。只断言「计划里有 disable」算弱，不算同等 | disable：`owner=None`。工单/写回配齐才 SUCCESS |
| 6 | `malicious_process` | `malicious_process` | `playbook_kb` + 进程查询 | `rag_output.playbook_refs` 或 Action `playbook_ref` 非空。A 档：`query_edr_process` success；`block_process` **执行 SUCCESS**（Mock 有） | 查询 degraded。杀进程 `owner=None`。工单/写回配齐才 SUCCESS |
| 7 | `lateral_movement` | `lateral_movement` | 图谱 + `attack_kb` | 夹具至少两主机 + 跨主机关系。`graph_output` 有 edges/features；`attack_techniques` 或 attack citations 非空。A 档：`block_ip` **执行 SUCCESS** | `block_ip` 仅 AF 齐时 SUCCESS。isolate/disable：`owner=None`。Neo4j 不是 P0 硬前置 |
| 8 | `other_unclassified` | `other` | `history_case_kb` + CLOSED | 种子对齐 `WKS-GEN-099`；`similar_cases` 非空（非空列表，不是 default）。`not_required`：CLOSED + 报告 llm，**不得**要求封禁 SUCCESS。乱规划 isolate 且执行 SUCCESS → 失败（与 FP 同纪律） | 同左。不要求厂商写 |

重规划：`ReplanHandler` 只吃 Verify 失败；本套件**不挂** `replan_count>=1`。另开 Issue。

**禁止** 5 条新场景只换 `event_type` 再 CLOSED。

---

## 5. 标明的缺口（执行时对着勾）

### 5.1 5 个系统包偏瘦

`_system_scenario_pack.py` 相对 3 个 Demo 包实体不够。升格时允许改 pack 与 KB 种子。禁止在 Agent 里硬编码「张三」。`host_compromise` 必须把 `scan_host_for_virus` 写入 `allowed_actions`。`lateral_movement` 必须双主机。

### 5.2 B 档 CLOSED vs 人工隔离

AES：`execution_owner is None` 不执行。关单路径在 `need_manual_resolution` 时不 CLOSED。因此 B 档若模型仍规划 isolate，可能永远关不了单。  
**A 档不受影响**（Mock 会执行隔离）。B 档开工前要先定产品：空 owners 工具不进可执行计划，或人工项不挡终态写回。未定前 B 档标 BLOCKED，**A 档照常验收**。

### 5.3 域名夹具与封禁主索冲突

今日 `suspicious_domain_access`：`disposition_policy=not_required`、`expected_verdict=none`。A 档要 `block_domain` 执行成功，必须改夹具（政策 / 裁决 / 遥测），否则不是评测问题。改 pack **不得**让 Demo 三场景回归变弱：若 Demo 仍依赖 `none`，用 8 条套件自己的 variant/seed，或把 Demo 域名也升到威胁闭环并更新 Demo 断言。

### 5.4 FP full_loop

`assert_fp_full_loop_gate` 已在 `EVAL_REQUIRE_CLOSED` 单条路径上调用。第 0 期只是复跑确认，不要按 matrix profile 推断「没有 full_loop」。

### 5.5 live 摄入

8 个包活在 MockXDR 种子里。B 档换 Adapter 后，生产 XDR **不会**自动出现这 8 个事件。B 档能验证的是：同一套断言在 live Adapter 下诚实，不是「对着生产跑 `eval-eventtype-8` 能 ingest 出这 8 条」。

---

## 6. 脚手架（不把 8 条塞进 `GOLD_SCENARIOS`）

| 路径 | 改什么 | 不改什么 |
|------|--------|----------|
| `scripts/dynamic_eval_profiles.py` | `EVENTTYPE8_SCENARIOS`、`EVENTTYPE8_EVAL_PROFILES`（8×`full_loop_strict`） | `SCENARIO_EVAL_PROFILES` 三行 |
| `scripts/dynamic_eval_full_loop.py` | `--suite {demo,eventtype8}`，默认 `demo`；eventtype8 强制 `--require-closed` + §3 质量门；拒绝 MockLLM | 默认 `--scenario` 仍 insider |
| `scripts/eventtype8_suite_expectations.py` | 每条 `mock_xdr` / `sangfor_xdr` 两列 | 不要用 `SCENARIO_EXPECTATIONS.allowed_actions` 当必过 |
| `scripts/strict_closed_acceptance.py` | 抽出 `generated_by=llm` 给 8 条 | Demo 路径默认不强制 llm |
| `scripts/dynamic_eval_matrix.py` | `--suite eventtype8` 串行 8 条 + `--fresh-volumes` | 默认 matrix 仍 3 条 |
| `Makefile` | `eval-eventtype-8` | `eval-full-loop` / `demo-full-loop` 行为 |
| `_system_scenario_pack.py` + 域名 pack（若升格封禁） | §4 实体/双主机/扫描/`allowed_actions` | 不删 Demo 隔离遥测 |
| `data/knowledge/*` | #1/#5/#6/#7/#8 种子与夹具原文对齐 | 不写厂商 URI |
| `test_dynamic_eval_*` | 锁 GOLD 仍 3；8 条拒绝 analysis_only；A 档 isolate SUCCESS 仍可断言；B 档 Mock provider 失败 | 不把系统测改成真 LLM |

`seed_mock_xdr_and_ingest.py` 已支持 8 个 id，不必新建 seed 脚本。  
`make load-kb` 必须进 8 条评测栈。种子用夹具原文（`EMBEDDING_MODE=mock` 靠 keyword）。

---

## 7. 真 LLM vs 单测；旧 3 条不得变弱

**必须真 LLM：** 8 条每一条。无密钥 skip，不准 MockLLM 顶。标 `needs-real-llm`。

**单测即可：** overlay 空设备 owners 空；Sangfor 查询 unavailable/degraded；期望解析；`GOLD_SCENARIOS` 长度 3；`--analysis-only --require-closed` 非零退出。

旧 3 条验收：

1. `GOLD_SCENARIOS` 仍那 3 个 id。  
2. `make demo-full-loop` 默认仍 insider。  
3. Demo insider 仍可断言 Mock 隔离执行成功。  
4. ISSUE-313 matrix 默认场景与 analysis_only 语义不变。  
5. Canonical Mock 隔离/账号/杀进程/`query_*` **不删**。

---

## 8. 分期（按这个顺序执行；一次一期）

| 期 | 你要做的 | 完成定义 | 没有 live XDR？ |
|----|----------|----------|-----------------|
| **0** | `EVAL_REQUIRE_CLOSED=1 EVAL_SCENARIO=account_anomaly_fp make eval-full-loop` | `assert_fp_full_loop_gate` 绿，或修 FP 跳过实体规划后再绿 | 只跑 Mock XDR，必须做 |
| **1** | 新 suite 常量、两列期望模块、`generated_by=llm` 门、`eval-eventtype-8`、单测锁旧 3 条 | `make eval-full-loop` 仍只默认 3 条且行为不变 | 必须做 |
| **2** | 瘦包 + KB 种子按 §4 对齐；`allowed_actions` 能逼出扫描/封禁/禁用/杀进程 | 无 LLM 检索单测打中种子 | 必须做 |
| **3** | **先 3 条已有场景**用 suite 跑通（质量不低于现金路径），**再逐条** 5 个新场景 `eval-eventtype-8 EVAL_SCENARIO=…` | 每条 A 档：质量门 + 主索 + Mock 执行 SUCCESS（#1/#8 除外） | **这是默认验收终点** |
| **4** | 可选：Sangfor live / overlay 单测 + 有库存才跑封禁 SUCCESS | 无凭证 skip。Mock 查询戳失败。不声称已对接生产 | 跳过不影响「8 条已完成」 |

第 3 期建议顺序（质量对齐）：

1. `insider_data_exfiltration`（对照现金路径，套件门不能弱）  
2. `account_anomaly_fp`  
3. `suspicious_domain_access`（先完成夹具升格）  
4. `host_compromise`  
5. `insider_privilege_abuse`  
6. `malicious_process`  
7. `lateral_movement`  
8. `other_unclassified`

一条红了先修夹具/种子/期望，再开下一条。不要 5 条一起合。

---

## 9. 风险

- LLM 非确定：主索靠种子对齐 + persist 结构，不用报告全文。风险分用宽区间，不用 ISSUE-229 Mock 金值。  
- 域名升格可能碰到 Demo 期望 `none`：用套件 variant 或同步更新 Demo，禁止偷偷改弱 Demo。  
- 图谱不补双主机则 #7 主索失败。  
- 8× full_loop 时长：矩阵 `--fresh-volumes` 串行。  
- 禁止 overlay 打到 `KIND=mock`。  
- B 档人工隔离卡 CLOSED：见 §5.2，不挡 A 档。

---

## 10. 明确不做

- 发明 isolate/disable/杀进程创建 URI。  
- 默认 8 条改成 `TOOL_MODE=live`（没接 XDR 时没有 Direct Tool 后端）。  
- 用 MockLLM / 模板报告 / `POST /events` / `APPROVAL_TIMEOUT` 过门。  
- 分析/报告写回 XDR。  
- 把 8 条塞进 `GOLD_SCENARIOS` 让 `make eval-full-loop` 默认跑 8 条。  
- 宣称 A 档绿 = 生产 XDR 已对接。  
- 调查阶段重规划、timeline 500、health、聊天、DSP 进 DoD。
