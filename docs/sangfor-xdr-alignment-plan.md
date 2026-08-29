# 深信服 XDR 对齐实施计划

> **接口合同以开放列表为全真来源**，不是猜测、不是截图、不是 Mock 路径。  
> 权威文件：`挑战杯物料/OpenAPIDocument/深信服XDR平台接口开放列表.html`（eolinker 导出，`projectUpdateTime=2026-04-28 11:28:37`，**129 个操作 / 124 条唯一 URI**）。  
> 鉴权：`OpenAPIDocument/python/authCodeDemo` 为主；java8 / java11 / go 只做交叉向量，**冲突时以 Python Demo 为准**。  
> 内部契约：根目录 `README.md` 第 1–4 节。Agent 不出现厂商路径；差异全部进 Adapter。Canonical Mock 继续走 `/mock-xdr/v1`，**禁止**改成深信服 URI。

本文按 2026-04-28 开放列表与 authCodeDemo **整份重写**。旧稿把 `dealstatus/list` 的库内码当成写入码、把 `block_domain` 写成无接口、把响应 `paramList` 当成「没展开」、把 `DISPOSITION_MODE=live` 与 ToolProvider 直调实体接口，均作废。

**2026-08 深修轮：** 对齐仓库 `live_xdr`/`mock_xdr` 命名、§2.0 Disposition outbox 管线、§2.1.1 摄入归一化、blockIpRule 字段、无 concurrency token、Layer 7 工厂、Layer 11 文档同步。

**2026-08-27 对照开放列表修订：** 用 HTML 全量 129 操作 + `aksk_py3.py` + 仓库 `Severity` / `production_fail_closed` 核对后，修正会写错线的合同。作废或改写：告警读 `item.dealStatus`、`block_domain` 可走 endpoint、`blockdevice` 字段原样当 `devices[]`、`has_more` 一律用 `total`、Query 签名只 urlencode、内核 Severity 出现 `information`、`TOOL_MODE=mock` 可进 production、隔离 Verify 把「查到一行」当已隔离、`securitylog`「无 uuIds」。详见 §2.1.2、§2.3.0–2.3.3、§2.5、§3、§7。

**2026-08-27 对照仓库深修（执行前必读）：** 开放列表合同保持不变；修正会在**本仓库**写错线的实现指令。作废或改写：新建并行 `effector_resolver.py`、给 `SourceIncident` 加 `description`、把 `gptResult` 填进 `gpt_verdict_label`、生产「allowlist 加入 `sangfor_xdr`」、把 `crowdstrike` 当成已有 adapter 包、Layer 7 只改 `deps.py`、Layer 8 在 VerifyAgent 里硬编码 URI、Layer 11 只改 README。冻结约束见 **§1.6**。

**2026-08-27 overlay / 工厂 / Query / Job 终态修订（执行前必读）：** 对照 `response_agent.py` / Celery worker / DSS ISSUE-311 后，修正下一层 AI 会写错的接法。作废或改写：Layer 8 只给 `ResponsePolicyFilter` 加 `tool_index`、物化再调一次 `baseline_tool_index()`、`owner is None` 时 `continue` 丢掉 isolate、Layer 7 只改 API `deps.py`、Layer 6 只写 list/detail `block success` 却不接 Job/effect completion、Cutover 用 `TOOL_MODE=mock` 冒充能力完整、live 质量门认 Mock `isolate_host` 成功。详见 **§1.5–1.6、Layer 4d/6/7/8/8b、硬规则 24–32**。

**2026-08-27 能力缺口合同修订（执行前必读）：** 对照 `Action._enforce_owner_and_phase`、`writeback_fields`、`approval_engine` AUTO_REJECT、ISSUE-302 `EXECUTION_JOB_ONLY` 后，修正「`execution_owner=None` 已合法 + 实体套 `CAPABILITY_UNSUPPORTED`」会写挂的接法。作废或改写：persist `owner=None` 不改校验器、实体 isolate 写 `writeback_readiness=capability_unsupported`（会 AUTO_REJECT 或 ValueError）、AES 只 skip 却不改收敛（`IN_FLIGHT_JOB` 关不了单）、Cutover 缺 `ALLOW_LIVE_SIDE_EFFECTS`、live 非 XDR_MANAGED Verify 回落 Mock 文件状态、8b 把事件实体当舰队 EDR 搜索、6c 工单不接 Job 终态。正确合同见 **§1.7**。详见 **§1.5–1.7、Layer 6c/7/8/8b、硬规则 33–40**。

**2026-08-27 双运行时修订（执行前必读）：** 厂商 OpenAPI 没有的能力（隔离创建、禁用账号、杀进程、舰队登录查询、`isolateStatus` 枚举、DSP 全码表、现场 AF/工单责任人）**不得**从内核或 Canonical Mock 删掉。本计划只约束 **live Sangfor Adapter** 诚实降级；**不接入生产、本地验证** 时产品闭环仍走 Mock，功能必须全在。生产 XDR 以后加接口 = **另开 Issue**，本计划不预写假 URI。作废：把「live 比 Mock 弱」写成「Demo 也砍功能」；把 Vendor Wire Mock（测 Adapter 的 HTTP 夹具）当成产品 Mock。正确合同见 **§1.8**。文档硬伤同步改：§2.0 总表分列 `block_ip`/`block_domain`；6c 工单 **仅 POST** list，创建 `orderId` **对不上** list 的 `workflowId`；空 `code` 示例不以 `"Success"` 强判；签名 `params is None` 当 `{}`。

**给执行 AI：** 一次只做一层。上一层验收未绿（含附录 A 真实 LLM 全链路未绿）禁止开下一层。只改该层「允许改」的路径。每一层合并后 **Canonical Mock 金路径必须仍绿且功能不减**（隔离、账号、杀进程、全套 `query_*`），并用 **真 LLM + Mock XDR** 跑三条 `EVAL_REQUIRE_CLOSED=1` 金场景（见附录 A）；有 `.env.live` 时禁止 `make up-demo`，改用 `make up WORKER=1`。开放列表有的字段名/枚举值 **原样使用**，禁止改名后再发给 XDR。URI 有 `:taskId` 而 `restfulParam` 为空时，**仍按 URI 占位符替换**，不得等 catalog 补字段。**禁止**为了对齐厂商而改 `SourceIncident` / `Severity` / `ExecutionOwner` 枚举（Layer 8 只允许给 RESPONSE 增加 **有文档的** `execution_owner=None` 窄例外，见 §1.7，仍禁止加 `manual` 成员）。**禁止**改 `/mock-xdr/v1` 去模仿深信服，也 **禁止** 为对齐 live 缺口去削弱 Mock 工具目录。

**2026-08-27 live 运营补救：** 若现场只用 live，Mock 保不住自动隔离。补救分档见 **§1.9**：本计划内用封禁/扫描/工单/人工待办；自动隔离/账号/舰队查询必须另开 Issue（厂商 URI 或真 Direct Tool），禁止 Mock 补 live。

**2026-08-27 逐层真实 LLM 全链路：** 每一层做完必须用 **真模型 + Mock XDR/工具** 跑三条金场景 `EVAL_REQUIRE_CLOSED=1`（不是 MockLLM、不是 Sangfor live、不是 CrowdStrike）。有 `.env.live` 时禁止 `make up-demo`（demo-guard），改用 `make up WORKER=1`；`.env.live` 只覆盖 LLM，禁止把 example 里的 `live_crowdstrike` 拷进来。命令与断言见 **附录 A**。

---

## 0. 物料：哪些全真、哪些旁路、哪些不用

挑战杯目录里有多套产品。它们 **不是** 同一个「AI 安全平台 REST」。

| 物料 | 产品面 | 本计划地位 |
|------|--------|------------|
| `OpenAPIDocument/深信服XDR平台接口开放列表.html` | **XDR OpenAPI** | **全真 REST 合同**。路径、方法、请求字段、响应 `paramList`、枚举一律按它实现与测 |
| `OpenAPIDocument/python/authCodeDemo`（及 java/go） | XDR 开放 API 鉴权 | **全真鉴权**。HMAC-SHA256 + 联动码/AKSK；签名算法细节见 §3 |
| `OpenAPIDocument/readme.pdf` | 接入说明 | 现场从「配置管理 → 系统设置 → 开放性 → 联动码管理」取码；签完禁止改请求 |
| `DataOpenDocument/DSP安全告警日志规范.pdf` + 样例 txt | **DSP（数据安全平台）** 日志外发 | **不是** XDR REST。仅 Layer 9 可选文件源；`source_product=sangfor_dsp`。禁止当 `incidents/list`。规范 PDF 多为扫描件，**码表未从 PDF 文本层坐实**；样例 txt 的 `dealStatus` 全为 `0`、`severity` 为 `50`。§2.4 标 UNVERIFIED |
| `深信服_可扩展的检测与响应平台XDR_用户手册.pdf` | XDR 产品手册 | 扫描件/水印为主，**抽不出字段**。只可作对象直觉（事件 ≠ 告警）。**不得覆盖**开放列表 URI/枚举 |
| `SANGFOR_STA_用户手册.pdf` | **STA 3.0.91 硬件探针**（安装、网口、WebUI） | 与 XDR OpenAPI **无关**。本计划不接入 |
| `数据集/测评中心基线样本nta.zip` | 评测 NTA 样本 | 更贴近 STA/流量侧。本计划不接入 |
| `AI安全平台AI共创模块使用说明文档（FastGPT）.pdf` | XDR **内置 AI 共创**（FastGPT 编排台） | **不进 Adapter、不进 Agent 依赖**。见 §1.2 |
| `AI安全平台AI共创模块使用说明文档（OpenClaw）.pdf` | 同上共创模块的 OpenClaw 通道（企微/飞书；文档写明走 XDR 运维 DNS） | 同上 |

开放列表 **129 个操作都是真接口**，不等于闭环要全做。大屏、脆弱性编辑、资产审核、白名单、SOAR 剧本历史等标「不实现」，原因是 **ShadowTrace 内核用不上**，不是怀疑它们假。

其中一条是 `POST /api/xdr/v2/assets/vpc`（v2）。catalog 必须原样收录，不要把「全部 v1」写进断言。

### 0.1 开放列表怎么读（Layer 0 抽取规则）

eolinker 导出是 `var projectJSON = {…}`，不是纯 OpenAPI YAML。

| 事实 | 存在哪里 | 禁止 |
|------|----------|------|
| 操作数 129 | 每个 `apiList[]` 一项（含同一 URI 不同 method） | 用「唯一 URI=124」当 129 的验收 |
| 方法 | `baseInfo.apiRequestType`：`0=POST, 1=GET, 2=PUT, 3=DELETE, 6=PATCH`。**`0` 不能写成空** | `apiRequestType or ""` 会把 94 个 POST 吃掉 |
| URI | `baseInfo.apiURI`，例如 `/api/xdr/v1/incidents/list` | 把 Mock 的 `GET /mock-xdr/v1/incidents` 写进 catalog |
| 路径参数 | URI 里 `:uuid` / `:id` / `:taskId`；`restfulParam[].paramKey` 常为 `uuId`（不是 `uuid`）。**例外：** `GET /responses/virusscantask/:taskId` 的 `restfulParam` 在导出里是 **空数组**，仍必须把路径里的 `:taskId` 换成任务 ID | 因为 restfulParam 为空就改成 query 或不发 |
| 查询参数 | `urlParam[]` | — |
| **请求体字段** | `requestInfo[]`：`paramKey` / `paramName` / `paramNotNull` / `paramValue` / `paramLimit` / 嵌套 `childList` | — |
| **响应字段** | `resultInfo[].paramList[]`（再嵌 `childList`），常见根：`code` / `message` / `data` | 只看 `resultInfo[].paramKey`（顶层没有，会误判「data 没展开」） |
| 成功码 | `code` 的示例值是字符串 **`Success`**，不是 `0`，也不是「HTTP 200 即可」 | 把 HTTP 200 当成业务成功 |
| `paramNotNull` | eolinker：`0` = 必填，`1` = 可空。列表里大量筛选字段标 `1`，调用时 **不要** 把可空字段全填示例值 | 把示例数组 `[1,2,3]` 当成必填枚举全集 |

响应仍可能缺叶子字段：未知键进 `raw_payload`（脱敏限长）。**禁止**用「没画某个叶子」否定该 URI 存在。

列表类 `data` 常见形状：`{ total, page, pageSize, item: [ … ] }`。`item` 是数组，不要当成单对象。**例外：** `analysislog/networksecurity/list` 的 `data` **没有** `total`；数量走伴随 `…/count`（`data.total`）。见 §2.1.2。

---

## 1. 目标与非目标

### 1.1 目标

在没有 XDR 真机的前提下，按官方接口把 Adapter 做到 **Cutover-Ready**：

1. **只读：** 用真接口拉安全事件、（可选）告警/资产/分析日志/实体/举证。
2. **写回：** 用真接口改 **事件** `dealStatus`；用 **另一套查询接口 + 另一套枚举** readback，通过后才能 `WritebackStatus.CONFIRMED`。
3. **实体动作：** 开放列表 **有创建** 的（网侧/端侧封禁含 IP/DNS/URL、病毒扫描、工单、解封、解隔离、解文件处置）按文档做。 **没有创建接口** 的（创建隔离、禁用账号、杀进程等）不得发明 URI；内核 Action **保留**。live 时 Sangfor pack **去掉** 这些工具的 **两个** owner（`XDR_MANAGED` **和** `DIRECT_TOOL`，本轮无 live Direct Tool）。计划仍含该 Action，物化 **不得** `continue` 丢掉；执行走 **§1.7 能力缺口合同**（`execution_owner=None` + 事件 `MANUAL_RESOLUTION`；实体 **不要** 套 `WritebackReadiness.CAPABILITY_UNSUPPORTED`）。**不要**加 `ExecutionOwner.manual`，也 **不要** 留下 `DIRECT_TOOL` 让 `TOOL_MODE=mock` 用幻想工具给真事件盖章。
4. **鉴权：** 官方签名（联动码或 AK/SK）。现场只配 URL、密钥、资产组、封禁设备、工单模板等。
5. **Demo 不动：** Canonical Mock（`/mock-xdr/v1`）继续支撑产品完整闭环与金路径。

Cutover-Ready **不是**「响应 JSON 已在真机验证」。无真机只能证明：请求字段、签名、枚举转换、readback 规则对着开放列表。第一份现场证据是 Layer 10 只读探测。

### 1.2 非目标（避免把挑战杯目录当成一个平台）

ShadowTrace 是 **独立部署的多 Agent SOC**。深信服侧要对接的是 **XDR 开放 API**（数据源 + 处置写回），不是把 ShadowTrace 嵌进「AI 共创模块」。

- **FastGPT / OpenClaw：** XDR 产品内的编排/IM 通道（挑战杯「AI 安全平台 AI 共创模块」文档）。**不是** OpenAPI，也不是 ShadowTrace 要嵌进去的运行时。本计划任何层都禁止依赖、引用、或把 ShadowTrace Agent 注册进该模块。`virusscantask.source=GPT_MANUAL` 只是 XDR 请求枚举，**不构成** FastGPT 集成。
- **XDR 内置 GPT 研判：** `gptResult` / `gptResults` **只进** `raw_payload`。禁止映射 `FinalVerdict`。禁止写入 `SourceIncident.gpt_verdict_label`（Ingester 会把它当 `event_type` 启发式，数字枚举会污染事件类型）。禁止把研判正文、报告、Prompt、decision_trace 写进 `dealComment` 或任何出站字段。
- **DSP：** 另一产品的日志规范；可选文件摄入，禁止与 XDR client 混用。
- **STA / NTA zip：** 不接入。
- **SOAR 剧本执行历史**（`/api/xdr/v1/soar/playbooks/...`）：真接口，本计划不接，避免和第二套编排缠在一起。ShadowTrace 自己的 playbook 资源保持内部。

### 1.3 可维护性

- 内部主名不变：`SecurityEvent`、`SourceDisposition`、`block_ip`、`block_domain`、`isolate_host` 等。
- 厂商 URI / 枚举 / 签名头只出现在 `backend/app/adapters/sangfor/` 与 `contracts/vendor/sangfor_xdr/`。
- 升级 XDR 版本 = 改 catalog + 映射测试，不是改 Agent。

### 1.4 能力完整性

本计划有 **两条运行时**，不得混写成一条「产品变弱了」。细节与验收见 **§1.8**。

- **内核工具目录不删。** `isolate_host`、`disable_account`、`block_process`、`quarantine_file`、全套 Evidence `query_*` 继续在 specs / Mock / Demo 计划里。
- **本地 / 不接入生产：** `SOURCE_MODE=mock_xdr` + `DISPOSITION_MODE=mock_xdr` + `DISPOSITION_ADAPTER_KIND=mock` + `TOOL_MODE=mock`（`make up-demo`）。Canonical Mock 金路径必须仍能规划、执行、Verify 隔离/账号/杀进程/登录查询。可继续用仓库自带 Mock，或日后换自己的 Mock 实现（**本计划不改 Mock 协议、不把 Mock 改成深信服 URI**）。
- **live Sangfor：** 文档有创建 → `xdr_managed`（配置齐）；文档只有查询/解除 → 查询可用于观测，解除仅补偿；文档完全没有写创建 → **两个 owner 都去掉**，保留 Action，走 **§1.7**。本轮 **没有** live Direct Tool；**禁止**留下 `DIRECT_TOOL` 让 `TOOL_MODE=mock` 给 **真事件** 盖章。Cutover-Ready **不等于** Demo 同等自动化：live 没有的写/查保持人工或 unavailable。**禁止在 live 路径用 Mock 补齐真平台效应**——这与「本地继续用 Mock 做完整产品」不矛盾。
- 调查：live 必须有 **Layer 8b**；语义不对等 → degraded / unavailable，**禁止** live 回落 Mock 成功。开放列表没有舰队登录查询，**不能**声称 live 与 Mock **同等**调查。Mock 路径的 `query_*` **保持完整**。
- **禁止**为了对齐从 Response 计划里删掉 `isolate_host`（含物化 `owner is None → continue`）。
- 生产 XDR **以后**若增加隔离创建等接口：另开计划，把矩阵从 `unsupported_write` 改回 `write`。本计划 **不预写假 URI**，也 **不提前删 Mock 实现**。
- 与仓库目标一致：独立 SOC、XDR 可替换、分析永不写回、**Mock 保 Demo 全功能**、live 只经 Adapter、单效应器、未知写能力不准假成功。风险只在 overlay 接错（删能力，或 Mock 冒充 **真** 平台效应）。

### 1.5 与现有代码 / env 对齐（修订旧稿偏差）

| 主题 | 仓库现状 | 本计划约定 |
|------|----------|------------|
| `DISPOSITION_MODE` live 取值 | 测试与 `production_settings` 使用 **`live_xdr`**，mock 为 `mock_xdr`；`is_mock_disposition_mode()` 只认后者 | **禁止**写 `DISPOSITION_MODE=live`。Cutover 用 `live_xdr` + `DISPOSITION_ADAPTER_KIND=sangfor_xdr` |
| `SOURCE_MODE` | 默认 `mock_xdr`。生产是 **mock 黑名单**（`_MOCK_MODE_VALUES["source_mode"]={"mock_xdr"}`），不是正选 allowlist | **不要**给生产新造 `sangfor_xdr` allowlist。`sangfor_xdr` 只要不进 `_MOCK_MODE_VALUES` 即可过 source 门。Layer 7 要加的是**工厂注册 + 拒绝 `DISPOSITION_MODE=live`（无 `_xdr`）** 等未配 adapter 组合 |
| `DISPOSITION_ADAPTER_KIND` | 默认 `mock`；代码包只有 `mock_xdr` + `http`。测试字符串里出现过 `crowdstrike`，**没有** `adapters/crowdstrike/` | 新增 `sangfor_xdr` 与 `mock` / `http` **并存**。禁止把工厂收成「只有 mock 与 sangfor」。不要实现 crowdstrike 包 |
| 效应器 | **没有** `effector_resolver.py`。归属在 `ResponsePolicyFilter.resolve_execution_owner`（[`response_agent.py`](../backend/app/agents/response_agent.py)），且 `ExecutionOwner` 只有 `xdr_managed` / `direct_tool`（**无** `manual` 枚举）。字段类型是 `ExecutionOwner \| None`，但 **RESPONSE/ROLLBACK 校验器今日禁止 None**（README §19） | Layer 2 **禁止**新建并行解析器。Sangfor pack **收窄** `supported_execution_owners`。`unsupported_write` 且无 live Direct Tool → **两个 owner 都去掉**。口语「manual」= §1.7：计划仍含该 Action，`execution_owner=None`（**Layer 8 才放宽校验器**），实体写回字段保持 `applicable=false` / `NOT_REQUIRED`，事件进 `MANUAL_RESOLUTION`。**禁止**加第三枚举，**禁止**物化 `continue` 丢掉，**禁止**把实体缺口写成 `CAPABILITY_UNSUPPORTED` |
| Overlay 接线 | `ResponsePolicyFilter.__init__` 写死 `self._tool_index = baseline_tool_index()`。Filter 是在 **`ResponseAgent._run` 里构造**的，不是 `deps.py`。`_materialize_actions` 自己再调一次 `baseline_tool_index()`，且 `owner is None → continue` | Layer 8：`ResponseAgent` **持有** overlay 副本；`_run` 创建 Filter 时传入。overlay 与物化共用同一份 `policy_filter._tool_index`。live execute 路径除 `build_mock_capability_manifest` 外 **禁止**再调 `baseline_tool_index()`。只给 Filter 加可选参数却不在 `_run` 传入 = 没接上 |
| Job / 工厂锁 | 生产 `DispositionAdapterRegistry()` **只有两处**：`deps.py` `_get_adapter_registry`（会 `register("mock_xdr")`）和 [`action_execution_tasks.py`](../backend/app/tasks/action_execution_tasks.py) `_build_execution_service`（**空 registry，连 mock 都不 register**；`ToolExecutor` 还写死 `tool_mode="mock"`）。`ActionExecutionService` XDR job 写死 `provider_name="mock_xdr"`，Direct Tool job 写死 `provider_name="mock_tool_provider"` | Layer 7：**同一套组装函数**，API 与 Celery worker **禁止**各复制一份。只改 API 进程则 worker 写回仍空。符号名：`ActionExecutionService` 插入 `provider_name`，不要用过期行号 |
| 实体动作下发 | `XDR_MANAGED` 走 **`DispositionCommand` → outbox → DispositionAdapter`**（`ENTITY_ACTION_SUBMIT`），**不是** ToolProvider | §2.0、Layer 6 必须按此实现；禁止在 `ToolProvider` 里再调 blockiprule |
| 实体 Job 终态（ISSUE-311） | DSS `_maybe_complete_entity_effect` **只在** `disposition_mode=mock_xdr` + adapter `mock_xdr` + `receipt.simulated` 时才调 `read_entity_effect_completion`。Verify 看 Job 是否终态 | Layer 5–6：Sangfor adapter **必须**实现 `BaseDispositionAdapter.read_entity_effect_completion`；DSS 闸门改为认 `capabilities().supports_entity_effect_readback`（live_xdr 也走）。**禁止**另写一套 Verify HTTP 轮询当 Job 完成。缺这层 live 会卡在 verifying（与当初 Mock 缺 observation 同类） |
| Verify 观测 | `execute_verification_tool`（[`tools/verify/_common.py`](../backend/app/tools/verify/_common.py)）**无条件**进 `MockVerificationRuntime` | Layer 8：`KIND=sangfor_xdr` 且 `execution_owner=XDR_MANAGED` → Sangfor 只读；`KIND=sangfor_xdr` 且 owner **不是** XDR_MANAGED（含 `None`）→ **UNVERIFIABLE**，**禁止**回落 Mock 文件状态。Canonical Mock 仍走 `MockVerificationRuntime`。**禁止**改 VerifyAgent 硬编码 URI。观测 ≠ Job 终态 |
| Evidence 查询 | EvidenceAgent `query_*` 走 ToolProvider。`APP_ENV=production` **禁止** `TOOL_MODE=mock`。开放列表有 proof / `entities/*` / `assets/list` / 分析日志。`configure_tool_registry` 注册非 simulated live adapter 需要 **`ALLOW_LIVE_SIDE_EFFECTS=true`** | Layer 8b：**仅 live。** 事件维度实体 ≠ 舰队 EDR/账号登录搜索（degraded / unavailable）。未接线 → unavailable，**live 禁止** Mock 成功。Cutover 调查闭环必须同时 `TOOL_MODE=live` + `ALLOW_LIVE_SIDE_EFFECTS=true`。`KIND=mock` 的 `query_*` **保持完整**。Layer 4b **不能**代替 8b |
| 写回 CAS | Mock 用 `source_concurrency_token` | XDR **无**并发令牌字段；Sangfor adapter 设 `supports_concurrency_token=False`（§2.0、Layer 5） |
| 列表 HTTP | Mock Source 为 **GET** `/mock-xdr/v1/incidents` + cursor | 真 XDR 列表多为 **POST** + `page`/`pageSize` + `item[]`；差异只在 Sangfor SourceAdapter 内消化 |
| 阶段声明 | README、`AI_ISSUE_EXECUTION_PROMPT`、**`仓库运作说明.md`、`AI_CODE_REVIEW_PROMPT.md`、`tool-adapter-guide.md`** 仍写「无正式 API / 猜测」 | 挑战杯 OpenAPI **已是 Adapter 层权威**；Agent 层仍禁止厂商字符串。Layer 11 必须同步上列全部文件 |

### 1.6 对照仓库后冻结的实现约束（执行时不得再发明）

这些是 2026-08-27 对照代码的结论，**覆盖**本文旧层里与之冲突的文件名/做法。

1. **`SourceIncident`（`extra=forbid`）只有** `reference` / `raw_payload` / `normalized` / `title` / `level` / `gpt_verdict_label` / `impacted_asset_refs` / `related_alert_refs`。**没有** `description`。`name`→`title`；厂商 `description`→`normalized["description"]`（Ingester 已读该键）或 `raw_payload`。禁止改 Pydantic 模型加字段。
2. **`gpt_verdict_label` 对 Sangfor 必须保持 `None`。** Ingester `_event_type` 会把它当事件类型候选。XDR `gptResult` 是 0/10/…/180，不是内部 `EventType`。
3. **不要新建** `backend/app/models/effector.py` 或 `backend/app/services/effector_resolver.py`。效应器只扩展现有 `resolve_execution_owner` + ToolMeta overlay。
4. **不要给 `ExecutionOwner` 加 `manual`。** 口语「live 走 manual」= §1.7：计划保留 Action + **两个 owner 都去掉** + Layer 8 **放宽** RESPONSE 校验器允许 `execution_owner=None` + 实体写回保持 `applicable=false` / `NOT_REQUIRED` + `ExecutionSubstate.MANUAL_RESOLUTION`。**今日** `execution_owner=None` 对 RESPONSE **不合法**，禁止写成「已合法」。仓库 **没有** `ActionStatus.blocked` / `skipped`，不要新造。
5. **生产 `SOURCE_MODE` 是 mock 黑名单。** 不要新增 `sangfor_xdr` 正选 allowlist；不要把 `sangfor_xdr` 放进 `_MOCK_MODE_VALUES`。
6. **`crowdstrike` 不是代码包。** 工厂保持 `mock` / `http` / `sangfor_xdr`（及未来其它 KIND）可并存。
7. Layer 7 允许改必须覆盖 **所有生产** `DispositionAdapterRegistry()` 入口：[`deps.py`](../backend/app/api/v1/deps.py) `_get_adapter_registry` **和** [`action_execution_tasks.py`](../backend/app/tasks/action_execution_tasks.py) `_build_execution_service`，以及 `ActionExecutionService` 插入 `provider_name`（XDR job 今日 `mock_xdr`，Direct Tool job 今日 `mock_tool_provider`）。**同一套组装函数**，禁止 API / worker 各复制一份。
8. Layer 8 overlay：`ResponseAgent` 持有 overlay；**`_run` 创建 `ResponsePolicyFilter` 时传入** `_tool_index`（与物化同一份）。Verify 只读仍锁定 [`execute_verification_tool`](../backend/app/tools/verify/_common.py)。Canonical Mock 继续走 `MockVerificationRuntime`。**禁止**只改 Filter 构造、让 `_materialize_actions` 再调 `baseline_tool_index()`。
9. Layer 8b（调查前置）：**live** Evidence `query_*` 必须有 Sangfor 只读 Query Provider 或显式 unavailable / degraded；**禁止** staging 真事件 + Mock 查询臆造证据。调查闭环 Cutover 必须 `ALLOW_LIVE_SIDE_EFFECTS=true`。Mock 路径 query **不**套 8b。
10. live 质量门认 **persist 后的 Action 行**仍有该 containment 工具、`execution_owner is None`、**未被 AUTO_REJECT**、且 **不进** ISSUE-302 `EXECUTION_JOB_ONLY` 无 Job 闸。**不认** live 路径上 Mock `isolate_host` / `disable_account` 执行成功，也 **不认** 实体 `CAPABILITY_UNSUPPORTED`。Mock 金路径 **仍认** Mock 执行成功。
11. `code` 示例多数是 `"Success"`，但 catalog 里还有 `"InvalidParameter"`、**空串**、个别 `"200"`（后者仅 out-of-loop 的 `incident/labelInfo`）。业务成功 **按操作**：文档写明 `"Success"` 的（事件 `dealstatus`、封禁创建、工单 **创建**）必须是该字符串；文档示例为 **空串** 的（`POST/GET virusscantask`、`POST /orders/list`）**不得**强求 `"Success"`——HTTP 2xx 且必填 `data` 字段在（`taskId` / `status` / `item`）即传输成功，显式 `Failed` / `InvalidParameter` 仍失败。夹具必须覆盖 HTTP 200 + 非 Success。
12. 解析器类名是 **`ResponsePolicyFilter`**（[`response_agent.py`](../backend/app/agents/response_agent.py)），不是 `ResponsePlanPolicyFilter`。Overlay **不得**接到 `configure_tool_registry`（那是 ToolProvider 路由）。
13. Overlay **只改** `supported_execution_owners`，**不要**把 `executable=False`（`ResponsePolicyFilter._filter_one` 会整条丢掉，质量门变红）。Sangfor `CapabilityManifest.allowed_operations` **必须仍含** `isolate_host` / `disable_account` 等内核名。
14. DSP / `isolateStatus` 无枚举时标 UNVERIFIED 是对的；**不要**把 isolate/list「命中一行」当已隔离。Cutover-Ready **不是**真机验证；开放列表没写的是现场库存（哪台 AF、`devices[]`、工单责任人），不是接口假。大屏/脆弱性/白名单不实现是因为不是 ShadowTrace P0，不是接口假。
15. **`WritebackReadiness.CAPABILITY_UNSUPPORTED` 只用于事件处置写回能力**（deferred `EVENT_STATUS_UPDATE` / manifest）。实体工具今日 `writeback_applicable=false`；把 isolate 改成 `CAPABILITY_UNSUPPORTED` 会与 `_enforce_writeback_consistency` 冲突，或触发审批 **AUTO_REJECT**。禁止混用。
16. live `ResponseAgent` **禁止**默认 `build_mock_capability_manifest()`：`provider_name` 会盖成 `mock_xdr`。Layer 8 传入 Sangfor manifest（`provider_name` 随 KIND，`supports_concurrency_control=False`，isolate 仍在 `allowed_operations`）。
17. DSS 闸门 `_mock_entity_effect_readback_enabled` 今日还要求 `simulation_enabled` 与 `receipt.simulated`。Layer 6 必须 **整段替换**为认 `supports_entity_effect_readback`；Cutover `SIMULATION_ENABLED=false` 时 live 仍要调用。

### 1.7 能力缺口 Action 合同（Layer 8 必守，禁止写成「已合法」）

开放列表没有创建隔离 / 禁用账号等写接口。这是 **厂商面缺口**，不是内核该删工具。下列是对照仓库后的唯一合法接法。

**今日仓库（未改前，禁止当合同）：**

| 机制 | 实际行为 |
|------|----------|
| `Action.execution_owner` 类型 | `ExecutionOwner \| None` |
| `_enforce_owner_and_phase` | RESPONSE/ROLLBACK 在 `owner is None` 时 **ValueError**（README §19：必须且只能选一个） |
| 实体 `writeback_fields` | `required=true, applicable=false, readiness=NOT_REQUIRED` |
| `_enforce_writeback_consistency` | `applicable=false` 时 readiness **只能** `NOT_REQUIRED` |
| `approval_engine` | `writeback_readiness in {CAPABILITY_UNSUPPORTED, NOT_CONFIGURED}` → **AUTO_REJECT** |
| `ActionExecutionService.execute_action` | 缺失 owner → `ValidationError` → **FAIL** |
| ISSUE-302 `EXECUTION_JOB_ONLY` | 无成功 Job → **`IN_FLIGHT_JOB`**，CLOSED 永久堵住 |
| `ActionStatus` | 无 `skipped` / `blocked` |

**Layer 8 必须同时改的窄例外（缺一条本层失败）：**

1. **校验器 + README §19：** RESPONSE/ROLLBACK **仅当** overlay 已清空该工具两个 owner 时允许 `execution_owner=None`。**禁止**加 `ExecutionOwner.manual`。单测：普通 response 仍必须有 owner；能力缺口 isolate 可以 persist。
2. **实体 `writeback_fields` 保持今日语义。** `owner is None` 时仍返回 `(True, False, NOT_REQUIRED, None)`。签名可改为 `ExecutionOwner \| None`，但 **禁止** 此时填 `CAPABILITY_UNSUPPORTED`。事件终态写回仍走 deferred `update_source_event_disposition`（`resolve_execution_owner` 对该虚工具仍返回 `XDR_MANAGED`）。
3. **审批：** `execution_owner is None` **不得**命中 `capability_unsupported` AUTO_REJECT（那条看的是 writeback_readiness）。新规则：不自动当执行成功、**不 REJECT** 该 Action（REJECT 等于否决「需要隔离」）。事件进现有 `ExecutionSubstate.MANUAL_RESOLUTION`。
4. **AES：** `_load_claimable_actions` **排除** `execution_owner is None`（不 claim、不建 Job）。`execute_action` 若仍撞上：跳过，不 Direct Tool，不 raise-to-FAIL，不标 `SUCCESS`（并未隔离成功）。
5. **ISSUE-302：** `_action_side_effect_blocks_convergence` 对 `execution_owner is None` **不得**按 `EXECUTION_JOB_ONLY` 无 Job 返回 `IN_FLIGHT_JOB`。该 Action 不参与实体效应关单闸（或 `blocking_reason is None`）。关单仍要求 **事件** `EVENT_STATUS_UPDATE` 收敛。
6. **Action 终态：** 保持已审批/待人工（无 Job）。**禁止** `SUCCESS`（假隔离）、`FAILED`（假失败）、`REJECTED`（假否决）。不要新造 `ActionStatus`。
7. **Verify：** **live** 对该 Action 的 effect 标 **UNVERIFIABLE**（或等价 `need_manual_resolution`），**禁止** Mock 文件状态自证已隔离。terminal disposition 不得因「isolate 还在计划里」自动 `contained` 成功；走已有人工恢复后再写事件 dealStatus。`KIND=mock` 仍走 `MockVerificationRuntime`。
8. **质量门验收看 persist 后的行：** 工具名仍在；`owner is None`；`writeback_applicable is False`；`writeback_readiness is NOT_REQUIRED`；status 不是 REJECTED；live 路径零次 Mock `isolate_host` / `disable_account` 执行。

Mock 金路径 **不**走这条例外（仍双 owner + Mock 执行）。见 §1.8：本条只作用于 **live Sangfor pack**。

### 1.8 双运行时：本地全功能 vs live 诚实缺口（执行前必读）

挑战杯 OpenAPI **没有** 的东西，生产 XDR **今天**也没有。这不是要把产品砍掉。本计划的终态是：

> **不接入生产、本地验证时，功能还都在。**  
> live 接真 XDR 时，没有的接口不造 URI、不拿 Mock 给真事件盖章。  
> 生产环境以后可以改（厂商加接口，或你换/扩 Mock），**都不在本计划施工范围内。**

| 运行时 | 典型 env | 隔离 / 禁用账号 / 杀进程 | 调查 `query_*` | Verify | 本计划允许改什么 |
|--------|----------|--------------------------|----------------|--------|------------------|
| **A. 本地产品闭环** | `SOURCE_MODE=mock_xdr` `DISPOSITION_MODE=mock_xdr` `DISPOSITION_ADAPTER_KIND=mock` `TOOL_MODE=mock`（`make up-demo`） | Canonical Mock **照常执行成功** | Mock Provider **全套可用**（含 `query_account_login`、舰队式 EDR） | `MockVerificationRuntime` | **禁止削弱。** 不改 `/mock-xdr/v1` 去模仿深信服；不从 specs 删工具名 |
| **B. live Sangfor** | `SOURCE_MODE=sangfor_xdr` `DISPOSITION_MODE=live_xdr` `KIND=sangfor_xdr` `TOOL_MODE=live` | 无创建 URI → §1.7 `owner=None` + 人工；**零次** Mock 这两名 | 8b：有 URI 则 degraded，无 URI 则 unavailable | XDR_MANAGED 只读真接口；非 XDR_MANAGED **UNVERIFIABLE**，禁 Mock 运行时 | Adapter / overlay / 8b / DSS 闸门 |
| **C. 自有 Mock（可选，本计划不施工）** | 仍走 Mock 通道（`mock_xdr` / `KIND=mock` / `TOOL_MODE=mock`），替换或扩展 Mock Source / Disposition / ToolProvider | 由你的 Mock 实现保证金路径 | 同上 | 同上 | **另开 Issue。** 本计划不规定新 Mock 协议，只要求本地验证不依赖真 XDR |

**禁止混用：**

1. **禁止** `KIND=sangfor_xdr` 时留下 `DIRECT_TOOL` + `TOOL_MODE=mock`（真事件被 Mock 隔离盖章）。
2. **禁止** 为了让 live「看起来完整」去改 Canonical Mock 的路径、枚举、或删 Demo 工具。
3. **禁止** 把 Layer 3 **Vendor Wire Mock**（只回放开放列表 URI、isolate **创建** 回 404）当成产品 Demo。Wire mock 只测 Sangfor Adapter；产品金路径仍是 `/mock-xdr/v1`。
4. **禁止** overlay 应用到 `KIND=mock`。Layer 2 纯函数可以存在，**默认不得**改变 Demo。
5. **禁止** 把「生产以后加隔离 API」写进本计划的 catalog。矩阵保持 `unsupported_write`；将来另开 Issue 再改矩阵 + overlay。

**本计划不施工、本地必须仍在的产品面（不是 XDR 缺口，禁止为对齐去改）：**  
图谱 / 检索、storyline、RAG、报告、事件问答、内部 playbook、自动响应（**仍仅 mock demo**）、回滚、误报关单、`notify_security_team`。它们不依赖深信服 URI；OpenAPI 没有 ≠ 产品没有。禁止为「生产没有」去关 `SIMULATION_ENABLED`、关 Demo 自动响应、或改分析 Agent。

**厂商缺口对照（zip 补不成 live 完整；本地仍用 Mock 验）：**

| 缺口 | live（本计划） | 本地 Mock | zip / 开放列表能不能补成 live 完整 |
|------|----------------|-----------|--------------------------------------|
| 隔离 / 禁用账号 / 杀进程 **创建** | 保留 Action，§1.7，不造 URI | 照常执行 | **不能。** 129 操作无这些写接口 |
| 隔离 Verify（`isolateStatus`） | list 可打，无枚举则不得 CONFIRMED | Mock 文件状态 | **不能。** 无枚举/无示例；真机/UI 另开 |
| 账号登录 / 舰队 EDR 进程搜索 | 8b unavailable / degraded | Mock `query_*` 全开 | **不能。** `entities/*` 只是事件快照 |
| DSP 处置码表 | Layer 9 只 raw，禁止自动写回 | 不走 DSP 也能闭环 | **不能。** PDF 无文本层；样例只有 `dealStatus:0` |
| 封禁设备 / 工单责任人 / 模板 ID | 空配置则 **不调用** 创建；L10 可拉 `blockdevice/list` | Mock 不依赖现场 AF | list **接口有**，现场值 **zip 没有** |
| 工单是否办结 | Job SUCCESS = **已创建**（有 `orderId`），**不是** 结案 | Mock 工单语义不变 | 创建 `orderId`（int）对不上 list `workflowId`（UUID），list 回查标 UNVERIFIED |

每一层验收必须 **先绿 A（Mock 金路径不减，含附录 A 真实 LLM 三场景 CLOSED）**，再绿 B（live 诚实，该层有 live 合同才测）。只绿 B、A 变红 = 本层失败。MockLLM / 模板回退 / 缺 `EVAL_REQUIRE_CLOSED` 的 compat 剖面 **不算** A 绿。

### 1.9 live 运营补救（只用 live 时怎么补，不造假 URI）

若现场 **只跑 live**（`sangfor_xdr` + `live_xdr`），Mock 金路径保不住隔离自动执行——那是 Demo 的事。live 的补救分三档：**本计划内就能用的真接口**、**本计划内的人工闭环**、**必须另开 Issue**。禁止用 Mock 工具补 live。

**本计划内 live 已经能自动做的（不是「全弱」）：**

| 能力 | 条件 | 本计划层 |
|------|------|----------|
| 拉事件 / 写事件 `dealStatus` | 时间窗 + 库内码 readback | L4 / L5 |
| `block_ip` / `block_domain`（DNS） | `devices[]` 配齐；域名仅 network | L6a |
| 病毒扫描 | 设备标识齐 | L6b |
| 建工单 | 模板 ID + 责任人 | L6c |
| 解封 / 解隔离 / 解文件 | **已有**厂商策略 ID | L6d |
| 调查：资产列表、事件 proof/实体、分析日志 | 语义可能 degraded | L8b |

insider 类在 live 上：目的 IP 仍可自动封禁、可开扫描、可开工单、可写事件处置；**缺的是「一键隔离主机 / 禁用账号」自动落地**。

**本计划内对缺口的运营补救（人工，不是假成功）：**

1. **隔离 / 禁用账号 / 杀进程：** 计划里保留 Action → `MANUAL_RESOLUTION`。分析员在 XDR / EDR / IAM 控制台做完后，走已有人工恢复，再写事件 `dealStatus`。禁止标 `SUCCESS`。工单（L6c）把主机/账号写进 `businessData`，作为待办，**不是**隔离已生效。
2. **隔离是否生效：** L10 / 现场从 `isolate/list` 抄回真实 `isolateStatus` 取值。有枚举后再 **另开 Issue** 锁 CONFIRMED 规则。在此之前 list 只给人工看，一行 ≠ 已隔离。
3. **调查缺口：** 8b 用 proof / `entities/*` / 分析日志顶「有限证据」；`query_account_login` live 保持 unavailable（无接口）。不要把事件进程快照宣传成舰队 EDR。
4. **现场库存：** L10 拉 `blockdevice/list`；空 `devices` 则封禁不自动发。工单责任人 zip 里没有，配进 env。

**本计划不施工、live 要「自动隔离/查登录」必须另开的 Issue：**

| 后续 Issue | 前提 | 做法 | 禁止 |
|------------|------|------|------|
| 厂商补了隔离创建 / 账号处置 OpenAPI | 新 HTML / 新 URI 进 catalog | 矩阵 `unsupported_write` → `write`；overlay 恢复 `XDR_MANAGED` | 本计划不预写假 path |
| `isolateStatus` 枚举从真机坐实 | L10 或 UI 导出过真实值 | Layer 8 Verify 才允许 CONFIRMED | 猜枚举 |
| **live Direct Tool**（EDR 隔离、AD/IAM 禁用账号、杀进程） | 有 **另一份** 真实设备/身份 API，不是开放列表里没有的 XDR path | 独立 Adapter；overlay 只给该工具加回 `DIRECT_TOOL`；成功后只 `EXECUTION_RESULT_RECORD` | Mock Direct Tool；XDR 里再偷建一道 |
| 舰队登录 / 主机进程检索 | 有 EDR 检索 API 或 DSP 实时查询（不是本 zip 的扫描件码表） | 新 Query Provider | 用 `entities/*` 冒充；SOAR 剧本执行史当效应器（本计划明确不接第二套编排） |

**结论：** 只用 live 时，本计划能补的是 **封禁/扫描/工单/事件写回 + 人工隔离待办**；不能补的是 **开放列表没有的自动隔离/账号/舰队查询**。后者要等厂商接口、真机枚举、或独立 Direct Tool Issue，不能在本计划里用 Mock 假装补上。

---

## 2. 真接口 → 内核映射（冻结）

身份：`source_product=sangfor_xdr`；`source_object_id` = 文档中的 `uuId` **原样**（事件形如 `incident-…`，告警形如 `alert-…`）。  
分页：文档是 `page` + `pageSize`。Adapter 编成现有不透明 `next_cursor`，**不改** Ingester / `SourcePage` 合同。

**cursor 编码（Layer 4 必实现，禁止 ad-hoc）：**  
不透明 cursor 建议固定前缀 + 可解析 payload（Base64 JSON 或等价），至少包含：

- `kind`（如 `incidents`）
- `page`（下一页页码，从 2 起）
- `page_size`
- `window_start` / `window_end`（Unix 秒，与当次 poll 时间窗一致）
- `time_field`（如 `endTime`）

Resume 时必须 **原样带回时间窗**，禁止翻页时丢窗口导致漏数或重复。`has_more` **禁止**对所有列表套同一公式，见 §2.1.2。

路径参数：开放列表写成 `/incidents/:uuid/proof`，restful 名是 `uuId`。HTTP 实际是 `/api/xdr/v1/incidents/{uuId}/proof`。`virusscantask/:taskId` 即使 restfulParam 为空，HTTP 仍是 `/api/xdr/v1/responses/virusscantask/{taskId}`。

### 2.0 内核 Disposition 管线（Layer 5–6 必守，禁止旁路）

ShadowTrace 已有 outbox 管线：`DispositionCommandFactory` → `DispositionSyncService` → `DispositionAdapter`。  
**所有** `ExecutionOwner=XDR_MANAGED` 的外部效应（含实体封禁、扫描、工单）都经此管线，**不得**：

- 在 `ToolProvider` 里直接 POST blockiprule / virusscantask / orders；
- 在 Agent / ResponseAgent 里按 `sangfor` 分支调 HTTP；
- Direct Tool 成功后再偷偷补一道 XDR 实体创建（违反单效应器）。

| 内核 / Action | `DispositionIntentKind` | `operation_code` | XDR REST（Sangfor adapter 内） |
|---------------|-------------------------|------------------|--------------------------------|
| deferred `update_source_event_disposition` | `EVENT_STATUS_UPDATE` | `set_event_disposition` | `POST …/incidents/dealstatus` |
| `block_ip`（XDR_MANAGED） | `ENTITY_ACTION_SUBMIT` | `submit_entity_action` | `POST …/blockiprule/network` **或** `/endpoint`（仅 IP；§2.3.0） |
| `block_domain`（XDR_MANAGED） | `ENTITY_ACTION_SUBMIT` | `submit_entity_action` | **仅** `POST …/blockiprule/network` + `blockIpRule.type=DNS`。**禁止** `/endpoint` |
| `scan_host_for_virus` | `ENTITY_ACTION_SUBMIT` | `submit_entity_action` | `POST …/virusscantask` + readback `GET …/:taskId` |
| `create_ticket` | `ENTITY_ACTION_SUBMIT` | `submit_entity_action` | `POST …/orders`（创建认 `code=Success` + `data.orderId`）。list 是 **POST** `/orders/list`，item 键是 `workflowId`，**没有** `orderId` |
| Direct Tool 成功后同步 | `EXECUTION_RESULT_RECORD` | `record_execution_result` | **无** XDR 实体创建；仅白名单最小摘要 |
| 补偿解封 / 解隔离 / 解文件 | `record_compensation` 或等价 | 按现有 factory | `unblock` / `unisolate` / `disposefilerule` |

**并发与幂等：** XDR 写入请求体 **不含** `concurrency_token` / etag。Sangfor `DispositionAdapter` 必须：

- `supports_concurrency_token=False`（与现有 `http_adapter` 一致）；
- 依赖本地 `idempotency_key` + outbox 去重 + §2.2 readback 规则判 CONFIRMED；
- **禁止**照搬 Mock 的 CAS 失败语义到 Sangfor path。

Verify 观测（`check_ip_block_status` 等）走 **只读** catalog 接口（list/detail/isolate/list），在 adapter 或只读 client 内实现，**不**创建新的 Disposition outbox。观测成功 **不等于** Job 终态。

**实体 Job / ISSUE-311（Layer 5–6 必接，禁止另写 Verify HTTP 管线）：**

仓库已有：`BaseDispositionAdapter.read_entity_effect_completion` → DSS `_maybe_complete_entity_effect` → 映射 `ActionExecutionJob` 终态；Verify 会看 Job 是否终态。今日闸门 `_mock_entity_effect_readback_enabled` **只认 mock_xdr**。Sangfor live 若不打通这条，会再次卡在 verifying（与当初 Mock 缺 observation 同类）。

Layer 6 必须：

- Sangfor `DispositionAdapter` 实现 `read_entity_effect_completion`（封禁用 list/detail 的 `status` 字面量；扫描用 `GET …/virusscantask/:taskId` 的任务状态，映射进现有 `EntityEffectCompletion` / Job 终态）；
- DSS 闸门改为：`adapter.capabilities().supports_entity_effect_readback is True` 即调用（live_xdr + sangfor 也走）。Mock 专有的「先 finish async provider job 再读」仍留在 Mock adapter 内；
- **禁止**在 VerifyAgent / ToolProvider 再写一套「轮询 virusscantask 直到完成」当 Job 完成器。`execute_verification_tool` 只做观测，不替代 DSS。

### 2.1 只读（Source）

| 内核 | 真接口 | 调用要点 |
|------|--------|----------|
| `SourceIncident` 列表 | `POST /api/xdr/v1/incidents/list` | 至少带 `startTimestamp`、`endTimestamp`、`timeField`、`page`、`pageSize`（`pageSize` 文档 **5–200**）。筛选字段多为可空，**不要**把文档示例数组当必填。`has_more` 用 `total`（§2.1.2） |
| 事件处置查询（readback） | `POST /api/xdr/v1/incidents/dealstatus/list` | 请求字段是 **`ids`**（不是 `uuIds`）。返回 `data.item[].uuId` + **库内** `dealStatus` 1–6，见 §2.2。无分页 `total`，按 ids 查 |
| 事件举证 | `GET /api/xdr/v1/incidents/:uuid/proof` | 路径参数名 **`uuId`**。失败记 data_quality，不让整个 poll 崩 |
| 事件实体 | `GET /api/xdr/v1/incidents/:uuid/entities/{dns,innerip,ip,host,file,process}` | 路径参数名 **`uuId`**。无 `/entities/account` |
| `SourceAlert` 列表 | `POST /api/xdr/v1/alerts/list` | 可用 `uuIds` 精确拉。处置筛选用 **`alertDealStatus`**（1/2/3），**不是** `dealStatus`。响应 item 同样是 **`alertDealStatus`**。告警 `severity` 是 **0–100 分数**，不是事件的 -1/1–4 |
| 告警举证 | `GET /api/xdr/v1/alerts/:uuid/proof` | 路径参数 `uuId`。导出示例值误写成 `incident-…`，实现仍用 **告警** `uuId` |
| `SourceLog` | `POST /api/xdr/v1/analysislog/networksecurity/list`；按 ID 批量：`POST /api/xdr/v1/securitylog/list` | 分析日志最多翻到约 10 万页后要改时间窗。**`analysislog` list 响应没有 `total`**；伴随 **`POST …/analysislog/networksecurity/count`** 有 `data.total`（§2.1.2）。`securitylog/list` **有** `uuIds`；仅当 **uuIds 与时间都省略** 时默认「当前前 10 分钟」 |
| `SourceAsset` | `POST /api/xdr/v1/assets/list` | `page`/`pageSize`；不要与 `DELETE/PUT /assets/list` 搞混。该接口 `code` 示例值是 `InvalidParameter`，夹具要覆盖「HTTP 200 但业务失败」 |
| 封禁设备（配置补全） | `POST /api/xdr/v1/device/blockdevice/list` | 请求 `type[]`：`AF` / `EDR` / `EDR LITE` / `SAAS EDR` / `SAAS EDR LITE`。响应字段是 **`deviceId`/`deviceName`/`deviceType`/`gatewayId`**，创建封禁前必须改名为 `devices[].devId`/`devName`/`devType`（§2.3.1） |
| 隔离策略查询（观测 / 补偿前置） | `POST /api/xdr/v1/responses/host/isolate/list` | 可按 `hostIp` 查；**不能创建隔离**。`isolateStatus` **无枚举**（§2.5） |
| 封禁策略查询 | `POST /api/xdr/v1/responses/blockiprule/list` 与 `/detail` | readback 用；`detail` 请求 `ids`。`list` 的 `pageSize` 枚举 **10/20/50/100**，不要发事件列表的 5 |

#### 2.1.2 分页 / `has_more`（按接口，禁止一套公式）

| 接口 | `data` 形状 | `has_more` | `pageSize` |
|------|-------------|------------|------------|
| `incidents/list`、`alerts/list`、`assets/list`、`isolate/list`、`blockiprule/list`、`securitylog/list` | 有 `total` + `item[]` | `page * pageSize < total`（page 从 1 计） | 见各接口；**不要**混用 |
| `analysislog/networksecurity/count` | **只有** `data.total` | 不分页；给 list 提供 total | 与 list 同筛选条件 |
| `analysislog/networksecurity/list` | **只有** `page` / `pageSize` / `item`，**无 `total`** | **优先**同条件调 count；count 失败或缺省时 **回退** `len(item)==pageSize` 则可能还有下一页，`len(item) < pageSize` 或空页则停。禁止给 list 夹具捏 `total`。同一条件最多约 10 万页后必须改时间窗 | 默认示例 5 |
| `incidents/dealstatus/list`、`blockiprule/detail` | 按 id 列表回查 | 不分页 | — |

cursor 的 `page_size` 必须是 **该 kind 合法值**。事件 cursor 的 5 不得拿去打 `blockiprule/list`。

**不要用** `POST /api/xdr/v1/bigscreen/branchs/incidents/list` 当 Source：那是大屏按资产组拉事件，字段是 `branchId`/`incidentSeverity`，不是主合同。

`GET /api/xdr/v1/incidents/gpt/isenabled`、`POST /api/xdr/v1/incident/labelInfo`（注意 **单数** `incident`）：真接口，本计划 **out**。后者是 AI 学习中心打标外发，不是事件列表。

生产 poll 建议可配置排除 `incidentSources` 含 `demo` 的样例事件。

**eolinker `paramNotNull` 与现场必填：** 导出里 `incidents/list` 的 `startTimestamp` 等常标 `1`（可空），但 Layer 10 与生产 poll **仍必须带时间窗**——以 first-contact 与 wire mock 行为为准，不以 eolinker 可空标记代替运行时策略。

#### 2.1.1 `SourceIncident` → Ingester / `SecurityEvent`（Layer 4 最小映射）

Adapter 输出 `SourceIncident` + `SourceReference`；Ingester 再建内部事件。P0 incident 列表至少映射：

| XDR 字段（`incidents/list` item） | 内部去向 | 规则 |
|-----------------------------------|----------|------|
| `uuId` | `source_object_id` / `SourceReference.source_object_id` | 原样，勿改大小写 |
| `name` | `SourceIncident.title` 候选 → Ingester `SecurityEvent.title` | 截断 + 脱敏。**禁止**给 `SourceIncident` 加字段 |
| `description` | `normalized["description"]`（Ingester 已读该键写入内部事件描述）和/或 `raw_payload` | **没有** `SourceIncident.description`（`extra=forbid`）。不进写回 |
| `incidentSeverity` | `SourceIncident.level` + Ingester `Severity` | 见下方；**禁止**发明第五档 `information` |
| `dealStatus` | `SourceDisposition` | **入站 A（TMG）**；`source_status_raw` 保留原整数 |
| `startTime` / `endTime` | `occurred_at` / `updated_at` 候选 | ISO 或 epoch，统一 UTC |
| `hostIp` | 实体候选 / evidence 种子 | 可多值时进 raw |
| `hostAssetId` | 资产关联候选 | 可选拉 `assets/list` |
| `alertIds` | 关联告警 ID 列表 | 仅 ID，不自动拉告警正文 |
| `threatDefineName` / `incidentThreatClass` / `incidentThreatType` | `event_type` **启发式** 候选 | 映射不到 → `other` + raw；**禁止**硬编码演示人名 |
| `branchName` / `hostGroups` | 组织上下文 raw | 可进 org_context 候选，非 P0 硬依赖 |
| `gptResult` / `gptResultDescription` | **只进** `raw_payload` | **禁止** → `FinalVerdict`。**禁止**写入 `gpt_verdict_label`（必须 `None`）。数字 0/10/…/180 不是内部 `EventType` |
| 未识别字段 | `raw_payload`（脱敏限长） | — |

`creation_source_ref` / `disposition_source_ref`：用 `source_product=sangfor_xdr` + connector 配置 + `uuId` 构造 `SourceObjectLocator`；**无** Mock 式 concurrency token 时 token 字段留空，Ingester 不得因此拒绝摄入。

**`incidentSeverity` → 内核 `Severity`（四档，不得扩枚举）：**

| `incidentSeverity` | 文档含义 | `SourceIncident.level`（可空字符串，仅 Adapter） | Ingester `Severity` |
|--------------------|----------|--------------------------------------------------|---------------------|
| `-1` 或 `0` | 信息 | `"information"` 写入 level/raw | **`low`**（内核无 information 档） |
| `1` | 低危 | `"low"` | `low` |
| `2` | 中危 | `"medium"` | `medium` |
| `3` | 高危 | `"high"` | `high` |
| `4` | 严重 | `"critical"` | `critical` |
| 其他 | — | 原值进 raw | `low` + data_quality 记未知 |

筛选请求 `severities` 用 **0–4**（信息是 `0`）。响应信息级是 **-1**。不要把 -1 当 unknown。

告警列表的 `severity` 是分数区间（`(0,10]` 信息 … `(70,100]` 严重），**禁止**套本表。Layer 4b 映射告警时：分数 → 最近的四档，原分进 raw。

### 2.2 事件处置状态（EVENT_STATUS_UPDATE）——两套码

真写入：`POST /api/xdr/v1/incidents/dealstatus`  
字段：`uuIds`（数组）、`dealStatus`（**JSON 整数**，示例 `10`）、`dealComment`。  
筛选 `incidents/list` 的 `dealStatus` 示例是 **字符串数组** `["0","10","60"]`。Adapter 必须按接口分类型，禁止用同一 JSON 值同时打写入和筛选。

**`dealComment`：** eolinker 标为可空（`paramNotNull=1`），允许省略或空字符串；若出站，必须走写回白名单（短固定码或运维配置模板，如 `shadowtrace:closed`），**禁止**报告/Prompt/研判正文/`decision_trace`。

真 readback：`POST /api/xdr/v1/incidents/dealstatus/list`  
字段：`ids`（事件 ID 列表）。

开放列表在 `incidents/list` 的 `apiNote` 写明 **TMG 码 ↔ 数据库码**。写入接口用 TMG 码；`dealstatus/list` 返回库内码。**对同一内部状态，写出的数字和读回的数字不同。** 旧稿用 70 去对 readback，永远对不上。

#### 出站（Adapter → XDR 写入）

| 内部 `SourceDisposition` | 写入 `dealStatus` | 文档含义 |
|-------------------------|-------------------|----------|
| `pending` | `0` | 待处置 |
| `processing` | `10` | 处置中 |
| `completed` | `40` | 已处置 |
| `suspended` | `50` | 已挂起 |
| `ignored` | `60` | 接受风险 |
| `contained` | `70` | 已遏制 |
| `unknown` | **不发 HTTP** | — |

写入枚举 **没有** 20、30。禁止把已防护/已通告当写出值。

**内核终态 → 出站码（Layer 5 冻结，禁止猜）：** `contained` → **70**（readback 必须见库内 **6**）。`completed` → **40**。`processing` → **10**。分析结论为误报 / `ignored` **不得**自动写出 **60**（接受风险是运营动作，不是 FP 默认写回；与仓库「分析永不擅自改源」一致）。`unknown` 不发 HTTP。本表只约束 Sangfor Adapter；Canonical Mock 仍用自己的 disposition 枚举，不改 `/mock-xdr/v1`。

#### 入站 A：`incidents/list` 的 `item.dealStatus`（TMG 码，含只读多余值）

列表 **响应** 枚举是 `0/10/30/40/50/60/70`（有 30 已防护，**没有 20**）。列表 **筛选** 请求枚举是 `0/10/40/50/60/70`（没有 20、没有 30）。

转换表（`apiNote`）关键句：库内「已遏制(6)」在列表上显示为 **已防护(30)**，不是 70。因此写入 70 之后，`incidents/list` 很可能读到 **30**。这再次证明写回证实只能用 `dealstatus/list` 的库内码。

`20` 只出现在转换表的 **写入侧**（已通告 → 库内 3）。入站 A 若见到 20 可映射 `completed`，但 **不要** 当成列表必现值，也不要写入 20。

| 列表 `dealStatus` | 文档含义 | 内部 `SourceDisposition` |
|-------------------|----------|--------------------------|
| `0` | 待处置 | `pending` |
| `10` | 处置中 | `processing` |
| `20` | 已通告（转换表写入侧；列表响应未列） | `completed`（`source_status_raw` 保留 `20`） |
| `30` | 已防护（库内 6 的列表形态） | `contained` |
| `40` | 已处置 | `completed` |
| `50` | 已挂起 | `suspended` |
| `60` | 接受风险 | `ignored` |
| `70` | 已遏制（列表可能不回显，回显更常见 30） | `contained` |
| 其他 | — | `unknown` + raw |

#### 入站 B：`dealstatus/list` 的 `item.dealStatus`（库内码，readback 用这张）

| 查询 `dealStatus` | 文档含义 | 内部 | 对应刚写入的 TMG 码 |
|-------------------|----------|------|---------------------|
| `1` | 待处置 | `pending` | `0` |
| `2` | 处置中 | `processing` | `10` |
| `3` | 处置完成 | `completed` | `40`（转换表还把写入 20 收到这里） |
| `4` | 挂起 | `suspended` | `50` |
| `5` | 已忽略 | `ignored` | `60` |
| `6` | 已遏制 | `contained` | `70`（及只读 30） |
| 其他 | — | `unknown` | — |

**CONFIRMED 规则：**

1. 写入响应 `code == "Success"`（字符串）。  
2. 写入 `data.succeededNum` 必须等于 `data.total`（允许在只写 1 条时两者都为 1）。部分成功 → 最多 `ACCEPTED`，按失败 ID 重试策略走 outbox，**禁止**整单 CONFIRMED。  
3. 再调 `dealstatus/list`，用 **入站 B** 看到目标内部状态（例如写入 70 后读到 **6**）。  
4. submit 成功但尚未读到目标库内码 → 最多 `ACCEPTED`。断连不得盲重放；无厂商幂等键，本地 outbox 幂等；readback 已是目标库内码视为成功。

`incidents/list` 上的 `dealStatus` **不能**代替 `dealstatus/list` 做写回证实（码制不同，列表还有 30 等只读值）。

#### 严重级别（事件）

| 方向 | 「信息」 | 低危 | 中危 | 高危 | 严重 |
|------|----------|------|------|------|------|
| 请求筛选 `severities` | **`0`** | 1 | 2 | 3 | 4 |
| 响应 `incidentSeverity` | **`-1`** | 1 | 2 | 3 | 4 |

内核归一化见 §2.1.1：0 与 -1 → `Severity.low` + level/raw 保留 information，**不要**把 -1 当 unknown，**不要**给 `Severity` 加第五档。

#### 告警处置（另一套，禁止与事件混用）

真写入：`POST /api/xdr/v1/alerts/dealstatus`  
`uuIds` + `dealStatus`（整数 `1` 待处置 / `2` 处置中 / `3` 处置完成）+ `dealComment`。

`POST /api/xdr/v1/alerts/dealstatus/list` 的 **请求体在导出里为空**，不能假装已经有过滤字段。该接口响应 item 虽有 `dealStatus` 1/2/3，但无过滤则无法按事件 ID 查证。

告警 readback **必须**用 `POST /api/xdr/v1/alerts/list` + `uuIds`，读 **`item.alertDealStatus`**（1/2/3）。  
**禁止**读 `item.dealStatus`（列表响应没有这个键）。筛选请求字段也是 **`alertDealStatus`**，不是 `dealStatus`。

本计划 P0 **不做告警写回**；若做，放 p2，且不得抄事件的 0/10/40… 表。

`FinalVerdict` / `gptResult` **不互相自动映射**。列表响应是单数 `gptResult`（含 0/10/20/30/40/50/60/70/110/**115**/120/…/180）；筛选请求是复数 `gptResults`（文档以 110–180 为主，**筛选枚举未列 115**）。全部进 raw。

### 2.3 实体与补偿（有则做，无则不准造）

**下发路径：** 下表「live owner」= Layer 2 overlay 之后、现有 `ResponsePolicyFilter.resolve_execution_owner` 的结果（有 `XDR_MANAGED` 则选它）。HTTP 仅能在 **`DispositionAdapter.submit`（`ENTITY_ACTION_SUBMIT`）** 或 compensation 分支触发，见 §2.0。口语「manual」**不是**枚举值。

| 内核 Action | 开放列表 | live owner（overlay 后） |
|-------------|----------|----------------|
| `block_ip` | 创建：`POST …/blockiprule/network` **或** `/endpoint`；查：`/list`、`/detail`；解：`/unblock`；再封：`/reblock` | `xdr_managed` → **`ENTITY_ACTION_SUBMIT`**。通道见 **§2.3.0**。`devices[]` 来自配置或 `blockdevice/list` **改名后**（§2.3.1）。空设备 → **不调用创建**，overlay **去掉 XDR_MANAGED 和 DIRECT_TOOL**（保留 Action，同 unsupported 人工路径） |
| `block_domain` | **仅网侧** `POST …/blockiprule/network`，`blockIpRule.type=DNS` | `xdr_managed` → **`ENTITY_ACTION_SUBMIT`**（有 **AF 类** devices 时）。**禁止**走 `/endpoint`（端侧无 DNS/URL 类型）。旧稿「无对等写接口」作废 |
| （无独立内核名，可进 parameters） | 仅网侧 `type=URL` | 默认不扩 `block_url` 工具名；若做，同样 **禁止 endpoint** |
| `scan_host_for_virus` | `POST …/virusscantask`；状态 `GET …/virusscantask/:taskId`（**restfulParam 为空仍替换路径**） | `xdr_managed` 异步 job。`source` 默认 **`GPT_MANUAL`**（这是 **XDR 枚举标签**，不是接入 FastGPT / 共创模块；禁止因此去引 FastGPT）。禁止默认 `GPT_AUTO`。设备标识见 §2.3.2。CONFIRMED 见任务状态表 |
| `create_ticket` | `POST /api/xdr/v1/orders`；列表 **仅** `POST /api/xdr/v1/orders/list` | `xdr_managed`。`processTemplateId` **仅配置**（示例 `incidentBulletin`）。`nextAssigneeIds` 在导出里 **`paramNotNull=0`（必填）**：缺模板或缺责任人 → **不调用**。`businessData.type` 枚举名 `ALERT`/`INCIDENT`/`VULNERABILITY`/`REVIEWASSET`；示例值有小写 `incident`，夹具覆盖大小写。创建响应 `data.orderId` 为整数（示例 `212`）。list item **只有** `workflowId`（UUID 示例），**没有** `orderId` 字段。Job 完成定义见 Layer 6c，**禁止**用 list 对 `orderId` 假装已证实 |
| `isolate_host` **创建** | **无写接口**（只有 `isolate/list`、`unisolate`） | **不得** XDR 创建，也 **不得** 留 `DIRECT_TOOL` 给 Mock。Action 保留；overlay **两个 owner 都去掉**；物化 `execution_owner=None`（§1.7 放宽校验器），实体写回 **保持** `applicable=false` / `NOT_REQUIRED`，**禁止** `continue`，**禁止**套 `CAPABILITY_UNSUPPORTED`。`isolate/list` 只作观测，**不得**因「查到一行」CONFIRMED（§2.5） |
| `isolate_host` 解除 | `POST …/host/unisolate` | 仅补偿：请求 `ids` = **隔离策略 ID**（list 的 `item.id`），不是 hostname。`ids` 类型按数组发（导出示例有时写成单字符串，实现仍发 JSON 数组） |
| `quarantine_file` 创建 | **无** | 保留 Action，不造 URI；overlay **两个 owner 都去掉**（§1.7） |
| 解除文件处置 | `POST …/disposefilerule`（`ids`） | 补偿；`code` 可为 `Part Success`（§2.3.3） |
| 信任文件移除 | `POST …/trustfilerule` | 本计划默认不做 |
| `disable_account`、`force_logout`、`reset_password`、`revoke_token`、`block_process` | **无对等写接口** | 保留 Action；overlay **两个 owner 都去掉**（同 isolate，§1.7） |
| 白名单 `/whitelists*` | 真接口 | 默认不做 |
| 大屏 / 脆弱性 / 资产写入 / vpc | 真接口 | 不实现 |

封禁 **readback 状态字面量**（`blockiprule/list` 的 `item.status`，含空格，原样比较）：

| `status` | 含义 | 内部写回 |
|----------|------|----------|
| `block success` | 已封禁 | 目标为封禁时 CONFIRMED |
| `block ip in deal` | 封禁中 | `ACCEPTED`，继续 poll |
| `part block success` | 部分封禁成功 | 按产品政策：默认不可整单 CONFIRMED |
| `block failed` | 封禁失败 | 失败 |
| `unblocked` | 已解封 | 目标为解封时 CONFIRMED |
| `unblock ip in deal` | 解封中 | `ACCEPTED` |
| `part unblock success` | 部分解封成功 | 同部分成功政策 |

创建封禁成功响应：`data.ids` = 规则 ID 列表。后续 `/detail` 或 `/list` 用这些 ID。

unblock / reblock / disposefilerule 的 `code` 枚举含 **`Success` / `Part Success` / `Failed`**（含空格的 `Part Success`）。`Part Success` 不得整单 CONFIRMED，按 `successIds`/`failIds` 记 PARTIAL，走 outbox 策略。

#### 2.3.0 封禁通道锁（Layer 6a 冻结，禁止一套 CHANNEL 打所有工具）

| 内核 | 允许的创建 URI | 禁止 |
|------|----------------|------|
| `block_ip` | `network`（`blockIpRule.type=SRC_IP` 或 `DST_IP`）**或** `endpoint`（`plugIpList` + `direction`） | 把 DNS/URL 塞进 endpoint |
| `block_domain` | **仅** `network` + `type=DNS` | `SANGFOR_BLOCK_CHANNEL=endpoint` 套到域名 |
| URL 拦截（若做） | **仅** `network` + `type=URL` | endpoint |

`SANGFOR_BLOCK_CHANNEL=network|endpoint` **只作用于 `block_ip`**。能力矩阵必须分列：`block_ip_network`、`block_ip_endpoint`、`block_domain_network`。

**`direction` 两套码，禁止混用：**

| 位置 | 字段 | 值 |
|------|------|-----|
| 创建 `/endpoint` 请求 | `direction` | 字符串 `SRC_IP` / `DST_IP` / `SRC_DST_IP` |
| list/detail 响应 | `direction` | 整数 `1` 入站 / `2` 出站 / `3` 入出站全封锁 |

不得用查询返回的 `1/2/3` 回填创建体。

#### blockIpRule 创建字段（network vs endpoint，Layer 6a 冻结）

开放列表 **网侧** `/blockiprule/network` 与 **端侧** `/blockiprule/endpoint` 请求体 **不同**，禁止混用：

| 字段 | 网侧 `network` | 端侧 `endpoint` | Adapter 取值 |
|------|----------------|-----------------|--------------|
| `name` | 必填（示例：事件名_主机） | 同左 | 配置模板或 `{event_id}-{action_id}` 短名；禁止塞报告 |
| `reason` | 可空 | 可空 | 白名单短码；可省略 |
| `timeType` | 必填，示例 `forever` / `temporary` | 同左 | 默认 `forever`；temporary 时 `timeUnit`+`timeValue` 必填 |
| `blockIpRule.type` | 必填：`SRC_IP` / `DST_IP` / `DNS` / `URL` | **无此对象** | IP/域名/URL 由 Action `target_type` + 参数决定 |
| `blockIpRule.mode` | 必填，示例 `in` | — | 默认 `in`（文档示例值） |
| `blockIpRule.view` | 必填，**字符串数组 JSON**，如 `["1.2.3.4"]` | — | `block_ip`→IP 列表；`block_domain`→域名列表；**禁止**单字符串漏数组 |
| `devices[]` | 必填 | 必填 | **创建体**用 `devId`/`devName`/`devType`；来源若是 `blockdevice/list` 必须先改名（§2.3.1）。端侧可含 `agents[]` |
| `direction` | — | 必填，字符串 `SRC_IP`/`DST_IP`/`SRC_DST_IP` | 仅创建 endpoint；与 Action 方向一致 |
| `plugIpList` / `plugPort` | — | 端侧封禁目标（IP 列表 / 端口） | 仅 `block_ip`；**不是**域名 |

`block_ip` 选 network 还是 endpoint：仅 `SANGFOR_BLOCK_CHANNEL` 或 Action 元数据。`block_domain` **忽略**该配置，永远 network。

#### 2.3.1 `blockdevice/list` → 创建 `devices[]`（改名表）

| list 响应 | 创建封禁 / 扫描请求 | 备注 |
|-----------|---------------------|------|
| `deviceId` | `devId` | 类型在 list 为整数示例 |
| `deviceName` | `devName` | — |
| `deviceType` | `devType` | `AF`/`EDR`/… |
| `deviceVersion` | `devVersion` | 可空 |
| `gatewayId` | 扫描优先 `gatewayId`；封禁创建体无此字段 | 文档：扫描 `devId` 与 `gatewayId` 有一个即可，最好 `gatewayId` |
| `deviceStatus` | 不发送 | `offline` / `not_active` 的设备默认不纳入自动 `devices[]` |

禁止把 list 响应整包当创建 body。

#### 2.3.2 病毒扫描 CONFIRMED（Layer 6b 冻结）

`GET /api/xdr/v1/responses/virusscantask/:taskId` 任务级 `data.status`（原样比较）：

| `status` | 含义 | 写回 |
|----------|------|------|
| `taskInit` / `underDistribution` / `distributed` | 任务未完成 | `ACCEPTED` |
| `completed` | 任务完成 | 仅当 **没有** `partialCompleted`，且无主机 `scanFailed`/`sendingFailed` → 可 CONFIRMED |
| `partialCompleted` / `partialDistribution` | 部分 | 不得整单 CONFIRMED |
| `distributionFailed` / `timeout` / `dataAnomaly` | 失败 | FAILED |

主机 `item[].scanStatus`：`sending`、`sendingFailed`、`sendingCancel`、`scanCancel`、`scanCanceled`、`scanCancelFailed`、`scanning`、`scanCompleted`、`scanFailed`。  
`scanResult` 仅扫描完成后出现：`exist` / `nonexist`——这是查杀结果，**不是**写回成功与否。

创建/查询接口的 `code` 示例在导出里是 **空串**（§1.6.11）：传输成功看 HTTP 与 `data` 字段，CONFIRMED 仍只看上表 `status`。

#### 2.3.3 补偿接口的 `Part Success`

`unblock` / `reblock` / `disposefilerule`：`code == "Part Success"`（含空格）或 `data.fail > 0` → 最多 PARTIAL，不得 CONFIRMED。事件 `dealstatus` 仍用 `succeededNum == total`，**不要**把两套成功模型抄错。

### 2.4 DSP（仅 Layer 9，第三套码）

样例 txt 已证明 DSP **不是** XDR 码：`dealStatus` 样例全为 `0`，`severity: 50`（分数，不是事件 `severities` 0–4）。

规范 PDF 本轮 **无可用文本层**（扫描件/水印）。下列码表来自旧稿摘录，实现前必须对照 PDF 人工复核，代码与测试标 **`UNVERIFIED`**：

| `dealStatus`（摘录，UNVERIFIED） | 含义 |
|----------------------------------|------|
| 0 | 待处理 |
| 20 | 处置完成 |
| 90 | 处置中 |
| 50 | 忽略 |
| 70 | 待确认 |
| 80 | 已确认 |
| 100 | 误报 |

与 XDR 事件 TMG、事件库内 1–6、告警 1/2/3 **都不同**。禁止复用 §2.2。Layer 9 未复核前只摄入 raw + `source_product=sangfor_dsp`，**不得**按上表自动写回。**本地 Mock 金路径不依赖 DSP**；不做 Layer 9 也不砍 Demo 功能。

### 2.5 隔离观测（`isolateStatus` UNVERIFIED）

开放列表：`isolate/list` 的请求/响应都有 `isolateStatus`，但 **没有枚举、没有示例值**。因此：

- 不得把「`hostIp` 命中一行」映射为已隔离 CONFIRMED / Verify 成功。
- `check_host_isolation_status` 在 Sangfor 路径上：有行 → 观测 `observed` + raw；无行 → 未隔离（对「验证隔离已生效」是 **未证实**，不是 Mock 式失败翻成成功）。
- `unisolate` 的 `ids` 仍用 list 返回的策略 `id`；没有 id 则不调用。
- 现场若从 UI/抓包得到枚举，写入 catalog notes 并加夹具后才能升级为 CONFIRMED 规则。
- **Canonical Mock 不走本条。** `KIND=mock` 的 `check_host_isolation_status` 仍用 `MockVerificationRuntime`，Demo 隔离 Verify 必须继续绿。

---

## 3. 鉴权（Layer 1 必须逐条测死）

官方：Access Key / Security Key；也可用 **联动码 `authCode`**（AES-CBC 解出 AK/SK，与 AK/SK 等价）。readme：签名结束后不能改 url/params/body/header，也不能把已签名请求拷成 curl 到别的环境。

以 `aksk_py3.py` 为准：

1. 头：`Authorization: algorithm=HMAC-SHA256, Access=…, SignedHeaders=…, Signature=…`（Python 键名 `Authorization`）。另需 `sdk-host`、`sdk-content-type`、`sign-date`（`YYYYMMDDTHHMMSSZ`）。若调用方已设 `content-type`，Demo 会把它拷到 `sdk-content-type`；**两套头都会进签名**。
2. Canonical 里的 path：取 URL path，**若不以 `/` 结尾则补一个 `/`**，再 quote。
3. Query：`params` 为 `None` 时按 **空 dict `{}`** 处理（Demo `__query_str_transform` 对 `None.items()` 会崩；测试脚本走 POST body 不一定暴露）。非空则按 key 排序后 `urlencode`，然后 **把 `%3D` 替换回 `=`**（`aksk_py3.py` 的 `__query_str_transform`）。漏 `%3D`→`=`，带 query 的请求会 401。黄金向量必须覆盖「有 query 且含 `=`」与无 query（含 `params is None` / `{}` → canonical query 空串）。
4. **Payload 哈希不是原文 SHA256：** 把 body UTF-8 字节当有符号 byte 排序，去掉空格（`0x20`），再 SHA256 大写十六进制。HTTP **实际发送的 body 仍是签名前的原文**。实现若对「已排序字节」当 body 发出，必 401 或业务校验失败。`{}` 在 Demo 里会被当成无 payload（空字符串）。
5. 签完禁止改 body；要改参数必须重签。
6. TLS：**默认校验**。Demo 里 `session.verify = False` 只是示例，禁止抄进生产默认。现场自签证书用配置项关掉，并打 health 警告。
7. Go Demo 的头键是 `authorization`（小写）。canonical 串对键名大小写敏感。黄金向量锁定 Python 头名；Go 只交叉「同一 AK/SK + 同一规范化输入 → 同一 Signature」。
8. Header 按 **key 的小写**排序，但 canonical 里输出 **原始大小写**。
9. **联动码 AES-CBC IV 为全零**（`bytearray(AES.block_size)`，16 字节 `\x00`）。黄金向量必须锁定该 IV，禁止换成随机 IV 或把 IV 写进密文前缀（Demo 密文是 hex，不含 IV）。

仓库现有 `require_separated_credentials`：Source 与 Disposition 默认不能同一密钥。现场通常 **一把联动码打全部 OpenAPI**。允许共用的唯一条件：配置显式 `shared_credential_scope_verified=true`，并在 docs/env 写明「只读与写回同一开放 API 范围」。**禁止**悄悄共用。

---

## 4. 给执行 AI 的硬规则

1. 开放列表有的字段名、枚举、状态字符串（含空格）按文档做，不要改名后发给 XDR。  
2. 开放列表没有的写路径，禁止在 **Sangfor Adapter / live**「补一个合理 URI」。隔离 **创建** 属于这一类。**Canonical Mock 继续提供隔离等完整工具，禁止据此删 Mock。**  
3. FastGPT / OpenClaw / 共创模块禁止进入实现与依赖。  
4. 禁止改 `app/agents/` 去出现 `dealStatus`、`uuId`、厂商 path。
5. 禁止改 Canonical Mock 的 `/mock-xdr/v1` 去模仿深信服。也禁止为对齐 live 缺口从 Mock / specs / Demo 计划删掉隔离、账号、杀进程、`query_*`。  
6. 一个 Action 一个效应器；Direct Tool 成功后只允许文档里的记录/终态接口，禁止再调一道不存在的 XDR 创建。
7. `ACCEPTED ≠ CONFIRMED`。CONFIRMED 必须来自文档中的 **查询** 接口，且枚举用对表（事件用库内 1–6，封禁用 `status` 字面量）。  
8. 只改本层允许的文件；每层可单独合并。
9. 写入 `code != "Success"` 或 `succeededNum != total` 不得 CONFIRMED（**仅**文档写明 `Success` 的操作；virusscantask / `orders/list` 空 `code` 见 §1.6.11）。  
10. 不要扩展通用 `HttpDispositionAdapter` 去填深信服 URL。新包：`adapters/sangfor/`。现有 `DISPOSITION_ADAPTER_KIND=http` / 测试里的 `crowdstrike` 保持独立，工厂不要写成「只有 mock 与 sangfor 两个值」。  
11. **`XDR_MANAGED` 实体动作只许进 Disposition outbox**（§2.0）；Verify 只读观测走 Sangfor 查询接口（§2.5 / Layer 8），**禁止**对 live `XDR_MANAGED` 动作再用 Mock ToolProvider 文件状态自证。`KIND=mock` 的 Demo **必须**继续走 Mock 执行与 `MockVerificationRuntime`。  
12. env 中 live Disposition 用 **`DISPOSITION_MODE=live_xdr`**，禁止写 `live`。  
13. **`block_domain` 只许 `network` + `type=DNS`。** `SANGFOR_BLOCK_CHANNEL=endpoint` 不得套到域名/URL。  
14. 告警列表读 **`alertDealStatus`**，禁止读 `item.dealStatus`。  
15. 内核 `Severity` 只有四档；信息级 → `low` + raw，禁止加 `information`。  
16. `APP_ENV=production` 时 **`TOOL_MODE=mock` 非法**（现有 `production_fail_closed`）。**本地 Demo / 不接入生产** 必须仍是 `TOOL_MODE=mock`（§1.8 运行时 A）。live 调查闭环用 `TOOL_MODE=live` + Layer 8b；L10 脚本本身不跑 ToolProvider。禁止为了过 production 栅栏去打开 live 设备乱打，也禁止用 Mock query 冒充 **真平台** 能力完整。  
17. URI 占位符以路径为准：`restfulParam` 为空仍要替换 `:taskId`。  
18. 补偿 `code == "Part Success"` 不得 CONFIRMED。  
19. `source=GPT_MANUAL` 是 XDR 枚举，**不是** FastGPT 集成许可。  
20. **禁止新建** `effector_resolver.py` / `models/effector.py`；效应器只 overlay 现有 `ToolMeta.supported_execution_owners`，解析仍走 `resolve_execution_owner`。  
21. **禁止**给 `ExecutionOwner` 加 `manual`；禁止给 `SourceIncident` 加 `description`。  
22. Sangfor `gptResult` **不得**写入 `gpt_verdict_label`（必须 `None`）。  
23. 生产 `SOURCE_MODE` 是 mock **黑名单**；不要新造 `sangfor_xdr` 正选 allowlist，也不要把 `sangfor_xdr` 放进 `_MOCK_MODE_VALUES`。  
24. Layer 7 必须用 **同一套组装函数** 覆盖 `deps.py` `_get_adapter_registry` **和** `action_execution_tasks.py` `_build_execution_service`，以及 `ActionExecutionService` 插入 `provider_name`。禁止只改 API、worker 仍空 registry / 写死 `tool_mode="mock"`。
25. Layer 8 overlay：**`ResponseAgent` 持有 overlay**，`_run` 传入 Filter；共用 `_tool_index`；`_materialize_actions` **禁止**再调 `baseline_tool_index()`；`owner is None` **禁止** `continue`。能力缺口走 **§1.7**，禁止实体 `CAPABILITY_UNSUPPORTED`。Verify 只读仍只许在 `execute_verification_tool` 注入；`KIND=sangfor_xdr` 且非 XDR_MANAGED **禁止** Mock 运行时；隔离观测不得因「查到一行」CONFIRMED。
26. Layer 11 必须同步 `docs/仓库运作说明.md`、`docs/AI_CODE_REVIEW_PROMPT.md`、`docs/tool-adapter-guide.md`，不能只改 README。README §19 必须写上 `execution_owner=None` 窄例外。
27. Layer 6 必须实现 `read_entity_effect_completion` 并 **整段替换** DSS 的 mock-only 闸门（含 `simulation_enabled` / `receipt.simulated`）；禁止另写 Verify HTTP 当 Job 完成器。6c 工单也必须有 Job 完成定义（§Layer 6）。
28. 声称「真环境调查可用」必须做 Layer 8b：query 只读打开放列表 URI；语义不对等标 degraded；未接线 → unavailable；**live 路径**禁止 Mock query 成功。Canonical Mock 的 `query_*` **必须仍成功**。Cutover 调查闭环必须 `ALLOW_LIVE_SIDE_EFFECTS=true`。
29. live 质量门认 persist 后 containment Action + `owner is None` + §1.7 人工路径；不认 Mock isolate/disable 执行成功，不认 AUTO_REJECT。验收：live 路径 **零次** Mock `isolate_host` / `disable_account` 执行。
30. Overlay 只改 `supported_execution_owners`，禁止 `executable=False` 让 Filter 丢掉 isolate。Sangfor manifest **不得**从 `allowed_operations` 删掉这些工具名。
31. 验收写符号名（`ResponsePolicyFilter._tool_index`、`ActionExecutionService` 插入 `provider_name`、`_enforce_owner_and_phase`），禁止把行号当合同。
32. `TOOL_MODE=mock` 不得作为 sangfor live Cutover「能力完整」示例。L10 脚本本身不跑 ToolProvider；跑调查闭环时 `TOOL_MODE=live` + `ALLOW_LIVE_SIDE_EFFECTS=true` + 8b 或 query unavailable。
33. **禁止**声称 `execution_owner=None` 对 RESPONSE「已经合法」。Layer 8 必须改校验器 + README；未改就 persist 会 ValueError。
34. **禁止**把实体能力缺口写成 `WritebackReadiness.CAPABILITY_UNSUPPORTED`（会 ValueError 或 AUTO_REJECT）。
35. Layer 8 必须改 `_load_claimable_actions` + ISSUE-302 收敛：`owner is None` 不得当 `EXECUTION_JOB_ONLY` 无 Job 堵 CLOSED，也不得标 `SUCCESS`/`FAILED`/`REJECTED`。
36. live `ResponseAgent` 必须传入 Sangfor `CapabilityManifest`，禁止默认 `build_mock_capability_manifest()` 把 `provider_name` 盖成 `mock_xdr`。
37. `KIND=sangfor_xdr` 的 Verify：非 `XDR_MANAGED`（含 owner `None`）必须 UNVERIFIABLE，禁止 `MockVerificationRuntime`。
38. **live 8b** 不得把事件 `entities/process|file` 宣传成舰队 EDR / 账号文件审计；live `query_account_login` 必须 unavailable。Mock 路径这两项 **保持可用**。
39. 允许改 Layer 8 合同文件：[`action.py`](../backend/app/models/action.py) `_enforce_owner_and_phase`、[`approval_engine.py`](../backend/app/services/approval_engine.py)、[`side_effect_convergence.py`](../backend/app/services/side_effect_convergence.py)、README §19。**禁止**加 `ExecutionOwner.manual` / `ActionStatus.skipped`。
40. Cutover env 调查闭环缺 `ALLOW_LIVE_SIDE_EFFECTS=true` 视为本层失败（8b live adapter 注册会被拒）。
41. **§1.8：** 每一层必须先保住 Canonical Mock 金路径（隔离/账号/杀进程/`query_*` 仍可执行）。live 诚实降级 **不得** 变成 Demo 砍功能。
42. **禁止**把 Vendor Wire Mock（isolate 创建 404）当成产品 Mock；禁止 overlay 默认应用到 `KIND=mock`。
43. 6c **禁止** `GET /orders/list`；**禁止**用 list `workflowId` 去匹配创建 `orderId` 并据此 FAIL；Job SUCCESS 只表示已创建。
44. 签名实现必须容忍 `params is None`（当 `{}`）。
45. 生产 XDR / 自有 Mock 的协议变更 **不在本计划**。本计划不预写假 URI，也不改 Mock 合同去「提前兼容」未来厂商接口。
46. **每一层**结束后必须跑附录 A「真实 LLM 全链路」：`LLM_MODE=openai_compatible` + `SOURCE_MODE=mock_xdr` + `DISPOSITION_MODE=mock_xdr` + `TOOL_MODE=mock` + `WORKER=1`；三条 `EVAL_REQUIRE_CLOSED=1` 场景全部 CLOSED；报告 `generated_by=llm`（禁止大面积模板回退）。有 `.env.live` 禁止 `make up-demo`。本项未绿禁止开下一层。禁止把本项验收切成 `sangfor_xdr` / CrowdStrike。

---

## 5. 分层（按层开 PR）

### Layer 0 — 抽出全真目录 + 闭环矩阵

**目的：** HTML → 仓库内机器可读合同；标明闭环用哪些、明确不实现哪些（仍是真接口）。

**允许改：**

- `scripts/extract_sangfor_catalog.py`
- `contracts/vendor/sangfor_xdr/catalog.json`（129 条全量，含 v2）
- `contracts/vendor/sangfor_xdr/capability_matrix.yaml`
- `scripts/check_sangfor_catalog_drift.py`
- `backend/tests/test_contracts/test_sangfor_catalog_drift.py`
- `docs/vendor-packs/README.md`（短：指向本文件 + catalog）

**抽取必须包含：** method、path、`requestInfo` 字段树、`resultInfo[].paramList` 字段树、`restfulParam`（允许空）、URI 占位符（即使 restful 为空也要从 `apiURI` 抽出 `:taskId`）、枚举/备注原文。

**矩阵每行：** `internal_name`、`method`、`path`、`in_loop`（p0/p1/p2/out）、`role`（source/query/write/compensate/unsupported_write/ignore）、`disposition_intent`（`EVENT_STATUS_UPDATE` / `ENTITY_ACTION_SUBMIT` / —）、`notes`（双套码、`ids` vs `uuIds`、`alertDealStatus`、封禁 `status`、`blockIpRule.view`、`deviceId→devId`、analysislog list **无 total** 且伴随 `/count` 有 `data.total`、isolateStatus UNVERIFIED）。

**`in_loop=p0`：** `incidents/list`、`incidents/dealstatus`、`incidents/dealstatus/list`。  
**p1：** `alerts/list`（只读；notes 写 `alertDealStatus`）、`assets/list`（GET 语义的 POST）、`analysislog/networksecurity/list`（notes：无 total）+ **`analysislog/networksecurity/count`（query；`data.total`）**、`entities/*`、`proof`、`blockiprule` 全套（**分列** network IP / endpoint IP / network DNS）、`virusscantask`（含 GET `:taskId` 路径参数）、`blockdevice/list`（notes：字段改名）、`isolate/list`（只读；isolateStatus UNVERIFIED）。  
**p2：** `orders`（`nextAssigneeIds` 必填）、`alerts/dealstatus`（写入，readback 走 `alerts/list` 的 `alertDealStatus`）、`securitylog/list`（有 uuIds）、`unisolate` / `disposefilerule` / `unblock` 补偿。  
**out：** bigscreen、vuls、资产写入/审核/vpc、whitelist、soar、trustfile、`gpt/isenabled`、`incident/labelInfo` 等。  
**isolate 创建：** 矩阵写 `unsupported_write`（文档确实没有），不是 IGNORE 假接口。账号类、杀进程、创建隔离同此 role。**这只影响 live overlay**；内核目录与 Canonical Mock **仍实现**这些工具（§1.8）。

**验收：** catalog 操作数 = 129；POST 数量与 HTML 一致（94）；drift 绿；p0 行路径与本文 §2 一致；至少抽到 `incidents/list` 响应 `data.item.uuId`、`dealstatus/list` 的 `dealStatus` 1–6、`alerts/list` 的 `alertDealStatus`、`analysislog/list` 的 data 键 **无** `total`、**`analysislog/count` 的 `data.total`**、`virusscantask/:taskId` 路径参数、`blockdevice` 的 `deviceId`。

**禁止：** 写 Adapter；改 Agent；实现 HTTP。

---

### Layer 1 — 签名与 HTTP 客户端

**目的：** 真鉴权先测死。无网络。

**允许证据：** 仅 authCodeDemo（python 为主，java/go 交叉一组向量）。

**允许改：**

- `backend/app/adapters/sangfor/signing.py`
- `backend/app/adapters/sangfor/client.py`（通用 `request()`，无业务方法）
- `backend/tests/test_adapters/test_sangfor_signing.py`
- `contracts/vendor/sangfor_xdr/signing_vectors.json`

**行为：** §3 全做；脱敏日志不打 SK/联动码/body 里的密钥；TLS 默认校验。client 只负责签 + 发 + 把 HTTP 与 `code` 分开建模。

**验收：** 黄金向量（含「body 含空格与键顺序不同、签名相同/不同」；**含 query 且 key/value 含 `=`，验证 `%3D`→`=`**；**`params is None` 与 `{}` 签名相同且 canonical query 为空**；空 body `{}` 与真正无 payload；**联动码 AES-CBC 全零 IV** 解出与 Demo 一致的 AK/SK）；篡改已签名 body 失败；path 无尾 `/` 与有尾 `/` 的签名差异与 Demo 一致。

**禁止：** `list_incidents()`；Bearer 冒充；引用 FastGPT；把 `verify=False` 当默认；AES 用随机 IV 或把 IV 拼进联动码密文。

---

### Layer 2 — 效应器 overlay（保住完整性，仍无厂商 HTTP 业务）

**目的：** **仅当** `DISPOSITION_ADAPTER_KIND=sangfor_xdr`（live pack）时，文档没有的写能力 **不得** 再被选成 `XDR_MANAGED`，但 **不删** 内核 Action、**不改** Mock 默认 owners。文档有的写能力在配置齐时仍走 `xdr_managed`（Disposition outbox）。

`KIND=mock` / 本地 Demo **不得**跑本 overlay。仓库 **已经有** 解析器：[`ResponsePolicyFilter.resolve_execution_owner`](../backend/app/agents/response_agent.py)（符号名，不要钉行号）。它优先选 `XDR_MANAGED`（若在 `ToolMeta.supported_execution_owners` 里），否则 `DIRECT_TOOL`；两个都没有则 `None`。内核实体工具（`isolate_host`、`block_ip` 等）在 [`tools/specs/response.py`](../backend/app/tools/specs/response.py) 同时广告 **两个** owner。`ExecutionOwner` **只有** `xdr_managed` | `direct_tool`。

**本层不是** 再建一套 resolver。本层是：Sangfor pack 按矩阵 **收窄** `supported_execution_owners`。

**允许改：**

- `backend/app/adapters/sangfor/capability_overlay.py`（纯函数：读 Layer 0 矩阵 + 配置是否齐全 → 返回 **副本** ToolMeta / owners；**不**发 HTTP）
- `backend/tests/test_adapters/test_sangfor_capability_overlay.py`
- 可选：给现有 [`backend/tests/test_models/test_tool_schemas.py`](../backend/tests/test_models/test_tool_schemas.py) 加「内核目录仍含下列名字」的锁，**不要**为此新建不存在的 `test_kernel_action_catalog_lock.py` 除非该文件已在本层创建且只测目录存在性

**禁止出现的路径：** `backend/app/models/effector.py`、`backend/app/services/effector_resolver.py`。若生成这些文件，本层失败。

**规则：**

- 矩阵 `write` 且配置齐全（封禁/扫描要有 devices 或等价标识）→ **保留** `XDR_MANAGED`（**Disposition outbox**，§2.0）
- 矩阵 `unsupported_write`（隔离创建、账号类、杀进程、无 URI 的文件隔离创建）→ **从该工具去掉 `XDR_MANAGED` 和 `DIRECT_TOOL`**（本轮无 live Direct Tool）。**不要**只去掉 XDR、留下 DIRECT_TOOL——live + `TOOL_MODE=mock` 会走 Mock `isolate_host` / `disable_account` 给真事件盖章
- 配置不齐的 `write`（无 devices / 无工单模板）→ 去掉 `XDR_MANAGED`；若本轮也无 live Direct Tool，同样去掉 `DIRECT_TOOL`，本轮不发创建 HTTP
- `block_domain`：仅当矩阵 network DNS + **AF 类设备** 时保留 `XDR_MANAGED`；`SANGFOR_BLOCK_CHANNEL=endpoint` **不得**给域名保留 XDR owner
- **只改** `supported_execution_owners` 副本。**不要**把 `executable` 改成 `False`（Filter 会整条丢掉，质量门变红）
- **不要**改 `resolve_execution_owner` 的优先顺序，**不要**在 `app/agents/` 出现 `sangfor` / URI
- **不要**把 `writeback_required` 改成 false；去掉 XDR owner 后 required 终态仍走事件 `EVENT_STATUS_UPDATE`；实体动作未落地不得自动 CLOSED
- 口语「manual」= 计划 **仍包含** 该 Action；Layer 8 物化 `execution_owner=None`（§1.7）；实体 `writeback_fields` **不改**；事件走 `ExecutionSubstate.MANUAL_RESOLUTION`。**禁止**加第三枚举。**禁止**靠物化 `continue` 从计划删除。**禁止**在本层改 Action 校验器（接线在 Layer 8）
- 锁死内核目录仍含：`block_ip, block_domain, isolate_host, quarantine_file, block_process, scan_host_for_virus, disable_account, force_logout, reset_password, revoke_token, create_ticket, notify_security_team, update_source_event_disposition`

**接线时机：** 本层可只交纯函数 + 单测。把 overlay 应用到 live 计划路径的调用点在 **Layer 8**（共用 `_tool_index`，见该层三件死规定）。**不要**改 `baseline_tool_index()` / `tools/specs/response.py` 的默认 owners（Mock 必须仍广告 `XDR_MANAGED`+`DIRECT_TOOL`）。Canonical Mock（`KIND=mock`）**不得**跑 overlay。

**验收：** **Canonical Mock 金路径不减**（本层未接线则天然不变；接线后 `KIND=mock` 仍不 overlay）。单测：无 isolate 写能力时 overlay 后 `isolate_host` **两个 owner 都不含** 且计划夹具仍能包含该工具名；`block_domain` 在 sangfor pack + **network 设备** 时 **仍含** `XDR_MANAGED`；`SANGFOR_BLOCK_CHANNEL=endpoint` 时 `block_domain` **不含** `XDR_MANAGED`；`ExecutionOwner` 成员数仍为 2；overlay 后 `executable` 仍为 True。

**禁止：** HTTP；按 `sangfor` 字符串写 Agent 分支；把 overlay 默认应用到 mock demo；从 `tools/specs/response.py` 删 isolate/disable。

---

### Layer 3 — Vendor Wire Mock（按真路径回放 p0/p1）

**目的：** 无真机时测 **Sangfor Adapter HTTP**。只实现矩阵 `in_loop` 的真 URI，其它返回 404。

**这不是产品 Demo。** Canonical Mock 仍是 `/mock-xdr/v1`，隔离创建等 **继续存在**。Wire mock 里 isolate **创建** 404 只证明 Adapter 不得发明 URI，**不得**据此去删 Mock 工具。

**允许改：** `backend/app/adapters/sangfor/wire_mock.py`（或 tests 内 ASGI）、`contracts/vendor/sangfor_xdr/fixtures/`、对应测试。

夹具 **请求字段**必须来自开放列表。  
夹具 **响应**按 `paramList` 搭最小合法 JSON：`code`/`message`/`data`。  
**禁止**给 `analysislog/networksecurity/list` 的夹具捏一个文档没有的 `total`。  
有 `total` 的列表才带 `item`/`total`/`page`/`pageSize`。  
`analysislog/networksecurity/count` 夹具返回 `data.total`，与 list 的 `item` 条数策略一致（count 成功时 Source 用 total 翻页）。

**必须覆盖的夹具行为：**

- 写入 70 后，`dealstatus/list` 返回 **`dealStatus: 6`** 才让 Adapter CONFIRMED；返回 70 应视为未对齐（测试断言 Adapter 不得误确认）。  
- `incidents/list` 在写入 70 后若回显，夹具可用 **`dealStatus: 30`**（已防护），证明不得用列表做 writeback 证实。  
- `dealstatus` 写 `succeededNum < total` 不得 CONFIRMED。  
- `code` 为 `InvalidParameter` 即使 HTTP 200 也是失败（assets 文档就用这个示例值）。  
- `code` 为 `Part Success` 的 unblock 不得 CONFIRMED。  
- 告警列表 item 用 **`alertDealStatus`**，不要用 `dealStatus`。  
- 不存在的 isolate **创建** path → 404。  
- 不实现 bigscreen。

**验收：** Canonical `mock_xdr` 测试不减（隔离/账号金路径仍绿）；上述夹具测试绿。

**禁止：** 在 wire mock 里编造开放列表没有的创建隔离 URI；把 wire mock 接到 `DISPOSITION_ADAPTER_KIND=mock` / Demo 默认路径。

---

### Layer 4 — SourceAdapter（只读真接口）

**目的：** 摄入调查数据。

**允许改：** `backend/app/adapters/sangfor/source.py`、归一化、测试。本层 **先做 incident list**；4b/4c 再加 alert/asset/log（每个 kind 测试齐全再合并）。

**映射：** §2.1.1 全表 + 下列技术点：

- `uuId` → `source_object_id`  
- `name` → `title`；`description` → `normalized["description"]`（**不要** `SourceIncident.description`）  
- `dealStatus` 用 **入站 A（TMG）**；见到 30 映射 `contained`  
- `incidentSeverity`：-1/0 → `level=information` 且 Ingester `Severity.low`；1–4 按 §2.1.1  
- `hostIp` / `hostAssetId` / `alertIds` 等进实体或 raw  
- `gptResult` / `gptResultDescription` **只进** `raw_payload`；`gpt_verdict_label` 保持 **`None`**；不进 `FinalVerdict`  
- 未知枚举 → `unknown` + raw；整包进 `raw_payload`（脱敏限长）
- **HTTP：** 列表用 **POST** + JSON body（不是 Mock 的 GET）
- **cursor：** §2 编码；`has_more` 按 §2.1.2；单测必须 page1→page2 往返且时间窗不变

**验收：** 夹具 → 合法 `SourceIncident`；cursor 往返；不改 Ingester 签名。client 默认填「可配置回看窗口」（`startTimestamp`/`endTimestamp`/`timeField`/`page`/`pageSize`），禁止空 body 裸调。信息级事件 `Severity` 为 `low` 且 raw 保留原 `incidentSeverity`。单测：`gpt_verdict_label is None` 且 `normalized["description"]` 有厂商描述（若 item 带了 description）。

**禁止：** DSP 当 incident；`gptResult`→`final_verdict` 或 `gpt_verdict_label`；给 `Severity` 加 `information`；给 `SourceIncident` 加字段；改 scheduler 默认（放 Layer 7）。

**Layer 4b：** entities + proof 作为 evidence 可选拉取，失败记 data_quality，不让整个 poll 崩。路径参数 `uuId`。

**Layer 4c：** `alerts/list` 读 `alertDealStatus`；`analysislog` 翻页 **优先 count 的 `data.total`**，count 失败才 `len(item)==pageSize`；`securitylog` 可带 `uuIds`。告警 `severity` 按分数映射，原分进 raw。禁止给 analysislog **list** 响应造 `total`。

**Layer 4d 不是调查 Query：** 4b 在 **摄入时**可选拉 proof/entities，失败记 data_quality。EvidenceAgent 运行时 `query_*` 仍走 ToolProvider，**不能**靠 4b 冒充调查能力。只读 Query Provider 放 **Layer 8b**（degraded / unavailable，见该层）。

---

### Layer 5 — DispositionAdapter：事件 dealStatus + readback

**目的：** `disposition_policy=required` 闭环的最小真写回。

**允许改：** `backend/app/adapters/sangfor/disposition.py`、测试。

**capabilities：** 仅 `EVENT_STATUS_UPDATE` / `set_event_disposition` = SUPPORTED；实体仍 UNSUPPORTED（Layer 6 再开）。本层 **不要**把 `supports_entity_effect_readback` 打开（没有实体 submit）。

**adapter 属性：** `supports_concurrency_token=False`（XDR 无令牌；outbox 不做 Mock 式 CAS）。

**submit：** 映射 §2.2 出站表；`dealStatus` 发 **整数**；`unknown` / 非法 disposition 不发 HTTP。`dealComment` 可省略或白名单短码。  
**confirm_readback：** `dealstatus/list` + **入站 B**（请求体字段 **`ids`**，不是 `uuIds`）。  
无厂商幂等键：本地 outbox 幂等；readback 已是目标 **库内码** 视为成功；断连不得盲重放。

**验收：** 写入 70 → list 读 6 → `contained` → CONFIRMED；list 仍为 2 或误把 70 当已确认 → 不得 CONFIRMED；分析字段不出站；Mock 金路径绿。

**禁止：** 本层实现 blockip；把 `ACCEPTED` 当 Job SUCCESS；用 `incidents/list` 的 TMG 码（含 30）充当 writeback 证实；要求 `source_concurrency_token`；另写一套 Verify HTTP 轮询当事件 Job 完成器（事件终态走 `confirm_readback`）。

---

### Layer 6 — 真实体写接口（一个 PR 一类）

**管线：** 全部经 §2.0 `ENTITY_ACTION_SUBMIT` / `record_compensation`；复用 `DispositionSyncService` outbox，**禁止** ToolProvider 直调。

**ISSUE-311 / Job 终态（本层必做，不只 list/detail 观测）：**

今日 DSS `_maybe_complete_entity_effect` 调 `read_entity_effect_completion` 之前先走 `_mock_entity_effect_readback_enabled`（`disposition_mode==mock_xdr` 且 adapter.name==`mock_xdr`）。**只实现 Sangfor list/detail `block success` 而不接这条，live Job 不会终态，Verify 会卡在 verifying。**

每个开实体写的子层必须同时：

1. Sangfor adapter：`capabilities().supports_entity_effect_readback=True`；实现 `read_entity_effect_completion`（封禁：list/detail `status` 字面量 → `EntityEffectCompletion`；扫描：`GET …/virusscantask/:taskId` 任务状态 → 同一结构）。**不得**把实体 receipt 自己提升到 `CONFIRMED`（基类注释已禁止）。
2. DSS：闸门改为认 `supports_entity_effect_readback`，**live_xdr 也调用**。必须 **整段替换** `_mock_entity_effect_readback_enabled`（今日还要求 `disposition_mode==mock_xdr`、`simulation_enabled`、`adapter.name==mock_xdr`、`receipt.simulated`）。Cutover `SIMULATION_ENABLED=false` 时仍要调用。Mock 的「先 complete async provider job 再读」留在 Mock adapter。允许改 [`disposition_sync_service.py`](../backend/app/services/disposition_sync_service.py) 的闸门函数 **仅为此条件**，禁止另写 Verify 轮询环。
3. VerifyAgent `check_*` 仍走 Layer 8 `execute_verification_tool` 做**观测**；Job SUCCESS/FAILED 只来自 DSS + effect completion。

按开放列表做，每类独立 PR：

| 子层 | 接口 | 完成定义 |
|------|------|----------|
| 6a 封禁 | IP：network **或** endpoint；域名：**仅** network + `type=DNS`；list/detail + unblock | §2.3.0 通道锁；§2.3.1 `deviceId`→`devId`；无设备 → 不创建。readback 用 `status` 字面量。`block_domain` **不得** POST `/endpoint`。单测：CHANNEL=endpoint 时域名请求零 HTTP。**Job 终态**来自 `read_entity_effect_completion`，不是 Verify 另打一遍 HTTP 当完成器 |
| 6b 病毒扫描 | POST task + GET `{taskId}`（路径替换，不依赖 restfulParam） | `source=GPT_MANUAL`（厂商枚举，非 FastGPT）；`sourceName` 配置短串。缺 gatewayId/devId/agent 则不调用。catalog 里创建/查询的 `code` 示例为 **空串**：传输成功 = HTTP 2xx 且 `data.taskId`（创建）或 `data.status`（查询）存在，**不要**强求 `"Success"`。CONFIRMED 仅任务 `status=completed` 且非 partial、无主机失败（§2.3.2）。GET `:taskId` **必须**映射进 `read_entity_effect_completion` |
| 6c 工单 | **仅 POST** `/orders` + **仅 POST** `/orders/list`（catalog `apiRequestType=0`，禁止写成 GET） | 缺 `processTemplateId` 或 `nextAssigneeIds` → 不调用。`businessData.ids` 用事件 `uuId`；`type` 夹具覆盖 `INCIDENT` 与小写示例。**Job 终态（防 ISSUE-311）：** 创建响应 `code == "Success"` 且 `data.orderId` 存在 → `read_entity_effect_completion` 可将 Job 标 **SUCCESS**，含义仅为「工单已创建」。**不要**用 list 对创建 `orderId`：list 只有 `workflowId`，开放列表 **没有** 关联键 → list 回查标 **UNVERIFIED**，不得因对不上 ID 把 Job 打 FAILED，也不得因 `orderStatus`（如「处置中」）等待结案。list 的 `code` 示例为空串，不要强求 `"Success"`。Verify **不得**等待 ticket-resolved。**禁止**只 POST 不接 Job 终态 |
| 6d 补偿 | unblock、unisolate、disposefilerule | 只补偿 **已有厂商策略 ID**；unisolate 禁止 hostname；`Part Success` 不得 CONFIRMED |

**允许改（相对旧稿加 DSS）：** `backend/app/adapters/sangfor/disposition.py`、测试、以及 DSS 闸门函数（仅 effect-readback 条件，不改 outbox 语义）。

**验收（每个子层）：** 效果以 **查询真接口** 为准；outbox 收据 + `read_entity_effect_completion` → Job 终态 + readback CONFIRMED；Layer 2 overlay 对该 tool **仍含** `XDR_MANAGED`（配置齐时）；isolate **创建** 仍无 HTTP；单测证明 **未** import ToolProvider 发 blockiprule；单测：`DISPOSITION_MODE=live_xdr` 时 DSS **会**调用 Sangfor `read_entity_effect_completion`（不再被 mock-only 闸门挡掉）。

**禁止：** 一个 PR 做完全部；账号类假路径；把 `block_domain` 再标成 unsupported_write；域名走 endpoint；在 `tools/` 或 MockToolProvider 加 sangfor 专用 **写** POST；为实体 Job 另写一套 Verify HTTP 完成器。

---

### Layer 7 — 组合层（默认仍 Mock）

现网有 **三个** 旋钮 + adapter kind，必须一起设计：

| 变量 | 现状 | sangfor 切入时 |
|------|------|----------------|
| `SOURCE_MODE` | 默认 `mock_xdr`。生产用 **`_MOCK_MODE_VALUES["source_mode"]={"mock_xdr"}` 黑名单** 拒绝 mock，**没有**正选 allowlist | **`sangfor_xdr`**。**不要**把它加进 `_MOCK_MODE_VALUES`，也 **不要**新造 production allowlist 数组 |
| `DISPOSITION_MODE` | 默认 `mock_xdr`；非 mock 测试用 **`live_xdr`** | **`live_xdr`**（**禁止**写 `live`）。工厂必须 **拒绝** 无 `_xdr` 的 `live`（未配 adapter） |
| `DISPOSITION_ADAPTER_KIND` | 默认 `mock`；代码包是 `mock_xdr` + `http`。测试字符串里出现过 `crowdstrike`，**没有** `adapters/crowdstrike/` | **`sangfor_xdr`**，与 `mock` / `http` **并存**。不要实现 crowdstrike 包，不要把工厂收成「只有 mock 与 sangfor」 |
| `TOOL_MODE` | 默认 `mock` | **禁止**把 `TOOL_MODE=mock` 当 sangfor **live**「真平台能力完整」。`APP_ENV=production` 禁止 mock；**development Demo 必须仍是 mock**（§1.8 A）。live 调查闭环：`TOOL_MODE=live` + **`ALLOW_LIVE_SIDE_EFFECTS=true`** + Layer 8b；未接线 query 标 unavailable。L10 只读脚本本身不跑 ToolProvider，可不设 live side effects。`KIND=sangfor_xdr` 时：XDR_MANAGED Verify **不**走 Mock 文件状态；非 XDR_MANAGED **也不**走 Mock。`KIND=mock` 必须走 Mock。Direct Tool 真设备适配器是后续独立 Issue；在此之前 live overlay **不得**留 DIRECT_TOOL 给 isolate/disable |

**Layer 7 必改 config（摘录）：**

- `backend/app/core/config.py`：仅 `mock_xdr` 为 mock source；`sangfor_xdr` 只要不在黑名单即非 mock。**禁止**新增 `sangfor_xdr` 正选 allowlist
- `is_mock_disposition_mode()`：仅 `mock_xdr` 为 true；`live_xdr` 为 false
- `production_fail_closed`：**不要**为 sangfor 放宽现有检查。`SOURCE_MODE=sangfor_xdr` 本来就不会命中 source mock 黑名单；`DISPOSITION_MODE=live_xdr` + `DISPOSITION_ADAPTER_KIND=sangfor_xdr` 同样不在 mock 集。**仍拒绝** `TOOL_MODE=mock`、`SIMULATION_ENABLED=true`、以及 `DISPOSITION_MODE=live`（无 `_xdr`）这种未注册组合
- `auto_response_fail_closed`：现状要求全 mock。本计划 **不**为 sangfor 打开 live auto-response 默认；保持 auto-response 仅 mock demo
- `require_separated_credentials`：**Sangfor 路径**在 `shared_credential_scope_verified=true` 时允许同一联动码；Mock 仍强制读写分离

**组装函数（本层核心，禁止复制粘贴 registry）：**

新增一处（建议 `backend/app/adapters/factory.py` 或 `deps.py` 抽出的纯函数，名字自定但必须单点）：

```text
build_disposition_adapter_registry(settings) -> DispositionAdapterRegistry
```

按 `DISPOSITION_ADAPTER_KIND` register `mock` / `http` / `sangfor_xdr`（及未来 KIND）。**所有生产入口必须调用它**，禁止再手写 `DispositionAdapterRegistry()` 后只 register 一部分。

今日生产入口（必须全部改到该函数）：

| 符号 | 今日行为 | 本层必须 |
|------|----------|----------|
| `deps.py` `_get_adapter_registry` | 只 `register("mock_xdr")` | 调组装函数 |
| `action_execution_tasks.py` `_build_execution_service` | `DispositionAdapterRegistry()` **空**；`ToolExecutor(..., auto_discover_for_mode(tool_mode="mock"))` | 调**同一**组装函数；ToolRegistry 跟 `settings.tool_mode`，**禁止** worker 写死 mock |
| `ActionExecutionService` 插入 `provider_name` | XDR job 写死 `"mock_xdr"`；Direct Tool job 写死 `"mock_tool_provider"` | 随 KIND / 实际 ToolProvider 变化。符号名验收，不要钉行号 |
| `ingestion_scheduler.py` Source 工厂 | 只建 MockXDR Source | 按 `SOURCE_MODE` 建 Sangfor Source；KIND=mock 仍 Mock |

测试可以继续本地 `DispositionAdapterRegistry()`；生产路径不行。

**允许改：**

- `backend/app/adapters/factory.py`（或等价单点组装）
- `backend/app/api/v1/deps.py`（`_get_adapter_registry()`）
- **`backend/app/tasks/action_execution_tasks.py`**（今日空 registry + 写死 mock ToolRegistry —— **必改**）
- **`backend/app/services/action_execution_service.py`**（插入 `provider_name` —— **必改**）
- `backend/app/ingestion/ingestion_scheduler.py` Source 工厂
- `backend/app/core/config.py`、`.env.example`、`infra/env/sangfor-xdr.example.env`
- health 组件 mode；鉴权失败 / 401 **不得** overall=ok

**Cutover env 示例（只读探测，非 production；L10 脚本不跑 query 工具）：**

```bash
APP_ENV=staging
SOURCE_MODE=sangfor_xdr
DISPOSITION_MODE=live_xdr
DISPOSITION_ADAPTER_KIND=sangfor_xdr
SIMULATION_ENABLED=false
ALLOW_XDR_WRITEBACK=false
BLOCK_LIVE_ACTION_EXECUTION=true
TOOL_MODE=live
ALLOW_LIVE_SIDE_EFFECTS=true
# BLOCK_LIVE_ACTION_EXECUTION 只拦 execute_plan / 写回，不拦只读 query 注册
# 缺 ALLOW_LIVE_SIDE_EFFECTS 时 8b live Query Provider 会被 configure_tool_registry 拒绝
# query 未接线 → ToolRegistry 标 unavailable，禁止回落 Mock 成功
# 禁止 TOOL_MODE=mock：overlay 若漏留 DIRECT_TOOL，会用 Mock isolate 给真事件盖章
# SANGFOR_XDR_BASE_URL=…  AUTH_CODE=… 或 AK/SK
# shared_credential_scope_verified=true  # 若读写同一联动码
```

跑 **调查闭环**（EvidenceAgent）：必须 `TOOL_MODE=live` + `ALLOW_LIVE_SIDE_EFFECTS=true`，且 Layer 8b 已接线或接受 query unavailable（证据缺口可见），**禁止** Mock query 成功。`APP_ENV=production` **禁止** `TOOL_MODE=mock`。L10 只读脚本若不跑 ToolProvider，可以不设 `ALLOW_LIVE_SIDE_EFFECTS`。

打开写回是运维动作：先 L10 只读绿，再 `ALLOW_XDR_WRITEBACK=true` 且 `BLOCK_LIVE_ACTION_EXECUTION=false`（仍受审批/能力栅栏约束）。

**本地全功能 env（不接入生产，本计划每一层必须仍绿）：**

```bash
# make up-demo / 默认开发。不要改成 sangfor live。
APP_ENV=development   # 或仓库 Demo 默认；非 production
SOURCE_MODE=mock_xdr
DISPOSITION_MODE=mock_xdr
DISPOSITION_ADAPTER_KIND=mock
TOOL_MODE=mock
SIMULATION_ENABLED=true   # 跟现网 Demo，不要为对齐 sangfor 关掉
# 不设 SANGFOR_XDR_* 。不跑 overlay。隔离/账号/query_* 全走 Canonical Mock。
# 若日后接「自己的 Mock」：仍用本通道（mock_xdr / KIND=mock），另开 Issue 换实现，不要借用 sangfor_xdr KIND。
```

**fail-closed：** production 禁止 mock/simulation；`SOURCE_MODE=sangfor_xdr` 且 `SIMULATION_ENABLED=true` 拒绝。**development Demo 必须允许 mock。**

**验收：** `make up-demo` 行为不变（仍 mock_xdr，**隔离/账号/全套 query 仍可跑通**）；工厂单测覆盖 mock / sangfor / live_xdr / 拒绝非法组合（含 **`DISPOSITION_MODE=live`** → fail-closed）；**API 与 Celery `_build_execution_service` 调同一组装函数**；worker 空 registry 测试必须失败；job 插入的 `provider_name` 随 KIND 变化，mock 路径仍为 `mock_xdr`；**production + TOOL_MODE=mock 仍失败**；**development + TOOL_MODE=mock 仍成功**。

**禁止：** 打开 live auto-response 作为代码默认；把 FastGPT 配进 LLM_MODE；只改 KIND 不改 MODE；只改 `deps.py` 不改 Celery / 不改 job `provider_name`；为过 production 栅栏而关掉 fail-closed；给生产新造 source allowlist；Cutover 示例继续写 `TOOL_MODE=mock` 当 **真平台** 能力完整；调查闭环 Cutover 漏掉 `ALLOW_LIVE_SIDE_EFFECTS=true`；为对齐 sangfor 把 Demo 默认改成 `live_xdr` 或关掉 Mock 工具。

---

### Layer 8 — overlay 接线 + 物化 + 能力缺口合同 + Verify 只读

本层必须一次写死下列事项（缺一则本层失败）。能力缺口的合法终态以 **§1.7** 为准，覆盖本层旧稿「`owner=None` 已合法 / 实体 `CAPABILITY_UNSUPPORTED`」。

1. **overlay 与物化共用同一份 ToolMeta。** `ResponseAgent` 增加可选 `tool_index`（默认仍 `baseline_tool_index()`）。`deps.py` 在 `DISPOSITION_ADAPTER_KIND=sangfor_xdr` 时把 Layer 2 overlay **副本**传给 `ResponseAgent`；**`_run` 创建 `ResponsePolicyFilter` 时必须传入该副本**。只给 Filter `__init__` 加参数、`_run` 仍 `ResponsePolicyFilter(manifest=..., entities=...)` 不传 index = **没接上**。`KIND=mock` 不传 overlay。`_materialize_actions`、`sort_candidates`、证据门 `_resolve_tool_level`、LLM available-tools、playbook/`resolve_entity_targets` 在 execute 路径一律用 `policy_filter._tool_index`。**禁止**物化再调 `baseline_tool_index()`。`build_mock_capability_manifest` 可继续用 baseline（那是 Mock）。
2. **Sangfor `CapabilityManifest` 必须传入，禁止默认 Mock manifest。** 今日 `ResponseAgent` 无参时 `provider_name="mock_xdr"`、`supports_concurrency_control=True`。live 必须传入 Sangfor manifest：`provider_name` 随 KIND（如 `sangfor_xdr`）、`supports_concurrency_control=False`、`event_disposition=SUPPORTED`（Layer 5 之后）、isolate / disable_account **仍在** `allowed_operations`（从 manifest 删名 = Filter 丢掉 = 质量门红）。overlay **只**清空 ToolMeta owners，不靠 manifest 删工具。
3. **`unsupported_write` 且无 live Direct Tool：两个 owner 都去掉，且不要 `continue`。** 按 **§1.7** persist：`execution_owner=None`（先放宽 `_enforce_owner_and_phase` + README §19）；实体 `writeback_fields` **保持** `(True, False, NOT_REQUIRED, None)`；审批 **不 AUTO_REJECT**；AES **不 claim**；ISSUE-302 **不**当无 Job 的 `EXECUTION_JOB_ONLY`；事件 `MANUAL_RESOLUTION`。仓库没有 `ActionStatus.blocked` / `skipped` / `ExecutionOwner.manual`，不要新造。
4. **live 路径零次 Mock `isolate_host` / `disable_account` 执行。** 单测或审计：`KIND=sangfor_xdr` 时 ToolProvider 不得成功执行这两名。AES Direct Tool 插入 `provider_name="mock_tool_provider"` 不得出现这两名。

若 overlay 只去掉 `XDR_MANAGED`、留下 `DIRECT_TOOL`：live + `TOOL_MODE=mock` 会走 Mock 隔离/禁用账号，等于用幻想工具给真事件盖章。若两个 owner 都去掉却 `continue`：isolate 从计划消失。若 persist `owner=None` 却不改校验器：ValueError。若实体套 `CAPABILITY_UNSUPPORTED`：ValueError 或 AUTO_REJECT。若只改 AES skip 不改收敛：CLOSED 被 `IN_FLIGHT_JOB` 卡住。

**允许改：**

- [`response_agent.py`](../backend/app/agents/response_agent.py)：Filter / Agent 的 `tool_index`；`_run` **传入** Filter；`writeback_fields` 接受 `ExecutionOwner | None` 但实体分支语义不变；`_materialize_actions` 用同一份 index 且 **删除** `owner is None: continue`。**禁止**在该文件出现 `sangfor` / URI / `dealStatus`
- [`action.py`](../backend/app/models/action.py) `_enforce_owner_and_phase`（§1.7 窄例外）及对应模型测试
- `README.md` §19（与校验器同步）
- [`approval_engine.py`](../backend/app/services/approval_engine.py)：`owner is None` 不 AUTO_REJECT
- [`side_effect_convergence.py`](../backend/app/services/side_effect_convergence.py)：`owner is None` 不进无 Job 的 `EXECUTION_JOB_ONLY` 闸
- [`action_execution_service.py`](../backend/app/services/action_execution_service.py)：`_load_claimable_actions` 排除 `owner is None`；`execute_action` 兜底 skip
- `backend/app/api/v1/deps.py`：KIND=sangfor 时传入 overlay **和** Sangfor `CapabilityManifest`
- `backend/app/adapters/sangfor/capability_manifest.py`（或 overlay 模块内纯函数）构造 Sangfor manifest
- `backend/app/tools/verify/_common.py` 的 **`execute_verification_tool`**：唯一 Verify 注入点。`KIND=sangfor_xdr` + `XDR_MANAGED` → `verify_observation.py`；`KIND=sangfor_xdr` + 非 XDR_MANAGED（含 `None`）→ UNVERIFIABLE，**禁止** `MockVerificationRuntime`。Canonical Mock 仍走 Mock 运行时。**这不是 Job 完成器**
- `backend/app/adapters/sangfor/verify_observation.py`（新建）
- quality gate / 测试：见下方「质量门」

**不要改：** `configure_tool_registry` 去决定 `supported_execution_owners`。  
**不要改：** `baseline_tool_index()` / `tools/specs/response.py` 默认双 owner。  
**不要改：** VerifyAgent 业务文件去硬编码 `/api/xdr/`。

**质量门（与 overlay 互撞时以本段为准）：**

`apply_containment_quality_gate` 仍看 **candidates**。验收 **必须另断言 persist 后的 Action 行**，否则会出现「candidates 绿、persist 缺 isolate / 被 REJECT / 关不了单」。

| 错误接法 | 结果 |
|----------|------|
| 物化 `continue` 丢掉 | 质量门 candidates 绿，persist 后计划缺 isolate |
| 留下 DIRECT_TOOL + Mock 执行成功 | 假绿：真事件被 Mock 盖章 |
| overlay `executable=False` 或从 manifest 删工具名 | Filter 丢掉，质量门红 |
| persist `owner=None` 不改校验器 | ValueError |
| 实体 `CAPABILITY_UNSUPPORTED` | ValueError 或 AUTO_REJECT |
| AES skip、收敛不改 | `IN_FLIGHT_JOB`，关不了单 |

规定：live 质量门认「**persist 后** Action 列表仍有该工具，`execution_owner is None`，`writeback_applicable=false`，`writeback_readiness=not_required`，status 不是 REJECTED，事件 `MANUAL_RESOLUTION`」。**不认** live 路径上 Mock 执行成功，**不认** 实体 `CAPABILITY_UNSUPPORTED`。**Canonical Mock 金路径质量门行为不变**：isolate 仍双 owner、仍执行、仍 Verify 成功。

**Verify 观测源：**

P0 事件终态 `EVENT_STATUS_UPDATE` 的证实走 DispositionAdapter `confirm_readback`（`dealstatus/list` 入站 B）。

Layer 6 起的 XDR_MANAGED 实体动作：Job 终态走 DSS `read_entity_effect_completion`。`check_*` 打 Sangfor 只读查询。

| 验证工具 | Sangfor 只读 | 成功规则 |
|----------|--------------|----------|
| `check_ip_block_status` | `blockiprule/list` 或 `/detail` | `status == "block success"`（含空格）；仅 XDR_MANAGED |
| `check_domain_block_status` | 同上，匹配 `type=DNS` 的规则 | 同上 |
| `check_host_isolation_status` | `isolate/list` + `hostIp` | overlay 后 owner 为 `None`：效果 **UNVERIFIABLE**，可打 list 作人工参考但 **不得** CONFIRMED / 不得 Mock 自证。`isolateStatus` **无枚举**；「查到一行」≠ 已隔离（§2.5） |
| `check_virus_scan_status` | `GET virusscantask/{taskId}` | §2.3.2（观测）；任务 Job 终态仍走 Layer 6 effect completion |
| `check_account_status` 等无写接口 | **不要**伪造 Sangfor 查询 | UNVERIFIABLE；禁止 Mock 文件状态 |

**验收：**

- **Mock golden / quality gate 不减：** isolate / disable_account / block_process / `query_account_login` 在 `KIND=mock` 下仍规划、执行、Verify。  
- sangfor pack：**persist 后** Action 仍含 `isolate_host`、`disable_account`；`execution_owner is None`；`writeback_applicable is False`；`writeback_readiness is not_required`；**不是** REJECTED；不打 XDR **创建**；**零次** Mock 这两名执行；单测 Action 模型允许该窄例外、普通 response 仍拒 None。  
- 单测：审批对该 isolate **不是** AUTO_REJECT；收敛摘要 **没有** 该 Action 的 `IN_FLIGHT_JOB`。  
- 单测：live `Action.provider_name` **不是** `mock_xdr`。  
- 单测：XDR_MANAGED `block_ip` 的 Verify **不**读 Mock 文件状态。  
- 单测：`KIND=sangfor_xdr` + owner `None` 的 `check_host_isolation_status` / `check_account_status` **不**进入 `MockVerificationRuntime`。  
- 单测：`check_host_isolation_status` 在 isolate/list 返回一行且 `isolateStatus` 任意字符串时 **不得** 把目标标为已隔离 CONFIRMED。  
- required 终态仅事件 dealstatus 时可走 deferred `EVENT_STATUS_UPDATE`；人工恢复前不得因 isolate 未执行自动 CLOSED。  
- 验收写符号：`ResponseAgent._run` 传入 `tool_index`、`_enforce_owner_and_phase`，不要写行号。

**禁止：** `if sangfor` 写进 agents；从计划删除 isolate；用 Mock check_* 给 live 盖章；把 URI 写进 VerifyAgent；只给 Filter 加参数却不在 `_run` 传入；声称 `owner=None` 已合法而不改校验器。

---

### Layer 8b — 只读 Query Provider（**仅 live Sangfor 调查**；语义不对等要标出来）

写回走 Disposition；EvidenceAgent 的 `query_*` 仍走 ToolProvider。本层 **只在** `KIND=sangfor_xdr` + `TOOL_MODE=live` 生效。`KIND=mock` **禁止**套本层映射（Mock `query_account_login` / 舰队 EDR 必须仍成功）。

没有本层会出现：

- staging：真事件 + Mock 查询（臆造证据）；或
- production：`TOOL_MODE=mock` 非法；有 live Query Provider 但缺 `ALLOW_LIVE_SIDE_EFFECTS` 则注册失败。

Layer 4b 摄入时可选拉 proof/entities **不能**代替本层。

开放列表 **没有** 与 Mock 对等的舰队级 EDR / 账号登录检索。Cutover-Ready 的 **live** 调查能力 = **文档有的只读 URI 按 degraded/unavailable 诚实接线**，不是「query_* 全部 Mock 成功」。本地验证不走本层。

**允许改：** `backend/app/adapters/sangfor/query_provider.py`（或等价只读 ToolProvider）、ToolRegistry 组装（跟 Layer 7 同一 `TOOL_MODE=live` + `ALLOW_LIVE_SIDE_EFFECTS=true` 路径）、测试。**禁止**改 EvidenceAgent 出现厂商 URI。

**映射（只读；语义列必须进 data_quality / 工具说明，禁止当完全匹配）：**

| 内核 query | 开放列表 | 语义 | 未接线 / 禁止 |
|------------|----------|------|----------------|
| `query_asset_info` | `POST …/assets/list` | 接近资产库存，可接线 | unavailable |
| `query_edr_process` | `GET …/incidents/:uuid/entities/process` | **事件实体快照**，不是按 `host_id` 的舰队 EDR 检索。接线则标 **degraded**；无事件 uuid 上下文 → unavailable | 禁止编造成主机进程搜索成功 |
| `query_file_access` | `GET …/incidents/:uuid/entities/file` | 事件文件实体，**不是** 按账号的文件访问审计（内核入参是 `account`）。接线则 degraded 或 **unavailable** | 禁止用账号字段假装审计命中 |
| `query_dns` / `query_network_flow` | `POST …/analysislog/networksecurity/list`（及 count）和/或 `securitylog/list` | 威胁/安全日志，**不是** 通用 netflow。可按 IP 降级查询并标 degraded | unavailable |
| `query_account_login` | **无** `/entities/account` | — | **必须** unavailable，禁止编造 |
| `query_threat_intel` | 无独立威胁情报 URI；可用 incident/alert **proof** 作有限只读 | degraded 或 unavailable | live 禁止 Mock 成功 |

失败 / 未接线 / 语义拒绝 → 现有 `ToolUnavailableReason`（或等价），Evidence 记 data_quality / collection failed。**live 禁止**回落 Mock 成功。`query_*` **禁止** POST 任何 responses/ 写接口。

**验收：** `TOOL_MODE=live` + `ALLOW_LIVE_SIDE_EFFECTS=true` + sangfor KIND：接线的 query 只打上表 URI；live `query_account_login` 不得 Mock 成功；`query_edr_process` 成功时证据带 degraded（或未接线 unavailable）；production 不以 `TOOL_MODE=mock` 启动。文档/health 标明「**live** 调查 ≠ Mock 金路径」。声称「query 全部可用且语义完整」而无舰队 API → 本层失败。**并行验收：** `TOOL_MODE=mock` 下 `query_account_login` / `query_edr_process` **仍成功**（功能还在）。

**禁止：** 用 Mock query 给 **live** 事件写证据；把 4b 当 8b；把事件 `entities/*` 宣传成 EDR 主机检索；为 8b 去改 Mock Provider 让本地 query 变 unavailable。

---

### Layer 9 — 可选 DSP 文件源（不是 XDR）

**仅当需要吃挑战杯 DSP 样例。** 独立 File/DSP Adapter：`uuId`、`name`、`severity` 分数进 raw；`source_product=sangfor_dsp`。

处置码表 §2.4 为 **UNVERIFIED**：未人工复核 PDF 前禁止按表自动映射 `SourceDisposition`，禁止写回。禁止与 Layer 4 混为一个 HTTP client、禁止当 `incidents/list`。

不用 FastGPT。

---

### Layer 10 — first-contact 剧本

**脚本：** `scripts/sangfor_xdr_first_contact.py`  
默认只读：签名 + `POST /api/xdr/v1/incidents/list`。必须带文档时间窗：`startTimestamp`、`endTimestamp`、`timeField`（建议 `endTime`）、`page=1`、`pageSize` 取文档允许的小值（如 5）。不要把示例里的 `uuIds`/`severities` 示例数组当必填塞满。

**建议同时只读探测（仍不写）：** `POST …/device/blockdevice/list`（空 `type` 或文档允许的类型）。用于发现现场有无 AF/EDR，**减少**空 `devices` 才 fail-closed 的惊吓。list 为空 = 站点没接设备，不是接口假；不要把空列表写成 Adapter bug。工单模板/责任人 **没有** 只读 enumeration 能从 zip 预填，缺配置就不调用 `orders`。

写回必须显式 flag + 测试用事件 `uuId`；默认探测「写回 **当前相同** dealStatus」（出站 TMG **整数**），再 `dealstatus/list`（`ids`）看库内码。产物 gitignore。L10 默认 `APP_ENV` 非 production。L10 **不是** 本地产品验证；本地验证继续 `make up-demo`。

**禁止：** 脚本对生产事件写 70；自动打开 `ALLOW_XDR_WRITEBACK`；用 DSP 样例 ID 打 XDR；因 isolate 创建 404 去改 Mock。

---

### Layer 11 — 文档与 env 同步

**目的：** 消除「仓库仍宣称无正式 API / 全是猜测」与 Adapter 实现之间的执行冲突。只改阶段声明，不改默认闭环。

**允许改：**

- `README.md`（§1 边界段）
- `docs/AI_ISSUE_EXECUTION_PROMPT.md`（当前阶段段）
- `docs/AI_CODE_REVIEW_PROMPT.md`（「厂商接口均为未验证猜测」段：改为 Adapter 以挑战杯 HTML 为权威，Agent 仍禁厂商字符串；P0 合格标准仍是 Mock 金路径）
- `docs/仓库运作说明.md`（文首「没有真实深信服 XDR」：改为默认仍 Mock；Adapter 合同已有开放列表；Cutover-Ready ≠ 真机验证）
- `docs/tool-adapter-guide.md`（「当前没有真实 XDR…正式接口文档」：Sangfor OpenAPI 是 Adapter 权威；`HttpDispositionAdapter` 仍不得填深信服 URL）
- `.env.example`、`docs/vendor-packs/README.md`

**内容：** 见 §9 表；**不**改 Agent 行为、**不**改 Mock 默认、**不**把 P0 合格标准从 Mock 金路径改成 live XDR。

**验收：** 全文检索 `DISPOSITION_MODE=live`（无 `_xdr`）在 docs 中为 0；上列三份「猜测/无正式 API」文档已改口；AI prompt 仍禁止 Agent 层厂商字符串；**仍写明** 默认闭环是 Mock，不接入生产时功能完整。

**禁止：** 声称已 production 对接；删除 Mock 金路径说明；只改 README 漏掉仓库运作说明 / code-review prompt / tool-adapter-guide；把「live 无隔离创建」写成「产品不再隔离」。

---

## 6. PR 顺序

```text
L0 catalog+矩阵（含 paramList、双套码、alertDealStatus、analysislog list 无 total + /count 有 total、deviceId 改名、virus :taskId）
 → L1 签名（Python Demo 变换，含 query %3D→=、联动码全零 IV）
 → L2 capability overlay 纯函数（禁止新建 effector_resolver；unsupported_write 去掉两个 owner；block_domain 仅 network 可保留；禁止 executable=False）
 → L3 wire mock（70 写入 vs 6 读回；列表 30 不得证实；Part Success；analysislog list 无 total、count 有 total）
 → L4 Source incident（信息级→low；description→normalized；gpt_verdict_label=None；4b entities/proof 摄入可选；4c alertDealStatus + count 翻页；4b ≠ 调查 query）
 → L5 dealstatus（出站 TMG 整数 + 入站库内码 + succeededNum）
 → L6a 封禁 IP（分通道）+ DNS 仅 network + read_entity_effect_completion + **整段替换** DSS mock-only 闸门 → 6b 扫描 GET :taskId 进 effect completion（空 code 不强制 Success）→ 6c 工单：**POST** list；Job SUCCESS = 创建有 `orderId`（非结案，不对 `workflowId`）→ 6d 补偿 Part Success
 → L7 同一套 build_disposition_adapter_registry（deps.py + action_execution_tasks.py + AES provider_name；SOURCE_MODE 黑名单不造 allowlist；**live_xdr** + KIND；拒绝 DISPOSITION_MODE=live；production 仍禁 TOOL_MODE=mock；**development Demo 仍 mock 全功能**；Cutover：`TOOL_MODE=live` + `ALLOW_LIVE_SIDE_EFFECTS=true`，禁止 mock 当真平台完整）
 → L8 overlay 经 `ResponseAgent._run` 传入 `_tool_index` 与物化共用 + Sangfor CapabilityManifest + §1.7 校验器/审批/收敛/AES + Verify：XDR_MANAGED 只读、非 XDR_MANAGED UNVERIFIABLE 禁 Mock + persist 后质量门；**KIND=mock 不 overlay**
 → L8b 只读 Query Provider（**仅 live** degraded/unavailable；禁止 live Mock query；Mock 路径 query 仍全开；调查闭环要 ALLOW_LIVE_SIDE_EFFECTS）。可与 L8 同 PR 或紧随其后
 → L10 剧本（建议加 blockdevice/list 只读）
 L9 DSP 可选并行（UNVERIFIED 码表不得自动写回），不挡 L4–L8
 →---

## 6.1 分工（按人，不要按「一人一层从头到尾」）

方案要求 **合并顺序** 仍是 §6；人可以并行起草，但 **共享内核文件同一时间只一个人改**。每一层合并前必须 Mock 金路径绿。

**角色（2～4 人）：**

| 角色 | 负责层 | 主文件 | 不碰 |
|------|--------|--------|------|
| **合同 / 客户端** | L0 → L1 → L3 | `contracts/vendor/sangfor_xdr/`、签名 client、wire mock 夹具 | `app/agents/`、`/mock-xdr/v1`、`tools/specs/response.py` |
| **只读摄入** | L4 / 4b / 4c（L1 绿后） | `adapters/sangfor/source.py`、归一化 | Disposition 写回、ResponseAgent |
| **写回 / 实体** | L5 → L6a→6d | `adapters/sangfor/disposition.py`；**L6a 独占** DSS `_maybe_complete_entity_effect` 闸门 | overlay 接到 Demo、VerifyAgent 硬编码 URI |
| **内核接线（一人到底）** | L2（纯函数可先做）→ **L7 → L8 → L8b** | `capability_overlay.py`、`adapters/factory.py`、`deps.py`、`action_execution_tasks.py`、`response_agent.py`、`action.py` 校验器、AES、审批、收敛、`execute_verification_tool`、8b Query Provider | 不要两个人同时改这些 |
| **现场 / 文档** | L10、L11；L9 可选 | first-contact 脚本、README / 运作说明 / env 示例 | 不改默认 `make up-demo` |

**时间线（可并行的窗口）：**

```text
周次示意（人齐时）：
  合同：     L0 ── L1 ── L3 ──────────────────────── L10
  overlay：      L2（L0 矩阵后即可，不接线）
  摄入：              L4 ── 4b/4c
  写回：                    L5 ── L6a(+DSS闸) ── 6b ── 6c ── 6d
  接线：  （等 L2+L5 至少）              L7 ── L8 ── L8b
  文档：  L11 可从 L7 起同 PR；不要等全部做完才改口
  DSP：   L9 全程旁路
```

**两人时：** A = 合同+客户端+摄入+写回（L0–L6）；B = overlay+工厂+内核接线（L2、L7、L8、L8b）+ 盯每层 Mock 金路径。L6a 的 DSS 闸门仍归 A，B 在 L7 接工厂时不要再改 DSS。

**三人时：** 上面「合同」「摄入+写回」「内核接线」各一人；L10/L11 谁先空谁做。

**必须串行、禁止拆给两个人同时改：**

- L6a DSS 闸门 ↔ L7 工厂 ↔ L8 `ResponseAgent` / `action.py` / AES / 收敛（会互相踩）
- L8 与 L8b 可同 PR，不要 L8b 先于 L8 合进默认路径
- 任何人改完都跑：`KIND=mock` 隔离/账号/`query_*` 仍执行

**本计划不分工（§1.9 另开 Issue）：** 厂商新隔离 API、live Direct Tool（EDR/IAM）、`isolateStatus` 真机枚举、自有 Mock 换皮。

---

## 7. 总验收

分两条跑，缺一不可（§1.8）：

**A. 不接入生产（本地 / Canonical Mock）**

1. 无 `.env.live` 时 `make up-demo` 金路径仍能 CLOSED。有 `.env.live`（只覆盖 LLM）时用 `make up WORKER=1`，**禁止** `make up-demo`。  
1b. **每一层**用真 LLM 跑三条 `EVAL_REQUIRE_CLOSED=1`：`insider_data_exfiltration` / `account_anomaly_fp` / `suspicious_domain_access`（附录 A）。MockLLM 或模板回退不算过。  
2. 隔离、禁用账号、杀进程、`query_account_login`、舰队式 EDR query **仍在计划中且仍能执行/Verify**。  
3. `/mock-xdr/v1` **未被**改成深信服 URI。overlay **未**应用到 `KIND=mock`。  
4. development + `TOOL_MODE=mock` 仍能启动。  
5. 分析 / 图谱 / 报告 / 事件问答 / playbook / Demo 自动响应 **行为不减**（本计划不得改这些默认）。

**B. live Sangfor Adapter（无真机也要证明合同）**

1. catalog 操作数 = 129 且 drift 绿；响应树抽到 `dealstatus/list` 的 1–6、`alerts/list.alertDealStatus`、`analysislog/list` data **无** `total`、`analysislog/count` **有** `data.total`、`virusscantask/:taskId` 路径参数。  
2. wire mock + sangfor Adapter：incident 摄入（TMG 码；30→contained；`gpt_verdict_label is None`；描述在 `normalized`）；写入 **整数** 70 后 `dealstatus/list` 读到 **6** 才 CONFIRMED；误用 70 或 `incidents/list` 的 30 当 writeback 证实的测试必须失败。  
3. `block_ip` 按通道；`block_domain` **仅** network + DNS，经 **outbox + ENTITY_ACTION_SUBMIT** + `read_entity_effect_completion`（Job 终态）+ `block success` 证实；endpoint 夹具不得发出域名创建；isolate 创建零请求；无写接口工具 overlay 后 **两个 owner 都不含**，persist 后 Action 仍在（人工路径，不是从产品删掉）。  
4. 分析不出站；`APP_ENV=production` + `TOOL_MODE=mock` 仍不能启动。  
5. `DISPOSITION_MODE=live_xdr` 工厂测试绿；拒绝 `DISPOSITION_MODE=live`；`supports_concurrency_token=False` 单测覆盖；**API 与 Celery 同一组装函数**；job `provider_name` 随 KIND，不永远 `mock_xdr`。  
6. 签名向量含 query `%3D`→`=`、`params is None`、联动码 **全零 IV**。  
7. XDR_MANAGED Verify 只从 `execute_verification_tool` 注入，不读 Mock 文件状态；`KIND=sangfor_xdr` 且非 XDR_MANAGED **不**进 Mock 运行时；`isolateStatus` 无枚举时不得 CONFIRMED。DSS live 路径会调 `read_entity_effect_completion`（`SIMULATION_ENABLED=false` 也走）。6c 工单 Job SUCCESS = 创建有 `orderId`，不对 list `workflowId`，不等结案。  
8. 仓库中 **不存在** `effector_resolver.py`；`ExecutionOwner` 仍两值；`SourceIncident` 仍无 `description` 字段。RESPONSE 仅 §1.7 窄例外允许 `execution_owner=None`。  
9. Layer 8：`ResponseAgent._run` 与物化 **共用** overlay；`owner is None` 不 `continue`；live **零次** Mock `isolate_host` / `disable_account` 执行；persist 后 isolate **不是** REJECTED，收敛 **无** `IN_FLIGHT_JOB`。  
10. live 质量门：persist 后含 isolate/disable 且 `owner is None` + `writeback_readiness=not_required` + `MANUAL_RESOLUTION` 算覆盖；不认 live Mock 执行成功，不认实体 `CAPABILITY_UNSUPPORTED`。  
11. Layer 8b：**live** `query_account_login` 不得 Mock 成功；事件实体 query 标 degraded 或 unavailable。调查闭环 Cutover 含 `ALLOW_LIVE_SIDE_EFFECTS=true`。Mock 路径这两项仍成功。

有真机：跑 L10 只读（含建议的 `blockdevice/list`）；确认现场 `code`/`item` 与文档一致后再开写回开关。现场库存（哪台 AF/EDR）文档里没有，必须配置；空 `devices` 不要自动封禁。`deviceId` 必须改名后才能进创建体。

**C. 明确不在本计划：** 换自有 Mock 实现、生产 XDR 新增隔离/账号 API、live Direct Tool（EDR/IAM）、`isolateStatus` 真机枚举后的 CONFIRMED、DSP PDF 人工复核后的自动写回。这些是 **live 补救的下一档**，见 **§1.9**，另开 Issue。

---

## 8. 现场只改配置、不改内核的项

- `SANGFOR_XDR_BASE_URL`  
- 联动码 `authCode` **或** AK/SK  
- TLS 校验开关（默认开）  
- 共用凭证确认 `shared_credential_scope_verified`  
- 回看时间窗、`timeField`、是否排除 `incidentSources=demo`  
- `hostBranchId` / `platformHostBranchIds` 过滤  
- 封禁 `devices`（配置里用创建体字段名 `devId`；从 list 拉取时走 §2.3.1 改名）  
- **`SANGFOR_BLOCK_CHANNEL=network|endpoint` 只作用于 `block_ip`**；`block_domain` 永远 network + DNS  
- 病毒扫描 `gatewayId`/`agentId` 解析策略、`sourceName`（短串；`source=GPT_MANUAL` 是枚举不是 FastGPT）  
- 工单 `processTemplateId`、`nextAssigneeIds`（缺一不调用）  
- `ALLOW_XDR_WRITEBACK`、`DISPOSITION_MODE`（**`live_xdr`**）、`SOURCE_MODE`（**`sangfor_xdr`**）、`DISPOSITION_ADAPTER_KIND`  
- `APP_ENV`：production 禁止 `TOOL_MODE=mock`；**本地 Demo 必须 `TOOL_MODE=mock`**。live 调查闭环用 `TOOL_MODE=live` + `ALLOW_LIVE_SIDE_EFFECTS=true` + Layer 8b，禁止用 mock query 冒充 **真平台** 完整能力  
- `BLOCK_LIVE_ACTION_EXECUTION`：L10 / 只读探测保持 true；打开自动写效应时再关

开放列表是真的；现场哪台防火墙、哪个流程模板、哪个资产组，文档里没有。空配置 = 该 Action 不自动下发。

---

## 9. 文档同步（Layer 11，避免 AI 仍按「无正式 API」拒绝实现）

挑战杯 OpenAPI 落地后，下列文档 **必须与本文一致**（单独 PR，可与 Layer 7 合并）：

| 文件 | 改什么 |
|------|--------|
| `README.md` §1.5–1.6、§19 | 「无正式 API」→「P0 仍 Mock；**Adapter 层**以 `contracts/vendor/sangfor_xdr` + 挑战杯 HTML 为准；Agent 禁止厂商字段。Cutover-Ready ≠ 真机验证」。§19：RESPONSE 在厂商写能力缺口、overlay 清空双 owner 时允许 `execution_owner=None`（§1.7）；仍禁止第三枚举 |
| `docs/AI_ISSUE_EXECUTION_PROMPT.md` §当前阶段 | 同上；明确 sangfor Issue 只改 Adapter/contract，不改 Agent；**不要**再把「根据截图猜测深信服 REST」写成绝对禁令以致拒绝按本计划实现 Adapter |
| `docs/AI_CODE_REVIEW_PROMPT.md` | 「厂商接口均为未验证猜测」→「挑战杯 OpenAPI 是 Adapter 权威；Agent 出现厂商 path 仍是 Blocker；P0 合格标准仍是 Mock 金路径（隔离等功能不减）」 |
| `docs/仓库运作说明.md` 文首 | 「没有真实深信服 XDR」→「默认闭环仍 Mock，不接入生产时功能完整；开放列表已是 Adapter 合同；现场未跑 L10 前不得声称 live 已验证」 |
| `docs/tool-adapter-guide.md` | 「没有正式接口文档」→ Sangfor 走 `adapters/sangfor/`，**禁止**把深信服 URL 填进通用 `HttpDispositionAdapter` |
| `.env.example` | 增加 sangfor 块注释 + `live_xdr` / `sangfor_xdr` 示例（默认仍 mock）；注明生产是 mock 黑名单不是 allowlist；调查闭环示例含 `TOOL_MODE=live` 与 `ALLOW_LIVE_SIDE_EFFECTS=true` |
| `docs/vendor-packs/README.md` | 指向 catalog + 本计划 |

**禁止：** 在 README 写「已对接生产 XDR」；Cutover-Ready ≠ 真机验证。

---

## 附录 A — 逐层交给执行 AI 的提示词

每开一个新对话，把下面整段贴进去，只改「本层：Layer N」。上一层未验收（含真实 LLM 全链路未绿）不要开下一层。

本层验收的「真实 LLM 全链路」= **真模型 + Mock XDR/工具**，不是接深信服、也不是 CrowdStrike。有 `.env.live` 时 **禁止** `make up-demo`（demo-guard）；用 `make up WORKER=1`。仓库路径含「副本」时必须 `COMPOSE_BAKE=0 DOCKER_BUILDKIT=0`。

```text
你是 ShadowTrace 仓库的实现工程师。本任务只做深信服 XDR 对齐计划的一层，做完必须跑真实 LLM 全链路，未绿不算完成。

本层：Layer 0
权威：docs/sangfor-xdr-alignment-plan.md
  （以文内最晚修订与 §1.6–1.9、§4 硬规则、附录 A 为准，不要用文首已作废的旧接法）
开放列表：挑战杯物料/OpenAPIDocument/深信服XDR平台接口开放列表.html
鉴权：OpenAPIDocument/python/authCodeDemo（冲突以 Python Demo 为准）

开工前必读：本层「目的 / 允许改 / 禁止 / 验收」，以及 §1.6、§1.7、§1.8、§1.9、§4、§6。
docs/AI_ISSUE_EXECUTION_PROMPT.md 里「禁止按猜测实现厂商 HTTP」被本计划覆盖：
Adapter 层以挑战杯 HTML 为合同；Agent 层仍禁止厂商 path。

规则：
1. 只改本层「允许改」的路径。上一层验收未绿则停止并说明缺什么，不要开始本层。
2. 字段名、枚举、URI 原样按开放列表；禁止发明 isolate 创建等不存在的写 path。
3. 禁止改 Canonical Mock `/mock-xdr/v1` 去模仿深信服；禁止从 specs 删 isolate_host / disable_account / query_*。
4. 禁止新建 effector_resolver.py；禁止给 ExecutionOwner 加 manual；禁止给 SourceIncident 加 description；禁止 gptResult → gpt_verdict_label。
5. overlay 不得默认应用到 KIND=mock。本层真实 LLM 全链路必须仍走 Mock XDR（见下方）。
6. 实体能力缺口走 §1.7，禁止套 CAPABILITY_UNSUPPORTED。禁止用 Mock 工具给真 Sangfor 事件盖章（本层验收也不要切 SOURCE_MODE=sangfor_xdr）。
7. 不要提交 git，除非我明确说 commit。不要做 §1.9 的后续 Issue。不要打印或提交 .env.live / API Key。
8. 本层结束后：列出改了哪些文件、本层单测、真实 LLM 三场景结果（status / generated_by / 是否模板回退）、下一层是什么。未测到的要写明。

先确认本层范围，再改代码。改完先跑本层单测，再跑「真实 LLM 全链路」（必修，缺一不可）。

—— 真实 LLM 全链路（本层 Definition of Done）——

目的：证明本层没有把产品闭环砍掉。栈 = 真 LLM + Mock XDR + Mock 工具。
不是 L10、不是 DISPOSITION_ADAPTER_KIND=sangfor_xdr。

若仓库根目录没有 gitignored 的 `.env.live`：停止，让用户补密钥，不要编造、不要用 MockLLM 冒充本项通过。

`.env.live` 只允许覆盖 LLM，例如：
  LLM_MODE=openai_compatible
  LLM_PRIMARY_MODEL=（用户已配的模型）
  LLM_API_BASE_URL= / LLM_API_KEY=
必须保持：
  SOURCE_MODE=mock_xdr
  DISPOSITION_MODE=mock_xdr
  TOOL_MODE=mock
  SIMULATION_ENABLED=true
禁止把 infra/.env.live.example 原样拷进来（那会把 XDR 切成 live_crowdstrike）。
禁止 cat / echo 密钥。

有 `.env.live` 时不要 make up-demo（会 demo-guard 失败）。在本机执行（路径含中文「副本」时加 COMPOSE_BAKE=0 DOCKER_BUILDKIT=0）：

  COMPOSE_BAKE=0 DOCKER_BUILDKIT=0 make down
  COMPOSE_BAKE=0 DOCKER_BUILDKIT=0 make up WORKER=1

确认 GET /api/v1/health：llm.mode=openai_compatible 且 status=ok；source/disposition 仍是 mock_xdr。
不要用模板回退当成功：报告/结构化输出应为 generated_by=llm（或等价 success），禁止大面积 llm_invalid_json → 模板。

然后三条金路径都必须 strict CLOSED（可串行，DYNAMIC_EVAL_MAX_WAIT_S 不够就加到 900）：

  DYNAMIC_EVAL_MAX_WAIT_S=900 EVAL_REQUIRE_CLOSED=1 EVAL_SCENARIO=insider_data_exfiltration make eval-full-loop
  DYNAMIC_EVAL_MAX_WAIT_S=900 EVAL_REQUIRE_CLOSED=1 EVAL_SCENARIO=account_anomaly_fp make eval-full-loop
  DYNAMIC_EVAL_MAX_WAIT_S=900 EVAL_REQUIRE_CLOSED=1 EVAL_SCENARIO=suspicious_domain_access make eval-full-loop

不要 make demo-full-loop（内部会跑 demo-guard）。
不要 EVAL_REQUIRE_CLOSED 缺省的 compat 剖面当本项通过。

额外断言（尤其 insider）：
- 事件 CLOSED；写回仍是 Mock simulated 合同，不要对外说成 live XDR
- 计划里仍有 isolate_host / disable_account 且被执行/Verify（Mock 双 owner）
- query_* 仍能出证据，不是 unavailable
- 分析 / 图谱 / 报告 / 事件问答不要无故挂掉

任何一条失败：修本层或回滚本层改动，禁止开下一层。
```

