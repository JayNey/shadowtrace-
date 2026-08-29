# RAG 五库内容补充方案

> 检索已经两阶段（先 `org_context_kb` 出约束，再对其余四库做 Constrained RRF）。空乏的是**句子和实体**，不是检索器。  
> 本方案只补**演示知识内容**（加种子 / 必要的种子 schema）。不改 Hybrid / C-RRF / QueryBuilder / pipeline 归一化（那是 `docs/rag-retrieval-upgrade-plan.md`）。不灌 DSP / pcap / 深信服 OpenAPI。  
> `data/knowledge/policy_controls.json` 是合规映射，**不在五库里**，不要混进 RAG。

**2026-08-29 第五次修订（执行前必读，覆盖第四次 Cutover / §1.6 / P3）：**

对照 `pipeline._ensure_normalized` 与 `reranker._mock_rerank`：两路都对 top_k **min-max**，池非空且分数有散度时最高块 **score=1.0**。内容 PR **禁止**改这两处。因此「六条真阳 `max_score < 0.7`」**不是内容能交的门**——那是检索方案组装口径 H（无精确实体则 id 与分同清，并把命中块提到第一再取 `max(score)`）。作废：用分阈值当 P1a/P3 内容关门；手搓无 C-RRF 的 Hybrid 当「与 RAGAgent 同一路径」；锁死的 severity 只用 pack 期望值（`other` A 档曾是 medium）。

权威对照：`backend/app/agents/verdict_resolver.py`（`fp_score >= 0.7` → `possible_false_positive`，排在 `risk_score>=70` 之前）；`backend/app/rag/pipeline.py`（`_ensure_normalized`）；`backend/app/rag/reranker.py`（mock min-max）；`backend/app/agents/rag_agent.py`（org catalog → `constraints_from_org_matches` → 四库 C-RRF；`_build_fp_similarity` 取最高块）；`backend/app/agents/rag_query_builder.py`（FP 只拼 `Account:`；`Analysis:` 仅 `reasoning` 非空）；`backend/app/agents/triage_agent.py`（生产 `reasoning=""`）；`backend/app/rag/constraint_rrf.py`（H 按 value 是否在正文，不看极性）；`backend/app/services/org_context_matcher.py`（`now=occurred_at`；`data_handling` 只扫 `facts.domains`）；`backend/app/models/case.py`；`data/knowledge/fp_cases.json`（`0d`=`PC-FIN-*`，`0e` 含 `brand-new-cdn-example.net`）；`data/knowledge/attack_techniques.json`（79 条；无 `T1021.001`/`T1570`；T1071 无 `beacon.exe`；T1078 detection 已有 `zhangsan`）；`scripts/dynamic_eval_full_loop.py`（`skip_entity_response` 的改密/`other` 不补 `confirmed_threat`）；`docs/rag-retrieval-upgrade-plan.md` §0.1 H/L/N。

加载：**必须** `make load-kb`（`load_attack_kb` + `load_attack_stix_release` + `load_case_kb` + `load_org_context_kb` + **`load_playbook_release`**）。不要用遗留 `load_playbook_kb`。组织上下文 **仅 Mock `SOURCE_MODE` 才种**。`load_attack_stix_release` 从 **79 条** JSON **派生** bundle。**禁止**把 `make load-kb` 当热重载循环跑——同一 `technique_id` 会 stamp 出多块占满 `fetch_k`。改完一轮内容只全量 load **一次**；只改 playbook 时优先 `python -m scripts.load_playbook_release`。

与检索升级方案：**按此顺序衔接，禁止交叉授权。**

1. 本文件 P1a（正文 0d/0e + §1.5 + §1.6 **id 锁**）必须先于检索侧：Host 写入误报 query、fp EventType SQL 过滤、组装口径 H。P1a 给 metadata 加 `event_type` **不等于**允许开过滤。  
2. 检索 P0 扩写 Host 之前，本文件必须改掉 `0d` 的 `PC-FIN-*` 与 `0e` 的 `office-user-*` / 真阳域名。否则 `simple` 分词把内鬼/域名真阳和 glob 负例撞在一起。  
3. 检索口径 H 未落地时，生产上六条真阳 **仍可能**因 min-max 得到 `max_score=1.0` 被 Resolver 打成 `possible_false_positive`。评测会对这些条补 `confirmed_threat`。**不要**把「Resolver 不是 PFP」写成内容关门。内容只保证 **冠军 id 不是改密卡、不是未改正文的 0d/0e**。  
4. 检索 H 落地后，联合 DoD 才是：六条真阳无精确实体命中 → persist `matched_case_id is None` 且 `max_score=0`；改密则 id=`case-00000001` 且分 ≥ 0.7（H 把命中块提到第一再取 `max(score)`）。

---

## 0. 结论

不要灌百科。按 **8 条 EventType + 夹具原文** 补对照样本，且 **不能把已能过的 Demo 金路径灌回**。

优先级：**组织上下文（allow 极保守，存量真阳 allow 冻结）> 历史夹具 TP（结案写进 summary；other 只加厚已有行）> 误报（先改危险正文 + 冻结类型再 schema）> 攻击（只加厚已有 T + 进程 keywords）> 剧本（本轮不加本，P0b 整段不做）**。

当前规模：攻击 79、误报 14、历史 21、剧本 13、组织上下文 14。8 条主索缺的是夹具原文进历史、改密窗进 org（**关单阶梯**）、误报冠军不要是改密卡或 glob 负例——不是再加剧本、不是扩 ATT&CK ID、**不是内容侧把 mock 归一化分压到 0.7 以下**。

**Cutover（内容 PR 缺一条不算完成）：**

- `account_anomaly_fp` persist：`matched_case_id=case-00000001`（现网归一化下分会 ≥ 0.7，这是冠军副作用，不要另造「内容把分做成 0.85」）。  
- **六条高风险真阳**（域名 / 内鬼 / 失陷 / 特权 / 恶意进程 / 横向）：persist 的 `matched_case_id` **不得**为 `case-00000001`；改正文后的 `0d`/`0e` 不得再以夹具账号/主机出现在冠军块。**不**验收 `max_score < 0.7`。  
- 域名剧本仍绑 `pb-c8d9e0f1` 第一步 `block_domain`。  
- 横向不得新增 `JUMP-HOST-001` allow；特权存量 allow **不改 kind、不再叠**。  
- `eval-eventtype-8` 全 8 条 A 档绿。读 persist 的 `fp_similarity.id`，不要用分析员补刀后的 `final_verdict` 推断生产 FP 门。

**联合 Cutover（内容 + 检索 H 都绿才算「生产不会被 0.7 误报门盖住」）：** 见检索方案口径 H。本文件单独合入时 **明确接受** 中间窗口。

---

## 0.1 冻结口径（禁止实现时二选一）

| # | 口径 | 禁止的替代 |
|---|------|------------|
| A | 0.7 门的权威是 `VerdictResolver`：`fp_similarity.max_score >= 0.7` → `possible_false_positive`，**排在** `risk_score>=70` 之前。Risk 同一阈值只举旗。Response 的 `close_as_fp` 另用 `FP_HIGH_THRESHOLD=0.9` | 只写「Risk 走误报门」；以为高风险真阳靠 70 分能压过 FP 分 |
| B | §1.6 锁必须走 **`RAGAgent` 同路径**：最小 Triage（`reasoning=""` + 下表 EntitySet）→ catalog `load_org_context_matches` → `constraints_from_org_matches` → fp 检索 → `_build_fp_similarity`。`make load-kb` **一次**之后打 | 对 JSON contains；手写缩水查询；**无 org 约束的裸 Hybrid**；用带 `login` 的 `reasoning` 当生产 DoD |
| C | 本轮 **没有** `suspicious_domain` 误报行。`0e` 标 `other`，并去掉真阳域 / `office-user-*`（§1.5、§4） | 把 `0e` 标成唯一 `suspicious_domain` 当「CDN 负例」 |
| D | 存量 `org-acct-svc-admin-abuse`、`org-src-srv-admin-003` **冻结**：不改 kind、不删、不再叠一条 allow。C-RRF 的 H 不看「不属于批准」 | 按 §1.1 旧黑名单去改 kind 或删掉这两条；再加一条否认式 `account_role` |
| E | `person_status` 的「≠」只约束 LLM 可读 content。Matcher 仍出 `account_exact`，**不进** H、不进 FP 关单 allow 阶梯 | 拿三条在职当主索 #5 的新门；指望「≠」改变 `match_type` |
| F | `data_handling` 的 `hosts`/`accounts` 是死字段。横向 JUMP-HOST 行 **不得**验收 catalog 命中 | 验收 `host_exact` / H 票 / 「deny hit」 |
| G | 剧本 **本轮零新增**。原 P0b host medium **整段不做**。`pb-3c4d5e6f` / `pb-2a3b4c5d` 的 `min_severity` **保持 medium**（金路径已靠这个绑上 disable / `block_ip`），禁止改回 high | 「禁止子串 high」当可合并闸门；先合 host medium 再看评测 |
| H | 内容 P1a **不授权**检索对 `fp_case_kb` 做 EventType SQL 过滤。`other` 永不对该库过滤 | 「metadata 有类型了就开过滤」；P1a 与过滤同一 PR |
| I | 历史结案动作必须出现在 `summary`（或 `key_entities`）。`resolution` 不是 RAG | 结案只写 `resolution`；用 `successful_response` 当检索信号 |
| J | ATT&CK **79 个 ID 冻结**。只加厚已有 T。T1078 detection 里已有的 `zhangsan` / `PC-FIN-023` **禁止删** | 新增 `T1021.001` / `T1570`；「detection 尽量不用人名」理解成删现句 |
| K | **内容锁认 id，不锁「真阳 max_score&lt;0.7」。** mock 归一化使冠军分为 1.0。分阈值是检索 H 的联合门 | 内容 PR 里 assert 六条 `max_score < 0.7`；改 pipeline 去「把分压下来」 |
| L | `0d` 首选仍标 `data_exfiltration`（fileshare 负例）。若 §1.6 内鬼锁因类型前缀把 `0d` 打成冠军 → **同 PR 改标 `other`**，不要加第三篇外泄误报 | 为了「外泄负例」硬留 typed 却让内鬼冠军变成 0d |
| M | `other` 的 FP 锁：`severity low` **和** `severity medium` 都要跑（A 档曾落 medium）。id 不得为 `01`。允许 max=1.0 | 只锁 pack 的 low；为压 other 的分把 03–09 改回 `account_anomaly` |
| N | 全量 `make load-kb` 每个内容迭代 **至多一次**。禁止循环 load 当调试 | 每改一行 JSON 就 load-kb；用块数膨胀当「知识变多」 |

---

## 1. 总原则

1. **夹具原文优先**：对齐 `seed_mock_xdr_and_ingest` 的 8 个场景（`scenarios/` + `_system_scenario_pack.py`）。进程名必须是 `_scenario_process_name()` 字面量。  
2. **真阳实体禁止出现在误报行**（§1.1）。对照用邻近但不同的主机（已有 `PC-FIN-011`）。**禁止 glob 前缀**去「概括」真阳主机族。  
3. **剧本 `tool_name` 只能用内核工具。** `Playbook` / `PlaybookStep` 为 `extra=forbid`。禁止厂商 URI。  
4. **中英都要能搜。** Mock 嵌入下 FTS 吃英文短查询。正文同时有中文别名和 `insider` / `exfiltration` / `lateral movement` 等。不要只堆中文。  
5. **不要灌**全量 STIX、pcap、DSP、开放列表、等保原文。  
6. **Response 只吃 `playbook_refs[0]`。** Hybrid 查剧本只有 `event_type` + `severity`，**没有** SQL `min_severity` 过滤。chunk 正文含 `Min Severity: …`。内鬼遏制本 / 横向遏制本今日已是 **medium**——本轮不要改。  
7. **`precondition` 不是代码门禁。** 禁止把 `ops-change-bot` / `PC-OPS-JUMP-01` / 「变更窗口」写进各本 precondition。  
8. **`match_type` 是** `account_exact` / `host_exact` / `domain_exact` / `window` / `restricted_domain` 等。评测表里的 `"exact"` 表示这一族（`is_exact_family_match_type`），不要断言字面量 `"exact"`。  
9. **检索看不到的字段不要当补库。** 历史只索引 `summary` + `key_entities`；`resolution` 不进 `history_case_to_text`，也不进 `similar_cases`。  
10. **评测绿 ≠ 生产没变弱。** `dynamic_eval_full_loop.py` 对非 `skip_entity_response` 条会把 `possible_false_positive` 补成 `confirmed_threat`。内容验收读 persist 的 **id**；检索 H 落地后再读 **分**。

### 1.1 八场景实体表

| 场景 | EventType | 夹具 severity | 评测曾出现的 triage severity | 主机 | 账号 | 关键 IOC / 进程 |
|------|-----------|---------------|------------------------------|------|------|-----------------|
| `account_anomaly_fp` | `account_anomaly` | **low** | low | **`PC-OPS-JUMP-01`** | `ops-change-bot` | 变更窗口改密 |
| `suspicious_domain_access` | `suspicious_domain` | closed-loop **high**；Demo **medium** | 两条都要锁 | `PC-OFFICE-014` | `office-user-014` | `brand-new-cdn-example.net` vs `cdn.corp.internal` |
| `insider_data_exfiltration` | `data_exfiltration` | **critical** | critical | `PC-FIN-023` | `zhangsan` | `7z.exe` / `finance_report.zip` / `unknown-upload-example.com` |
| `host_compromise` | `host_compromise` | high | 建议 high+medium | `WKS-HOST-007` | `svc-beacon-007` | **`beacon.exe`**、`beacon-example.test` |
| `insider_privilege_abuse` | `insider_threat` | high | 曾 medium（才绑上 disable 本）→ **high+medium** | `SRV-ADMIN-003` | `svc-admin-abuse` | **`net.exe`** |
| `malicious_process` | `malicious_process` | high | high | `DEV-WKS-012` | `dev-user-012` | **`ransomware_stage.exe`** |
| `lateral_movement` | `lateral_movement` | high | high | **`JUMP-HOST-001`** → `SRV-CORE-002` | `ops-jump-001` | **`mstsc.exe`** / RDP |
| `other_unclassified` | `other` | low | **medium 已在 A 档出现** | `WKS-GEN-099` | `general-user-099` | 低置信未分类 |

**两台跳板不得混用：**

| 主机 | 场景 | 组织语义 |
|------|------|----------|
| `PC-OPS-JUMP-01` | 改密 **误报** | 可以是 `allowed_source` / `account_role`（已有） |
| `JUMP-HOST-001` | 横向 **真阳** | **禁止新增** `allowed_source` / `account_role`。负向只用 `data_handling` 的 **content**（catalog 命不中主机） |

**误报库实体黑名单**（禁止写入任何 `fp_cases.json` 的六段字段；含「在否定句里点名」）：

`PC-FIN-023`、`zhangsan`、`unknown-upload-example.com`、`brand-new-cdn-example.net`、`svc-admin-abuse`、`SRV-ADMIN-003`、`WKS-HOST-007`、`svc-beacon-007`、`beacon.exe`、`beacon-example.test`、`DEV-WKS-012`、`dev-user-012`、`ransomware_stage.exe`、`JUMP-HOST-001`、`ops-jump-001`、`SRV-CORE-002`、`mstsc.exe`、`net.exe`、`office-user-014`、`PC-OFFICE-014`、`general-user-099`。

另禁 glob：`PC-FIN-*`、`office-user-*`、`PC-OFFICE-*`、`finance-*`。对照主机用已有 **`PC-FIN-011`** 或全新、不在上表的名字。

历史 **TP** 必须用真阳实体。`WKS-GEN-099` 只留在 `other` 历史（可加厚 `case-10000021` 的 summary，见 §5，**不要换 id**）。

**组织上下文 allow：两套名单，不要合成一句「真阳禁止 allow」。**

| 范围 | 规则 |
|------|------|
| **本轮新增** allow | 只绑误报侧：`ops-change-bot`、`PC-OPS-JUMP-01`、已有 `files.corp.internal` / `cdn.corp.internal` / `svc-backup` / `vuln-scanner-01`。禁止绑上表真阳实体，也禁止绑 `JUMP-HOST-001` |
| **存量冻结** | `org-acct-svc-admin-abuse`（`account_role` + `svc-admin-abuse`）→ 主索 #5 `account_exact`；`org-src-srv-admin-003`（`allowed_source` + `SRV-ADMIN-003`）→ 进 C-RRF H。正文「不属于批准」**不会**让 H 少投票。禁止再叠一条 |

**攻击库 IOC 扩散黑名单**（只允许出现在下表指定的 **已有** T 的 `keywords`/`detection`，禁止再抄到其它 T、禁止进 aliases）：

| 字符串 | 只允许出现在 |
|--------|----------------|
| `ops-change-bot`、`PC-OPS-JUMP-01`、change window 时钟 | **仅 T1110**（已有一句则不要再复制） |
| `JUMP-HOST-001`、`mstsc.exe`、`SRV-CORE-002` | **仅 T1021**（已有 keywords） |
| `7z.exe`、`finance_report.zip`、`unknown-upload-example.com` | **仅 T1560.001 / T1567**（已有则加厚这两条，不要给 T1048 再抄一份） |
| `brand-new-cdn-example.net` | **仅 T1566 / T1608**（T1566 detection 已有例句则不要再复制） |
| `beacon.exe`、`beacon-example.test` | **仅 T1071**（本轮要写入 keywords；今日该条还没有） |
| `ransomware_stage.exe` | **仅 T1059 与 T1218** |
| `net.exe` | **仅 T1134**（T1548 只加英文特权词，不抄主机名） |
| `zhangsan`、`PC-FIN-023` | **哪里都不进 aliases**。T1078 detection **已有**这两词 → **保持，禁止删**。其它 T 的 detection 不要再抄人名 |

### 1.2 组织上下文 kind 合同

`CONSTRAINT_KINDS` 与 `_FP_ORG_CONTEXT_CLOSE_KINDS` 同一套 allow 四种：

| kind | 进 C-RRF 的 H？ | FP 关单 allow 阶梯？ | 本方案允许绑谁 |
|------|-----------------|----------------------|----------------|
| `allowed_destination` | 是 | 是 | **仅已有** `files.corp.internal`、`cdn.corp.internal`。**本轮禁止新增** 办公门户或其它 allow 域 |
| `allowed_source` | 是 | 是 | **新增**仅误报侧：已有 `PC-OPS-JUMP-01`、`vuln-scanner-01`。禁止 `JUMP-HOST-001` / `SRV-CORE-002` / `WKS-HOST-007`。**存量** `org-src-srv-admin-003` 见口径 D |
| `account_role` | 是 | 是 | **新增**仅已有 `ops-change-bot`、`svc-backup`。禁止再给真阳账号加否认式 `account_role`。**存量** `org-acct-svc-admin-abuse` 见口径 D |
| `time_window` | 是（H 的 value 几乎抬不动案例） | **是，这是本轮 org 主收益** | 改密窗必须绑 `ops-change-bot` 和 `PC-OPS-JUMP-01` |
| `data_handling` | **否** | **否** | 未批准域名、U 盘说明、横向/失陷给 LLM 的句子 |
| `person_status` | **否** | **否** | 在职/离职。会出 `account_exact`，content **必须**带「≠ 批准…」。不是 persist 金路径门 |
| `security_product` | **否** | **否** | 已有 `carbonblack.corp.internal`。本轮不必再加 |

**禁止：** 一条**新**记录混 allow kind + 负向语义。`data_handling.domains` 点名未批准对端，`allowed_channels` 写批准通道。存量特权两条已经混了「allow kind + 否认 content」——冻结，不当范本。

内鬼事件的 `facts.domains` 是 `unknown-upload-example.com`，**不一定**含 `files.corp.internal`，因此 C-RRF **未必**用批准域去抬 `0d`。内鬼锁红更常见的原因是 **类型前缀** `event type data_exfiltration`（口径 L），不是 H。

### 1.2.1 Matcher 实际认哪些字段

| kind | catalog 怎么命中 | `match_type` | 进 H / FP 关单 allow？ | 怎么写 |
|------|------------------|--------------|------------------------|--------|
| allow 四种 + `security_product` + `person_status` | 通用：`domains` / `cidrs` / `ips` / `hosts` / `accounts` | `domain_exact` / `host_exact` / `account_exact` / … | 仅 allow 四种 + `time_window` | 新增 allow 只绑误报实体 |
| `time_window` | 实体交集 **且** 时钟罩住 **事件** `occurred_at` | **`window`**；`matched_value` = `08:00/12:00` | 是（关单） | 见 §1.3 |
| `data_handling` | **只扫 `facts.domains`** | `restricted_domain` 或批准 `domain_exact` | **否** | 未批准写域名。**`hosts`/`accounts` 是死字段**。进程只能写进 content |

横向「JUMP-HOST 不是批准源」：**不能** catalog 命中该主机。验收只许「无 `JUMP-HOST-001` 的 `allowed_source`」，句子靠 org 查询里的 `Host:` 做 Hybrid。失陷 catalog deny 点名 **`beacon-example.test`**。

已有、**禁止改 kind / 禁止再叠一条 allow** 的记录：

- `org-acct-svc-admin-abuse`、`org-src-srv-admin-003`（主索 #5；后者会抬含 `SRV-ADMIN-003` 的块——本轮接受）
- `org-acct-ops-change-bot`、`org-src-ops-jump`（缺的是 time_window，不是再写角色）

`person_status` 三条在职 **content 合同**（缺「≠」视为不合格）。不要写进主索 persist 验收：

| 账号 | 必须出现的意思 |
|------|----------------|
| `zhangsan` | 在职财务 **≠** 批准把 `finance_report.zip` 发外网 / 非 `files.corp.internal` |
| `office-user-014` | 在职办公 **≠** 批准访问未登记域 `brand-new-cdn-example.net`；批准 CDN 仍是 `cdn.corp.internal` |
| `general-user-099` | 在职无特权 **≠** 可忽略 / 不等于无需观察 |

`contractor-temp` 离职已有，不要改成 allow。

### 1.3 时间窗（两套日历 + C-RRF 诚实口径）

| 系统 | 文件 | 用途 |
|------|------|------|
| FP 关单 baseline | `data/organization/change_windows.json` | `2024-06-15T08:00:00+00:00` ~ `12:00:00+00:00`，账号 `ops-change-bot` |
| 夹具时钟 | `DEFAULT_BASE_TIME` | **2024-06-15 09:00 UTC** |
| org matcher | `time_window` 的 `HH:MM` | 按 **UTC 当日时刻** 对照 **事件** `occurred_at`；必须与实体字段有交集 |

新增改密窗写成 **`08:00`–`12:00`**，绑 `ops-change-bot` **和** `PC-OPS-JUMP-01`。禁止 `10:00–12:00`。禁止不绑实体。禁止改夜间备份窗 `02:00–04:00`。禁止改 `change_windows.json`。

**不要指望这扇窗抬高误报检索分。** Matcher 写入 H 的 `matched_value` 是 `08:00/12:00`，案例正文几乎没有这串。改密块今天能被抬，靠的是已有 `account_role`（`ops-change-bot`）。新窗的验收是：**夹具 `occurred_at=2024-06-15T09:00:00Z` 时 `match_type=window`，能进 FP 关单 allow 阶梯**。禁止用本机墙钟。

### 1.4 允许改的路径

- `backend/app/knowledge/org_context_seed.py`
- `data/knowledge/{playbooks,fp_cases,history_cases,attack_techniques}.json`
- `backend/tests/test_rag/test_knowledge_seed_files.py`
- **P1a 同 PR：** `backend/app/models/case.py` 的 `FalsePositiveCase` + `fp_case_metadata` + `fp_case_to_text` + 对应单测。只改 JSON = 空转（Pydantic 丢未知键）。
- 可选 `ORG_CONTEXT_SEED_PATH`（同 `record_id` 覆盖）
- P1a 锁测：新增测试必须调 **`RAGAgent`（或抽出来的「catalog + 带 org_constraints 的 pipeline.retrieve(fp)」）**。禁止改 `rag_query_builder.py` / `pipeline.py` / `verdict_resolver.py`

**禁止改：** QueryBuilder、C-RRF、VerdictResolver、pipeline 归一化、`keyword_aliases` 写死演示人名、Agent、Adapter、Mock URI。

### 1.5 现有 14 条误报 `event_type` 冻结表（P1a 必遵守）

语义上像账号异常的行 **不得**标 `account_anomaly`，否则 `fp_case_to_text` 拼上类型后会跟 `case-00000001` 抢查询前缀。组装在检索 H 落地前只认最高分一块。

**原则：不要给真阳 EventType 做「唯一 typed 误报」，除非正文与该真阳零实体重叠且 §1.6 id 锁已绿。**

| case_id | 冻结 `event_type` | 理由 |
|---------|-------------------|------|
| `case-00000001` | `account_anomaly` | 改密金路径，**唯一**该类型 |
| `case-00000002` | `data_exfiltration` | 夜间备份负例。P1b 账号改为 `svc-backup`；不得含 `zhangsan` / `PC-FIN-023` |
| `case-00000003` | `other` | 扫描器。禁止 `account_anomaly` / `lateral_movement` |
| `case-00000004` | `other` | CI 批量 SSH，**禁止**标 `account_anomaly` |
| `case-00000005` | `other` | AD 复制 |
| `case-00000006` | `other` | DHCP |
| `case-00000007` | `other` | EDR 心跳。禁止 `suspicious_domain` |
| `case-00000008` | `other` | VPN 地理登录。**禁止** `account_anomaly` |
| `case-00000009` | `other` | 钓鱼演练。禁止 `suspicious_domain` |
| `case-0000000a` | `malicious_process` | npm/pip。若 §1.6 恶意进程 **id 锁**红 → **改标 `other`**，不要加第三篇 |
| `case-0000000b` | `other` | 财务月结 DLP。禁止 `data_exfiltration` |
| `case-0000000c` | `malicious_process` | K8s HPA。同 0a |
| `case-0000000d` | `data_exfiltration`（首选） | fileshare 负例。**必须改正文**（§4）。内鬼 id 锁若仍冠军是 0d → 改标 `other`（口径 L） |
| `case-0000000e` | **`other`** | 内部 CDN 负例。**禁止**标 `suspicious_domain`。去掉真阳域 / `office-user-*` / `PC-OFFICE-*` |

执行 P1a 时把上表写进 JSON，**禁止「按正文自选」**。本轮结束后 **0 条** `suspicious_domain` 误报。

`other` 行会很多。`other_unclassified` 查询带 `event type other`。评测 `skip_entity_response`、禁止 isolate。**不把** FP 分当硬门。禁止为压 other 把 03–09 改回 `account_anomaly`。

### 1.6 八条 FP 查询锁（P1a 硬门 = **冠军 id**）

构造最小 `RAGAgentInput` / Triage：

- `reasoning=""`（生产形状）。`decision_summary` 不进 Builder。  
- `entities.accounts[0].username`、`entities.hosts[0].hostname` 按下表填（锁测 **带 Host**，即使 QueryBuilder 今天不把 Host 写进 fp query——catalog / 以后扩写需要这套 EntitySet）。  
- `occurred_at=2024-06-15T09:00:00Z`。  
- 走 **RAGAgent 同路径**（口径 B），读 `_build_fp_similarity`。

**禁止**只断言文档字面量。字面量仅便于核对 Builder 的 verbose 串。

| 场景 | EntitySet（账号 / 主机） | 查询形状（空 reasoning） | 内容硬锁（id） |
|------|--------------------------|------------------------|----------------|
| `account_anomaly_fp` | `ops-change-bot` / `PC-OPS-JUMP-01`，severity **low** | `… event type account_anomaly, severity low. Account:ops-change-bot` | top-1 **`case-00000001`** |
| `suspicious_domain_access` | `office-user-014` / `PC-OFFICE-014` | `severity high` **以及** `severity medium` 各一条 | 冠军 **不是** `01`；**不是**未改正文的 `0e` |
| `insider_data_exfiltration` | `zhangsan` / `PC-FIN-023`，severity **critical** | `… data_exfiltration, severity critical. Account:zhangsan` | 冠军 **不是** `01`；**不是** `0d`（若是 → 口径 L 改标 `other` 后重跑） |
| `host_compromise` | `svc-beacon-007` / `WKS-HOST-007` | `severity high` **以及** `severity medium` | 冠军不是 `01` |
| `insider_privilege_abuse` | `svc-admin-abuse` / `SRV-ADMIN-003` | `severity high` **以及** `severity medium` | 冠军不是 `01`（H 会抬含这些实体的块——误报行不得含它们） |
| `malicious_process` | `dev-user-012` / `DEV-WKS-012`，severity high | `… malicious_process … Account:dev-user-012` | 冠军不是 `01`；若是 `0a`/`0c` → 改标 `other` 后重跑 |
| `lateral_movement` | `ops-jump-001` / `JUMP-HOST-001`，severity high | `… lateral_movement … Account:ops-jump-001` | 冠军不是 `01` |
| `other_unclassified` | `general-user-099` / `WKS-GEN-099` | `severity low` **以及** `severity medium` | 冠军 **不是** `01`。允许 max=1.0 |

可选回归（**不算**生产 DoD）：同一改密 Triage 但 `reasoning` 含 `login` → top-1 仍须 `01`。

P1a / 任何误报正文改动之后，上表 **全部**重跑。缺一条停。不要用「评测 A 档绿了」替代。**不要**在这些锁里 assert `max_score < 0.7`。

---

## 2. `org_context_kb`

**文件：** `backend/app/knowledge/org_context_seed.py`。现约 14 条。缺改密 `time_window`，以及 deny 种类讲清新场景。  
**目标：** +6～10，总量约 20～24。**不要冲 35，不要新增 allow 域。**

| kind | 补什么 | 禁止 |
|------|--------|------|
| `time_window` | `08:00`–`12:00` UTC，绑 `ops-change-bot` + `PC-OPS-JUMP-01` | 10:00–12:00；不绑实体；改备份窗；指望它抬 FP 检索分；用墙钟验收 |
| `person_status` | §1.2.1 三条约定全文 | 写成 `account_role`；只写「在职」不写「≠」；给 `ops-change-bot` 加 person_status；当 persist 门 |
| `data_handling` | U 盘/网盘不是财务批准通道；批准仍是 `files.corp.internal`。`unknown-upload` 行已有则 **不要复制** | 把未批准域改成 allow |
| `data_handling`（仅 content） | `JUMP-HOST-001` RDP 到 `SRV-CORE-002` 不是批准运维；批准跳板是 `PC-OPS-JUMP-01`。`hosts`/`accounts` 可空 | 指望 catalog `host_exact` |
| `data_handling`（catalog deny 用域） | `domains=("beacon-example.test",)`；content 写 `beacon.exe` / `svc-beacon-007` | 新 `account_role` 绑失陷账号；只填 `WKS-HOST-007` 当命中 |
| `data_handling`（仅 content） | 开发允许编译；**`ransomware_stage.exe` 写进 content** | `account_role` 绑 `dev-user-012` |

**本轮删除的原可选行：** 新增 `allowed_destination` 办公门户；新增 `security_product`；原 P0b。

P0 验收（org）：

- 改密 `occurred_at=2024-06-15T09:00:00Z` → 新窗 `match_type=window`。  
- 特权滥用：现有 `svc-admin-abuse` 仍 `account_exact`。  
- 横向：**无新增** `JUMP-HOST-001` 的 `allowed_source`。  
- 失陷 C2 行若存在：`beacon-example.test` 为 `restricted_domain`；无 `WKS-HOST-007` allow。  
- 三条在职 `person_status` content 含「≠」。

---

## 3. `playbook_kb`

**文件：** `data/knowledge/playbooks.json`。入库 **`load_playbook_release`**。  
**本轮零新增，维持 13 本。** 域名 low **永不加**。

| event_type | 现有 | 本方案 |
|------------|------|--------|
| `account_anomaly` | high（disable）+ medium 调查 | 不再加 disable 本 |
| `host_compromise` | 仅 high `pb-1c2d3e4f`（isolate → scan） | **不加** medium |
| `suspicious_domain` | 仅 `pb-c8d9e0f1`，第一步 `block_domain`，`min_severity=medium` | **禁止** low/无封禁本。closed-loop high 与 Demo medium 两条查询的 `[0]` 都必须是这一本 |
| `malicious_process` | high + medium（`block_process` + `query_edr_process`） | 不加 |
| `insider_threat` | `pb-3c4d5e6f` 第一步 `disable_account`，**`min_severity=medium`** | **保住 medium**，禁止改回 high |
| `lateral_movement` | `pb-2a3b4c5d` 第一步 `block_ip`，**`min_severity=medium`**；另有调查本 | 不加第三本；禁止把遏制本改回 high |
| `data_exfiltration` | high / medium | 本轮不动 |
| `other` | 仅 low 分诊 | 禁止 isolate/block 的 high 本 |

**P0b：整段取消。**

不要改域名本描述去「加强 FTS」。不要在 precondition 写变更窗口。

回归锚：恶意进程含 `block_process`+`query_edr_process`；`pb-3c4d5e6f` / `pb-2a3b4c5d` / **`pb-c8d9e0f1` 仍是 suspicious_domain 唯一本且第一步 `block_domain`**；`other` 无 isolate/block；失陷仍只有 `pb-1c2d3e4f`。

---

## 4. `fp_case_kb`

**文件：** `data/knowledge/fp_cases.json`。检索 H 落地前 `_build_fp_similarity` **无条件取最高块**。QueryBuilder **只拼 Account**。生产 `reasoning=""`。

查询与锁见 **§1.6**。锁的是 **id**。

### P1a（schema + 冻结表 + 危险正文，同一 PR）

顺序：**先改正文，再加 schema，再跑 §1.6。** 不要先打类型再改 0e。

1. 按 §1.5 改 14 条 `event_type`。`0e` 必须是 `other`。  
2. **`case-0000000d` 正文：** `host=PC-FIN-011`（或其它非黑名单主机），禁止 `PC-FIN-*`、`finance-*`、黑名单真阳 IOC。目标域可保留 `files.corp.internal`。  
3. **`case-0000000e` 正文：** 邻近但不同实体（例如 `cdn-publisher-01` / `PC-CDN-LAB-02`）。禁止 `office-user-014`、`office-user-*`、`PC-OFFICE-*`、`brand-new-cdn-example.net`。可保留 `cdn.corp.internal`。  
4. `FalsePositiveCase.event_type: EventType` 必填。  
5. `fp_case_metadata` 写入 `event_type`。  
6. `fp_case_to_text` **追加** event_type 字面量。  
7. 本轮不要给模型加 `extra=forbid`。  
8. **禁止**第二篇 `account_anomaly`。本轮 **禁止**任何 `suspicious_domain` 误报。  
9. 跑 §1.6；`0a`/`0c` 若成为恶意进程冠军 → 改标 `other`。`0d` 若成为内鬼冠军 → 改标 `other`。

### P1b（对齐实体，不增条数；P1a id 锁绿之后）

- `case-00000003`：保留 `SCANNER-01` / `scanner-svc`，**另加** `vuln-scanner-01` / `10.20.0.15`。今日 FP 查询无 Host，这 **不是**改密召回修复。  
- `case-00000002`：账号改为 **`svc-backup`**，旧名留作别名；目标仍 `files.corp.internal`。  
- **禁止删旧 token。** 改完重跑 §1.6。

### P1c（本轮默认不做）

检索 EventType 过滤 + 组装口径 H 落地且 §1.6 仍绿之前，**不要加条**。

---

## 5. `history_case_kb`

**文件：** `history_cases.json`。`history_case_to_text` = **`summary` + `key_entities` 而已**。  
**`resolution` 里的结案动作等于没进 RAG。**

现 21 条。Emotet `case-10000003` 不得再占 `PC-FIN-023` / `zhangsan`。

**`case-10000021`（`WKS-GEN-099`）不要换 id、不要删。** A 档 `other_unclassified` 的 persist 门是 `similar_cases` **非空**，不是必须命中这一行（检索方案：`other` 永不硬过滤）。本轮允许 **加厚** 其 `summary`/`key_entities`：补上英文 `unclassified` / `insufficient context` / `WKS-GEN-099` / `general-user-099`，让现有 query（`Event type: other` + Host/Account）更容易把同类型块召进 `fetch_k`。禁止新开第二条 other 历史去「冲非空」。

目标另 +4 条夹具 TP（不要 +10）。新 id 从 `case-10000022` 起。

| 类型 | 必须写入 `summary` **和** `key_entities` 的原文 | 结案（也要在 summary） |
|------|-----------------------------------------------|------------------------|
| `host_compromise` TP | `WKS-HOST-007`、`svc-beacon-007`、`beacon.exe`、`beacon-example.test` | isolate + scan |
| `malicious_process` TP | `DEV-WKS-012`、`ransomware_stage.exe` | `block_process` |
| `insider_threat` TP | `svc-admin-abuse`、`SRV-ADMIN-003`、`net.exe` | `disable_account`；不要覆盖离职 U 盘案。存量 org allow 会经 H 抬这些块——预期 |
| `lateral_movement` TP | `JUMP-HOST-001`、`SRV-CORE-002`、`mstsc.exe`、`ops-jump-001`、`lateral movement` | 与 T1021 同词 |

可选 +1 条 `suspicious_domain` **uncertain**：内部工具域名 **不是** `brand-new-cdn-example.net`。账号/主机不要用 `office-user-014` / `PC-OFFICE-014`。

`account_anomaly` / `data_exfiltration` 历史已齐，本轮只核对、不堆。

`key_entities` 形如 `account=; host=; domain=; process=`。`summary` 中英关键名词各一次。`final_verdict` / `case_label` 用现有枚举。

历史 TP 用真阳实体；误报库不用。不要抄反。

---

## 6. `attack_kb`

**文件：** `attack_techniques.json`（约 79 条）。  
**做法：只改现有 ID，禁止新增 `T1021.001` / `T1570` 或其它不在 JSON 里的技术。**

对照句写进 `detection` / `description` / `keywords`。aliases 可补中文事件名，**遵守 §1.1 攻击 IOC 扩散黑名单**。

| EventType | 只加厚这些 **已有** ID | 本轮必须写入 keywords 的夹具词 |
|-----------|------------------------|--------------------------------|
| 账号 | T1078、T1110 | T1110 已有改密对照则 **不要再复制**；T1078 不加 `ops-change-bot`；**不要删** T1078 里的 `zhangsan` / `PC-FIN-023` |
| 内鬼/特权 | T1078、T1134、T1548 | T1134：`net.exe` |
| 外泄 | T1567、T1560.001 | 已有 7z / unknown-upload 则只补英文 `exfiltration`；**不要**给 T1048 再抄 7z |
| 域名 | T1566、T1608、T1189 | T1566 可留「可疑域名」；新注册域例句已有则不要再复制 |
| 失陷 | T1071、T1003、T1059 | **T1071：`beacon.exe`、`beacon-example.test`**。T1003/T1059 不加跳板、不加 `beacon.exe` |
| 恶意进程 | T1059、T1055、T1218 | **`ransomware_stage.exe`** 进 T1059 与 T1218 |
| 横向 | **仅 T1021**（已有 JUMP-HOST / mstsc / RDP）。T1047 只加 `WMI` / `lateral` 英文 | 不要新增 T1021.001、T1570 |

T1059 被失陷与恶意进程共用：keywords 可以同时有 `scripting` 与 `ransomware_stage.exe`；**不要**把 `beacon.exe` 和 `ransomware_stage.exe` 写进同一条 aliases。beacon 只留 T1071。

全量 STIX 只作离线升级。加载纪律见文首：全量 load-kb **每轮一次**。检索侧按 `technique_id` 去重（检索方案口径 I）；内容侧不要制造更多 ID。

---

## 7. 分期与验收

静态 JSON 绿 **不算**完成。种子测 + **§1.6 id 锁（RAGAgent 路径）** + **`eval-eventtype-8` 全 8 条** + persist **id**。

| 阶段 | 做什么 | 验收 |
|------|--------|------|
| **P0** | org：改密窗 + §2 deny/person_status | `occurred_at=2024-06-15T09:00:00Z` → `window`；特权现有 exact 仍在；横向无新增 JUMP-HOST allow；在职三条含「≠」 |
| **P0** | 剧本不加本 | `pb-c8d9e0f1` 唯一且第一步 `block_domain`；`pb-1c2d3e4f` 仍是唯一失陷本；内鬼/横向遏制本仍是 medium |
| **P0b** | **不做** | — |
| **P1** | 历史四条 TP + **加厚** `case-10000021` | `WKS-GEN-099` id 仍在；summary 含 unclassified；Emotet 无 `PC-FIN-023`；新 TP 的 summary 含进程名与处置词 |
| **P1a** | §4 正文（尤其 0d/0e）+ schema + §1.5 | metadata 有 `event_type`；**0e 不是 `suspicious_domain`**；**04/08 不是 `account_anomaly`**；**0b 不是 `data_exfiltration`**；0d 无 `PC-FIN-*` |
| **P1a 锁** | §1.6 **id** 锁（含 other 的 medium、特权/失陷的 high+medium） | 改密冠军 `01`；六条真阳冠军不是 `01`；内鬼冠军不是 `0d`；域名冠军不是未改的 `0e`。**不** assert `max_score < 0.7` |
| **P1b** | 扫描器/备份别名 | `svc-backup`、`vuln-scanner-01` 在正文；旧名仍在；重跑 §1.6 |
| **P1c** | **本轮不做** | — |
| **P2** | 加厚已有 T + 进程 keywords；**一次** load-kb | 横向 `attack_techniques` 非空；T1021 仍含 JUMP-HOST/mstsc；T1071 含 `beacon.exe`；**JSON 技术条数仍为 79**；T1110 仍是唯一含 `ops-change-bot` 的技术；T1078 detection 仍含 `zhangsan` |
| **P3** | 一次 load-kb 后 `eval-eventtype-8` | 8 条 A 档绿；persist **id** 满足 Cutover。记录（不必红）六条真阳的 `max_score`——检索 H 落地前预期可为 1.0 |

落地顺序：`org_context_seed.py` → 历史 TP + 加厚 10000021 → FP P1a（正文 → schema → §1.6）→ P1b → 攻击 P2 → **P3 eval**。剧本不动。禁止一次灌 8 条误报。禁止 P1a 未锁完就开检索 Host 扩写或 fp EventType 过滤。禁止循环 `make load-kb`。

测：

1. `test_knowledge_seed_files.py`（冻结表、`0e` 类型、0d/0e 禁词、T 条数=79、进程在指定 T、历史 summary、T1078 保留人名、内鬼/横向剧本 `min_severity=medium`）  
2. `test_keyword_aliases.py`  
3. §1.6 **RAGAgent 路径** id 锁  
4. `make load-kb` **一次**  
5. `eval-eventtype-8` 全 8 条；persist dump 核对 **id**，不要用 Job SUCCESS 或补刀后的 `final_verdict` 代替

---

## 8. 明确不做

- 不灌 DSP / pcap / 深信服开放列表 / `policy_controls` 第六库。  
- 不预置生产 org_context。  
- 不改 Mock URI、不把厂商串写进 Agent、不在 `keyword_aliases` 写死人名。  
- 不删除或改 kind 存量特权两条 allow。  
- 不把新的真阳写成 allow `account_role` / `allowed_source`。  
- 不加域名 low 剧本；不加 host medium；不把内鬼/横向遏制本的 `min_severity` 改回 high。  
- 不改 `change_windows.json` 迁就错误时钟。  
- 不把评测默认改成真 embedding。  
- 不把 `data_handling.hosts` / `.accounts` 当 catalog 命中。  
- 不把 04/08 标成 `account_anomaly`；不把 0b 标成 `data_exfiltration`；不把 07/09/`0e` 标成 `suspicious_domain`。  
- 不拆开 P1a。  
- 不新增 ATT&CK ID。  
- 不把改密/跳板/7z IOC 抄进多个 T；不删 T1078 现有人名例句。  
- 不把结案只写在 `resolution`。  
- 不新增 `allowed_destination` 门户。  
- 不在内容 PR 里改 Hybrid / C-RRF / QueryBuilder / VerdictResolver / **pipeline 归一化**。  
- **不在内容 PR 里 assert 六条真阳 `max_score < 0.7`。**  
- 不把 `eval-eventtype-8` 绿当成 id 锁的替代。  
- 不在 P1a 后立刻对 `fp_case_kb` 开 EventType SQL 过滤。  
- 本轮不加 P1c typed 误报。  
- 不循环 `make load-kb`。  
- 不对 `other` 开历史/误报存储层 EventType 过滤来「逼」`WKS-GEN-099`。
