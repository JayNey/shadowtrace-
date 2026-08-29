# RAG 五库内容补充方案

> 检索已经两阶段（先 `org_context_kb` 出约束，再对其余四库做 Constrained RRF）。空乏的是**句子和实体**，不是检索器。  
> 本方案只补演示知识内容，不改 Adapter、不灌 DSP / pcap / 深信服 OpenAPI。  
> `data/knowledge/policy_controls.json` 是合规映射，**不在五库里**，不要混进 RAG。

权威对照：`backend/app/agents/rag_agent.py`（`_KB_NAMES`）；`backend/app/knowledge/org_context_seed.py`；`data/knowledge/{attack_techniques,fp_cases,history_cases,playbooks}.json`；`backend/tests/test_rag/test_knowledge_seed_files.py`；`docs/eval-8-eventtype-gold-paths-plan.md` §4 主索。

加载：`make load-kb`。组织上下文走 Python 种子（Mock 才种，生产默认空）；其余 JSON 由现有 loader 入库。

---

## 0. 结论

不要灌百科。按 **8 条 EventType + 演示夹具原文** 补「能被检索命中、且不会把真阳打成误报」的对照样本。

优先级：**组织上下文 > 剧本 > 误报 / 历史 > 攻击技术**。

当前规模大约：攻击 79 条、误报 14、历史 21、剧本 13、组织上下文 14。够三条金路径对上号，不够看起来像「单位知识库」，也不够撑满 8 条 EventType 评测主索。

---

## 1. 总原则

1. **夹具原文优先**：实体必须对上 `seed_mock_xdr_and_ingest` 的 8 个场景，不要另造一套公司名。
2. **真阳实体禁止出现在误报行**：`PC-FIN-023` + `zhangsan`、`unknown-upload-example.com`、`brand-new-cdn-example.net`、`svc-admin-abuse` 只能出现在「这是威胁 / 这不是批准行为」的记录里。误报对照用邻近但不同的主机（已有 `PC-FIN-011`、`files.corp.internal` 这一套）。
3. **剧本 `tool_name` 只能用现有内核工具**：`query_*`、`isolate_host`、`disable_account`、`block_ip` / `block_domain`、`block_process`、`scan_host_for_virus`、`create_ticket`、`notify_security_team` 等。禁止厂商 URI。
4. **中英都要能搜**：`keyword_aliases` 把「内鬼 / 数据外泄 / 横向移动」映射成短英文 FTS。种子正文、`aliases`、`keywords` 里要同时有这些词，否则 Mock 嵌入下会漏。
5. **不要灌**：全量 ATT&CK STIX、pcap/NTA、DSP 日志、厂商开放列表。

### 1.1 八场景实体表（补库必须对齐）

| 场景 | EventType | 主机 | 账号 | 关键 IOC |
|------|-----------|------|------|----------|
| `account_anomaly_fp` | `account_anomaly` | `PC-OPS-JUMP-01` | `ops-change-bot` | 变更窗口改密 |
| `suspicious_domain_access` | `suspicious_domain` | `PC-OFFICE-014` | `office-user-014` | `brand-new-cdn-example.net` vs `cdn.corp.internal` |
| `insider_data_exfiltration` | `data_exfiltration` | `PC-FIN-023` | `zhangsan` | `7z.exe` / `finance_report.zip` / `unknown-upload-example.com` |
| `host_compromise` | `host_compromise` | `WKS-HOST-007` | `svc-beacon-007` | 外连 beacon |
| `insider_privilege_abuse` | `insider_threat` | `SRV-ADMIN-003` | `svc-admin-abuse` | 越权加组 |
| `malicious_process` | `malicious_process` | `DEV-WKS-012` | `dev-user-012` | 恶意进程 |
| `lateral_movement` | `lateral_movement` | `JUMP-HOST-001` → `SRV-CORE-002` | `ops-jump-001` | RDP / `mstsc.exe` |
| `other_unclassified` | `other` | `WKS-GEN-099` | `general-user-099` | 低置信未分类 |

---

## 2. `org_context_kb`（最先补）

**文件**：`backend/app/knowledge/org_context_seed.py`（可选 `ORG_CONTEXT_SEED_PATH` 覆盖）。  
**现在**：约 14 条。覆盖 fileshare / 备份窗 / 扫描器 / 跳板改密 / 未批准外发 / CDN / 特权滥用。缺「变更窗口」和 5 条新场景的主机事实。  
**用途**：Phase-1 约束。Matcher 吃 `kind` + `domains/hosts/accounts/windows`；`content` 给 LLM 讲「本公司规定」。  
**生产**：继续空。客户 CMDB 用种子路径灌，不要把演示单位写进生产镜像。

**目标总量**：25～35 条（建议 +12～18）。七类 `kind` 都要有，一条事实一句人话 + 结构化字段。

| kind | 补什么 | 对齐谁 |
|------|--------|--------|
| `time_window` | **变更窗口**（例如工作日 10:00–12:00 UTC），绑 `ops-change-bot` + `PC-OPS-JUMP-01` | FP 金路径现在只有夜间备份窗，改密场景没有自己的窗 |
| `account_role` | `ops-jump-001` = 跳板运维账号；批准行为是从 JUMP-HOST 做运维，**不批准** RDP 扫核心区 | 横向：避免「跳板账号 = 无条件合法」 |
| `allowed_source` / 负向 `data_handling` | `JUMP-HOST-001` 是批准跳板；`SRV-CORE-002` 不是该账号的日常登录目标 | 横向双主机 |
| `person_status` | `zhangsan` 在职财务；`office-user-014` 在职办公；`general-user-099` 在职、无特权；`contractor-temp` 已有离职 | 内鬼 vs 普通用户 |
| `account_role` | `svc-beacon-007` **不是**批准的可外连服务账号（或仅限 WKS-HOST 本机） | 主机失陷 |
| `account_role` | `dev-user-012` = 开发，允许编译/包管理，**不允许**无签名注入/远控 | 恶意进程对照 |
| `allowed_destination` | 已有 `cdn.corp.internal`；可再加一条办公终端允许的内部门户 | 域名场景只加强白名单，不要把新域写成允许 |
| `security_product` | 再 1～2 个内部安全域（与 FP 里 EDR 心跳同族） | 不要用公网厂商云域名冒充批准外连 |
| `data_handling` | 财务机密只走 `files.corp.internal`（已有）；补一句 U 盘 / 个人网盘不是批准通道 | 内鬼 USB 历史案例能对上 |

**不要补**：大段制度原文、等保条款、组织架构 PPT。

---

## 3. `playbook_kb`（第二优先，会真的驱动处置）

**文件**：`data/knowledge/playbooks.json`。  
**现在**：13 本。`host_compromise` 只有 high；`suspicious_domain` 只有 medium（一上来 `block_domain`）；`other` 只有低烈度分诊；两条 lateral 都偏封禁。  
**用途**：Response 按检索到的剧本填 `tool_name`。评测：恶意进程必须能绑到 `block_process` + `query_edr_process`；内鬼 medium 必须能绑到 `disable_account`。

**目标总量**：17～20 本（建议 +4～6）。

- **`host_compromise` medium**：先 `query_edr_process` → `scan_host_for_virus` → 工单；隔离放到 high。否则 medium 分会直接 isolate。
- **`suspicious_domain` low**：只 `query_dns` + `query_threat_intel` + 工单，**不要** `block_domain`。给「新域但可能是内部 SaaS」留退路；high/medium 维持现有封禁本。
- **`account_anomaly` 已够**：不要再加一本也会 `disable_account` 的 medium，以免 FP 被剧本拖进处置（FP 门禁是不得进 `planning_response`）。
- **`other` 保持禁止 isolate/block**：不要加 high 遏制本。
- 每本步骤写清 **precondition**（例如「目标不是 `files.corp.internal` / 不在变更窗口」）。
- `description` 里写 EventType 英文名 + 中文别名（`malicious process` / `恶意进程`），方便 FTS。

**不要补**：没有 Registry 的工具名、厂商工单字段、人工 SOP 长文。

现有必须保住的回归锚（`test_knowledge_seed_files.py`）：

- 恶意进程本含 `block_process` 与 `query_edr_process`
- `pb-3c4d5e6f`（内鬼遏制）`min_severity=medium`，第一步 `disable_account`
- `pb-2a3b4c5d`（横向遏制）第一步 `block_ip`

---

## 4. `fp_case_kb`（第三，分诊打分）

**文件**：`data/knowledge/fp_cases.json`。  
**现在**：14 条。金路径负例只有改密、fileshare、CDN。扫描器 FP 写的是 `SCANNER-01`，组织上下文是 `vuln-scanner-01` / `10.20.0.15`，检索对不齐。  
**用途**：`fp_similarity.matched_case_id`。`account_anomaly_fp` 必须稳定命中 `case-00000001`。

**目标总量**：约 22 条（建议 +8）。每类 EventType 至少 1 条「长得像但不是金路径」的误报。

| EventType | 补什么 | 明确写「不是谁」 |
|-----------|--------|------------------|
| `host_compromise` | 授权渗透 / 已签名运维脚本无文件执行 | 不要用 `WKS-HOST-007` |
| `malicious_process` | 合法远程工具或开发机包安装（已有 K8s HPA 可保留） | 不要用 `DEV-WKS-012` |
| `insider_threat` | 发版前主管审代码 / PAM 签出查库 | 不要用 `svc-admin-abuse` 或 `zhangsan` |
| `lateral_movement` | SCCM / WinRM 补丁窗（历史里已有，FP 库缺同实体） | 不要用 `JUMP-HOST-001` |
| `other` | 低置信未分类、门禁 / DHCP 类 | 不要把 `WKS-GEN-099` 写成误报金句（历史已承担 `similar_cases`） |
| `account_anomaly` | 已有 `case-00000001`；把扫描器实体改成与 org 一致 | 对齐 `vuln-scanner-01` |
| `data_exfiltration` | 已有 fileshare 负例；夜间备份改为 `svc-backup` + `files.corp.internal` | 不要再用检索对不上的 `BACKUP-SRV-03` |
| `suspicious_domain` | 已有内部 CDN 负例；可加 EDR 心跳对 `carbonblack.corp.internal` | 不要把 `brand-new-cdn-example.net` 写成误报 |

每条固定六段：`pattern_summary`、`alert_signature`（英文，给 FTS）、`entity_pattern`、`fp_reason`、确认人、时间。`alert_signature` 必须短、像告警标题。

---

## 5. `history_case_kb`（第四，报告「以前怎么结」）

**文件**：`data/knowledge/history_cases.json`。  
**现在**：21 条，八类都有，但新 5 场景的**夹具实体**几乎没进历史：没有 `WKS-HOST-007`、`DEV-WKS-012`、`JUMP-HOST-001`、`svc-admin-abuse` 的结案故事。`other` 已有 `WKS-GEN-099`，不要动。  
**用途**：`similar_cases`。`other_unclassified` 要求非空且能对上 `WKS-GEN-099`。

**目标总量**：约 30 条（建议 +8～10）。每类 EventType 维持 TP + FP/uncertain 各至少 1。

- `host_compromise` **TP**：`WKS-HOST-007` / `svc-beacon-007` 外连 C2，结案隔离 + 扫描。另留一条 FP/uncertain 用别的主机（已有 `WEB-APP-05` 可保留）。
- `malicious_process` **TP**：`DEV-WKS-012` 上具体进程名（与 pack 的 `_scenario_process_name` 一致），结案 `block_process`。
- `insider_threat` **TP**：`svc-admin-abuse` 在 `SRV-ADMIN-003` 加本地管理员组；**不要**覆盖已有离职 U 盘案。
- `lateral_movement` **TP**：`JUMP-HOST-001` RDP 到 `SRV-CORE-002` / `mstsc.exe`，与 T1021 关键词一致。
- `suspicious_domain`：金路径 TP 已有 `brand-new-cdn`；可再加一条低分 uncertain（新内部工具域名），避免模型只会封禁。
- `account_anomaly` / `data_exfiltration`：金路径已齐，只对齐实体，不再堆同类。

`key_entities` 用 `account=; host=; domain=` 这种可 FTS 的串；`summary` 中英关键名词都出现一次。`final_verdict` 只用产品枚举：`confirmed_threat` / `false_positive` / `none` / `possible_false_positive`。

Emotet 历史案不得再占用 `PC-FIN-023` / `zhangsan`（已有回归测）。

---

## 6. `attack_kb`（最后，别上全量）

**文件**：`data/knowledge/attack_techniques.json`（v15.1 子集）。仓库里另有 `data/knowledge/stix/attack_enterprise_v15_1.bundle.json`，**演示默认不整包加载**。  
**现在**：79 条。金路径别名已有（内鬼、7z、数据外泄、可疑域名、JUMP-HOST-001/RDP）。大量条目没有 `keywords` / `aliases`，检索全靠英文 description。  
**用途**：报告 / 图谱旁路的技术名；横向评测要 `attack_techniques` 非空。

**做法**：改现有 79 条，不要扩到 600。为 8 类事件各钉 2～4 个 T 编号，补中文 `aliases` + 短 `keywords`（含 EventType 英文、演示进程/协议）。**不要**把 `zhangsan` 写进别名表——IOC 放 `detection` 例句即可。

| EventType | 优先 T 编号 |
|-----------|-------------|
| 账号 / 内鬼 | T1078、T1110、T1134 |
| 外泄 | T1567、T1560.001、T1048 |
| 域名 | T1566、T1608、T1189 |
| 失陷 | T1003、T1059、T1071 |
| 恶意进程 | T1055、T1059、T1218 |
| 横向 | T1021、T1021.001、T1570、T1047 |
| 特权 | T1548、T1078、T1136 |

每条 `detection` 加 **一句对照**：批准行为 vs 威胁（备份到 files.corp vs 7z 外发；跳板改密 vs 密码喷洒；内部 CDN vs 新注册域）。这是 Constrained RRF 真正用得上的句子。

全量 STIX 只作离线升级选项。不要补移动 / ICS 矩阵或中文维基长文。

---

## 7. 分期与验收

| 阶段 | 做什么 | 验收 |
|------|--------|------|
| **P0** | org：变更窗口 + 5 条新场景主机/账号事实 | `insider_privilege_abuse` 仍能 exact match；横向 / 失陷检索能讲出「是否批准」 |
| **P0** | playbook：host medium、domain low | `malicious_process` 仍有 `block_process`；`other` 仍无 isolate |
| **P1** | 对齐 FP 扫描器实体；每类 EventType 一条不撞车的 FP | `account_anomaly_fp` 仍命中 `case-00000001` |
| **P1** | 历史：四条新场景 TP 用夹具原文 | `other_unclassified` 仍命中 `WKS-GEN-099` |
| **P2** | attack：八类 T 编号补齐 aliases / detection 对照句 | 横向 `attack_techniques` 非空；中文「内鬼 / 外泄」回归仍绿 |

改完种子后：

1. `backend/tests/test_rag/test_knowledge_seed_files.py`
2. `backend/tests/test_rag/test_keyword_aliases.py`
3. `make load-kb`

不要把金路径实体抄到无关 FP / 历史行上。落地时建议先改 **org_context_seed.py + playbooks.json**（对演示话术和处置绑定最明显），再分批加 FP / 历史 / 攻击，避免一次灌库把金路径检索打偏。

---

## 8. 明确不做

- 不把 DSP / pcap / 深信服开放列表写进五库。
- 不把 `policy_controls` 扩成第六 RAG 库。
- 不为「看起来丰富」复制同质误报。
- 生产环境继续 **不预置** org_context。
- 不改 Canonical Mock URI、不把厂商字符串写进 Agent。
