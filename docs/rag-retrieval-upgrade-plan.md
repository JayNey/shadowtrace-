# RAG 检索代码优化方案

> 只做对 **本仓库告警闭环** 有效果的改动。对标 Dify/扣子是为了补精度缺口，不是把产品做成通用文档问答。  
> 内容补库见 `docs/rag-kb-content-plan.md`。本文件只动检索代码；**但 P0 召回依赖内容里已有夹具原文**，见 §9。  
> 金路径默认仍是 `EMBEDDING_MODE=mock` + keyword（`docs/eval-8-eventtype-gold-paths-plan.md`）。**禁止**把评测默认改成真向量来「假装变强」。  
> 8 条 A 档（`eval-eventtype-8`）已经按 persist + Job SUCCESS 绿过。本方案任何改排序 / 改 `fp_similarity` 组装的步骤，**单测绿不算过门**，见 §7。

**2026-08-29 深度修订（仍有效）：** 有效 FP 匹配不是只看最高块；`other` 永不 EventType 硬过滤；历史硬过滤要种子 **且** 能进 `fetch_k`；glob 不是精确命中；扩写与 `L_E` 按库收窄；剧本过滤空之前先排除 release pin；P0 必跑横向。

**2026-08-29 对照代码二次修订（仍有效）：** 对照 `keyword_aliases.keyword_queries_for_kb`（fp 前 2 个实体做 `plainto_tsquery` **AND**）、`constraint_rrf._token_bounded`（`-` **不是** token 内部）、`load_attack_kb`（metadata **只有** `technique_id`）、`_materialize_attack_chunks`（`chunk_id` 含 `release_id`）、`_build_fp_similarity`（仍取最高块）。作废：P0 只扩写 Host、P1 才改组装；复用 `_token_bounded`；攻击去重只认 `object_id`。

**2026-08-29 三次修订（执行前必读）：** 对照 `keyword_queries_for_kb` 的 **`_dedupe(..., limit=2)`：extras 先入队会把实体 AND 挤掉**；套件门 `max_score ≥ 0.7`。作废或改写：以为扩写了 Host 则 FTS 一定发出 `ops-change-bot PC-OPS-JUMP-01`；口径 H 选中非第一名的 `01` 却上报该块原始 RRF 分（常 < 0.7，改密金路径 id 对仍红）。正确合同见 **§0.1 M–N、§1.1.1、§1.2、§5**。

权威对照：`backend/app/rag/pipeline.py`、`hybrid_retriever.py`（`fetch_k = top_k * 2`，默认 10）、`context.py`（`storage_filters_for_kb` **只在** `query_plan.kb_name==kb` 时返回 typed_filters）、`constraint_rrf.py`（`_token_bounded` 的 lookaround 是 `[a-z0-9]`，**不含** `-`）、`reranker.py`、`rrf_fusion.py`（按 `kb_name:chunk_id` 融合）、`keyword_aliases.py`（fp：`entity_like[:2]` 拼成一句 AND；`limit=2`）、`agents/rag_query_builder.py`、`agents/rag_agent.py`（history/fp 的 `query_plan` 为 `None`）、`agents/risk_agent.py`（`fp_similarity.max_score >= 0.7`）、`services/knowledge_store_prefilter.py`（`typed_filter_clause` **只**认 `source_id` / `content_type`）、`services/attack_kb_service.py`、`services/knowledge_release_service.py` `_attack_pattern_to_chunk`、`models/case.py`、`models/knowledge_release.py` `KnowledgeFilterKind`、`data/knowledge/fp_cases.json`（`0d`=`host=PC-FIN-*`，`01` 有精确 `ops-change-bot` / `PC-OPS-JUMP-01`）。

---

## 0. 结论：追什么、不追什么

现有骨架已经是扣子同族（改写 → 向量+FTS → RRF → rerank），外加组织约束 C-RRF。再抄 Dify 的父子分段、多模态、NL2SQL、加权滑条，**不会提高** 八类 EventType 的命中。

上一稿把「实体感知」做成只给候选池加 `L_E` 票。那是 **rerank 不能补召回**：`HybridRetriever` 每路只取 `top_k*2`（默认 10）。误报库 14 条时，mock 向量已把 `case-0000000d` 排在 `case-00000001` 前——块若不在池里，精确实体票抬不起来。本修订把 P0 做成 **查询扩写 + 去重 + `L_E` + 误报组装**。扩写与组装拆开 = 内鬼 Host 扩写把 `0d` 顶得更死。

要追赶 / 超越的只有这些：

| 优先级 | 改什么 | 为什么对本仓库有效 | 明确不做 / 会变弱的替代 |
|--------|--------|-------------------|------------------------|
| **P0-a1** | 查询扩写 + **实体 AND 占住 keyword 2 路之一** | 误报查询今天只有 `Account:`；且 extras 会占满 `limit=2`，实体 AND 发不出去 | 只改 QueryBuilder 不改 `keyword_queries_for_kb`；进程进 AND；白名单域名进 fp query |
| **P0-a2** | 实体感知融合 `L_E`（池内**精确**票；fp 上有命中块必须排在 0 命中之前） | mock 向量无语义；`L_C` 仍会用 `_token_bounded` 抬 `0d` | 复用 `_token_bounded` 当 `L_E`；误报 `L_E` 吃批准域名 |
| **P0-c** | 融合前按 **`technique_id`** / `case_id` / `playbook_id` 去重；fp 的 `fetch_k` 提到盖住全库 | JSON 无 `object_id`；误报 14 条、默认 `fetch_k=10` | 只按 `object_id`；冲突只留向量最高分 |
| **P0-d** | FP 组装：第一个精确命中块 **提到第一再取分**（与 a1 同一 PR） | 只看最高块会吞 glob；选中埋着的 `01` 却用它的 0.3 分，套件 `≥0.7` 仍红 | P0 只扩写；只看 top-1 无效就整表清空；上报非第一名的原始 RRF 分 |
| **P0-b** | EventType 预过滤（剧本 **先做**；历史见 §2.2 闸门） | 错类型剧本会带偏 `playbook_refs[0]`。历史硬过滤会让组装 fail-soft 失效 | 不对误报库切片；不把 filter 挂进现有 `storage_filters_for_kb`；**不对 `other` 注入**；给 `KnowledgeFilterKind` 加导出成员却不改 Retriever SQL |
| **P1** | 真 Rerank（仅 `RERANK_MODE=remote`）+ mock 跳过锁死 | 对齐扣子「结果重排」；只在真 embedding 时有精度 | mock 下 `L_C`/`L_E` 命中后仍跳过 rerank |
| **P1** | 可选 `FP_ASSEMBLE_MIN`（标定后） | 未标定的 0.35 对 mock 形同虚设 | 未标定就上门槛；清空 id 却保留高分 |
| **P2** | 可选真 embedding 演示轨 | 语义近似需要真向量；与 mock 金路径 **分轨** | 不改 eval 默认 `EMBEDDING_MODE` |

**降级（原「始终 rerank」）：** `pipeline.py` 在 `constraint_channel` 时跳过 rerank，对 **mock** 是保护票。Mock rerank 是 `0.65*RRF + 0.35*token overlap` 再对 top_k min-max，会拆掉 `L_C` / `L_E`。始终 rerank 只允许 remote 轨，见 §3–§4。

`should_skip_query_rewrite` 已会跳过带 `event type` 的查询。再加 `Host:` **不会**重新打开 LLM 改写。**禁止**为了「扩写后还要改写」去关掉这条 skip。

下面「明确不做」见 §8。冻结实现口径见 **§0.1**。

### 0.1 冻结实现口径（禁止实现时二选一）

这些条若做成「看起来差不多」的替代，8 条 A 档会回红。实现 PR 必须按此字面，不要自行简化。

| # | 口径 | 禁止的替代 |
|---|------|------------|
| A | 抽出函数 **一份**；扩写与 `L_E` 都先 `project_entities_for_kb(kb, E)` 再使用 | 融合收窄、扩写用全量 `E`；`pipeline.py` 与 `rag_query_builder.py` 各写一套正则 |
| B | **精确命中** = §1.2.1。glob / 前缀 / 中缀 **不是**命中 | `PC-FIN` 抬 `PC-FIN-023`；`PC-FIN-*` 匹配 `PC-FIN-023`；`in` / `startswith`；整段 `entity_pattern == "ops-change-bot"` |
| C | fp query **只**追加账号、主机、进程（告警 IOC）。**禁止**域名、IP、白名单 `allowed_destination` | 把 evidence 里的 `files.corp.internal` 写进误报 query |
| D | fp **标注顺序锁死**：`Account:` → `Host:` →（可选）`Process:`。账号 ≤4、主机 ≤4、进程 ≤3。keyword 路只用前两个实体 AND（见 §1.1.1）。`L_E` 的 `E` 可以含进程，**query 的 keyword AND 不要含进程** | 进程写在 Host 前面；把 evidence `related_entities` 全写进 fp query |
| E | `EventType.OTHER` 与无法解析的类型：**永不**注入存储层 EventType 过滤（剧本、历史、误报都不注入） | 「history 已有 other 种子所以对该类型开过滤」 |
| F | 历史硬过滤 = 内容已有该类型种子 **且** 检索冒烟证明同类型块能进该类型事件的 `fetch_k`。缺一不可 | 只数 JSON 行数 ≥1 就关 fail-soft |
| G | 剧本过滤后 0 条：先看 active playbook release 的块是否带 `embedding_release_id`。pin 空 → `degraded_steps+=playbook_release_pin_empty`，**不要**标成「该类没剧本」。pin 正常且类型过滤空 → `event_type_filter_empty`，保持空 refs，**禁止**回退全库 | 过滤空就去掉 filter 再查；把 release 空当成内容缺口去灌错类型本 |
| H | FP 有效匹配：融合序从前往后第一个对 fp 允许 `E` 精确命中的块。命中后 **先提到该 kb 结果第一**，其 `score` **改为提权前的 `max(score)`**，再写入 id 与 `max_score`。没有则 id 与分一起清空。**属 P0，与 §1.1 同一 PR** | 只检验 top-1；P0 扩写、P1 再组装；top-1 无效就清空后面的 `01`；选中 `01` 却上报 0.35；只改 FpSimilarity 不改 `chunks[0]` |
| I | 攻击去重键：`metadata.technique_id` → 否则 `object_id` → 否则 `chunk_id`。冲突时 **先**留 `E_kb` 精确命中更多的块，再留带 `keywords`/`aliases` 的块，最后才是 `score` | 只按 `object_id`（JSON 种子没有这个键）；一律留向量分最高（STIX 长描述可能压过带 `JUMP-HOST-001` 的 JSON 份） |
| J | `L_E` / FP 组装 **同一**命中函数（§1.2.1）。**禁止**调用 `constraint_rrf._token_bounded` / `constraint_hits_text` | 连字符当词边界（`PC-FIN` 命中 `PC-FIN-023`）；把 glob 编译成正则 |
| K | EventType 预过滤走 `RetrievalContext` + Retriever/store **旁路 SQL**。`typed_filter_clause` 今日忽略未知 kind。**默认不**把 `EVENT_TYPE` 加进导出的 `KnowledgeFilterKind` / query-plan OpenAPI | 只改 `storage_filters_for_kb`；给枚举加成员却不改 HybridRetriever/store；silent contract drift |
| L | fp 的 Host 扩写 **不得**单独合入。没有口径 H 的组装，禁止把 `PC-FIN-023` / `PC-OFFICE-014` 写进误报 query（`simple` 分词会把它们和 `PC-FIN-*` / `PC-OFFICE-*` 撞在一起） | 「先合扩写看评测、组装下个 PR」 |
| M | `fp_case_kb` / `history_case_kb` 的 keyword **2 路必须留 1 路给实体 AND**（建议第一路 = `Account+Host` 那句）。alias extras 最多占另一路。实现上要改 `keyword_queries_for_kb` 的入队顺序，不是只扩写 verbose query | 保持今天「extras 先 append 实体再 `limit=2`」；以为 QueryBuilder 写了 `Host:` 则 FTS 一定带上它 |
| N | fp 库：`L_E` 命中数 > 0 的块 **必须**排在命中数 = 0 的块之前（稳定次序：命中数 ↓，再 RRF）。这是给 `L_C` 仍抬 `0d` 时的融合层补丁 | 只靠组装扫描、融合序仍是 `0d` 第一且 `01` 分 < 0.7 |

---

## 1. P0-a 实体进查询 + 池内 `L_E` + 去重 + 误报组装

### 1.0 失败模式（本条就是为这个写的）

融合通道 **不能** 把未召回的块变出来。因此：

1. 先改 query，让正确卡进入 `fetch_k` 池。  
2. 再在池内用 `L_E` 把精确实体命中排到前面。  
3. 误报出口 **不要**把「最高分但只是 glob/分词撞车」的块当成已匹配。  
4. 实体 AND 必须真的作为 FTS 的一路发出去（口径 M）。只改 verbose query、不改 `keyword_queries_for_kb` 入队顺序 = keyword 路仍可能只有 `valid accounts` + `change window`。  
5. 精确命中若不是融合第一，**先提权再取分**（口径 H/N）。否则改密条 `matched_case_id` 对了、`max_score` 仍 < 0.7。  
只做 2 = 金路径增益落空。做 1 不做 3 = 内鬼 Host 扩写把 `0d` 顶成 Risk 误报门。做 1+3 不做 4/5 = 评测间歇性假红。

`fetch_k` 被重复块占满，效果等于正确卡不在池里。去重（口径 I）与扩写一起做。

### 1.1 查询扩写（召回）

落点：`RAGQueryBuilder.build_queries`。实体来自 **Triage `EntitySet` + evidence 实体**（与 §1.2 同一抽出函数，再经 `project_entities_for_kb`）。禁止只靠 `keyword_aliases._LABELED_ENTITY` 扫已生成的 query——但扩写 **必须**产出该正则能吃的 `Account:` / `Host:` / `Process:` 标签（已有，大小写不敏感）。

| 库 | 今天 | 改成 |
|----|------|------|
| `fp_case_kb` | EventType + severity + reasoning + **仅 Account:** | 按 **Account → Host → Process** 追加（改密缺的是 `PC-OPS-JUMP-01`）。**不要**写 Domain / IP / `files.corp.internal` / `cdn.corp.internal`。与 §5 **同一 PR** |
| `history_case_kb` | 已有较完整 Host/Account/Domain/Process | 改用抽出函数 + 按库投影，去重要求与 `EntitySet` 一致。条数上限与今天同级（Host/Account ≤5，进程 ≤3，Domain ≤4）。keyword 仍最多前 2 个 token AND，**不要**把 5 个 Host 写进同一句 `plainto_tsquery` |
| `attack_kb` | type + hint + 行为摘要；实体较少 | 追加 **进程名优先**，然后 Host/Account（横向：`mstsc.exe`、`JUMP-HOST-001`）。官方 ATT&CK 正文往往没有夹具主机名，演示 JSON 块才有 |
| `playbook_kb` | 只有 type + severity | **保持**。剧本正文几乎没有夹具主机；扩写实体会变成噪声，类型过滤才是剧本主杠杆 |
| `org_context_kb` | 已有实体 | **不改**（exact matcher 是另一条路） |

抽出规则与 §1.2 共用：值 trim 后长度 ≥ 3（`7z.exe` 可以，单独 `7z` 丢给 aliases，不要当实体）。禁止把前缀写进 query（不要写 `PC-FIN`，要写完整 `PC-OPS-JUMP-01` / `PC-FIN-023`）。生产别名表 **禁止** 写死 `zhangsan` / `ops-change-bot`。

**按库投影（扩写与投票同一张表）：**

| 库 | query 允许 | `L_E` 允许 |
|----|------------|------------|
| `fp_case_kb` | 账号、主机；进程 **可以出现在 query 末尾** 但 **不得**进入 keyword AND（§1.1.1） | 账号、主机、进程名。**排除**域名、IP、组织批准对端 |
| `history_case_kb` | 账号、主机、域名、进程、IP（前两个进 keyword AND） | 同左 |
| `attack_kb` | 进程优先，然后主机/账号；域名/IP 可选且不得压过进程 IOC | 同左 |
| `playbook_kb` | 不追加实体 | 允许投，通常 0 命中 |
| `org_context_kb` | 不改 | **不投** `L_E` |

白名单域名的权威名单与内容方案 / org 种子一致：至少 `files.corp.internal`、`cdn.corp.internal`、`carbonblack.corp.internal`。实现用「org allow 类约束里的 domains」**加上**这一短名单，不要只扫 query 字符串里有没有 `internal`。

#### 1.1.1 fp / history 的 keyword AND（必须按这个接）

`KnowledgeStore.keyword_search` 用 `plainto_tsquery('simple', :q)`——句内 token 是 **AND**。今天的 `keyword_queries_for_kb`：

- `fp_case_kb`：`ordered = extras` 先入队，再 `append(" ".join(entity_like[:2]))`，再 `event_fts`，最后 **`_dedupe(..., limit=2)`**。改密查询里 extras 经常已是 `valid accounts` + `change window` → **实体 AND 被丢掉**，Host 扩写对 FTS 无效。
- `history_case_kb`：`tokens[:2]` 同样 AND，同样会被 extras 挤掉。
- `_looks_like_entity` 要求 token 含 `-` / `_` / `.`。

**P0 必须改入队顺序（口径 M），不是只改 QueryBuilder：**

1. **第一路（锁定）**：实体 AND。fp = 标注序下前两个 entity-like，改密必须是 `ops-change-bot` + `PC-OPS-JUMP-01`。history = 投影后的前两个实体（不要 5 个 Host 写进同一句）。  
2. **第二路（可选）**：一条 alias extra 或 `event_fts`，不得再占第三路。  
3. **禁止**保持「extras 全部先 append、实体最后、limit=2」。  
4. fp 标注必须先 `Account:` 再 `Host:`。**禁止**让 `Process:…` 成为前两个 entity-like。  
5. 进程仍可给 `L_E` 和向量用的 verbose query 末尾；**不要**进这句 AND。  
6. 单测：扩写后的 fp query 经 `keyword_queries_for_kb("fp_case_kb", q, limit=2)`，返回列表里 **必须含** `ops-change-bot` 与 `PC-OPS-JUMP-01` 同时出现的那一路（改密夹具）。今天的实现过不了这条，所以这条测是 P0 准入。

内鬼会变成 `Account:zhangsan Host:PC-FIN-023`。`simple` 分词仍可能把 `0d` 的 `PC-FIN-*` 召进池——所以必须同 PR 做口径 H + N，不是扩写写错了。

向量路吃的是 **整句** verbose query。扩写会改变 mock 哈希排序，组装必须同时改。

#### 1.1.2 fp 的 `fetch_k` 托底

误报库现在 14 条，`HybridRetriever` 默认 `fetch_k = top_k * 2 = 10`。实体 AND 被挤掉时向量只看 10 条，`01` 可能根本不进池。

P0：对 **`fp_case_kb` 单独** 把 `fetch_k` 提到 `max(top_k * 2, 16)`（盖住当前 14 条即可）。其它库维持 `top_k * 2`。这是召回托底，**不替代**口径 M。不要把全局 `fetch_k` 改成 50。

### 1.2 融合票 `L_E`（排序）

在 RRF 里增加一路 `L_E`，与 C-RRF 的 `L_C` 同构：

```
C-RRF(L_vec, L_kw… ; H, E) = RRF(lists + [L_C?] + [L_E?])
```

- `E_raw` = 抽出函数。`E_kb = project_entities_for_kb(kb, E_raw)`。单账号也要投票（改密常常只有 `ops-change-bot`）。空 `E_kb` ⇒ 该库不投 `L_E`，与现在恒等。
- `L_E` = 去重后的候选池按「命中了多少个 `E_kb`」（§1.2.1）排序，命中数为 0 的块不进 `L_E` 通道。  
- **fp 库额外（口径 N）：** 融合完成后（或融合后对 fp 列表做稳定重排）：精确命中数 > 0 的块必须排在 = 0 的块之前，再按 RRF。原因：`L_C` **仍使用** `_token_bounded`，内鬼/改密上 `files.corp.internal` 会继续抬 `0d`。只靠 `L_E` 当 RRF 的一路投票，`0d` 仍可能总分第一。N 是融合层补丁，H 是组装层补丁，两层都要。  
- **按库收窄**见 §1.1 表。禁止一套实体打所有库。
- `H` 仍只含 allow 类组织约束。`L_E` **不**替代 exact org match，也不产生 `OrgContextMatch`。
- `playbook_kb`：允许投 `L_E`，通常 0 命中 ⇒ 与现在恒等。不要为了「四个库都投票」去改剧本正文塞主机名（内容方案禁止，也会改 `playbook_refs[0]`）。
- `org_context_kb`：**不要**打 `L_E`（exact matcher + `L_C` 会双计）。

落点：抽出 + 按库投影 + 精确命中集中一处（建议 `entity_rrf.py`）。**禁止**从 `constraint_rrf` import `_token_bounded`。`pipeline.py` / `rag_query_builder.py` **禁止**再写一套正则。

#### 1.2.1 精确命中函数（`L_E` 与 FP 组装共用）

对实体字符串 `e`（已 lower/trim）和一块 chunk，**命中**当且仅当下列之一为真。含 `*` 的种子值、或以 `-`/`*` 结尾的 glob **永远不命中**任何具体夹具值。

1. **字段解析全等。** 从 `entity_pattern`、`key_entities`、chunk `content`、以及 metadata 里字符串化的字段，解析 `host=` / `account=` / `process=` / `domain=` 右侧 token（遇 `;` 或空白结束）。右侧与 `e` 全等（大小写不敏感）。`host=PC-FIN-*` 含 `*` → 丢弃，不得匹配 `PC-FIN-023`。  
2. **连字符感知的整词。** 在 `content` + `entity_pattern` + `key_entities` 上：

   ```
   (?<![a-z0-9-]) + re.escape(e) + (?![a-z0-9-])
   ```

   与 `_token_bounded` 的差别：lookaround 是 `[a-z0-9-]`。因此 `pc-fin` **不会**命中 `pc-fin-023`；`pc-fin-023` **不会**命中 `host=pc-fin-*`。

**禁止：**

- `e in text` / `startswith` / `fnmatch` / 把 `*` 当正则。  
- 要求整段 `entity_pattern == e`（永远假，`L_E` 会 0 票，改密也抬不起来）。  
- 调用 `_token_bounded`（`-` 当词界，`PC-FIN` 会抬 `PC-FIN-023`）。  
- 用 C-RRF 的域名后缀规则给主机/账号投票。

### 1.3 融合前去重（P0-c）

`load_attack_kb` 按 `technique_id` + `attack_version` 生成稳定 `chunk_id`，metadata **有 `technique_id`、无 `object_id`**。  
`load_attack_stix_release` → `_materialize_attack_chunks` 再 upsert 一份，`chunk_id` 含 **`release:{release.release_id}`**，metadata 才有 `object_id`。重复 activate / `make load-kb` 会留下同一 T 的多份不同 `chunk_id`。`rrf_fuse` 按 `chunk_id` 融合，citations 里 T1021 可以出现 4 次，`fetch_k=10` 被占满。

**做法：** 每路 store 结果、以及 RRF 输入前：同一 kb 内按稳定键去重。

| kb | 去重键 |
|----|--------|
| `attack_kb` | `metadata.technique_id` → 否则 `object_id` → 否则 `chunk_id` |
| `fp_case_kb` / `history_case_kb` | `metadata.case_id` |
| `playbook_kb` | `metadata.playbook_id` |
| `org_context_kb` | 不在本条范围（matcher 另路） |

同一键多块时的保留顺序（**禁止**简化成 `max(score)`）：

1. §1.2.1 对当前 `E_kb` 命中数更多；  
2. metadata 含非空 `keywords` 或 `aliases`（演示 JSON 份通常有夹具 IOC）；  
3. `score` 更高。

这样横向扩写 `mstsc.exe` / `JUMP-HOST-001` 时，不会只留下 STIX 长描述、把 JSON 种子挤出池。

本条 **不**改 Makefile / 不禁止 `load-kb`。内容方案仍要求 load STIX release。检索必须能在「库已膨胀」时仍把正确技术留在池里。fp 的 `fetch_k` 见 §1.1.2。

---

## 2. P0-b EventType 预过滤（剧本先做；历史按闸门，other 永不）

现状：

- Response 用的 `playbook_refs` 来自 **HybridRetriever**，不是 `PlaybookKBService.search_playbooks`（后者另有 `metadata->>'event_type'` SQL）。向量路仍可能召回错类型剧本。`ResponseAgent` 吃 `playbook_refs[0]`：同类型里 investigation 本排在 containment 前，是内容/排序问题，**不是**本阶段用类型过滤能修的。不要靠给剧本塞主机名来改 `[0]`。
- `history_case_kb`：`_build_similar_cases` 同类型优先、空则 fail-soft——这依赖结果里 **还留着** 错类型块。A 档 `other_unclassified` 已绿，靠的就是 fail-soft 非空，不是命中 `WKS-GEN-099` 那一行。
- `fp_case_kb`：`fp_case_metadata()` 无 `event_type` 键。等值过滤结果恒为 0。等内容方案 P1a。
- `RAGAgent._retrieve_for_kb`：只给 `attack_kb` / `playbook_kb` 设 `query_plan`。`history_case_kb` / `fp_case_kb` 的 plan 为 `None`。
- `RetrievalContext.storage_filters_for_kb`：`query_plan is None or kb_name 不匹配` ⇒ **返回空 typed_filters**。把 EventType 挂在这里，历史库过滤是空转。
- `KnowledgeFilterKind` 只有 `source_id` / `content_type`（`time_*` 校验拒绝）。`typed_filter_clause` **不会**为未知 kind 生成 SQL。把 `EVENT_TYPE` 塞进已签名 plan 会契约失败或 `check-contract-drift`。
- playbook / attack 的 plan 还 pin `embedding_release_id`。类型过滤与 pin **AND**：pin 未盖章时过滤空 ≠ 没剧本。恶意进程 A 档曾经因此 `playbook_refs=[]`。

**禁止的挂法：** 只改 `storage_filters_for_kb`；给导出 OpenAPI 的 `KnowledgeFilterKind` 加 `event_type` 却不改 Retriever；以为改枚举 `typed_filter_clause` 就会自动发出条件。

**正确挂法：**

1. `RetrievalContext` 增加与 plan 无关的字段，例如 `event_type: EventType | None`。`RAGAgent._retrieve_for_kb` 对 **每一个** kb（含 history/fp）传入同一 context 字段；不要指望 history 的 `query_plan`。  
2. `HybridRetriever` 在调用 store 前，按 **当前 kb_name** 决定是否附加 `metadata->>'event_type' = :event_type`。与 plan 的 `source_id`/`content_type` **以及** 已有 `embedding_release_id` **AND**，不要覆盖 pin。  
3. SQL 写在 store 预过滤（扩展 `typed_filter_clause` 的 **内部** 旁路，或 Retriever 传入额外 clause）。**不必**把该 kind 放进对外 KnowledgeQueryPlan schema。若非加枚举不可：本阶段必须带契约 PR，且 Retriever 仍要走这条 SQL，不要 silently drift。  
4. 注入条件：context 的 `event_type` 是**具体非 `other` 的** `EventType`，且 kb ∈ 下面允许集合。`other` / 未知 / `None` **不**注入（口径 E）。

### 2.1 按库

| 库 | 本阶段 | 空结果 |
|----|--------|--------|
| `playbook_kb` | **P0 做**（`other` 除外）。有 `event_type` metadata | **先**判定 release pin：active 剧本块 0 条带 `embedding_release_id` → `playbook_release_pin_empty`，本阶段不要用类型过滤空当验收。pin 正常且类型过滤 0 条 → **保持空** refs，`degraded_steps+=event_type_filter_empty`。**禁止**去 filter 再查全库 |
| `history_case_kb` | 见 §2.2。`other` **不开** | 一旦对该类型开硬过滤：0 条就是 0 条。组装 fail-soft **失效**。**禁止**检索层再查一遍未过滤结果把错类型灌回 top_k |
| `fp_case_kb` | **不做** 等值过滤，直到内容方案 P1a 写入 metadata 并迁移 | — |
| `attack_kb` / `org_context_kb` | 不做 EventType 过滤 | — |

剧本过滤空保持空，会让「该类没有剧本」的主索变红——这是内容缺口，不是检索该回退全库。内容方案：P0 剧本不加本；**禁止**加会抢走 `playbook_refs[0]` 的域名 low 本。某类完全没本时，先补剧本再开评测，不要为了绿去回退。

同类型多本时，Hybrid 仍可能把 investigation 本排在 containment 前（横向 A 档曾如此，block_ip 靠质量门而不是 `playbook_refs[0]`）。本阶段 **不**用 EventType 过滤去改同类型排序，也 **不加** 第二套 `min_severity` SQL（Hybrid 今天就没有这条 SQL）。

### 2.2 历史硬过滤闸门（写死）

对某个 `EventType` `T`（`T ≠ other`）打开 `history_case_kb` 存储层过滤，必须 **同时** 满足：

1. 内容方案已为 `T` 写入 ≥1 条 `history_cases.json`（`event_type` metadata 真字段，不是摘要里的词）。  
2. **检索冒烟（无 LLM 即可）：** 用该类型金路径夹具的 `EntitySet` 跑 Hybrid（含 §1.1 扩写、§1.3 去重、**不**开类型过滤），`fetch_k` 池里至少 1 条 chunk 的 `metadata.event_type == T`。  
3. 文档/单测记下这次冒烟的 scenario_id。未记不得开。

缺 2：种子在库里但 mock 向量 + 当前 query 召不进前 10（`other` + `WKS-GEN-099` 已发生）。此时保持今天的组装 fail-soft。

**`other`：** 即使 1、2 都满足，也 **不开**。A 档 `other_unclassified` 的 persist 门是「`similar_cases` 非空」，不是必须命中 `case-10000021`。关 fail-soft 会把已绿路径变成内容召回问题。

效果：恶意进程 `playbook_refs` 不再套外泄本。历史过滤不抢在「能召回同类型」之前把 `similar_cases` 抽空。`other` 继续 fail-soft。

---

## 3. P1 mock 保护票；remote 才始终精排

现状（`pipeline.py`）：

```
if constraint_channel:
    reranked = fused[:top_k]   # 跳过 Reranker
else:
    reranked = await reranker.rerank(...)
```

这 **不是** 一律该拆掉的逻辑错误：

- Mock rerank 用 verbose 查询做 token overlap，再对 top_k **min-max**。`L_C` / `L_E` 拉开的序会被抹平。
- 8 条 A 档刚绿。先「始终 rerank」再补实体票，等于先拆保护。
- 真阳里 allow 约束（如 `files.corp.internal`）可能把负例钉在前面。那是 **remote rerank** 该修的，不是 mock overlap 该修的。
- P0-a2 落地后，绝大多数调查都会非空 `L_E`，mock rerank 几乎只在空 `EntitySet` 时跑。这是预期，不要为了「还要跑 rerank」去把 `L_E` 弄空。

**做法：**

- 融合始终：去重 → `rrf_fuse` 或 `c_rrf_fuse`（+ §1 的 `L_E`）。
- `RERANK_MODE=mock`（评测默认）：
  - 有 `constraint_channel` **或** 非空 `L_E` → **仍跳过** rerank，沿用融合序。
  - 两者都空 → 保持今天的 mock rerank。
- `RERANK_MODE=remote`：对 fused 候选 **始终** rerank；`constraint_channel` / `L_E` 只留在 `retrieval_metrics`，不再 bypass。
- `RERANK_MODE=off`：只用融合序（单测）。
- 回归：`test_constraint_rrf.py` 恒等与 allow-boost。新增 pipeline 测：
  - mock + `constraint_channel=True` → **不** 调用 reranker
  - mock + 非空 `L_E`、无 constraint → **不** 调用 reranker
  - remote + `constraint_channel=True` → reranker **被** 调用

效果：mock 金路径排序不被 overlap 拆票；答辩轨上白名单不再钉死攻击/剧本块。

---

## 4. P1 真 Rerank（追扣子「结果重排」）

现状：`Reranker.remote` 抛 `NotImplementedError`；mock 是 `0.65*score + 0.35*token_overlap`。

**做法：**

- `RERANK_MODE=mock|remote|off`。`off` = 只用融合序。
- `remote`：OpenAI 兼容 rerank 或 Cohere 形 API（`RERANK_API_BASE_URL` / `RERANK_MODEL_ID`）。失败则 degraded + 回退 **融合序**，不要回退 mock overlap。
- **闸门：** `EMBEDDING_MODE=mock` 时拒绝 `RERANK_MODE=remote`（启动校验或入口直接 mock）。对哈希向量做 Cross-Encoder 没有精度，只会抖评测。
- 输入：query + fused 前 `max(top_k*4, 20)` 条，输出截断 `top_k`。
- 不把 C-RRF 分和 rerank 分再加权；remote 精排是该轨的唯一分。

效果：真 embedding 演示轨上压「备份 vs 外泄」近义噪声。mock 金路径行为不变。

---

## 5. FP 组装（P0-d，与 §1.1 同一 PR；id 与分数同生共死）

> **分期更正：** 本条不是可以晚于 Host 扩写的 P1。没有本条，§1.1 对内鬼是负增益。P1 只保留「标定后的可选分数门」和 remote 精排。

现状：

| 出口 | 门槛 |
|------|------|
| `attack_techniques` | score ≥ 0.3；出口已按 `technique_id` 去重 |
| `similar_cases` | ≥ 0.25，同类型优先，空则 fail-soft |
| `fp_similarity` | **无**，永远取最高块的 `case_id` |
| `playbook_refs` | 无分数门 |

已知事实：

- RiskAgent：`fp_similarity.max_score >= 0.7` 即可把路径标成可能误报（`risk_agent.py`）。内容方案（第五次修订）锁的是 **冠军 id**，不锁真阳 `max_score < 0.7`——mock 归一化会把冠军做成 1.0。六条真阳要 `max_score=0`，靠本文件口径 H（无精确实体则 id 与分同清）。  
- 套件门：`account_anomaly_fp` 的 `matched_case_id == case-00000001` 且分 ≥ 0.7。  
- Mock 精排 min-max 后 top 经常是 **1.0**，拍 `0.35` 对 mock 形同虚设。  
- 改用 `raw_rrf_score` 会清掉金路径 id。  
- 已发生的失败是 **错 case**（`0d` 压过 `01`），不是分数太低。  
- `0d` / `0e` / `0c` 的主机/账号大量是 glob。精确命中若做成 glob，内鬼会「有效匹配」到 fileshare 卡。  
- 域名 A 档要的是 `block_domain`，**不是** `matched_case_id=case-0000000e`。P0 **不要**把 `0e` 精确命中当验收。

**写死的合同（禁止实现时二选一）：**

1. **排序先于门槛。** 未用 mock 夹具标定真命中 vs 错命中的 `RetrievedChunk.score` 之前，**禁止** 上线 `FP_ASSEMBLE_MIN`。标定是 P1 可选，不是 P0 准入。  
2. 组装只用 `RetrievedChunk.score`（融合序或 remote 精排后），**禁止**混用 `raw_rrf_score`。  
3. **有效匹配 = 融合序上第一个对 fp 允许 `E` 精确命中的块**（口径 B + H + N + §1.2.1）。  
   - 扫描范围：去重后的 `result.chunks` 按 `score` 降序。  
   - 命中后 **先把该块移到该列表第一**（其余相对序不变），并把该块的 `score` **提升为提权前列表的 `max(score)`**（原 top-1 的分），再写入 `max_score` / `matched_case_id`。套件门 `≥ 0.7` 吃的是提权后的分，不是埋在第 5 名的 0.35。  
   - 允许实现等价：先按口径 N 重排（有精确命中的整体在前），再按新序把第一名的分抬到原 `max(score)`。若新序第一名仍无精确命中则清空。  
   - 没有任何块有效：**`matched_case_id=None` 且 `max_score=0.0`**。  
   - **禁止：** 只看 `chunks[0]` 无效就扔掉后面的 `01`；选中 `01` 却上报它未提权的原始分；把 `0d` 的分写到 `01` 的 id 上却不把 `01` 提到第一（Agent 看到的 chunks[0] 仍是错卡）。提权必须反映到 **返回给 Agent 的 `result.chunks` 顺序**，不能只改 FpSimilarity 字段。  
4. RiskAgent **不必**再改认 id 的分支——组装保证不会出现 id=None 且分=1.0。禁止「清空 id、max_score 仍上报」。  
5. 标定后若仍要分数门：只作用于「有效匹配」；不得把 `account_anomaly_fp` 的 `case-00000001` 清掉。  
6. `playbook_refs`：无 event_type 命中时不输出（配合 §2）；有类型时不加 0.5。release pin 空时也不要输出假 refs。本方案 **不**保证 `playbook_refs[0]` 是遏制本（同类型排序是内容问题）。  
7. 召回层不加全局 `min_score`。`RERANK_MIN_SCORE` 仅 remote 轨，默认 0.0。

效果：fileshare/CDN glob 负例不再变成「已匹配改密 FP」；真阳不会被错 id + 满分拖进误报；`01` 在池内但不是融合第一时，提权后仍能过 `≥ 0.7`；内鬼 Host 扩写后 `0d` 不是有效匹配。

单测必须覆盖（**P0**，与 §1 同一 PR）：

- 序：`[0d 分=1.0 无精确实体, 01 分=0.35 有 Host+Account]` → 匹配 `case-00000001`，**chunks[0] 变为 01**，`max_score` **为原 max（1.0）不得仍是 0.35**。  
- 序：`[0d 且错误地把 glob 当命中]` → 0d **无效**，落到 01 并提权。  
- 全无精确实体 → id 与分均为空，chunks 序可不变。  
- 内鬼 EntitySet + 池里只有 0d → 清空，不得 `matched_case_id=case-0000000d`，`max_score=0`。  
- 改密 EntitySet：`keyword_queries_for_kb` 的 2 路里 **有** Account+Host AND；fp query 含 `Account:`/`Host:`，**不含**白名单域名；进程不在 AND 前两槽；`matched_case_id=case-00000001` 且分 ≥ 0.7。  
- **不**要求域名场景匹配 `case-0000000e`。

---

## 6. P2 真 embedding 演示轨（可选，与评测分轨）

代码已有 `RemoteEmbedder`。缺的是纪律，不是新 embedder。

- 金路径 / `eval-eventtype-8`：**锁定** `EMBEDDING_MODE=mock`。
- 答辩：`EMBEDDING_MODE=remote` + 同模型 `make load-kb`（`embedding_release_id` 必须变）。
- 向量失败：标 `vector_unavailable`，回退纯关键词，**禁止**静默改 mock 向量。
- 演示轨仍走 §1.3 去重。不要指望「真向量了就可以容忍 300+ 重复 attack 块」。

不作为评测 DoD。操作步骤见 `docs/rag-remote-embedding-demo.md`；可选 overlay `infra/docker-compose.embedding-remote.yml`（不进 `eval-full-loop` 默认，不打到 `KIND=mock` 评测栈）。

---

## 7. 分期与验收

落地顺序：**§1.1 + §1.1.1 + §1.1.2 + §1.3 + §1.2 + §5 必须同一 P0 PR**（含改 `keyword_queries_for_kb` 入队）→ §2 剧本过滤可同 PR 或紧随 →（§2.2 闸门全过之后，且从不对 other）历史过滤 → §3 → §4 → 可选 `FP_ASSEMBLE_MIN`。

| 阶段 | 改动 | 必须仍绿 | 新增证明 |
|------|------|----------|----------|
| **P0** | §1.1+§1.1.1+§1.1.2+§1.2+§1.2.1+§1.3+§5；§2 剧本 EventType 过滤（`other` 除外）。历史过滤 **默认不开** | RAG 单测 **以及** `eval-eventtype-8`：`account_anomaly_fp`（`matched_case_id=case-00000001` 且分 ≥ 0.7）、`insider_data_exfiltration`（**不得**匹配 `0d`；FP 分 **< 0.7**）、`malicious_process`（剧本过滤 + pin；**不**断言 `playbook_refs[0]` 必须是遏制本）、`lateral_movement`（attack 扩写 + `technique_id` 去重后 `attack_techniques` 非空）、`other_unclassified`（**不得**对 other 注入 type filter；`similar_cases` 仍非空——允许 fail-soft 错类型） | fp query 含 Host 且 **不含**白名单域名；`keyword_queries_for_kb` 2 路里 **有** Account+Host AND（extras 不得挤掉）；无实体恒等；单账号投票；`PC-FIN-023` 不命中 `PC-FIN-*`；仅 `files.corp.internal` 不抬误报出口；`[0d@1.0, 01@0.35]` 提权后 chunks[0] 为 01 且分 ≥ 0.7；命中函数覆盖 `_token_bounded` 反例；playbook pin 空 ≠ type 空；`fp_case_kb` 无 type filter；fp `fetch_k≥16`；同一 `technique_id` 融合前只留一条且优先带 keywords 的块 |
| **P1** | §3 mock 跳过锁死 + §4 remote rerank；可选分数门 | mock 默认零网络；上表 P0 场景仍绿 | mock+constraint 或非空 `L_E` **不**调 reranker；remote+constraint **调**；`httpx` mock 的 remote 契约 |
| **P2** | 演示 remote embedding runbook | 不改 Makefile 金路径默认 | 文档 + 可选 overlay，不进 `eval-full-loop` 默认 |

P0 合入后把 **8 条** A 档都过一遍（含 `host_compromise`、`insider_privilege_abuse`、`suspicious_domain_access`：org exact 不走 Hybrid；fp 组装不得把真阳标成已匹配误报；**不要**为域名场景断言 `0e`）。

**禁止**「每阶段只跑 RAG 单测」。动融合 / 过滤 / 组装之后：

1. `test_knowledge_seed_files`、`test_keyword_aliases`、`test_constraint_rrf`、`test_rag_agent`、pipeline 单测。  
2. 上表 `eval-eventtype-8`（真 LLM，`--require-closed`）。一条红了先修。  
3. 禁止 `--analysis-only`、MockLLM、改评测默认 `EMBEDDING_MODE`。

CJK：`COMPOSE_BAKE=0 DOCKER_BUILDKIT=0`。不要为了跑本方案循环 `make load-kb`；attack 块会累积。去重是防护，不是许可膨胀。

---

## 8. 明确不做（对本仓库无效果或有负效果）

- 父子分段 / QA / NL2SQL / 多模态 / Dify 滑条 / 扣子多轮改写 / HyDE / OpenSearch BM25 / 点亮 `time_*`。  
- 改评测默认 `EMBEDDING_MODE=remote`。  
- Graph 并进 RAG。  
- 对 `fp_case_kb` 做 EventType 等值过滤（字段不存在，等内容 P1a）。  
- playbook 过滤为空后回退全库。  
- 把 `playbook_release_pin_empty` 当成「该类没剧本」去回退或灌错类型。  
- mock 下始终 rerank。  
- 未标定就上 `FP_ASSEMBLE_MIN=0.35`。  
- 清空 `matched_case_id` 但保留 `max_score≥0.7`。  
- **只检验 fp 最高块**；top-1 无效就清空整条。  
- **选中非第一名的精确命中却上报其原始低分**（改密条 id 对、分不够）。  
- **只改 QueryBuilder、不改 `keyword_queries_for_kb` 入队**（extras 占满 `limit=2`）。  
- **只做 `L_E` 不做 query 扩写。**  
- **P0 只扩写 Host、组装留到 P1。**  
- 把 EventType 只挂在 `storage_filters_for_kb` / KnowledgeQueryPlan hints 上（history 永远套不上）。  
- 给导出的 `KnowledgeFilterKind` 加 `event_type` 却不改 HybridRetriever SQL。  
- 历史硬过滤抢在该类型种子补齐之前，或只因数到 ≥1 行种子、冒烟未过就开。  
- **对 `other` 开 EventType 存储层过滤**（有 `WKS-GEN-099` 种子也不开）。  
- 误报 `L_E` / 误报 query 吃 `files.corp.internal` 一类批准域名。  
- 把 `PC-FIN-*` / `finance-*` 当精确命中。  
- 复用 `_token_bounded` 当 `L_E` 精确（`L_C` 维持现状，靠 N/H 补）。  
- 攻击去重只认 `object_id`，或冲突时只留 score 最高。  
- 把进程写进 fp keyword AND 的前两个实体。  
- 关掉 `should_skip_query_rewrite` 让 LLM 改写带 `Host:` 的结构化查询。  
- 在 Agent / `keyword_aliases` 生产表写死演示人名。  
- 为了让 `L_E` 在剧本上非零去改 playbook 正文塞夹具主机。  
- 把 overlay 打到 `KIND=mock`。  
- 要求域名场景 `matched_case_id=case-0000000e`（glob 卡，A 档要封禁不是匹配 CDN 误报）。  
- P0 宣传「历史已按类型召回干净」或「`playbook_refs[0]` 已是遏制本」。

---

## 9. 和内容方案的关系

本文件 **不** 改种子 JSON。没有夹具原文，扩写也召不回。

| 内容方案（2026-08-29 **第五次**修订） | 本检索方案 |
|----------|------------|
| P1a 补 metadata `event_type`；14 条类型冻结；§1.6 锁 **冠军 id**（改密=`01`；六条真阳不是 `01`/`0d`）；**不**锁真阳 `max_score < 0.7` | §1 扩写 Host+Account；§5 **P0** 按序取第一个精确命中，无命中则 id 与分同清；§2 **仍不**过滤误报库，直到内容 P1a |
| 真阳实体禁止出现在误报行；白名单域名可以出现在误报行 | §1.1/§1.2 误报 query 与 `L_E` **都不吃**白名单域名；glob 不算精确 |
| 剧本 P0 零新增；Response 只吃 `playbook_refs[0]`；host medium **整段不做**；内鬼/横向遏制本保持 `min_severity=medium` | §2 只按 EventType 滤 Hybrid 路；不加第二套 severity SQL；不靠检索去改同类型 `[0]` |
| 历史按 EventType 补夹具 TP；加厚已有 `case-10000021`，不换 id | §2.2：种子 **且** 能进 `fetch_k` 才开硬过滤；**`other` 永不注入** |
| org：allow 种类只绑误报实体；改密窗 08:00–12:00 UTC | `L_C` 继续只吃 allow 类；本方案不改 matcher |
| 攻击只加厚已有 T，不发明 `T1021.001` | §1.1 给已有块加进程/主机 query；§1.3 按 `technique_id` 去重 |
| 每个内容迭代全量 `make load-kb` **至多一次** | §1.3 检索侧去重；不要循环 load-kb 当调试手段 |

**并行纪律：** 内容 P0（org 窗、历史 TP）与检索 §1.1 可并行。检索 PR 合入评测默认前，改密卡正文里必须已有 `ops-change-bot` **和** `PC-OPS-JUMP-01`。历史 EventType 硬过滤不得抢在内容补类型 **和** 召回冒烟之前。误报类型过滤不得抢在内容 P1a 之前。内容不进本文件的实现 PR。剧本 P0 不加本；内容 P0b 若做，必须在检索 EventType 过滤之前通过 `playbook_refs[0]` 闸门。

**P0 检索 PR 自己必须同时含：** QueryBuilder 扩写（含标注顺序）、`keyword_queries_for_kb` 入队（口径 M）、命中函数、去重、fp `fetch_k`、`_build_fp_similarity` 提权（口径 H/N）。缺组装或缺 keyword 入队的扩写 PR **禁止**合入默认栈。
