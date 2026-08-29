# RAG 检索代码优化方案

> 只做对 **本仓库告警闭环** 有效果的改动。对标 Dify/扣子是为了补精度缺口，不是把产品做成通用文档问答。  
> 内容补库见 `docs/rag-kb-content-plan.md`。本文件只动检索代码。  
> 金路径默认仍是 `EMBEDDING_MODE=mock` + keyword（`docs/eval-8-eventtype-gold-paths-plan.md`）。**禁止**把评测默认改成真向量来「假装变强」。

权威对照：`backend/app/rag/pipeline.py`、`hybrid_retriever.py`、`constraint_rrf.py`、`reranker.py`、`keyword_aliases.py`、`agents/rag_agent.py`、`services/knowledge_store_prefilter.py`。

---

## 0. 结论：追什么、不追什么

现有骨架已经是扣子同族（改写 → 向量+FTS → RRF → rerank），外加组织约束 C-RRF。再抄 Dify 的父子分段、多模态、NL2SQL、加权滑条，**不会提高** 八类 EventType 的命中。

要追赶 / 超越的只有这些：

| 优先级 | 改什么 | 为什么对本仓库有效 | 明确不做的替代方案 |
|--------|--------|-------------------|-------------------|
| **P0** | 实体感知融合（IOC 多一票） | 金路径靠主机/账号/域名对上号；mock 向量无语义，多一路实体投票立刻提高召回精度 | 不上 OpenSearch/BM25 |
| **P0** | EventType 预过滤（剧本/历史/误报） | 错类型剧本和历史会带偏处置与 `similar_cases`；现在只在拼装后软过滤 | 不做通用标签 UI |
| **P0** | C-RRF 命中后 **不要跳过 rerank** | `pipeline.py` 在 `constraint_channel` 时直接切掉 rerank，组织约束把顺序定死，相关性不再校准 | 不要为此改成 Dify 加权滑条 |
| **P1** | 真 Rerank（仅 `RERANK_MODE=remote`） | 对齐扣子「结果重排」；只在真 embedding 时打开才有精度 | mock 评测保持 mock rerank |
| **P1** | FP / 攻击组装门槛收紧 | `_build_fp_similarity` 无下限，垃圾块也会带 `matched_case_id`；攻击已有 0.3 | 不要用扣子默认 0.5 卡死 mock 分 |
| **P2** | 可选真 embedding 演示轨 | 语义「像不像外泄」需要真向量；与 mock 金路径 **分轨** | 不改 eval 默认 `EMBEDDING_MODE` |

下面「明确不做」见 §8。

---

## 1. P0-a 实体感知融合（超越 Dify/扣子的点）

低代码知识节点没有「从告警里抽出 host/account/domain 再当融合通道」。我们查询里本来就有 `Host:` / `Account:` / `Domain:`（`keyword_aliases._LABELED_ENTITY`）。

**做法：** 在 RRF 里增加一路 `L_E`，与 C-RRF 的 `L_C` 同构：

```
C-RRF(L_vec, L_kw… ; H, E) = RRF(lists + [L_C?] + [L_E?])
```

- `E` = 查询中抽出的实体（主机、账号、域名、进程），长度 ≥ 3。
- `L_E` = 候选池按「content+metadata 命中多少个实体」排序。
- `H` 仍只含 allow 类组织约束。`L_E` **不**替代 exact org match，也不产生 `OrgContextMatch`。
- 空 `E` 或空 `L_E` ⇒ 与现在恒等（和 C-RRF identity 一样）。

落点：

- 抽出逻辑复用 `keyword_aliases`，不要在 pipeline 再写一套正则。
- 新模块宜叫 `entity_rrf.py` 或扩 `constraint_rrf.py` 的第二 voter，单测必须覆盖：
  - 无实体 ⇒ 分数与 `rrf_fuse` 相同
  - `PC-FIN-023` + `zhangsan` 把外泄历史/攻击块抬到 FP fileshare 之上
  - **禁止**用 `zhangsan` 去抬 `fp_cases` 里的 `PC-FIN-011` 行

效果：mock 金路径（内鬼 / 改密 / CDN / `WKS-GEN-099`）主要吃 keyword，这一路比换 embedding 更立竿见影。

---

## 2. P0-b EventType 预过滤

现状：

- `playbook_kb` 的 FTS 已要求 query 里有 event_type，但 **向量路仍可能召回错类型剧本**。
- `history_case_kb` 在 `_build_similar_cases` 里同类型优先、空则 fail-soft。错类型块已经占了 top_k。
- typed filter 只有 `source_id` / `content_type`（`KnowledgeFilterKind`）。

**做法：** 为 `fp_case_kb` / `history_case_kb` / `playbook_kb` 增加存储层 `event_type` 等值过滤。

1. `KnowledgeFilterKind.EVENT_TYPE = "event_type"`（不要启用已保留的 `time_*`）。
2. `typed_filter_clause`：`metadata->>'event_type' = :event_type`。
3. `RetrievalContext.storage_filters_for_kb`：当 query/context 带 `EventType` 且 kb ∈ 上述三库时注入。
4. **fail-soft**：过滤后 0 条则去掉该 filter 再查一次，并记 `degraded_steps+=event_type_filter_empty`。`other` / 未知类型不注入。
5. `attack_kb` / `org_context_kb` **不要**按 EventType 过滤（技术卡片和白名单跨类型复用）。

效果：恶意进程主索 `playbook_refs`、未分类 `similar_cases`、FP `case-00000001` 更稳，减少「外泄剧本打到账号异常上」。

---

## 3. P0-c 约束通道不再跳过 rerank

现状（`pipeline.py`）：

```
if constraint_channel:
    reranked = fused[:top_k]   # 跳过 Reranker
else:
    reranked = await reranker.rerank(...)
```

组织约束只应 **多一票**，不应取消相关性排序。跳过之后，命中白名单的块会压过更相关的攻击/剧本块。

**做法：**

- 融合始终：`rrf_fuse` 或 `c_rrf_fuse`（+ §1 的 `L_E`）。
- **始终**对 fused 候选做 rerank（mock 或 remote）。
- `constraint_channel` 只留在 `retrieval_metrics` 里做可观测，不再当 bypass。
- 回归：`test_constraint_rrf.py` 的恒等与 allow-boost 保持；新增 pipeline 测：`constraint_channel=True` 时 reranker 仍被调用。

效果：有组织上下文的事件（内鬼、CDN、改密）排序不再被白名单通道钉死。

---

## 4. P1-a 真 Rerank（追扣子「结果重排」）

现状：`Reranker.remote` 抛 `NotImplementedError`；mock 是 `0.65*score + 0.35*token_overlap`。

**做法：**

- `RERANK_MODE=mock|remote|off`。`off` = 只用 RRF 序（给单测）。
- `remote`：OpenAI 兼容 rerank 或 Cohere 形 API（`RERANK_API_BASE_URL` / `RERANK_MODEL_ID`）。失败则 degraded + 回退 RRF 序（已有 `except`）。
- **闸门：** `EMBEDDING_MODE=mock` 时拒绝 `RERANK_MODE=remote`（启动校验或 rerank 入口直接 mock）。对哈希向量做 Cross-Encoder 没有精度意义，只会抖评测。
- 输入：query + fused 前 `max(top_k*4, 20)` 条，输出截断 `top_k`。
- 不把 C-RRF 分和 rerank 分再加权一遍；rerank 是精排唯一分。

效果：真 embedding 演示轨上，混入的近义噪声（「备份」vs「外泄」）会被压下去。mock 金路径行为不变。

---

## 5. P1-b 组装门槛（不要抄扣子 0.5）

现状：

| 出口 | 门槛 |
|------|------|
| `attack_techniques` | score ≥ 0.3 |
| `similar_cases` | ≥ 0.25，同类型优先 |
| `fp_similarity` | **无**，永远取最高块 |
| `playbook_refs` | 无分数门 |

mock RRF 分经 min-max 后经常偏高，扣子默认 0.5 会把金路径打空。

**做法：**

- `fp_similarity`：最高分 `< FP_ASSEMBLE_MIN`（建议 **0.35**，与 RiskAgent 门对齐前先对现有 fixture 测）则 `matched_case_id=None`、`max_score` 仍上报。评测断言的是「过阈值才认匹配」，空匹配比错匹配安全。
- `playbook_refs`：无 event_type 命中时不输出 refs（配合 §2）；有类型时保留现逻辑，不必再加 0.5。
- 召回层 **不** 加全局 `min_score`（mock 分不可比）。真 rerank 轨可加 `RERANK_MIN_SCORE`（默认 0.0，演示再调），且只滤 remote 分。

效果：随机历史/误报块不再变成「已匹配 FP 案例」，减少 FP 误杀和真阳被判误报。

---

## 6. P2 真 embedding 演示轨（可选，与评测分轨）

代码已有 `RemoteEmbedder`（`/v1/embeddings`，维度钉在 release）。缺的是 **纪律**，不是新 embedder。

- 金路径 / `eval-eventtype-8`：**锁定** `EMBEDDING_MODE=mock`。
- 答辩演示：`EMBEDDING_MODE=remote` + 同模型 `make load-kb`（embedding_release_id 必须变，否则 pin 会拒）。
- 向量失败已有产品约定：标 `vector_unavailable`，回退纯关键词，**禁止**静默改 mock 向量（`ShadowTrace 工程实施拆解方案.md`）。保持。

效果：只有这条轨能让「语义近似、关键词对不上」的攻击技术被召回。不作为评测 DoD。

---

## 7. 分期与验收

| 阶段 | 改动 | 必须仍绿 | 新增证明 |
|------|------|----------|----------|
| **P0** | §1 实体融合 + §2 EventType filter + §3 始终 rerank | `test_knowledge_seed_files`、`test_keyword_aliases`、`test_constraint_rrf`、`test_rag_agent`、`test_pipeline` | 实体恒等测；event_type 空则 fail-soft；constraint 时 rerank 被调用 |
| **P1** | §4 remote rerank + §5 FP 组装门 | mock 默认测零网络 | `RERANK_MODE=remote` 契约测（httpx mock）；FP 低分无 `matched_case_id` |
| **P2** | 演示 remote embedding runbook | 不改 Makefile 金路径默认 | 文档 + 可选 compose overlay，不进 `eval-full-loop` 默认 |

落地顺序：**§3 → §2 → §1 → §5 → §4**。§3 最小、直接修现有逻辑错误；§1 对 mock 金路径增益最大。

每阶段后用现有 RAG 单测即可，不必先跑完整 LLM eval。动到 `fp_similarity` 组装后再跑 `EVAL_SCENARIO=account_anomaly_fp` 防回归。

---

## 8. 明确不做（对本仓库无效果或有负效果）

- **父子分段 / QA 模式**：五库是卡片不是 PDF。
- **NL2SQL / 表格知识库**：没有结构化表知识。
- **多模态图文**：告警检索不吃图。
- **Dify 语义/关键词滑条**：已有 RRF + C-RRF；滑条无法表达白名单。
- **扣子多轮对话改写**：我们是单次调查查询；结构化告警已 `should_skip_query_rewrite`。
- **HyDE**：告警查询已够具体，多一轮 LLM 延迟且扰动 T 编号。
- **上 OpenSearch 换 BM25**：`OPENSEARCH_ENABLED` 默认关；短卡片 + 别名足够。运维成本换不来金路径分。
- **把 `time_*` filter 做亮**：案例排序不是新闻时效问题。
- **改评测默认 `EMBEDDING_MODE=remote`**：会打穿现有 keyword 金标。
- **Graph 并进 RAG**：横向已有 Graph Agent；Phase A 注释已排除。不要在本方案里做双通道融合。

---

## 9. 和内容方案的关系

代码再好，库里没有夹具原文也对不上。P0 代码与 `docs/rag-kb-content-plan.md` 的 P0 内容（变更窗口、剧本档位）应 **并行**，不要互相等待。内容不进本文件的 PR。
