# P2 真 embedding 演示轨（与评测分轨）

> 纪律文档。**不是** `eval-eventtype-8` / `eval-full-loop` DoD。  
> 金路径继续 `EMBEDDING_MODE=mock` + keyword。本轨只给答辩看语义近似。

权威对照：`docs/rag-retrieval-upgrade-plan.md` §6 / §8；`docs/eval-8-eventtype-gold-paths-plan.md`。

## 1. 两条轨

| 轨 | `EMBEDDING_MODE` | 入口 | DoD |
|----|------------------|------|-----|
| 金路径 / 8 条 A 档 | **mock**（锁定） | `make eval-eventtype-8`、`make eval-full-loop`、`make eval-full-loop-matrix` | 8 条 A 档 persist + CLOSED |
| 答辩演示 | **remote** + 同模型 `make load-kb` | 可选 overlay `infra/docker-compose.embedding-remote.yml` | 不是评测门 |

禁止把评测默认改成 `EMBEDDING_MODE=remote` 来「假装变强」。  
禁止把本 overlay 写进 `eval-eventtype-8`、`eval-full-loop`、`eval-full-loop-matrix` 或 `infra/docker-compose.eval.yml`。  
本文件 **不是** Sangfor capability overlay。禁止把厂商 overlay 打到 `KIND=mock`。本 overlay **不**设置 `SOURCE_MODE` / `DISPOSITION_MODE` / `DISPOSITION_ADAPTER_KIND` / `TOOL_MODE`。

## 2. 金路径锁 mock

栈与评测入口保持 `.env.example` 默认 `EMBEDDING_MODE=mock`。  
`make eval-eventtype-8` 不切换向量后端。CJK：`COMPOSE_BAKE=0 DOCKER_BUILDKIT=0`。

不要为跑评测循环 `make load-kb`。attack 块会累积。去重是防护，不是许可膨胀。

## 3. 答辩：remote + 同模型 load-kb

先起 Canonical Mock 栈（`make up-demo` 或 `make up WORKER=1`）。再叠 embedding overlay。**一次** `make load-kb`，同一 `EMBEDDING_MODEL_ID`。`EMBEDDING_RELEASE_ID` **必须**不是 `mock-v1`（overlay 默认 `remote-v1`）。换模型或换 `release_id` 才再 load；不要循环 load。

CJK 示例（host 已有 `COMPOSE_PROJECT_NAME`）：

```bash
export COMPOSE_BAKE=0 DOCKER_BUILDKIT=0
export EMBEDDING_API_BASE_URL=https://api.example.invalid/v1
export EMBEDDING_API_KEY=...          # 勿提交
export EMBEDDING_MODEL_ID=your-embed-model
export EMBEDDING_RELEASE_ID=remote-v1  # 禁止仍用 mock-v1
export EMBEDDING_DIMENSION=1024       # 须与模型一致

docker compose --project-name "$COMPOSE_PROJECT_NAME" \
  -f infra/docker-compose.yml \
  -f infra/docker-compose.embedding-remote.yml \
  up -d --no-deps backend worker

make load-kb
```

`make up-demo` 栈还要带 observability 文件与 `--profile demo`，见 `Makefile` 的 `COMPOSE_DEMO`，最后再 `-f infra/docker-compose.embedding-remote.yml`。  
Makefile 可选入口：`make up-embedding-remote`（**不是**金路径；不进 `eval-full-loop`）。

切回评测：去掉 overlay，恢复 `EMBEDDING_MODE=mock`，**不要**把 remote 向量当 8 条 A 档证据。

## 4. 向量失败

`RemoteEmbedder` 失败 **禁止**静默改 `MockEmbedder`。  
检索标 `degraded_steps` 含 `vector_unavailable`，该次只走 keyword。金路径 mock 向量正常时不应出现该标签。

## 5. 去重

演示轨仍走 `docs/rag-retrieval-upgrade-plan.md` §1.3（`technique_id` → `object_id` → `chunk_id`）。  
禁止写「真向量了就可以容忍 300+ 重复 attack 块」。
