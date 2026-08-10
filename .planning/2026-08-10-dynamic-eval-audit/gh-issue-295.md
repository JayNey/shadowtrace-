<!-- ShadowTrace live-LLM audit ID-EVAL-001；main@34947d1；CONFIRMED -->

### 类型

Bug 修复（正式动态评测 / API 契约）

### 优先级

P0

### 当前事实

- `GET /api/v1/events/{event_id}` 返回 `EventDetailResponse`，事件主体位于 `payload["event"]`（`backend/app/api/v1/events.py:744-753`，`schemas.py:230-244`）。
- `scripts/dynamic_eval_full_loop.py:get_event()` 仍要求顶层存在 `event_id`（`:184-188`），真实 HTTP 200 也会抛 `unexpected event payload`。
- `collection_status_from_event()` 直接从顶层读 `event_context_snapshot`（`:246-255`），解包后字段同样错位。
- `backend/tests/test_infra/test_dynamic_eval_gold_path.py` 测试桩仍返回扁平事件对象（`:244-248`），未覆盖生产响应。

### 目标

恢复正式金标评测脚本对当前 API 契约的读取能力；不改变后端 `EventDetailResponse` 形状。

### 推荐修复方案（工业级）

1. 在 `dynamic_eval_full_loop.py` 增加单一响应归一化函数：
   - 优先识别 `payload["event"]`；
   - 为旧环境保留扁平对象兼容；
   - 解包后校验 `event_id` 与请求 ID 一致。
2. 所有读取事件快照/状态的 helper 统一基于解包后的 `SecurityEvent`。
3. 将测试桩改为真实 `EventDetailResponse` 结构，并增加 OpenAPI/TestClient 契约测试，禁止再次手写漂移的响应形状。
4. `dynamic_eval_approve.py` 若同样 GET detail，复用同一 unwrap helper。

### 文件范围

- `scripts/dynamic_eval_full_loop.py`
- `scripts/dynamic_eval_approve.py`（若适用）
- `backend/tests/test_infra/test_dynamic_eval_gold_path.py`

### 验收标准

- [ ] 真实 `EventDetailResponse` 不再导致 `unexpected event payload`。
- [ ] 扁平旧响应在兼容模式仍可读取。
- [ ] `collection_status_from_event` 等 helper 在解包后正常工作。
- [ ] 契约测试失败时能阻止回归。

### 测试与验证

```bash
cd backend
uv run --frozen pytest tests/test_infra/test_dynamic_eval_gold_path.py -q
```

修复后配合 ISSUE-301 strict matrix 做三场景动态复测。

### 依赖/关联

- 严格 CLOSED / fresh-stack 隔离见 ISSUE-301。
- 不改变后端 API；后端是权威契约。

### 禁止事项

- 禁止把后端响应改回扁平对象迁就脚本。
- 禁止通过提高总 timeout 掩盖状态停滞。
