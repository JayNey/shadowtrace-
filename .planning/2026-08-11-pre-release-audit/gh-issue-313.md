<!-- ShadowTrace live full-loop audit F-1/F-2/F-4；revalidated against main@44ff256；CODE_CONFIRMED + HISTORICAL_RUNTIME -->

### 类型

Bug 修复 / 评测合同决策（FP 基线加载与场景 profile；需讨论）

### 优先级

P1·需讨论

### 当前事实

- `change_window_baseline_loader.py` 默认路径：

```python
Path(__file__).resolve().parents[3] / "data" / "organization" / "change_windows.json"
```

- 容器内模块位于 `/app/app/services`，该表达式解析到 `/data/organization/change_windows.json`；Dockerfile 实际复制到 `/app/data/organization/change_windows.json`。
- baseline 缺失时 loader 降级为空，应用 health 仍可为 ok；`account_anomaly_fp` 因此失去 change-window adjudication 输入，结果可信度下降。
- ISSUE-114 的设计要求 FP 在 post-evidence 阶段裁决，`route_after_fp_adjudication` 仍继续流程；baseline 修复不会让 full-loop 自动 short-circuit。
- 当前 gold-path 对所有场景强制 `include_response_execution=true`。FP 为 `disposition_policy=not_required`；是否将 analysis-only `CLOSED + false_positive` 定为 FP 语义门、把 full-loop 改为独立压力门，属于本 issue 需要确认的评测合同，不能当成既有事实。
- eval 失败文案固定提示 “Check evidence/entities”，没有 status trace、degraded_flags、transition audit、intent 状态，容易误导根因。
- 已关闭 #916（ISSUE-301）建立 fresh-stack/strict matrix，#923（ISSUE-304）修复官方入口；两者没有校验容器 baseline 可读性，也没有定义 NOT_REQUIRED 场景的独立语义门与 response 压力门。本 issue 只补这两个增量。

### 目标

让 FP 场景在宿主与容器内都使用同一可验证 baseline，并把“FP 语义验收”与“完整 response 链压力测试”分开，避免假绿与假红。

### 推荐修复方案（工业级）

1. **显式配置 baseline**
   - Settings 增加 `CHANGE_WINDOW_BASELINE_PATH`（或复用统一 organization-data root）；
   - compose/container 默认 `/app/data/organization/change_windows.json`；
   - 本地 fallback 通过 repository root 定位 `data/organization/...`，不要仅将 `parents[3]` 改为另一个 magic index。
2. **启动期校验**
   - 路径不存在、JSON schema 错、目标 tenant 无条目时输出结构化 warning/health component；
   - 仅对显式配置为 required 的 tenant/data profile 允许生产 fail-closed；普通生产启动保持可用但 degraded；
   - demo eval preflight 必须因其声明依赖 tenant-demo baseline 而直接失败，不能静默当“无窗口”。
3. **按场景定义 eval profile**
   - 以下为推荐的待确认合同，不改变现有 strict 的全局定义：
   - insider：full-loop strict CLOSED；
   - domain：analysis-only 验场景语义，另跑 full-loop 验 phase1/response；
   - FP：analysis-only `CLOSED + false_positive` 为语义门；full-loop 仅作独立压力测试，不替代语义门。
4. **保持 fresh-state**
   - 复用 ISSUE-301 matrix 的独立 project/volume；
   - 若单场景命令使用确定性 event_id，seed 前检测冲突并显式清理/换 run-scoped ID，禁止复用旧 event 轨迹。
5. **改进失败诊断**
   - FAILED/timeout 输出 event_id、elapsed、status 轨迹、degraded_flags、最近 transition audit、investigation/graph-resume intent 状态；
   - 删除将所有 FAILED 归因于 evidence/entities 的固定提示。

### 文件范围

- `backend/app/services/change_window_baseline_loader.py`
- `backend/app/core/config.py` / `.env.example` / compose env
- `scripts/dynamic_eval_full_loop.py`
- `scripts/dynamic_eval_matrix.py`
- Makefile eval targets / deployment docs
- loader、container-path、scenario-profile tests

### 验收标准

- [ ] 宿主与 backend 容器内均加载同一 tenant-demo change-window 数据。
- [ ] baseline 不可读时 eval preflight 非零退出并打印实际解析路径。
- [ ] FP fresh-volume analysis-only 达到 CLOSED，final verdict/disposition 明确为 false_positive。
- [ ] FP full-loop 作为独立压力测试报告，不覆盖 analysis-only 语义门结果。
- [ ] domain 同时有 analysis-only 语义门和 full-loop phase1 门。
- [ ] 真实 LLM 验收保持 `LLM_MODE=openai_compatible`，并确认至少一次 provider success。
- [ ] 失败输出实际状态轨迹，不再统一提示 evidence/entities。

### 测试与验证

```bash
docker compose -f infra/docker-compose.yml exec -T backend python - <<'PY'
from app.services.change_window_baseline_loader import load_change_window_baseline
assert load_change_window_baseline().get("tenant-demo")
PY

# 实现后新增/调整的 per-scenario profile 入口（命令名可按实现确定）：
python scripts/dynamic_eval_matrix.py --profile-by-scenario
```

### 关联

- #916（ISSUE-301，fresh-stack matrix）
- #923（ISSUE-304，官方全链路入口）
- #619（ISSUE-114，post-evidence FP adjudication）
- 审计报告：`深度问题调查报告-live-full-loop-20260811.md` F-1/F-2/F-4

### 禁止事项

- 禁止把 baseline 修复解释为 full-loop early close。
- 禁止全局放宽 strict CLOSED 或让 FP analysis-only 替代 insider full-loop。
- 禁止静默吞 baseline 路径/schema 错误。
- 禁止切回 MockGPT、复用旧 volume/event 或 force_close 换绿。
