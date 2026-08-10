<!-- ShadowTrace live-LLM audit ID-CLOSE-CANDIDATE；main@34947d1；NEEDS_CLEAN_REPRO -->

### 类型

Bug 修复（CLOSED 终态一致性；需确认产品合同）

### 优先级

P1·需讨论

### 当前事实

- 动态评测运行数据存在 `event.status=closed`，同时 3 个 action/job 为 running、3 个 outbox 为 ready。
- 代码明确允许 `disposition_policy=not_required` 在报告存在后快速关闭；这能降低低风险/误报结案延迟。
- 当前 close gate 约束的是 required terminal disposition，不是所有异步 entity action（`workflow.py:911-998`）。
- 运行数据来自共享 DB batch；该事件是最后 seed 的场景，但仍需 fresh-volume 单场景确认 outbox 是否属于 gate-applicable current revision。

### 发布条件（实现前需确认）

满足以下任一条件后再实施修复：

1. 产品合同明确规定 CLOSED 代表所有当前 revision 副作用完成；或
2. fresh-volume 单场景复现 CLOSED 后仍存在 gate-applicable READY outbox；或
3. CLOSED 后后台 job 实际继续产生用户可见副作用，且违反已确认的 CLOSED 产品合同或 UI/API 明示语义。

### 建议修复方向

- 不要取消 NOT_REQUIRED quick-close。
- 若副作用允许后台继续：
  - 明确标记 `detached/background`；
  - UI/API 展示 outstanding count；
  - 禁止把它们描述为已执行完成。
- 若副作用必须收敛：
  - close gate 只阻断当前 revision、非 superseded、需要收敛的 response/rollback action；
  - force-close 保留显式 bypass 和 `external_unsynced`；
  - 加 stale job reconcile，避免严格门禁造成永久死锁。

### 禁止事项

- 禁止全局要求所有通知/审计类 job 完成后才能 CLOSED。
- 禁止在没有 fresh-volume 复现时改变状态机终态合同。

### 测试与验证

在 ISSUE-301 strict matrix 上单场景复现后再定修复范围。
