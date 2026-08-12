/** Human-readable labels for side-effect convergence fields (ISSUE-323). */

import type {
  SideEffectConvergencePolicy,
  SideEffectConvergenceReason,
  SideEffectScope,
} from "../types/event";

export const SIDE_EFFECT_SCOPE_LABELS: Record<SideEffectScope, string> = {
  gate_applicable: "关单门禁",
  background_detached: "后台/游离",
};

export const SIDE_EFFECT_REASON_LABELS: Record<SideEffectConvergenceReason, string> = {
  in_flight_job: "执行作业进行中",
  executing_action: "动作执行中",
  effect_unverified: "实体效果未验证",
  terminal_writeback_unconfirmed: "终态写回未确认",
  outbox_not_confirmed: "Outbox 未确认",
  outbox_undelivered: "Outbox 未投递",
};

export const SIDE_EFFECT_POLICY_LABELS: Record<SideEffectConvergencePolicy, string> = {
  terminal_writeback: "终态写回",
  independent_entity_effect: "独立实体效果",
  execution_job_only: "仅执行作业",
};

export function sideEffectScopeLabel(scope: SideEffectScope): string {
  return SIDE_EFFECT_SCOPE_LABELS[scope] ?? scope;
}

export function sideEffectReasonLabel(
  reason: SideEffectConvergenceReason | null | undefined,
): string {
  if (!reason) {
    return "—";
  }
  return SIDE_EFFECT_REASON_LABELS[reason] ?? reason;
}

export function sideEffectPolicyLabel(
  policy: SideEffectConvergencePolicy | null | undefined,
): string {
  if (!policy) {
    return "—";
  }
  return SIDE_EFFECT_POLICY_LABELS[policy] ?? policy;
}

export function isSideEffectProjectionDegraded(
  gateCount: number | undefined,
  totalCount: number | undefined,
): boolean {
  return gateCount === -1 || totalCount === -1;
}

export function hasVisibleOutstandingSideEffects(input: {
  outstanding_side_effects?: readonly unknown[];
  gate_applicable_outstanding_count?: number;
  outstanding_side_effect_count?: number;
  background_side_effects_pending?: boolean;
}): boolean {
  if (isSideEffectProjectionDegraded(
    input.gate_applicable_outstanding_count,
    input.outstanding_side_effect_count,
  )) {
    return true;
  }
  if ((input.outstanding_side_effects?.length ?? 0) > 0) {
    return true;
  }
  if ((input.gate_applicable_outstanding_count ?? 0) > 0) {
    return true;
  }
  if (input.background_side_effects_pending) {
    return true;
  }
  return false;
}
