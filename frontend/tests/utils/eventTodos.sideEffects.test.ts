/** eventTodos side-effect convergence todo tests (ISSUE-323). */

import { describe, expect, it } from "vitest";
import { buildEventTodos, canCloseEvent } from "../../src/utils/eventTodos";
import type { EventDetailResponse } from "../../src/types/event";

function baseDetail(overrides: Partial<EventDetailResponse> = {}): EventDetailResponse {
  return {
    event: {
      event_id: "evt-todo-323",
      event_type: "account_anomaly",
      title: "todo side effects",
      description: "",
      status: "reporting",
      severity: "high",
      risk_score: 70,
      confidence: 0.8,
      final_verdict: "confirmed_threat",
      entities: {
        accounts: [],
        hosts: [],
        ips: [],
        domains: [],
        processes: [],
        files: [],
      },
      creation_source_ref: {
        source_id: "mock",
        source_type: "xdr",
        object_kind: "event",
        object_id: "obj",
        source_status_raw: "OPEN",
      },
      source_reference_snapshots: [],
      current_primary_source_record_id: null,
      disposition_source_ref: null,
      disposition_policy: "required",
      raw_alert_ids: [],
      raw_alert_snapshot: {},
      source_type: "xdr",
      occurred_at: null,
      created_at: null,
      updated_at: null,
      closed_at: null,
      replan_count: 0,
      degraded_flags: [],
      escalated: false,
      external_unsynced: false,
      row_version: 1,
      event_context_snapshot: {
        report: { report_id: "rpt-1" },
      },
    },
    writeback_required: true,
    writeback_readiness: "ready",
    writeback_overall_status: "pending",
    pending_writeback_count: 0,
    next_recommended_action: "none",
    analysis_only_complete: true,
    response_phase_state: "complete",
    ...overrides,
  };
}

describe("buildEventTodos side effects", () => {
  it("adds side_effects_pending when gate_applicable_outstanding_count > 0", () => {
    const todos = buildEventTodos({
      detail: baseDetail({
        gate_applicable_outstanding_count: 2,
        outstanding_side_effect_count: 2,
        outstanding_side_effects: [
          {
            action_id: "act-1",
            scope: "gate_applicable",
            action_status: "executing",
            execution_phase: "post_verify",
            writeback_applicable: true,
            plan_revision: 1,
            blocking_reason: "executing_action",
          },
        ],
      }),
      actions: [],
      writebacks: [],
      evidenceDetail: null,
    });

    const sideEffectTodo = todos.find((item) => item.kind === "side_effects_pending");
    expect(sideEffectTodo).toBeDefined();
    expect(sideEffectTodo?.label).toContain("2");
    expect(sideEffectTodo?.tabKey).toBeUndefined();
  });

  it("blocks canCloseEvent / close_ready while gate outstanding remains", () => {
    const detail = baseDetail({
      next_recommended_action: "close",
      gate_applicable_outstanding_count: 1,
      outstanding_side_effect_count: 1,
    });
    expect(canCloseEvent(detail)).toBe(false);
    const todos = buildEventTodos({
      detail,
      actions: [],
      writebacks: [],
      evidenceDetail: null,
    });
    expect(todos.some((item) => item.kind === "close_ready")).toBe(false);
    expect(todos.some((item) => item.kind === "side_effects_pending")).toBe(true);
  });

  it("blocks canCloseEvent when side-effect projection is degraded", () => {
    expect(
      canCloseEvent(
        baseDetail({
          next_recommended_action: "close",
          gate_applicable_outstanding_count: -1,
          outstanding_side_effect_count: -1,
        }),
      ),
    ).toBe(false);
  });

  it("does not add side_effects_pending when event is closed", () => {
    const todos = buildEventTodos({
      detail: baseDetail({
        event: {
          ...baseDetail().event,
          status: "closed",
        },
        gate_applicable_outstanding_count: 1,
      }),
      actions: [],
      writebacks: [],
      evidenceDetail: null,
    });

    expect(todos.some((item) => item.kind === "side_effects_pending")).toBe(false);
  });

  it("adds degraded side_effects_pending when counts are -1", () => {
    const todos = buildEventTodos({
      detail: baseDetail({
        gate_applicable_outstanding_count: -1,
        outstanding_side_effect_count: -1,
      }),
      actions: [],
      writebacks: [],
      evidenceDetail: null,
    });

    const sideEffectTodo = todos.find((item) => item.kind === "side_effects_pending");
    expect(sideEffectTodo?.label).toContain("不可用");
  });
});
