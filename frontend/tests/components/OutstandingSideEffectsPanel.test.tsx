/** OutstandingSideEffectsPanel tests (ISSUE-323). */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import OutstandingSideEffectsPanel from "../../src/components/event/OutstandingSideEffectsPanel";
import type {
  EventDetailResponse,
  OutstandingSideEffectView,
} from "../../src/types/event";

const sampleOutstanding: OutstandingSideEffectView = {
  action_id: "act-gate-1",
  scope: "gate_applicable",
  action_status: "executing",
  execution_phase: "post_verify",
  writeback_applicable: true,
  convergence_policy: "terminal_writeback",
  job_status: "running",
  outbox_delivery_status: "ready",
  outbox_writeback_status: "pending",
  plan_revision: 2,
  blocking_reason: "outbox_not_confirmed",
};

function makeProjection(
  overrides: Partial<EventDetailResponse> = {},
): EventDetailResponse {
  return {
    event: {
      event_id: "evt-323",
      event_type: "account_anomaly",
      title: "Side effect gate",
      description: "test",
      status: "reporting",
      severity: "high",
      risk_score: 80,
      confidence: 0.9,
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
        object_id: "obj-323",
        source_status_raw: "OPEN",
      },
      source_reference_snapshots: [],
      current_primary_source_record_id: null,
      disposition_source_ref: null,
      disposition_policy: "required",
      raw_alert_ids: [],
      raw_alert_snapshot: {},
      source_type: "xdr",
      occurred_at: "2026-08-12T00:00:00Z",
      created_at: "2026-08-12T00:00:00Z",
      updated_at: "2026-08-12T00:00:00Z",
      closed_at: null,
      replan_count: 0,
      degraded_flags: [],
      escalated: false,
      external_unsynced: false,
      row_version: 1,
      event_context_snapshot: {},
    },
    writeback_required: true,
    writeback_readiness: "ready",
    writeback_overall_status: "pending",
    pending_writeback_count: 1,
    gate_applicable_outstanding_count: 1,
    outstanding_side_effect_count: 1,
    outstanding_side_effects: [sampleOutstanding],
    ...overrides,
  };
}

describe("OutstandingSideEffectsPanel", () => {
  it("renders nothing when no outstanding side effects are present", () => {
    const { container } = render(
      <OutstandingSideEffectsPanel
        projection={{
          gate_applicable_outstanding_count: 0,
          outstanding_side_effect_count: 0,
          outstanding_side_effects: [],
          background_side_effects_pending: false,
        }}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders structured outstanding rows with reason, scope, and action_id", () => {
    render(<OutstandingSideEffectsPanel projection={makeProjection()} />);

    expect(screen.getByTestId("outstanding-side-effects-panel")).toBeInTheDocument();
    expect(screen.getByTestId("outstanding-side-effects-table")).toBeInTheDocument();
    expect(screen.getByText("act-gate-1")).toBeInTheDocument();
    expect(screen.getByTestId("outstanding-scope-gate_applicable")).toHaveTextContent(
      "关单门禁",
    );
    expect(screen.getByTestId("outstanding-reason-outbox_not_confirmed")).toHaveTextContent(
      "Outbox 未确认",
    );
    expect(screen.getByText("终态写回")).toBeInTheDocument();
    expect(screen.getByText("门禁待收敛")).toBeInTheDocument();
    expect(screen.getByText("Outstanding 总数")).toBeInTheDocument();
  });

  it("shows degraded alert when convergence counts are unavailable", () => {
    render(
      <OutstandingSideEffectsPanel
        projection={{
          gate_applicable_outstanding_count: -1,
          outstanding_side_effect_count: -1,
          outstanding_side_effects: [],
        }}
      />,
    );

    expect(screen.getByTestId("outstanding-side-effects-degraded")).toBeInTheDocument();
    expect(screen.queryByTestId("outstanding-side-effects-table")).not.toBeInTheDocument();
  });

  it("shows background pending info without gate rows", () => {
    render(
      <OutstandingSideEffectsPanel
        projection={{
          gate_applicable_outstanding_count: 0,
          outstanding_side_effect_count: 1,
          background_side_effects_pending: true,
          outstanding_side_effects: [
            {
              ...sampleOutstanding,
              action_id: "act-bg-1",
              scope: "background_detached",
              blocking_reason: "in_flight_job",
            },
          ],
        }}
      />,
    );

    expect(screen.getByTestId("outstanding-side-effects-background")).toBeInTheDocument();
    expect(screen.getByTestId("outstanding-scope-background_detached")).toHaveTextContent(
      "后台/游离",
    );
  });

  it("links action_id to actions tab when handler provided", async () => {
    const user = userEvent.setup();
    const onNavigateActionsTab = vi.fn();

    render(
      <OutstandingSideEffectsPanel
        projection={makeProjection()}
        onNavigateActionsTab={onNavigateActionsTab}
      />,
    );

    await user.click(screen.getByTestId("outstanding-action-link-act-gate-1"));
    expect(onNavigateActionsTab).toHaveBeenCalledTimes(1);
  });
});
