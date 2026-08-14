/** EventOperationalInsights writeback count split (ISSUE-331). */

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import EventOperationalInsights from "../../src/components/event/EventOperationalInsights";
import type { EventDetailResponse } from "../../src/types/event";

function makeDetail(): EventDetailResponse {
  return {
    event: {
      event_id: "evt-331",
      event_type: "account_anomaly",
      title: "Writeback counts",
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
        object_id: "obj-331",
        source_status_raw: "OPEN",
      },
      source_reference_snapshots: [],
      current_primary_source_record_id: null,
      disposition_source_ref: null,
      disposition_policy: "required",
      raw_alert_ids: [],
      raw_alert_snapshot: {},
      source_type: "xdr",
      occurred_at: "2026-08-14T00:00:00Z",
      created_at: "2026-08-14T00:00:00Z",
      updated_at: "2026-08-14T00:00:00Z",
      closed_at: null,
      replan_count: 0,
      degraded_flags: [],
      escalated: false,
      external_unsynced: false,
      row_version: 1,
      event_context_snapshot: {
        writeback_summary: {
          event_id: "evt-331",
          closure_cycle: 1,
          disposition_policy: "required",
          required_action_count: 3,
          applicable_action_count: 1,
          blocked_action_ids: [],
          readiness_counts: { ready: 1, not_required: 2 },
          aggregate_readiness: "ready",
          writeback_counts: { pending: 1 },
          aggregate_status: "pending",
          terminal_event_action_id: "act-terminal",
          terminal_event_writeback_id: "wb-terminal",
          terminal_event_disposition: "closed",
          terminal_event_confirmed: false,
          external_unsynced: false,
          updated_at: "2026-08-14T00:00:00Z",
        },
      },
    },
    writeback_required: true,
    writeback_readiness: "ready",
    writeback_overall_status: "pending",
    pending_writeback_count: 1,
  };
}

describe("EventOperationalInsights", () => {
  it("splits required vs applicable writeback action counts", () => {
    render(<EventOperationalInsights detail={makeDetail()} writebacks={[]} />);
    expect(screen.getByTestId("writeback-required-action-count")).toHaveTextContent("3");
    expect(screen.getByTestId("writeback-applicable-action-count")).toHaveTextContent("1");
    expect(screen.getByText("写回义务动作数")).toBeInTheDocument();
    expect(screen.getByText("可写回动作数")).toBeInTheDocument();
  });
});
