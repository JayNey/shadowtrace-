/** EventOverviewCard classification UI tests (ISSUE-209). */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import EventOverviewCard, {
  isLowConfidenceClassification,
} from "../../src/components/event/EventOverviewCard";
import { ApiError } from "../../src/services/apiClient";
import type { EventDetailResponse } from "../../src/types/event";

const mockPatch = vi.fn();
const mockCanRoles = vi.fn(() => ["analyst"]);
const mockKnownRoles = vi.fn(() => true);

vi.mock("../../src/services/eventApi", () => ({
  patchEventClassification: (...args: unknown[]) => mockPatch(...args),
}));

vi.mock("../../src/config/auth", () => ({
  currentAuthRoles: () => mockCanRoles(),
  hasKnownAuthRoles: () => mockKnownRoles(),
}));

function makeDetail(
  overrides: Partial<EventDetailResponse["event"]> = {},
): EventDetailResponse {
  return {
    event: {
      event_id: "evt-209",
      event_type: "other",
      title: "Classification overview",
      description: "test",
      status: "new",
      severity: "medium",
      risk_score: 40,
      confidence: 0.5,
      final_verdict: "none",
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
        object_id: "obj-209",
        source_status_raw: "OPEN",
      },
      source_reference_snapshots: [],
      current_primary_source_record_id: null,
      disposition_source_ref: null,
      disposition_policy: "required",
      raw_alert_ids: [],
      raw_alert_snapshot: {},
      source_type: "xdr",
      occurred_at: "2026-08-06T00:00:00Z",
      created_at: "2026-08-06T00:00:00Z",
      updated_at: "2026-08-06T00:00:00Z",
      closed_at: null,
      replan_count: 0,
      degraded_flags: [],
      escalated: false,
      external_unsynced: false,
      row_version: 1,
      event_context_snapshot: {},
      classification_source: "heuristic",
      ...overrides,
    },
    writeback_required: false,
    writeback_readiness: "not_required",
    writeback_overall_status: null,
    pending_writeback_count: 0,
  };
}

function renderCard(detail: EventDetailResponse, onRefresh = vi.fn()) {
  return render(
    <AntApp>
      <EventOverviewCard detail={detail} onRefresh={onRefresh} />
    </AntApp>,
  );
}

describe("isLowConfidenceClassification", () => {
  it("flags other / heuristic / llm_fallback", () => {
    expect(isLowConfidenceClassification("other", "source")).toBe(true);
    expect(isLowConfidenceClassification("account_anomaly", "heuristic")).toBe(true);
    expect(isLowConfidenceClassification("account_anomaly", "llm_fallback")).toBe(true);
    expect(isLowConfidenceClassification("account_anomaly", "source")).toBe(false);
    expect(isLowConfidenceClassification("account_anomaly", "human")).toBe(false);
  });
});

describe("EventOverviewCard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCanRoles.mockReturnValue(["analyst"]);
    mockKnownRoles.mockReturnValue(true);
    mockPatch.mockResolvedValue({
      data: {
        event_id: "evt-209",
        event_type: "data_exfiltration",
        classification_source: "human",
        previous_event_type: "other",
        reinvestigate_requested: false,
        reinvestigate_started: false,
        side_effects: [],
      },
    });
  });

  it("shows low-confidence chip and reclassify entry for analyst", () => {
    renderCard(makeDetail());
    expect(screen.getByTestId("low-confidence-chip")).toBeInTheDocument();
    expect(screen.getByTestId("classification-source-chip")).toHaveTextContent("启发式");
    expect(screen.getByTestId("reclassify-open")).toBeInTheDocument();
  });

  it("hides reclassify for non-analyst roles", () => {
    mockCanRoles.mockReturnValue(["approver"]);
    renderCard(makeDetail({ event_type: "account_anomaly", classification_source: "source" }));
    expect(screen.queryByTestId("reclassify-open")).not.toBeInTheDocument();
    expect(screen.queryByTestId("low-confidence-chip")).not.toBeInTheDocument();
  });

  it("keeps reclassify visible when roles are unknown", () => {
    mockKnownRoles.mockReturnValue(false);
    mockCanRoles.mockReturnValue(["approver"]);
    renderCard(makeDetail());
    expect(screen.getByTestId("reclassify-open")).toBeInTheDocument();
  });

  it("prefers risk_assessment severity and shows triage chip when divergent", () => {
    renderCard(
      makeDetail({
        severity: "high",
        risk_score: 77,
        event_context_snapshot: {
          risk_assessment: {
            risk_score: 77,
            severity: "high",
            confidence: 0.8,
            risk_factors: [],
            possible_false_positive: false,
            scoring_mode: "rule_only",
          },
          triage_severity: "medium",
        },
      }),
    );
    expect(screen.getByText("高")).toBeInTheDocument();
    expect(screen.getByTestId("overview-triage-severity-tag")).toHaveTextContent("分诊 中");
  });

  it("hides triage chip when severities match", () => {
    renderCard(
      makeDetail({
        severity: "high",
        event_context_snapshot: {
          risk_assessment: {
            risk_score: 77,
            severity: "high",
            confidence: 0.8,
            risk_factors: [],
            possible_false_positive: false,
            scoring_mode: "rule_only",
          },
          triage_severity: "high",
        },
      }),
    );
    expect(screen.queryByTestId("overview-triage-severity-tag")).not.toBeInTheDocument();
  });

  it("falls back to event.severity when risk_assessment is absent", () => {
    renderCard(makeDetail({ severity: "medium", event_context_snapshot: {} }));
    expect(screen.getByText("中")).toBeInTheDocument();
    expect(screen.queryByTestId("overview-triage-severity-tag")).not.toBeInTheDocument();
  });

  it("does not show triage chip when API snapshot omits triage_severity", () => {
    renderCard(
      makeDetail({
        severity: "high",
        event_context_snapshot: {
          risk_assessment: {
            risk_score: 77,
            severity: "high",
            confidence: 0.8,
            risk_factors: [],
            possible_false_positive: false,
            scoring_mode: "rule_only",
          },
        },
      }),
    );
    expect(screen.getByText("高")).toBeInTheDocument();
    expect(screen.queryByTestId("overview-triage-severity-tag")).not.toBeInTheDocument();
  });

  it("submits trimmed reason and refreshes on success", async () => {
    const user = userEvent.setup();
    const onRefresh = vi.fn().mockResolvedValue(undefined);
    renderCard(makeDetail(), onRefresh);

    await user.click(screen.getByTestId("reclassify-open"));
    await user.type(screen.getByLabelText(/原因/), "  source mismatch  ");
    await user.click(screen.getByRole("button", { name: "保 存" }));

    await waitFor(() =>
      expect(mockPatch).toHaveBeenCalledWith("evt-209", {
        event_type: "other",
        reason: "source mismatch",
        reinvestigate: false,
      }),
    );
    await waitFor(() => expect(onRefresh).toHaveBeenCalled());
  });

  it("surfaces classification conflict errors", async () => {
    const user = userEvent.setup();
    mockPatch.mockRejectedValue(
      new ApiError({
        error_code: "classification_conflict_active_investigation",
        error_message: "classification cannot change while verifying",
      }),
    );
    renderCard(makeDetail());
    await user.click(screen.getByTestId("reclassify-open"));
    await user.type(screen.getByLabelText(/原因/), "blocked");
    await user.click(screen.getByRole("button", { name: "保 存" }));
    expect(
      await screen.findByText(/classification cannot change while verifying/),
    ).toBeInTheDocument();
  });

  it("shows pending citation strip when rag_citations is absent", () => {
    renderCard(makeDetail({ event_context_snapshot: {} }));
    expect(screen.getByTestId("rag-citation-pending")).toHaveTextContent("检索未完成");
    expect(screen.queryByTestId("rag-citation-fp")).not.toBeInTheDocument();
    expect(screen.queryByText("误报裁决")).not.toBeInTheDocument();
    expect(screen.queryByText("组织上下文")).not.toBeInTheDocument();
  });

  it("shows empty citation slots after retrieval with no hits", () => {
    renderCard(
      makeDetail({
        event_context_snapshot: {
          rag_citations: { retrieved: true, degraded: false },
        },
      }),
    );
    expect(screen.queryByTestId("rag-citation-pending")).not.toBeInTheDocument();
    expect(screen.getByTestId("rag-citation-fp-value")).toHaveTextContent("未命中误报卡");
    expect(screen.getByTestId("rag-citation-org-value")).toHaveTextContent("无组织约束");
    expect(screen.getByTestId("rag-citation-playbook-value")).toHaveTextContent("无剧本引用");
    expect(screen.getByTestId("rag-citation-attack-value")).toHaveTextContent("无攻击技术");
  });

  it("shows hit citation slots and optional tool / adjudication suffix", async () => {
    const user = userEvent.setup();
    const onNavigateTab = vi.fn();
    render(
      <AntApp>
        <EventOverviewCard
          detail={makeDetail({
            event_context_snapshot: {
              rag_citations: {
                retrieved: true,
                degraded: true,
                fp_case_id: "case-00000001",
                playbook_ids: ["pb-c8d9e0f1"],
                attack_techniques: [
                  { technique_id: "T1021", technique_name: "Remote Services" },
                ],
              },
              org_context_matches: [
                { kind: "time_window", matched_value: "08:00-12:00" },
              ],
              fp_adjudication: { recommendation: "close_as_fp" },
            },
          })}
          primaryActionTool="block_domain"
          onNavigateTab={onNavigateTab}
        />
      </AntApp>,
    );
    expect(screen.getByTestId("rag-citation-degraded")).toHaveTextContent("检索降级");
    expect(screen.getByTestId("rag-citation-fp-value")).toHaveTextContent(
      "命中 case-00000001 · close_as_fp",
    );
    expect(screen.getByTestId("rag-citation-org-value")).toHaveTextContent(
      "time_window 08:00-12:00",
    );
    expect(screen.getByTestId("rag-citation-playbook-value")).toHaveTextContent(
      "pb-c8d9e0f1 · block_domain",
    );
    expect(screen.getByTestId("rag-citation-attack-value")).toHaveTextContent(
      "T1021 Remote Services",
    );
    await user.click(screen.getByTestId("rag-citation-playbook-value"));
    expect(onNavigateTab).toHaveBeenCalledWith("actions");
    await user.click(screen.getByTestId("rag-citation-attack-value"));
    expect(onNavigateTab).toHaveBeenCalledWith("report");
  });
});
