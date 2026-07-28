/** ApprovalCenterPage tests (ISSUE-073). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import ApprovalPage from "../../src/pages/ApprovalPage";

const { mockIsActionTimedOut, mockLoadRevisionProgress } = vi.hoisted(() => ({
  mockIsActionTimedOut: vi.fn(() => false),
  mockLoadRevisionProgress: vi.fn(async () => new Map()),
}));

vi.mock("../../src/stores/approvalStore", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/stores/approvalStore")>();
  return {
    ...actual,
    useApprovalStore: vi.fn(),
    loadRevisionProgress: mockLoadRevisionProgress,
    isActionTimedOut: mockIsActionTimedOut,
  };
});

import { useApprovalStore } from "../../src/stores/approvalStore";

const mockStore = {
  pendingApprovals: [] as unknown[],
  loading: false,
  error: null as string | null,
  approvalDeadlines: {} as Record<string, string>,
  loadPendingApprovals: vi.fn(),
  refreshEventIds: vi.fn(async () => ["evt-test"]),
  approve: vi.fn(),
  reject: vi.fn(),
};

function setStore(overrides: Partial<typeof mockStore>) {
  (useApprovalStore as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
    ...mockStore,
    ...overrides,
  });
}

describe("ApprovalPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsActionTimedOut.mockReturnValue(false);
    mockLoadRevisionProgress.mockResolvedValue(new Map());
    setStore({});
  });

  it("renders page title", () => {
    render(<ApprovalPage />);
    expect(screen.getByText("审批中心")).toBeDefined();
  });

  it("shows empty state when no pending approvals", () => {
    render(<ApprovalPage />);
    expect(screen.getByText("暂无待审批动作")).toBeDefined();
  });

  it("renders approval cards and revision progress", async () => {
    mockLoadRevisionProgress.mockResolvedValue(
      new Map([
        [
          "evt-test:1",
          { eventId: "evt-test", planRevision: 1, decided: 1, total: 3 },
        ],
      ]),
    );
    setStore({
      pendingApprovals: [
        {
          action_id: "act-1",
          event_id: "evt-test",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          execution_phase: "immediate",
          execution_owner: "xdr_managed",
          target: "10.0.0.1",
          target_type: "ip",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date().toISOString(),
        },
      ],
    });

    render(<ApprovalPage />);
    expect(screen.getByText("block_ip")).toBeDefined();
    expect(screen.getByText("L4")).toBeDefined();
    await waitFor(() => {
      expect(screen.getByText(/本 revision 已决出 1\/3/)).toBeDefined();
    });
  });

  it("shows timed-out badge for old actions", () => {
    mockIsActionTimedOut.mockReturnValue(true);
    setStore({
      pendingApprovals: [
        {
          action_id: "act-old",
          event_id: "evt-test",
          action_name: "isolate_host",
          tool_name: "isolate_host",
          action_level: "l4",
          execution_phase: "immediate",
          execution_owner: "direct_tool",
          target: "host-1",
          target_type: "host",
          status: "waiting_approval",
          plan_revision: 1,
          updated_at: new Date(Date.now() - 40 * 60 * 1000).toISOString(),
        },
      ],
    });

    render(<ApprovalPage />);
    expect(screen.getByText("已超时")).toBeDefined();
  });

  it("shows deferred action tag", () => {
    setStore({
      pendingApprovals: [
        {
          action_id: "act-def",
          event_id: "evt-test",
          action_name: "update_disposition",
          tool_name: "update_disposition",
          action_level: "l2",
          execution_phase: "post_verify",
          execution_owner: "xdr_managed",
          target: null,
          target_type: null,
          status: "waiting_approval",
          plan_revision: 2,
          updated_at: new Date().toISOString(),
        },
      ],
    });

    render(<ApprovalPage />);
    expect(screen.getByText("POST_VERIFY")).toBeDefined();
  });

  it("displays error alert when error is set", () => {
    setStore({ error: "Network Error" });
    render(<ApprovalPage />);
    expect(screen.getByText("Network Error")).toBeDefined();
  });
});
