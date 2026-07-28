/** approvalStore unit tests (ISSUE-073). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { notification } from "antd";

vi.mock("../../src/services/eventApi", () => ({
  listEvents: vi.fn(),
  listActions: vi.fn(),
  approveAction: vi.fn(),
  rejectAction: vi.fn(),
}));

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: vi.fn(),
    onEvent: vi.fn(() => vi.fn()),
  },
}));

import { listEvents, listActions, approveAction } from "../../src/services/eventApi";
import { socketClient } from "../../src/services/socketClient";
import { useApprovalStore } from "../../src/stores/approvalStore";
import type { SocketEvent } from "../../src/types/socket";

describe("approvalStore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useApprovalStore.setState({
      pendingApprovals: [],
      loading: false,
      error: null,
      unreadCount: 0,
      approvalDeadlines: {},
      _pollTimer: null,
      _globalSocketUnsub: null,
      _eventIds: [],
    });
    vi.spyOn(notification, "info").mockImplementation(() => ({}) as never);
  });

  it("loadPendingApprovals requests waiting_approval status filter", async () => {
    vi.mocked(listActions).mockResolvedValue({
      data: {
        total: 1,
        page: 1,
        page_size: 200,
        items: [
          {
            action_id: "act-1",
            event_id: "evt-1",
            action_name: "block_ip",
            tool_name: "block_ip",
            action_level: "l4",
            action_category: "response",
            execution_phase: "immediate",
            status: "waiting_approval",
            parameters: {},
            updated_at: new Date().toISOString(),
          },
        ],
      },
    } as never);

    await useApprovalStore.getState().loadPendingApprovals(["evt-1"]);

    expect(listActions).toHaveBeenCalledWith("evt-1", {
      page_size: 200,
      status: "waiting_approval",
    });
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(1);
  });

  it("approve passes comment and decision_id to API", async () => {
    useApprovalStore.setState({
      pendingApprovals: [
        {
          action_id: "act-1",
          event_id: "evt-1",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          action_category: "response",
          execution_phase: "immediate",
          status: "waiting_approval",
          parameters: {},
          updated_at: new Date().toISOString(),
        },
      ],
    });
    vi.mocked(approveAction).mockResolvedValue({ data: {} } as never);

    await useApprovalStore.getState().approve("act-1", {
      decision_id: "dec-123",
      comment: "ok",
    });

    expect(approveAction).toHaveBeenCalledWith("act-1", {
      decision_id: "dec-123",
      comment: "ok",
    });
    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
  });

  it("initGlobalListener registers socket handler once", () => {
    useApprovalStore.getState().initGlobalListener();
    useApprovalStore.getState().initGlobalListener();
    expect(socketClient.connect).toHaveBeenCalled();
    expect(socketClient.onEvent).toHaveBeenCalledTimes(1);
  });

  it("approval_required increments unread and stores deadline", async () => {
    vi.mocked(listEvents).mockResolvedValue({
      data: { total: 0, page: 1, page_size: 200, items: [] },
    } as never);
    vi.mocked(listActions).mockResolvedValue({
      data: { total: 0, page: 1, page_size: 200, items: [] },
    } as never);

    let handler: ((event: SocketEvent) => void) | undefined;
    vi.mocked(socketClient.onEvent).mockImplementation((fn) => {
      handler = fn;
      return vi.fn();
    });

    useApprovalStore.getState().initGlobalListener();
    expect(handler).toBeDefined();

    handler?.({
      type: "approval_required",
      event_id: "evt-1",
      payload: {
        action_id: "act-new",
        deadline: "2099-01-01T00:00:00.000Z",
        summary: "isolate host",
      },
    });

    expect(useApprovalStore.getState().unreadCount).toBe(1);
    expect(useApprovalStore.getState().approvalDeadlines["act-new"]).toBe(
      "2099-01-01T00:00:00.000Z",
    );
    expect(notification.info).toHaveBeenCalled();
  });

  it("approval_updated removes pending action", () => {
    useApprovalStore.setState({
      pendingApprovals: [
        {
          action_id: "act-1",
          event_id: "evt-1",
          action_name: "block_ip",
          tool_name: "block_ip",
          action_level: "l4",
          action_category: "response",
          execution_phase: "immediate",
          status: "waiting_approval",
          parameters: {},
          updated_at: new Date().toISOString(),
        },
      ],
    });

    useApprovalStore.getState()._applySocketEvent({
      type: "approval_updated",
      event_id: "evt-1",
      payload: { action_id: "act-1" },
    });

    expect(useApprovalStore.getState().pendingApprovals).toHaveLength(0);
  });
});
