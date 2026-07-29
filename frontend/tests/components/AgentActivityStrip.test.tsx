/** AgentActivityStrip tests (ISSUE-085). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, waitFor, act } from "@testing-library/react";
import AgentActivityStrip from "../../src/components/dashboard/AgentActivityStrip";

const mockEnsureGlobalRoom = vi.fn();
let socketHandlers: Array<(evt: unknown) => void> = [];

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    ensureGlobalRoom: () => mockEnsureGlobalRoom(),
    onEvent: (handler: (evt: unknown) => void) => {
      socketHandlers.push(handler);
      return () => {
        socketHandlers = socketHandlers.filter((item) => item !== handler);
      };
    },
  },
}));

describe("AgentActivityStrip", () => {
  beforeEach(() => {
    mockEnsureGlobalRoom.mockClear();
    socketHandlers = [];
  });

  it("joins global socket room on mount for standalone reuse", async () => {
    render(<AgentActivityStrip />);
    await waitFor(() => expect(mockEnsureGlobalRoom).toHaveBeenCalledTimes(1));
  });

  it("shows agent progress rows from global room events", async () => {
    render(<AgentActivityStrip />);
    expect(socketHandlers).toHaveLength(1);

    socketHandlers[0]?.({
      type: "agent_progress",
      event_id: "evt-strip-1",
      payload: { agent_name: "risk_agent", message: "scoring" },
    });

    await waitFor(() => {
      expect(document.querySelector('[data-testid="agent-activity-row"]')).toBeTruthy();
    });
  });
});
