/** AgentStatusPanel tests — socket drive, feed cap, traces replay (ISSUE-075). */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import type { AgentTrace } from "../../src/types/trace";
import {
  ALL_AGENT_NAMES,
  useAgentStatusStore,
} from "../../src/stores/agentStatusStore";

const mockGetTraces = vi.fn();

vi.mock("../../src/services/eventApi", () => ({
  getTraces: (...args: unknown[]) => mockGetTraces(...args),
}));

type SocketHandler = (event: {
  type: string;
  event_id: string;
  payload: Record<string, unknown>;
}) => void;

let socketHandler: SocketHandler | undefined;
let connected = false;

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: vi.fn(() => {
      connected = true;
    }),
    subscribe: vi.fn(),
    get isConnected() {
      return connected;
    },
    onEvent: (handler: SocketHandler) => {
      socketHandler = handler;
      return () => {
        socketHandler = undefined;
      };
    },
  },
}));

import AgentStatusPanel from "../../src/components/agent/AgentStatusPanel";

function makeTrace(overrides: Partial<AgentTrace> = {}): AgentTrace {
  return {
    trace_id: "trc-1",
    event_id: "evt-75",
    agent_name: "triage_agent",
    status: "completed",
    input_data: null,
    output_data: null,
    started_at: "2026-07-28T10:00:00Z",
    completed_at: "2026-07-28T10:00:01Z",
    duration_ms: 1000,
    error_detail: null,
    llm_model: null,
    llm_tokens_used: null,
    ...overrides,
  };
}

function emitSocket(
  type: string,
  payload: Record<string, unknown>,
  eventId = "evt-75",
) {
  act(() => {
    socketHandler?.({ type, event_id: eventId, payload });
  });
}

describe("AgentStatusPanel", () => {
  beforeEach(() => {
    connected = false;
    socketHandler = undefined;
    mockGetTraces.mockResolvedValue({ data: { items: [], total: 0, page: 1, page_size: 50 } });
    act(() => {
      useAgentStatusStore.getState().reset();
      useAgentStatusStore.setState({ pollTimer: null, socketUnsub: null });
    });
  });

  afterEach(() => {
    act(() => {
      useAgentStatusStore.getState().stopWatching();
    });
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("renders 12 fixed Agent cards with Chinese labels", () => {
    render(
      <AgentStatusPanel eventId="evt-75" eventStatus="analyzing" traces={[]} />,
    );

    expect(screen.getByTestId("agent-status-panel")).toBeInTheDocument();
    expect(screen.getByText("分诊")).toBeInTheDocument();
    expect(screen.getByText("证据采集")).toBeInTheDocument();
    for (const name of ALL_AGENT_NAMES) {
      expect(screen.getByTestId(`agent-card-${name}`)).toBeInTheDocument();
    }
  });

  it("marks socketConnected true after connect without waiting for agent events", async () => {
    render(
      <AgentStatusPanel eventId="evt-75" eventStatus="analyzing" traces={[]} />,
    );

    await waitFor(() => {
      expect(useAgentStatusStore.getState().socketConnected).toBe(true);
    });
    expect(screen.queryByText(/轮询降级/)).not.toBeInTheDocument();
  });

  it("drives PROCESSING then COMPLETED from socket events", async () => {
    render(
      <AgentStatusPanel eventId="evt-75" eventStatus="analyzing" traces={[]} />,
    );

    await waitFor(() => expect(socketHandler).toBeDefined());

    emitSocket("agent_progress", {
      agent_name: "triage_agent",
      message: "提取 IOC…",
      progress_percent: 40,
    });

    const card = screen.getByTestId("agent-card-triage_agent");
    expect(card).toHaveAttribute("data-status", "PROCESSING");
    expect(screen.getAllByText("提取 IOC…").length).toBeGreaterThanOrEqual(1);

    emitSocket("agent_completed", {
      agent_name: "triage_agent",
      output_summary: "分诊完成",
      duration_ms: 850,
    });

    expect(card).toHaveAttribute("data-status", "COMPLETED");
    expect(screen.getAllByText("分诊完成").length).toBeGreaterThanOrEqual(1);
  });

  it("marks FAILED red and appends error to activity feed", async () => {
    render(
      <AgentStatusPanel eventId="evt-75" eventStatus="analyzing" traces={[]} />,
    );
    await waitFor(() => expect(socketHandler).toBeDefined());

    emitSocket("agent_failed", {
      agent_name: "evidence_agent",
      error: "LLM timeout after 3 retries",
    });

    const card = screen.getByTestId("agent-card-evidence_agent");
    expect(card).toHaveAttribute("data-status", "FAILED");

    const feed = screen.getByTestId("agent-activity-feed");
    expect(feed.textContent).toContain("LLM timeout after 3 retries");
  });

  it("caps activity feed at 200 entries", () => {
    const { applyAgentProgress } = useAgentStatusStore.getState();

    act(() => {
      for (let i = 0; i < 210; i += 1) {
        applyAgentProgress({
          agent_name: "triage_agent",
          message: `step-${i}`,
          progress_percent: i % 100,
        });
      }
    });

    expect(useAgentStatusStore.getState().feed).toHaveLength(200);
    expect(useAgentStatusStore.getState().feed[0].message).toBe("step-10");
    expect(useAgentStatusStore.getState().feed[199].message).toBe("step-209");
  });

  it("does not let delayed pollTraces overwrite live socket PROCESSING", async () => {
    let resolveTraces!: (value: unknown) => void;
    mockGetTraces.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveTraces = resolve;
        }),
    );

    render(
      <AgentStatusPanel eventId="evt-75" eventStatus="analyzing" traces={[]} />,
    );
    await waitFor(() => expect(socketHandler).toBeDefined());

    emitSocket("agent_progress", {
      agent_name: "triage_agent",
      message: "live progress",
      progress_percent: 40,
    });
    expect(useAgentStatusStore.getState().agents.triage_agent.status).toBe(
      "PROCESSING",
    );
    expect(useAgentStatusStore.getState().agents.triage_agent.message).toBe(
      "live progress",
    );

    await act(async () => {
      resolveTraces({
        data: {
          items: [
            makeTrace({
              agent_name: "triage_agent",
              status: "completed",
              duration_ms: 1,
            }),
          ],
          total: 1,
          page: 1,
          page_size: 50,
        },
      });
      await Promise.resolve();
    });

    expect(useAgentStatusStore.getState().agents.triage_agent.status).toBe(
      "PROCESSING",
    );
    expect(useAgentStatusStore.getState().agents.triage_agent.message).toBe(
      "live progress",
    );
    expect(useAgentStatusStore.getState().isInvestigating).toBe(true);
  });

  it("polls traces every 10s only when socket is disconnected", async () => {
    vi.useFakeTimers();
    connected = true;
    mockGetTraces.mockResolvedValue({
      data: { items: [], total: 0, page: 1, page_size: 50 },
    });

    render(
      <AgentStatusPanel eventId="evt-75" eventStatus="analyzing" traces={[]} />,
    );

    await act(async () => {
      await Promise.resolve();
    });
    const callsAfterStart = mockGetTraces.mock.calls.length;
    expect(callsAfterStart).toBeGreaterThanOrEqual(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(mockGetTraces.mock.calls.length).toBe(callsAfterStart);

    connected = false;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(mockGetTraces.mock.calls.length).toBe(callsAfterStart + 1);
    expect(useAgentStatusStore.getState().socketConnected).toBe(false);
  });

  it("replays historical status from traces on closed events", async () => {
    const traces: AgentTrace[] = [
      makeTrace({
        trace_id: "trc-triage",
        agent_name: "triage_agent",
        status: "completed",
        duration_ms: 500,
        started_at: "2026-07-28T10:00:00Z",
        completed_at: "2026-07-28T10:00:00.500Z",
      }),
      makeTrace({
        trace_id: "trc-evidence",
        agent_name: "evidence_agent",
        status: "failed",
        error_detail: "query_siem unavailable",
        started_at: "2026-07-28T10:00:01Z",
        completed_at: "2026-07-28T10:00:02Z",
        duration_ms: 1000,
      }),
    ];

    render(
      <AgentStatusPanel
        eventId="evt-75"
        eventStatus="closed"
        traces={traces}
      />,
    );

    // CLOSED collapses the panel; assert replay via store + header activity count.
    await waitFor(() => {
      const state = useAgentStatusStore.getState();
      expect(state.agents.triage_agent.status).toBe("COMPLETED");
      expect(state.agents.evidence_agent.status).toBe("FAILED");
      expect(
        state.feed.some((e) => e.message.includes("query_siem unavailable")),
      ).toBe(true);
    });
    expect(screen.getByText(/2\s*条活动/)).toBeInTheDocument();
    expect(screen.getByText("已结案回放")).toBeInTheDocument();
    expect(screen.getByTestId("agent-status-replay-summary")).toHaveTextContent(
      "1 完成 · 1 失败",
    );
  });

  it("defaults expanded while investigating and collapsed when CLOSED", () => {
    const { rerender } = render(
      <AgentStatusPanel eventId="evt-75" eventStatus="analyzing" traces={[]} />,
    );

    expect(screen.getByTestId("agent-card-triage_agent")).toBeVisible();
    expect(
      screen.getByRole("button", { name: /Agent 实时状态/ }).getAttribute(
        "aria-expanded",
      ),
    ).toBe("true");

    rerender(
      <AgentStatusPanel eventId="evt-75" eventStatus="closed" traces={[]} />,
    );

    expect(
      screen.getByRole("button", { name: /Agent 实时状态/ }).getAttribute(
        "aria-expanded",
      ),
    ).toBe("false");
  });
});
