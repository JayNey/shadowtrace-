/** SocDashboardPage tests (ISSUE-085). */

import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { App as AntApp } from "antd";
import type { StatsResponse } from "../../src/types/stats";

const mockGetStats = vi.fn();
const mockListEvents = vi.fn();

vi.mock("../../src/services/apiClient", async () => {
  const actual = await vi.importActual<typeof import("../../src/services/apiClient")>(
    "../../src/services/apiClient",
  );
  return {
    ...actual,
    default: {
      get: (...args: unknown[]) => mockGetStats(...args),
    },
    showApiErrorToast: () => {},
    setApiErrorToastHandler: () => {},
  };
});

vi.mock("../../src/services/eventApi", () => ({
  listEvents: (...args: unknown[]) => mockListEvents(...args),
}));

let socketHandler: ((evt: unknown) => void) | undefined;
const mockSocketConnect = vi.fn();

vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: () => mockSocketConnect(),
    onEvent: (h: (evt: unknown) => void) => {
      socketHandler = h;
      return () => {
        socketHandler = undefined;
      };
    },
    get isConnected() {
      return true;
    },
  },
}));

vi.mock("echarts-for-react", () => ({
  default: ({ option }: { option: unknown }) => (
    <div data-testid="echarts-mock">{JSON.stringify(option)}</div>
  ),
}));

function makeStats(over: Partial<StatsResponse> = {}): StatsResponse {
  return {
    total_events: 3,
    by_status: { new: 1, closed: 1, analyzing: 1 },
    by_severity: { critical: 1, high: 1, low: 1 },
    by_event_type: { data_exfiltration: 1, host_compromise: 1, account_anomaly: 1 },
    action_execution_success_rate: { rate: 1, numerator: 1, denominator: 1 },
    effect_verification_rate: { rate: 0, numerator: 0, denominator: 1 },
    writeback_confirmation_rate: { rate: null, numerator: 0, denominator: 0 },
    avg_investigation_seconds: 3600,
    events_last_24h: [
      { hour: "2026-07-29T08:00:00Z", count: 1 },
      { hour: "2026-07-29T09:00:00Z", count: 2 },
    ],
    open_events: 2,
    closed_events: 1,
    pending_approvals: 0,
    pending_writebacks: 0,
    external_unsynced_events: 0,
    ...over,
  };
}

function renderPage() {
  return render(
    <AntApp>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Routes>
          <Route path="/dashboard" element={<SocDashboardPage />} />
          <Route path="/events" element={<div>events-ok</div>} />
        </Routes>
      </MemoryRouter>
    </AntApp>,
  );
}

let SocDashboardPage: typeof import("../../src/pages/SocDashboardPage").default;

beforeAll(async () => {
  ({ default: SocDashboardPage } = await import("../../src/pages/SocDashboardPage"));
}, 60_000);

describe("SocDashboardPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    socketHandler = undefined;
    mockGetStats.mockResolvedValue({ data: makeStats() });
    mockListEvents.mockResolvedValue({
      data: {
        items: [
          {
            event_id: "evt-crit-1",
            title: "Critical sample",
            severity: "critical",
            event_type: "data_exfiltration",
            status: "new",
            risk_score: 90,
            final_verdict: "none",
            writeback_required: false,
            writeback_readiness: "not_required",
            writeback_overall_status: null,
            pending_writeback_count: 0,
            created_at: "2026-07-29T08:00:00Z",
            updated_at: null,
            occurred_at: null,
          },
        ],
        total: 1,
        page: 1,
        page_size: 10,
      },
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders dark theme shell and three separate rate cards", async () => {
    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId("soc-dashboard")).toHaveClass("soc-dark");
    });

    expect(screen.getByText("ShadowTrace SOC")).toBeInTheDocument();
    expect(screen.getByText("动作执行成功率")).toBeInTheDocument();
    expect(screen.getByText("效果验证率")).toBeInTheDocument();
    expect(screen.getByText("写回确认率")).toBeInTheDocument();
    // Must never present a folded single success rate label.
    expect(screen.queryByText("处置成功率")).not.toBeInTheDocument();
    expect(screen.queryByText(/action_success_rate/i)).not.toBeInTheDocument();

    expect(screen.getByTestId("severity-pie-chart")).toBeInTheDocument();
    expect(screen.getByTestId("event-trend-chart")).toBeInTheDocument();
    expect(screen.getByTestId("high-risk-ticker")).toBeInTheDocument();
  });

  it("shows fullscreen toggle button", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByTestId("soc-fullscreen")).toBeInTheDocument());
    expect(screen.getByTestId("soc-fullscreen")).toHaveTextContent("全屏模式");
  });

  it("refreshes stats on a 30s interval", async () => {
    renderPage();
    await waitFor(() => expect(mockGetStats).toHaveBeenCalled());
    const initialCalls = mockGetStats.mock.calls.length;

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });

    await waitFor(() => {
      expect(mockGetStats.mock.calls.length).toBeGreaterThan(initialCalls);
    });
  });

  it("appends high-risk events from socket into the ticker", async () => {
    renderPage();
    await waitFor(() => expect(mockSocketConnect).toHaveBeenCalled());
    await waitFor(() => expect(socketHandler).toBeDefined());

    act(() => {
      socketHandler?.({
        type: "event_created",
        event_id: "evt-socket-high",
        payload: {
          event_id: "evt-socket-high",
          severity: "high",
          event_type: "host_compromise",
          created_at: "2026-07-29T10:00:00Z",
        },
      });
    });

    await waitFor(() => {
      // Ticker duplicates items for seamless marquee scroll.
      expect(screen.getAllByText("evt-socket-high").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("manual refresh reloads stats", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderPage();
    await waitFor(() => expect(mockGetStats).toHaveBeenCalled());
    const before = mockGetStats.mock.calls.length;

    await user.click(screen.getByTestId("soc-refresh"));

    await waitFor(() => {
      expect(mockGetStats.mock.calls.length).toBeGreaterThan(before);
    });
  });

  it("does not break sibling routes when dashboard is mounted", async () => {
    render(
      <AntApp>
        <MemoryRouter initialEntries={["/events"]}>
          <Routes>
            <Route path="/dashboard" element={<SocDashboardPage />} />
            <Route path="/events" element={<div>events-ok</div>} />
          </Routes>
        </MemoryRouter>
      </AntApp>,
    );
    expect(screen.getByText("events-ok")).toBeInTheDocument();
    expect(screen.queryByTestId("soc-dashboard")).not.toBeInTheDocument();
  });
});
