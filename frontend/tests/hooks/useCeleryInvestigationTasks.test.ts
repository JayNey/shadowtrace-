import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";

const mockGetTask = vi.fn();

vi.mock("../../src/services/eventApi", () => ({
  getTask: (...args: unknown[]) => mockGetTask(...args),
}));

import { useCeleryInvestigationTasks } from "../../src/hooks/useCeleryInvestigationTasks";

describe("useCeleryInvestigationTasks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("polls getTask every 3s until terminal state", async () => {
    mockGetTask
      .mockResolvedValueOnce({ data: { task_id: "t1", state: "STARTED" } })
      .mockResolvedValue({ data: { task_id: "t1", state: "SUCCESS" } });

    const { result } = renderHook(() => useCeleryInvestigationTasks(true));

    act(() => {
      result.current.registerTrack({
        event_id: "evt-1",
        task_id: "t1",
        intent_id: null,
      });
    });

    await waitFor(() => expect(mockGetTask).toHaveBeenCalled());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
    });
    await waitFor(() =>
      expect(result.current.tracksByEventId.get("evt-1")?.state).toBe("SUCCESS"),
    );

    const callsAtTerminal = mockGetTask.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6_000);
    });
    expect(mockGetTask.mock.calls.length).toBe(callsAtTerminal);
  });

  it("marks track UNKNOWN after repeated getTask failures", async () => {
    mockGetTask.mockRejectedValue(new Error("503"));

    const { result } = renderHook(() => useCeleryInvestigationTasks(true));

    act(() => {
      result.current.registerTrack({
        event_id: "evt-1",
        task_id: "t1",
      });
    });

    for (let i = 0; i < 5; i += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3_000);
      });
    }

    await waitFor(() =>
      expect(result.current.tracksByEventId.get("evt-1")?.state).toBe("UNKNOWN"),
    );
  });

  it("does not regress terminal state on stale poll response", async () => {
    let resolveSlow: (value: { data: { task_id: string; state: string } }) => void;
    const slowPromise = new Promise<{ data: { task_id: string; state: string } }>(
      (resolve) => {
        resolveSlow = resolve;
      },
    );

    mockGetTask
      .mockResolvedValueOnce({ data: { task_id: "t1", state: "SUCCESS" } })
      .mockReturnValueOnce(slowPromise);

    const { result } = renderHook(() => useCeleryInvestigationTasks(true));

    act(() => {
      result.current.registerTrack({
        event_id: "evt-1",
        task_id: "t1",
        state: "STARTED",
      });
    });

    await waitFor(() =>
      expect(result.current.tracksByEventId.get("evt-1")?.state).toBe("SUCCESS"),
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
    });

    resolveSlow!({ data: { task_id: "t1", state: "STARTED" } });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.tracksByEventId.get("evt-1")?.state).toBe("SUCCESS");
  });
});
