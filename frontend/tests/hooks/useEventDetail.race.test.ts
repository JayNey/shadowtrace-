import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  getEvent: vi.fn(),
  getEventEvidence: vi.fn(),
  getExecutionJob: vi.fn(),
  getReport: vi.fn(),
  getSourceRecord: vi.fn(),
  getTraces: vi.fn(),
  getWriteback: vi.fn(),
  listActions: vi.fn(),
  listConnectors: vi.fn(),
  listDispositions: vi.fn(),
}));

let socketHandler: ((event: { event_id: string; type: string }) => void) | undefined;

vi.mock("../../src/services/eventApi", () => api);
vi.mock("../../src/services/socketClient", () => ({
  socketClient: {
    connect: vi.fn(),
    subscribe: vi.fn(),
    forgetEvent: vi.fn(),
    onEvent: vi.fn((handler: typeof socketHandler) => {
      socketHandler = handler;
      return () => {
        if (socketHandler === handler) socketHandler = undefined;
      };
    }),
  },
}));

import { useEventDetail } from "../../src/hooks/useEventDetail";

function eventResponse(eventId: string) {
  return {
    data: {
      event: {
        event_id: eventId,
        status: "received",
        current_primary_source_record_id: null,
        event_context_snapshot: {},
      },
    },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("useEventDetail request races", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    socketHandler = undefined;
    api.getEvent.mockImplementation((eventId: string) =>
      Promise.resolve(eventResponse(eventId)),
    );
    api.getEventEvidence.mockResolvedValue({ data: null });
    api.getReport.mockResolvedValue({ data: { report: null } });
    api.getSourceRecord.mockResolvedValue({ data: null });
    api.getTraces.mockResolvedValue({ data: { items: [] } });
    api.listActions.mockResolvedValue({ data: { items: [] } });
    api.listConnectors.mockResolvedValue({ data: { items: [] } });
    api.listDispositions.mockResolvedValue({ data: { items: [] } });
    api.getExecutionJob.mockResolvedValue({ data: null });
    api.getWriteback.mockResolvedValue({ data: null });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not let an old eventId response overwrite the new event", async () => {
    const old = deferred<ReturnType<typeof eventResponse>>();
    api.getEvent.mockImplementation((eventId: string) =>
      eventId === "event-a" ? old.promise : Promise.resolve(eventResponse(eventId)),
    );
    const { result, rerender } = renderHook(
      ({ eventId }: { eventId: string | undefined }) => useEventDetail(eventId),
      { initialProps: { eventId: "event-a" } },
    );

    rerender({ eventId: "event-b" });
    await waitFor(() => expect(result.current.event?.event.event_id).toBe("event-b"));
    await act(async () => old.resolve(eventResponse("event-a")));
    expect(result.current.event?.event.event_id).toBe("event-b");
  });

  it("coalesces high-frequency socket events without dropping distinct resources", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { result } = renderHook(() => useEventDetail("event-a"));
    await waitFor(() => expect(result.current.loading).toBe(false));
    vi.clearAllMocks();

    act(() => {
      for (let index = 0; index < 10; index += 1) {
        socketHandler?.({ event_id: "event-a", type: "approval_updated" });
      }
      socketHandler?.({ event_id: "event-a", type: "writeback_updated" });
      socketHandler?.({ event_id: "event-a", type: "disposition_submitted" });
    });
    await act(async () => vi.advanceTimersByTimeAsync(50));

    expect(api.listActions).toHaveBeenCalledTimes(1);
    expect(api.getEvent).toHaveBeenCalledTimes(1);
    expect(api.listDispositions).toHaveBeenCalledTimes(1);
  });

  it("lets the initial full load finish loading after a socket refresh", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const initial = deferred<ReturnType<typeof eventResponse>>();
    api.getEvent
      .mockReturnValueOnce(initial.promise)
      .mockResolvedValue(eventResponse("event-a"));
    const { result } = renderHook(() => useEventDetail("event-a"));

    act(() => socketHandler?.({ event_id: "event-a", type: "state_change" }));
    await act(async () => vi.advanceTimersByTimeAsync(50));
    expect(result.current.loading).toBe(true);
    await act(async () => initial.resolve(eventResponse("event-a")));
    await waitFor(() => expect(result.current.loading).toBe(false));
  });

  it("invalidates an in-flight request when eventId becomes undefined", async () => {
    const initial = deferred<ReturnType<typeof eventResponse>>();
    api.getEvent.mockReturnValue(initial.promise);
    const { result, rerender } = renderHook(
      ({ eventId }: { eventId: string | undefined }) => useEventDetail(eventId),
      { initialProps: { eventId: "event-a" as string | undefined } },
    );

    rerender({ eventId: undefined });
    await act(async () => initial.resolve(eventResponse("event-a")));
    expect(result.current.event).toBeNull();
    expect(result.current.loading).toBe(false);
  });

  it("clears the pending socket timer on unmount", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { result, unmount } = renderHook(() => useEventDetail("event-a"));
    await waitFor(() => expect(result.current.loading).toBe(false));
    vi.clearAllMocks();
    act(() => socketHandler?.({ event_id: "event-a", type: "writeback_updated" }));
    unmount();
    await act(async () => vi.advanceTimersByTimeAsync(100));
    expect(api.getEvent).not.toHaveBeenCalled();
    expect(api.listDispositions).not.toHaveBeenCalled();
  });
});
