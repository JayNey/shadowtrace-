import { useCallback, useEffect, useRef, useState } from "react";
import type { CeleryInvestigationTrack } from "../types/event";
import { getTask } from "../services/eventApi";
import {
  isTerminalTaskState,
  normalizeTaskState,
  shouldAcceptTaskStateUpdate,
} from "../utils/investigationTaskTracking";

const POLL_INTERVAL_MS = 3_000;
const MAX_POLL_FAILURES = 5;

export interface RegisterCeleryTrackInput {
  event_id: string;
  task_id: string;
  intent_id?: string | null;
  state?: string;
}

export interface UseCeleryInvestigationTasksResult {
  tracksByEventId: ReadonlyMap<string, CeleryInvestigationTrack>;
  registerTrack: (input: RegisterCeleryTrackInput) => void;
  clearTrack: (eventId: string) => void;
}

/**
 * Minimal celery task polling for POST /investigate responses.
 * Polls GET /tasks/{task_id} until a terminal public state is observed.
 */
export function useCeleryInvestigationTasks(
  enabled: boolean,
): UseCeleryInvestigationTasksResult {
  const [tracksByEventId, setTracksByEventId] = useState<
    Map<string, CeleryInvestigationTrack>
  >(() => new Map());
  const tracksRef = useRef(tracksByEventId);
  tracksRef.current = tracksByEventId;

  const pollInFlightRef = useRef(false);
  const pollFailuresRef = useRef<Map<string, number>>(new Map());

  const registerTrack = useCallback((input: RegisterCeleryTrackInput) => {
    pollFailuresRef.current.delete(input.event_id);
    setTracksByEventId((prev) => {
      const next = new Map(prev);
      next.set(input.event_id, {
        event_id: input.event_id,
        task_id: input.task_id,
        intent_id: input.intent_id ?? null,
        state: normalizeTaskState(input.state ?? "PENDING"),
        poll_interrupted: false,
      });
      return next;
    });
  }, []);

  const clearTrack = useCallback((eventId: string) => {
    pollFailuresRef.current.delete(eventId);
    setTracksByEventId((prev) => {
      if (!prev.has(eventId)) return prev;
      const next = new Map(prev);
      next.delete(eventId);
      return next;
    });
  }, []);

  const pollOnce = useCallback(async () => {
    if (pollInFlightRef.current) return;

    const current = tracksRef.current;
    if (current.size === 0) return;

    pollInFlightRef.current = true;
    try {
      const entries = [...current.entries()];
      const results = await Promise.all(
        entries.map(async ([eventId, track]) => {
          if (isTerminalTaskState(track.state) || track.poll_interrupted) {
            return [eventId, track] as const;
          }
          try {
            const res = await getTask(track.task_id);
            pollFailuresRef.current.delete(eventId);
            const nextState = normalizeTaskState(res.data.state);
            if (!shouldAcceptTaskStateUpdate(track.state, nextState)) {
              return [eventId, track] as const;
            }
            return [
              eventId,
              {
                ...track,
                state: nextState,
                poll_interrupted: false,
              },
            ] as const;
          } catch {
            const failures = (pollFailuresRef.current.get(eventId) ?? 0) + 1;
            pollFailuresRef.current.set(eventId, failures);
            return [
              eventId,
              {
                ...track,
                poll_interrupted: failures >= MAX_POLL_FAILURES,
              },
            ] as const;
          }
        }),
      );

      setTracksByEventId((prev) => {
        let changed = false;
        const next = new Map(prev);
        for (const [eventId, track] of results) {
          const existing = prev.get(eventId);
          if (
            !existing ||
            existing.state !== track.state ||
            existing.task_id !== track.task_id ||
            existing.intent_id !== track.intent_id ||
            existing.poll_interrupted !== track.poll_interrupted
          ) {
            if (
              existing &&
              existing.state !== track.state &&
              !shouldAcceptTaskStateUpdate(existing.state, track.state)
            ) {
              continue;
            }
            next.set(eventId, track);
            changed = true;
          }
        }
        return changed ? next : prev;
      });
    } finally {
      pollInFlightRef.current = false;
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    void pollOnce();
    const timer = window.setInterval(() => {
      const active = [...tracksRef.current.values()].some(
        (track) => !isTerminalTaskState(track.state) && !track.poll_interrupted,
      );
      if (!active) return;
      void pollOnce();
    }, POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [enabled, pollOnce]);

  const trackCount = tracksByEventId.size;
  useEffect(() => {
    if (!enabled || trackCount === 0) return;
    void pollOnce();
  }, [enabled, trackCount, pollOnce]);

  return { tracksByEventId, registerTrack, clearTrack };
}
