/** Agent real-time status store — socket-driven + traces fallback (ISSUE-075). */

import { create } from "zustand";
import type { AgentTrace } from "../types/trace";
import type {
  SocketAgentCompletedPayload,
  SocketAgentFailedPayload,
  SocketAgentProgressPayload,
} from "../types/socket";
import { socketClient } from "../services/socketClient";
import { getTraces } from "../services/eventApi";

/* ------------------------------------------------------------------ */
/*  Agent identities (12 agents — intro §4.4)                         */
/* ------------------------------------------------------------------ */

export const ALL_AGENT_NAMES = [
  "super_agent",
  "planner_agent",
  "triage_agent",
  "evidence_agent",
  "graph_agent",
  "rag_agent",
  "risk_agent",
  "response_agent",
  "verify_agent",
  "report_agent",
  "memory_agent",
  "tool_agent",
] as const;

export type AgentName = (typeof ALL_AGENT_NAMES)[number];

/** Chinese labels for the 12 agents (ISSUE-075 unified naming). */
export const AGENT_LABELS: Record<AgentName, string> = {
  super_agent: "编排",
  planner_agent: "规划",
  triage_agent: "分诊",
  evidence_agent: "证据采集",
  graph_agent: "图谱构建",
  rag_agent: "知识检索",
  risk_agent: "风险评分",
  response_agent: "处置建议",
  verify_agent: "验证",
  report_agent: "报告生成",
  memory_agent: "记忆归档",
  tool_agent: "工具调度",
};

/* ------------------------------------------------------------------ */
/*  AgentStatus (5 states — ISSUE-075 unified naming)                 */
/* ------------------------------------------------------------------ */

export type AgentStatus =
  | "IDLE"
  | "PROCESSING"
  | "COMPLETED"
  | "FAILED"
  | "DEGRADED";

/** Color mapping per AgentStatus. */
export const AGENT_STATUS_COLORS: Record<AgentStatus, string> = {
  IDLE: "#8c8c8c",
  PROCESSING: "#1677ff",
  COMPLETED: "#52c41a",
  FAILED: "#ff4d4f",
  DEGRADED: "#fa8c16",
};

/** Silence window: poll traces when no agent_* arrives (false "connected"). */
export const AGENT_SOCKET_SILENCE_MS = 10_000;

/* ------------------------------------------------------------------ */
/*  Per-agent info                                                    */
/* ------------------------------------------------------------------ */

export interface AgentStatusInfo {
  agent_name: AgentName;
  status: AgentStatus;
  message: string | null;
  progress_percent: number | null;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  error_detail: string | null;
}

/** Empty initial state for each of the 12 agents. */
function defaultAgentInfo(name: AgentName): AgentStatusInfo {
  return {
    agent_name: name,
    status: "IDLE",
    message: null,
    progress_percent: null,
    started_at: null,
    completed_at: null,
    duration_ms: null,
    error_detail: null,
  };
}

function defaultAgentMap(): Record<AgentName, AgentStatusInfo> {
  const map = {} as Record<AgentName, AgentStatusInfo>;
  for (const name of ALL_AGENT_NAMES) {
    map[name] = defaultAgentInfo(name);
  }
  return map;
}

/** True when a recent agent_* socket event is driving the panel. */
export function hasFreshAgentSocketTraffic(
  lastAgentEventAt: number,
  now = Date.now(),
): boolean {
  return lastAgentEventAt > 0 && now - lastAgentEventAt < AGENT_SOCKET_SILENCE_MS;
}

/**
 * Protect live socket UI from traces overwrite only while agent traffic is fresh.
 * Transport-connected but silent sockets must NOT block poll / replay (ISSUE-075).
 */
export function shouldProtectLiveSocketState(
  isInvestigating: boolean,
  connected: boolean,
  lastAgentEventAt: number,
  now = Date.now(),
): boolean {
  return (
    isInvestigating &&
    connected &&
    hasFreshAgentSocketTraffic(lastAgentEventAt, now)
  );
}

/* ------------------------------------------------------------------ */
/*  Activity feed                                                     */
/* ------------------------------------------------------------------ */

export interface ActivityFeedEntry {
  /** Local monotonic id for React keys. */
  id: number;
  timestamp: string;
  agent_name: AgentName;
  message: string;
}

const MAX_FEED_ENTRIES = 200;
let feedIdCounter = 0;

function pushFeedEntry(
  entries: ActivityFeedEntry[],
  agent_name: AgentName,
  message: string,
  timestamp?: string,
): ActivityFeedEntry[] {
  const entry: ActivityFeedEntry = {
    id: ++feedIdCounter,
    timestamp: timestamp ?? new Date().toISOString(),
    agent_name,
    message,
  };
  // Append (oldest → newest) so ActivityFeed can auto-scroll to latest.
  const next = [...entries, entry];
  return next.length > MAX_FEED_ENTRIES
    ? next.slice(-MAX_FEED_ENTRIES)
    : next;
}

/* ------------------------------------------------------------------ */
/*  Store state                                                       */
/* ------------------------------------------------------------------ */

interface AgentStatusState {
  /** Per-agent status map. */
  agents: Record<AgentName, AgentStatusInfo>;

  /** Activity feed (oldest → newest; capped at 200). */
  feed: ActivityFeedEntry[];

  /** Whether a real-time investigation is currently running. */
  isInvestigating: boolean;

  /** Whether socket is currently connected. */
  socketConnected: boolean;

  /** Epoch ms of last agent_progress / completed / failed (0 = none). */
  lastAgentEventAt: number;

  /** Poll fallback interval id. */
  pollTimer: ReturnType<typeof setInterval> | null;
  /** Socket unsubscribe function. */
  socketUnsub: (() => void) | null;
  /** Event id currently watched (for subscription cleanup). */
  watchedEventId: string | null;

  /* ---- actions ---- */

  /** Start listening for a specific event's agent status. */
  startWatching: (eventId: string) => void;
  /** Stop listening and reset state. */
  stopWatching: () => void;

  /** Apply a socket agent_progress event. */
  applyAgentProgress: (payload: SocketAgentProgressPayload) => void;
  /** Apply a socket agent_completed event. */
  applyAgentCompleted: (payload: SocketAgentCompletedPayload) => void;
  /** Apply a socket agent_failed event. */
  applyAgentFailed: (payload: SocketAgentFailedPayload) => void;

  /** Replay historical status from traces data. */
  replayFromTraces: (traces: AgentTrace[]) => void;

  /** Fallback: poll traces endpoint. */
  pollTraces: (eventId: string) => Promise<void>;

  /** Reset all agents to IDLE and clear feed. */
  reset: () => void;
}

export const useAgentStatusStore = create<AgentStatusState>((set, get) => ({
  agents: defaultAgentMap(),
  feed: [],
  isInvestigating: false,
  socketConnected: false,
  lastAgentEventAt: 0,
  pollTimer: null,
  socketUnsub: null,
  watchedEventId: null,

  /* ---- actions ---- */

  startWatching(eventId: string) {
    const { socketUnsub, pollTimer, watchedEventId } = get();
    // Clean up previous watchers.
    socketUnsub?.();
    if (pollTimer) {
      clearInterval(pollTimer);
      set({ pollTimer: null });
    }
    if (watchedEventId && watchedEventId !== eventId) {
      socketClient.forgetEvent(watchedEventId);
    }

    // Reset state for new event.
    set({
      agents: defaultAgentMap(),
      feed: [],
      isInvestigating: false,
      socketConnected: false,
      lastAgentEventAt: 0,
      watchedEventId: eventId,
    });

    // Connect then subscribe (subscribe queues until transport is up).
    socketClient.connect();
    socketClient.subscribe(eventId);
    set({ socketConnected: socketClient.isConnected });

    const unsub = socketClient.onEvent((evt) => {
      if (evt.event_id !== eventId) return;
      if (evt.type === "agent_progress") {
        set({ socketConnected: true });
        get().applyAgentProgress(
          evt.payload as unknown as SocketAgentProgressPayload,
        );
        return;
      }
      if (evt.type === "agent_completed") {
        set({ socketConnected: true });
        get().applyAgentCompleted(
          evt.payload as unknown as SocketAgentCompletedPayload,
        );
        return;
      }
      if (evt.type === "agent_failed") {
        set({ socketConnected: true });
        get().applyAgentFailed(
          evt.payload as unknown as SocketAgentFailedPayload,
        );
        return;
      }
      // When event closes, stop investigating animation.
      if (evt.type === "state_change") {
        const toStatus = (evt.payload as { to_status?: string }).to_status;
        if (toStatus === "closed" || toStatus === "failed") {
          set({ isInvestigating: false });
        }
      }
    });

    // Immediate traces snapshot (history replay / socket-down bootstrap).
    void get().pollTraces(eventId);

    // ISSUE-075 降级：仅 Socket 不可用时每 10s 轮询 traces（勿在 connected-but-silent
    // 时 poll，否则长 _run 会把 live PROCESSING 抹成 IDLE——trace 仅在结束后写入）。
    const timer = setInterval(() => {
      const connected = socketClient.isConnected;
      set({ socketConnected: connected });
      if (!connected) {
        void get().pollTraces(eventId);
      }
    }, AGENT_SOCKET_SILENCE_MS);

    set({ socketUnsub: unsub, pollTimer: timer });
  },

  stopWatching() {
    const { socketUnsub, pollTimer, watchedEventId } = get();
    socketUnsub?.();
    if (pollTimer) {
      clearInterval(pollTimer);
    }
    if (watchedEventId) {
      socketClient.forgetEvent(watchedEventId);
    }
    get().reset();
    set({ socketUnsub: null, pollTimer: null, watchedEventId: null });
  },

  /* ---- socket event handlers ---- */

  applyAgentProgress(payload: SocketAgentProgressPayload) {
    const agentName = payload.agent_name as AgentName;
    if (!ALL_AGENT_NAMES.includes(agentName)) return;

    // Contract primary field is progress_pct; ISSUE-075 also allows progress_percent.
    const message = payload.message ?? payload.phase ?? "处理中…";
    const progress =
      payload.progress_percent ?? payload.progress_pct ?? null;

    set((state) => ({
      agents: {
        ...state.agents,
        [agentName]: {
          ...state.agents[agentName],
          status: "PROCESSING" as AgentStatus,
          message: message,
          progress_percent: progress,
          started_at:
            state.agents[agentName].started_at ?? new Date().toISOString(),
        },
      },
      feed: pushFeedEntry(state.feed, agentName, message),
      isInvestigating: true,
      lastAgentEventAt: Date.now(),
    }));
  },

  applyAgentCompleted(payload: SocketAgentCompletedPayload) {
    const agentName = payload.agent_name as AgentName;
    if (!ALL_AGENT_NAMES.includes(agentName)) return;

    const message = payload.output_summary ?? "执行完成";

    set((state) => {
      const prev = state.agents[agentName];
      return {
        agents: {
          ...state.agents,
          [agentName]: {
            ...prev,
            status: payload.degraded
              ? "DEGRADED"
              : ("COMPLETED" as AgentStatus),
            message: message,
            progress_percent: 100,
            completed_at: new Date().toISOString(),
            duration_ms: payload.duration_ms ?? null,
            error_detail: null,
          },
        },
        feed: pushFeedEntry(state.feed, agentName, message),
        lastAgentEventAt: Date.now(),
      };
    });
  },

  applyAgentFailed(payload: SocketAgentFailedPayload) {
    const agentName = payload.agent_name as AgentName;
    if (!ALL_AGENT_NAMES.includes(agentName)) return;

    // Contract primary field is `error`; accept error_detail as alias.
    const error = payload.error ?? payload.error_detail ?? "执行失败";

    set((state) => {
      const prev = state.agents[agentName];
      return {
        agents: {
          ...state.agents,
          [agentName]: {
            ...prev,
            status: "FAILED" as AgentStatus,
            message: error,
            progress_percent: null,
            completed_at: new Date().toISOString(),
            error_detail: error,
          },
        },
        feed: pushFeedEntry(state.feed, agentName, error),
        lastAgentEventAt: Date.now(),
      };
    });
  },

  /* ---- traces replay ---- */

  replayFromTraces(traces: AgentTrace[]) {
    if (!traces || traces.length === 0) return;

    // Never overwrite fresh live socket-driven status with a delayed HTTP snapshot.
    if (
      shouldProtectLiveSocketState(
        get().isInvestigating,
        socketClient.isConnected || get().socketConnected,
        get().lastAgentEventAt,
      )
    ) {
      return;
    }

    const previous = get().agents;
    const agents = defaultAgentMap();
    const feed: ActivityFeedEntry[] = [];

    // Sort traces by started_at for chronological replay.
    const sorted = [...traces].sort(
      (a, b) =>
        new Date(a.started_at).getTime() - new Date(b.started_at).getTime(),
    );

    for (const trace of sorted) {
      const name = trace.agent_name as AgentName;
      if (!ALL_AGENT_NAMES.includes(name)) continue;

      const info = agents[name];

      if (trace.status === "completed") {
        info.status = "COMPLETED";
        info.message = "执行完成";
        info.progress_percent = 100;
        info.started_at = trace.started_at;
        info.completed_at = trace.completed_at;
        info.duration_ms = trace.duration_ms;
        info.error_detail = null;
      } else if (trace.status === "failed") {
        info.status = "FAILED";
        info.message = trace.error_detail ?? "执行失败";
        info.progress_percent = null;
        info.started_at = trace.started_at;
        info.completed_at = trace.completed_at;
        info.duration_ms = trace.duration_ms;
        info.error_detail = trace.error_detail;
      } else if (trace.status === "processing") {
        info.status = "PROCESSING";
        info.message = "处理中（历史记录）";
        info.started_at = trace.started_at;
      }

      // Build a feed entry for each trace.
      const label = AGENT_LABELS[name] ?? name;
      const feedMsg =
        trace.status === "completed"
          ? `${label} 执行完成${trace.duration_ms != null ? `（${trace.duration_ms}ms）` : ""}`
          : trace.status === "failed"
            ? `${label} 执行失败：${trace.error_detail ?? "未知错误"}`
            : `${label} 处理中（历史记录）`;
      feed.push({
        id: ++feedIdCounter,
        timestamp: trace.completed_at ?? trace.started_at,
        agent_name: name,
        message: feedMsg,
      });
    }

    // Preserve live socket statuses not yet reflected in traces (trace is
    // recorded only after _run finishes — ISSUE-075). Keep PROCESSING and
    // terminal COMPLETED/FAILED/DEGRADED so disconnect/stale-prop replay
    // cannot wipe cards back to IDLE.
    let preservedLive = false;
    for (const name of ALL_AGENT_NAMES) {
      const prev = previous[name];
      if (agents[name].status !== "IDLE") continue;
      if (
        prev.status === "PROCESSING" ||
        prev.status === "COMPLETED" ||
        prev.status === "FAILED" ||
        prev.status === "DEGRADED"
      ) {
        agents[name] = { ...prev };
        preservedLive = true;
      }
    }

    const stillProcessing = ALL_AGENT_NAMES.some(
      (name) => agents[name].status === "PROCESSING",
    );

    // When preserving live cards, keep the live feed; traces-only feed would
    // drop socket messages for agents not yet in the HTTP snapshot.
    const nextFeed = preservedLive
      ? get().feed
      : feed.slice(-MAX_FEED_ENTRIES);

    set({
      agents,
      feed: nextFeed,
      isInvestigating: stillProcessing || (preservedLive && get().isInvestigating),
    });
  },

  async pollTraces(eventId: string) {
    // Skip while fresh live socket investigation owns the panel.
    if (
      shouldProtectLiveSocketState(
        get().isInvestigating,
        socketClient.isConnected || get().socketConnected,
        get().lastAgentEventAt,
      )
    ) {
      return;
    }
    try {
      const res = await getTraces(eventId);
      const traces = res.data.items;
      if (traces && traces.length > 0) {
        get().replayFromTraces(traces);
      }
    } catch {
      // best-effort poll, silent failure
    }
  },

  reset() {
    set({
      agents: defaultAgentMap(),
      feed: [],
      isInvestigating: false,
      socketConnected: false,
      lastAgentEventAt: 0,
    });
  },
}));
