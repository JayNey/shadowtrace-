/** Approval store — pending approvals with socket-driven updates (ISSUE-073). */

import { create } from "zustand";
import { notification } from "antd";
import type { Action } from "../types/action";
import {
  listActions,
  listEvents,
  approveAction,
  rejectAction,
} from "../services/eventApi";
import { socketClient } from "../services/socketClient";
import type { SocketEvent } from "../types/socket";

export interface ApprovalDecisionBody {
  comment?: string;
  decision_id: string;
}

interface ApprovalState {
  pendingApprovals: Action[];
  loading: boolean;
  error: string | null;
  unreadCount: number;
  /** action_id -> ISO deadline from approval_required socket payload. */
  approvalDeadlines: Record<string, string>;

  _pollTimer: ReturnType<typeof setInterval> | null;
  _globalSocketUnsub: (() => void) | null;
  _eventIds: string[];

  refreshEventIds: () => Promise<string[]>;
  loadPendingApprovals: (eventIds?: string[]) => Promise<void>;
  approve: (actionId: string, body: ApprovalDecisionBody) => Promise<void>;
  reject: (actionId: string, body: ApprovalDecisionBody) => Promise<void>;
  initGlobalListener: () => void;
  startPolling: (eventIds?: string[]) => void;
  stopPolling: () => void;
  clearUnread: () => void;
  _applySocketEvent: (event: SocketEvent) => void;
}

const APPROVAL_STATUSES = new Set(["waiting_approval", "approved", "rejected"]);

async function fetchWaitingApprovals(eventIds: string[]): Promise<Action[]> {
  if (eventIds.length === 0) return [];
  const results = await Promise.allSettled(
    eventIds.map((id) =>
      listActions(id, { page_size: 200, status: "waiting_approval" }).then(
        (r) => r.data.items,
      ),
    ),
  );
  const all: Action[] = [];
  for (const r of results) {
    if (r.status === "fulfilled") all.push(...r.value);
  }
  all.sort((a, b) => (a.updated_at ?? "").localeCompare(b.updated_at ?? ""));
  return all;
}

export const useApprovalStore = create<ApprovalState>((set, get) => ({
  pendingApprovals: [],
  loading: false,
  error: null,
  unreadCount: 0,
  approvalDeadlines: {},
  _pollTimer: null,
  _globalSocketUnsub: null,
  _eventIds: [],

  async refreshEventIds() {
    try {
      const res = await listEvents({ page_size: 200 });
      const ids = res.data.items.map((e) => e.event_id);
      set({ _eventIds: ids });
      return ids;
    } catch {
      return get()._eventIds;
    }
  },

  async loadPendingApprovals(eventIds) {
    const ids = eventIds ?? get()._eventIds;
    if (ids.length === 0) {
      set({ pendingApprovals: [], loading: false });
      return;
    }
    set({ loading: true, error: null, _eventIds: ids });
    try {
      const all = await fetchWaitingApprovals(ids);
      set({ pendingApprovals: all, loading: false });
    } catch (err: unknown) {
      set({ error: String(err), loading: false });
    }
  },

  async approve(actionId, body) {
    await approveAction(actionId, body);
    set((s) => ({
      pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== actionId),
    }));
  },

  async reject(actionId, body) {
    await rejectAction(actionId, body);
    set((s) => ({
      pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== actionId),
    }));
  },

  initGlobalListener() {
    socketClient.connect();

    if (!get()._globalSocketUnsub) {
      const unsub = socketClient.onEvent((event) => {
        if (event.type === "approval_required" || event.type === "approval_updated") {
          get()._applySocketEvent(event);
        }
      });
      set({ _globalSocketUnsub: unsub });
    }

    void get()
      .refreshEventIds()
      .then((ids) => {
        void get().loadPendingApprovals(ids);
        get().startPolling(ids);
      });
  },

  startPolling(eventIds) {
    const { _pollTimer } = get();
    if (_pollTimer) clearInterval(_pollTimer);
    if (eventIds && eventIds.length > 0) {
      set({ _eventIds: eventIds });
    }

    const timer = setInterval(() => {
      const ids = get()._eventIds;
      if (ids.length > 0) void get().loadPendingApprovals(ids);
    }, 10_000);
    set({ _pollTimer: timer });
  },

  stopPolling() {
    const { _pollTimer } = get();
    if (_pollTimer) clearInterval(_pollTimer);
    set({ _pollTimer: null });
  },

  _applySocketEvent(event) {
    if (event.type !== "approval_required" && event.type !== "approval_updated") return;
    const action_id = event.payload?.action_id ?? "";
    if (!action_id) return;

    if (event.type === "approval_updated") {
      set((s) => ({
        pendingApprovals: s.pendingApprovals.filter((a) => a.action_id !== action_id),
        approvalDeadlines: Object.fromEntries(
          Object.entries(s.approvalDeadlines).filter(([id]) => id !== action_id),
        ),
      }));
      return;
    }

    const deadline = event.payload.deadline;
    if (deadline) {
      set((s) => ({
        approvalDeadlines: { ...s.approvalDeadlines, [action_id]: deadline },
      }));
    }

    set((s) => ({ unreadCount: s.unreadCount + 1 }));
    const summary = event.payload.summary;
    notification.info({
      message: "新的审批请求",
      description: summary ? `${action_id}: ${summary}` : `动作 ${action_id} 需要审批`,
      placement: "topRight",
    });

    void get()
      .refreshEventIds()
      .then((ids) => get().loadPendingApprovals(ids));
  },

  clearUnread() {
    set({ unreadCount: 0 });
  },
}));

/** Revision progress for one event plan revision. */
export interface RevisionProgress {
  eventId: string;
  planRevision: number;
  decided: number;
  total: number;
}

export function revisionProgressKey(eventId: string, planRevision: number): string {
  return `${eventId}:${planRevision}`;
}

/** Compute decided/total approval counts per event revision. */
export async function loadRevisionProgress(
  pending: Action[],
): Promise<Map<string, RevisionProgress>> {
  const result = new Map<string, RevisionProgress>();
  const eventIds = [...new Set(pending.map((a) => a.event_id))];

  await Promise.all(
    eventIds.map(async (eventId) => {
      const { data } = await listActions(eventId, { page_size: 200 });
      const revisions = new Set(
        pending
          .filter((a) => a.event_id === eventId)
          .map((a) => a.plan_revision ?? 0),
      );
      for (const planRevision of revisions) {
        const inRev = data.items.filter((a) => (a.plan_revision ?? 0) === planRevision);
        const approvalSet = inRev.filter((a) => APPROVAL_STATUSES.has(a.status));
        const total = approvalSet.length;
        const decided = approvalSet.filter((a) => a.status !== "waiting_approval").length;
        result.set(revisionProgressKey(eventId, planRevision), {
          eventId,
          planRevision,
          decided,
          total,
        });
      }
    }),
  );

  return result;
}

/** Dev/mock approver label shown in the approval modal (read-only). */
export function currentApproverDisplay(): string {
  // Mock stage: prefer explicit env; future: read from auth context / token subject.
  return (
    import.meta.env.VITE_AUTH_SUBJECT ??
    import.meta.env.VITE_APPROVER_DISPLAY ??
    "审批员 (dev)"
  );
}

export function newDecisionId(): string {
  return crypto.randomUUID();
}

/** Fallback timeout when socket deadline is unavailable (30 minutes). */
export const APPROVAL_TIMEOUT_FALLBACK_MS = 30 * 60 * 1000;

export function isActionTimedOut(
  action: Action,
  deadline: string | undefined,
): boolean {
  if (deadline) {
    return Date.now() > new Date(deadline).getTime();
  }
  if (!action.updated_at) return false;
  return Date.now() - new Date(action.updated_at).getTime() > APPROVAL_TIMEOUT_FALLBACK_MS;
}

export function formatDispositionPreview(
  ref: Record<string, unknown> | null | undefined,
): string {
  if (!ref || Object.keys(ref).length === 0) return "—";
  const parts: string[] = [];
  for (const key of [
    "source_record_id",
    "object_type",
    "object_id",
    "field",
    "value",
  ]) {
    const val = ref[key];
    if (val !== undefined && val !== null && val !== "") {
      parts.push(`${key}=${String(val)}`);
    }
  }
  if (parts.length > 0) return parts.join("; ");
  const raw = JSON.stringify(ref);
  return raw.length > 160 ? `${raw.slice(0, 160)}…` : raw;
}
