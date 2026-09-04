import { useCallback, useEffect, useRef, useState } from "react";
import type { Action } from "../types/action";
import type {
  ConnectorPublic,
  DispositionResponse,
  EventDetailResponse,
  EventEvidenceResponse,
  ExecutionJobResponse,
  SourceRecordResponse,
  WritebackResponse,
} from "../types/event";
import type { AgentTrace } from "../types/trace";
import type { InvestigationReport } from "../types/report";
import { coerceInvestigationReport } from "../types/report";
import {
  getEvent,
  getEventEvidence,
  getExecutionJob,
  getReport,
  getSourceRecord,
  getTraces,
  getWriteback,
  listActions,
  listConnectors,
  listDispositions,
} from "../services/eventApi";
import { shouldFetchEventEvidence } from "../utils/evidenceContext";
import { socketClient } from "../services/socketClient";

type DetailResource =
  | "all"
  | "event"
  | "traces"
  | "actions"
  | "executionJobs"
  | "dispositions"
  | "writebacks";

/** Per-resource fetch success flags (ISSUE-206/207): callers like the report tab
 *  and inline approval flow must distinguish a refresh failure from success. */
export interface DetailRefreshResult {
  actionsOk: boolean;
  eventOk: boolean;
}

export interface EventWriteback extends WritebackResponse {
  provider_job_id?: string | null;
  provider_message?: string | null;
  submitted_at?: string | null;
  confirmed_at?: string | null;
  sequence?: number;
}

function contextJobs(detail: EventDetailResponse | null): ExecutionJobResponse[] {
  const context = detail?.event.event_context_snapshot;
  return context?.execution_jobs ?? context?.execution_summary?.jobs ?? [];
}

function contextWritebacks(detail: EventDetailResponse | null): EventWriteback[] {
  return (detail?.event.event_context_snapshot?.disposition_receipts ?? []).map(
    (receipt) => ({
      writeback_id: receipt.writeback_id,
      disposition_id: receipt.disposition_id,
      action_id: receipt.action_id,
      status: receipt.status,
      confirmation_evidence: receipt.confirmation_evidence,
      evidence_tier: null,
      provider_code: receipt.provider_code ?? null,
      message_code: null,
      target_results: receipt.target_results ?? [],
      provider_job_id: receipt.provider_job_id,
      provider_message: receipt.provider_message,
      submitted_at: receipt.submitted_at,
      confirmed_at: receipt.confirmed_at,
      simulated: receipt.simulated,
      sequence: receipt.sequence,
    }),
  );
}

export function mergeWritebacks(
  contextItems: EventWriteback[],
  apiItems: WritebackResponse[],
): EventWriteback[] {
  const merged = new Map<string, EventWriteback>();
  for (const item of contextItems) {
    const existing = merged.get(item.writeback_id);
    if (!existing || (item.sequence ?? 0) >= (existing.sequence ?? 0)) {
      merged.set(item.writeback_id, item);
    }
  }
  for (const item of apiItems) {
    const existing = merged.get(item.writeback_id);
    // API is source of truth: explicit false overwrites snapshot true.
    // ?? only applies when an older payload omits the field.
    merged.set(item.writeback_id, {
      ...existing,
      ...item,
      simulated: item.simulated ?? existing?.simulated ?? false,
    });
  }
  return [...merged.values()];
}

export function useEventDetail(eventId: string | undefined) {
  const [event, setEvent] = useState<EventDetailResponse | null>(null);
  const [traces, setTraces] = useState<AgentTrace[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [executionJobs, setExecutionJobs] = useState<ExecutionJobResponse[]>([]);
  const [dispositions, setDispositions] = useState<DispositionResponse[]>([]);
  const [writebacks, setWritebacks] = useState<EventWriteback[]>([]);
  const [sourceRecord, setSourceRecord] = useState<SourceRecordResponse | null>(null);
  const [connectors, setConnectors] = useState<ConnectorPublic[]>([]);
  const [evidenceDetail, setEvidenceDetail] = useState<EventEvidenceResponse | null>(null);
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [loading, setLoading] = useState(true);
  const mountedRef = useRef(true);
  const eventIdentityRef = useRef<string | undefined>(eventId);
  const resourceGenerationRef = useRef<Record<string, number>>({});
  const fullLoadTokenRef = useRef(0);
  const socketRefreshTimerRef = useRef<number | undefined>(undefined);
  const eventRef = useRef<EventDetailResponse | null>(null);
  const actionsRef = useRef<Action[]>([]);

  eventRef.current = event;
  actionsRef.current = actions;

  const refresh = useCallback(
    async (resource: DetailResource = "all"): Promise<DetailRefreshResult> => {
      if (!eventId) {
        if (mountedRef.current) setLoading(false);
        return { actionsOk: false, eventOk: false };
      }
      const isAll = resource === "all";
      const resources = isAll
        ? ["event", "traces", "actions", "executionJobs", "dispositions", "writebacks", "connectors"]
        : resource === "writebacks"
          ? ["event", "dispositions", "writebacks"]
          : resource === "actions" || resource === "executionJobs"
            ? ["actions", "executionJobs"]
            : resource === "dispositions"
              ? ["dispositions", "writebacks"]
              : [resource];
      const generations = new Map<string, number>();
      for (const item of resources) {
        const next = (resourceGenerationRef.current[item] ?? 0) + 1;
        resourceGenerationRef.current[item] = next;
        generations.set(item, next);
      }
      const fullLoadToken = isAll ? ++fullLoadTokenRef.current : 0;
      if (isAll && mountedRef.current) setLoading(true);
      const isResourceCurrent = (item: string) =>
        mountedRef.current &&
        eventIdentityRef.current === eventId &&
        resourceGenerationRef.current[item] === generations.get(item);

      try {
      const eventPromise =
        isAll || resource === "event" || resource === "writebacks"
          ? getEvent(eventId)
          : null;
      const tracesPromise = isAll || resource === "traces" ? getTraces(eventId) : null;
      const actionsPromise =
        isAll || resource === "actions" || resource === "executionJobs"
          ? listActions(eventId, { page: 1, page_size: 100 })
          : null;
      const dispositionsPromise =
        isAll || resource === "dispositions" || resource === "writebacks"
          ? listDispositions(eventId)
          : null;
      const connectorsPromise = isAll ? listConnectors() : null;

      const [eventResult, tracesResult, actionsResult, dispositionsResult, connectorsResult] =
        await Promise.allSettled([
          eventPromise,
          tracesPromise,
          actionsPromise,
          dispositionsPromise,
          connectorsPromise,
        ]);
      let actionsOk = false;
      let eventOk = false;
      let nextEvent = eventRef.current;
      if (
        eventResult.status === "fulfilled" &&
        eventResult.value &&
        isResourceCurrent("event")
      ) {
        nextEvent = eventResult.value.data;
        eventRef.current = nextEvent;
        setEvent(nextEvent);
        eventOk = true;
      }
      if (
        tracesResult.status === "fulfilled" &&
        tracesResult.value &&
        isResourceCurrent("traces")
      ) {
        setTraces(tracesResult.value.data.items);
      }

      let nextActions = actionsRef.current;
      if (
        actionsResult.status === "fulfilled" &&
        actionsResult.value &&
        isResourceCurrent("actions")
      ) {
        nextActions = actionsResult.value.data.items;
        actionsRef.current = nextActions;
        setActions(nextActions);
        actionsOk = true;
      }
      if (
        dispositionsResult.status === "fulfilled" &&
        dispositionsResult.value &&
        isResourceCurrent("dispositions")
      ) {
        setDispositions(dispositionsResult.value.data.items);
      }
      if (
        connectorsResult.status === "fulfilled" &&
        connectorsResult.value &&
        isResourceCurrent("connectors")
      ) {
        setConnectors(connectorsResult.value.data.items);
      }

      if ((isAll || resource === "event") && shouldFetchEventEvidence(nextEvent)) {
        try {
          const evidenceResult = await getEventEvidence(eventId);
          if (isResourceCurrent("event")) {
            setEvidenceDetail(evidenceResult.data);
          }
        } catch {
          if (isResourceCurrent("event")) {
            setEvidenceDetail(null);
          }
        }
      } else if (isAll || resource === "event") {
        if (isResourceCurrent("event")) setEvidenceDetail(null);
      }

      if (isAll || resource === "event") {
        try {
          const reportResult = await getReport(eventId);
          if (isResourceCurrent("event")) {
            setReport(
              coerceInvestigationReport(reportResult.data.report) ??
                coerceInvestigationReport(reportResult.data),
            );
          }
        } catch {
          if (isResourceCurrent("event")) {
            setReport(null);
          }
        }
      }

      if (isAll && nextEvent?.event.current_primary_source_record_id) {
        void getSourceRecord(nextEvent.event.current_primary_source_record_id)
          .then((response) => {
            if (isResourceCurrent("event")) setSourceRecord(response.data);
          })
          .catch(() => undefined);
      }

      if (isAll || resource === "executionJobs" || resource === "actions") {
        const snapshotJobs = contextJobs(nextEvent);
        const jobIds = new Set(
          nextActions
            .map((action) => action.execution_job_id)
            .filter((id): id is string => Boolean(id)),
        );
        const fetched = await Promise.allSettled(
          [...jobIds].map((jobId) => getExecutionJob(jobId)),
        );
        if (isResourceCurrent("executionJobs")) {
          const apiJobs = fetched.flatMap((result) =>
            result.status === "fulfilled" ? [result.value.data] : [],
          );
          const byId = new Map(snapshotJobs.map((job) => [job.job_id, job]));
          for (const job of apiJobs) byId.set(job.job_id, { ...byId.get(job.job_id), ...job });
          setExecutionJobs([...byId.values()]);
        }
      }

      if (isAll || resource === "writebacks" || resource === "dispositions") {
        const snapshotWritebacks = contextWritebacks(nextEvent);
        const terminalId =
          nextEvent?.event.event_context_snapshot?.writeback_summary
            ?.terminal_event_writeback_id;
        const writebackIds = new Set(snapshotWritebacks.map((item) => item.writeback_id));
        if (terminalId) writebackIds.add(terminalId);
        const fetched = await Promise.allSettled(
          [...writebackIds].map((writebackId) => getWriteback(writebackId)),
        );
        if (isResourceCurrent("writebacks")) {
          const apiWritebacks = fetched.flatMap((result) =>
            result.status === "fulfilled" ? [result.value.data] : [],
          );
          setWritebacks(mergeWritebacks(snapshotWritebacks, apiWritebacks));
        }
      }

      return { actionsOk, eventOk };
      } finally {
        if (isAll && mountedRef.current && fullLoadToken === fullLoadTokenRef.current) {
          setLoading(false);
        }
      }
    },
    [eventId],
  );

  useEffect(() => {
    eventIdentityRef.current = eventId;
    mountedRef.current = true;
    eventRef.current = null;
    actionsRef.current = [];
    setEvent(null);
    setTraces([]);
    setActions([]);
    setExecutionJobs([]);
    setDispositions([]);
    setWritebacks([]);
    setSourceRecord(null);
    setConnectors([]);
    setEvidenceDetail(null);
    setReport(null);
    void refresh("all");
    return () => {
      mountedRef.current = false;
      eventIdentityRef.current = undefined;
      for (const key of Object.keys(resourceGenerationRef.current)) {
        resourceGenerationRef.current[key] += 1;
      }
    };
  }, [refresh]);

  useEffect(() => {
    if (!eventId) return;
    socketClient.connect();
    socketClient.subscribe(eventId);
    const queuedResources = new Set<DetailResource>();
    const queueRefresh = (resource: DetailResource) => {
      queuedResources.add(resource);
      if (socketRefreshTimerRef.current != null) return;
      socketRefreshTimerRef.current = window.setTimeout(() => {
        socketRefreshTimerRef.current = undefined;
        if (queuedResources.has("all")) {
          queuedResources.clear();
          void refresh("all");
          return;
        }
        if (queuedResources.has("writebacks")) {
          queuedResources.delete("event");
          queuedResources.delete("dispositions");
        }
        if (queuedResources.has("actions")) {
          queuedResources.delete("executionJobs");
        }
        const pending = [...queuedResources];
        queuedResources.clear();
        void Promise.all(pending.map((item) => refresh(item)));
      }, 50);
    };
    const unsubscribe = socketClient.onEvent((socketEvent) => {
      if (socketEvent.event_id !== eventId) return;
      if (
        socketEvent.type === "risk_updated" ||
        socketEvent.type === "state_change" ||
        socketEvent.type === "final_verdict_updated" ||
        socketEvent.type === "event_type_rewritten" ||
        socketEvent.type === "report_generated" ||
        socketEvent.type === "classification_updated"
      ) {
        queueRefresh("event");
      } else if (
        socketEvent.type === "action_executed" ||
        socketEvent.type === "action_verified" ||
        socketEvent.type === "approval_required" ||
        socketEvent.type === "approval_updated"
      ) {
        queueRefresh("actions");
        if (
          socketEvent.type === "approval_required" ||
          socketEvent.type === "approval_updated"
        ) {
          queueRefresh("event");
        }
      } else if (socketEvent.type === "disposition_submitted") {
        queueRefresh("dispositions");
      } else if (socketEvent.type === "writeback_updated") {
        queueRefresh("writebacks");
      }
    });
    return () => {
      unsubscribe();
      socketClient.forgetEvent(eventId);
      if (socketRefreshTimerRef.current != null) {
        window.clearTimeout(socketRefreshTimerRef.current);
        socketRefreshTimerRef.current = undefined;
      }
      queuedResources.clear();
    };
  }, [eventId, refresh]);

  return {
    event,
    traces,
    actions,
    executionJobs,
    dispositions,
    writebacks,
    sourceRecord,
    connectors,
    evidenceDetail,
    report,
    loading,
    refresh,
  };
}
