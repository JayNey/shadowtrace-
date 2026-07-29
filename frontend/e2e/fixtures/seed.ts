/**
 * ISSUE-077 global setup: ingest ISSUE-011 demo data via REST API, trigger
 * investigation, and wait until report / timeline / graph / L4 approval are ready.
 *
 * Writes `frontend/e2e/.seed.json` for specs to consume.
 *
 * Telemetry is NOT ingested as SecurityEvents — MockXDR (Compose) already loads
 * `insider_data_exfiltration` for evidence projection. Only incident + linked
 * alerts are posted so the board stays clean.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../../..");
const SEED_STATE_PATH = path.join(__dirname, "..", ".seed.json");

const BACKEND_BASE_URL =
  process.env.E2E_BACKEND_URL ?? "http://127.0.0.1:8000/api/v1";
const AUTH_TOKEN = process.env.E2E_AUTH_TOKEN ?? "e2e-token";

export interface SeedState {
  analysisEventId: string;
  approvalEventId: string;
  approvalActionId: string;
  seededAt: string;
}

type Json = Record<string, unknown>;

async function api<T = Json>(
  method: string,
  route: string,
  body?: unknown,
): Promise<{ status: number; data: T }> {
  const res = await fetch(`${BACKEND_BASE_URL}${route}`, {
    method,
    headers: {
      Authorization: `Bearer ${AUTH_TOKEN}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data: T;
  try {
    data = text ? (JSON.parse(text) as T) : ({} as T);
  } catch {
    throw new Error(
      `${method} ${route} → ${res.status}: non-JSON body: ${text.slice(0, 200)}`,
    );
  }
  return { status: res.status, data };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor<T>(
  label: string,
  fn: () => Promise<T | null | undefined>,
  options: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? 180_000;
  const intervalMs = options.intervalMs ?? 2_000;
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await sleep(intervalMs);
  }
  throw new Error(
    `timeout waiting for ${label}` +
      (lastError
        ? `: ${lastError instanceof Error ? lastError.message : String(lastError)}`
        : ""),
  );
}

async function ingestSourceRecord(payload: {
  reference: Json;
  raw_payload?: Json;
  normalized?: Json;
  incident_ref?: Json;
  related_alert_refs?: Json[];
}): Promise<{ source_record_id: string; event_id: string | null }> {
  const { status, data } = await api<{
    source_record_id: string;
    event_id: string | null;
    accepted: boolean;
  }>("POST", "/ingestion/source-records", payload);
  if (status !== 202 && status !== 200) {
    throw new Error(
      `ingest failed (${status}): ${JSON.stringify(data).slice(0, 400)}`,
    );
  }
  return {
    source_record_id: data.source_record_id,
    event_id: data.event_id ?? null,
  };
}

async function ingestScenarioPack(): Promise<string> {
  const scenarioPath = path.join(
    REPO_ROOT,
    "data",
    "mock",
    "insider_data_exfiltration.scenario.json",
  );
  const scenario = JSON.parse(fs.readFileSync(scenarioPath, "utf-8")) as {
    incidents?: Array<{
      reference: Json;
      raw_payload?: Json;
      normalized?: Json;
      title?: string;
      level?: string;
    }>;
    alerts?: Array<{
      reference: Json;
      raw_payload?: Json;
      normalized?: Json;
      incident_ref?: Json;
    }>;
  };

  let eventId: string | null = null;
  let incidentRef: Json | null = null;

  for (const incident of scenario.incidents ?? []) {
    const normalized = {
      ...(incident.normalized ?? {}),
      title: incident.title,
      severity: incident.level,
      event_type: "data_exfiltration",
      scenario: "insider_data_exfiltration",
    };
    const result = await ingestSourceRecord({
      reference: incident.reference,
      raw_payload: incident.raw_payload ?? {},
      normalized,
    });
    if (result.event_id) eventId = result.event_id;
    incidentRef = incident.reference;
  }

  // Alerts with verified incident_ref merge into the incident event (no new
  // SecurityEvent). Assets / logs / raw telemetry files are NOT ingested here —
  // they would spawn orphan events; MockXDR supplies evidence for investigation.
  for (const alert of scenario.alerts ?? []) {
    const link = alert.incident_ref ?? incidentRef;
    if (!link) {
      throw new Error("scenario alert missing incident_ref and no incident ingested");
    }
    await ingestSourceRecord({
      reference: alert.reference,
      raw_payload: alert.raw_payload ?? {},
      normalized: alert.normalized ?? {},
      incident_ref: link,
    });
  }

  if (!eventId) {
    throw new Error("scenario ingest produced no event_id");
  }
  return eventId;
}

async function createApprovalEvent(): Promise<string> {
  const stamp = Date.now();
  const scenarioPath = path.join(
    REPO_ROOT,
    "data",
    "mock",
    "insider_data_exfiltration.scenario.json",
  );
  const scenario = JSON.parse(fs.readFileSync(scenarioPath, "utf-8")) as {
    incidents?: Array<{
      reference: Json;
      raw_payload?: Json;
      normalized?: Json;
      title?: string;
      level?: string;
    }>;
  };
  const incident = scenario.incidents?.[0];
  if (!incident) {
    throw new Error("scenario missing incident for approval seed");
  }
  const reference = {
    ...incident.reference,
    source_object_id: `e2e-approval-${stamp}`,
    connector_id: "conn-disposition",
  };
  const result = await ingestSourceRecord({
    reference,
    raw_payload: incident.raw_payload ?? {},
    normalized: {
      ...(incident.normalized ?? {}),
      title: `E2E L4 approval ${incident.title ?? "incident"} ${stamp}`,
      severity: incident.level ?? "critical",
      event_type: "data_exfiltration",
      scenario: "insider_data_exfiltration",
    },
  });
  if (!result.event_id) {
    throw new Error("approval ingest produced no event_id");
  }
  return result.event_id;
}

async function triggerInvestigate(
  eventId: string,
  options: { includeResponseExecution?: boolean } = {},
): Promise<void> {
  const includeResponseExecution = options.includeResponseExecution ?? false;
  const { status, data } = await api("POST", `/events/${eventId}/investigate`, {
    force_replan: false,
    include_response_execution: includeResponseExecution,
  });
  if (status !== 202 && status !== 200) {
    const code =
      data && typeof data === "object" && "error_code" in data
        ? String((data as Json).error_code)
        : "";
    if (
      code !== "investigation_in_progress" &&
      code !== "invalid_state_transition"
    ) {
      throw new Error(
        `investigate ${eventId} failed (${status}): ${JSON.stringify(data).slice(0, 400)}`,
      );
    }
  }
}

async function waitAnalysisReady(eventId: string): Promise<void> {
  const requiredPhases = new Set([
    "initial_access",
    "collection",
    "staging",
    "exfiltration",
    "post_action",
  ]);

  await waitFor(`analysis artifacts for ${eventId}`, async () => {
    const detail = await api<{
      event: {
        status: string;
        event_context_snapshot?: {
          evidence_output?: {
            evidence_list?: Array<{ is_conflicting?: boolean }>;
            conflicts?: unknown[];
          };
        };
      };
    }>("GET", `/events/${eventId}`);
    const status = detail.data.event?.status;
    if (!status || status === "new" || status === "triaging") {
      return null;
    }
    if (status === "failed") throw new Error(`event ${eventId} failed`);

    const evidenceOutput =
      detail.data.event?.event_context_snapshot?.evidence_output;
    const evidenceList = evidenceOutput?.evidence_list ?? [];
    if (evidenceList.length === 0) return null;
    const hasConflict =
      (evidenceOutput?.conflicts?.length ?? 0) > 0 ||
      evidenceList.some((item) => item.is_conflicting);
    if (!hasConflict) return null;

    const report = await api("GET", `/events/${eventId}/report`);
    if (report.status !== 200) return null;

    const timeline = await api<{
      phases?: Array<{ phase_name?: string; entries?: unknown[] }>;
    }>("GET", `/events/${eventId}/timeline`);
    if (timeline.status !== 200) return null;
    const phases = timeline.data.phases ?? [];
    const phaseNames = new Set(
      phases.map((phase) => String(phase.phase_name ?? "")),
    );
    for (const required of requiredPhases) {
      if (!phaseNames.has(required)) return null;
    }
    const hasExpandableEntry = phases.some(
      (phase) => Array.isArray(phase.entries) && phase.entries.length > 0,
    );
    if (!hasExpandableEntry) return null;

    const graph = await api<{
      nodes?: unknown[];
      attack_path_candidates?: unknown[][];
    }>("GET", `/events/${eventId}/graph`);
    if (graph.status !== 200) return null;
    if (!Array.isArray(graph.data.nodes) || graph.data.nodes.length === 0) {
      return null;
    }
    const paths = graph.data.attack_path_candidates ?? [];
    if (!paths.some((path) => Array.isArray(path) && path.length > 0)) {
      return null;
    }

    return { ok: true };
  });
}

async function waitApprovalReady(eventId: string): Promise<string> {
  return waitFor(`L4 waiting_approval for ${eventId}`, async () => {
    const detail = await api<{ event: { status: string } }>(
      "GET",
      `/events/${eventId}`,
    );
    if (detail.data.event?.status === "failed") {
      throw new Error(`approval event ${eventId} failed`);
    }
    const actions = await api<{
      items: Array<{ action_id: string; action_level: string; status: string }>;
    }>("GET", `/events/${eventId}/actions?status=waiting_approval&page_size=50`);
    if (actions.status !== 200) return null;
    const l4 = (actions.data.items ?? []).find(
      (item) =>
        item.status === "waiting_approval" &&
        String(item.action_level).toLowerCase() === "l4",
    );
    return l4?.action_id ?? null;
  });
}

export default async function globalSetup(): Promise<void> {
  const health = await api("GET", "/health");
  if (health.status !== 200) {
    throw new Error(
      `backend health check failed (${health.status}). Run: docker compose up -d`,
    );
  }

  console.log("[e2e seed] ingesting insider_data_exfiltration via API…");
  const analysisEventId = await ingestScenarioPack();
  console.log(
    `[e2e seed] analysis event=${analysisEventId}; triggering investigate…`,
  );
  await triggerInvestigate(analysisEventId, { includeResponseExecution: false });
  await waitAnalysisReady(analysisEventId);
  console.log("[e2e seed] analysis artifacts ready");

  console.log("[e2e seed] creating L4 approval event…");
  const approvalEventId = await createApprovalEvent();
  await triggerInvestigate(approvalEventId, { includeResponseExecution: true });
  const approvalActionId = await waitApprovalReady(approvalEventId);
  console.log(
    `[e2e seed] approval event=${approvalEventId} action=${approvalActionId}`,
  );

  const state: SeedState = {
    analysisEventId,
    approvalEventId,
    approvalActionId,
    seededAt: new Date().toISOString(),
  };
  fs.writeFileSync(SEED_STATE_PATH, `${JSON.stringify(state, null, 2)}\n`, "utf-8");
  process.env.E2E_ANALYSIS_EVENT_ID = analysisEventId;
  process.env.E2E_APPROVAL_EVENT_ID = approvalEventId;
  process.env.E2E_APPROVAL_ACTION_ID = approvalActionId;
}

export function readSeedState(): SeedState {
  if (!fs.existsSync(SEED_STATE_PATH)) {
    throw new Error(
      `missing seed state at ${SEED_STATE_PATH}; run global setup first`,
    );
  }
  const state = JSON.parse(fs.readFileSync(SEED_STATE_PATH, "utf-8")) as SeedState;
  if (!state.analysisEventId || !state.approvalEventId || !state.approvalActionId) {
    throw new Error(
      `incomplete seed state at ${SEED_STATE_PATH}: ${JSON.stringify(state)}`,
    );
  }
  return state;
}
