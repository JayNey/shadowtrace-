/**
 * ISSUE-077 global setup: ingest ISSUE-011 demo data via REST API, trigger
 * investigation, and wait until report / timeline / graph / L4 approval are ready.
 *
 * Writes `frontend/e2e/.seed.json` for specs to consume.
 *
 * Ingests incident + linked alerts/assets/logs (via incident_ref) so
 * EvidenceProjection can query telemetry without orphan SecurityEvents.
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

type ScenarioRecord = Record<string, unknown>;

const TELEMETRY_DEVICE_SOURCE: Record<string, string> = {
  identity: "iam",
  endpoint: "edr",
  dlp: "dlp",
  dns: "dns",
  network: "nfw",
  threat_intel: "threat_intel",
  asset: "asset",
};

function buildTelemetryReference(record: ScenarioRecord): Json {
  const recordId = String(record.record_id ?? "");
  const channel = String(record.channel ?? "log");
  const isAsset = channel === "asset";
  return {
    source_kind: isAsset ? "asset" : "log",
    source_product: "mock_xdr",
    source_tenant_id: "tenant-demo",
    connector_id: "conn-disposition",
    source_object_type: channel,
    source_object_id: recordId,
    parent_source_object_id: null,
    source_status_raw: "indexed",
    source_disposition: "pending",
    source_concurrency_token: null,
    source_updated_at: String(record.logged_at ?? new Date().toISOString()),
    schema_version: "1",
    ingested_at: null,
    raw_payload_hash: null,
  };
}

function buildTelemetryNormalized(record: ScenarioRecord): Json {
  const channel = String(record.channel ?? "log");
  const { event_type: _drop, ...rest } = record;
  return {
    ...rest,
    channel,
    device_source: TELEMETRY_DEVICE_SOURCE[channel] ?? channel,
  };
}

async function ingestTelemetryTimeline(
  incidentRef: Json,
  records: ScenarioRecord[],
): Promise<void> {
  for (const record of records) {
    if (!record.record_id) {
      throw new Error("telemetry_timeline entry missing record_id");
    }
    await ingestSourceRecord({
      reference: buildTelemetryReference(record),
      raw_payload: record,
      normalized: buildTelemetryNormalized(record),
      incident_ref: incidentRef,
    });
  }
}

type ScenarioPack = {
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
  assets?: Array<{
    reference: Json;
    raw_payload?: Json;
    normalized?: Json;
  }>;
  logs?: Array<{
    reference: Json;
    raw_payload?: Json;
    normalized?: Json;
  }>;
  telemetry_timeline?: ScenarioRecord[];
};

function loadScenarioPack(): ScenarioPack {
  const scenarioPath = path.join(
    REPO_ROOT,
    "data",
    "mock",
    "insider_data_exfiltration.scenario.json",
  );
  return JSON.parse(fs.readFileSync(scenarioPath, "utf-8")) as ScenarioPack;
}

function suffixReference(reference: Json, stamp: string): Json {
  const sourceObjectId = String(reference.source_object_id ?? "object");
  return {
    ...reference,
    source_object_id: `${sourceObjectId}-e2e-${stamp}`,
  };
}

function suffixTelemetryRecord(record: ScenarioRecord, stamp: string): ScenarioRecord {
  return {
    ...record,
    record_id: `${String(record.record_id ?? "rec")}-e2e-${stamp}`,
  };
}

async function ingestScenarioPackVariant(options: {
  stamp?: string;
  incidentTitle?: string;
} = {}): Promise<string> {
  const stamp = options.stamp ?? "analysis";
  const scenario = loadScenarioPack();

  let eventId: string | null = null;
  let incidentRef: Json | null = null;

  for (const incident of scenario.incidents ?? []) {
    const reference = suffixReference(incident.reference, stamp);
    const normalized = {
      ...(incident.normalized ?? {}),
      title: options.incidentTitle ?? incident.title,
      severity: incident.level,
      event_type: "data_exfiltration",
      scenario: "insider_data_exfiltration",
    };
    const result = await ingestSourceRecord({
      reference,
      raw_payload: incident.raw_payload ?? {},
      normalized,
    });
    if (result.event_id) eventId = result.event_id;
    incidentRef = reference;
  }

  for (const alert of scenario.alerts ?? []) {
    const link = alert.incident_ref
      ? suffixReference(alert.incident_ref, stamp)
      : incidentRef;
    if (!link) {
      throw new Error("scenario alert missing incident_ref and no incident ingested");
    }
    await ingestSourceRecord({
      reference: suffixReference(alert.reference, stamp),
      raw_payload: alert.raw_payload ?? {},
      normalized: alert.normalized ?? {},
      incident_ref: link,
    });
  }

  for (const asset of scenario.assets ?? []) {
    if (!incidentRef) {
      throw new Error("scenario asset ingest requires incident reference");
    }
    await ingestSourceRecord({
      reference: suffixReference(asset.reference, stamp),
      raw_payload: asset.raw_payload ?? {},
      normalized: {
        ...(asset.normalized ?? {}),
        channel: "asset",
        device_source: "asset",
      },
      incident_ref: incidentRef,
    });
  }

  if ((scenario.telemetry_timeline ?? []).length > 0) {
    if (!incidentRef) {
      throw new Error("telemetry_timeline ingest requires incident reference");
    }
    const records = (scenario.telemetry_timeline ?? []).map((record) =>
      suffixTelemetryRecord(record, stamp),
    );
    await ingestTelemetryTimeline(incidentRef, records);
  } else {
    for (const log of scenario.logs ?? []) {
      if (!incidentRef) {
        throw new Error("scenario log ingest requires incident reference");
      }
      await ingestSourceRecord({
        reference: suffixReference(log.reference, stamp),
        raw_payload: log.raw_payload ?? {},
        normalized: log.normalized ?? {},
        incident_ref: incidentRef,
      });
    }
  }

  if (!eventId) {
    throw new Error("scenario ingest produced no event_id");
  }
  return eventId;
}

async function ingestScenarioPack(): Promise<string> {
  return ingestScenarioPackVariant({ stamp: "analysis" });
}

async function createApprovalEvent(): Promise<string> {
  const stamp = String(Date.now());
  return ingestScenarioPackVariant({
    stamp: `approval-${stamp}`,
    incidentTitle: `E2E L4 approval insider_data_exfiltration ${stamp}`,
  });
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
    const detail = await api<{ event: { status: string } }>(
      "GET",
      `/events/${eventId}`,
    );
    const status = detail.data.event?.status;
    if (!status || status === "new" || status === "triaging") {
      return null;
    }
    if (status === "failed") throw new Error(`event ${eventId} failed`);

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
    const eventStatus = detail.data.event?.status;
    if (eventStatus === "failed") {
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
