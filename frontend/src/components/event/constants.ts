/** Centralized color & label constants for event tags (ISSUE-068).

  Status color convention:
    - NEW                  -> gray
    - In-progress (TRIAGING ~ VERIFYING, REPLANNING, REPORTING) -> blue
    - WAITING_APPROVAL     -> orange
    - CONTAINED            -> cyan
    - CLOSED               -> green
    - FAILED               -> red

  Severity color:
    - low      -> green
    - medium   -> yellow / gold
    - high     -> orange
    - critical -> red
*/

import type { EventStatus, FinalVerdict, Severity, WritebackStatus } from "../../types/event";

// --- Status -----------------------------------------------------------

export type StatusColorKey =
  | "default"
  | "processing"
  | "warning"
  | "success"
  | "error"
  | "cyan";

export interface StatusConfig {
  label: string;
  color: StatusColorKey;
}

const STATUS_CONFIG: Record<EventStatus, StatusConfig> = {
  new: { label: "新建", color: "default" },
  triaging: { label: "研判中", color: "processing" },
  collecting_evidence: { label: "取证中", color: "processing" },
  analyzing: { label: "分析中", color: "processing" },
  scoring: { label: "评分中", color: "processing" },
  planning_response: { label: "规划响应", color: "processing" },
  waiting_approval: { label: "待审批", color: "warning" },
  executing_response: { label: "执行响应", color: "processing" },
  verifying: { label: "验证中", color: "processing" },
  replanning: { label: "重新规划", color: "processing" },
  reporting: { label: "报告生成", color: "processing" },
  contained: { label: "已遏制", color: "cyan" },
  closed: { label: "已关闭", color: "success" },
  failed: { label: "失败", color: "error" },
};

export function getStatusConfig(status: EventStatus): StatusConfig {
  return STATUS_CONFIG[status] ?? { label: status, color: "default" };
}

/** Statuses where the list-page trigger button must stay disabled. */
export const NON_TRIGGERABLE_STATUSES: readonly EventStatus[] = [
  "triaging",
  "collecting_evidence",
  "analyzing",
  "scoring",
  "planning_response",
  "waiting_approval",
  "executing_response",
  "verifying",
  "replanning",
  "reporting",
  "contained",
  "closed",
];

/** Heuristic for list-first-screen writeback sync hints (ISSUE-038 degradation). */
export function isListExternalUnsynced(item: {
  status: EventStatus;
  writeback_required: boolean;
  writeback_overall_status: WritebackStatus | null;
  external_unsynced?: boolean;
}): boolean {
  if (item.external_unsynced === true) return true;
  return (
    item.status === "closed" &&
    item.writeback_required &&
    item.writeback_overall_status !== "confirmed"
  );
}

/** Map logical color key to Ant Design Badge status. */
export function toBadgeStatus(color: StatusColorKey) {
  switch (color) {
    case "default":
      return "default" as const;
    case "processing":
      return "processing" as const;
    case "warning":
      return "warning" as const;
    case "success":
      return "success" as const;
    case "error":
      return "error" as const;
    case "cyan":
      return "processing" as const;
    default:
      return "default" as const;
  }
}

/** Ant Design color tokens for Tag rendering. */
export function toTagColor(color: StatusColorKey) {
  switch (color) {
    case "default":
      return "default" as const;
    case "processing":
      return "blue" as const;
    case "warning":
      return "orange" as const;
    case "success":
      return "green" as const;
    case "error":
      return "red" as const;
    case "cyan":
      return "cyan" as const;
    default:
      return "default" as const;
  }
}

// --- Severity ---------------------------------------------------------

export interface SeverityConfig {
  label: string;
  color: "green" | "gold" | "orange" | "red";
}

const SEVERITY_CONFIG: Record<Severity, SeverityConfig> = {
  low: { label: "低", color: "green" },
  medium: { label: "中", color: "gold" },
  high: { label: "高", color: "orange" },
  critical: { label: "紧急", color: "red" },
};

export function getSeverityConfig(severity: Severity): SeverityConfig {
  return SEVERITY_CONFIG[severity] ?? { label: severity, color: "green" };
}

// --- Final verdict ----------------------------------------------------

export interface VerdictConfig {
  label: string;
  color: "default" | "gold" | "red" | "blue";
}

const VERDICT_CONFIG: Record<FinalVerdict, VerdictConfig> = {
  none: { label: "未判定", color: "default" },
  possible_false_positive: { label: "疑似误报", color: "gold" },
  false_positive: { label: "误报", color: "blue" },
  confirmed_threat: { label: "确认威胁", color: "red" },
};

export function getVerdictConfig(verdict: FinalVerdict): VerdictConfig {
  return VERDICT_CONFIG[verdict] ?? { label: verdict, color: "default" };
}

// --- Status filter options (for <Select>) -----------------------------

export const STATUS_FILTER_OPTIONS: { label: string; value: EventStatus }[] = [
  ...Object.entries(STATUS_CONFIG).map(([value, cfg]) => ({
    label: cfg.label,
    value: value as EventStatus,
  })),
];

export const SEVERITY_FILTER_OPTIONS: { label: string; value: Severity }[] = [
  ...Object.entries(SEVERITY_CONFIG).map(([value, cfg]) => ({
    label: cfg.label,
    value: value as Severity,
  })),
];

export const EVENT_TYPE_OPTIONS: {
  label: string;
  value: import("../../types/event").EventType;
}[] = [
  { label: "账号异常", value: "account_anomaly" },
  { label: "主机入侵", value: "host_compromise" },
  { label: "数据外泄", value: "data_exfiltration" },
  { label: "内部威胁", value: "insider_threat" },
  { label: "恶意进程", value: "malicious_process" },
  { label: "可疑域名", value: "suspicious_domain" },
  { label: "横向移动", value: "lateral_movement" },
  { label: "其他", value: "other" },
];
