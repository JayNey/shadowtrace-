/** Dashboard color constants aligned with event status/severity (ISSUE-085). */

import { getSeverityConfig, getStatusConfig } from "../event/constants";
import type { EventStatus, Severity } from "../../types/event";

/** Ant Design-ish hex tokens for ECharts / CSS on the SOC dark theme. */
export const SEVERITY_HEX: Record<Severity, string> = {
  low: "#52c41a",
  medium: "#faad14",
  high: "#fa8c16",
  critical: "#f5222d",
};

export const STATUS_HEX: Record<string, string> = {
  default: "#8c8c8c",
  processing: "#1677ff",
  warning: "#fa8c16",
  success: "#52c41a",
  error: "#f5222d",
  cyan: "#13c2c2",
};

export function severityLabel(severity: string): string {
  return getSeverityConfig(severity as Severity).label;
}

export function severityColor(severity: string): string {
  return SEVERITY_HEX[severity as Severity] ?? "#8c8c8c";
}

export function statusLabel(status: string): string {
  return getStatusConfig(status as EventStatus).label;
}

export function statusColor(status: string): string {
  const cfg = getStatusConfig(status as EventStatus);
  return STATUS_HEX[cfg.color] ?? STATUS_HEX.default;
}
