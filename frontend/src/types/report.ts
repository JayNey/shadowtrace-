/** Report models — matching backend app/models/report.py + openapi.json */

export type ReportQuality =
  | "complete"
  | "degraded_template"
  | "quick_close"
  | "incomplete_placeholder";

export interface ReportSection {
  key: string;
  title: string;
  content: string;
  data: Record<string, unknown>;
}

export interface InvestigationReport {
  report_id: string;
  event_id: string;
  title: string;
  summary: string;
  sections: ReportSection[];
  final_verdict: string;
  risk_score: number;
  severity: string;
  version: number;
  generated_by: string | null;
  generated_at: string | null;
  updated_at: string | null;
  warnings?: string[];
  error_detail?: string | null;
  report_quality?: ReportQuality;
  degraded?: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function coerceReportQuality(value: unknown): ReportQuality | undefined {
  if (
    value === "complete" ||
    value === "degraded_template" ||
    value === "quick_close" ||
    value === "incomplete_placeholder"
  ) {
    return value;
  }
  return undefined;
}

/** Narrow EventContext.report into InvestigationReport when structurally valid. */
export function coerceInvestigationReport(value: unknown): InvestigationReport | null {
  if (!isRecord(value)) return null;
  if (typeof value.report_id !== "string" || typeof value.event_id !== "string") {
    return null;
  }
  if (typeof value.title !== "string" || !Array.isArray(value.sections)) {
    return null;
  }
  const sections = value.sections.filter((section): section is ReportSection => {
    if (!isRecord(section)) return false;
    return (
      typeof section.key === "string" &&
      typeof section.title === "string" &&
      typeof section.content === "string"
    );
  });
  if (sections.length === 0) return null;
  const report_quality = coerceReportQuality(value.report_quality);
  const degraded =
    typeof value.degraded === "boolean"
      ? value.degraded
      : report_quality !== undefined
        ? report_quality !== "complete"
        : undefined;
  return {
    report_id: value.report_id,
    event_id: value.event_id,
    title: value.title,
    summary: typeof value.summary === "string" ? value.summary : "",
    sections: sections.map((section) => ({
      key: section.key,
      title: section.title,
      content: section.content,
      data: isRecord(section.data) ? section.data : {},
    })),
    final_verdict: typeof value.final_verdict === "string" ? value.final_verdict : "none",
    risk_score: typeof value.risk_score === "number" ? value.risk_score : 0,
    severity: typeof value.severity === "string" ? value.severity : "low",
    version: typeof value.version === "number" ? value.version : 1,
    generated_by: typeof value.generated_by === "string" ? value.generated_by : null,
    generated_at: typeof value.generated_at === "string" ? value.generated_at : null,
    updated_at: typeof value.updated_at === "string" ? value.updated_at : null,
    warnings: Array.isArray(value.warnings)
      ? value.warnings.filter((item): item is string => typeof item === "string")
      : [],
    error_detail: typeof value.error_detail === "string" ? value.error_detail : null,
    report_quality,
    degraded,
  };
}
