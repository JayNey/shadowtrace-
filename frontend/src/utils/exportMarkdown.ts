/** Markdown export utility (ISSUE-074). */

import type { InvestigationReport } from "../types/report";

/** 15 chapter keys matching backend ReportSectionBuilder.SECTION_KEYS (ISSUE-036). */
const CHAPTER_KEYS = [
  "overview",
  "severity_level",
  "risk_scoring",
  "involved_accounts",
  "involved_assets",
  "involved_processes",
  "involved_files",
  "involved_external_addresses",
  "evidence_chain",
  "attack_storyline",
  "attack_mapping",
  "executed_actions",
  "verification_results",
  "recommendations",
  "appendix_index",
] as const;

/** Build Markdown matching backend report_template.md.j2 / ReportAgent output. */
export function buildReportMarkdown(report: InvestigationReport): string {
  const lines: string[] = [];
  lines.push(`# ${report.title}`);
  lines.push("");
  if (report.summary.trim()) {
    lines.push(report.summary.trim());
    lines.push("");
  }

  for (const key of CHAPTER_KEYS) {
    const section = report.sections.find((item) => item.key === key);
    if (!section) continue;
    lines.push(`## ${section.title}`);
    lines.push("");
    if (section.content) {
      lines.push(section.content);
      lines.push("");
    }
  }

  return `${lines.join("\n").trimEnd()}\n`;
}

/** Download a Markdown file for the report. */
export function downloadReportMarkdown(report: InvestigationReport): void {
  try {
    const md = buildReportMarkdown(report);
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `shadowtrace-report-${report.event_id}.md`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  } catch {
    // SSR / test environment — silently no-op
  }
}

export { CHAPTER_KEYS };
