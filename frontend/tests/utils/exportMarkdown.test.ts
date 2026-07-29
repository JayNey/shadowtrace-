/** exportMarkdown tests (ISSUE-074). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  buildReportMarkdown,
  downloadReportMarkdown,
  CHAPTER_KEYS,
} from "../../src/utils/exportMarkdown";
import type { InvestigationReport } from "../../src/types/report";

const SECTION_TITLES: Record<(typeof CHAPTER_KEYS)[number], string> = {
  overview: "事件概述",
  severity_level: "严重级别",
  risk_scoring: "风险评分",
  involved_accounts: "涉及账号",
  involved_assets: "涉及资产",
  involved_processes: "涉及进程",
  involved_files: "涉及文件",
  involved_external_addresses: "涉及外部地址",
  evidence_chain: "证据链",
  attack_storyline: "攻击故事线",
  attack_mapping: "攻击映射",
  executed_actions: "已执行处置",
  verification_results: "验证结果",
  recommendations: "处置建议",
  appendix_index: "附录索引",
};

function fullReport(overrides: Partial<InvestigationReport> = {}): InvestigationReport {
  return {
    report_id: "rpt-export-001",
    event_id: "evt-export-001",
    title: "导出测试报告",
    summary: "这是报告摘要。",
    sections: CHAPTER_KEYS.map((key) => ({
      key,
      title: SECTION_TITLES[key],
      content: `${key} content`,
      data: {},
    })),
    final_verdict: "confirmed_threat",
    risk_score: 90,
    severity: "high",
    version: 1,
    generated_by: null,
    generated_at: null,
    updated_at: null,
    ...overrides,
  };
}

describe("buildReportMarkdown", () => {
  it("matches backend report_template.md.j2 shape", () => {
    const report = fullReport();
    expect(buildReportMarkdown(report)).toBe(
      [
        "# 导出测试报告",
        "",
        "这是报告摘要。",
        "",
        ...CHAPTER_KEYS.flatMap((key) => [
          `## ${SECTION_TITLES[key]}`,
          "",
          `${key} content`,
          "",
        ]),
      ]
        .join("\n")
        .trimEnd()
        .concat("\n"),
    );
  });

  it("names download file shadowtrace-report-{event_id}.md", () => {
    const report = fullReport();
    const click = vi.fn();
    const anchor = {
      href: "",
      download: "",
      click,
    } as unknown as HTMLAnchorElement;
    const createElement = vi.spyOn(document, "createElement").mockReturnValue(anchor);
    vi.spyOn(document.body, "appendChild").mockImplementation(() => anchor);
    vi.spyOn(document.body, "removeChild").mockImplementation(() => anchor);
    Object.defineProperty(globalThis.URL, "createObjectURL", {
      configurable: true,
      writable: true,
      value: vi.fn(() => "blob:report"),
    });
    Object.defineProperty(globalThis.URL, "revokeObjectURL", {
      configurable: true,
      writable: true,
      value: vi.fn(),
    });

    downloadReportMarkdown(report);

    expect(anchor.download).toBe("shadowtrace-report-evt-export-001.md");
    expect(click).toHaveBeenCalledTimes(1);
    createElement.mockRestore();
  });
});

describe("downloadReportMarkdown", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("no-ops safely when DOM APIs are unavailable", () => {
    vi.spyOn(document, "createElement").mockImplementation(() => {
      throw new Error("DOM unavailable");
    });
    expect(() => downloadReportMarkdown(fullReport())).not.toThrow();
  });
});
