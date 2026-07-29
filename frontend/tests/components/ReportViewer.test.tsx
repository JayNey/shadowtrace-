/** ReportViewer tests (ISSUE-074). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ReportViewer from "../../src/components/report/ReportViewer";
import { CHAPTER_KEYS } from "../../src/utils/exportMarkdown";

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

const MockIntersectionObserver = vi.fn(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
  takeRecords: vi.fn(() => []),
  root: null,
  rootMargin: "",
  thresholds: [],
}));
vi.stubGlobal("IntersectionObserver", MockIntersectionObserver);

describe("ReportViewer", () => {
  const mockReport = {
    report_id: "rpt-abc12345",
    event_id: "evt-test001",
    title: "数据外泄调查报告",
    summary: "调查摘要",
    sections: [
      { key: "overview", title: "事件概述", content: "事件概述内容...", data: {} },
      { key: "severity_level", title: "严重级别", content: "高危", data: {} },
      { key: "risk_scoring", title: "风险评分", content: "**高风险** 数据外泄", data: {} },
      { key: "executed_actions", title: "已执行处置", content: "block_ip", data: {} },
      { key: "recommendations", title: "处置建议", content: "加强监控", data: {} },
    ],
    final_verdict: "confirmed_threat",
    risk_score: 85,
    severity: "high",
    version: 1,
    generated_by: null,
    generated_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows loading spinner when loading", () => {
    render(<ReportViewer report={null} loading={true} />);
    expect(screen.getByText("加载中...")).toBeDefined();
  });

  it("shows placeholder when no report and not generating", () => {
    render(<ReportViewer report={null} loading={false} />);
    expect(screen.getByText("报告尚未生成")).toBeDefined();
  });

  it("shows generating message when event is REPORTING", () => {
    render(<ReportViewer report={null} loading={false} eventStatus="reporting" />);
    expect(screen.getByText("报告生成中，请稍候...")).toBeDefined();
  });

  it("renders report title and sections", () => {
    render(<ReportViewer report={mockReport} loading={false} />);
    expect(screen.getByText("数据外泄调查报告")).toBeDefined();
    expect(screen.getAllByText("事件概述").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("严重级别").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("风险评分").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("已执行处置").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("处置建议").length).toBeGreaterThanOrEqual(1);
  });

  it("shows template warning when generated_by=template", () => {
    render(
      <ReportViewer
        report={{ ...mockReport, generated_by: "template" }}
        loading={false}
      />,
    );
    expect(screen.getByText("模板生成（LLM 降级）")).toBeDefined();
  });

  it("renders markdown emphasis in section content", () => {
    render(<ReportViewer report={mockReport} loading={false} />);
    expect(screen.getByText("高风险")).toBeDefined();
    expect(screen.queryByText("**高风险** 数据外泄")).toBeNull();
  });

  it("renders all fifteen chapters when present", () => {
    const fullReport = {
      ...mockReport,
      sections: CHAPTER_KEYS.map((key) => ({
        key,
        title: SECTION_TITLES[key],
        content: `${key}-body`,
        data: {},
      })),
    };
    render(<ReportViewer report={fullReport} loading={false} />);
    for (const key of CHAPTER_KEYS) {
      expect(document.getElementById(key)).not.toBeNull();
    }
  });

  it("scrolls to chapter when TOC entry is clicked", async () => {
    const user = userEvent.setup();
    const scrollIntoView = vi.fn();
    HTMLElement.prototype.scrollIntoView = scrollIntoView;
    render(<ReportViewer report={mockReport} loading={false} />);

    await user.click(screen.getAllByText("已执行处置")[0]);

    expect(scrollIntoView).toHaveBeenCalled();
  });
});
