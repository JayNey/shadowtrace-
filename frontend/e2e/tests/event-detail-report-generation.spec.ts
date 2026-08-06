/** ISSUE-206 e2e (mock API): on-demand report generation from the report tab. */

import { test, expect } from "@playwright/test";

const EVENT_ID = "evt-on-demand-report";

const GENERATED_REPORT = {
  report_id: "rpt-on-demand",
  event_id: EVENT_ID,
  title: "按需生成调查报告",
  summary: "E2E on-demand generation",
  sections: [
    {
      key: "event_overview",
      title: "事件概述",
      content: "操作员在报告 Tab 手动触发生成，非占位章节。",
    },
    {
      key: "severity",
      title: "严重级别",
      content: "high",
    },
    {
      key: "risk_score",
      title: "风险评分",
      content: "72",
    },
  ],
  final_verdict: "confirmed_threat",
  risk_score: 72,
  severity: "high",
  generated_by: "llm",
  generated_at: "2026-08-06T12:00:00Z",
  report_quality: "complete",
  degraded: false,
};

function baseDetail(status: string, report: typeof GENERATED_REPORT | null) {
  return {
    event: {
      event_id: EVENT_ID,
      event_type: "account_anomaly",
      title: "On-demand report e2e event",
      description: "analysis complete, no report bytes yet",
      status,
      severity: "high",
      risk_score: 72,
      confidence: 0.88,
      final_verdict: "confirmed_threat",
      entities: { accounts: [], hosts: [], ips: [], domains: [], processes: [], files: [] },
      creation_source_ref: null,
      source_reference_snapshots: [],
      current_primary_source_record_id: null,
      disposition_source_ref: null,
      disposition_policy: "required",
      raw_alert_ids: [],
      raw_alert_snapshot: {},
      source_type: "xdr",
      occurred_at: "2026-08-05T08:00:00Z",
      created_at: "2026-08-05T08:01:00Z",
      updated_at: "2026-08-06T12:00:00Z",
      closed_at: null,
      replan_count: 0,
      degraded_flags: [],
      escalated: false,
      external_unsynced: false,
      row_version: 1,
      event_context_snapshot: report ? { report } : {},
    },
    writeback_required: false,
    writeback_readiness: "not_required",
    writeback_overall_status: null,
    pending_writeback_count: 0,
    analysis_only_complete: true,
    next_recommended_action: "none",
    phase_message: null,
    execution_substate: null as string | null,
  };
}

const emptyList = { total: 0, page: 1, page_size: 100, items: [] };

test.describe("ISSUE-206 · on-demand report generation", () => {
  test("generates a report from the empty-state CTA without a full page reload", async ({
    page,
  }) => {
    let postCalled = false;
    let hasReport = false;

    const isEventDetailUrl = (url: URL) =>
      new RegExp(`/api/v1/events/${EVENT_ID}/?$`).test(url.pathname);

    await page.route((url) => isEventDetailUrl(new URL(url)), async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(
            baseDetail("reporting", hasReport ? GENERATED_REPORT : null),
          ),
        });
        return;
      }
      await route.fallback();
    });

    await page.route(`**/api/v1/events/${EVENT_ID}/report`, async (route) => {
      if (route.request().method() === "POST") {
        postCalled = true;
        hasReport = true;
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ report: GENERATED_REPORT }),
        });
        return;
      }
      await route.fallback();
    });

    await page.route("**/api/v1/events/*/actions**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(emptyList),
      });
    });
    await page.route("**/api/v1/events/*/dispositions**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ event_id: EVENT_ID, items: [] }),
      });
    });
    await page.route("**/api/v1/events/*/traces**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(emptyList),
      });
    });
    await page.route("**/api/v1/connectors**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ items: [] }),
      });
    });
    await page.route("**/api/v1/knowledge/reviews**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ total: 0, items: [] }),
      });
    });
    await page.route("**/api/v1/events/*/decision-trace**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          event_id: EVENT_ID,
          entries: [],
          missing_sources: [],
          summary: {},
        }),
      });
    });
    await page.route("**/api/v1/events/*/trajectory**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          event_id: EVENT_ID,
          total_steps: 0,
          agent_invocations: 0,
          tool_calls: 0,
          llm_calls: 0,
          metrics: {},
          findings: [],
          insufficient_trace: false,
        }),
      });
    });

    await page.goto(`/events/${EVENT_ID}#report`);

    await expect(page.getByText("报告尚未生成")).toBeVisible();
    await expect(page.getByTestId("report-generate-button")).toBeVisible();

    await page.getByTestId("report-generate-button").click();

    await expect.poll(() => postCalled).toBe(true);
    await expect(page.getByText("报告已生成")).toBeVisible();
    await expect(page.getByTestId("report-viewer")).toBeVisible();
    await expect(page.getByText("按需生成调查报告")).toBeVisible();
    await expect(page.getByText("操作员在报告 Tab 手动触发生成，非占位章节。")).toBeVisible();
  });
});
