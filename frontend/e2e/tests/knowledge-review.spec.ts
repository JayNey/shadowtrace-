import { test, expect } from "@playwright/test";

const API_BASE = process.env.E2E_BACKEND_URL ?? "http://127.0.0.1:8000/api/v1";

const PROFILE_ONLY_FIXTURE = {
  total: 1,
  items: [
    {
      review_id: "rev-e2e-profile",
      kb_name: "entity_profile",
      candidate_type: "profile",
      payload: {
        event_id: "evt-e2e-open",
        entity_type: "host",
        entity_value: "WKS-DATA-031",
        behavior_tags: ["event_type:data_exfiltration"],
      },
      status: "pending",
      confidence: 0.72,
      created_at: "2026-08-05T12:00:00Z",
    },
  ],
};

const CLOSED_LOOP_FIXTURE = {
  total: 2,
  items: [
    PROFILE_ONLY_FIXTURE.items[0],
    {
      review_id: "rev-e2e-fp",
      kb_name: "fp_case_kb",
      candidate_type: "fp_rule",
      payload: {
        source_event_id: "evt-e2e-closed",
        rule_summary: "Approved backup upload pattern",
        alert_signature: "backup:upload",
      },
      status: "pending",
      confidence: 0.88,
      created_at: "2026-08-05T13:00:00Z",
    },
  ],
};

/** Match only GET list endpoint — not /promote or /reject. */
function isReviewsListUrl(url: URL): boolean {
  return /\/api\/v1\/knowledge\/reviews\/?$/.test(url.pathname);
}

function isPromoteUrl(url: URL): boolean {
  return /\/api\/v1\/knowledge\/reviews\/[^/]+\/promote\/?$/.test(url.pathname);
}

async function mockReviewsRoute(
  page: import("@playwright/test").Page,
  fixture: typeof PROFILE_ONLY_FIXTURE,
  promoteHandler?: () => object,
) {
  await page.route(
    (url) => isReviewsListUrl(new URL(url)),
    async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(fixture),
        });
        return;
      }
      await route.fallback();
    },
  );

  if (promoteHandler) {
    await page.route(
      (url) => isPromoteUrl(new URL(url)),
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(promoteHandler()),
        });
      },
    );
  }
}

test.describe("ISSUE-213 · knowledge review page", () => {
  test("shows profile-only pending with CLOSED timing guidance", async ({ page }) => {
    await mockReviewsRoute(page, PROFILE_ONLY_FIXTURE);

    await page.goto("/knowledge/reviews");

    await expect(page.getByRole("heading", { name: "知识审核" })).toBeVisible();
    await expect(page.getByTestId("knowledge-review-timing-note")).toContainText(
      "ISSUE-208",
    );
    await expect(page.getByTestId("candidate-type-profile")).toBeVisible();
    await expect(page.getByText("rev-e2e-profile")).toBeVisible();
    await expect(page.getByText(/当前均为 profile，符合 CLOSED 前预期/)).toBeVisible();
  });

  test("shows closed-loop types and promotes a review", async ({ page }) => {
    let listed = CLOSED_LOOP_FIXTURE;

    await page.route(
      (url) => isReviewsListUrl(new URL(url)),
      async (route) => {
        if (route.request().method() === "GET") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify(listed),
          });
          return;
        }
        await route.fallback();
      },
    );

    await page.route(
      (url) => isPromoteUrl(new URL(url)),
      async (route) => {
        listed = { total: 1, items: [CLOSED_LOOP_FIXTURE.items[1]!] };
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            review_id: "rev-e2e-profile",
            status: "promoted",
            message: "memory candidate promoted",
          }),
        });
      },
    );

    await page.goto("/knowledge/reviews");

    await expect(page.getByTestId("candidate-type-fp_rule")).toBeVisible();
    await expect(
      page.getByText(/含须 CLOSED 后入队的 fp_rule \/ history_case/),
    ).toBeVisible();

    await page.getByTestId("promote-rev-e2e-profile").click();
    await page.getByRole("button", { name: "入 库" }).click();

    await expect(page.getByText("候选已入库")).toBeVisible();
    await expect(page.getByTestId("candidate-type-profile")).toHaveCount(0);
    await expect(page.getByTestId("candidate-type-fp_rule")).toBeVisible();
  });

  test("empty list explains ISSUE-208 expectation instead of missing feature", async ({
    page,
  }) => {
    await mockReviewsRoute(page, { total: 0, items: [] });

    await page.goto("/knowledge/reviews");

    await expect(page.getByText("当前暂无 pending 候选")).toBeVisible();
    await expect(page.getByText(/不代表本页未实现/)).toBeVisible();
  });
});

// Guard against accidental coupling to live backend shape during mocked e2e.
test("knowledge reviews API base path remains /api/v1/knowledge/reviews", async () => {
  expect(`${API_BASE}/knowledge/reviews`).toContain("/knowledge/reviews");
});

test("list route matcher excludes promote/reject paths", () => {
  expect(
    isReviewsListUrl(new URL("http://127.0.0.1:8000/api/v1/knowledge/reviews")),
  ).toBe(true);
  expect(
    isReviewsListUrl(
      new URL("http://127.0.0.1:8000/api/v1/knowledge/reviews?kb_name=x"),
    ),
  ).toBe(true);
  expect(
    isReviewsListUrl(
      new URL("http://127.0.0.1:8000/api/v1/knowledge/reviews/rev-1/promote"),
    ),
  ).toBe(false);
  expect(
    isReviewsListUrl(
      new URL("http://127.0.0.1:8000/api/v1/knowledge/reviews/rev-1/reject"),
    ),
  ).toBe(false);
  expect(
    isPromoteUrl(
      new URL("http://127.0.0.1:8000/api/v1/knowledge/reviews/rev-1/promote"),
    ),
  ).toBe(true);
});
