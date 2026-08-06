import { test, expect } from "@playwright/test";

const BACKEND_BASE_URL =
  process.env.E2E_BACKEND_URL ?? "http://127.0.0.1:8000/api/v1";
const AUTH_TOKEN = process.env.E2E_AUTH_TOKEN ?? "e2e-token";

async function createNewEvent(): Promise<string> {
  const suffix = Date.now().toString(36);
  const res = await fetch(`${BACKEND_BASE_URL}/events`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${AUTH_TOKEN}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      event_type: "insider_threat",
      title: `E2E investigate mode ${suffix}`,
      description: "ISSUE-103 modal startup test",
      severity: "medium",
      creation_source_ref: {
        source_kind: "incident",
        source_product: "mock_xdr",
        source_tenant_id: "tenant-demo",
        connector_id: "conn-e2e",
        source_object_id: `INC-E2E-${suffix}`,
        ingested_at: new Date().toISOString(),
      },
    }),
  });
  const data = (await res.json()) as { event_id?: string; error_message?: string };
  if (!res.ok || !data.event_id) {
    throw new Error(
      `create event failed (${res.status}): ${data.error_message ?? JSON.stringify(data)}`,
    );
  }
  return data.event_id;
}

test.describe("ISSUE-103 · investigate mode modal", () => {
  test("defaults to analysis-only investigate request", async ({ page }) => {
    const eventId = await createNewEvent();
    let capturedBody: Record<string, unknown> | null = null;

    await page.route(`**/api/v1/events/${eventId}/investigate`, async (route) => {
      capturedBody = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          event_id: eventId,
          task_id: eventId,
          status: "new",
          include_response_execution: false,
          full_loop_available: true,
        }),
      });
    });

    await page.goto("/events?status=new");
    await expect(page.getByTestId("event-table")).toBeVisible();
    await expect(page.getByTestId(`event-row-${eventId}`)).toBeVisible({
      timeout: 60_000,
    });

    await page.getByTestId(`trigger-investigation-${eventId}`).click();
    await expect(page.getByTestId("investigate-mode-modal")).toBeVisible();
    await page.getByRole("button", { name: "开始调查" }).click();

    await expect.poll(() => capturedBody).not.toBeNull();
    expect(capturedBody).toMatchObject({
      include_response_execution: false,
      generate_report: false,
    });
  });

  test("full-loop selection sends include_response_execution=true", async ({ page }) => {
    const eventId = await createNewEvent();
    let capturedBody: Record<string, unknown> | null = null;

    await page.route(`**/api/v1/events/${eventId}/investigate`, async (route) => {
      capturedBody = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          event_id: eventId,
          task_id: eventId,
          status: "new",
          include_response_execution: true,
          full_loop_available: true,
        }),
      });
    });

    await page.goto("/events?status=new");
    await expect(page.getByTestId(`event-row-${eventId}`)).toBeVisible({
      timeout: 60_000,
    });

    await page.getByTestId(`trigger-investigation-${eventId}`).click();
    await expect(page.getByTestId("investigate-mode-modal")).toBeVisible();
    await page.getByTestId("investigate-mode-full-loop").click();
    await page.getByRole("button", { name: "开始调查" }).click();

    await expect.poll(() => capturedBody).not.toBeNull();
    expect(capturedBody).toMatchObject({ include_response_execution: true });
  });
});
