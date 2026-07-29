/** EventTrendChart — UTC hour label regression (ISSUE-085). */

import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("echarts-for-react", () => ({
  default: ({ option }: { option: { xAxis: { data: string[] } } }) => (
    <div data-testid="echarts-option">{JSON.stringify(option.xAxis.data)}</div>
  ),
}));

import EventTrendChart from "../../src/components/dashboard/EventTrendChart";

describe("EventTrendChart", () => {
  it("formats hour buckets with UTC hours (not local timezone)", () => {
    render(
      <EventTrendChart
        series={[
          { hour: "2026-07-29T08:00:00Z", count: 1 },
          { hour: "2026-07-29T15:00:00+00:00", count: 2 },
        ]}
      />,
    );
    const raw = screen.getByTestId("echarts-option").textContent ?? "";
    expect(raw).toContain("08:00");
    expect(raw).toContain("15:00");
  });
});
