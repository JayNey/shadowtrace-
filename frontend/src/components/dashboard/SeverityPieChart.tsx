/** SeverityPieChart — ECharts pie of by_severity (ISSUE-085). */

import ReactECharts from "echarts-for-react";
import { Empty, Typography } from "antd";
import { SEVERITY_HEX, severityLabel } from "./constants";
import type { Severity } from "../../types/event";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

export default function SeverityPieChart({
  bySeverity,
}: {
  bySeverity: Record<string, number>;
}) {
  const data = ORDER.filter((s) => (bySeverity[s] ?? 0) > 0).map((s) => ({
    name: severityLabel(s),
    value: bySeverity[s] ?? 0,
    itemStyle: { color: SEVERITY_HEX[s] },
  }));

  // Include any unexpected keys so the chart still reflects DB truth.
  for (const [key, value] of Object.entries(bySeverity)) {
    if (!ORDER.includes(key as Severity) && value > 0) {
      data.push({
        name: key,
        value,
        itemStyle: { color: "#8c8c8c" },
      });
    }
  }

  if (data.length === 0) {
    return (
      <div className="soc-panel" data-testid="severity-pie-chart">
        <Typography.Title level={5} className="soc-panel-title">
          严重度分布
        </Typography.Title>
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />
      </div>
    );
  }

  const option = {
    backgroundColor: "transparent",
    tooltip: { trigger: "item" },
    legend: {
      bottom: 0,
      textStyle: { color: "#bfbfbf" },
    },
    series: [
      {
        type: "pie",
        radius: ["40%", "68%"],
        avoidLabelOverlap: true,
        label: { color: "#d9d9d9" },
        data,
      },
    ],
  };

  return (
    <div className="soc-panel" data-testid="severity-pie-chart">
      <Typography.Title level={5} className="soc-panel-title">
        严重度分布
      </Typography.Title>
      <ReactECharts option={option} style={{ height: 280 }} opts={{ renderer: "canvas" }} />
    </div>
  );
}
