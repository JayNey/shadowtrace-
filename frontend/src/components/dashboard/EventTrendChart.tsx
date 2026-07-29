/** EventTrendChart — ECharts line of events_last_24h (ISSUE-085). */

import ReactECharts from "echarts-for-react";
import { Empty, Typography } from "antd";
import type { HourlyEventCount } from "../../types/stats";

export default function EventTrendChart({
  series,
}: {
  series: HourlyEventCount[];
}) {
  if (!series.length) {
    return (
      <div className="soc-panel" data-testid="event-trend-chart">
        <Typography.Title level={5} className="soc-panel-title">
          近 24 小时事件趋势
        </Typography.Title>
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />
      </div>
    );
  }

  const labels = series.map((b) => {
    const d = new Date(b.hour);
    if (Number.isNaN(d.getTime())) return b.hour;
    // Backend emits UTC hour buckets — keep axis labels in UTC.
    return `${String(d.getUTCHours()).padStart(2, "0")}:00`;
  });
  const values = series.map((b) => b.count);

  const option = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis" },
    grid: { left: 40, right: 16, top: 24, bottom: 32 },
    xAxis: {
      type: "category",
      data: labels,
      axisLabel: { color: "#8c8c8c" },
      axisLine: { lineStyle: { color: "#434343" } },
    },
    yAxis: {
      type: "value",
      minInterval: 1,
      axisLabel: { color: "#8c8c8c" },
      splitLine: { lineStyle: { color: "#303030" } },
    },
    series: [
      {
        type: "line",
        smooth: true,
        data: values,
        areaStyle: { color: "rgba(22,119,255,0.22)" },
        lineStyle: { color: "#1677ff" },
        itemStyle: { color: "#1677ff" },
      },
    ],
  };

  return (
    <div className="soc-panel" data-testid="event-trend-chart">
      <Typography.Title level={5} className="soc-panel-title">
        近 24 小时事件趋势
      </Typography.Title>
      <ReactECharts option={option} style={{ height: 280 }} opts={{ renderer: "canvas" }} />
    </div>
  );
}
