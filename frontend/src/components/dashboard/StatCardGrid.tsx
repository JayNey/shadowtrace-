/** StatCardGrid — KPI cards for SOC dashboard rates (ISSUE-085). */

import { Col, Row, Statistic, Typography } from "antd";
import type { RateStat, StatsResponse } from "../../types/stats";

function formatRate(stat: RateStat): string {
  if (stat.rate == null || stat.denominator === 0) return "—";
  return `${(stat.rate * 100).toFixed(1)}%`;
}

function rateSuffix(stat: RateStat): string {
  return `${stat.numerator}/${stat.denominator}`;
}

function formatSeconds(seconds: number | null): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

export default function StatCardGrid({ stats }: { stats: StatsResponse | null }) {
  // Avoid flashing "0" as if the DB were empty before the first successful load.
  if (stats == null) {
    const placeholderCards = [
      { key: "total", title: "事件总数" },
      { key: "last24h", title: "近 24h 事件" },
      { key: "action", title: "动作执行成功率" },
      { key: "effect", title: "效果验证率" },
      { key: "writeback", title: "写回确认率" },
      { key: "avg", title: "平均研判时长" },
    ];
    return (
      <Row gutter={[16, 16]} data-testid="stat-card-grid">
        {placeholderCards.map((card) => (
          <Col xs={12} sm={8} md={4} key={card.key}>
            <div className="soc-stat-card">
              <Typography.Text className="soc-stat-title">{card.title}</Typography.Text>
              <Statistic value="—" valueStyle={{ color: "#e6f4ff", fontSize: 22 }} />
            </div>
          </Col>
        ))}
      </Row>
    );
  }

  const s = stats;
  const last24h = s.events_last_24h.reduce((sum, b) => sum + b.count, 0);

  const cards = [
    {
      key: "total",
      title: "事件总数",
      value: s.total_events,
      suffix: undefined as string | undefined,
    },
    {
      key: "last24h",
      title: "近 24h 事件",
      value: last24h,
      suffix: undefined,
    },
    {
      key: "action",
      title: "动作执行成功率",
      value: formatRate(s.action_execution_success_rate),
      suffix: rateSuffix(s.action_execution_success_rate),
    },
    {
      key: "effect",
      title: "效果验证率",
      value: formatRate(s.effect_verification_rate),
      suffix: rateSuffix(s.effect_verification_rate),
    },
    {
      key: "writeback",
      title: "写回确认率",
      value: formatRate(s.writeback_confirmation_rate),
      suffix: rateSuffix(s.writeback_confirmation_rate),
    },
    {
      key: "avg",
      title: "平均研判时长",
      value: formatSeconds(s.avg_investigation_seconds),
      suffix: undefined,
    },
  ];

  return (
    <Row gutter={[16, 16]} data-testid="stat-card-grid">
      {cards.map((card) => (
        <Col xs={12} sm={8} md={4} key={card.key}>
          <div className="soc-stat-card">
            <Typography.Text className="soc-stat-title">{card.title}</Typography.Text>
            <Statistic
              value={card.value}
              suffix={
                card.suffix ? (
                  <Typography.Text className="soc-stat-suffix">{card.suffix}</Typography.Text>
                ) : undefined
              }
              valueStyle={{ color: "#e6f4ff", fontSize: 22 }}
            />
          </div>
        </Col>
      ))}
    </Row>
  );
}
