import { Alert, Card, Col, Progress, Row, Space, Statistic, Tag, Typography } from "antd";
import type { AgentQualityScore, TrajectoryReport } from "../../types/trace";

const METRIC_LABELS: Record<string, string> = {
  redundant_tool_calls: "冗余工具调用",
  loop_suspected: "循环风险",
  replan_effectiveness: "重规划有效性",
  avg_agent_latency_ms: "Agent 平均延迟",
  evidence_yield: "证据产出率",
  steps_to_verdict: "到达结论步数",
};

function metricDisplay(key: string, value: number): string {
  if (key.endsWith("_ms")) return `${Math.round(value)} ms`;
  if (key === "steps_to_verdict" || key === "redundant_tool_calls") {
    return String(Math.round(value));
  }
  return `${Math.round(value * 100)}%`;
}

export default function TrajectorySummary({
  report,
  qualityScores,
}: {
  report: TrajectoryReport | null;
  qualityScores: AgentQualityScore[];
}) {
  if (!report && qualityScores.length === 0) return null;

  return (
    <Card title="轨迹质量摘要" size="small">
      <Space direction="vertical" size={16} style={{ width: "100%" }}>
        {report?.insufficient_trace && (
          <Alert type="info" showIcon message="轨迹数据不足，部分指标暂不可计算" />
        )}
        {report && (
          <>
            <Row gutter={[12, 12]}>
              <Col xs={12} md={6}>
                <Statistic title="总步骤" value={report.total_steps} />
              </Col>
              <Col xs={12} md={6}>
                <Statistic title="Agent 执行" value={report.agent_invocations} />
              </Col>
              <Col xs={12} md={6}>
                <Statistic title="工具调用" value={report.tool_calls} />
              </Col>
              <Col xs={12} md={6}>
                <Statistic title="模型调用" value={report.llm_calls} />
              </Col>
            </Row>
            <Row gutter={[12, 12]}>
              {Object.entries(report.metrics).map(([key, value]) => (
                <Col xs={12} md={8} key={key}>
                  <Typography.Text type="secondary">
                    {METRIC_LABELS[key] ?? key}
                  </Typography.Text>
                  <div>
                    <Typography.Text strong>{metricDisplay(key, value)}</Typography.Text>
                  </div>
                </Col>
              ))}
            </Row>
            {report.findings.length > 0 && (
              <Alert
                type="warning"
                showIcon
                message="轨迹发现"
                description={report.findings.join("；")}
              />
            )}
          </>
        )}
        {qualityScores.length > 0 && (
          <div>
            <Typography.Text strong>各 Agent 输出质量</Typography.Text>
            <Row gutter={[12, 12]} style={{ marginTop: 8 }}>
              {qualityScores.map((quality) => (
                <Col xs={24} md={12} xl={8} key={quality.agent_name}>
                  <Card size="small">
                    <Space direction="vertical" style={{ width: "100%" }}>
                      <Space>
                        <Typography.Text strong>{quality.agent_name}</Typography.Text>
                        {quality.verdict && <Tag>{quality.verdict}</Tag>}
                      </Space>
                      <Progress
                        percent={Math.round(quality.score * 100)}
                        size="small"
                        status={quality.score < 0.6 ? "exception" : "normal"}
                      />
                      {quality.reasons && quality.reasons.length > 0 && (
                        <Typography.Text type="secondary">
                          {quality.reasons.join("；")}
                        </Typography.Text>
                      )}
                    </Space>
                  </Card>
                </Col>
              ))}
            </Row>
          </div>
        )}
      </Space>
    </Card>
  );
}
