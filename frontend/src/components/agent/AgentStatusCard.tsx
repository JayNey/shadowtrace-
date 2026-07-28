/** Single Agent status card — fixed grid cell (ISSUE-075). */

import { Typography } from "antd";
import {
  AGENT_LABELS,
  AGENT_STATUS_COLORS,
  type AgentStatusInfo,
} from "../../stores/agentStatusStore";

interface Props {
  info: AgentStatusInfo;
}

function formatDuration(ms: number | null): string | null {
  if (ms == null || !Number.isFinite(ms)) return null;
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export default function AgentStatusCard({ info }: Props) {
  const color = AGENT_STATUS_COLORS[info.status];
  const label = AGENT_LABELS[info.agent_name];
  const duration = formatDuration(info.duration_ms);
  const isProcessing = info.status === "PROCESSING";

  return (
    <div
      data-testid={`agent-card-${info.agent_name}`}
      data-status={info.status}
      style={{
        border: `1px solid ${color}33`,
        borderLeft: `3px solid ${color}`,
        borderRadius: 6,
        padding: "10px 12px",
        background: isProcessing ? `${color}0d` : "#fff",
        minHeight: 88,
        display: "flex",
        flexDirection: "column",
        gap: 4,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span
          data-testid={`agent-status-dot-${info.agent_name}`}
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: color,
            flexShrink: 0,
            animation: isProcessing ? "agent-status-pulse 1.2s ease-in-out infinite" : undefined,
          }}
        />
        <Typography.Text strong style={{ fontSize: 13 }}>
          {label}
        </Typography.Text>
        <Typography.Text
          type="secondary"
          style={{ marginLeft: "auto", fontSize: 11, color }}
        >
          {info.status}
        </Typography.Text>
      </div>
      <Typography.Text
        type="secondary"
        ellipsis
        style={{ fontSize: 12, minHeight: 18 }}
        title={info.message ?? undefined}
      >
        {info.message ?? "—"}
      </Typography.Text>
      {(duration || info.progress_percent != null) && (
        <Typography.Text type="secondary" style={{ fontSize: 11 }}>
          {info.progress_percent != null ? `${Math.round(info.progress_percent)}%` : null}
          {info.progress_percent != null && duration ? " · " : null}
          {duration ? `耗时 ${duration}` : null}
        </Typography.Text>
      )}
    </div>
  );
}
