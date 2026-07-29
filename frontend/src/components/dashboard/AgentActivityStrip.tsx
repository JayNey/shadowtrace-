/** AgentActivityStrip — global-room agent progress feed for SOC wall (ISSUE-085). */

import { useEffect, useState } from "react";
import { Typography } from "antd";
import { socketClient } from "../../services/socketClient";
import {
  AGENT_LABELS,
  AGENT_STATUS_COLORS,
  type AgentName,
} from "../../stores/agentStatusStore";

const MAX_ROWS = 12;

export interface AgentActivityRow {
  id: string;
  event_id: string;
  agent_name: string;
  label: string;
  status: "PROCESSING" | "COMPLETED" | "FAILED";
  message: string;
  at: number;
}

function agentLabel(name: string): string {
  return AGENT_LABELS[name as AgentName] ?? name;
}

export default function AgentActivityStrip() {
  const [rows, setRows] = useState<AgentActivityRow[]>([]);

  useEffect(() => {
    socketClient.ensureGlobalRoom();
    const unsub = socketClient.onEvent((evt) => {
      if (
        evt.type !== "agent_progress" &&
        evt.type !== "agent_completed" &&
        evt.type !== "agent_failed"
      ) {
        return;
      }
      const payload = evt.payload as Record<string, unknown>;
      const agentName = String(payload.agent_name ?? "unknown");
      const status: AgentActivityRow["status"] =
        evt.type === "agent_failed"
          ? "FAILED"
          : evt.type === "agent_completed"
            ? "COMPLETED"
            : "PROCESSING";
      const message =
        evt.type === "agent_failed"
          ? String(payload.error_detail ?? payload.message ?? "failed")
          : String(payload.message ?? status.toLowerCase());
      const row: AgentActivityRow = {
        id: `${evt.event_id}-${agentName}-${Date.now()}-${Math.random()}`,
        event_id: evt.event_id,
        agent_name: agentName,
        label: agentLabel(agentName),
        status,
        message,
        at: Date.now(),
      };
      setRows((prev) => [row, ...prev].slice(0, MAX_ROWS));
    });
    return () => {
      unsub();
    };
  }, []);

  return (
    <div className="soc-panel" data-testid="agent-activity-strip">
      <Typography.Title level={5} className="soc-panel-title">
        Agent 活动
      </Typography.Title>
      {rows.length === 0 ? (
        <Typography.Text type="secondary" data-testid="agent-activity-empty">
          等待 Agent 进度事件（global 房间）
        </Typography.Text>
      ) : (
        <ul className="soc-agent-list">
          {rows.map((row) => (
            <li key={row.id} className="soc-agent-row" data-testid="agent-activity-row">
              <span
                className="soc-agent-dot"
                style={{ background: AGENT_STATUS_COLORS[row.status] }}
              />
              <span className="soc-agent-label">{row.label}</span>
              <span className="soc-agent-id">{row.event_id}</span>
              <span className="soc-agent-msg">{row.message}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
