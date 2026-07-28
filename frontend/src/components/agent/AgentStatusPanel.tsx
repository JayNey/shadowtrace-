/** Agent real-time status panel — 12-card grid + activity feed (ISSUE-075). */

import { useEffect, useState } from "react";
import { Col, Collapse, Row, Space, Tag, Typography } from "antd";
import {
  ALL_AGENT_NAMES,
  useAgentStatusStore,
} from "../../stores/agentStatusStore";
import type { AgentTrace } from "../../types/trace";
import type { EventStatus } from "../../types/event";
import AgentStatusCard from "./AgentStatusCard";
import AgentActivityFeed from "./AgentActivityFeed";

const PULSE_STYLE_ID = "agent-status-pulse-keyframes";

function ensurePulseKeyframes(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById(PULSE_STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = PULSE_STYLE_ID;
  style.textContent = `
@keyframes agent-status-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.45; transform: scale(1.35); }
}
`;
  document.head.appendChild(style);
}

interface Props {
  eventId: string;
  eventStatus: EventStatus;
  traces: AgentTrace[];
}

export default function AgentStatusPanel({
  eventId,
  eventStatus,
  traces,
}: Props) {
  const agents = useAgentStatusStore((s) => s.agents);
  const feed = useAgentStatusStore((s) => s.feed);
  const isInvestigating = useAgentStatusStore((s) => s.isInvestigating);
  const socketConnected = useAgentStatusStore((s) => s.socketConnected);
  const startWatching = useAgentStatusStore((s) => s.startWatching);
  const stopWatching = useAgentStatusStore((s) => s.stopWatching);
  const replayFromTraces = useAgentStatusStore((s) => s.replayFromTraces);

  const closed = eventStatus === "closed";
  const [activeKeys, setActiveKeys] = useState<string[]>(
    closed ? [] : ["agent-status"],
  );

  useEffect(() => {
    ensurePulseKeyframes();
  }, []);

  // Socket watch + 10s poll fallback (store-owned).
  useEffect(() => {
    startWatching(eventId);
    return () => {
      stopWatching();
    };
  }, [eventId, startWatching, stopWatching]);

  // Page-load history replay from traces (closed / mid-flight summary).
  // Skip overwrite while live socket investigation is driving the panel.
  useEffect(() => {
    if (traces.length === 0) return;
    if (isInvestigating && socketConnected) return;
    replayFromTraces(traces);
  }, [eventId, traces, replayFromTraces, isInvestigating, socketConnected]);

  // Expand while investigating; collapse after CLOSED.
  useEffect(() => {
    if (closed) {
      setActiveKeys([]);
    } else {
      setActiveKeys(["agent-status"]);
    }
  }, [eventId, closed]);

  const headerExtra = (
    <Space size={8} onClick={(e) => e.stopPropagation()}>
      {isInvestigating && <Tag color="processing">研判进行中</Tag>}
      {closed && <Tag>已结案回放</Tag>}
      {!socketConnected && (
        <Tag color="default">轮询降级 · 10s</Tag>
      )}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {feed.length} 条活动
      </Typography.Text>
    </Space>
  );

  return (
    <div data-testid="agent-status-panel">
      <Collapse
        activeKey={activeKeys}
        onChange={(keys) =>
          setActiveKeys(Array.isArray(keys) ? keys : [keys].filter(Boolean))
        }
        items={[
          {
            key: "agent-status",
            label: (
              <Space>
                <Typography.Text strong>Agent 实时状态</Typography.Text>
                {headerExtra}
              </Space>
            ),
            children: (
              <Space direction="vertical" size={16} style={{ width: "100%" }}>
                <Row gutter={[12, 12]}>
                  {ALL_AGENT_NAMES.map((name) => (
                    <Col key={name} xs={12} sm={8} md={6} lg={4}>
                      <AgentStatusCard info={agents[name]} />
                    </Col>
                  ))}
                </Row>
                <div>
                  <Typography.Text
                    type="secondary"
                    style={{ fontSize: 12, display: "block", marginBottom: 4 }}
                  >
                    活动流
                  </Typography.Text>
                  <AgentActivityFeed entries={feed} />
                </div>
              </Space>
            ),
          },
        ]}
      />
    </div>
  );
}
