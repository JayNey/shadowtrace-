/** Scrollable Agent activity feed — auto-scroll to latest (ISSUE-075). */

import { useEffect, useRef } from "react";
import { Empty, Typography } from "antd";
import {
  AGENT_LABELS,
  type ActivityFeedEntry,
  type AgentName,
} from "../../stores/agentStatusStore";

interface Props {
  entries: ActivityFeedEntry[];
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleTimeString("zh-CN", { hour12: false });
  } catch {
    return iso;
  }
}

export default function AgentActivityFeed({ entries }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = bottomRef.current;
    if (el && typeof el.scrollIntoView === "function") {
      el.scrollIntoView({ behavior: "smooth", block: "end" });
    } else if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [entries.length]);

  if (entries.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="暂无活动"
        style={{ padding: "24px 0" }}
      />
    );
  }

  return (
    <div
      ref={containerRef}
      data-testid="agent-activity-feed"
      style={{
        maxHeight: 240,
        overflowY: "auto",
        padding: "4px 0",
        borderTop: "1px solid #f0f0f0",
      }}
    >
      {entries.map((entry) => {
        const label =
          AGENT_LABELS[entry.agent_name as AgentName] ?? entry.agent_name;
        return (
          <div
            key={entry.id}
            data-testid="agent-feed-entry"
            data-agent={entry.agent_name}
            style={{
              display: "flex",
              gap: 10,
              padding: "6px 4px",
              borderBottom: "1px solid #fafafa",
              fontSize: 12,
            }}
          >
            <Typography.Text type="secondary" style={{ flexShrink: 0, fontFamily: "monospace" }}>
              {formatTime(entry.timestamp)}
            </Typography.Text>
            <Typography.Text strong style={{ flexShrink: 0, minWidth: 64 }}>
              {label}
            </Typography.Text>
            <Typography.Text style={{ wordBreak: "break-word" }}>
              {entry.message}
            </Typography.Text>
          </div>
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}
