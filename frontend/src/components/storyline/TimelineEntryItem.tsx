import {
  ClockCircleOutlined,
  DownOutlined,
  RightOutlined,
} from "@ant-design/icons";
import { Button, Popover, Space, Tag, Typography } from "antd";
import { useState } from "react";
import type { Evidence, TimelineEntry } from "../../types/event";

const SEVERITY_COLORS = {
  low: "green",
  medium: "gold",
  high: "orange",
  critical: "red",
} as const;

const SEVERITY_LABELS = {
  low: "低",
  medium: "中",
  high: "高",
  critical: "严重",
} as const;

const TECHNIQUE_NAMES: Record<string, string> = {
  T1005: "Data from Local System",
  T1027: "Obfuscated/Compressed Files and Information",
  T1041: "Exfiltration Over C2 Channel",
  T1059: "Command and Scripting Interpreter",
  T1071: "Application Layer Protocol",
  T1078: "Valid Accounts",
  T1486: "Data Encrypted for Impact",
  T1560: "Archive Collected Data",
  T1566: "Phishing",
  T1567: "Exfiltration Over Web Service",
};

function formatTimestamp(timestamp: string): string {
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return timestamp;
  return parsed.toLocaleString("zh-CN", { hour12: false });
}

function observationEntries(evidence: Evidence): Array<[string, string]> {
  const fields = evidence.observation_fields;
  if (!fields) return [];
  return Object.entries(fields).filter(([, value]) => value.trim().length > 0);
}

export default function TimelineEntryItem({
  entry,
  evidence,
}: {
  entry: TimelineEntry;
  evidence?: Evidence;
}) {
  const [expanded, setExpanded] = useState(false);
  const techniqueName = entry.technique_id
    ? (TECHNIQUE_NAMES[entry.technique_id] ?? "MITRE ATT&CK 技术")
    : null;

  return (
    <div data-testid={`timeline-entry-${entry.evidence_id}`}>
      <Space direction="vertical" size={6} style={{ width: "100%" }}>
        <Space wrap size={[8, 4]}>
          <Typography.Text type="secondary">
            <ClockCircleOutlined />{" "}
            <time dateTime={entry.timestamp} title={entry.timestamp}>
              {formatTimestamp(entry.timestamp)}
            </time>
          </Typography.Text>
          {entry.technique_id && (
            <Popover
              trigger="click"
              title={entry.technique_id}
              content={techniqueName}
            >
              <Button
                type="text"
                size="small"
                aria-label={`查看 ${entry.technique_id} 技术名称`}
                style={{ padding: 0 }}
              >
                <Tag color="geekblue" style={{ marginInlineEnd: 0 }}>
                  {entry.technique_id}
                </Tag>
              </Button>
            </Popover>
          )}
          {entry.severity_hint && (
            <Tag color={SEVERITY_COLORS[entry.severity_hint]}>
              {SEVERITY_LABELS[entry.severity_hint]}
            </Tag>
          )}
        </Space>
        <Typography.Text>{entry.description}</Typography.Text>
        <Button
          type="link"
          size="small"
          icon={expanded ? <DownOutlined /> : <RightOutlined />}
          onClick={() => setExpanded((value) => !value)}
          aria-expanded={expanded}
          aria-label={expanded ? "收起关联证据" : "展开关联证据"}
          style={{ alignSelf: "flex-start", paddingInline: 0 }}
        >
          {expanded ? "收起关联证据" : "展开关联证据"}
        </Button>
        {expanded && (
          <div
            data-testid={`timeline-evidence-${entry.evidence_id}`}
            style={{
              borderLeft: "3px solid #d9d9d9",
              background: "#fafafa",
              padding: "10px 12px",
              borderRadius: 4,
            }}
          >
            <Typography.Text strong>证据 {entry.evidence_id}</Typography.Text>
            {evidence ? (
              <ExpandedEvidenceBody entry={entry} evidence={evidence} />
            ) : (
              <Typography.Text type="secondary">
                未找到关联证据
              </Typography.Text>
            )}
          </div>
        )}
      </Space>
    </div>
  );
}

function ExpandedEvidenceBody({
  entry,
  evidence,
}: {
  entry: TimelineEntry;
  evidence: Evidence;
}) {
  const fields = observationEntries(evidence);
  const description = (evidence.description || "").trim();
  const showDescription =
    description.length > 0 &&
    (fields.length === 0 || description !== (entry.description || "").trim());

  return (
    <>
      {showDescription ? (
        <Typography.Paragraph style={{ margin: "6px 0" }}>
          {description}
        </Typography.Paragraph>
      ) : null}
      {fields.length > 0 ? (
        <Typography.Text
          type="secondary"
          data-testid={`timeline-observation-${entry.evidence_id}`}
          style={{ fontSize: 12, display: "block", marginTop: 4 }}
        >
          {fields.map(([key, value]) => `${key}: ${value}`).join(" · ")}
        </Typography.Text>
      ) : null}
      {evidence.related_entities && evidence.related_entities.length > 0 ? (
        <Typography.Text type="secondary" style={{ fontSize: 12, display: "block", marginTop: 4 }}>
          关联实体：{evidence.related_entities.join(", ")}
        </Typography.Text>
      ) : null}
    </>
  );
}
