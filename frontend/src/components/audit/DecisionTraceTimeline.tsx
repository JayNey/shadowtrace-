import {
  Alert,
  Button,
  Checkbox,
  Descriptions,
  Empty,
  Space,
  Tag,
  Timeline,
  Typography,
} from "antd";
import { LinkOutlined } from "@ant-design/icons";
import { useMemo, useState } from "react";
import type {
  DecisionTraceEntry,
  DecisionTraceEntryType,
} from "../../types/trace";
import {
  ALL_TRACE_TYPES,
  TRACE_TYPE_COLORS,
  TRACE_TYPE_LABELS,
} from "./constants";
import JsonTree from "./JsonTree";

function formatTimestamp(value: string): string {
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function textList(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join("、");
  return value === undefined || value === null || value === "" ? "暂无数据" : String(value);
}

function AgentDecisionBasis({ entry }: { entry: DecisionTraceEntry }) {
  const detail = entry.detail;
  const confidence =
    typeof detail.confidence === "number"
      ? `${Math.round(detail.confidence * 100)}%`
      : textList(detail.confidence);
  const model = [detail.model_name ?? detail.model, detail.model_version]
    .filter(Boolean)
    .join(" / ");
  const rules = [textList(detail.rules_applied), detail.rule_version]
    .filter((value) => value && value !== "暂无数据")
    .join(" / ");

  return (
    <Descriptions size="small" column={1} style={{ marginTop: 8 }}>
      <Descriptions.Item label="决策依据">
        {textList(detail.structured_conclusion)}
      </Descriptions.Item>
      <Descriptions.Item label="证据引用">
        {textList(detail.evidence_refs)}
      </Descriptions.Item>
      <Descriptions.Item label="规则 / 版本">{rules || "暂无数据"}</Descriptions.Item>
      <Descriptions.Item label="模型 / 版本">{model || "暂无数据"}</Descriptions.Item>
      <Descriptions.Item label="置信度">{confidence}</Descriptions.Item>
      <Descriptions.Item label="警告">{textList(detail.warnings)}</Descriptions.Item>
    </Descriptions>
  );
}

function TraceDetail({ entry }: { entry: DecisionTraceEntry }) {
  if (entry.entry_type === "agent_execution") {
    return <AgentDecisionBasis entry={entry} />;
  }
  if (entry.entry_type === "writeback") {
    return (
      <Descriptions size="small" column={1} style={{ marginTop: 8 }}>
        <Descriptions.Item label="状态">{textList(entry.detail.status)}</Descriptions.Item>
        <Descriptions.Item label="confirmation_evidence">
          {textList(entry.detail.confirmation_evidence)}
        </Descriptions.Item>
        <Descriptions.Item label="disposition_id">
          {textList(entry.detail.disposition_id)}
        </Descriptions.Item>
      </Descriptions>
    );
  }
  return (
    <div style={{ marginTop: 8 }}>
      <JsonTree value={entry.detail} />
    </div>
  );
}

export default function DecisionTraceTimeline({
  entries,
  missingSources = [],
  onToolCallSelect,
}: {
  entries: DecisionTraceEntry[];
  missingSources?: string[];
  onToolCallSelect?: (callId: string) => void;
}) {
  const [selectedTypes, setSelectedTypes] =
    useState<DecisionTraceEntryType[]>(ALL_TRACE_TYPES);
  const orderedEntries = useMemo(
    () =>
      [...entries]
        .filter((entry) => selectedTypes.includes(entry.entry_type))
        .sort(
          (left, right) =>
            new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime(),
        ),
    [entries, selectedTypes],
  );

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      {missingSources.length > 0 && (
        <Alert
          type="warning"
          showIcon
          message="部分决策轨迹来源不可用"
          description={missingSources.join("；")}
        />
      )}
      <Checkbox.Group
        aria-label="轨迹类型筛选"
        value={selectedTypes}
        options={ALL_TRACE_TYPES.map((value) => ({
          value,
          label: TRACE_TYPE_LABELS[value],
        }))}
        onChange={(values) =>
          setSelectedTypes(values as DecisionTraceEntryType[])
        }
      />
      {orderedEntries.length === 0 ? (
        <Empty description="暂无符合条件的决策轨迹" />
      ) : (
        <Timeline
          items={orderedEntries.map((entry) => ({
            color: TRACE_TYPE_COLORS[entry.entry_type],
            children: (
              <div data-testid={`trace-entry-${entry.entry_type}`}>
                <Space wrap>
                  <Tag color={TRACE_TYPE_COLORS[entry.entry_type]}>
                    {TRACE_TYPE_LABELS[entry.entry_type]}
                  </Tag>
                  {entry.entry_type === "tool_call" && entry.ref_id ? (
                    <Button
                      type="link"
                      style={{ padding: 0, height: "auto" }}
                      icon={<LinkOutlined />}
                      onClick={() => onToolCallSelect?.(entry.ref_id!)}
                    >
                      {entry.title}
                    </Button>
                  ) : (
                    <Typography.Text strong>{entry.title}</Typography.Text>
                  )}
                  <Typography.Text type="secondary">{entry.actor}</Typography.Text>
                </Space>
                <div>
                  <Typography.Text type="secondary">
                    {formatTimestamp(entry.timestamp)}
                  </Typography.Text>
                </div>
                <TraceDetail entry={entry} />
              </div>
            ),
          }))}
        />
      )}
    </Space>
  );
}
