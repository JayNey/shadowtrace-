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
  DecisionTraceSummary,
} from "../../types/trace";
import {
  AGENT_NAME_LABELS,
  ALL_TRACE_TYPES,
  DEFAULT_TRACE_TYPES,
  TRACE_TYPE_COLORS,
  TRACE_TYPE_LABELS,
} from "./constants";
import JsonTree from "./JsonTree";

function formatTimestamp(value: string): string {
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function formatDurationMs(value: number): string {
  if (value < 1000) return `${value} ms`;
  const seconds = value / 1000;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  const minutes = Math.floor(seconds / 60);
  const rem = Math.round(seconds % 60);
  return rem > 0 ? `${minutes} min ${rem} s` : `${minutes} min`;
}

function isPresent(value: unknown): boolean {
  if (value === undefined || value === null || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

function textList(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).join("、");
  return String(value);
}

function primaryBrief(detail: Record<string, unknown>): string | null {
  const brief = detail.brief ?? detail.structured_conclusion;
  if (typeof brief === "string" && brief.trim()) {
    return brief.trim();
  }
  return null;
}

function displayActor(actor: string): string {
  return AGENT_NAME_LABELS[actor] ?? actor;
}

function displayTitle(title: string, actor: string): string {
  const label = AGENT_NAME_LABELS[actor];
  let text = title;
  if (!label) {
    return text;
  }
  if (text === actor || text.startsWith(`${actor} `) || text.startsWith(`${actor}：`)) {
    text = text.slice(actor.length).replace(/^[\s：]+/u, "");
  }
  return text.replace(/：summary_unavailable=\S+$/u, "").replace(/：status=\S+$/u, "");
}

function AgentDecisionBasis({ entry }: { entry: DecisionTraceEntry }) {
  const detail = entry.detail;
  const rows: Array<{ label: string; value: string }> = [];
  const brief = primaryBrief(detail);
  if (brief) {
    rows.push({ label: "决策依据", value: brief });
  }
  if (isPresent(detail.evidence_refs)) {
    rows.push({ label: "证据引用", value: textList(detail.evidence_refs) });
  }
  const rules = [detail.rules_applied, detail.rule_version]
    .filter((value) => isPresent(value))
    .map((value) => textList(value));
  if (rules.length > 0) {
    rows.push({ label: "规则 / 版本", value: rules.join(" / ") });
  }
  const model = [detail.model_name ?? detail.model, detail.model_version]
    .filter((value) => isPresent(value))
    .map(String);
  if (model.length > 0) {
    rows.push({ label: "模型 / 版本", value: model.join(" / ") });
  }
  if (typeof detail.confidence === "number") {
    rows.push({ label: "置信度", value: `${Math.round(detail.confidence * 100)}%` });
  }
  if (isPresent(detail.warnings)) {
    rows.push({ label: "警告", value: textList(detail.warnings) });
  }

  if (rows.length === 0) {
    return null;
  }

  return (
    <div style={{ marginTop: 8 }}>
      <Descriptions size="small" column={1}>
        {rows.map((row) => (
          <Descriptions.Item key={row.label} label={row.label}>
            {row.value}
          </Descriptions.Item>
        ))}
      </Descriptions>
    </div>
  );
}

function NonAgentTraceDetail({ entry }: { entry: DecisionTraceEntry }) {
  const detail = entry.detail;
  const rows: Array<{ label: string; value: unknown }> = [];

  const push = (label: string, ...keys: string[]) => {
    for (const key of keys) {
      if (isPresent(detail[key])) {
        rows.push({ label, value: detail[key] });
        return;
      }
    }
  };

  switch (entry.entry_type) {
    case "tool_call":
      push("工具", "tool_name");
      push("状态", "status");
      push("工具结果语义", "tool_outcome");
      push("提供者状态", "provider_status");
      push("记录数", "records_count");
      push("缺口原因", "gap_reason");
      push("耗时 (ms)", "duration_ms");
      push("结果摘要", "result_summary", "summary", "message");
      break;
    case "llm_call":
      push("模型", "model_name", "model");
      push("状态", "status");
      push("Tokens", "tokens_used", "total_tokens");
      push("输出摘要", "output_summary", "summary");
      break;
    case "state_transition":
      push("原状态", "from_status");
      push("新状态", "to_status");
      push("原因", "reason", "message");
      break;
    case "approval":
      push("动作 ID", "action_id");
      push("状态", "status", "decision");
      push("说明", "comment", "summary");
      break;
    case "action_execution":
      push("动作 ID", "action_id");
      push("动作名", "action_name");
      push("状态", "status");
      push("目标", "target");
      break;
    case "disposition":
      push("disposition_id", "disposition_id");
      push("intent", "intent_kind");
      push("状态", "status");
      break;
    case "writeback":
      push("状态", "status");
      push("confirmation_evidence", "confirmation_evidence");
      push("disposition_id", "disposition_id");
      break;
    default:
      break;
  }

  if (rows.length === 0) {
    const hasDetail = Object.keys(detail).length > 0;
    if (!hasDetail) {
      return null;
    }
    return (
      <div style={{ marginTop: 8 }}>
        <JsonTree value={detail} />
      </div>
    );
  }

  return (
    <Descriptions size="small" column={1} style={{ marginTop: 8 }}>
      {rows.map((row) => (
        <Descriptions.Item key={row.label} label={row.label}>
          {textList(row.value)}
        </Descriptions.Item>
      ))}
    </Descriptions>
  );
}

function TraceDetail({ entry }: { entry: DecisionTraceEntry }) {
  if (entry.entry_type === "agent_execution") {
    return <AgentDecisionBasis entry={entry} />;
  }
  return <NonAgentTraceDetail entry={entry} />;
}

export default function DecisionTraceTimeline({
  entries,
  missingSources = [],
  summary = null,
  onToolCallSelect,
}: {
  entries: DecisionTraceEntry[];
  missingSources?: string[];
  summary?: DecisionTraceSummary | null;
  onToolCallSelect?: (callId: string) => void;
}) {
  const [selectedTypes, setSelectedTypes] =
    useState<DecisionTraceEntryType[]>(DEFAULT_TRACE_TYPES);
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

  // ISSUE-253/257: prefer active (excludes approval + writeback idle); wall secondary.
  const activeMs = summary?.active_duration_ms ?? null;
  const wallMs = summary?.total_duration_ms ?? null;
  const primaryDurationMs = activeMs ?? wallMs;

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
      {primaryDurationMs != null && (
        <Typography.Paragraph style={{ marginBottom: 0 }} data-testid="trace-duration-summary">
          <Typography.Text type="secondary">调查耗时：</Typography.Text>
          <Typography.Text strong>
            {formatDurationMs(primaryDurationMs)}
          </Typography.Text>
          {activeMs != null ? (
            <Typography.Text type="secondary">（有效，已排除审批/写回空等）</Typography.Text>
          ) : (
            <Typography.Text type="secondary">（墙钟）</Typography.Text>
          )}
          {activeMs != null && wallMs != null && wallMs !== activeMs ? (
            <Typography.Text type="secondary">
              {" "}· 墙钟 {formatDurationMs(wallMs)}
            </Typography.Text>
          ) : null}
        </Typography.Paragraph>
      )}
      <Space wrap align="center">
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
        <Button
          type="link"
          size="small"
          aria-label="仅展示 Agent 执行"
          onClick={() => setSelectedTypes([...DEFAULT_TRACE_TYPES])}
        >
          仅 Agent
        </Button>
        <Button
          type="link"
          size="small"
          aria-label="展示全部轨迹类型"
          onClick={() => setSelectedTypes([...ALL_TRACE_TYPES])}
        >
          全部类型
        </Button>
      </Space>
      <Typography.Text type="secondary">
        每一步展示结论、证据引用和置信度。模型独白不落库。需要排障时再勾选工具、模型或写回。
      </Typography.Text>
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
                      {displayTitle(entry.title, entry.actor)}
                    </Button>
                  ) : (
                    <Typography.Text strong>
                      {displayTitle(entry.title, entry.actor)}
                    </Typography.Text>
                  )}
                  <Typography.Text type="secondary">
                    {displayActor(entry.actor)}
                  </Typography.Text>
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
