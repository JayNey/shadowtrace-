import { Card, Empty, Space, Tag, Timeline, Typography } from "antd";
import type {
  Evidence,
  StorylinePhase,
} from "../../types/event";
import { PHASE_COLORS, PHASE_LABELS } from "./constants";
import TimelineEntryItem from "./TimelineEntryItem";

function timestampValue(value: string): number {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Number.POSITIVE_INFINITY : parsed;
}

export default function PhaseSection({
  phase,
  evidenceById,
  isPlaceholder = false,
}: {
  phase: StorylinePhase;
  evidenceById: Map<string, Evidence>;
  /** Synthetic empty shell padded by the timeline layout — not real storyline data. */
  isPlaceholder?: boolean;
}) {
  const color = PHASE_COLORS[phase.phase_name];
  const entries = [...phase.entries].sort(
    (left, right) =>
      timestampValue(left.timestamp) - timestampValue(right.timestamp),
  );

  return (
    <Card
      size="small"
      data-testid={
        isPlaceholder
          ? `storyline-phase-empty-${phase.phase_name}`
          : `storyline-phase-${phase.phase_name}`
      }
      style={{ borderLeft: `4px solid ${color}` }}
      title={
        <Space wrap>
          <Tag color={color}>{phase.phase_order}</Tag>
          <Typography.Text strong>
            {PHASE_LABELS[phase.phase_name]}
          </Typography.Text>
          {phase.tactic && <Tag>ATT&CK · {phase.tactic}</Tag>}
        </Space>
      }
    >
      {phase.narrative && (
        <Typography.Paragraph type="secondary">
          {phase.narrative}
        </Typography.Paragraph>
      )}
      {entries.length > 0 ? (
        <Timeline
          items={entries.map((entry) => ({
            color,
            children: (
              <TimelineEntryItem
                entry={entry}
                evidence={evidenceById.get(entry.evidence_id)}
              />
            ),
          }))}
        />
      ) : (
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="该阶段暂无时间线条目"
        />
      )}
    </Card>
  );
}
