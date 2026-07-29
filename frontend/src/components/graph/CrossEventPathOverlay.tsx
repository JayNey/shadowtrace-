/**
 * Cross-event path overlay toggle (ISSUE-083).
 *
 * Hidden when there are no cross_event_paths (Neo4j disabled or no overlaps).
 * Default: overlay off. When on, parent highlights shared entities with a
 * double-ring and draws dashed links to related-event anchors.
 */
import { Space, Switch, Typography } from "antd";
import type { CrossEventPath } from "../../types/event";

export default function CrossEventPathOverlay({
  paths,
  enabled,
  onEnabledChange,
}: {
  paths: CrossEventPath[];
  enabled: boolean;
  onEnabledChange: (enabled: boolean) => void;
}) {
  if (paths.length === 0) {
    return null;
  }

  const sharedCount = new Set(paths.flatMap((p) => p.shared_entities)).size;
  const relatedCount = new Set(paths.flatMap((p) => p.related_event_ids)).size;

  return (
    <Space wrap data-testid="cross-event-path-overlay">
      <Switch
        checked={enabled}
        onChange={(checked) => onEnabledChange(checked)}
        data-testid="cross-event-path-toggle"
        aria-label="叠加跨事件路径"
      />
      <Typography.Text>
        跨事件路径
        <Typography.Text type="secondary" style={{ marginLeft: 8 }}>
          {relatedCount} 个关联事件 · {sharedCount} 个共享实体
        </Typography.Text>
      </Typography.Text>
    </Space>
  );
}
