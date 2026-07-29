/**
 * Cross-event path overlay toggle (ISSUE-083).
 *
 * Hidden when there are no cross_event_paths (Neo4j disabled or no overlaps).
 * Default: overlay off. When on, parent highlights shared entities with a
 * double-ring and draws dashed links to related-event anchors.
 */
import { Space, Switch, Typography } from "antd";
import type { CrossEventPath } from "../../types/event";

export interface CrossEventOverlayHints {
  sharedEntityValues: Set<string>;
  /** Synthetic dashed edges: source = local node id, target = related-event anchor id */
  dashedLinks: Array<{
    edgeId: string;
    source: string;
    target: string;
    relatedEventId: string;
    sharedEntity: string;
  }>;
  relatedEventAnchors: Array<{
    id: string;
    label: string;
  }>;
}

export function buildCrossEventOverlayHints(
  paths: CrossEventPath[],
  nodeIdByEntityValue: Map<string, string>,
): CrossEventOverlayHints {
  const sharedEntityValues = new Set<string>();
  const dashedLinks: CrossEventOverlayHints["dashedLinks"] = [];
  const anchorMap = new Map<string, string>();

  for (const path of paths) {
    for (const entity of path.shared_entities) {
      sharedEntityValues.add(entity);
    }
    for (const relatedEventId of path.related_event_ids) {
      const anchorId = `rel-evt-${relatedEventId}`;
      if (!anchorMap.has(anchorId)) {
        anchorMap.set(anchorId, relatedEventId);
      }
      const primaryShared = path.shared_entities[0];
      const localNodeId = primaryShared
        ? nodeIdByEntityValue.get(primaryShared)
        : undefined;
      if (!localNodeId || !primaryShared) continue;
      dashedLinks.push({
        edgeId: `cross-${path.path_id}-${relatedEventId}`,
        source: localNodeId,
        target: anchorId,
        relatedEventId,
        sharedEntity: primaryShared,
      });
    }
  }

  return {
    sharedEntityValues,
    dashedLinks,
    relatedEventAnchors: [...anchorMap.entries()].map(([id, label]) => ({
      id,
      label,
    })),
  };
}

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
        onChange={onEnabledChange}
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
