/**
 * Pure helpers for cross-event path overlay rendering (ISSUE-083).
 */
import type { CrossEventPath, GraphNode } from "../../types/event";

export interface CrossEventOverlayHints {
  /** Local graph node ids participating in a cross-event path. */
  sharedNodeIds: Set<string>;
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

export function entityOverlayKey(entityType: string, entityValue: string): string {
  return `${entityType}\0${entityValue}`;
}

/** Visible local nodes that participate in a cross-event path for overlay styling. */
export function localSharedNodesForPath(
  path: CrossEventPath,
  visibleNodes: GraphNode[],
): GraphNode[] {
  const sharedValues = new Set(path.shared_entities);
  const pathNodeIds = new Set(path.path_nodes);
  return visibleNodes.filter(
    (node) =>
      sharedValues.has(node.entity_value) || pathNodeIds.has(node.node_id),
  );
}

export function buildCrossEventOverlayHints(
  paths: CrossEventPath[],
  visibleNodes: GraphNode[],
): CrossEventOverlayHints {
  const sharedNodeIds = new Set<string>();
  const dashedLinks: CrossEventOverlayHints["dashedLinks"] = [];
  const anchorMap = new Map<string, string>();

  for (const path of paths) {
    const localNodes = localSharedNodesForPath(path, visibleNodes);
    for (const node of localNodes) {
      sharedNodeIds.add(node.node_id);
    }
    for (const relatedEventId of path.related_event_ids) {
      const anchorId = `rel-evt-${relatedEventId}`;
      if (!anchorMap.has(anchorId)) {
        anchorMap.set(anchorId, relatedEventId);
      }
      for (const localNode of localNodes) {
        dashedLinks.push({
          edgeId: `cross-${path.path_id}-${relatedEventId}-${localNode.node_id}`,
          source: localNode.node_id,
          target: anchorId,
          relatedEventId,
          sharedEntity: localNode.entity_value,
        });
      }
    }
  }

  return {
    sharedNodeIds,
    dashedLinks,
    relatedEventAnchors: [...anchorMap.entries()].map(([id, label]) => ({
      id,
      label,
    })),
  };
}
