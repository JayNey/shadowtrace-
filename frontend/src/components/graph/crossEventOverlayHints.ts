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

export function buildCrossEventOverlayHints(
  paths: CrossEventPath[],
  visibleNodes: GraphNode[],
): CrossEventOverlayHints {
  const visibleNodeIds = new Set(visibleNodes.map((node) => node.node_id));
  const sharedNodeIds = new Set<string>();
  const dashedLinks: CrossEventOverlayHints["dashedLinks"] = [];
  const anchorMap = new Map<string, string>();

  for (const path of paths) {
    for (const nodeId of path.path_nodes) {
      if (visibleNodeIds.has(nodeId)) {
        sharedNodeIds.add(nodeId);
      }
    }
    for (const relatedEventId of path.related_event_ids) {
      const anchorId = `rel-evt-${relatedEventId}`;
      if (!anchorMap.has(anchorId)) {
        anchorMap.set(anchorId, relatedEventId);
      }
      const localNodeId = path.path_nodes[0];
      const primaryShared = path.shared_entities[0];
      if (!localNodeId || !primaryShared || !visibleNodeIds.has(localNodeId)) {
        continue;
      }
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
    sharedNodeIds,
    dashedLinks,
    relatedEventAnchors: [...anchorMap.entries()].map(([id, label]) => ({
      id,
      label,
    })),
  };
}
