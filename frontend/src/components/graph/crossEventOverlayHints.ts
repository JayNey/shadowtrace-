/**
 * Pure helpers for cross-event path overlay rendering (ISSUE-083).
 */
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
