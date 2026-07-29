import { describe, expect, it } from "vitest";
import {
  buildCrossEventOverlayHints,
  entityOverlayKey,
} from "../../src/components/graph/crossEventOverlayHints";
import type { CrossEventPath, GraphNode } from "../../src/types/event";

const node = (
  nodeId: string,
  entityType: GraphNode["entity_type"],
  entityValue: string,
): GraphNode => ({
  node_id: nodeId,
  event_id: "evt-local",
  entity_type: entityType,
  entity_value: entityValue,
  properties: {},
});

describe("buildCrossEventOverlayHints", () => {
  it("uses path_nodes for dashed links instead of entity_value collisions", () => {
    const paths: CrossEventPath[] = [
      {
        path_id: "cep-demo",
        related_event_ids: ["evt-other"],
        shared_entities: ["10.0.0.1"],
        path_nodes: ["node-ip-host", "node-ip-domain"],
        risk_hint: "shared_external_ip",
      },
    ];
    const visibleNodes = [
      node("node-ip-host", "ip", "10.0.0.1"),
      node("node-ip-domain", "domain", "10.0.0.1"),
    ];

    const hints = buildCrossEventOverlayHints(paths, visibleNodes);

    expect(hints.dashedLinks).toHaveLength(1);
    expect(hints.dashedLinks[0]?.source).toBe("node-ip-host");
    expect(hints.sharedNodeIds.has("node-ip-host")).toBe(true);
    expect(hints.sharedNodeIds.has("node-ip-domain")).toBe(false);
  });

  it("skips dashed links when the local node is filtered out", () => {
    const paths: CrossEventPath[] = [
      {
        path_id: "cep-hidden",
        related_event_ids: ["evt-other"],
        shared_entities: ["198.51.100.77"],
        path_nodes: ["node-hidden"],
        risk_hint: "shared_external_ip",
      },
    ];

    const hints = buildCrossEventOverlayHints(paths, []);

    expect(hints.dashedLinks).toHaveLength(0);
    expect(hints.relatedEventAnchors).toEqual([
      { id: "rel-evt-evt-other", label: "evt-other" },
    ]);
  });
});

describe("entityOverlayKey", () => {
  it("builds a composite key for entity type and value", () => {
    expect(entityOverlayKey("ip", "10.0.0.1")).toBe("ip\u000010.0.0.1");
  });
});
