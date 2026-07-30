import { describe, expect, it } from "vitest";
import {
  buildCrossEventOverlayHints,
  entityOverlayKey,
  localSharedNodesForPath,
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
  it("highlights all visible local nodes matching shared entity values", () => {
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

    expect(hints.sharedNodeIds.has("node-ip-host")).toBe(true);
    expect(hints.sharedNodeIds.has("node-ip-domain")).toBe(true);
    expect(hints.dashedLinks).toHaveLength(2);
    expect(hints.dashedLinks.map((link) => link.source).sort()).toEqual([
      "node-ip-domain",
      "node-ip-host",
    ]);
  });

  it("skips dashed links when no local shared nodes are visible", () => {
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

describe("localSharedNodesForPath", () => {
  it("matches by shared entity value even when path_nodes omits a node id", () => {
    const path: CrossEventPath = {
      path_id: "cep-x",
      related_event_ids: ["evt-b"],
      shared_entities: ["alice"],
      path_nodes: ["node-account"],
      risk_hint: "shared_account",
    };
    const visible = [
      node("node-account", "account", "alice"),
      node("node-host", "host", "ws-01"),
    ];
    expect(localSharedNodesForPath(path, visible).map((n) => n.node_id)).toEqual([
      "node-account",
    ]);
  });
});

describe("entityOverlayKey", () => {
  it("builds a composite key for entity type and value", () => {
    expect(entityOverlayKey("ip", "10.0.0.1")).toBe("ip\u000010.0.0.1");
  });
});
