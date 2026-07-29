import { describe, expect, it } from "vitest";
import { buildCrossEventOverlayHints } from "../../src/components/graph/crossEventOverlayHints";
import type { CrossEventPath } from "../../src/types/event";

describe("buildCrossEventOverlayHints", () => {
  it("builds dashed links and related-event anchors for shared entities", () => {
    const paths: CrossEventPath[] = [
      {
        path_id: "cep-demo",
        related_event_ids: ["evt-other"],
        shared_entities: ["198.51.100.77"],
        path_nodes: ["node-ip-a", "node-ip-b"],
        risk_hint: "shared_external_ip",
      },
    ];
    const nodeIdByEntityValue = new Map([["198.51.100.77", "node-ip-a"]]);

    const hints = buildCrossEventOverlayHints(paths, nodeIdByEntityValue);

    expect([...hints.sharedEntityValues]).toEqual(["198.51.100.77"]);
    expect(hints.relatedEventAnchors).toEqual([
      { id: "rel-evt-evt-other", label: "evt-other" },
    ]);
    expect(hints.dashedLinks).toEqual([
      {
        edgeId: "cross-cep-demo-evt-other",
        source: "node-ip-a",
        target: "rel-evt-evt-other",
        relatedEventId: "evt-other",
        sharedEntity: "198.51.100.77",
      },
    ]);
  });

  it("skips dashed links when the shared entity is not in the local graph", () => {
    const paths: CrossEventPath[] = [
      {
        path_id: "cep-missing",
        related_event_ids: ["evt-b"],
        shared_entities: ["203.0.113.9"],
        path_nodes: [],
        risk_hint: "shared_external_ip",
      },
    ];

    const hints = buildCrossEventOverlayHints(paths, new Map());

    expect([...hints.sharedEntityValues]).toEqual(["203.0.113.9"]);
    expect(hints.dashedLinks).toEqual([]);
    expect(hints.relatedEventAnchors).toHaveLength(1);
  });
});
