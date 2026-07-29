import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import CrossEventPathOverlay from "../../src/components/graph/CrossEventPathOverlay";
import type { CrossEventPath } from "../../src/types/event";

const PATHS: CrossEventPath[] = [
  {
    path_id: "cep-demo",
    related_event_ids: ["evt-other"],
    shared_entities: ["198.51.100.77"],
    path_nodes: ["node-a", "node-b"],
    risk_hint: "shared_external_ip",
  },
];

describe("CrossEventPathOverlay", () => {
  it("hides when paths are empty", () => {
    const { container } = render(
      <CrossEventPathOverlay
        paths={[]}
        enabled={false}
        onEnabledChange={vi.fn()}
      />,
    );
    expect(container).toBeEmptyDOMElement();
    expect(
      screen.queryByTestId("cross-event-path-overlay"),
    ).not.toBeInTheDocument();
  });

  it("renders toggle off by default and notifies parent when enabled", async () => {
    const user = userEvent.setup();
    const onEnabledChange = vi.fn();
    render(
      <CrossEventPathOverlay
        paths={PATHS}
        enabled={false}
        onEnabledChange={onEnabledChange}
      />,
    );

    expect(screen.getByTestId("cross-event-path-overlay")).toBeInTheDocument();
    const toggle = screen.getByTestId("cross-event-path-toggle");
    expect(toggle).toHaveAttribute("aria-checked", "false");

    await user.click(toggle);
    expect(onEnabledChange).toHaveBeenCalledWith(true);
  });
});
