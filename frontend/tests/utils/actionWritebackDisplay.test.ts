/** actionWritebackDisplay unit tests (ISSUE-331). */

import { describe, expect, it } from "vitest";
import {
  resolveActionWritebackDisplay,
  resolveWritebackReceiptDisplay,
} from "../../src/utils/actionWritebackDisplay";

describe("resolveActionWritebackDisplay", () => {
  it("does not treat required=true + applicable=false as confirmed writeback", () => {
    const display = resolveActionWritebackDisplay({
      writeback_required: true,
      writeback_applicable: false,
      writeback_status: null,
    });
    expect(display.isConfirmedApplicableWriteback).toBe(false);
    expect(display.label).toContain("不承担终态写回");
    expect(display.tone).toBe("neutral");
  });

  it("shows confirmed only when applicable and status confirmed", () => {
    const display = resolveActionWritebackDisplay({
      writeback_required: true,
      writeback_applicable: true,
      writeback_status: "confirmed",
    });
    expect(display.isConfirmedApplicableWriteback).toBe(true);
    expect(display.tone).toBe("success");
  });

  it("does not show success when required but status confirmed without applicable", () => {
    const display = resolveActionWritebackDisplay({
      writeback_required: true,
      writeback_applicable: false,
      writeback_status: "confirmed",
    });
    expect(display.isConfirmedApplicableWriteback).toBe(false);
    expect(display.tone).toBe("neutral");
  });

  it("treats omitted applicable as unknown, not entity_side_effect", () => {
    const display = resolveActionWritebackDisplay({
      writeback_required: true,
      writeback_status: "confirmed",
    });
    expect(display.isConfirmedApplicableWriteback).toBe(false);
    expect(display.tone).not.toBe("success");
    expect(display.label).toContain("适用性未知");
    expect(display.label).not.toContain("不承担终态写回");
  });
});

describe("resolveWritebackReceiptDisplay", () => {
  it("labels entity ACCEPTED as side-effect submit, not terminal done", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "accepted",
      intentKind: "entity_action_submit",
      matchingAction: {
        writeback_required: true,
        writeback_applicable: false,
      },
      terminal: false,
    });
    expect(display.isConfirmedApplicableWriteback).toBe(false);
    expect(display.label).toBe("实体侧效应已提交");
    expect(display.tone).not.toBe("success");
  });

  it("allows green terminal confirmed for EVENT_STATUS_UPDATE row", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "confirmed",
      intentKind: "event_status_update",
      matchingAction: {
        writeback_required: true,
        writeback_applicable: true,
      },
      terminal: true,
    });
    expect(display.isConfirmedApplicableWriteback).toBe(true);
    expect(display.tone).toBe("success");
  });

  it("does not paint orphan confirmed receipts as terminal success", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "confirmed",
      matchingAction: null,
      terminal: false,
    });
    expect(display.isConfirmedApplicableWriteback).toBe(false);
    expect(display.tone).not.toBe("success");
  });

  it("labels entity failed receipts as error, not obligation-neutral", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "failed",
      intentKind: "entity_action_submit",
      matchingAction: {
        writeback_required: true,
        writeback_applicable: false,
      },
      terminal: false,
    });
    expect(display.tone).toBe("error");
    expect(display.label).toContain("实体侧效应");
    expect(display.isConfirmedApplicableWriteback).toBe(false);
  });

  it("labels entity_action_submit confirmed without matchingAction as side-effect", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "confirmed",
      intentKind: "entity_action_submit",
      matchingAction: null,
      terminal: false,
    });
    expect(display.tone).not.toBe("success");
    expect(display.label).toBe("实体侧效应已确认");
  });

  it("does not let terminal=true bypass entity ACCEPTED side-effect labelling", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "accepted",
      intentKind: "entity_action_submit",
      matchingAction: {
        writeback_required: true,
        writeback_applicable: false,
      },
      terminal: true,
    });
    expect(display.label).toBe("实体侧效应已提交");
    expect(display.tone).not.toBe("success");
    expect(display.isConfirmedApplicableWriteback).toBe(false);
  });

  it("keeps in-progress entity receipts visible instead of collapsing to obligation copy", () => {
    const display = resolveWritebackReceiptDisplay({
      status: "sending",
      intentKind: "entity_action_submit",
      matchingAction: {
        writeback_required: true,
        writeback_applicable: false,
      },
      terminal: false,
    });
    expect(display.label).toBe("发送中");
    expect(display.tone).not.toBe("success");
    expect(display.label).not.toContain("不承担终态写回");
  });
});
