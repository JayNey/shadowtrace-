import { describe, expect, it } from "vitest";
import {
  formatAttackSlot,
  formatFpSlot,
  formatOrgSlot,
  formatPlaybookSlot,
  isCitationPending,
} from "../../src/utils/ragCitationStrip";

describe("ragCitationStrip", () => {
  it("treats missing or unretrieved citations as pending", () => {
    expect(isCitationPending(undefined)).toBe(true);
    expect(isCitationPending(null)).toBe(true);
    expect(isCitationPending({ retrieved: false })).toBe(true);
    expect(isCitationPending({ retrieved: true })).toBe(false);
  });

  it("formats fp hit with optional adjudication suffix", () => {
    expect(formatFpSlot({ retrieved: true, fp_case_id: "case-00000001" })).toBe(
      "命中 case-00000001",
    );
    expect(
      formatFpSlot(
        { retrieved: true, fp_case_id: "case-00000001" },
        "close_as_fp",
      ),
    ).toBe("命中 case-00000001 · close_as_fp");
    expect(formatFpSlot({ retrieved: true })).toBe("未命中误报卡");
  });

  it("formats org matches and empty state", () => {
    expect(
      formatOrgSlot([
        { kind: "time_window", matched_value: "08:00-12:00" },
        { kind: "account_role", matched_value: "ops-change-bot" },
      ]),
    ).toBe("time_window 08:00-12:00；account_role ops-change-bot");
    expect(formatOrgSlot([])).toBe("无组织约束");
  });

  it("formats playbook id with optional first tool", () => {
    expect(formatPlaybookSlot({ retrieved: true, playbook_ids: ["pb-c8d9e0f1"] })).toBe(
      "pb-c8d9e0f1",
    );
    expect(
      formatPlaybookSlot(
        { retrieved: true, playbook_ids: ["pb-c8d9e0f1"] },
        "block_domain",
      ),
    ).toBe("pb-c8d9e0f1 · block_domain");
    expect(formatPlaybookSlot({ retrieved: true })).toBe("无剧本引用");
  });

  it("formats attack techniques without inventing extra hosts", () => {
    expect(
      formatAttackSlot({
        retrieved: true,
        attack_techniques: [
          { technique_id: "T1021", technique_name: "Remote Services" },
        ],
      }),
    ).toBe("T1021 Remote Services");
    expect(formatAttackSlot({ retrieved: true })).toBe("无攻击技术");
  });
});
