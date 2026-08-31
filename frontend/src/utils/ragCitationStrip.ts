/** Copy and state for the event-overview RAG citation strip. */

import type { RagCitations } from "../types/event";

export type OrgMatchView = { kind?: string; matched_value?: string };

export function isCitationPending(
  citations: RagCitations | null | undefined,
): boolean {
  return citations == null || citations.retrieved !== true;
}

export function formatFpSlot(
  citations: RagCitations,
  recommendation?: string | null,
): string {
  const caseId = citations.fp_case_id?.trim();
  if (caseId) {
    const rec = recommendation?.trim();
    return rec ? `命中 ${caseId} · ${rec}` : `命中 ${caseId}`;
  }
  return "未命中误报卡";
}

export function formatOrgSlot(matches: OrgMatchView[] | null | undefined): string {
  const labels = (matches ?? [])
    .slice(0, 3)
    .map((match) => [match.kind, match.matched_value].filter(Boolean).join(" "))
    .filter(Boolean);
  return labels.length > 0 ? labels.join("；") : "无组织约束";
}

export function formatPlaybookSlot(
  citations: RagCitations,
  toolName?: string | null,
): string {
  const playbookId = citations.playbook_ids?.[0]?.trim();
  if (!playbookId) return "无剧本引用";
  const tool = toolName?.trim();
  return tool ? `${playbookId} · ${tool}` : playbookId;
}

export function formatAttackSlot(citations: RagCitations): string {
  const labels = (citations.attack_techniques ?? [])
    .slice(0, 3)
    .map((item) =>
      [item.technique_id, item.technique_name].filter(Boolean).join(" "),
    )
    .filter(Boolean);
  return labels.length > 0 ? labels.join("；") : "无攻击技术";
}
