/** Event-overview citation strip: FP / org / playbook / ATT&CK (read persist only). */

import { Space, Tag, Typography } from "antd";
import type { EventContextSnapshot } from "../../types/event";
import {
  formatAttackSlot,
  formatFpSlot,
  formatOrgSlot,
  formatPlaybookSlot,
  isCitationPending,
} from "../../utils/ragCitationStrip";

interface Props {
  snapshot: EventContextSnapshot | null | undefined;
  primaryActionTool?: string;
  onNavigateTab?: (tabKey: string) => void;
}

export default function RagCitationStrip({
  snapshot,
  primaryActionTool,
  onNavigateTab,
}: Props) {
  const citations = snapshot?.rag_citations ?? undefined;
  const pending = isCitationPending(citations);

  if (pending || !citations) {
    return (
      <div data-testid="rag-citation-strip" style={{ marginTop: 16 }}>
        <Typography.Text type="secondary" data-testid="rag-citation-pending">
          检索未完成
        </Typography.Text>
      </div>
    );
  }

  const fpText = formatFpSlot(citations, snapshot?.fp_adjudication?.recommendation);
  const orgText = formatOrgSlot(snapshot?.org_context_matches);
  const playbookText = formatPlaybookSlot(citations, primaryActionTool);
  const attackText = formatAttackSlot(citations);
  const fpHit = Boolean(citations.fp_case_id?.trim());
  const orgHit = orgText !== "无组织约束";
  const playbookHit = Boolean(citations.playbook_ids?.[0]?.trim());
  const attackHit = attackText !== "无攻击技术";

  return (
    <div data-testid="rag-citation-strip" style={{ marginTop: 16 }}>
      <Space wrap size={[8, 8]} align="center">
        {citations.degraded ? (
          <Tag data-testid="rag-citation-degraded">检索降级</Tag>
        ) : null}
        <Slot label="误报对照" testId="rag-citation-fp" hit={fpHit}>
          {fpText}
        </Slot>
        <Slot label="组织约束" testId="rag-citation-org" hit={orgHit}>
          {orgText}
        </Slot>
        <Slot
          label="处置剧本"
          testId="rag-citation-playbook"
          hit={playbookHit}
          onClick={
            playbookHit && onNavigateTab
              ? () => onNavigateTab("actions")
              : undefined
          }
        >
          {playbookText}
        </Slot>
        <Slot
          label="攻击技术"
          testId="rag-citation-attack"
          hit={attackHit}
          onClick={
            attackHit && onNavigateTab ? () => onNavigateTab("report") : undefined
          }
        >
          {attackText}
        </Slot>
      </Space>
    </div>
  );
}

function Slot({
  label,
  testId,
  hit,
  onClick,
  children,
}: {
  label: string;
  testId: string;
  hit: boolean;
  onClick?: () => void;
  children: string;
}) {
  return (
    <Space size={4} data-testid={testId}>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {label}
      </Typography.Text>
      <Tag
        color={hit ? "blue" : "default"}
        style={onClick ? { cursor: "pointer" } : undefined}
        onClick={onClick}
        data-testid={`${testId}-value`}
      >
        {children}
      </Tag>
    </Space>
  );
}
