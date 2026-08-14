/** Per-action writeback lamp — splits obligation vs applicability (ISSUE-331). */

import { Tooltip, Typography, theme } from "antd";
import {
  CheckCircleFilled,
  CloseCircleFilled,
  ExclamationCircleFilled,
  MinusCircleOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import type { ActionWritebackInput } from "../../utils/actionWritebackDisplay";
import {
  resolveActionWritebackDisplay,
  type ActionWritebackDisplayTone,
} from "../../utils/actionWritebackDisplay";

export interface ActionWritebackStatusProps extends ActionWritebackInput {
  "data-testid"?: string;
}

function ToneIcon({ tone }: { tone: ActionWritebackDisplayTone }) {
  if (tone === "success") return <CheckCircleFilled />;
  if (tone === "error") return <CloseCircleFilled />;
  if (tone === "warning") return <ExclamationCircleFilled />;
  if (tone === "info") return <SyncOutlined />;
  return <MinusCircleOutlined />;
}

export default function ActionWritebackStatus({
  writeback_required,
  writeback_applicable,
  writeback_status,
  "data-testid": testId,
}: ActionWritebackStatusProps) {
  const { token } = theme.useToken();
  const toneColors: Record<ActionWritebackDisplayTone, string> = {
    neutral: token.colorTextSecondary,
    success: token.colorSuccess,
    warning: token.colorWarning,
    error: token.colorError,
    info: token.colorInfo,
  };
  const display = resolveActionWritebackDisplay({
    writeback_required,
    writeback_applicable,
    writeback_status,
  });
  const color = toneColors[display.tone];

  return (
    <Tooltip title={display.tooltip}>
      <span data-testid={testId} style={{ fontSize: 12, color }}>
        <ToneIcon tone={display.tone} />
        <Typography.Text style={{ marginLeft: 4, color, fontSize: 12 }}>
          {display.label}
        </Typography.Text>
      </span>
    </Tooltip>
  );
}
