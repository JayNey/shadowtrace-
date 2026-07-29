/** ApprovalCard — single pending-approval action (ISSUE-073). */

import { memo, useEffect, useState } from "react";
import { Card, Tag, Typography, Space, theme } from "antd";
import { ClockCircleOutlined, WarningOutlined } from "@ant-design/icons";
import type { Action } from "../../types/action";
import { formatDispositionPreview, APPROVAL_TIMEOUT_FALLBACK_MS } from "../../stores/approvalStore";

const { Text } = Typography;
const { useToken } = theme;

interface ApprovalCardProps {
  action: Action;
  deadline?: string;
  timedOut: boolean;
  onApprove: (actionId: string) => void;
  onReject: (actionId: string) => void;
}

function formatCountdown(deadline: string): string {
  const ms = new Date(deadline).getTime() - Date.now();
  if (ms <= 0) return "已超时";
  const totalSec = Math.floor(ms / 1000);
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  return `${min}:${sec.toString().padStart(2, "0")}`;
}

function effectiveDeadline(action: Action, socketDeadline?: string): string | undefined {
  if (socketDeadline) return socketDeadline;
  if (!action.updated_at) return undefined;
  return new Date(
    new Date(action.updated_at).getTime() + APPROVAL_TIMEOUT_FALLBACK_MS,
  ).toISOString();
}

function ApprovalCard({
  action,
  deadline,
  timedOut,
  onApprove,
  onReject,
}: ApprovalCardProps) {
  const { token } = useToken();
  const resolvedDeadline = effectiveDeadline(action, deadline);
  const [countdown, setCountdown] = useState(() =>
    resolvedDeadline ? formatCountdown(resolvedDeadline) : "",
  );

  useEffect(() => {
    if (!resolvedDeadline) return;
    const tick = () => setCountdown(formatCountdown(resolvedDeadline));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [resolvedDeadline]);

  const isDeferred = action.execution_phase === "post_verify";
  const levelColors: Record<string, string> = {
    l0: token.colorSuccess,
    l1: token.colorSuccess,
    l2: token.colorWarning,
    l3: token.colorWarning,
    l4: token.colorError,
    l5: token.colorError,
  };

  const cardStyle: React.CSSProperties = timedOut
    ? { opacity: 0.5, borderColor: token.colorBorderSecondary }
    : {};

  return (
    <Card
      size="small"
      style={cardStyle}
      data-testid={`approval-card-${action.action_id}`}
      title={
        <Space wrap>
          <Text strong>{action.action_name || action.tool_name}</Text>
          <Tag color={levelColors[action.action_level] || "default"}>
            {action.action_level.toUpperCase()}
          </Tag>
          {isDeferred && (
            <Tag color="purple">
              <WarningOutlined /> POST_VERIFY
            </Tag>
          )}
          {resolvedDeadline && !timedOut && (
            <Tag icon={<ClockCircleOutlined />} color="processing">
              剩余 {countdown}
            </Tag>
          )}
          {timedOut && (
            <Tag color="default">
              <ClockCircleOutlined /> 已超时
            </Tag>
          )}
        </Space>
      }
      extra={
        !timedOut ? (
          <Space>
            <a onClick={() => onApprove(action.action_id)}>批准</a>
            <a style={{ color: token.colorError }} onClick={() => onReject(action.action_id)}>
              拒绝
            </a>
          </Space>
        ) : (
          <Text type="secondary">超时（以后端判定为准）</Text>
        )
      }
    >
      <Space direction="vertical" size="small" style={{ width: "100%" }}>
        {action.reason && (
          <div>
            <Text type="secondary">理由：</Text>
            <Text>{action.reason}</Text>
          </div>
        )}
        <div>
          <Text type="secondary">目标：</Text>
          <Text>{action.target || "—"}</Text>
          <Text type="secondary" style={{ marginLeft: 16 }}>
            类型：
          </Text>
          <Text>{action.target_type || "—"}</Text>
        </div>
        <div>
          <Text type="secondary">执行者：</Text>
          <Text>{action.execution_owner || "—"}</Text>
          <Text type="secondary" style={{ marginLeft: 16 }}>
            阶段：
          </Text>
          <Text>{action.execution_phase}</Text>
        </div>
        <div>
          <Text type="secondary">XDR 来源对象：</Text>
          <Text code>{formatDispositionPreview(action.disposition_source_ref)}</Text>
        </div>
        {isDeferred && (
          <Text type="warning">
            <WarningOutlined /> 效果验证后激活，须先批准。分析内容仅本地保存，不写回。
          </Text>
        )}
        <div>
          <Text type="secondary">事件：</Text>
          <Text code>{action.event_id}</Text>
          <Text type="secondary" style={{ marginLeft: 16 }}>
            动作：
          </Text>
          <Text code>{action.action_id}</Text>
        </div>
      </Space>
    </Card>
  );
}

export default memo(ApprovalCard);
