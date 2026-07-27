/** WritebackBadge — renders writeback overall status with sync hints (ISSUE-068).

  Logic (per ISSUE-068 spec):
  1. No writeback required  -> "无需写回"
  2. writeback_overall_status === null -> "未写回"
  3. CONFIRMED with readback_verified evidence -> "已同步"
  4. CONFIRMED but evidence is NOT readback_verified -> "已同步（弱证据）"
     (must NOT show plain green success)
  5. CLOSED + external_unsynced OR terminal writeback not confirmed ->
     "本地已关/外部未确认"
  6. Other statuses (pending/sending/partial/failed/conflict/unknown) ->
     mapped label
*/

import { Tooltip, Typography } from "antd";
import {
  CheckCircleFilled,
  CloseCircleFilled,
  ExclamationCircleFilled,
  SyncOutlined,
} from "@ant-design/icons";
import type { EventStatus, WritebackStatus } from "../../types/event";

export interface WritebackBadgeProps {
  status: WritebackStatus | null;
  /** Whether writeback is required at all for this event. */
  required: boolean;
  /** Host-side confirmation evidence string (e.g. "readback_verified"). */
  confirmationEvidence?: string | null;
  /** The local event status — used to detect CLOSED-with-unsynced case. */
  eventStatus: EventStatus;
  /** True if external side has not been synced yet (from SecurityEvent). */
  externalUnsynced?: boolean;
}

const STATUS_LABELS: Record<WritebackStatus, string> = {
  pending: "待发送",
  sending: "发送中",
  accepted: "已接收",
  confirmed: "已同步",
  partial: "部分成功",
  failed: "失败",
  conflict: "冲突",
  unknown: "未知",
};

export default function WritebackBadge({
  status,
  required,
  confirmationEvidence,
  eventStatus,
  externalUnsynced,
}: WritebackBadgeProps) {
  // Case 1: writeback not required.
  if (!required) {
    return (
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        无需写回
      </Typography.Text>
    );
  }

  // Case 5: CLOSED but external side not synced or terminal writeback unconfirmed.
  const terminalWritebackUnconfirmed =
    status !== "confirmed" && eventStatus === "closed";
  if (eventStatus === "closed" && (externalUnsynced || terminalWritebackUnconfirmed)) {
    return (
      <Tooltip title="本地事件已关闭，但外部系统状态尚未同步确认">
        <span style={{ fontSize: 12 }}>
          <ExclamationCircleFilled style={{ color: "#fa8c16" }} />
          <Typography.Text type="warning" style={{ marginLeft: 4 }}>
            本地已关/外部未确认
          </Typography.Text>
        </span>
      </Tooltip>
    );
  }

  // Case 2: no status yet.
  if (status === null || status === undefined) {
    return (
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        未写回
      </Typography.Text>
    );
  }

  const label = STATUS_LABELS[status] ?? status;

  // Case 3 & 4: CONFIRMED — must distinguish weak evidence.
  if (status === "confirmed") {
    const isReadbackVerified = confirmationEvidence === "readback_verified";
    if (isReadbackVerified) {
      return (
        <Tooltip title={`写回已确认（证据：${confirmationEvidence ?? "无"}）`}>
          <span style={{ fontSize: 12, color: "#52c41a" }}>
            <CheckCircleFilled />
            <span style={{ marginLeft: 4 }}>已同步</span>
          </span>
        </Tooltip>
      );
    }
    // Case 4: confirmed but weak evidence — must not show plain green success.
    return (
      <Tooltip
        title={`写回已确认，但证据为「${confirmationEvidence ?? "无"}」非读回验证，属弱证据`}
      >
        <span style={{ fontSize: 12, color: "#faad14" }}>
          <ExclamationCircleFilled />
          <span style={{ marginLeft: 4 }}>已同步（弱证据）</span>
        </span>
      </Tooltip>
    );
  }

  // Failure-ish statuses.
  if (status === "failed" || status === "conflict") {
    return (
      <Tooltip title={`写回状态：${label}`}>
        <span style={{ fontSize: 12, color: "#ff4d4f" }}>
          <CloseCircleFilled />
          <span style={{ marginLeft: 4 }}>{label}</span>
        </span>
      </Tooltip>
    );
  }

  // In-progress / partial.
  return (
    <Tooltip title={`写回状态：${label}`}>
      <span style={{ fontSize: 12, color: "#1677ff" }}>
        <SyncOutlined spin={status === "sending"} />
        <span style={{ marginLeft: 4 }}>{label}</span>
      </span>
    </Tooltip>
  );
}
