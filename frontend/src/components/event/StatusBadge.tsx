/** StatusBadge — renders event status with localized label and color (ISSUE-068).

  Renders the "本地状态" (local status). Uses a custom colored dot so that
  cyan (CONTAINED) renders distinctly from the in-progress blue statuses —
  Ant Design's <Badge status> has no cyan variant, so we render a styled
  dot + text ourselves to honor the color convention exactly.
*/

import { Tooltip, Typography } from "antd";
import type { EventStatus } from "../../types/event";
import { getStatusConfig, type StatusColorKey } from "./constants";

export interface StatusBadgeProps {
  status: EventStatus;
  /** Optional suffix text appended after the label (e.g. "本地已关/外部未确认"). */
  suffix?: string;
}

/** Map logical color key to an actual CSS color (covers cyan). */
const DOT_COLORS: Record<StatusColorKey, string> = {
  default: "#8c8c8c", // gray
  processing: "#1677ff", // blue
  warning: "#fa8c16", // orange
  success: "#52c41a", // green
  error: "#ff4d4f", // red
  cyan: "#13c2c2", // cyan (distinct from blue)
};

export default function StatusBadge({ status, suffix }: StatusBadgeProps) {
  const cfg = getStatusConfig(status);
  const dotColor = DOT_COLORS[cfg.color] ?? DOT_COLORS.default;

  return (
    <Tooltip title={`本地状态：${cfg.label}`}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
        <span
          style={{
            display: "inline-block",
            width: 6,
            height: 6,
            borderRadius: "50%",
            background: dotColor,
            flexShrink: 0,
          }}
        />
        <span style={{ fontSize: 13 }}>{cfg.label}</span>
        {suffix && (
          <Typography.Text type="warning" style={{ marginLeft: 4, fontSize: 12 }}>
            {suffix}
          </Typography.Text>
        )}
      </span>
    </Tooltip>
  );
}
