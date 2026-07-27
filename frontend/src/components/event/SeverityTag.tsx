/** SeverityTag — renders severity level with color (ISSUE-068). */

import { Tag } from "antd";
import type { Severity } from "../../types/event";
import { getSeverityConfig } from "./constants";

export interface SeverityTagProps {
  severity: Severity;
}

export default function SeverityTag({ severity }: SeverityTagProps) {
  const cfg = getSeverityConfig(severity);
  return <Tag color={cfg.color}>{cfg.label}</Tag>;
}
