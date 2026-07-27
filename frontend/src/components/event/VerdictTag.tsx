/** VerdictTag — renders final verdict with color (ISSUE-068). */

import { Tag } from "antd";
import type { FinalVerdict } from "../../types/event";
import { getVerdictConfig } from "./constants";

export interface VerdictTagProps {
  verdict: FinalVerdict;
}

export default function VerdictTag({ verdict }: VerdictTagProps) {
  const cfg = getVerdictConfig(verdict);
  return <Tag color={cfg.color}>{cfg.label}</Tag>;
}
