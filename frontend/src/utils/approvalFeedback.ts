/** Approval decision feedback helpers (ISSUE-207). */

import { message } from "antd";
import type { ActionOperationResponse } from "../types/action";

function resumeFailureDetail(result: ActionOperationResponse): string {
  const detail = result.message?.trim();
  if (!detail) return "";
  // Skip generic echoes of the HTTP status field.
  if (detail === result.status) return "";
  return `：${detail}`;
}

/**
 * Surface resume_status / degraded to the operator after approve/reject.
 * resume "failed" must not pretend the investigation continued.
 */
export function showResumeFeedback(
  actionId: string,
  mode: "approve" | "reject",
  result?: ActionOperationResponse,
): void {
  const verb = mode === "approve" ? "已批准" : "已拒绝";
  if (!result) {
    message.success(`动作 ${actionId} ${verb}`);
    return;
  }
  const degradedSuffix = result.degraded ? "（降级模式运行）" : "";
  switch (result.resume_status) {
    case "ok":
      message.success(`动作 ${actionId} ${verb}，调查流程已继续${degradedSuffix}`);
      break;
    case "skipped":
      message.info(`动作 ${actionId} ${verb}（当前无待继续的调查流程）${degradedSuffix}`);
      break;
    case "failed":
      message.error(
        `动作 ${actionId} ${verb}，但调查流程继续失败，请查看事件状态${resumeFailureDetail(result)}${degradedSuffix}`,
      );
      break;
    default:
      message.success(`动作 ${actionId} ${verb}${degradedSuffix}`);
  }
}
