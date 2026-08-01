import { Alert } from "antd";
import type { EventDetailResponse } from "../../types/event";

interface Props {
  detail: EventDetailResponse;
}

export default function InvestigationPhaseBanner({ detail }: Props) {
  const phase = detail.response_phase_state;
  if (phase !== "analysis_complete_deferred") {
    return null;
  }

  return (
    <Alert
      type="warning"
      showIcon
      message="分析已完成，处置方案未生成"
      description={
        detail.phase_message ??
        "当前为仅分析路径。安全处置动作尚未生成；如需生成处置方案并进入审批，请在事件 NEW 状态选择「分析并生成处置方案」发起调查。"
      }
      data-testid="analysis-phase-banner"
    />
  );
}
