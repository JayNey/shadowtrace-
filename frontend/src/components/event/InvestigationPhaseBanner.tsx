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
        "本事件已完成仅分析，无法从 REPORTING 补发处置方案。对新事件请在发起调查前选择「分析并生成处置方案」。"
      }
      data-testid="analysis-phase-banner"
    />
  );
}
