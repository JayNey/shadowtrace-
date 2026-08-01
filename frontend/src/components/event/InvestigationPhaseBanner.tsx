import { Alert, Button, Space } from "antd";
import type { EventDetailResponse } from "../../types/event";

interface Props {
  detail: EventDetailResponse;
  onStartResponse?: () => void;
  startingResponse?: boolean;
}

export default function InvestigationPhaseBanner({
  detail,
  onStartResponse,
  startingResponse = false,
}: Props) {
  const phase = detail.response_phase_state;
  if (phase !== "analysis_complete_deferred") {
    return null;
  }

  const showCta =
    detail.next_recommended_action === "start_response_execution" &&
    detail.full_loop_available !== false;

  return (
    <Alert
      type="warning"
      showIcon
      message="分析已完成，处置方案未生成"
      description={
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          <span>
            {detail.phase_message ??
              "当前为仅分析路径。安全处置动作尚未生成；可点击下方按钮生成处置方案并进入审批。"}
          </span>
          {showCta ? (
            <Button
              type="primary"
              onClick={onStartResponse}
              loading={startingResponse}
              data-testid="start-response-execution-cta"
            >
              生成处置方案并提交审批
            </Button>
          ) : null}
        </Space>
      }
      data-testid="analysis-phase-banner"
    />
  );
}
