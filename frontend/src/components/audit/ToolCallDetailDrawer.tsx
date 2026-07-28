import { Alert, Descriptions, Divider, Drawer, Space, Tag, Typography } from "antd";
import type { ToolCallItem } from "../../types/trace";
import JsonTree from "./JsonTree";

function formatTime(value: string | null): string {
  return value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "暂无数据";
}

export default function ToolCallDetailDrawer({
  toolCall,
  open,
  onClose,
}: {
  toolCall: ToolCallItem | null;
  open: boolean;
  onClose: () => void;
}) {
  return (
    <Drawer
      title={toolCall ? `工具调用详情 · ${toolCall.tool_name}` : "工具调用详情"}
      width={680}
      open={open}
      onClose={onClose}
      destroyOnClose
    >
      {toolCall && (
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          {toolCall.truncated && (
            <Alert
              type="warning"
              showIcon
              message="部分内容已截断"
              description="审计存储已对超长字段限长；页面仅展示安全投影与完整性哈希。"
            />
          )}
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="call_id" span={2}>
              <Typography.Text copyable code>
                {toolCall.call_id}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="event_id">{toolCall.event_id}</Descriptions.Item>
            <Descriptions.Item label="action_id">
              {toolCall.action_id ?? "暂无数据"}
            </Descriptions.Item>
            <Descriptions.Item label="provider">
              {toolCall.provider ?? "暂无数据"}
            </Descriptions.Item>
            <Descriptions.Item label="execution_owner">
              {toolCall.execution_owner ?? "暂无数据"}
            </Descriptions.Item>
            <Descriptions.Item label="状态">
              <Tag color={toolCall.status === "success" ? "blue" : "default"}>
                {toolCall.status}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="重试次数">
              {toolCall.retry_count}
            </Descriptions.Item>
            <Descriptions.Item label="耗时">
              {toolCall.duration_ms === null ? "暂无数据" : `${toolCall.duration_ms} ms`}
            </Descriptions.Item>
            <Descriptions.Item label="开始时间">
              {formatTime(toolCall.started_at)}
            </Descriptions.Item>
            <Descriptions.Item label="完成时间">
              {formatTime(toolCall.completed_at)}
            </Descriptions.Item>
            <Descriptions.Item label="disposition_id">
              {toolCall.disposition_id ?? "暂无数据"}
            </Descriptions.Item>
            <Descriptions.Item label="writeback_status">
              {toolCall.writeback_status ?? "暂无数据"}
            </Descriptions.Item>
          </Descriptions>

          {toolCall.error_detail && (
            <Alert
              type="error"
              showIcon
              message="错误明细"
              description={
                <Typography.Text style={{ whiteSpace: "pre-wrap" }}>
                  {toolCall.error_detail}
                </Typography.Text>
              }
            />
          )}

          <Divider orientation="left">参数（字段级脱敏）</Divider>
          <JsonTree value={toolCall.parameters} />
          <Divider orientation="left">结果（字段级脱敏）</Divider>
          <JsonTree value={toolCall.result} />
          <Typography.Text type="secondary">
            秘密字段、完整 raw payload、系统提示词和隐藏推理不会在审计视图中显示。
          </Typography.Text>
        </Space>
      )}
    </Drawer>
  );
}
