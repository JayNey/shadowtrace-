/** Structured outstanding side-effect list for event detail / close diagnosis (ISSUE-323). */

import { Alert, Descriptions, Space, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import type {
  EventDetailResponse,
  OutstandingSideEffectView,
  SideEffectConvergenceProjection,
} from "../../types/event";
import {
  hasVisibleOutstandingSideEffects,
  isSideEffectProjectionDegraded,
  sideEffectPolicyLabel,
  sideEffectReasonLabel,
  sideEffectScopeLabel,
} from "../../utils/sideEffectLabels";

type SideEffectProjectionSource = SideEffectConvergenceProjection | EventDetailResponse;

interface Props {
  projection: SideEffectProjectionSource;
  /** When set, action_id cells link to the actions tab. */
  onNavigateActionsTab?: () => void;
}

function scopeTagColor(scope: OutstandingSideEffectView["scope"]): string {
  return scope === "gate_applicable" ? "volcano" : "gold";
}

function buildColumns(
  onNavigateActionsTab?: () => void,
): ColumnsType<OutstandingSideEffectView> {
  return [
    {
      title: "动作 ID",
      dataIndex: "action_id",
      key: "action_id",
      render: (actionId: string) =>
        onNavigateActionsTab ? (
          <Typography.Link
            data-testid={`outstanding-action-link-${actionId}`}
            onClick={onNavigateActionsTab}
          >
            {actionId}
          </Typography.Link>
        ) : (
          <Typography.Text code>{actionId}</Typography.Text>
        ),
    },
    {
      title: "Scope",
      dataIndex: "scope",
      key: "scope",
      render: (scope: OutstandingSideEffectView["scope"]) => (
        <Tag color={scopeTagColor(scope)} data-testid={`outstanding-scope-${scope}`}>
          {sideEffectScopeLabel(scope)}
        </Tag>
      ),
    },
    {
      title: "阻断原因",
      dataIndex: "blocking_reason",
      key: "blocking_reason",
      render: (reason: OutstandingSideEffectView["blocking_reason"]) => (
        <Typography.Text data-testid={`outstanding-reason-${reason ?? "none"}`}>
          {sideEffectReasonLabel(reason)}
        </Typography.Text>
      ),
    },
    {
      title: "收敛策略",
      dataIndex: "convergence_policy",
      key: "convergence_policy",
      render: (policy: OutstandingSideEffectView["convergence_policy"]) =>
        sideEffectPolicyLabel(policy),
    },
    {
      title: "动作状态",
      dataIndex: "action_status",
      key: "action_status",
    },
    {
      title: "作业 / Outbox",
      key: "delivery",
      render: (_value, row) => {
        const parts: string[] = [];
        if (row.job_status) {
          parts.push(`job=${row.job_status}`);
        }
        if (row.outbox_delivery_status) {
          parts.push(`outbox=${row.outbox_delivery_status}`);
        }
        if (row.outbox_writeback_status) {
          parts.push(`wb=${row.outbox_writeback_status}`);
        }
        return parts.length > 0 ? parts.join(" · ") : "—";
      },
    },
    {
      title: "计划版本",
      dataIndex: "plan_revision",
      key: "plan_revision",
      width: 96,
    },
  ];
}

export default function OutstandingSideEffectsPanel({
  projection,
  onNavigateActionsTab,
}: Props) {
  const gateCount = projection.gate_applicable_outstanding_count ?? 0;
  const totalCount = projection.outstanding_side_effect_count ?? 0;
  const items = projection.outstanding_side_effects ?? [];
  const degraded = isSideEffectProjectionDegraded(gateCount, totalCount);

  if (!hasVisibleOutstandingSideEffects(projection)) {
    return null;
  }

  return (
    <Space direction="vertical" size={12} style={{ width: "100%" }} data-testid="outstanding-side-effects-panel">
      <Descriptions size="small" column={{ xs: 1, sm: 3 }} title="副作用收敛">
        <Descriptions.Item label="门禁待收敛">
          {degraded ? "不可用" : gateCount}
        </Descriptions.Item>
        <Descriptions.Item label="Outstanding 总数">
          {degraded ? "不可用" : totalCount}
        </Descriptions.Item>
        <Descriptions.Item label="后台 pending">
          {projection.background_side_effects_pending ? "是" : "否"}
        </Descriptions.Item>
      </Descriptions>

      {degraded && (
        <Alert
          type="warning"
          showIcon
          message="副作用投影降级"
          description="gate_applicable_outstanding_count 或 outstanding_side_effect_count 为 -1，明细列表可能为空；请刷新或查看后端日志。"
          data-testid="outstanding-side-effects-degraded"
        />
      )}

      {projection.background_side_effects_pending && gateCount === 0 && !degraded && (
        <Alert
          type="info"
          showIcon
          message="存在后台/游离副作用"
          description="当前无门禁阻断项，但仍有 detached 副作用在收敛中。"
          data-testid="outstanding-side-effects-background"
        />
      )}

      {items.length > 0 && (
        <Table<OutstandingSideEffectView>
          size="small"
          rowKey="action_id"
          pagination={false}
          dataSource={items}
          columns={buildColumns(onNavigateActionsTab)}
          data-testid="outstanding-side-effects-table"
        />
      )}
    </Space>
  );
}
