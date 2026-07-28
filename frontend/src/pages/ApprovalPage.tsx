/** ApprovalCenterPage — approval queue with cards and real-time updates (ISSUE-073). */

import { useEffect, useMemo, useState } from "react";
import { Typography, Space, Empty, Spin, Alert, message } from "antd";
import { CheckCircleOutlined } from "@ant-design/icons";
import {
  useApprovalStore,
  loadRevisionProgress,
  revisionProgressKey,
  isActionTimedOut,
  type ApprovalDecisionBody,
  type RevisionProgress,
} from "../stores/approvalStore";
import ApprovalCard from "../components/approval/ApprovalCard";
import ApprovalActionModal from "../components/approval/ApprovalActionModal";
import type { Action } from "../types/action";

const { Title, Text } = Typography;

interface ModalState {
  open: boolean;
  actionId: string | null;
  mode: "approve" | "reject";
}

export default function ApprovalPage() {
  const {
    pendingApprovals,
    loading,
    error,
    approvalDeadlines,
    loadPendingApprovals,
    refreshEventIds,
    approve,
    reject,
  } = useApprovalStore();

  const [modal, setModal] = useState<ModalState>({ open: false, actionId: null, mode: "approve" });
  const [submitting, setSubmitting] = useState(false);
  const [revisionProgress, setRevisionProgress] = useState<Map<string, RevisionProgress>>(
    new Map(),
  );

  useEffect(() => {
    void refreshEventIds().then((ids) => loadPendingApprovals(ids));
  }, [loadPendingApprovals, refreshEventIds]);

  useEffect(() => {
    if (pendingApprovals.length === 0) {
      setRevisionProgress(new Map());
      return;
    }
    let cancelled = false;
    void loadRevisionProgress(pendingApprovals).then((map) => {
      if (!cancelled) setRevisionProgress(map);
    });
    return () => {
      cancelled = true;
    };
  }, [pendingApprovals]);

  const groupedByEvent = useMemo(() => {
    const groups = new Map<string, Action[]>();
    for (const action of pendingApprovals) {
      const list = groups.get(action.event_id) ?? [];
      list.push(action);
      groups.set(action.event_id, list);
    }
    return [...groups.entries()].map(([eventId, actions]) => ({ eventId, actions }));
  }, [pendingApprovals]);

  const handleApprove = (actionId: string) => {
    setModal({ open: true, actionId, mode: "approve" });
  };

  const handleReject = (actionId: string) => {
    setModal({ open: true, actionId, mode: "reject" });
  };

  const handleConfirm = async (actionId: string, body: ApprovalDecisionBody) => {
    const action = pendingApprovals.find((a) => a.action_id === actionId);
    const eventId = action?.event_id;
    const remainingBefore = eventId
      ? pendingApprovals.filter((a) => a.event_id === eventId).length
      : 0;
    setSubmitting(true);
    try {
      if (modal.mode === "approve") {
        await approve(actionId, body);
      } else {
        if (!body.comment?.trim()) {
          message.error("拒绝必须填写原因");
          return;
        }
        await reject(actionId, body);
      }
      setModal({ open: false, actionId: null, mode: "approve" });
      if (eventId && remainingBefore > 1) {
        message.info("本事件仍有待审批动作，计划尚未全部决出。");
      }
    } catch {
      // API error toast already shown by apiClient interceptor
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = () => {
    setModal({ open: false, actionId: null, mode: "approve" });
  };

  return (
    <div style={{ padding: 24 }}>
      <Title level={3}>
        <CheckCircleOutlined style={{ marginRight: 8 }} />
        审批中心
      </Title>

      <Text type="secondary">
        需审批的处置动作。同一事件的审批计划需全部决出后方可进入执行。
        {pendingApprovals.length > 0 && (
          <span style={{ marginLeft: 16 }}>共 {pendingApprovals.length} 个待审批动作</span>
        )}
      </Text>

      {error && (
        <Alert message={error} type="error" showIcon style={{ marginBottom: 16 }} closable />
      )}

      <Spin spinning={loading}>
        {pendingApprovals.length === 0 && !loading ? (
          <Empty description="暂无待审批动作" style={{ marginTop: 48 }} />
        ) : (
          <Space direction="vertical" size="large" style={{ width: "100%", marginTop: 16 }}>
            {groupedByEvent.map(({ eventId, actions }) => {
              const sample = actions[0];
              const rev = sample.plan_revision ?? 0;
              const progress = revisionProgress.get(revisionProgressKey(eventId, rev));
              return (
                <Space key={eventId} direction="vertical" size="middle" style={{ width: "100%" }}>
                  <Alert
                    type="info"
                    showIcon
                    message={
                      progress
                        ? `事件 ${eventId} · revision ${rev} · 本 revision 已决出 ${progress.decided}/${progress.total}`
                        : `事件 ${eventId} · revision ${rev}`
                    }
                    description="同一计划须全部审批完（含 deferred）后才进入执行。"
                  />
                  {actions.map((action) => (
                    <ApprovalCard
                      key={action.action_id}
                      action={action}
                      deadline={approvalDeadlines[action.action_id]}
                      timedOut={isActionTimedOut(
                        action,
                        approvalDeadlines[action.action_id],
                      )}
                      onApprove={handleApprove}
                      onReject={handleReject}
                    />
                  ))}
                </Space>
              );
            })}
          </Space>
        )}
      </Spin>

      <ApprovalActionModal
        open={modal.open}
        actionId={modal.actionId}
        mode={modal.mode}
        loading={submitting}
        onConfirm={handleConfirm}
        onCancel={handleCancel}
      />
    </div>
  );
}
