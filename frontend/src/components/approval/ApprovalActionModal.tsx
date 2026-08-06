/** ApprovalActionModal — approve / reject dialog (ISSUE-073 / ISSUE-207). */

import { Modal, Form, Input } from "antd";
import {
  currentApproverDisplay,
  newDecisionId,
  type ApprovalDecisionBody,
} from "../../stores/approvalStore";

const { TextArea } = Input;

interface ApprovalActionModalProps {
  open: boolean;
  actionId: string | null;
  mode: "approve" | "reject";
  loading: boolean;
  onConfirm: (actionId: string, body: ApprovalDecisionBody) => void | Promise<void>;
  onCancel: () => void;
}

export default function ApprovalActionModal({
  open,
  actionId,
  mode,
  loading,
  onConfirm,
  onCancel,
}: ApprovalActionModalProps) {
  const [form] = Form.useForm<{ comment: string }>();

  const title = mode === "approve" ? "批准动作" : "拒绝动作";
  const okText = mode === "approve" ? "批准" : "拒绝";
  const isReject = mode === "reject";

  const handleOk = async () => {
    if (!actionId) return;
    try {
      const values = await form.validateFields();
      const comment = values.comment?.trim();
      // Await the caller so a failed API leave the reject reason intact (ISSUE-207).
      await onConfirm(actionId, {
        decision_id: newDecisionId(),
        comment: comment || undefined,
      });
      form.resetFields();
    } catch {
      // Validation failed or onConfirm rejected — keep modal + form values.
    }
  };

  return (
    <Modal
      title={title}
      open={open}
      onOk={handleOk}
      onCancel={() => {
        form.resetFields();
        onCancel();
      }}
      confirmLoading={loading}
      okText={okText}
      okButtonProps={{ danger: isReject }}
      cancelText="取消"
      destroyOnHidden
    >
      <Form form={form} layout="vertical">
        <Form.Item label="当前审批者">
          <Input value={currentApproverDisplay()} disabled />
        </Form.Item>
        {isReject && (
          <Form.Item
            name="comment"
            label="拒绝原因"
            rules={[{ required: true, message: "拒绝必须填写原因" }]}
          >
            <TextArea rows={3} placeholder="请填写拒绝原因" />
          </Form.Item>
        )}
        {!isReject && (
          <Form.Item name="comment" label="审批备注（可选）">
            <TextArea rows={2} placeholder="可选备注" />
          </Form.Item>
        )}
      </Form>
    </Modal>
  );
}
