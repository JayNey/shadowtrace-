/** ApprovalActionModal tests (ISSUE-073 / ISSUE-207). */

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import ApprovalActionModal from "../../src/components/approval/ApprovalActionModal";

vi.mock("../../src/stores/approvalStore", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/stores/approvalStore")>();
  return {
    ...actual,
    currentApproverDisplay: () => "审批员张三",
    newDecisionId: () => "dec-test-001",
  };
});

describe("ApprovalActionModal", () => {
  it("shows read-only approver and passes approve comment", async () => {
    const onConfirm = vi.fn();
    render(
      <ApprovalActionModal
        open
        actionId="act-1"
        mode="approve"
        loading={false}
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );

    expect(screen.getByDisplayValue("审批员张三")).toBeDefined();

    fireEvent.change(screen.getByPlaceholderText("可选备注"), {
      target: { value: "LGTM" },
    });
    fireEvent.click(screen.getByRole("button", { name: /批\s*准/ }));

    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledWith("act-1", {
        decision_id: "dec-test-001",
        comment: "LGTM",
      });
    });
  });

  it("requires reject comment", async () => {
    const onConfirm = vi.fn();
    render(
      <ApprovalActionModal
        open
        actionId="act-1"
        mode="reject"
        loading={false}
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /拒\s*绝/ }));
    expect(await screen.findByText("拒绝必须填写原因")).toBeDefined();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("keeps reject comment when onConfirm rejects", async () => {
    const onConfirm = vi.fn().mockRejectedValue(new Error("forbidden"));
    render(
      <ApprovalActionModal
        open
        actionId="act-1"
        mode="reject"
        loading={false}
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText("请填写拒绝原因"), {
      target: { value: "证据不足" },
    });
    fireEvent.click(screen.getByRole("button", { name: /拒\s*绝/ }));

    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalled();
    });
    expect(screen.getByDisplayValue("证据不足")).toBeDefined();
  });

  it("clears comment after successful onConfirm", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    render(
      <ApprovalActionModal
        open
        actionId="act-1"
        mode="approve"
        loading={false}
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText("可选备注"), {
      target: { value: "LGTM" },
    });
    fireEvent.click(screen.getByRole("button", { name: /批\s*准/ }));

    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(screen.queryByDisplayValue("LGTM")).toBeNull();
    });
  });
});
