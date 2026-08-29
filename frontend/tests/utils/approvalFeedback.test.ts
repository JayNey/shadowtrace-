/** approvalFeedback tests (ISSUE-207). */

import { afterEach, describe, expect, it, vi } from "vitest";
import { message } from "antd";
import { showResumeFeedback } from "../../src/utils/approvalFeedback";

describe("showResumeFeedback", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows ok resume with degraded suffix", () => {
    const success = vi.spyOn(message, "success").mockImplementation(() => undefined as never);
    showResumeFeedback("act-1", "approve", {
      action_id: "act-1",
      status: "approved",
      message: "approved",
      resume_status: "ok",
      degraded: true,
    });
    expect(success).toHaveBeenCalledWith(
      "动作 act-1 已批准，调查流程已继续（降级模式运行）",
    );
  });

  it("includes backend message detail when resume failed", () => {
    const error = vi.spyOn(message, "error").mockImplementation(() => undefined as never);
    showResumeFeedback("act-2", "approve", {
      action_id: "act-2",
      status: "approved",
      message: "graph resume timeout",
      resume_status: "failed",
      degraded: false,
    });
    expect(error).toHaveBeenCalledWith(
      "动作 act-2 已批准，但调查流程继续失败，请查看事件状态：graph resume timeout",
    );
  });

  it("skips generic message echo equal to status", () => {
    const error = vi.spyOn(message, "error").mockImplementation(() => undefined as never);
    showResumeFeedback("act-3", "reject", {
      action_id: "act-3",
      status: "rejected",
      message: "rejected",
      resume_status: "failed",
      degraded: true,
    });
    expect(error).toHaveBeenCalledWith(
      "动作 act-3 已拒绝，但调查流程继续失败，请查看事件状态（降级模式运行）",
    );
  });

  it("warns when resume is deferred", () => {
    const warning = vi.spyOn(message, "warning").mockImplementation(() => undefined as never);
    showResumeFeedback("act-4", "approve", {
      action_id: "act-4",
      status: "approved",
      message: "approved",
      resume_status: "deferred",
      degraded: false,
    });
    expect(warning).toHaveBeenCalledWith(
      "动作 act-4 已批准，调查流程暂未继续（租约占用，将自动重试）",
    );
  });
});
