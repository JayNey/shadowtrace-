/** KnowledgeReviewPage tests (ISSUE-213). */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { MemoryRouter } from "react-router-dom";
import KnowledgeReviewPage from "../../src/pages/KnowledgeReviewPage";
import { ApiError } from "../../src/services/apiClient";
import type { MemoryReviewItem } from "../../src/types/knowledge";

const mockListMemoryReviews = vi.fn();
const mockPromoteMemoryReview = vi.fn();
const mockRejectMemoryReview = vi.fn();
const mockCanPromote = vi.fn(() => true);

vi.mock("../../src/services/knowledgeApi", () => ({
  listMemoryReviews: (...args: unknown[]) => mockListMemoryReviews(...args),
  promoteMemoryReview: (...args: unknown[]) => mockPromoteMemoryReview(...args),
  rejectMemoryReview: (...args: unknown[]) => mockRejectMemoryReview(...args),
}));

vi.mock("../../src/config/auth", () => ({
  canPromoteKnowledgeReviews: () => mockCanPromote(),
}));

vi.mock("../../src/services/apiClient", async () => {
  const actual = await vi.importActual<
    typeof import("../../src/services/apiClient")
  >("../../src/services/apiClient");
  return {
    ...actual,
    showApiErrorToast: () => {},
    setApiErrorToastHandler: () => {},
  };
});

function makeReview(overrides: Partial<MemoryReviewItem> = {}): MemoryReviewItem {
  return {
    review_id: "rev-profile-1",
    kb_name: "entity_profile",
    candidate_type: "profile",
    payload: {
      event_id: "evt-profile-1",
      entity_type: "account",
      entity_value: "svc-analytics-47",
      behavior_tags: ["event_type:data_exfiltration"],
    },
    status: "pending",
    confidence: 0.77,
    created_at: "2026-08-05T10:00:00Z",
    ...overrides,
  };
}

function renderPage() {
  return render(
    <AntApp>
      <MemoryRouter>
        <KnowledgeReviewPage />
      </MemoryRouter>
    </AntApp>,
  );
}

describe("KnowledgeReviewPage", () => {
  beforeEach(() => {
    // resetAllMocks clears once-queues so prior tests cannot leak mockResolvedValueOnce.
    vi.resetAllMocks();
    mockCanPromote.mockReturnValue(true);
    mockListMemoryReviews.mockResolvedValue({ data: { total: 0, items: [] } });
    mockPromoteMemoryReview.mockResolvedValue({
      data: { review_id: "rev-profile-1", status: "promoted", message: "ok" },
    });
    mockRejectMemoryReview.mockResolvedValue({
      data: { review_id: "rev-profile-1", status: "rejected", message: "ok" },
    });
  });

  it("renders title and timing guidance", async () => {
    renderPage();
    expect(screen.getByText("知识审核")).toBeInTheDocument();
    const note = await screen.findByTestId("knowledge-review-timing-note");
    expect(note).toHaveTextContent("ISSUE-208");
    expect(note).toHaveTextContent("fp_rule / history_case");
  });

  it("shows empty state without pretending feature is missing", async () => {
    renderPage();
    expect(await screen.findByText("当前暂无 pending 候选")).toBeInTheDocument();
    expect(screen.getByText(/不代表本页未实现/)).toBeInTheDocument();
  });

  it("lists profile candidate_type and summary", async () => {
    mockListMemoryReviews.mockResolvedValue({
      data: {
        total: 1,
        items: [makeReview()],
      },
    });
    renderPage();

    expect(await screen.findByTestId("candidate-type-profile")).toBeInTheDocument();
    expect(screen.getByText("entity_profile")).toBeInTheDocument();
    expect(screen.getByText("evt-profile-1")).toBeInTheDocument();
    expect(screen.getByText(/account:svc-analytics-47/)).toBeInTheDocument();
    expect(screen.getByText(/当前均为 profile，符合 CLOSED 前预期/)).toBeInTheDocument();
  });

  it("lists closed-loop candidate types with footer hint", async () => {
    mockListMemoryReviews.mockResolvedValue({
      data: {
        total: 2,
        items: [
          makeReview(),
          makeReview({
            review_id: "rev-fp-1",
            kb_name: "fp_case_kb",
            candidate_type: "fp_rule",
            payload: {
              source_event_id: "evt-closed-1",
              rule_summary: "Approved backup activity",
              alert_signature: "backup-login",
            },
          }),
        ],
      },
    });
    renderPage();

    expect(await screen.findByTestId("candidate-type-fp_rule")).toBeInTheDocument();
    expect(
      screen.getByText(/含须 CLOSED 后入队的 fp_rule \/ history_case/),
    ).toBeInTheDocument();
  });

  it("promotes a review and reloads the list", async () => {
    const user = userEvent.setup();
    mockListMemoryReviews
      .mockResolvedValueOnce({
        data: { total: 1, items: [makeReview()] },
      })
      .mockResolvedValueOnce({
        data: { total: 0, items: [] },
      });

    renderPage();
    await screen.findByTestId("promote-rev-profile-1");
    await user.click(screen.getByTestId("promote-rev-profile-1"));
    await user.click(await screen.findByRole("button", { name: "入 库" }));

    await waitFor(() =>
      expect(mockPromoteMemoryReview).toHaveBeenCalledWith("rev-profile-1"),
    );
    await waitFor(() => expect(mockListMemoryReviews).toHaveBeenCalledTimes(2));
  });

  it("rejects a review, closes the modal, and reloads", async () => {
    const user = userEvent.setup();
    mockListMemoryReviews
      .mockResolvedValueOnce({
        data: { total: 1, items: [makeReview()] },
      })
      .mockResolvedValueOnce({
        data: { total: 0, items: [] },
      });

    renderPage();
    await screen.findByTestId("reject-rev-profile-1");
    await user.click(screen.getByTestId("reject-rev-profile-1"));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/rev-profile-1/)).toBeInTheDocument();
    await user.type(screen.getByLabelText("拒绝原因"), "not useful for RAG");
    await user.click(screen.getByRole("button", { name: "确认拒绝" }));

    await waitFor(() =>
      expect(mockRejectMemoryReview).toHaveBeenCalledWith("rev-profile-1", {
        reason: "not useful for RAG",
      }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(mockListMemoryReviews).toHaveBeenCalledTimes(2));
  });

  it("keeps reject modal open and shows error on 409 conflict", async () => {
    const user = userEvent.setup();
    mockListMemoryReviews.mockResolvedValue({
      data: { total: 1, items: [makeReview()] },
    });
    mockRejectMemoryReview.mockRejectedValue(
      new ApiError({
        error_code: "memory_review_conflict",
        error_message: "memory review is already demoted",
      }),
    );

    renderPage();
    await user.click(await screen.findByTestId("reject-rev-profile-1"));
    await user.type(screen.getByLabelText("拒绝原因"), "already decided elsewhere");
    await user.click(screen.getByRole("button", { name: "确认拒绝" }));

    await waitFor(() => expect(mockRejectMemoryReview).toHaveBeenCalled());
    expect(await screen.findByText(/already demoted|memory_review_conflict/)).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(mockListMemoryReviews).toHaveBeenCalledTimes(1);
  });

  it("keeps list row on promote memory_review_conflict", async () => {
    const user = userEvent.setup();
    mockListMemoryReviews.mockResolvedValue({
      data: { total: 1, items: [makeReview()] },
    });
    mockPromoteMemoryReview.mockRejectedValue(
      new ApiError({
        error_code: "memory_review_conflict",
        error_message: "memory review is already demoted",
      }),
    );

    renderPage();
    await user.click(await screen.findByTestId("promote-rev-profile-1"));
    await user.click(await screen.findByRole("button", { name: "入 库" }));

    await waitFor(() => expect(mockPromoteMemoryReview).toHaveBeenCalled());
    expect(screen.getByTestId("promote-rev-profile-1")).toBeInTheDocument();
    expect(mockListMemoryReviews).toHaveBeenCalledTimes(1);
  });

  it("shows load error and retries", async () => {
    const user = userEvent.setup();
    mockListMemoryReviews
      .mockRejectedValueOnce(new Error("network down"))
      .mockResolvedValueOnce({ data: { total: 0, items: [] } });

    renderPage();
    expect(await screen.findByText("待审核列表加载失败")).toBeInTheDocument();
    await user.click(screen.getByTestId("knowledge-review-retry"));
    await waitFor(() => expect(mockListMemoryReviews).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("当前暂无 pending 候选")).toBeInTheDocument();
  });

  it("revokes actions after promote returns forbidden", async () => {
    const user = userEvent.setup();
    mockListMemoryReviews.mockResolvedValue({
      data: { total: 1, items: [makeReview()] },
    });
    mockPromoteMemoryReview.mockRejectedValue(
      new ApiError({
        error_code: "forbidden",
        error_message: "requires one of roles: approver",
      }),
    );

    renderPage();
    await user.click(await screen.findByTestId("promote-rev-profile-1"));
    await user.click(await screen.findByRole("button", { name: "入 库" }));

    await waitFor(() =>
      expect(screen.queryByTestId("promote-rev-profile-1")).not.toBeInTheDocument(),
    );
    expect(screen.getByText(/仅可查看待审核列表/)).toBeInTheDocument();
  });

  it("hides promote/reject actions for analyst-only role", async () => {
    mockCanPromote.mockReturnValue(false);
    mockListMemoryReviews.mockResolvedValue({
      data: { total: 1, items: [makeReview()] },
    });
    renderPage();

    await screen.findByTestId("candidate-type-profile");
    expect(screen.queryByTestId("promote-rev-profile-1")).not.toBeInTheDocument();
    expect(screen.getByText(/仅可查看待审核列表/)).toBeInTheDocument();
  });
});
