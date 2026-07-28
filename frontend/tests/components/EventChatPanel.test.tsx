import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { MemoryRouter, useLocation } from "react-router-dom";
import EventChatPanel from "../../src/components/chat/EventChatPanel";

const mockAskEventQuestion = vi.fn();

vi.mock("../../src/services/chatApi", () => ({
  askEventQuestion: (...args: unknown[]) => mockAskEventQuestion(...args),
}));

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location-hash">{location.hash}</span>;
}

function renderPanel() {
  return render(
    <AntApp>
      <MemoryRouter initialEntries={["/events/evt-076#chat"]}>
        <LocationProbe />
        <EventChatPanel eventId="evt-076" />
      </MemoryRouter>
    </AntApp>,
  );
}

describe("EventChatPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders user and assistant messages with grounded references", async () => {
    const user = userEvent.setup();
    mockAskEventQuestion.mockResolvedValue({
      data: {
        answer: "风险评分 88，异常登录证据支持高危结论。",
        references: [
          { ref_type: "evidence", ref_id: "evd-event-qa-001" },
        ],
      },
    });
    renderPanel();

    await user.type(screen.getByLabelText("事件问题"), "为什么判定为高危");
    await user.click(screen.getByRole("button", { name: /发送/ }));

    expect(await screen.findByText("为什么判定为高危")).toBeInTheDocument();
    expect(
      await screen.findByText("风险评分 88，异常登录证据支持高危结论。"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /证据 evd-event-qa-001/ }),
    ).toBeInTheDocument();
    expect(mockAskEventQuestion).toHaveBeenCalledWith("evt-076", {
      question: "为什么判定为高危",
      history: [],
    });
  });

  it("jumps evidence and trace references to their event detail tabs", async () => {
    const user = userEvent.setup();
    mockAskEventQuestion.mockResolvedValue({
      data: {
        answer: "请核验引用。",
        references: [
          { ref_type: "evidence", ref_id: "evd-1" },
          { ref_type: "trace", ref_id: "trace-1" },
        ],
      },
    });
    renderPanel();

    await user.type(screen.getByLabelText("事件问题"), "有哪些依据");
    await user.click(screen.getByRole("button", { name: /发送/ }));
    await user.click(
      await screen.findByRole("button", { name: /证据 evd-1/ }),
    );
    expect(screen.getByTestId("location-hash")).toHaveTextContent("#evidence");

    await user.click(screen.getByRole("button", { name: /轨迹 trace-1/ }));
    expect(screen.getByTestId("location-hash")).toHaveTextContent("#audit");
  });

  it("sends at most ten prior messages as history", async () => {
    const user = userEvent.setup();
    mockAskEventQuestion.mockResolvedValue({
      data: { answer: "收到", references: [] },
    });
    renderPanel();

    for (let index = 0; index < 6; index += 1) {
      await user.type(screen.getByLabelText("事件问题"), `问题 ${index}`);
      await user.click(screen.getByRole("button", { name: /发送/ }));
      await screen.findAllByText("收到");
    }

    const lastCall =
      mockAskEventQuestion.mock.calls[mockAskEventQuestion.mock.calls.length - 1];
    const lastRequest = lastCall?.[1];
    expect(lastRequest.history).toHaveLength(10);
    expect(lastRequest.history[0]).toEqual({ role: "user", content: "问题 0" });
    expect(lastRequest.history[lastRequest.history.length - 1]).toEqual({
      role: "assistant",
      content: "收到",
    });
  });

  it("degrades locally when event Q&A is unavailable", async () => {
    const user = userEvent.setup();
    mockAskEventQuestion.mockRejectedValue({
      response: { status: 503, data: { error_code: "qa_unavailable" } },
    });
    renderPanel();

    await user.type(screen.getByLabelText("事件问题"), "为什么高危");
    await user.click(screen.getByRole("button", { name: /发送/ }));

    expect(await screen.findByText("问答暂不可用")).toBeInTheDocument();
    expect(
      screen.getByText("事件详情和其他研判功能不受影响，请稍后重试。"),
    ).toBeInTheDocument();
    expect(screen.getByText("为什么高危")).toBeInTheDocument();
  });

  it("supports Enter to send and Shift+Enter to keep composing", async () => {
    const user = userEvent.setup();
    mockAskEventQuestion.mockResolvedValue({
      data: { answer: "已回答", references: [] },
    });
    renderPanel();

    const input = screen.getByLabelText("事件问题");
    await user.type(input, "第一行{shift>}{enter}{/shift}第二行");
    expect(input).toHaveValue("第一行\n第二行");
    await user.type(input, "{enter}");

    await waitFor(() => {
      expect(mockAskEventQuestion).toHaveBeenCalledWith("evt-076", {
        question: "第一行\n第二行",
        history: [],
      });
    });
  });
});
