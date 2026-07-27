/** WritebackBadge unit tests — evidence tiers and CLOSED unsynced hints (ISSUE-068). */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import WritebackBadge from "../../src/components/event/WritebackBadge";

describe("WritebackBadge", () => {
  it("shows 无需写回 when writeback is not required", () => {
    render(
      <WritebackBadge
        status={null}
        required={false}
        eventStatus="new"
      />,
    );
    expect(screen.getByText("无需写回")).toBeInTheDocument();
  });

  it("shows 未写回 when required but status is null", () => {
    render(
      <WritebackBadge
        status={null}
        required={true}
        eventStatus="analyzing"
      />,
    );
    expect(screen.getByText("未写回")).toBeInTheDocument();
  });

  it("shows green 已同步 for confirmed + readback_verified", () => {
    render(
      <WritebackBadge
        status="confirmed"
        required={true}
        confirmationEvidence="readback_verified"
        eventStatus="closed"
      />,
    );
    expect(screen.getByText("已同步")).toBeInTheDocument();
    expect(screen.queryByText("已同步（弱证据）")).not.toBeInTheDocument();
  });

  it("shows 已同步（弱证据） for confirmed without readback evidence", () => {
    render(
      <WritebackBadge
        status="confirmed"
        required={true}
        confirmationEvidence={null}
        eventStatus="closed"
      />,
    );
    expect(screen.getByText("已同步（弱证据）")).toBeInTheDocument();
  });

  it("shows 本地已关/外部未确认 when CLOSED and externalUnsynced", () => {
    render(
      <WritebackBadge
        status="pending"
        required={true}
        eventStatus="closed"
        externalUnsynced={true}
      />,
    );
    expect(screen.getByText("本地已关/外部未确认")).toBeInTheDocument();
  });

  it("shows 本地已关/外部未确认 when CLOSED and writeback not confirmed", () => {
    render(
      <WritebackBadge
        status="failed"
        required={true}
        eventStatus="closed"
      />,
    );
    expect(screen.getByText("本地已关/外部未确认")).toBeInTheDocument();
  });
});
