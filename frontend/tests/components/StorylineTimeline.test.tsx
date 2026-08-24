import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import StorylineTimeline from "../../src/components/storyline/StorylineTimeline";
import { PHASE_LABELS } from "../../src/components/storyline/constants";
import type {
  AttackStoryline,
  Evidence,
  StorylinePhaseName,
} from "../../src/types/event";

const { mockGetTimeline } = vi.hoisted(() => ({
  mockGetTimeline: vi.fn(),
}));

vi.mock("../../src/services/eventApi", () => ({
  getTimeline: (...args: unknown[]) => mockGetTimeline(...args),
}));

const PHASES = Object.keys(PHASE_LABELS) as StorylinePhaseName[];

const evidence: Evidence[] = [
  {
    evidence_id: "ev-070",
    event_id: "evt-070",
    source: "identity",
    evidence_type: "login",
    description: "原始证据：管理员账户从异常地址登录",
    confidence: 0.94,
    timestamp: "2026-07-27T08:00:00Z",
    observation_fields: { src_ip: "203.0.113.8", account: "admin" },
    mitre_technique: "T1078",
    is_conflicting: false,
  },
];

function makeStoryline(): AttackStoryline {
  return {
    storyline_id: "sty-070",
    event_id: "evt-070",
    narrative_summary: "攻击者使用有效账户进入环境并完成数据外泄。",
    generated_by: "rule",
    phases: PHASES.map((phaseName, index) => ({
      phase_order: index + 1,
      phase_name: phaseName,
      tactic: [
        "Initial Access",
        "Collection",
        "Collection",
        "Exfiltration",
        "Impact",
      ][index],
      narrative: `${PHASE_LABELS[phaseName]}阶段叙事`,
      entries:
        index === 0
          ? [
              {
                timestamp: "2026-07-27T08:00:00Z",
                description: "攻击者使用有效账户登录",
                evidence_id: "ev-070",
                technique_id: "T1078",
                severity_hint: "high",
              },
            ]
          : [],
    })),
  };
}

describe("StorylineTimeline", () => {
  beforeEach(() => {
    mockGetTimeline.mockReset();
  });

  it("renders all five phases, narrative and rule-generation marker", () => {
    render(
      <StorylineTimeline
        storyline={makeStoryline()}
        evidence={evidence}
      />,
    );

    expect(
      screen.getByText("攻击者使用有效账户进入环境并完成数据外泄。"),
    ).toBeInTheDocument();
    expect(screen.getByText("规则生成")).toBeInTheDocument();
    for (const phaseName of PHASES) {
      expect(
        screen.getByTestId(`storyline-phase-${phaseName}`),
      ).toBeInTheDocument();
      expect(screen.getByText(PHASE_LABELS[phaseName])).toBeInTheDocument();
    }
  });

  it("uses empty testids for phases missing from the storyline payload", () => {
    const partial = makeStoryline();
    partial.phases = partial.phases.filter(
      (phase) => phase.phase_name === "initial_access",
    );
    render(<StorylineTimeline storyline={partial} evidence={evidence} />);

    expect(screen.getByTestId("storyline-phase-initial_access")).toBeInTheDocument();
    expect(
      screen.getByTestId("storyline-phase-empty-collection"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("storyline-phase-empty-exfiltration"),
    ).toBeInTheDocument();
  });

  it("expands linked evidence and reveals the ATT&CK technique name", async () => {
    const user = userEvent.setup();
    render(
      <StorylineTimeline
        storyline={makeStoryline()}
        evidence={evidence}
      />,
    );

    const entry = screen.getByTestId("timeline-entry-ev-070");
    await user.click(
      within(entry).getByRole("button", { name: "展开关联证据" }),
    );
    const panel = screen.getByTestId("timeline-evidence-ev-070");
    expect(
      within(panel).getByText("原始证据：管理员账户从异常地址登录"),
    ).toBeInTheDocument();
    expect(within(panel).getByText(/src_ip: 203\.0\.113\.8/)).toBeInTheDocument();
    expect(within(panel).getByText(/account: admin/)).toBeInTheDocument();

    await user.click(
      within(entry).getByRole("button", { name: /查看 T1078 技术名称/ }),
    );
    expect(await screen.findByText("Valid Accounts")).toBeInTheDocument();
  });

  it("does not repeat the timeline sentence when observation fields exist", async () => {
    const user = userEvent.setup();
    const duplicate = "主机 PC-FIN-023 于 2024-06-15 09:13:30 UTC 发生 network_connect：7z.exe";
    const storyline = makeStoryline();
    storyline.phases[0].entries = [
      {
        timestamp: "2024-06-15T09:13:30Z",
        description: duplicate,
        evidence_id: "ev-070",
        technique_id: "T1078",
        severity_hint: "high",
      },
    ];
    render(
      <StorylineTimeline
        storyline={storyline}
        evidence={[
          {
            ...evidence[0],
            description: duplicate,
            related_entities: ["PC-FIN-023", "7z.exe"],
            observation_fields: {
              action: "network_connect",
              process: "7z.exe",
              cmdline: "7z.exe a finance_report.zip",
              dst_ip: "203.0.113.88",
            },
          },
        ]}
      />,
    );

    const entry = screen.getByTestId("timeline-entry-ev-070");
    expect(within(entry).getByText(duplicate)).toBeInTheDocument();
    await user.click(within(entry).getByRole("button", { name: "展开关联证据" }));
    const panel = screen.getByTestId("timeline-evidence-ev-070");
    expect(within(panel).queryByText(duplicate)).not.toBeInTheDocument();
    expect(within(panel).getByText(/cmdline: 7z\.exe a finance_report\.zip/)).toBeInTheDocument();
    expect(within(panel).getByText(/关联实体：PC-FIN-023, 7z\.exe/)).toBeInTheDocument();
  });

  it("falls back to evidence ordered by time when storyline is not ready", () => {
    const later = {
      ...evidence[0],
      evidence_id: "ev-later",
      description: "稍后的证据",
      timestamp: "2026-07-27T09:00:00Z",
    };
    const earlier = {
      ...evidence[0],
      evidence_id: "ev-earlier",
      description: "更早的证据",
      timestamp: "2026-07-27T07:00:00Z",
    };

    render(
      <StorylineTimeline storyline={null} evidence={[later, earlier]} />,
    );

    expect(screen.getByText("故事线未生成")).toBeInTheDocument();
    const rows = screen.getAllByTestId(/^evidence-row-/);
    expect(rows[0]).toHaveAttribute("data-testid", "evidence-row-ev-earlier");
    expect(rows[1]).toHaveAttribute("data-testid", "evidence-row-ev-later");
  });

  it("handles the storyline_not_ready API response as a fallback state", async () => {
    mockGetTimeline.mockRejectedValue({
      response: {
        status: 404,
        data: { error_code: "storyline_not_ready" },
      },
    });

    render(<StorylineTimeline eventId="evt-070" evidence={evidence} />);

    expect(await screen.findByText("故事线未生成")).toBeInTheDocument();
    expect(mockGetTimeline).toHaveBeenCalledWith("evt-070");
    expect(screen.getByTestId("evidence-row-ev-070")).toBeInTheDocument();
  });
});
