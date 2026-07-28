import type { DecisionTraceEntryType } from "../../types/trace";

export const TRACE_TYPE_LABELS: Record<DecisionTraceEntryType, string> = {
  agent_execution: "Agent 执行",
  tool_call: "工具调用",
  llm_call: "模型调用",
  state_transition: "状态转移",
  approval: "审批",
  action_execution: "动作执行",
  disposition: "处置命令",
  writeback: "外部同步",
};

export const TRACE_TYPE_COLORS: Record<DecisionTraceEntryType, string> = {
  agent_execution: "blue",
  tool_call: "cyan",
  llm_call: "purple",
  state_transition: "geekblue",
  approval: "gold",
  action_execution: "orange",
  disposition: "magenta",
  writeback: "green",
};

export const ALL_TRACE_TYPES = Object.keys(
  TRACE_TYPE_LABELS,
) as DecisionTraceEntryType[];

export const TOOL_STATUS_OPTIONS = [
  { value: "running", label: "执行中" },
  { value: "success", label: "成功" },
  { value: "failed", label: "失败" },
  { value: "timeout", label: "超时" },
  { value: "unsupported", label: "不支持" },
];
