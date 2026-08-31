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

/** Operator / demo default: decision chain only. Other types stay one click away. */
export const DEFAULT_TRACE_TYPES: DecisionTraceEntryType[] = ["agent_execution"];

export const AGENT_NAME_LABELS: Record<string, string> = {
  triage_agent: "分诊",
  TriageAgent: "分诊",
  risk_agent: "风险评估",
  RiskAgent: "风险评估",
  evidence_agent: "证据收集",
  EvidenceAgent: "证据收集",
  planner_agent: "计划生成",
  PlannerAgent: "计划生成",
  rag_agent: "知识检索",
  RAGAgent: "知识检索",
  graph_agent: "图谱构建",
  GraphAgent: "图谱构建",
  super_agent: "编排",
  SuperAgent: "编排",
  memory_agent: "记忆沉淀",
  MemoryAgent: "记忆沉淀",
  response_agent: "响应方案",
  ResponseAgent: "响应方案",
  verify_agent: "效果验证",
  VerifyAgent: "效果验证",
  report_agent: "报告生成",
  ReportAgent: "报告生成",
};

export const TOOL_STATUS_OPTIONS = [
  { value: "running", label: "执行中" },
  { value: "success", label: "成功" },
  { value: "failed", label: "失败" },
  { value: "timeout", label: "超时" },
  { value: "unsupported", label: "不支持" },
];
