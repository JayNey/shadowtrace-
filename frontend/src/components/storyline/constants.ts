import type { StorylinePhaseName } from "../../types/event";

export const PHASE_LABELS: Record<StorylinePhaseName, string> = {
  initial_access: "初始访问",
  collection: "数据收集",
  staging: "数据集结",
  exfiltration: "数据外泄",
  post_action: "后续动作",
};

export const PHASE_COLORS: Record<StorylinePhaseName, string> = {
  initial_access: "#1677ff",
  collection: "#d4b106",
  staging: "#fa8c16",
  exfiltration: "#f5222d",
  post_action: "#722ed1",
};
