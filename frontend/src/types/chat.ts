export type ChatRole = "user" | "assistant";
export type ChatReferenceType = "evidence" | "trace" | "report";

export interface ChatHistoryItem {
  role: ChatRole;
  content: string;
}

export interface ChatReference {
  ref_type: ChatReferenceType;
  ref_id: string;
}

export interface ChatRequest {
  question: string;
  history: ChatHistoryItem[];
}

export interface ChatAnswer {
  answer: string;
  references: ChatReference[];
}
