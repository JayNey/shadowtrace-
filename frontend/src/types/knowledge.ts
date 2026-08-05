/** Knowledge memory review API types (ISSUE-213 / OpenAPI MemoryReview*). */

export type MemoryReviewCandidateType = "fp_rule" | "history_case" | "profile";

export type MemoryReviewStatus = "pending" | "promoted" | "demoted";

export interface MemoryReviewItem {
  review_id: string;
  kb_name: string;
  candidate_type: MemoryReviewCandidateType;
  payload: Record<string, unknown>;
  status: MemoryReviewStatus;
  confidence: number;
  created_at: string;
  decided_at?: string | null;
  operator?: string | null;
}

export interface MemoryReviewListResponse {
  total: number;
  items: MemoryReviewItem[];
}

export interface MemoryReviewOperationResponse {
  review_id: string;
  status: "promoted" | "demoted";
  message: string;
}

export interface MemoryReviewRejectRequest {
  reason: string;
}
