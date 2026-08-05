/** Knowledge memory review API client (ISSUE-213). */

import apiClient from "./apiClient";
import type {
  MemoryReviewListResponse,
  MemoryReviewOperationResponse,
  MemoryReviewRejectRequest,
} from "../types/knowledge";

export interface ListMemoryReviewsParams {
  kb_name?: string;
}

export function listMemoryReviews(params?: ListMemoryReviewsParams) {
  return apiClient.get<MemoryReviewListResponse>("/knowledge/reviews", { params });
}

export function promoteMemoryReview(reviewId: string) {
  return apiClient.post<MemoryReviewOperationResponse>(
    `/knowledge/reviews/${encodeURIComponent(reviewId)}/promote`,
    undefined,
    { skipGlobalErrorToast: true },
  );
}

export function rejectMemoryReview(reviewId: string, body: MemoryReviewRejectRequest) {
  return apiClient.post<MemoryReviewOperationResponse>(
    `/knowledge/reviews/${encodeURIComponent(reviewId)}/reject`,
    body,
    { skipGlobalErrorToast: true },
  );
}
