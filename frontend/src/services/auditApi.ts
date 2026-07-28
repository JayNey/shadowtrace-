/** Tool audit and decision trajectory endpoints (ISSUE-072). */

import apiClient from "./apiClient";
import type {
  DecisionTraceResponse,
  ToolCallsResponse,
  TrajectoryReport,
} from "../types/trace";

export interface ToolCallListParams {
  page?: number;
  page_size?: number;
  tool_name?: string;
  status?: string;
}

export function listToolCalls(params?: ToolCallListParams) {
  return apiClient.get<ToolCallsResponse>("/tool-calls", { params });
}

export function getEventToolCalls(eventId: string, params?: ToolCallListParams) {
  return apiClient.get<ToolCallsResponse>(`/events/${eventId}/tool-calls`, {
    params,
  });
}

export function getDecisionTrace(
  eventId: string,
  params?: { page?: number; page_size?: number },
) {
  return apiClient.get<DecisionTraceResponse>(
    `/events/${eventId}/decision-trace`,
    { params },
  );
}

export function getTrajectory(eventId: string) {
  return apiClient.get<TrajectoryReport>(`/events/${eventId}/trajectory`);
}
