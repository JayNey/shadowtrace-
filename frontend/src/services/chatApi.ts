import { apiClient } from "./apiClient";
import type { ChatAnswer, ChatRequest } from "../types/chat";

export function askEventQuestion(eventId: string, request: ChatRequest) {
  return apiClient.post<ChatAnswer>(`/events/${eventId}/chat`, request);
}
