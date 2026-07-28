/** Frontend feature flags aligned with backend runtime toggles. */

export function isEventChatEnabled(): boolean {
  return import.meta.env.VITE_EVENT_CHAT_ENABLED !== "false";
}
