/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_SOCKET_URL?: string;
  readonly VITE_DEV_AUTH_TOKEN?: string;
  readonly VITE_AUTH_SUBJECT?: string;
  readonly VITE_AUTH_ROLES?: string;
  readonly VITE_APPROVER_DISPLAY?: string;
  readonly VITE_EVENT_CHAT_ENABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
