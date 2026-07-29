/** Typed Axios client with unified error handling (ISSUE-067). */

import axios, { AxiosError } from "axios";
import { message } from "antd";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";
const DEV_AUTH_TOKEN = import.meta.env.VITE_DEV_AUTH_TOKEN ?? "";

export interface ApiErrorPayload {
  error_code: string;
  error_message: string;
  details?: Record<string, unknown>;
}

export class ApiError extends Error {
  error_code: string;
  details?: Record<string, unknown>;

  constructor(payload: ApiErrorPayload) {
    super(payload.error_message);
    this.name = "ApiError";
    this.error_code = payload.error_code;
    this.details = payload.details;
  }
}

let toastHandler: (errorMessage: string) => void = (errorMessage) => {
  if (import.meta.env.MODE !== "test") {
    message.error(errorMessage);
  }
};

export function showApiErrorToast(errorMessage: string): void {
  toastHandler(errorMessage);
}

export function setApiErrorToastHandler(handler: (errorMessage: string) => void): void {
  toastHandler = handler;
}

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 30_000,
  headers: { "Content-Type": "application/json" },
});

apiClient.interceptors.request.use((config) => {
  // Local / Compose mock stage: map a fixed bearer token to Principal via
  // DEV_AUTH_TOKENS. Production rejects DEV_AUTH_TOKENS outright.
  if (DEV_AUTH_TOKEN && !config.headers?.Authorization) {
    config.headers.set("Authorization", `Bearer ${DEV_AUTH_TOKEN}`);
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiErrorPayload>) => {
    let apiError: ApiError;
    if (error.response?.data) {
      const { error_code, error_message, details } = error.response.data;
      apiError = new ApiError({
        error_code: error_code ?? "unknown_error",
        error_message: error_message ?? error.message,
        details,
      });
    } else if (error.code === "ECONNABORTED") {
      apiError = new ApiError({ error_code: "timeout", error_message: "Request timed out" });
    } else {
      apiError = new ApiError({
        error_code: "network_error",
        error_message: error.message,
      });
    }
    showApiErrorToast(apiError.message);
    throw apiError;
  },
);

export default apiClient;
