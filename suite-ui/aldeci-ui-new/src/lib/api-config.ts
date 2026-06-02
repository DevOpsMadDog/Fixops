/**
 * api-config.ts — Environment-based API configuration.
 *
 * Reads VITE_API_URL from the environment, falling back to the page's own
 * origin (same-origin) when not set — NOT a hardcoded localhost. A hardcoded
 * http://localhost:8000 fallback broke every deployed instance (fly/prod): the
 * browser POSTed to localhost:8000, which is CSP-blocked / unreachable. Same-origin
 * matches buildApiUrl() in api.ts and works in dev (Vite proxies /api -> :8000)
 * and in prod (UI + API served from one origin). All API clients import
 * `API_BASE_URL` from here rather than reading import.meta.env directly.
 */

/** Base URL of the ALDECI backend API. */
export const API_BASE_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined)?.trim() ||
  (typeof window !== "undefined" ? window.location.origin : "");

/** Optional static API key (for non-JWT / token-based auth). */
export const API_KEY: string =
  (import.meta.env.VITE_API_KEY as string | undefined)?.trim() || "";

/**
 * Resolve the API key at REQUEST time: build-time VITE_API_KEY if set, else the
 * real logged-in token from localStorage ("aldeci.authToken"). The static API_KEY
 * const above is evaluated once at module load (before login) and is empty in
 * prod/dev, which caused authed pages to send no X-API-Key -> 401. Always prefer
 * getApiKey() over API_KEY for outgoing requests.
 */
export function getApiKey(): string {
  const envKey = (import.meta.env.VITE_API_KEY as string | undefined)?.trim();
  if (envKey) return envKey;
  if (typeof window !== "undefined") {
    return window.localStorage.getItem("aldeci.authToken") ?? "";
  }
  return "";
}

/** Default organisation ID injected as X-Org-ID header. */
export const DEFAULT_ORG_ID: string =
  (import.meta.env.VITE_ORG_ID as string | undefined)?.trim() || "default";

/** Milliseconds to wait before timing out a request (10 s). */
export const REQUEST_TIMEOUT_MS = 10_000;

/** How many times the client will retry on 5xx / network errors. */
export const MAX_RETRIES = 2;

/** Base delay (ms) for exponential back-off between retries. */
export const RETRY_BASE_DELAY_MS = 500;
