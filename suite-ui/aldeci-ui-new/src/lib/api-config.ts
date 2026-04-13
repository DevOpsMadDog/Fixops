/**
 * api-config.ts — Environment-based API configuration.
 *
 * Reads VITE_API_URL from the environment, falling back to
 * http://localhost:8000 when not set.  All API client instances
 * should import `API_BASE_URL` from here rather than reading
 * import.meta.env directly.
 */

/** Base URL of the ALDECI backend API. */
export const API_BASE_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined)?.trim() ||
  "http://localhost:8000";

/** Optional static API key (for non-JWT / token-based auth). */
export const API_KEY: string =
  (import.meta.env.VITE_API_KEY as string | undefined)?.trim() || "";

/** Default organisation ID injected as X-Org-ID header. */
export const DEFAULT_ORG_ID: string =
  (import.meta.env.VITE_ORG_ID as string | undefined)?.trim() || "default";

/** Milliseconds to wait before timing out a request (10 s). */
export const REQUEST_TIMEOUT_MS = 10_000;

/** How many times the client will retry on 5xx / network errors. */
export const MAX_RETRIES = 2;

/** Base delay (ms) for exponential back-off between retries. */
export const RETRY_BASE_DELAY_MS = 500;
