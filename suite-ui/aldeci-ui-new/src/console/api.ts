/**
 * The console's only door to the API.
 *
 * No login screen. The key comes from configuration, not from a form — this
 * build is for demonstration and single-tenant operation, where an auth wall
 * between the operator and their own console buys nothing and costs a step.
 *
 * Two rules this module exists to enforce:
 *
 * 1. A failed call NEVER degrades into fabricated data. It returns an error the
 *    screen must render as an error. Every prior generation of this UI grew
 *    `?? MOCK_DATA` fallbacks that turned an outage into a plausible-looking
 *    dashboard, which is worse than a blank one because nobody investigates it.
 * 2. Empty is reported as EMPTY, not as zero. "No findings yet" and "0 findings"
 *    look identical on screen and mean completely different things — one is an
 *    onboarding step, the other is a clean bill of health.
 */

/**
 * `??` falls back on null/undefined only — never on an empty string. A .env with
 * `VITE_API_KEY=` therefore yields "" and every call 401s, while the code reads
 * as though it has a default. Same shape as the request models that defaulted
 * org_id to "default" and made the credential-derived value unreachable: a
 * present-but-empty value defeating a fallback that looks correct.
 *
 * Trim and test for content, not for presence.
 */
function envOr(value: unknown, fallback: string): string {
  const s = typeof value === "string" ? value.trim() : "";
  return s || fallback;
}

const API_BASE = envOr(
  import.meta.env.VITE_API_BASE_URL ?? import.meta.env.VITE_API_URL,
  "http://localhost:8000",
);
const API_KEY = envOr(import.meta.env.VITE_API_KEY, "uat-token");

export type LoadState = "loading" | "data" | "empty" | "error";

export interface Result<T> {
  state: LoadState;
  data: T | null;
  /** Present only when state === "error". Shown to the user verbatim. */
  error: string | null;
  /** Which endpoint produced this, so a screen can say where its numbers came from. */
  source: string;
}

function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    for (const key of ["total", "count", "total_findings"]) {
      const n = record[key];
      if (typeof n === "number") return n === 0;
    }
    const values = Object.values(record);
    if (values.length === 0) return true;
    return values.every((v) => isEmpty(v));
  }
  if (typeof value === "number") return value === 0;
  if (typeof value === "string") return value.trim() === "";
  return false;
}

export async function apiGet<T = unknown>(path: string): Promise<Result<T>> {
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      headers: { "X-API-Key": API_KEY },
    });

    if (!response.ok) {
      // The API distinguishes "this resource has no data yet" from "this URL is
      // wrong", and so must we — the difference is a next action versus a bug.
      let detail = `HTTP ${response.status}`;
      try {
        const body = await response.json();
        if (body?.detail) detail = String(body.detail);
      } catch {
        /* non-JSON error body; the status is all we have */
      }
      return { state: "error", data: null, error: detail, source: path };
    }

    const data = (await response.json()) as T;
    return {
      state: isEmpty(data) ? "empty" : "data",
      data,
      error: null,
      source: path,
    };
  } catch (err) {
    const message =
      err instanceof TypeError
        ? `Could not reach the API at ${API_BASE}. Is it running?`
        : String(err);
    return { state: "error", data: null, error: message, source: path };
  }
}

export async function apiPost<T = unknown>(path: string, body: unknown): Promise<Result<T>> {
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = text;
    }
    if (!response.ok) {
      const detail =
        parsed && typeof parsed === "object" && "detail" in (parsed as Record<string, unknown>)
          ? String((parsed as Record<string, unknown>).detail)
          : `HTTP ${response.status}`;
      return { state: "error", data: null, error: detail, source: path };
    }
    return { state: "data", data: parsed as T, error: null, source: path };
  } catch (err) {
    return { state: "error", data: null, error: String(err), source: path };
  }
}

export async function uploadScan<T = unknown>(file: File, scannerType: string): Promise<Result<T>> {
  const form = new FormData();
  form.append("file", file);
  form.append("scanner_type", scannerType);
  try {
    const response = await fetch(`${API_BASE}/api/v1/scanner-ingest/upload`, {
      method: "POST",
      headers: { "X-API-Key": API_KEY },
      body: form,
    });
    const data = await response.json();
    if (!response.ok) {
      return { state: "error", data: null, error: data?.detail ?? `HTTP ${response.status}`, source: "upload" };
    }
    return { state: "data", data: data as T, error: null, source: "upload" };
  } catch (err) {
    return { state: "error", data: null, error: String(err), source: "upload" };
  }
}

export { API_BASE };
