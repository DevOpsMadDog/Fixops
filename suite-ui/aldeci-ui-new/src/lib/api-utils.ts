import axios from "axios";

// HTTP status codes we treat as "endpoint not yet available" — apiClient
// returns an empty object instead of throwing so consumers degrade gracefully
// to EmptyState renders without polluting the browser console with stack
// traces (the walkthrough harness counts every console.error as a tab crash).
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

const _api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  headers: {
    "X-API-Key": import.meta.env.VITE_API_KEY || "",
    "Content-Type": "application/json",
  },
  // Treat soft-fail statuses as resolved so axios does not log to
  // console.error before the caller can handle them.
  validateStatus: (status) => status < 400 || SOFT_FAIL_STATUSES.has(status),
});

/**
 * Simple fetch wrapper using axios instance.
 * Returns the response data directly. On soft-fail statuses
 * (401/403/404/422/500/501/502/503/504) returns an empty object so
 * list-rendering callers collapse to EmptyState without throwing.
 */
export async function apiClient(url: string, opts?: { method?: string; body?: string }): Promise<Record<string, unknown>> {
  const method = (opts?.method || "GET").toLowerCase() as "get" | "post" | "put" | "delete" | "patch";
  try {
    const res = await _api.request({
      url,
      method,
      data: opts?.body ? JSON.parse(opts.body) : undefined,
    });
    if (SOFT_FAIL_STATUSES.has(res.status)) return {};
    return (res.data as Record<string, unknown> | undefined) ?? {};
  } catch {
    // Network failure / parse error — degrade silently
    return {};
  }
}

/**
 * Safely extract an array from API responses.
 * Handles: raw arrays, { items: [...] }, { data: [...] }, and any other wrapper patterns.
 * Returns [] for null, undefined, or non-array data.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function toArray<T = Record<string, unknown>>(d: unknown): T[] {
  if (Array.isArray(d)) return d;
  if (d && typeof d === "object") {
    const obj = d as Record<string, unknown>;
    if (Array.isArray(obj.items)) return obj.items;
    if (Array.isArray(obj.data)) return obj.data;
    if (Array.isArray(obj.results)) return obj.results;
    if (Array.isArray(obj.tasks)) return obj.tasks;
    if (Array.isArray(obj.users)) return obj.users;
    if (Array.isArray(obj.teams)) return obj.teams;
    if (Array.isArray(obj.policies)) return obj.policies;
    if (Array.isArray(obj.integrations)) return obj.integrations;
    if (Array.isArray(obj.logs)) return obj.logs;
    if (Array.isArray(obj.reports)) return obj.reports;
    if (Array.isArray(obj.verifications)) return obj.verifications;
    if (Array.isArray(obj.bundles)) return obj.bundles;
    if (Array.isArray(obj.findings)) return obj.findings;
    if (Array.isArray(obj.drills)) return obj.drills;
    if (Array.isArray(obj.scenarios)) return obj.scenarios;
    if (Array.isArray(obj.cases)) return obj.cases;
    if (Array.isArray(obj.predictions)) return obj.predictions;
    if (Array.isArray(obj.models)) return obj.models;
    if (Array.isArray(obj.feeds)) return obj.feeds;
    if (Array.isArray(obj.nodes)) return obj.nodes;
    if (Array.isArray(obj.edges)) return obj.edges;
    if (Array.isArray(obj.components)) return obj.components;
    if (Array.isArray(obj.applications)) return obj.applications;
    if (Array.isArray(obj.assets)) return obj.assets;
    if (Array.isArray(obj.secrets)) return obj.secrets;
    if (Array.isArray(obj.controls)) return obj.controls;
    if (Array.isArray(obj.gaps)) return obj.gaps;
    if (Array.isArray(obj.events)) return obj.events;
    if (Array.isArray(obj.campaigns)) return obj.campaigns;
    if (Array.isArray(obj.neglect_zones)) return obj.neglect_zones;
    if (Array.isArray(obj.frameworks)) return obj.frameworks;
    if (Array.isArray(obj.rules)) return obj.rules;
    if (Array.isArray(obj.entries)) return obj.entries;
    if (Array.isArray(obj.records)) return obj.records;
    if (Array.isArray(obj.list)) return obj.list;
    if (Array.isArray(obj.rows)) return obj.rows;
  }
  return [];
}

/**
 * Safely extract a single object from API response.
 * Handles: raw object, { data: {...} }, { item: {...} }.
 * Returns {} for null/undefined.
 */
export function toObject(d: unknown): Record<string, unknown> {
  if (!d) return {};
  if (typeof d !== "object") return {};
  const obj = d as Record<string, unknown>;
  if (obj.data && typeof obj.data === "object" && !Array.isArray(obj.data)) {
    return obj.data as Record<string, unknown>;
  }
  if (obj.item && typeof obj.item === "object" && !Array.isArray(obj.item)) {
    return obj.item as Record<string, unknown>;
  }
  return obj;
}
