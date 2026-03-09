import axios from "axios";

const _api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  headers: {
    "X-API-Key": import.meta.env.VITE_API_KEY || "",
    "Content-Type": "application/json",
  },
});

/**
 * Simple fetch wrapper using axios instance.
 * Returns the response data directly.
 */
export async function apiClient(url: string, opts?: { method?: string; body?: string }): Promise<Record<string, unknown>> {
  const method = (opts?.method || "GET").toLowerCase() as "get" | "post" | "put" | "delete" | "patch";
  const res = await _api.request({
    url,
    method,
    data: opts?.body ? JSON.parse(opts.body) : undefined,
  });
  return res.data;
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
    if (Array.isArray(obj.verifications)) return obj.verifications;
    if (Array.isArray(obj.bundles)) return obj.bundles;
    if (Array.isArray(obj.findings)) return obj.findings;
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
