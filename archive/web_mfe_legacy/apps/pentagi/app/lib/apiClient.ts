/**
 * API Client for FixOps Pentagi
 * 
 * This module provides a centralized way to make API calls to the FixOps backend.
 * It handles authentication, base URL configuration, and error handling.
 */

const API_BASE = process.env.NEXT_PUBLIC_FIXOPS_API_URL ?? 'http://localhost:8000';
const API_TOKEN = process.env.NEXT_PUBLIC_FIXOPS_API_TOKEN ?? 'demo-token';

export interface ApiError {
  status: number;
  message: string;
  detail?: string;
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    'X-API-Key': API_TOKEN,
    ...(init?.headers || {}),
  };

  try {
    const res = await fetch(url, { ...init, headers });
    
    if (!res.ok) {
      const errorBody = await res.text();
      let detail: string | undefined;
      try {
        const parsed = JSON.parse(errorBody);
        detail = parsed.detail || parsed.message;
      } catch {
        detail = errorBody;
      }
      throw {
        status: res.status,
        message: `API error ${res.status}`,
        detail,
      } as ApiError;
    }
    
    return res.json();
  } catch (error) {
    if ((error as ApiError).status) {
      throw error;
    }
    throw {
      status: 0,
      message: 'Network error',
      detail: (error as Error).message,
    } as ApiError;
  }
}

// Pentagi API types
export interface PentestRequest {
  id: string;
  name: string;
  target: string;
  type: string;
  scope: string;
  status: string;
  severity_found: string | null;
  findings_count: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  requested_by: string;
}

export interface PentestFinding {
  id: string;
  request_id: string;
  title: string;
  severity: string;
  cvss_score: number;
  description: string;
  remediation: string;
  status: string;
}

export interface PentestStats {
  total: number;
  pending: number;
  in_progress: number;
  completed: number;
  total_findings: number;
}

// Backend response wrapper types
interface RequestsApiResponse {
  items: PentestRequest[];
  total: number;
}

interface ResultsApiResponse {
  items: PentestFinding[];
  total: number;
}

interface StatsApiResponse {
  total_requests: number;
  total_results: number;
  by_status: Record<string, number>;
  by_exploitability: Record<string, number>;
  by_priority: Record<string, number>;
}

// Pentagi API functions
export async function getPentestRequests(): Promise<PentestRequest[]> {
  // Backend returns {items: [...], total: number} but UI expects array directly
  try {
    const response = await apiFetch<RequestsApiResponse>('/api/v1/pentagi/requests');
    return response.items ?? [];
  } catch {
    return [];
  }
}

export async function getPentestRequest(id: string): Promise<PentestRequest> {
  return apiFetch<PentestRequest>(`/api/v1/pentagi/requests/${id}`);
}

export async function createPentestRequest(data: Partial<PentestRequest>): Promise<PentestRequest> {
  return apiFetch<PentestRequest>('/api/v1/pentagi/requests', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function startPentestRequest(id: string): Promise<PentestRequest> {
  return apiFetch<PentestRequest>(`/api/v1/pentagi/requests/${id}/start`, {
    method: 'POST',
  });
}

export async function cancelPentestRequest(id: string): Promise<PentestRequest> {
  return apiFetch<PentestRequest>(`/api/v1/pentagi/requests/${id}/cancel`, {
    method: 'POST',
  });
}

export async function getPentestResults(requestId?: string): Promise<PentestFinding[]> {
  // Backend returns {items: [...], total: number} but UI expects array directly
  const path = requestId 
    ? `/api/v1/pentagi/results/by-request/${requestId}`
    : '/api/v1/pentagi/results';
  try {
    const response = await apiFetch<ResultsApiResponse>(path);
    return response.items ?? [];
  } catch {
    return [];
  }
}

export async function getPentestStats(): Promise<PentestStats> {
  // Backend returns {total_requests, total_results, by_status, ...} but UI expects {total, pending, in_progress, completed, total_findings}
  try {
    const response = await apiFetch<StatsApiResponse>('/api/v1/pentagi/stats');
    return {
      total: response.total_requests ?? 0,
      pending: response.by_status?.pending ?? 0,
      in_progress: response.by_status?.running ?? 0,
      completed: response.by_status?.completed ?? 0,
      total_findings: response.total_results ?? 0,
    };
  } catch {
    return {
      total: 0,
      pending: 0,
      in_progress: 0,
      completed: 0,
      total_findings: 0,
    };
  }
}

// Micropentest API functions
export async function runMicropentest(cves: string[]): Promise<{ status: string; results: unknown[] }> {
  return apiFetch<{ status: string; results: unknown[] }>('/api/v1/enhanced/micropentest', {
    method: 'POST',
    body: JSON.stringify({ cves }),
  });
}

export async function runAttackChain(sbomPath?: string, cves?: string[]): Promise<{ status: string; chain: unknown[] }> {
  return apiFetch<{ status: string; chain: unknown[] }>('/api/v1/enhanced/attack-chain', {
    method: 'POST',
    body: JSON.stringify({ sbom_path: sbomPath, cves }),
  });
}
