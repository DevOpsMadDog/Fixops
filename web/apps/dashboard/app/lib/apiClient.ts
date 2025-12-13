/**
 * API Client for FixOps Dashboard
 * 
 * This module provides a centralized way to make API calls to the FixOps backend.
 * It handles authentication, base URL configuration, and error handling.
 * 
 * Environment Variables:
 * - NEXT_PUBLIC_FIXOPS_API_URL: Base URL for the API (default: http://localhost:8000)
 * - NEXT_PUBLIC_FIXOPS_API_TOKEN: API token for authentication (default: demo-token)
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

// Dashboard API types
export interface DashboardOverview {
  total_issues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  new_7d: number;
  resolved_7d: number;
  kev_count: number;
  internet_facing: number;
  avg_age_days: number;
}

export interface DashboardTrends {
  total_issues: { value: number; change: number; direction: 'up' | 'down' };
  critical: { value: number; change: number; direction: 'up' | 'down' };
  avg_resolution_time: { value: number; change: number; direction: 'up' | 'down'; unit: string };
  compliance_score: { value: number; change: number; direction: 'up' | 'down'; unit: string };
}

export interface TopRisk {
  name: string;
  issues: number;
  critical: number;
  high: number;
}

export interface ComplianceStatus {
  framework: string;
  score: number;
  controls_passed: number;
  controls_total: number;
}

// Dashboard API functions
export async function getDashboardOverview(): Promise<DashboardOverview> {
  return apiFetch<DashboardOverview>('/api/v1/analytics/dashboard/overview');
}

export async function getDashboardTrends(): Promise<DashboardTrends> {
  return apiFetch<DashboardTrends>('/api/v1/analytics/dashboard/trends');
}

export async function getTopRisks(): Promise<TopRisk[]> {
  return apiFetch<TopRisk[]>('/api/v1/analytics/dashboard/top-risks');
}

export async function getComplianceStatus(): Promise<ComplianceStatus[]> {
  return apiFetch<ComplianceStatus[]>('/api/v1/analytics/dashboard/compliance-status');
}

// Feeds API
export interface FeedsStatus {
  epss: { last_updated: string; total_records: number };
  kev: { last_updated: string; total_records: number };
  nvd: { last_updated: string; total_records: number };
}

export async function getFeedsStatus(): Promise<FeedsStatus> {
  return apiFetch<FeedsStatus>('/api/v1/feeds/status');
}

// Health check
export async function getHealth(): Promise<{ status: string }> {
  return apiFetch<{ status: string }>('/health');
}

// MTTR/MTTD metrics
export interface MTTRMetrics {
  mttr: number;
  mttd: number;
  mttr_trend: Array<{ week: string; mttr: number; mttd: number }>;
}

export async function getMTTRMetrics(): Promise<MTTRMetrics> {
  return apiFetch<MTTRMetrics>('/api/v1/analytics/mttr');
}

// Teams data
export interface TeamData {
  name: string;
  issues: number;
  critical: number;
  resolved_7d: number;
  avg_resolution: number;
}

export async function getTeams(): Promise<TeamData[]> {
  return apiFetch<TeamData[]>('/api/v1/teams');
}

// Issue trends
export interface IssueTrendPoint {
  day: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export async function getIssueTrends(days: number = 10): Promise<IssueTrendPoint[]> {
  return apiFetch<IssueTrendPoint[]>(`/api/v1/analytics/issue-trends?days=${days}`);
}

// Resolution trends
export interface ResolutionTrendPoint {
  week: string;
  avgDays: number;
  target: number;
}

export async function getResolutionTrends(): Promise<ResolutionTrendPoint[]> {
  return apiFetch<ResolutionTrendPoint[]>('/api/v1/analytics/resolution-trends');
}

// Compliance trends
export interface ComplianceTrendPoint {
  month: string;
  score: number;
}

export async function getComplianceTrends(): Promise<ComplianceTrendPoint[]> {
  return apiFetch<ComplianceTrendPoint[]>('/api/v1/analytics/compliance-trends');
}

// Recent findings
export interface RecentFinding {
  id: string;
  title: string;
  severity: string;
  service: string;
  age: string;
  kev: boolean;
}

export async function getRecentFindings(limit: number = 10): Promise<RecentFinding[]> {
  return apiFetch<RecentFinding[]>(`/api/v1/analytics/findings/recent?limit=${limit}`);
}
