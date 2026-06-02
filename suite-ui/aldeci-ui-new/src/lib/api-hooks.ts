/**
 * api-hooks.ts — React hooks wrapping ALDECIClient.
 *
 * Each hook returns { data, loading, error, refetch }.
 * When the API is unavailable (network error / 5xx), hooks fall back
 * to lightweight mock data so dashboards remain usable during dev.
 *
 * Auto-refresh: pass `refreshInterval` (ms) to enable polling.
 *
 * Dependencies: React 19 (useState, useEffect, useCallback, useRef).
 * No external query library is required — hooks self-manage state.
 * For heavy pages already using @tanstack/react-query, prefer the
 * existing use-api.ts hooks which wire into the shared QueryClient cache.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import {
  aldeciClient,
  ApiError,
  type Finding,
  type FindingsResponse,
  type PostureScore,
  type ComplianceStatus,
  type SLAMetrics,
  type AttackSurfaceData,
  type IncidentsResponse,
  type VendorsResponse,
  type IntegrationHealthResponse,
  type DashboardMetrics,
  type ThreatHuntingResponse,
} from "@/lib/api-client";

// ─────────────────────────────────────────────────────────────────────────────
// Generic hook state + return type
// ─────────────────────────────────────────────────────────────────────────────

export interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

// ─────────────────────────────────────────────────────────────────────────────
// Honest EMPTY-shaped fallbacks (zeros / empty arrays) used when the API is unreachable.
// NOT fabricated data — components also receive `error`, never fake findings/scores.
// ─────────────────────────────────────────────────────────────────────────────

const EMPTY_FINDINGS: FindingsResponse = {
  findings: [],
  items: [],
  total: 0,
};

const EMPTY_POSTURE: PostureScore = {
  score: 0,
  grade: "N/A",
  trend: "stable",
  critical_count: 0,
  high_count: 0,
  medium_count: 0,
  low_count: 0,
};

const EMPTY_COMPLIANCE: ComplianceStatus = {
  frameworks: [],
  overall_score: 0,
};

const EMPTY_SLA: SLAMetrics = {
  total_findings: 0,
  within_sla: 0,
  breached: 0,
  at_risk: 0,
  compliance_rate: 0,
};

const EMPTY_ATTACK_SURFACE: AttackSurfaceData = {
  assets: [],
  attack_paths: [],
  risk_score: 0,
  exposed_count: 0,
};

const EMPTY_INCIDENTS: IncidentsResponse = {
  incidents: [],
  items: [],
  total: 0,
};

const EMPTY_VENDORS: VendorsResponse = {
  vendors: [],
  items: [],
  total: 0,
};

const EMPTY_INTEGRATION_HEALTH: IntegrationHealthResponse = {
  integrations: [],
  total: 0,
  healthy: 0,
  degraded: 0,
  down: 0,
};

const EMPTY_METRICS: DashboardMetrics = {
  total_findings: 0,
  critical_findings: 0,
  open_findings: 0,
  resolved_findings: 0,
  posture_score: 0,
  compliance_rate: 0,
  sla_compliance: 0,
};

const EMPTY_THREAT_HUNTING: ThreatHuntingResponse = {
  sessions: [],
  items: [],
  total: 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Internal generic hook factory
// ─────────────────────────────────────────────────────────────────────────────

function isApiUnavailable(err: unknown): boolean {
  if (err instanceof ApiError) {
    // Network error (status 0) or server error — surface error + honest empty (not mock)
    return err.status === 0 || err.status >= 500;
  }
  return true;
}

interface UseApiOptions {
  /** Polling interval in milliseconds.  Omit to disable auto-refresh. */
  refreshInterval?: number;
  /** When false the fetch is skipped entirely (useful for conditional hooks). */
  enabled?: boolean;
}

function useApiQuery<T>(
  fetcher: () => Promise<T>,
  fallback: T,
  options: UseApiOptions = {},
): UseApiState<T> {
  const { refreshInterval, enabled = true } = options;

  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<string | null>(null);

  // Keep fetcher stable across renders without triggering re-runs
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const execute = useCallback(async () => {
    if (!enabled) return;
    setLoading(true);
    setError(null);
    try {
      const result = await fetcherRef.current();
      setData(result);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? `API ${err.status}: ${err.message}`
          : (err as Error).message ?? "Unknown error";
      setError(message);
      // Honest empty fallback (+ error set above) when the API is unreachable — never fabricated
      if (isApiUnavailable(err)) {
        setData(fallback);
      }
    } finally {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  useEffect(() => {
    execute();
  }, [execute]);

  useEffect(() => {
    if (!refreshInterval || !enabled) return;
    const id = setInterval(execute, refreshInterval);
    return () => clearInterval(id);
  }, [execute, refreshInterval, enabled]);

  return { data, loading, error, refetch: execute };
}

// ─────────────────────────────────────────────────────────────────────────────
// Public hooks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * useFindings — fetches findings list, supports filters and auto-refresh.
 *
 * @example
 *   const { data, loading, error, refetch } = useFindings({ severity: "critical" });
 */
export function useFindings(
  filters?: Record<string, string | number | boolean | undefined>,
  options?: UseApiOptions,
): UseApiState<FindingsResponse> {
  // Stable serialised key so the effect only re-runs when filters actually change
  const filtersKey = JSON.stringify(filters ?? {});
  return useApiQuery<FindingsResponse>(
    // eslint-disable-next-line react-hooks/exhaustive-deps
    useCallback(() => aldeciClient.getFindings(filters), [filtersKey]),
    EMPTY_FINDINGS,
    options,
  );
}

/**
 * usePosture — fetches the current security posture score.
 */
export function usePosture(options?: UseApiOptions): UseApiState<PostureScore> {
  return useApiQuery<PostureScore>(
    useCallback(() => aldeciClient.getPostureScore(), []),
    EMPTY_POSTURE,
    options,
  );
}

/**
 * useCompliance — fetches compliance status across all frameworks.
 */
export function useCompliance(options?: UseApiOptions): UseApiState<ComplianceStatus> {
  return useApiQuery<ComplianceStatus>(
    useCallback(() => aldeciClient.getComplianceStatus(), []),
    EMPTY_COMPLIANCE,
    options,
  );
}

/**
 * useSLA — fetches SLA metrics (breaches, at-risk, compliance rate).
 */
export function useSLA(options?: UseApiOptions): UseApiState<SLAMetrics> {
  return useApiQuery<SLAMetrics>(
    useCallback(() => aldeciClient.getSLAStatus(), []),
    EMPTY_SLA,
    options,
  );
}

/**
 * useAttackSurface — fetches attack surface assets and paths.
 */
export function useAttackSurface(options?: UseApiOptions): UseApiState<AttackSurfaceData> {
  return useApiQuery<AttackSurfaceData>(
    useCallback(() => aldeciClient.getAttackSurface(), []),
    EMPTY_ATTACK_SURFACE,
    options,
  );
}

/**
 * useIncidents — fetches active incidents / cases.
 */
export function useIncidents(
  params?: Record<string, string | number | boolean | undefined>,
  options?: UseApiOptions,
): UseApiState<IncidentsResponse> {
  const paramsKey = JSON.stringify(params ?? {});
  return useApiQuery<IncidentsResponse>(
    // eslint-disable-next-line react-hooks/exhaustive-deps
    useCallback(() => aldeciClient.getIncidents(params), [paramsKey]),
    EMPTY_INCIDENTS,
    options,
  );
}

/**
 * useVendors — fetches third-party vendor list.
 */
export function useVendors(
  params?: Record<string, string | number | boolean | undefined>,
  options?: UseApiOptions,
): UseApiState<VendorsResponse> {
  const paramsKey = JSON.stringify(params ?? {});
  return useApiQuery<VendorsResponse>(
    // eslint-disable-next-line react-hooks/exhaustive-deps
    useCallback(() => aldeciClient.getVendors(params), [paramsKey]),
    EMPTY_VENDORS,
    options,
  );
}

/**
 * useIntegrationHealth — fetches integration health for all connected tools.
 */
export function useIntegrationHealth(options?: UseApiOptions): UseApiState<IntegrationHealthResponse> {
  return useApiQuery<IntegrationHealthResponse>(
    useCallback(() => aldeciClient.getIntegrationHealth(), []),
    EMPTY_INTEGRATION_HEALTH,
    options,
  );
}

/**
 * useMetrics — fetches high-level dashboard metrics.
 */
export function useMetrics(options?: UseApiOptions): UseApiState<DashboardMetrics> {
  return useApiQuery<DashboardMetrics>(
    useCallback(() => aldeciClient.getMetrics(), []),
    EMPTY_METRICS,
    options,
  );
}

/**
 * useThreatHunting — fetches threat hunting sessions.
 */
export function useThreatHunting(
  params?: Record<string, string | number | boolean | undefined>,
  options?: UseApiOptions,
): UseApiState<ThreatHuntingResponse> {
  const paramsKey = JSON.stringify(params ?? {});
  return useApiQuery<ThreatHuntingResponse>(
    // eslint-disable-next-line react-hooks/exhaustive-deps
    useCallback(() => aldeciClient.getThreatHunting(params), [paramsKey]),
    EMPTY_THREAT_HUNTING,
    options,
  );
}

// Re-export Finding type for convenience
export type { Finding };
