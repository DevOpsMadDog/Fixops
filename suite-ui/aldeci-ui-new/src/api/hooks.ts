/**
 * React Hooks for API Data Fetching
 * Uses React 19 hooks with suspense and promise-based patterns
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  Finding,
  FindingFilters,
  FindingSLA,
  FindingTimeline,
  FindingSummary,
  PaginatedResponse,
  PipelineHealth,
  DashboardMetric,
  RiskPosture,
  KPIs,
  ExecutiveReport,
  ConnectorHealth,
  ConnectorRegistry,
  Playbook,
  PlaybookRun,
  ComplianceTemplate,
  StreamEvent,
  EventStats,
  PipelineStage,
  ThroughputMetrics,
} from "./types";
import * as endpoints from "./endpoints";

// ════════════════════════════════════════════════════════════════
// Generic Hook for Any API Call
// ════════════════════════════════════════════════════════════════

export interface UseApiOptions {
  /** Auto-refetch interval in milliseconds */
  refetchInterval?: number;
  /** Enable automatic refetch */
  enabled?: boolean;
  /** Callback when data is loaded */
  onSuccess?: (data: unknown) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
}

export interface UseApiResult<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
}

/**
 * Generic hook for fetching data from API endpoints
 * @param fetcher Async function that fetches data
 * @param deps Dependency array for re-running fetch
 * @param options Configuration options
 */
export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  options: UseApiOptions = {}
): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const intervalRef = useRef<NodeJS.Timeout | undefined>(undefined);

  const refetch = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await fetcher();
      setData(result);
      options.onSuccess?.(result);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      options.onError?.(error);
    } finally {
      setLoading(false);
    }
  }, [fetcher, options]);

  useEffect(() => {
    if (options.enabled === false) return;

    refetch();

    if (options.refetchInterval) {
      intervalRef.current = setInterval(refetch, options.refetchInterval);
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [refetch, options.refetchInterval, options.enabled, ...deps]);

  return { data, loading, error, refetch };
}

// ════════════════════════════════════════════════════════════════
// Finding Hooks
// ════════════════════════════════════════════════════════════════

/**
 * Fetch list of findings with filtering
 */
export function useFindingsList(
  filters?: FindingFilters,
  options?: UseApiOptions
): UseApiResult<PaginatedResponse<Finding>> {
  return useApi(
    () => endpoints.findings.list(filters),
    [JSON.stringify(filters)],
    options
  );
}

/**
 * Fetch single finding by ID
 */
export function useFinding(
  findingId: string,
  options?: UseApiOptions
): UseApiResult<Finding> {
  return useApi(
    () => endpoints.findings.getById(findingId),
    [findingId],
    options
  );
}

/**
 * Fetch finding timeline (history)
 */
export function useFindingTimeline(
  findingId: string,
  options?: UseApiOptions
): UseApiResult<FindingTimeline> {
  return useApi(
    () => endpoints.findings.getTimeline(findingId),
    [findingId],
    options
  );
}

/**
 * Fetch finding SLA information
 */
export function useFindingSLA(
  findingId: string,
  options?: UseApiOptions
): UseApiResult<FindingSLA> {
  return useApi(
    () => endpoints.findings.getSLA(findingId),
    [findingId],
    options
  );
}

/**
 * Fetch findings summary
 */
export function useFindingsSummary(
  filters?: FindingFilters,
  options?: UseApiOptions
): UseApiResult<FindingSummary> {
  return useApi(
    () => endpoints.findings.getSummary(filters),
    [JSON.stringify(filters)],
    options
  );
}

/**
 * Hook to update finding status
 */
export function useUpdateFindingStatus() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const update = useCallback(
    async (findingId: string, status: string, reason?: string) => {
      try {
        setLoading(true);
        setError(null);
        const result = await endpoints.findings.updateStatus(findingId, status, reason);
        return result;
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setError(error);
        throw error;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  return { update, loading, error };
}

/**
 * Hook to assign finding
 */
export function useAssignFinding() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const assign = useCallback(async (findingId: string, assignee: string) => {
    try {
      setLoading(true);
      setError(null);
      const result = await endpoints.findings.assign(findingId, assignee);
      return result;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, []);

  return { assign, loading, error };
}

// ════════════════════════════════════════════════════════════════
// Pipeline Hooks
// ════════════════════════════════════════════════════════════════

/**
 * Fetch pipeline health with auto-refresh
 */
export function usePipelineHealth(
  refetchInterval: number = 30000,
  options?: Omit<UseApiOptions, "refetchInterval">
): UseApiResult<PipelineHealth> {
  return useApi(
    () => endpoints.pipeline.getHealth(),
    [],
    { ...options, refetchInterval }
  );
}

/**
 * Fetch pipeline stages
 */
export function usePipelineStages(
  options?: UseApiOptions
): UseApiResult<PipelineStage[]> {
  return useApi(
    () => endpoints.pipeline.getStages(),
    [],
    options
  );
}

/**
 * Fetch pipeline throughput metrics
 */
export function usePipelineThroughput(
  options?: UseApiOptions
): UseApiResult<ThroughputMetrics> {
  return useApi(
    () => endpoints.pipeline.getThroughput(),
    [],
    options
  );
}

// ════════════════════════════════════════════════════════════════
// Dashboard & Analytics Hooks
// ════════════════════════════════════════════════════════════════

/**
 * Fetch dashboard data for a specific persona
 */
export function useDashboard(
  persona?: string,
  options?: UseApiOptions
): UseApiResult<Record<string, DashboardMetric>> {
  return useApi(
    () => endpoints.analytics.getDashboard(persona),
    [persona],
    options
  );
}

/**
 * Fetch KPIs with auto-refresh
 */
export function useKPIs(
  refetchInterval: number = 60000,
  options?: Omit<UseApiOptions, "refetchInterval">
): UseApiResult<KPIs> {
  return useApi(
    () => endpoints.analytics.getKPIs(),
    [],
    { ...options, refetchInterval }
  );
}

/**
 * Fetch current risk posture
 */
export function useRiskPosture(
  options?: UseApiOptions
): UseApiResult<RiskPosture> {
  return useApi(
    () => endpoints.analytics.getPosture(),
    [],
    options
  );
}

/**
 * Fetch executive report
 */
export function useExecutiveReport(
  startDate?: string,
  endDate?: string,
  options?: UseApiOptions
): UseApiResult<ExecutiveReport> {
  return useApi(
    () => endpoints.analytics.getExecutiveReport(startDate, endDate),
    [startDate, endDate],
    options
  );
}

/**
 * Fetch specific metric trend
 */
export function useMetricTrend(
  metricName: string,
  days?: number,
  options?: UseApiOptions
): UseApiResult<Array<{ date: string; value: number }>> {
  return useApi(
    () => endpoints.analytics.getTrend(metricName, days),
    [metricName, days],
    options
  );
}

// ════════════════════════════════════════════════════════════════
// Connector Hooks
// ════════════════════════════════════════════════════════════════

/**
 * Fetch connector registry
 */
export function useConnectors(
  options?: UseApiOptions
): UseApiResult<ConnectorRegistry> {
  return useApi(
    () => endpoints.connectors.getRegistry(),
    [],
    options
  );
}

/**
 * Fetch connector health status
 */
export function useConnectorHealth(
  refetchInterval: number = 30000,
  options?: Omit<UseApiOptions, "refetchInterval">
): UseApiResult<ConnectorHealth[]> {
  return useApi(
    () => endpoints.connectors.getStatus(),
    [],
    { ...options, refetchInterval }
  );
}

/**
 * Hook to trigger connector sync
 */
export function useSyncConnector() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const sync = useCallback(async (connectorId: string) => {
    try {
      setLoading(true);
      setError(null);
      const result = await endpoints.connectors.sync(connectorId);
      return result;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, []);

  return { sync, loading, error };
}

// ════════════════════════════════════════════════════════════════
// Playbook Hooks
// ════════════════════════════════════════════════════════════════

/**
 * Fetch all playbooks
 */
export function usePlaybooks(
  options?: UseApiOptions
): UseApiResult<Playbook[]> {
  return useApi(
    () => endpoints.playbooks.list(),
    [],
    options
  );
}

/**
 * Fetch single playbook
 */
export function usePlaybook(
  playbookId: string,
  options?: UseApiOptions
): UseApiResult<Playbook> {
  return useApi(
    () => endpoints.playbooks.getById(playbookId),
    [playbookId],
    options
  );
}

/**
 * Fetch playbook runs
 */
export function usePlaybookRuns(
  playbookId: string,
  limit?: number,
  options?: UseApiOptions
): UseApiResult<PlaybookRun[]> {
  return useApi(
    () => endpoints.playbooks.getRuns(playbookId, limit),
    [playbookId, limit],
    options
  );
}

/**
 * Hook to execute playbook
 */
export function useExecutePlaybook() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const execute = useCallback(
    async (playbookId: string, context?: Record<string, unknown>) => {
      try {
        setLoading(true);
        setError(null);
        const result = await endpoints.playbooks.execute(playbookId, context);
        return result;
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setError(error);
        throw error;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  return { execute, loading, error };
}

// ════════════════════════════════════════════════════════════════
// Compliance Hooks
// ════════════════════════════════════════════════════════════════

/**
 * Fetch compliance templates
 */
export function useComplianceTemplates(
  options?: UseApiOptions
): UseApiResult<ComplianceTemplate[]> {
  return useApi(
    () => endpoints.compliance.getTemplates(),
    [],
    options
  );
}

/**
 * Fetch compliance assessment
 */
export function useComplianceAssessment(
  assessmentId: string,
  options?: UseApiOptions
): UseApiResult<ComplianceTemplate> {
  return useApi(
    () => endpoints.compliance.getTemplate(assessmentId),
    [assessmentId],
    options
  );
}

// ════════════════════════════════════════════════════════════════
// Event Stream Hooks
// ════════════════════════════════════════════════════════════════

/**
 * Hook for real-time event stream via WebSocket
 */
export function useEventStream(
  types?: string[]
): { events: StreamEvent[]; connected: boolean; error: Error | null } {
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    try {
      const url = endpoints.events.getStreamUrl(types);
      const ws = new WebSocket(url);

      ws.onopen = () => {
        setConnected(true);
        setError(null);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as StreamEvent;
          setEvents((prev) => [data, ...prev.slice(0, 99)]); // Keep last 100
        } catch (err) {
          console.error("Failed to parse event:", err);
        }
      };

      ws.onerror = () => {
        setError(new Error("WebSocket connection error"));
        setConnected(false);
      };

      ws.onclose = () => {
        setConnected(false);
      };

      wsRef.current = ws;

      return () => {
        ws.close();
      };
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
    }
  }, [types?.join(",")]);

  return { events, connected, error };
}

/**
 * Fetch recent events
 */
export function useRecentEvents(
  limit?: number,
  types?: string[],
  options?: UseApiOptions
): UseApiResult<StreamEvent[]> {
  return useApi(
    () => endpoints.events.getRecent(limit, types),
    [limit, types?.join(",")],
    options
  );
}

/**
 * Fetch event statistics
 */
export function useEventStats(
  refetchInterval: number = 30000,
  options?: Omit<UseApiOptions, "refetchInterval">
): UseApiResult<EventStats> {
  return useApi(
    () => endpoints.events.getStats(),
    [],
    { ...options, refetchInterval }
  );
}

// ════════════════════════════════════════════════════════════════
// Mutation Hooks (for creating/updating data)
// ════════════════════════════════════════════════════════════════

/**
 * Hook for bulk updating findings
 */
export function useBulkUpdateFindings() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const bulkUpdate = useCallback(
    async (findingIds: string[], updates: Record<string, unknown>) => {
      try {
        setLoading(true);
        setError(null);
        const result = await endpoints.findings.bulkUpdate(findingIds, updates);
        return result;
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setError(error);
        throw error;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  return { bulkUpdate, loading, error };
}

/**
 * Hook for exporting findings
 */
export function useExportFindings() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const export_findings = useCallback(
    async (filters?: FindingFilters, format: "csv" | "json" = "csv") => {
      try {
        setLoading(true);
        setError(null);
        const blob = await endpoints.findings.export(filters, format);
        // Trigger download
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `findings.${format}`;
        a.click();
        URL.revokeObjectURL(url);
        return blob;
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setError(error);
        throw error;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  return { export_findings, loading, error };
}
