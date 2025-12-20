/**
 * FixOps API React Hooks
 * 
 * Custom hooks for data fetching and state management.
 */

import { useState, useEffect, useCallback } from 'react';
import { fetchApi, ApiError, getApiClient } from './client';
import { getSystemMode, setSystemMode, SystemMode } from './config';

/**
 * Hook for fetching data from the API.
 */
export function useApi<T>(
  path: string,
  options?: {
    params?: Record<string, string | number | boolean | undefined>;
    skip?: boolean;
    refreshInterval?: number;
  }
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(!options?.skip);

  // Stringify params to create a stable dependency value and prevent infinite loops
  const paramsKey = options?.params ? JSON.stringify(options.params) : '';
  const skip = options?.skip;

  const fetchData = useCallback(async () => {
    if (skip) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const params = paramsKey ? JSON.parse(paramsKey) : undefined;
      const result = await fetchApi<T>(path, { params });
      setData(result);
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setLoading(false);
    }
  }, [path, paramsKey, skip]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (options?.refreshInterval && !skip) {
      const interval = setInterval(fetchData, options.refreshInterval);
      return () => clearInterval(interval);
    }
  }, [fetchData, options?.refreshInterval, skip]);

  return { data, error, loading, refetch: fetchData };
}

/**
 * Hook for system mode management.
 */
export function useSystemMode() {
  const [mode, setMode] = useState<SystemMode>('demo');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setMode(getSystemMode());
    setLoading(false);
  }, []);

  const toggleMode = useCallback(async () => {
    const newMode = mode === 'demo' ? 'enterprise' : 'demo';
    setSystemMode(newMode);
    setMode(newMode);
    
    // Optionally sync with backend
    try {
      await fetchApi('/api/v1/system-mode/toggle', { method: 'POST' });
    } catch {
      // Ignore backend sync errors - local mode is sufficient
    }
  }, [mode]);

  const switchMode = useCallback((newMode: SystemMode) => {
    setSystemMode(newMode);
    setMode(newMode);
  }, []);

  return { mode, loading, toggleMode, switchMode, isDemo: mode === 'demo', isEnterprise: mode === 'enterprise' };
}

/**
 * Hook for reports API.
 */
export function useReports(options?: { type?: string; limit?: number; offset?: number }) {
  return useApi<{
    items: Array<{
      id: string;
      name: string;
      report_type: string;
      format: string;
      status: string;
      file_path: string | null;
      file_size: number | null;
      created_at: string;
      completed_at: string | null;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/reports', {
    params: {
      report_type: options?.type,
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for downloading a report.
 */
export function useReportDownload() {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const downloadReport = useCallback(async (reportId: string, filename?: string) => {
    setDownloading(true);
    setError(null);
    
    try {
      const client = getApiClient();
      const downloadInfo = await client.get<{
        report_id: string;
        download_url: string;
        file_size: number;
        format: string;
      }>(`/api/v1/reports/${reportId}/download`);
      
      await client.download(
        downloadInfo.download_url,
        filename || `report-${reportId}.${downloadInfo.format}`
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setDownloading(false);
    }
  }, []);

  return { downloadReport, downloading, error };
}

/**
 * Hook for Pentagi requests.
 */
export function usePentagiRequests(options?: { 
  findingId?: string; 
  status?: string; 
  limit?: number; 
  offset?: number 
}) {
  return useApi<{
    items: Array<{
      id: string;
      finding_id: string;
      target_url: string;
      vulnerability_type: string;
      test_case: string;
      priority: string;
      status: string;
      created_at: string;
      started_at: string | null;
      completed_at: string | null;
    }>;
    total: number;
  }>('/api/v1/pentagi/requests', {
    params: {
      finding_id: options?.findingId,
      status: options?.status,
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for Pentagi results.
 */
export function usePentagiResults(options?: { 
  findingId?: string; 
  exploitability?: string; 
  limit?: number; 
  offset?: number 
}) {
  return useApi<{
    items: Array<{
      id: string;
      request_id: string;
      finding_id: string;
      exploitability: string;
      exploit_successful: boolean;
      evidence: string;
      steps_taken: string[];
      artifacts: string[];
      confidence_score: number;
      execution_time_seconds: number;
      created_at: string;
    }>;
    total: number;
  }>('/api/v1/pentagi/results', {
    params: {
      finding_id: options?.findingId,
      exploitability: options?.exploitability,
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for Pentagi stats.
 */
export function usePentagiStats() {
  return useApi<{
    total_requests: number;
    total_results: number;
    by_status: Record<string, number>;
    by_exploitability: Record<string, number>;
    by_priority: Record<string, number>;
  }>('/api/v1/pentagi/stats');
}

/**
 * Hook for marketplace browse.
 */
export function useMarketplaceBrowse(options?: {
  contentType?: string;
  framework?: string;
  pricingModel?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  return useApi<{
    items: Array<{
      id: string;
      name: string;
      description: string;
      content_type: string;
      compliance_frameworks: string[];
      ssdlc_stages: string[];
      pricing_model: string;
      price: number;
      tags: string[];
      rating: number;
      rating_count: number;
      downloads: number;
      version: string;
      qa_status: string;
      author: string;
      organization: string;
      created_at: string;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/marketplace/browse', {
    params: {
      content_type: options?.contentType,
      framework: options?.framework,
      pricing_model: options?.pricingModel,
      search: options?.search,
      limit: options?.limit || 20,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for marketplace stats.
 */
export function useMarketplaceStats() {
  return useApi<{
    total_items: number;
    total_downloads: number;
    total_contributors: number;
    by_content_type: Record<string, number>;
    by_framework: Record<string, number>;
    by_pricing_model: Record<string, number>;
    top_rated: Array<{ id: string; name: string; rating: number }>;
    most_downloaded: Array<{ id: string; name: string; downloads: number }>;
  }>('/api/v1/marketplace/stats');
}

/**
 * Hook for compliance data.
 */
export function useCompliance(options?: { framework?: string }) {
  return useApi<{
    frameworks: Array<{
      id: string;
      name: string;
      description: string;
      controls_total: number;
      controls_passed: number;
      controls_failed: number;
      controls_not_applicable: number;
      last_assessed: string;
    }>;
    overall_score: number;
    gaps: Array<{
      control_id: string;
      framework: string;
      description: string;
      severity: string;
      remediation: string;
    }>;
  }>('/api/v1/compliance/summary', {
    params: { framework: options?.framework },
  });
}

/**
 * Hook for findings.
 */
export function useFindings(options?: {
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}) {
  return useApi<{
    items: Array<{
      id: string;
      rule_id: string;
      severity: string;
      status: string;
      title: string;
      description: string;
      file_path: string;
      line_number: number;
      created_at: string;
      updated_at: string;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/findings', {
    params: {
      severity: options?.severity,
      status: options?.status,
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for inventory.
 */
export function useInventory(options?: { type?: string; limit?: number; offset?: number }) {
  return useApi<{
    items: Array<{
      id: string;
      name: string;
      type: string;
      version: string;
      license: string;
      vulnerabilities: number;
      risk_score: number;
      last_scanned: string;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/inventory', {
    params: {
      type: options?.type,
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for users.
 */
export function useUsers(options?: { limit?: number; offset?: number }) {
  return useApi<{
    items: Array<{
      id: string;
      email: string;
      name: string;
      role: string;
      status: string;
      last_login: string;
      created_at: string;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/users', {
    params: {
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for teams.
 */
export function useTeams(options?: { limit?: number; offset?: number }) {
  return useApi<{
    items: Array<{
      id: string;
      name: string;
      description: string;
      member_count: number;
      created_at: string;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/teams', {
    params: {
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for policies.
 */
export function usePolicies(options?: { limit?: number; offset?: number }) {
  return useApi<{
    items: Array<{
      id: string;
      name: string;
      description: string;
      type: string;
      status: string;
      last_evaluated: string;
      created_at: string;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/policies', {
    params: {
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for workflows.
 */
export function useWorkflows(options?: { status?: string; limit?: number; offset?: number }) {
  return useApi<{
    items: Array<{
      id: string;
      name: string;
      description: string;
      status: string;
      trigger: string;
      last_run: string;
      created_at: string;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/workflows', {
    params: {
      status: options?.status,
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}

/**
 * Hook for audit logs.
 */
export function useAuditLogs(options?: { 
  action?: string; 
  user_id?: string; 
  limit?: number; 
  offset?: number 
}) {
  return useApi<{
    items: Array<{
      id: string;
      action: string;
      user_id: string;
      user_email: string;
      resource_type: string;
      resource_id: string;
      details: Record<string, unknown>;
      ip_address: string;
      timestamp: string;
    }>;
    total: number;
    limit: number;
    offset: number;
  }>('/api/v1/audit', {
    params: {
      action: options?.action,
      user_id: options?.user_id,
      limit: options?.limit || 100,
      offset: options?.offset || 0,
    },
  });
}
