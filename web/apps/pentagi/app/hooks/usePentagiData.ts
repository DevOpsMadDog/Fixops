/**
 * Custom hook for fetching pentagi data from the FixOps API
 * 
 * This hook provides real-time data fetching with automatic polling
 * and fallback to demo data when the API is unavailable.
 */

import { useState, useEffect, useCallback } from 'react';
import { 
  getPentestRequests, 
  getPentestResults,
  getPentestStats,
  PentestRequest,
  PentestFinding,
  PentestStats,
  ApiError
} from '../lib/apiClient';

// Demo data fallback (used when API is unavailable)
const DEMO_PENTEST_REQUESTS: PentestRequest[] = [
  {
    id: '1',
    name: 'Payment API Security Assessment',
    target: 'payment-api.fixops.com',
    type: 'web_application',
    scope: 'Full API endpoints, authentication, authorization',
    status: 'completed',
    severity_found: 'high',
    findings_count: 12,
    created_at: '2024-11-15T10:00:00Z',
    started_at: '2024-11-16T09:00:00Z',
    completed_at: '2024-11-18T17:00:00Z',
    requested_by: 'sarah.chen@fixops.io',
  },
  {
    id: '2',
    name: 'Infrastructure Penetration Test',
    target: 'prod.fixops.com',
    type: 'infrastructure',
    scope: 'Network perimeter, cloud infrastructure, VPN access',
    status: 'in_progress',
    severity_found: null,
    findings_count: 0,
    created_at: '2024-11-20T08:00:00Z',
    started_at: '2024-11-21T10:00:00Z',
    completed_at: null,
    requested_by: 'john.doe@fixops.io',
  },
  {
    id: '3',
    name: 'Mobile App Security Review',
    target: 'FixOps Mobile App v2.1',
    type: 'mobile_application',
    scope: 'iOS and Android apps, API communication, data storage',
    status: 'pending',
    severity_found: null,
    findings_count: 0,
    created_at: '2024-11-22T07:00:00Z',
    started_at: null,
    completed_at: null,
    requested_by: 'emily.rodriguez@fixops.io',
  },
];

const DEMO_FINDINGS: PentestFinding[] = [
  {
    id: 'f1',
    request_id: '1',
    title: 'SQL Injection in Payment Endpoint',
    severity: 'critical',
    cvss_score: 9.8,
    description: 'SQL injection vulnerability in /api/payments endpoint allows unauthorized data access',
    remediation: 'Use parameterized queries and input validation',
    status: 'open',
  },
  {
    id: 'f2',
    request_id: '1',
    title: 'Broken Authentication',
    severity: 'high',
    cvss_score: 8.1,
    description: 'JWT tokens do not expire and can be reused indefinitely',
    remediation: 'Implement token expiration and refresh mechanism',
    status: 'open',
  },
];

export interface PentagiData {
  requests: PentestRequest[];
  findings: PentestFinding[];
  stats: PentestStats;
  isLoading: boolean;
  error: string | null;
  isLiveData: boolean;
  lastUpdated: Date | null;
  refresh: () => void;
}

export function usePentagiData(pollInterval: number = 30000): PentagiData {
  const [requests, setRequests] = useState<PentestRequest[]>(DEMO_PENTEST_REQUESTS);
  const [findings, setFindings] = useState<PentestFinding[]>(DEMO_FINDINGS);
  const [stats, setStats] = useState<PentestStats>({
    total: DEMO_PENTEST_REQUESTS.length,
    pending: DEMO_PENTEST_REQUESTS.filter(r => r.status === 'pending').length,
    in_progress: DEMO_PENTEST_REQUESTS.filter(r => r.status === 'in_progress').length,
    completed: DEMO_PENTEST_REQUESTS.filter(r => r.status === 'completed').length,
    total_findings: DEMO_PENTEST_REQUESTS.reduce((sum, r) => sum + r.findings_count, 0),
  });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isLiveData, setIsLiveData] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      // Fetch all pentagi data in parallel
      const [requestsData, findingsData, statsData] = await Promise.all([
        getPentestRequests(),
        getPentestResults(),
        getPentestStats(),
      ]);

      setRequests(requestsData);
      setFindings(findingsData);
      setStats(statsData);
      setIsLiveData(true);
      setLastUpdated(new Date());
    } catch (err) {
      const apiError = err as ApiError;
      console.warn('Failed to fetch pentagi data, using demo data:', apiError.detail || apiError.message);
      
      // Fall back to demo data
      setRequests(DEMO_PENTEST_REQUESTS);
      setFindings(DEMO_FINDINGS);
      setStats({
        total: DEMO_PENTEST_REQUESTS.length,
        pending: DEMO_PENTEST_REQUESTS.filter(r => r.status === 'pending').length,
        in_progress: DEMO_PENTEST_REQUESTS.filter(r => r.status === 'in_progress').length,
        completed: DEMO_PENTEST_REQUESTS.filter(r => r.status === 'completed').length,
        total_findings: DEMO_PENTEST_REQUESTS.reduce((sum, r) => sum + r.findings_count, 0),
      });
      setIsLiveData(false);
      setError(apiError.detail || apiError.message || 'Failed to connect to API');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Polling for real-time updates
  useEffect(() => {
    if (pollInterval <= 0) return;

    const interval = setInterval(fetchData, pollInterval);
    return () => clearInterval(interval);
  }, [fetchData, pollInterval]);

  return {
    requests,
    findings,
    stats,
    isLoading,
    error,
    isLiveData,
    lastUpdated,
    refresh: fetchData,
  };
}
