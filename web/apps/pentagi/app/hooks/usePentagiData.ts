/**
 * Custom hook for fetching pentagi data from the FixOps API
 * 
 * This hook provides real-time data fetching with automatic polling.
 * No demo data fallback - only real API data is shown.
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

// Empty initial state (no demo data)
const EMPTY_STATS: PentestStats = {
  total: 0,
  pending: 0,
  in_progress: 0,
  completed: 0,
  total_findings: 0,
};

export interface PentagiData {
  requests: PentestRequest[];
  findings: PentestFinding[];
  stats: PentestStats;
  isLoading: boolean;
  error: string | null;
  lastUpdated: Date | null;
  refresh: () => void;
}

export function usePentagiData(pollInterval: number = 30000): PentagiData {
  const [requests, setRequests] = useState<PentestRequest[]>([]);
  const [findings, setFindings] = useState<PentestFinding[]>([]);
  const [stats, setStats] = useState<PentestStats>(EMPTY_STATS);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
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
      setLastUpdated(new Date());
    } catch (err) {
      const apiError = err as ApiError;
      console.error('Failed to fetch pentagi data:', apiError.detail || apiError.message);
      setError(apiError.detail || apiError.message || 'Failed to connect to API. Please ensure the FixOps API server is running.');
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
    lastUpdated,
    refresh: fetchData,
  };
}
