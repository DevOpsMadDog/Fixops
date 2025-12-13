/**
 * Custom hook for fetching dashboard data from the FixOps API
 * 
 * This hook provides real-time data fetching with automatic polling
 * and fallback to demo data when the API is unavailable.
 */

import { useState, useEffect, useCallback } from 'react';
import { 
  getDashboardOverview, 
  getDashboardTrends, 
  getTopRisks,
  DashboardOverview,
  DashboardTrends,
  TopRisk,
  ApiError
} from '../lib/apiClient';

// Demo data fallback (used when API is unavailable)
const DEMO_SUMMARY_STATS: DashboardOverview = {
  total_issues: 789,
  critical: 45,
  high: 123,
  medium: 298,
  low: 323,
  new_7d: 87,
  resolved_7d: 52,
  kev_count: 12,
  internet_facing: 234,
  avg_age_days: 23,
};

const DEMO_TRENDS: DashboardTrends = {
  total_issues: { value: 789, change: -5.2, direction: 'down' },
  critical: { value: 45, change: 12.5, direction: 'up' },
  avg_resolution_time: { value: 4.2, change: -8.3, direction: 'down', unit: 'days' },
  compliance_score: { value: 85, change: 3.1, direction: 'up', unit: '%' },
};

const DEMO_TOP_SERVICES: TopRisk[] = [
  { name: 'payment-api', issues: 45, critical: 8, high: 15 },
  { name: 'user-service', issues: 38, critical: 5, high: 12 },
  { name: 'auth-service', issues: 32, critical: 4, high: 10 },
  { name: 'logging-service', issues: 28, critical: 6, high: 8 },
  { name: 'api-gateway', issues: 24, critical: 3, high: 9 },
];

export interface DashboardData {
  summary: DashboardOverview;
  trends: DashboardTrends;
  topServices: TopRisk[];
  isLoading: boolean;
  error: string | null;
  isLiveData: boolean;
  lastUpdated: Date | null;
  refresh: () => void;
}

export function useDashboardData(pollInterval: number = 30000): DashboardData {
  const [summary, setSummary] = useState<DashboardOverview>(DEMO_SUMMARY_STATS);
  const [trends, setTrends] = useState<DashboardTrends>(DEMO_TRENDS);
  const [topServices, setTopServices] = useState<TopRisk[]>(DEMO_TOP_SERVICES);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isLiveData, setIsLiveData] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      // Fetch all dashboard data in parallel
      const [overviewData, trendsData, topRisksData] = await Promise.all([
        getDashboardOverview(),
        getDashboardTrends(),
        getTopRisks(),
      ]);

      setSummary(overviewData);
      setTrends(trendsData);
      setTopServices(topRisksData);
      setIsLiveData(true);
      setLastUpdated(new Date());
    } catch (err) {
      const apiError = err as ApiError;
      console.warn('Failed to fetch dashboard data, using demo data:', apiError.detail || apiError.message);
      
      // Fall back to demo data
      setSummary(DEMO_SUMMARY_STATS);
      setTrends(DEMO_TRENDS);
      setTopServices(DEMO_TOP_SERVICES);
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
    summary,
    trends,
    topServices,
    isLoading,
    error,
    isLiveData,
    lastUpdated,
    refresh: fetchData,
  };
}
