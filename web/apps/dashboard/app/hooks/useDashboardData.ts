/**
 * Custom hook for fetching dashboard data from the FixOps API
 * 
 * This hook provides real-time data fetching with automatic polling.
 * No demo data fallback - only real API data is shown.
 */

import { useState, useEffect, useCallback } from 'react';
import { 
  getDashboardOverview, 
  getDashboardTrends, 
  getTopRisks,
  getMTTRMetrics,
  getTeams,
  getIssueTrends,
  getResolutionTrends,
  getComplianceTrends,
  getRecentFindings,
  DashboardOverview,
  DashboardTrends,
  TopRisk,
  MTTRMetrics,
  TeamData,
  IssueTrendPoint,
  ResolutionTrendPoint,
  ComplianceTrendPoint,
  RecentFinding,
  ApiError
} from '../lib/apiClient';

// Empty initial state (no demo data)
const EMPTY_SUMMARY: DashboardOverview = {
  total_issues: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  new_7d: 0,
  resolved_7d: 0,
  kev_count: 0,
  internet_facing: 0,
  avg_age_days: 0,
};

const EMPTY_TRENDS: DashboardTrends = {
  total_issues: { value: 0, change: 0, direction: 'up' },
  critical: { value: 0, change: 0, direction: 'up' },
  avg_resolution_time: { value: 0, change: 0, direction: 'up', unit: 'days' },
  compliance_score: { value: 0, change: 0, direction: 'up', unit: '%' },
};

const EMPTY_MTTR: MTTRMetrics = {
  mttr: 0,
  mttd: 0,
  mttr_trend: [],
};

export interface DashboardData {
  summary: DashboardOverview;
  trends: DashboardTrends;
  topServices: TopRisk[];
  mttrMetrics: MTTRMetrics;
  teams: TeamData[];
  issueTrends: IssueTrendPoint[];
  resolutionTrends: ResolutionTrendPoint[];
  complianceTrends: ComplianceTrendPoint[];
  recentFindings: RecentFinding[];
  isLoading: boolean;
  error: string | null;
  lastUpdated: Date | null;
  refresh: () => void;
}

export function useDashboardData(pollInterval: number = 30000): DashboardData {
  const [summary, setSummary] = useState<DashboardOverview>(EMPTY_SUMMARY);
  const [trends, setTrends] = useState<DashboardTrends>(EMPTY_TRENDS);
  const [topServices, setTopServices] = useState<TopRisk[]>([]);
  const [mttrMetrics, setMttrMetrics] = useState<MTTRMetrics>(EMPTY_MTTR);
  const [teams, setTeams] = useState<TeamData[]>([]);
  const [issueTrends, setIssueTrends] = useState<IssueTrendPoint[]>([]);
  const [resolutionTrends, setResolutionTrends] = useState<ResolutionTrendPoint[]>([]);
  const [complianceTrends, setComplianceTrends] = useState<ComplianceTrendPoint[]>([]);
  const [recentFindings, setRecentFindings] = useState<RecentFinding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      // Fetch all dashboard data in parallel
      const [
        overviewData, 
        trendsData, 
        topRisksData,
        mttrData,
        teamsData,
        issueTrendsData,
        resolutionTrendsData,
        complianceTrendsData,
        recentFindingsData,
      ] = await Promise.all([
        getDashboardOverview(),
        getDashboardTrends(),
        getTopRisks(),
        getMTTRMetrics().catch(() => EMPTY_MTTR),
        getTeams().catch(() => []),
        getIssueTrends().catch(() => []),
        getResolutionTrends().catch(() => []),
        getComplianceTrends().catch(() => []),
        getRecentFindings().catch(() => []),
      ]);

      setSummary(overviewData);
      setTrends(trendsData);
      setTopServices(topRisksData);
      setMttrMetrics(mttrData);
      setTeams(teamsData);
      setIssueTrends(issueTrendsData);
      setResolutionTrends(resolutionTrendsData);
      setComplianceTrends(complianceTrendsData);
      setRecentFindings(recentFindingsData);
      setLastUpdated(new Date());
    } catch (err) {
      const apiError = err as ApiError;
      console.error('Failed to fetch dashboard data:', apiError.detail || apiError.message);
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
    summary,
    trends,
    topServices,
    mttrMetrics,
    teams,
    issueTrends,
    resolutionTrends,
    complianceTrends,
    recentFindings,
    isLoading,
    error,
    lastUpdated,
    refresh: fetchData,
  };
}
