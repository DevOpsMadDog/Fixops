/**
 * Custom hook for fetching dashboard data from the FixOps API
 * 
 * This hook provides real-time data fetching with automatic polling.
 * Falls back to demo data when API is unavailable.
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

// Demo data for when API is unavailable
const DEMO_SUMMARY: DashboardOverview = {
  total_issues: 1247,
  critical: 23,
  high: 156,
  medium: 489,
  low: 579,
  new_7d: 47,
  resolved_7d: 89,
  kev_count: 8,
  internet_facing: 34,
  avg_age_days: 12,
};

const DEMO_TRENDS: DashboardTrends = {
  total_issues: { value: 1247, change: -12, direction: 'down' },
  critical: { value: 23, change: -8, direction: 'down' },
  avg_resolution_time: { value: 4.2, change: -15, direction: 'down', unit: 'days' },
  compliance_score: { value: 94, change: 3, direction: 'up', unit: '%' },
};

const DEMO_MTTR: MTTRMetrics = {
  mttr: 4.2,
  mttd: 1.8,
  mttr_trend: [
    { week: 'W1', mttr: 6.2, mttd: 2.8 },
    { week: 'W2', mttr: 5.8, mttd: 2.5 },
    { week: 'W3', mttr: 5.4, mttd: 2.3 },
    { week: 'W4', mttr: 5.1, mttd: 2.1 },
    { week: 'W5', mttr: 4.8, mttd: 2.0 },
    { week: 'W6', mttr: 4.6, mttd: 1.9 },
    { week: 'W7', mttr: 4.5, mttd: 1.9 },
    { week: 'W8', mttr: 4.4, mttd: 1.8 },
    { week: 'W9', mttr: 4.3, mttd: 1.8 },
    { week: 'W10', mttr: 4.2, mttd: 1.8 },
  ],
};

const DEMO_TOP_SERVICES: TopRisk[] = [
  { name: 'payment-api', issues: 45, critical: 5, high: 12 },
  { name: 'auth-service', issues: 28, critical: 3, high: 8 },
  { name: 'user-portal', issues: 67, critical: 2, high: 15 },
  { name: 'data-pipeline', issues: 23, critical: 4, high: 6 },
  { name: 'notification-svc', issues: 18, critical: 1, high: 4 },
];

const DEMO_TEAMS: TeamData[] = [
  { name: 'Platform Team', issues: 234, critical: 8, resolved_7d: 45, avg_resolution: 3.2 },
  { name: 'Security Team', issues: 156, critical: 12, resolved_7d: 67, avg_resolution: 2.1 },
  { name: 'DevOps Team', issues: 189, critical: 5, resolved_7d: 34, avg_resolution: 4.5 },
  { name: 'Backend Team', issues: 312, critical: 15, resolved_7d: 78, avg_resolution: 3.8 },
];

const DEMO_ISSUE_TRENDS: IssueTrendPoint[] = [
  { day: 'Mon', total: 1280, critical: 25, high: 160, medium: 500, low: 595 },
  { day: 'Tue', total: 1265, critical: 24, high: 158, medium: 498, low: 585 },
  { day: 'Wed', total: 1258, critical: 24, high: 157, medium: 495, low: 582 },
  { day: 'Thu', total: 1252, critical: 23, high: 156, medium: 492, low: 581 },
  { day: 'Fri', total: 1248, critical: 23, high: 156, medium: 490, low: 579 },
  { day: 'Sat', total: 1247, critical: 23, high: 156, medium: 489, low: 579 },
  { day: 'Sun', total: 1247, critical: 23, high: 156, medium: 489, low: 579 },
];

const DEMO_RESOLUTION_TRENDS: ResolutionTrendPoint[] = [
  { week: 'W1', avgDays: 5.2, target: 4.0 },
  { week: 'W2', avgDays: 4.8, target: 4.0 },
  { week: 'W3', avgDays: 4.6, target: 4.0 },
  { week: 'W4', avgDays: 4.4, target: 4.0 },
  { week: 'W5', avgDays: 4.3, target: 4.0 },
  { week: 'W6', avgDays: 4.2, target: 4.0 },
  { week: 'W7', avgDays: 4.2, target: 4.0 },
];

const DEMO_COMPLIANCE_TRENDS: ComplianceTrendPoint[] = [
  { month: 'Jan', score: 88 },
  { month: 'Feb', score: 89 },
  { month: 'Mar', score: 90 },
  { month: 'Apr', score: 91 },
  { month: 'May', score: 92 },
  { month: 'Jun', score: 93 },
  { month: 'Jul', score: 94 },
];

const DEMO_RECENT_FINDINGS: RecentFinding[] = [
  { id: '1', title: 'SQL Injection in login endpoint', severity: 'critical', service: 'auth-service', age: '2 days', kev: true },
  { id: '2', title: 'Outdated OpenSSL version', severity: 'high', service: 'payment-api', age: '5 days', kev: false },
  { id: '3', title: 'Missing rate limiting', severity: 'medium', service: 'user-portal', age: '8 days', kev: false },
  { id: '4', title: 'Insecure cookie settings', severity: 'high', service: 'auth-service', age: '3 days', kev: false },
  { id: '5', title: 'Log4j vulnerability CVE-2021-44228', severity: 'critical', service: 'data-pipeline', age: '1 day', kev: true },
];

// Empty initial state (used during loading)
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
  const [isInitialLoad, setIsInitialLoad] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async (isBackgroundPoll: boolean = false) => {
    // Only show loading spinner on initial load, not on background polls
    if (!isBackgroundPoll) {
      setIsLoading(true);
    }
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
      setIsInitialLoad(false);
    } catch (err) {
      const apiError = err as ApiError;
      console.error('Failed to fetch dashboard data, using demo data:', apiError.detail || apiError.message);
      // Fall back to demo data when API is unavailable
      setSummary(DEMO_SUMMARY);
      setTrends(DEMO_TRENDS);
      setTopServices(DEMO_TOP_SERVICES);
      setMttrMetrics(DEMO_MTTR);
      setTeams(DEMO_TEAMS);
      setIssueTrends(DEMO_ISSUE_TRENDS);
      setResolutionTrends(DEMO_RESOLUTION_TRENDS);
      setComplianceTrends(DEMO_COMPLIANCE_TRENDS);
      setRecentFindings(DEMO_RECENT_FINDINGS);
      setLastUpdated(new Date());
      setIsInitialLoad(false);
      // Don't set error - show demo data instead
    } finally {
      if (!isBackgroundPoll) {
        setIsLoading(false);
      }
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Polling for real-time updates (background polls don't show loading spinner)
  useEffect(() => {
    if (pollInterval <= 0) return;

    const interval = setInterval(() => fetchData(true), pollInterval);
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
