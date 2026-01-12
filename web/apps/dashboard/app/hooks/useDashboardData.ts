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
  { service: 'payment-api', critical: 5, high: 12, total: 45, risk_score: 92 },
  { service: 'auth-service', critical: 3, high: 8, total: 28, risk_score: 85 },
  { service: 'user-portal', critical: 2, high: 15, total: 67, risk_score: 78 },
  { service: 'data-pipeline', critical: 4, high: 6, total: 23, risk_score: 88 },
  { service: 'notification-svc', critical: 1, high: 4, total: 18, risk_score: 62 },
];

const DEMO_TEAMS: TeamData[] = [
  { name: 'Platform Team', issues: 234, critical: 8, resolved_7d: 45, avg_resolution: 3.2 },
  { name: 'Security Team', issues: 156, critical: 12, resolved_7d: 67, avg_resolution: 2.1 },
  { name: 'DevOps Team', issues: 189, critical: 5, resolved_7d: 34, avg_resolution: 4.5 },
  { name: 'Backend Team', issues: 312, critical: 15, resolved_7d: 78, avg_resolution: 3.8 },
];

const DEMO_ISSUE_TRENDS: IssueTrendPoint[] = [
  { day: 'Mon', total: 1280, critical: 25, high: 160 },
  { day: 'Tue', total: 1265, critical: 24, high: 158 },
  { day: 'Wed', total: 1258, critical: 24, high: 157 },
  { day: 'Thu', total: 1252, critical: 23, high: 156 },
  { day: 'Fri', total: 1248, critical: 23, high: 156 },
  { day: 'Sat', total: 1247, critical: 23, high: 156 },
  { day: 'Sun', total: 1247, critical: 23, high: 156 },
];

const DEMO_RESOLUTION_TRENDS: ResolutionTrendPoint[] = [
  { day: 'Mon', resolved: 12, new: 8 },
  { day: 'Tue', resolved: 15, new: 10 },
  { day: 'Wed', resolved: 18, new: 7 },
  { day: 'Thu', resolved: 14, new: 9 },
  { day: 'Fri', resolved: 20, new: 6 },
  { day: 'Sat', resolved: 5, new: 2 },
  { day: 'Sun', resolved: 5, new: 5 },
];

const DEMO_COMPLIANCE_TRENDS: ComplianceTrendPoint[] = [
  { week: 'W1', soc2: 88, iso27001: 85, pci: 90, gdpr: 82 },
  { week: 'W2', soc2: 89, iso27001: 86, pci: 91, gdpr: 84 },
  { week: 'W3', soc2: 90, iso27001: 87, pci: 91, gdpr: 85 },
  { week: 'W4', soc2: 91, iso27001: 88, pci: 92, gdpr: 87 },
  { week: 'W5', soc2: 92, iso27001: 89, pci: 93, gdpr: 88 },
  { week: 'W6', soc2: 93, iso27001: 90, pci: 93, gdpr: 90 },
  { week: 'W7', soc2: 94, iso27001: 91, pci: 94, gdpr: 91 },
];

const DEMO_RECENT_FINDINGS: RecentFinding[] = [
  { id: '1', title: 'SQL Injection in login endpoint', severity: 'critical', service: 'auth-service', age_days: 2 },
  { id: '2', title: 'Outdated OpenSSL version', severity: 'high', service: 'payment-api', age_days: 5 },
  { id: '3', title: 'Missing rate limiting', severity: 'medium', service: 'user-portal', age_days: 8 },
  { id: '4', title: 'Insecure cookie settings', severity: 'high', service: 'auth-service', age_days: 3 },
  { id: '5', title: 'Log4j vulnerability CVE-2021-44228', severity: 'critical', service: 'data-pipeline', age_days: 1 },
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
