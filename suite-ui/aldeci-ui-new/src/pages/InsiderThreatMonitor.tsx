/**
 * Insider Threat Monitor
 *
 * Behavioral analytics for internal user risk.
 * High-risk users table, threat indicators feed, risk trends, active investigations.
 * Route: /insider-threats
 *
 * API: GET /api/v1/insider-threat/high-risk  GET /api/v1/insider-threat/timeline
 * Falls back to mock data on failure.
 */

import { useState, useMemo, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Users,
  TrendingUp,
  Activity,
  Clock,
  Search,
  Filter,
  ChevronRight,
  AlertCircle,
  User,
  Building2,
  FileText,
  Lock,
  Download,
  Shield,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ===========================================================
// Types
// ===========================================================

type RiskLevel = "critical" | "high" | "medium" | "low";
type IndicatorType = "after_hours_access" | "bulk_download" | "privilege_escalation" | "policy_violation" | "failed_auth";
type Severity = "critical" | "high" | "medium" | "low";

interface HighRiskUser {
  id: string;
  user: string;
  department: string;
  risk_level: RiskLevel;
  top_indicator: string;
  last_activity: string;
  score: number;
}

interface ThreatIndicator {
  id: string;
  timestamp: string;
  user: string;
  indicator_type: IndicatorType;
  severity: Severity;
  resource: string;
}

interface Investigation {
  id: string;
  title: string;
  user: string;
  status: "open" | "investigating" | "escalated";
  risk_indicator_count: number;
  created: string;
}

// ===========================================================
// Mock data
// ===========================================================

const MOCK_HIGH_RISK_USERS: HighRiskUser[] = [
  {
    id: "usr-001",
    user: "john.smith@corp.com",
    department: "Finance",
    risk_level: "critical",
    top_indicator: "Bulk download of financial records",
    last_activity: "2m ago",
    score: 92,
  },
  {
    id: "usr-002",
    user: "sarah.johnson@corp.com",
    department: "Engineering",
    risk_level: "high",
    top_indicator: "After-hours access to prod database",
    last_activity: "15m ago",
    score: 78,
  },
  {
    id: "usr-003",
    user: "michael.chen@corp.com",
    department: "Marketing",
    risk_level: "high",
    top_indicator: "Privilege escalation attempt",
    last_activity: "1h ago",
    score: 72,
  },
  {
    id: "usr-004",
    user: "emma.wilson@corp.com",
    department: "HR",
    risk_level: "medium",
    top_indicator: "Multiple policy violations",
    last_activity: "3h ago",
    score: 58,
  },
  {
    id: "usr-005",
    user: "david.brown@corp.com",
    department: "Operations",
    risk_level: "medium",
    top_indicator: "Unusual data access pattern",
    last_activity: "5h ago",
    score: 54,
  },
];

const MOCK_THREAT_TIMELINE: ThreatIndicator[] = [
  {
    id: "ti-001",
    timestamp: "2024-04-14 14:32:18",
    user: "john.smith@corp.com",
    indicator_type: "bulk_download",
    severity: "critical",
    resource: "financial_db.xlsx (2.3 GB)",
  },
  {
    id: "ti-002",
    timestamp: "2024-04-14 14:15:42",
    user: "sarah.johnson@corp.com",
    indicator_type: "after_hours_access",
    severity: "high",
    resource: "prod-db-cluster (10.245.12.5)",
  },
  {
    id: "ti-003",
    timestamp: "2024-04-14 13:48:09",
    user: "michael.chen@corp.com",
    indicator_type: "privilege_escalation",
    severity: "high",
    resource: "admin_console (failed)",
  },
  {
    id: "ti-004",
    timestamp: "2024-04-14 13:22:31",
    user: "emma.wilson@corp.com",
    indicator_type: "policy_violation",
    severity: "medium",
    resource: "external_email_forward",
  },
  {
    id: "ti-005",
    timestamp: "2024-04-14 12:54:17",
    user: "john.smith@corp.com",
    indicator_type: "bulk_download",
    severity: "critical",
    resource: "customer_list.csv (418 MB)",
  },
  {
    id: "ti-006",
    timestamp: "2024-04-14 11:30:45",
    user: "david.brown@corp.com",
    indicator_type: "failed_auth",
    severity: "medium",
    resource: "compliance_vault (5 failed attempts)",
  },
];

const MOCK_INVESTIGATIONS: Investigation[] = [
  {
    id: "inv-001",
    title: "Suspicious data exfiltration = Financial data",
    user: "john.smith@corp.com",
    status: "escalated",
    risk_indicator_count: 8,
    created: "2024-04-14",
  },
  {
    id: "inv-002",
    title: "After-hours prod access pattern",
    user: "sarah.johnson@corp.com",
    status: "investigating",
    risk_indicator_count: 5,
    created: "2024-04-13",
  },
  {
    id: "inv-003",
    title: "Privilege escalation attempt = Engineering",
    user: "michael.chen@corp.com",
    status: "open",
    risk_indicator_count: 3,
    created: "2024-04-12",
  },
];

// ===========================================================
// Helper functions
// ===========================================================

const RISK_LEVEL_CONFIG: Record<RiskLevel, { label: string; color: string; bgColor: string }> = {
  critical: { label: "Critical", color: "text-red-400", bgColor: "bg-red-500/10" },
  high: { label: "High", color: "text-orange-400", bgColor: "bg-orange-500/10" },
  medium: { label: "Medium", color: "text-yellow-400", bgColor: "bg-yellow-500/10" },
  low: { label: "Low", color: "text-green-400", bgColor: "bg-green-500/10" },
};

const INDICATOR_CONFIG: Record<IndicatorType, { label: string; icon: typeof AlertTriangle; color: string }> = {
  after_hours_access: { label: "After-hours access", icon: Clock, color: "text-blue-400" },
  bulk_download: { label: "Bulk download", icon: Download, color: "text-red-400" },
  privilege_escalation: { label: "Privilege escalation", icon: Shield, color: "text-orange-400" },
  policy_violation: { label: "Policy violation", icon: AlertTriangle, color: "text-yellow-400" },
  failed_auth: { label: "Failed authentication", icon: Lock, color: "text-red-500" },
};

const SEVERITY_BADGE: Record<Severity, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

const INVESTIGATION_STATUS: Record<string, { label: string; color: string }> = {
  open: { label: "Open", color: "bg-blue-500/10 text-blue-400" },
  investigating: { label: "Investigating", color: "bg-yellow-500/10 text-yellow-400" },
  escalated: { label: "Escalated", color: "bg-red-500/10 text-red-400" },
};

// ===========================================================
// Risk trend bar chart (using divs + Tailwind)
// ===========================================================

interface TrendData {
  day: string;
  value: number;
}

const RISK_TREND: TrendData[] = [
  { day: "Sun", value: 32 },
  { day: "Mon", value: 45 },
  { day: "Tue", value: 38 },
  { day: "Wed", value: 52 },
  { day: "Thu", value: 61 },
  { day: "Fri", value: 58 },
  { day: "Sat", value: 73 },
];

const maxTrendValue = Math.max(...RISK_TREND.map((d) => d.value));

// ===========================================================
// Component: Risk Trend Chart (Div-based)
// ===========================================================

function RiskTrendChart() {
  return (
    <div className="flex items-end gap-2 h-40 pt-6">
      {RISK_TREND.map((item, idx) => (
        <motion.div
          key={`${item.day}-${idx}`}
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: `${(item.value / maxTrendValue) * 100}%`, opacity: 1 }}
          transition={{ delay: idx * 0.05 }}
          className="flex-1 bg-gradient-to-t from-red-500 to-orange-400 rounded-t opacity-80 hover:opacity-100 cursor-pointer transition-opacity"
          title={`${item.day}: ${item.value} risk incidents`}
        />
      ))}
    </div>
  );
}

// ===========================================================
// Component: High Risk Users Table
// ===========================================================

interface HighRiskTableProps {
  users: HighRiskUser[];
  isLoading: boolean;
}

function HighRiskUsersTable({ users, isLoading }: HighRiskTableProps) {
  const [searchTerm, setSearchTerm] = useState("");

  const filtered = useMemo(
    () =>
      users.filter(
        (u: HighRiskUser) =>
          u.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
          u.department.toLowerCase().includes(searchTerm.toLowerCase()),
      ),
    [users, searchTerm],
  );

  return (
    <Card className="border-slate-700 bg-slate-900/40 col-span-1 md:col-span-2">
      <CardHeader className="border-b border-slate-700 pb-4">
        <div className="flex items-center justify-between gap-4">
          <CardTitle className="flex items-center gap-2">
            <Users className="w-5 h-5 text-red-400" />
            High Risk Users
          </CardTitle>
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-slate-500" />
            <Input
              placeholder="Search user, dept..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="h-8 w-48 border-slate-700 bg-slate-800/50"
            />
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-6">
        {isLoading ? (
          <div className="text-slate-400">Loading...</div>
        ) : (
          <div className="overflow-x-auto">
          <ScrollArea className="w-full">
            <table role="table" className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700/50">
                  <th className="text-left py-3 px-4 font-semibold text-slate-300">User</th>
                  <th className="text-left py-3 px-4 font-semibold text-slate-300">Department</th>
                  <th className="text-left py-3 px-4 font-semibold text-slate-300">Risk Level</th>
                  <th className="text-left py-3 px-4 font-semibold text-slate-300">Top Indicator</th>
                  <th className="text-left py-3 px-4 font-semibold text-slate-300">Last Activity</th>
                  <th className="text-left py-3 px-4 font-semibold text-slate-300">Score</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-slate-500">
                      No users found
                    </td>
                  </tr>
                ) : (
                  filtered.map((user) => (
                    <motion.tr
                      key={user.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="border-b border-slate-700/30 hover:bg-slate-800/30 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4 text-slate-200">
                        <div className="flex items-center gap-2">
                          <User className="w-4 h-4 text-slate-500" />
                          {user.user}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        <div className="flex items-center gap-2">
                          <Building2 className="w-4 h-4 text-slate-500" />
                          {user.department}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          variant="outline"
                          className={cn(
                            "border-0",
                            RISK_LEVEL_CONFIG[user.risk_level].color,
                            RISK_LEVEL_CONFIG[user.risk_level].bgColor,
                          )}
                        >
                          {RISK_LEVEL_CONFIG[user.risk_level].label}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-xs truncate">{user.top_indicator}</td>
                      <td className="py-3 px-4 text-slate-400 text-xs">{user.last_activity}</td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-2 bg-slate-700 rounded-full overflow-hidden">
                            <div
                              className={cn(
                                "h-full rounded-full transition-all",
                                user.score >= 80
                                  ? "bg-red-500"
                                  : user.score >= 60
                                    ? "bg-orange-500"
                                    : "bg-yellow-500",
                              )}
                              style={{ width: `${user.score}%` }}
                            />
                          </div>
                          <span className="text-slate-300 font-semibold">{user.score}</span>
                        </div>
                      </td>
                    </motion.tr>
                  ))
                )}
              </tbody>
            </table>
          </ScrollArea>
          </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ===========================================================
// Component: Recent Threat Indicators Feed
// ===========================================================

interface ThreatFeedProps {
  indicators: ThreatIndicator[];
  isLoading: boolean;
}

function RecentThreatFeed({ indicators, isLoading }: ThreatFeedProps) {
  const [filter, setFilter] = useState<Severity | "all">("all");

  const filtered = useMemo(
    () => (filter === "all" ? indicators : indicators.filter((ind) => ind.severity === filter)),
    [indicators, filter],
  );

  return (
    <Card className="border-slate-700 bg-slate-900/40">
      <CardHeader className="border-b border-slate-700 pb-4">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-orange-400" />
            Recent Threat Indicators
          </CardTitle>
          <div className="flex gap-2">
            {(["critical", "high", "medium", "low"] as const).map((sev) => (
              <Button
                key={sev}
                size="sm"
                variant={filter === sev ? "default" : "ghost"}
                onClick={() => setFilter(filter === sev ? "all" : sev)}
                className={cn("h-7 text-xs", filter === sev && "bg-slate-700")}
              >
                {sev.charAt(0).toUpperCase() + sev.slice(1)}
              </Button>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-6">
        {isLoading ? (
          <div className="text-slate-400">Loading...</div>
        ) : (
          <ScrollArea className="h-96">
            <div className="space-y-3 pr-4">
              {filtered.length === 0 ? (
                <div className="text-center py-8 text-slate-500">No indicators matching filter</div>
              ) : (
                filtered.map((indicator) => {
                  const IndicatorIcon = INDICATOR_CONFIG[indicator.indicator_type].icon;
                  return (
                    <motion.div
                      key={indicator.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600 transition-colors cursor-pointer"
                    >
                      <div className="flex items-start gap-3">
                        <div
                          className={cn(
                            "p-2 rounded-lg mt-1 flex-shrink-0",
                            indicator.severity === "critical"
                              ? "bg-red-500/10"
                              : indicator.severity === "high"
                                ? "bg-orange-500/10"
                                : "bg-yellow-500/10",
                          )}
                        >
                          <IndicatorIcon
                            className={cn("w-4 h-4", INDICATOR_CONFIG[indicator.indicator_type].color)}
                          />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-sm font-semibold text-slate-200">{indicator.user}</span>
                            <Badge
                              variant="outline"
                              className={cn(
                                "border-0 h-5 text-xs",
                                indicator.severity === "critical"
                                  ? "bg-red-500/20 text-red-400"
                                  : indicator.severity === "high"
                                    ? "bg-orange-500/20 text-orange-400"
                                    : "bg-yellow-500/20 text-yellow-400",
                              )}
                            >
                              {indicator.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <p className="text-xs text-slate-400 mb-2">
                            {INDICATOR_CONFIG[indicator.indicator_type].label}
                          </p>
                          <div className="flex items-center justify-between">
                            <span className="text-xs text-slate-500 truncate">{indicator.resource}</span>
                            <span className="text-xs text-slate-600 flex-shrink-0 ml-2">{indicator.timestamp}</span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  );
                })
              )}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}

// ===========================================================
// Component: Active Investigations Cards
// ===========================================================

interface InvestigationsProps {
  investigations: Investigation[];
  isLoading: boolean;
}

function ActiveInvestigations({ investigations, isLoading }: InvestigationsProps) {
  return (
    <Card className="border-slate-700 bg-slate-900/40 col-span-1 md:col-span-3">
      <CardHeader className="border-b border-slate-700 pb-4">
        <CardTitle className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-blue-400" />
          Active Investigations
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-6">
        {isLoading ? (
          <div className="text-slate-400">Loading...</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {investigations.map((inv) => (
              <motion.div
                key={inv.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600 transition-colors cursor-pointer group"
              >
                <div className="flex items-start justify-between mb-3">
                  <h3 className="text-sm font-semibold text-slate-200 group-hover:text-slate-100 flex-1 pr-2">
                    {inv.title}
                  </h3>
                  <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0" />
                </div>
                <div className="space-y-2 mb-4">
                  <div className="flex items-center gap-2">
                    <User className="w-3 h-3 text-slate-500" />
                    <span className="text-xs text-slate-400">{inv.user}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Clock className="w-3 h-3 text-slate-500" />
                    <span className="text-xs text-slate-400">{inv.created}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between pt-3 border-t border-slate-700/50">
                  <Badge
                    variant="outline"
                    className={cn(
                      "border-0 h-6 text-xs",
                      INVESTIGATION_STATUS[inv.status].color,
                    )}
                  >
                    {INVESTIGATION_STATUS[inv.status].label}
                  </Badge>
                  <span className="text-xs text-slate-500">
                    {inv.risk_indicator_count} indicators
                  </span>
                </div>
              </motion.div>
            )))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ===========================================================
// Main Page
// ===========================================================

export default function InsiderThreatMonitor() {
  const [liveStats, setLiveStats] = useState<any>(null);

  // Fetch stats for KPI cards
  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/insider-threat/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/insider-threat/distribution?org_id=${ORG_ID}`),
    ]).then(([statsRes, distRes]) => {
      const stats = statsRes.status === "fulfilled" ? statsRes.value : null;
      const dist  = distRes.status  === "fulfilled" ? distRes.value  : null;
      if (stats || dist) setLiveStats({ stats, dist });
    });
  }, []);

  // Fetch high-risk users
  const { data: highRiskUsers = MOCK_HIGH_RISK_USERS, isLoading: loadingUsers } = useQuery({
    queryKey: ["insider-threat-high-risk"],
    queryFn: async () => {
      try {
        const data = await apiFetch(`/api/v1/insider-threat/high-risk?org_id=${ORG_ID}&threshold=50`);
        // API returns List[UserRiskProfile] = map to page's shape
        if (Array.isArray(data) && data.length > 0) {
          return data.map((u: any) => ({
            id: u.user_email ?? u.id ?? String(Math.random()),
            user: u.user_email ?? u.user ?? "unknown",
            department: u.department ?? "=",
            risk_level: u.alert_level ?? u.risk_level ?? "low",
            top_indicator: u.top_indicator ?? (u.indicators?.[0]?.indicator_type ?? "="),
            last_activity: u.last_activity ?? "=",
            score: Math.round(u.risk_score ?? u.score ?? 0),
          }));
        }
        return MOCK_HIGH_RISK_USERS;
      } catch {
        return MOCK_HIGH_RISK_USERS;
      }
    },
  });

  // Fetch threat indicators (distribution used as proxy; timeline needs a user_email)
  const { data: threatTimeline = MOCK_THREAT_TIMELINE, isLoading: loadingTimeline } = useQuery({
    queryKey: ["insider-threat-timeline"],
    queryFn: async () => {
      try {
        // Use the first high-risk user's email if available, else return mock
        const users = Array.isArray(highRiskUsers) && highRiskUsers.length > 0 ? highRiskUsers : MOCK_HIGH_RISK_USERS;
        const email = encodeURIComponent(users[0]?.user ?? "unknown@corp.com");
        const data = await apiFetch(`/api/v1/insider-threat/timeline/${email}?org_id=${ORG_ID}&limit=20`);
        if (Array.isArray(data) && data.length > 0) {
          return data.map((a: any) => ({
            id: a.id ?? a.activity_id ?? String(Math.random()),
            timestamp: a.recorded_at ?? a.timestamp ?? "=",
            user: a.user_email ?? a.user ?? "unknown",
            indicator_type: a.activity_type ?? "policy_violation",
            severity: a.severity ?? "medium",
            resource: a.details?.resource ?? a.resource ?? "=",
          }));
        }
        return MOCK_THREAT_TIMELINE;
      } catch {
        return MOCK_THREAT_TIMELINE;
      }
    },
    enabled: true,
  });

  const totalUsersMonitored = liveStats?.stats?.total_users ?? liveStats?.dist?.total ?? 2847;
  const highRiskCount = liveStats?.stats?.high_risk_count ??
    highRiskUsers.filter((u: HighRiskUser) => u.risk_level === "critical" || u.risk_level === "high").length;
  const activeAlertsCount = liveStats?.stats?.total_alerts ?? threatTimeline.length;
  const incidentsThisMonth = liveStats?.stats?.incidents_this_month ?? 12;

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Page Header */}
      <PageHeader
        title="Insider Threat Monitor"
        description="Behavioral analytics for internal user risk"
        actions={
          <Button className="bg-red-600 hover:bg-red-700">
            <AlertTriangle className="w-4 h-4 mr-2" />
            Escalate
          </Button>
        }
      />

      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* KPI Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title="Total Users Monitored"
            value={totalUsersMonitored.toLocaleString()}
            trend="up"
            trendLabel="+2.4%"
            icon={Users}
          />
          <KpiCard
            title="High Risk Users"
            value={highRiskCount.toString()}
            trend="up"
            trendLabel="+1 this week"
            icon={AlertTriangle}
          />
          <KpiCard
            title="Active Alerts"
            value={activeAlertsCount.toString()}
            trend="flat"
            trendLabel="Last 24h"
            icon={Activity}
          />
          <KpiCard
            title="Incidents This Month"
            value={incidentsThisMonth.toString()}
            trend="up"
            trendLabel="+3 from last month"
            icon={TrendingUp}
          />
        </div>

        {/* Risk Trend & High Risk Users Table = 2 cols on lg, stack on md */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Risk Trend Chart */}
          <Card className="border-slate-700 bg-slate-900/40">
            <CardHeader className="border-b border-slate-700 pb-4">
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-green-400" />
                Risk Trend (7 days)
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-4 pb-6">
              <RiskTrendChart />
              <p className="text-xs text-slate-500 mt-4 text-center">Incident count by severity</p>
            </CardContent>
          </Card>

          {/* High Risk Users Table */}
          <HighRiskUsersTable users={highRiskUsers} isLoading={loadingUsers} />
        </div>

        {/* Threat Feed & Investigations Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <RecentThreatFeed indicators={threatTimeline} isLoading={loadingTimeline} />
        </div>

        {/* Active Investigations */}
        <ActiveInvestigations investigations={MOCK_INVESTIGATIONS} isLoading={false} />
      </div>
    </div>
  );
}
