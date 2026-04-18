/**
 * Cloud IAM Security
 *
 * Privilege analysis, unused permissions, and cloud identity risk.
 * KPIs, high-risk principals table, privilege escalation paths,
 * unused permissions by service, least privilege gauge, access anomalies, recommendations.
 * Route: /cloud-iam
 *
 * API: GET /api/v1/cloud-iam/principals  GET /api/v1/cloud-iam/findings
 * Falls back to mock data on failure.
 */

import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Shield,
  Users,
  AlertTriangle,
  Key,
  Cloud,
  ChevronRight,
  Activity,
  Lock,
  TrendingDown,
  CheckCircle,
  XCircle,
  ArrowRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_KEY = localStorage.getItem("aldeci_api_key") || import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type RiskLevel = "critical" | "high" | "medium" | "low";
type Provider = "AWS" | "Azure" | "GCP";
type PrincipalType = "User" | "Role" | "Service Account" | "Group";

interface Principal {
  id: string;
  principal_name: string;
  principal_type: PrincipalType;
  provider: Provider;
  last_activity: string;
  permissions_count: number;
  unused_permissions_pct: number;
  risk_score: number;
  risk_level: RiskLevel;
}

interface EscalationPath {
  id: string;
  title: string;
  steps: string[];
  severity: RiskLevel;
}

interface Anomaly {
  id: string;
  principal: string;
  event: string;
  detail: string;
  time: string;
  severity: RiskLevel;
}

interface Recommendation {
  id: string;
  title: string;
  impact: string;
  priority: RiskLevel;
  affected_count: number;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_PRINCIPALS: Principal[] = [
  { id: "1", principal_name: "svc-data-pipeline@prod.iam", principal_type: "Service Account", provider: "GCP", last_activity: "90 days ago", permissions_count: 312, unused_permissions_pct: 94, risk_score: 98, risk_level: "critical" },
  { id: "2", principal_name: "root", principal_type: "User", provider: "AWS", last_activity: "2 hours ago", permissions_count: 1024, unused_permissions_pct: 12, risk_score: 97, risk_level: "critical" },
  { id: "3", principal_name: "cross-account-deploy-role", principal_type: "Role", provider: "AWS", last_activity: "3 days ago", permissions_count: 287, unused_permissions_pct: 61, risk_score: 91, risk_level: "critical" },
  { id: "4", principal_name: "ci-cd-automation", principal_type: "Service Account", provider: "Azure", last_activity: "1 day ago", permissions_count: 198, unused_permissions_pct: 78, risk_score: 85, risk_level: "high" },
  { id: "5", principal_name: "dev-team-group", principal_type: "Group", provider: "GCP", last_activity: "6 hours ago", permissions_count: 145, unused_permissions_pct: 52, risk_score: 74, risk_level: "high" },
  { id: "6", principal_name: "eks-node-role", principal_type: "Role", provider: "AWS", last_activity: "12 minutes ago", permissions_count: 89, unused_permissions_pct: 44, risk_score: 68, risk_level: "high" },
  { id: "7", principal_name: "backup-service-sp", principal_type: "Service Account", provider: "Azure", last_activity: "45 days ago", permissions_count: 76, unused_permissions_pct: 83, risk_score: 61, risk_level: "medium" },
  { id: "8", principal_name: "analytics-reader", principal_type: "User", provider: "GCP", last_activity: "4 days ago", permissions_count: 54, unused_permissions_pct: 35, risk_score: 42, risk_level: "medium" },
  { id: "9", principal_name: "audit-log-role", principal_type: "Role", provider: "AWS", last_activity: "1 hour ago", permissions_count: 23, unused_permissions_pct: 22, risk_score: 28, risk_level: "low" },
  { id: "10", principal_name: "readonly-reporter", principal_type: "User", provider: "Azure", last_activity: "30 minutes ago", permissions_count: 18, unused_permissions_pct: 11, risk_score: 15, risk_level: "low" },
];

const ESCALATION_PATHS: EscalationPath[] = [
  {
    id: "1",
    title: "Developer → Production Admin",
    steps: ["john.doe (User)", "sts:AssumeRole", "dev-cross-account-role", "iam:PassRole", "AdminRole (AdministratorAccess)"],
    severity: "critical",
  },
  {
    id: "2",
    title: "CI/CD Service → Secrets Access",
    steps: ["ci-cd-automation (SA)", "secretsmanager:GetSecretValue", "prod-db-credentials", "rds:Connect", "prod-database (Full Access)"],
    severity: "high",
  },
  {
    id: "3",
    title: "Lambda Execution → Data Exfiltration",
    steps: ["lambda-ingest-fn (Role)", "s3:GetObject s3:ListBucket", "customer-data-bucket", "s3:PutObject", "external-storage-bucket"],
    severity: "high",
  },
];

const UNUSED_BY_SERVICE = [
  { service: "S3", pct: 89, color: "bg-red-500" },
  { service: "EC2", pct: 67, color: "bg-orange-500" },
  { service: "RDS", pct: 78, color: "bg-red-400" },
  { service: "IAM", pct: 45, color: "bg-yellow-500" },
  { service: "Lambda", pct: 34, color: "bg-green-500" },
];

const ANOMALIES: Anomaly[] = [
  { id: "1", principal: "svc-data-pipeline@prod.iam", event: "First-time service access", detail: "Accessed BigQuery for the first time after 90 days of inactivity", time: "14 min ago", severity: "critical" },
  { id: "2", principal: "john.doe@corp.com", event: "Access from new region", detail: "Console login from ap-southeast-1 — user typically operates from us-east-1", time: "1 hr ago", severity: "high" },
  { id: "3", principal: "ci-cd-automation", event: "Access at unusual hour", detail: "API calls to IAM:CreateRole at 03:47 UTC (outside business hours)", time: "3 hrs ago", severity: "high" },
  { id: "4", principal: "analytics-reader", event: "Bulk data download", detail: "Downloaded 4.2 GB from S3 customer-exports bucket in single session", time: "6 hrs ago", severity: "medium" },
  { id: "5", principal: "eks-node-role", event: "Privilege escalation attempt", detail: "Attempted iam:PassRole on AdminRole — denied by SCP", time: "Yesterday", severity: "medium" },
];

const RECOMMENDATIONS: Recommendation[] = [
  { id: "1", title: "Remove unused S3:* permissions from 47 roles", impact: "Reduces attack surface by 31%", priority: "critical", affected_count: 47 },
  { id: "2", title: "Revoke inactive service accounts (90+ days)", impact: "Eliminates 12 dormant high-risk principals", priority: "critical", affected_count: 12 },
  { id: "3", title: "Restrict cross-account trust policies to specific external IDs", impact: "Prevents confused-deputy attacks on 8 roles", priority: "high", affected_count: 8 },
  { id: "4", title: "Enable MFA for all IAM users with console access", impact: "Blocks credential stuffing on 23 accounts", priority: "high", affected_count: 23 },
  { id: "5", title: "Scope EC2:* to minimum required actions across dev roles", impact: "Reduces over-provisioned dev permissions by 67%", priority: "medium", affected_count: 34 },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

const riskBadge = (level: RiskLevel) => {
  const map: Record<RiskLevel, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return map[level];
};

const providerColor: Record<Provider, string> = {
  AWS: "text-orange-400",
  Azure: "text-blue-400",
  GCP: "text-green-400",
};

// ═══════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════

function LeastPrivilegeGauge({ score }: { score: number }) {
  const radius = 54;
  const circ = 2 * Math.PI * radius;
  const dash = (score / 100) * circ;
  const color = score < 40 ? "#ef4444" : score < 65 ? "#f97316" : "#22c55e";

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="#1e293b" strokeWidth="12" />
        <circle
          cx="70" cy="70" r={radius} fill="none"
          stroke={color} strokeWidth="12"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
        />
        <text x="70" y="66" textAnchor="middle" fill={color} fontSize="24" fontWeight="bold">{score}</text>
        <text x="70" y="84" textAnchor="middle" fill="#64748b" fontSize="11">/100</text>
      </svg>
      <span className="text-xs text-red-400 font-medium">Red Zone — High Risk</span>
      <span className="text-xs text-slate-400 text-center px-2">
        Projected improvement: <span className="text-green-400 font-semibold">+28 pts</span> if recommendations applied
      </span>
    </div>
  );
}

function EscalationPathCard({ path }: { path: EscalationPath }) {
  const nodeColors = ["bg-blue-500/20 text-blue-300 border-blue-500/30", "bg-slate-700 text-slate-300 border-slate-600", "bg-orange-500/20 text-orange-300 border-orange-500/30", "bg-slate-700 text-slate-300 border-slate-600", "bg-red-500/20 text-red-300 border-red-500/30"];

  return (
    <div className={cn("rounded-lg border p-4", path.severity === "critical" ? "border-red-500/30 bg-red-500/5" : "border-orange-500/30 bg-orange-500/5")}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-semibold text-slate-200">{path.title}</span>
        <Badge className={cn("text-xs border", riskBadge(path.severity))}>{path.severity.toUpperCase()}</Badge>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {path.steps.map((step, i) => (
          <div key={i} className="flex items-center gap-1.5">
            <span className={cn("text-xs px-2 py-0.5 rounded border", nodeColors[i % nodeColors.length])}>{step}</span>
            {i < path.steps.length - 1 && <ArrowRight className="h-3 w-3 text-slate-500 flex-shrink-0" />}
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main page
// ═══════════════════════════════════════════════════════════

export default function CloudIAM() {
  const [activeProvider, setActiveProvider] = useState<"All" | Provider>("All");
  const [liveStats, setLiveStats] = useState<{ total: number; critical: number; high: number } | null>(null);
  const [loading, setLoading] = useState(true);

  // Fetch identity analytics sessions and stats
  const { data: iaSessions } = useQuery<any>({
    queryKey: ["identity-analytics-sessions"],
    queryFn: () => apiFetch(`/identity-analytics/sessions?org_id=${ORG_ID}&limit=20`),
    retry: false,
  });

  const { data: iaStats } = useQuery<any>({
    queryKey: ["identity-analytics-stats"],
    queryFn: () => apiFetch(`/identity-analytics/stats?org_id=${ORG_ID}`),
    retry: false,
  });

  // Derive principals from identity analytics sessions
  const principalsFromSessions: Principal[] = (() => {
    const sessions = Array.isArray(iaSessions) ? iaSessions : (iaSessions?.sessions ?? []);
    if (!sessions.length) return MOCK_PRINCIPALS;
    return sessions.slice(0, 10).map((s: any, idx: number) => {
      const riskScore = s.risk_score ?? s.anomaly_score ?? 50;
      const riskLevel: RiskLevel = riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 40 ? "medium" : "low";
      return {
        id: String(idx + 1),
        principal_name: s.user_id ?? s.username ?? s.principal ?? "unknown",
        principal_type: "User" as PrincipalType,
        provider: "AWS" as Provider,
        last_activity: s.last_seen ?? s.timestamp ?? "—",
        permissions_count: s.event_count ?? s.actions ?? 0,
        unused_permissions_pct: s.unused_pct ?? 0,
        risk_score: riskScore,
        risk_level: riskLevel,
      };
    });
  })();

  // Compute live stats from identity analytics
  useEffect(() => {
    if (!iaStats) return;
    setLiveStats({
      total: iaStats.total_users ?? iaStats.user_count ?? iaStats.total ?? 0,
      critical: iaStats.high_risk_count ?? iaStats.critical ?? 0,
      high: iaStats.medium_risk_count ?? iaStats.high ?? 0,
    });
  
    setLoading(false);}, [iaStats]);

  const principals = principalsFromSessions.length > 0 && principalsFromSessions[0].principal_name !== "unknown"
    ? principalsFromSessions
    : MOCK_PRINCIPALS;
  const filtered = activeProvider === "All" ? principals : principals.filter(p => p.provider === activeProvider);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Cloud IAM Security"
        description="Privilege analysis, unused permissions, and cloud identity risk"
        icon={<Key className="h-6 w-6 text-blue-400" />}
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard title="IAM Principals"  value={liveStats?.total ?? "1,247"}    icon={<Users className="h-4 w-4" />}         trend="neutral" />
        <KpiCard title="Over-privileged" value={liveStats?.critical ?? "89"}     icon={<AlertTriangle className="h-4 w-4" />} trend="up"      trendLabel="+7 this week"        className="border-orange-500/20" />
        <KpiCard title="High Risk"       value={liveStats?.high ?? "234"}        icon={<Lock className="h-4 w-4" />}          trend="up"      trendLabel="High severity risks"  className="border-red-500/20" />
        <KpiCard title="Admin Accounts"  value="8"                               icon={<Shield className="h-4 w-4" />}        trend="neutral" trendLabel="Requires MFA" />
      </div>

      {/* High-Risk Principals + Least Privilege Gauge */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2 border-slate-700/50 bg-slate-800/50">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Users className="h-4 w-4 text-orange-400" />
                High-Risk Principals
              </CardTitle>
              <div className="flex gap-1">
                {(["All", "AWS", "Azure", "GCP"] as const).map(p => (
                  <button
                    key={p}
                    onClick={() => setActiveProvider(p)}
                    className={cn("text-xs px-2 py-1 rounded transition-colors", activeProvider === p ? "bg-blue-600 text-white" : "text-slate-400 hover:text-slate-200")}
                  >
                    {p}
                  </button>
                ))
    setLoading(false);}
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    {["Principal", "Type", "Provider", "Last Activity", "Perms", "Unused %", "Risk"].map(h => (
                      <th key={h} className="px-4 py-2 text-left text-slate-400 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    filtered.map((p, i) => (
                    <motion.tr
                      key={p.id}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.03 }}
                      className="border-b border-slate-700/30 hover:bg-slate-700/20 transition-colors"
                    >
                      <td className="px-4 py-2.5 font-mono text-slate-200 max-w-[180px] truncate">{p.principal_name}</td>
                      <td className="px-4 py-2.5 text-slate-400">{p.principal_type}</td>
                      <td className={cn("px-4 py-2.5 font-semibold", providerColor[p.provider])}>{p.provider}</td>
                      <td className="px-4 py-2.5 text-slate-400">{p.last_activity}</td>
                      <td className="px-4 py-2.5 text-slate-300">{p.permissions_count.toLocaleString()}</td>
                      <td className="px-4 py-2.5">
                        <span className={cn("font-semibold", p.unused_permissions_pct >= 80 ? "text-red-400" : p.unused_permissions_pct >= 50 ? "text-orange-400" : "text-yellow-400")}>
                          {p.unused_permissions_pct}%
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge className={cn("text-xs border", riskBadge(p.risk_level))}>{p.risk_score}</Badge>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Least Privilege Gauge */}
        <Card className="border-slate-700/50 bg-slate-800/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <TrendingDown className="h-4 w-4 text-red-400" />
              Least Privilege Score
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center pt-2">
            <LeastPrivilegeGauge score={42} />
            <div className="mt-4 w-full space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Over-privileged principals</span>
                <span className="text-red-400 font-semibold">89 / 1,247</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Avg unused permissions</span>
                <span className="text-orange-400 font-semibold">54%</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Zero-standing access</span>
                <span className="text-yellow-400 font-semibold">12%</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Privilege Escalation Paths */}
      <Card className="border-slate-700/50 bg-slate-800/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <ChevronRight className="h-4 w-4 text-red-400" />
            Privilege Escalation Paths
            <Badge className="bg-red-500/20 text-red-400 border-red-500/30 border text-xs ml-1">{ESCALATION_PATHS.length} active</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {ESCALATION_PATHS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            ESCALATION_PATHS.map(path => (
            <EscalationPathCard key={path.id} path={path} />
          ))}
        </CardContent>
      </Card>

      {/* Unused Permissions + Anomalies */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card className="border-slate-700/50 bg-slate-800/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Cloud className="h-4 w-4 text-blue-400" />
              Unused Permissions by Service
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {UNUSED_BY_SERVICE.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              UNUSED_BY_SERVICE.map(svc => (
              <div key={svc.service} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium w-16">{svc.service}</span>
                  <span className={cn("font-semibold", svc.pct >= 75 ? "text-red-400" : svc.pct >= 50 ? "text-orange-400" : "text-yellow-400")}>{svc.pct}% unused</span>
                </div>
                <div className="h-2 rounded-full bg-slate-700/50">
                  <div className={cn("h-2 rounded-full transition-all", svc.color)} style={{ width: `${svc.pct}%` }} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="border-slate-700/50 bg-slate-800/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="h-4 w-4 text-yellow-400" />
              Access Pattern Anomalies
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {ANOMALIES.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              ANOMALIES.map(a => (
              <div key={a.id} className="flex items-start gap-3 p-2.5 rounded-lg bg-slate-700/20 border border-slate-700/30">
                <AlertTriangle className={cn("h-4 w-4 mt-0.5 flex-shrink-0", a.severity === "critical" ? "text-red-400" : a.severity === "high" ? "text-orange-400" : "text-yellow-400")} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-200 truncate">{a.event}</span>
                    <span className="text-xs text-slate-500 flex-shrink-0">{a.time}</span>
                  </div>
                  <span className="text-xs text-blue-400 font-mono">{a.principal}</span>
                  <p className="text-xs text-slate-400 mt-0.5 line-clamp-1">{a.detail}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Recommendations */}
      <Card className="border-slate-700/50 bg-slate-800/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            Least Privilege Recommendations
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {RECOMMENDATIONS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            RECOMMENDATIONS.map((rec, i) => (
            <motion.div
              key={rec.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className="flex items-center gap-4 p-3 rounded-lg bg-slate-700/20 border border-slate-700/30 hover:bg-slate-700/30 transition-colors"
            >
              <Badge className={cn("text-xs border flex-shrink-0", riskBadge(rec.priority))}>{rec.priority.toUpperCase()}</Badge>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-slate-200 truncate">{rec.title}</p>
                <p className="text-xs text-slate-400">{rec.impact}</p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <span className="text-xs text-slate-400">{rec.affected_count} affected</span>
                <Button size="sm" variant="ghost" className="h-6 px-2 text-xs text-blue-400 hover:text-blue-300">
                  Apply
                </Button>
              </div>
            </motion.div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
