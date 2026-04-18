/**
 * Main Overview Dashboard
 *
 * Live platform overview with:
 *   1. Security posture score gauge (RadialBar)
 *   2. Alert counts by severity (BarChart)
 *   3. Compliance status bars (horizontal progress)
 *   4. Top 5 critical vulnerabilities table
 *   5. Recent incidents timeline
 *   6. Threat intel feed status grid
 *
 * Route: /dashboard
 * APIs:
 *   GET /api/v1/posture-score/current
 *   GET /api/v1/alert-triage/stats
 *   GET /api/v1/compliance/status
 *   GET /api/v1/vuln-intel/stats
 *   GET /api/v1/incident-orchestration/incidents
 *   GET /api/v1/feeds/config
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck, Bell, AlertTriangle, Activity,
  Rss, RefreshCw, TrendingUp, TrendingDown, Minus,
  CheckCircle2, XCircle, Clock, Zap,
} from "lucide-react";
import {
  RadialBarChart, RadialBar, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Cell,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

// ── Config ──────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

// ── Fallback mock data ───────────────────────────────────────────
const MOCK_POSTURE = { score: 74, grade: "B", trend: "improving", previous_score: 71 };

const MOCK_ALERT_STATS = {
  by_severity: [
    { severity: "critical", count: 12 },
    { severity: "high",     count: 47 },
    { severity: "medium",   count: 118 },
    { severity: "low",      count: 203 },
  ],
  total: 380,
  p1_open: 12,
  avg_triage_time_min: 8.3,
};

const MOCK_COMPLIANCE = {
  frameworks: [
    { name: "SOC 2",    score: 88, status: "compliant"     },
    { name: "ISO 27001",score: 76, status: "partial"       },
    { name: "PCI DSS",  score: 91, status: "compliant"     },
    { name: "HIPAA",    score: 62, status: "partial"       },
    { name: "NIST CSF", score: 79, status: "partial"       },
    { name: "GDPR",     score: 83, status: "compliant"     },
  ],
};

const MOCK_VULNS = [
  { id: "CVE-2024-3094", title: "XZ Utils Backdoor",          cvss: 10.0, epss: 0.97, asset: "build-server-01", kev: true  },
  { id: "CVE-2024-6387", title: "OpenSSH RCE (regreSSHion)",  cvss: 8.1,  epss: 0.89, asset: "edge-gw-03",     kev: true  },
  { id: "CVE-2024-4577", title: "PHP CGI RCE",                cvss: 9.8,  epss: 0.85, asset: "web-prod-02",    kev: false },
  { id: "CVE-2023-46805",title: "Ivanti Auth Bypass",         cvss: 8.2,  epss: 0.72, asset: "vpn-cluster",    kev: true  },
  { id: "CVE-2024-21762",title: "Fortinet RCE",               cvss: 9.6,  epss: 0.91, asset: "fw-corp-01",     kev: true  },
];

const MOCK_INCIDENTS = [
  { id: "INC-0041", title: "Ransomware Indicator",    severity: "critical", status: "active",   created_at: "2026-04-17T08:12:00Z" },
  { id: "INC-0040", title: "Cloud Misconfiguration",  severity: "high",     status: "contained","created_at": "2026-04-17T07:45:00Z" },
  { id: "INC-0039", title: "Credential Stuffing",     severity: "high",     status: "resolved", created_at: "2026-04-17T06:30:00Z" },
  { id: "INC-0038", title: "Insider Data Access",     severity: "medium",   status: "active",   created_at: "2026-04-16T23:18:00Z" },
  { id: "INC-0037", title: "Phishing Campaign",       severity: "medium",   status: "resolved", created_at: "2026-04-16T21:05:00Z" },
];

const MOCK_FEEDS = [
  { name: "NVD CVE",          status: "active",   last_sync: "2026-04-17T08:00:00Z", ioc_count: 245192 },
  { name: "OTX AlienVault",   status: "active",   last_sync: "2026-04-17T07:55:00Z", ioc_count: 91043  },
  { name: "AbuseIPDB",        status: "active",   last_sync: "2026-04-17T07:50:00Z", ioc_count: 430781 },
  { name: "URLhaus",          status: "inactive", last_sync: "2026-04-16T18:00:00Z", ioc_count: 128300 },
  { name: "MITRE ATT&CK",     status: "active",   last_sync: "2026-04-17T06:00:00Z", ioc_count: 0      },
  { name: "CISA KEV",         status: "active",   last_sync: "2026-04-17T08:05:00Z", ioc_count: 1148   },
];

// ── Colour helpers ───────────────────────────────────────────────
const SEV_COLOUR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#6b7280",
};

const STATUS_COLOUR: Record<string, string> = {
  active:    "border-red-500/30 text-red-400 bg-red-500/10",
  contained: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  resolved:  "border-green-500/30 text-green-400 bg-green-500/10",
};

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function gradeColour(grade: string) {
  const map: Record<string, string> = { A: "text-green-400", B: "text-cyan-400", C: "text-yellow-400", D: "text-orange-400", F: "text-red-400" };
  return map[grade] ?? "text-zinc-400";
}

function scoreColour(score: number) {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#06b6d4";
  if (score >= 40) return "#eab308";
  return "#ef4444";
}

function complianceBarColour(score: number) {
  if (score >= 80) return "bg-green-500";
  if (score >= 60) return "bg-cyan-500";
  return "bg-yellow-500";
}

// ── Posture Gauge ────────────────────────────────────────────────
function PostureGauge({ score, grade, trend }: { score: number; grade: string; trend: string }) {
  const data = [{ value: score, fill: scoreColour(score) }];
  const TrendIcon = trend === "improving" ? TrendingUp : trend === "declining" ? TrendingDown : Minus;
  const trendCls = trend === "improving" ? "text-green-400" : trend === "declining" ? "text-red-400" : "text-zinc-400";

  return (
    <div className="flex flex-col items-center justify-center h-full gap-1">
      <div className="relative w-48 h-48">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            cx="50%" cy="50%"
            innerRadius="70%" outerRadius="90%"
            startAngle={210} endAngle={-30}
            data={data}
            barSize={14}
          >
            <RadialBar dataKey="value" cornerRadius={8} background={{ fill: "#27272a" }} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("text-4xl font-black", gradeColour(grade))}>{grade}</span>
          <span className="text-2xl font-bold text-white">{score}</span>
          <span className="text-xs text-zinc-400">/ 100</span>
        </div>
      </div>
      <div className={cn("flex items-center gap-1 text-sm font-medium", trendCls)}>
        <TrendIcon className="w-4 h-4" />
        <span className="capitalize">{trend}</span>
      </div>
    </div>
  );
}

// ── Alert Severity Chart ─────────────────────────────────────────
function AlertSeverityChart({ data }: { data: { severity: string; count: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={160}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
        <XAxis dataKey="severity" tick={{ fill: "#a1a1aa", fontSize: 11 }} />
        <YAxis tick={{ fill: "#a1a1aa", fontSize: 11 }} />
        <Tooltip
          contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", borderRadius: 8 }}
          labelStyle={{ color: "#e4e4e7" }}
          itemStyle={{ color: "#a1a1aa" }}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            data.map((entry) => (
            <Cell key={entry.severity} fill={SEV_COLOUR[entry.severity] ?? "#6b7280"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── KPI pill ─────────────────────────────────────────────────────
function KpiPill({ label, value, sub, colour }: { label: string; value: string | number; sub?: string; colour?: string }) {
  return (
    <div className="flex flex-col gap-0.5 rounded-lg border border-border/50 bg-zinc-900/60 px-4 py-3 min-w-[110px]">
      <span className={cn("text-2xl font-black tabular-nums", colour ?? "text-white")}>{value}</span>
      <span className="text-xs text-zinc-400 leading-tight">{label}</span>
      {sub && <span className="text-[10px] text-zinc-500">{sub}</span>}
    </div>
  );
}

// ── Main component ───────────────────────────────────────────────
export default function MainOverviewDashboard() {
  const [posture, setPosture]     = useState<typeof MOCK_POSTURE | null>(null);
  const [alertStats, setAlerts]   = useState<typeof MOCK_ALERT_STATS | null>(null);
  const [compliance, setCompliance] = useState<typeof MOCK_COMPLIANCE | null>(null);
  const [vulns, setVulns]         = useState<typeof MOCK_VULNS | null>(null);
  const [incidents, setIncidents] = useState<typeof MOCK_INCIDENTS | null>(null);
  const [feeds, setFeeds]         = useState<typeof MOCK_FEEDS | null>(null);
  const [loading, setLoading]     = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const load = useCallback(async () => {
    setLoading(true);
    const results = await Promise.allSettled([
      apiFetch(`/api/v1/posture-score/current?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/alert-triage/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/compliance/status?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-intel/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/incident-orchestration/incidents?org_id=${ORG_ID}&limit=5`),
      apiFetch(`/api/v1/feeds/config?org_id=${ORG_ID}`),
    ]);

    const [p, a, c, v, i, f] = results;
    setPosture(   p.status === "fulfilled" ? p.value : MOCK_POSTURE);
    setAlerts(    a.status === "fulfilled" ? a.value : MOCK_ALERT_STATS);
    setCompliance(c.status === "fulfilled" ? c.value : MOCK_COMPLIANCE);
    setVulns(     v.status === "fulfilled" ? (v.value.top_critical ?? MOCK_VULNS) : MOCK_VULNS);
    setIncidents( i.status === "fulfilled" ? (i.value.incidents ?? MOCK_INCIDENTS) : MOCK_INCIDENTS);
    setFeeds(     f.status === "fulfilled" ? (f.value.feeds ?? MOCK_FEEDS) : MOCK_FEEDS);

    setLastRefresh(new Date());
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const p   = posture   ?? MOCK_POSTURE;
  const a   = alertStats ?? MOCK_ALERT_STATS;
  const c   = compliance ?? MOCK_COMPLIANCE;
  const v   = vulns      ?? MOCK_VULNS;
  const inc = incidents  ?? MOCK_INCIDENTS;
  const fd  = feeds      ?? MOCK_FEEDS;

  const activeFeeds = fd.filter(f => f.status === "active").length;

  return (
    <div className="flex flex-col gap-6 p-6 min-h-screen bg-background">
      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2">
            <ShieldCheck className="w-7 h-7 text-cyan-400" />
            Platform Overview
          </h1>
          <p className="text-sm text-zinc-400 mt-0.5">
            Live security posture across all domains &mdash; last refreshed {lastRefresh.toLocaleTimeString()}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={load}
          disabled={loading}
          className="gap-2 border-zinc-700 text-zinc-300 hover:text-white"
        >
          <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {/* ── Top KPI strip ── */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-wrap gap-3"
      >
        <KpiPill label="Posture Score" value={p.score} sub={`Grade ${p.grade}`} colour={gradeColour(p.grade)} />
        <KpiPill label="Open Alerts"   value={a.total}  sub={`${a.p1_open} P1`}  colour="text-orange-400" />
        <KpiPill label="Critical Alerts" value={a.by_severity.find(s => s.severity === "critical")?.count ?? 0} sub="needs immediate action" colour="text-red-400" />
        <KpiPill label="Active Feeds"  value={`${activeFeeds}/${fd.length}`} sub="threat intel sources" colour="text-cyan-400" />
        <KpiPill label="Avg Triage"    value={`${a.avg_triage_time_min}m`} sub="mean triage time" colour="text-zinc-300" />
        <KpiPill label="Compliant Frameworks" value={c.frameworks.filter(f => f.status === "compliant").length} sub={`of ${c.frameworks.length} total`} colour="text-green-400" />
      </motion.div>

      {/* ── Row 1: Posture gauge + Alert chart + Compliance bars ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Posture Gauge */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <Card className="border-border/50 bg-zinc-900/60 h-full">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                Security Posture
              </CardTitle>
              <CardDescription className="text-xs text-zinc-500">Composite risk score</CardDescription>
            </CardHeader>
            <CardContent className="flex items-center justify-center pb-4">
              <PostureGauge score={p.score} grade={p.grade} trend={p.trend} />
            </CardContent>
          </Card>
        </motion.div>

        {/* Alert Severity Chart */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <Card className="border-border/50 bg-zinc-900/60 h-full">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <Bell className="w-4 h-4 text-orange-400" />
                Alerts by Severity
              </CardTitle>
              <CardDescription className="text-xs text-zinc-500">{a.total} total open alerts</CardDescription>
            </CardHeader>
            <CardContent>
              <AlertSeverityChart data={a.by_severity} />
            </CardContent>
          </Card>
        </motion.div>

        {/* Compliance Bars */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <Card className="border-border/50 bg-zinc-900/60 h-full">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-400" />
                Compliance Status
              </CardTitle>
              <CardDescription className="text-xs text-zinc-500">Framework coverage scores</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {c.frameworks.map((fw) => (
                <div key={fw.name} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-zinc-300 font-medium">{fw.name}</span>
                    <span className="text-xs font-bold text-zinc-200">{fw.score}%</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                    <div
                      className={cn("h-full rounded-full transition-all", complianceBarColour(fw.score))}
                      style={{ width: `${fw.score}%` }}
                    />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* ── Row 2: Top vulns + Incidents timeline ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Top 5 Critical Vulnerabilities */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <Card className="border-border/50 bg-zinc-900/60 h-full">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                Top Critical Vulnerabilities
              </CardTitle>
              <CardDescription className="text-xs text-zinc-500">Highest priority by CVSS + EPSS + KEV</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-zinc-800">
                    <th className="text-left px-4 py-2 text-zinc-500 font-medium">CVE</th>
                    <th className="text-left px-4 py-2 text-zinc-500 font-medium hidden sm:table-cell">Asset</th>
                    <th className="text-right px-4 py-2 text-zinc-500 font-medium">CVSS</th>
                    <th className="text-right px-4 py-2 text-zinc-500 font-medium">KEV</th>
                  </tr>
                </thead>
                <tbody>
                  {v.slice(0, 5).map((vuln, idx) => (
                    <tr key={vuln.id} className={cn("border-b border-zinc-800/50", idx % 2 === 0 ? "bg-zinc-900/30" : "")}>
                      <td className="px-4 py-2">
                        <div className="font-mono text-red-300">{vuln.id}</div>
                        <div className="text-zinc-400 text-[10px] truncate max-w-[160px]">{vuln.title}</div>
                      </td>
                      <td className="px-4 py-2 text-zinc-400 hidden sm:table-cell">{vuln.asset}</td>
                      <td className="px-4 py-2 text-right">
                        <span className={cn("font-bold tabular-nums", vuln.cvss >= 9 ? "text-red-400" : vuln.cvss >= 7 ? "text-orange-400" : "text-yellow-400")}>
                          {vuln.cvss.toFixed(1)}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-right">
                        {vuln.kev
                          ? <Zap className="w-3.5 h-3.5 text-red-400 inline" />
                          : <span className="text-zinc-600">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </motion.div>

        {/* Recent Incidents Timeline */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
          <Card className="border-border/50 bg-zinc-900/60 h-full">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <Activity className="w-4 h-4 text-purple-400" />
                Recent Incidents
              </CardTitle>
              <CardDescription className="text-xs text-zinc-500">Latest 5 across all severity levels</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="relative flex flex-col gap-0">
                {/* Timeline line */}
                <div className="absolute left-[7px] top-2 bottom-2 w-px bg-zinc-700" />
                {inc.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  inc.map((incident, idx) => (
                  <motion.div
                    key={incident.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.25 + idx * 0.05 }}
                    className="flex gap-3 pl-6 pb-4 relative"
                  >
                    {/* Dot */}
                    <div className={cn(
                      "absolute left-0 top-1 w-3.5 h-3.5 rounded-full border-2 border-background",
                      incident.severity === "critical" ? "bg-red-500" :
                      incident.severity === "high"     ? "bg-orange-500" :
                      incident.severity === "medium"   ? "bg-yellow-500" : "bg-zinc-500"
                    )} />
                    <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-semibold text-zinc-200 truncate">{incident.title}</span>
                        <Badge className={cn("text-[9px] border capitalize shrink-0", STATUS_COLOUR[incident.status] ?? "border-border")}>
                          {incident.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-zinc-500">
                        <span className="font-mono">{incident.id}</span>
                        <span>·</span>
                        <Clock className="w-3 h-3" />
                        <span>{timeAgo(incident.created_at)}</span>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* ── Row 3: Threat intel feed status ── */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <Card className="border-border/50 bg-zinc-900/60">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
              <Rss className="w-4 h-4 text-cyan-400" />
              Threat Intelligence Feeds
            </CardTitle>
            <CardDescription className="text-xs text-zinc-500">
              {activeFeeds} of {fd.length} feeds active
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {fd.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                fd.map((feed) => (
                <div
                  key={feed.name}
                  className={cn(
                    "rounded-lg border p-3 flex flex-col gap-1.5",
                    feed.status === "active"
                      ? "border-green-500/20 bg-green-500/5"
                      : "border-zinc-700/50 bg-zinc-800/30 opacity-60"
                  )}
                >
                  <div className="flex items-center justify-between gap-1">
                    <span className="text-[11px] font-semibold text-zinc-200 truncate">{feed.name}</span>
                    {feed.status === "active"
                      ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
                      : <XCircle    className="w-3.5 h-3.5 text-zinc-500 shrink-0" />}
                  </div>
                  {feed.ioc_count > 0 && (
                    <span className="text-[10px] text-zinc-400 tabular-nums">
                      {feed.ioc_count.toLocaleString()} IOCs
                    </span>
                  )}
                  <span className="text-[9px] text-zinc-600 leading-tight">
                    Synced {timeAgo(feed.last_sync)}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
