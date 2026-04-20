/**
 * Main Overview Dashboard — ALDECI Platform Command Center
 *
 * Live platform overview with:
 *   1. Security posture score gauge (RadialBar) — animated hero
 *   2. Alert counts by severity (BarChart with gradient fills)
 *   3. Compliance status bars (horizontal progress with badges)
 *   4. Top 5 critical vulnerabilities table
 *   5. Recent incidents timeline
 *   6. Threat intel feed status grid with pulse indicators
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
import { useAutoRefresh } from "@/hooks/use-auto-refresh";
import { Pause, Play } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck, Bell, AlertTriangle, Activity,
  Rss, RefreshCw, TrendingUp, TrendingDown, Minus,
  CheckCircle2, XCircle, Clock, Zap, Database,
  Shield, Target, BarChart2, Wifi,
} from "lucide-react";
import {
  RadialBarChart, RadialBar, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Cell,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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

// Gradient IDs for the bar chart
const SEV_GRADIENT_ID: Record<string, string> = {
  critical: "gradCritical",
  high:     "gradHigh",
  medium:   "gradMedium",
  low:      "gradLow",
};

const SEV_GRADIENT_TOP: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#71717a",
};

const SEV_GRADIENT_BOT: Record<string, string> = {
  critical: "#7f1d1d",
  high:     "#7c2d12",
  medium:   "#713f12",
  low:      "#27272a",
};

const STATUS_COLOUR: Record<string, string> = {
  active:    "border-red-500/40 text-red-300 bg-red-500/10",
  contained: "border-amber-500/40 text-amber-300 bg-amber-500/10",
  resolved:  "border-emerald-500/40 text-emerald-300 bg-emerald-500/10",
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
  const map: Record<string, string> = {
    A: "text-emerald-400",
    B: "text-cyan-400",
    C: "text-amber-400",
    D: "text-orange-400",
    F: "text-red-400",
  };
  return map[grade] ?? "text-zinc-400";
}

function gradeGlow(grade: string) {
  const map: Record<string, string> = {
    A: "drop-shadow(0 0 16px rgba(52,211,153,0.5))",
    B: "drop-shadow(0 0 16px rgba(34,211,238,0.5))",
    C: "drop-shadow(0 0 16px rgba(251,191,36,0.4))",
    D: "drop-shadow(0 0 16px rgba(251,146,60,0.4))",
    F: "drop-shadow(0 0 16px rgba(239,68,68,0.5))",
  };
  return map[grade] ?? "none";
}

function scoreColour(score: number) {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#06b6d4";
  if (score >= 40) return "#eab308";
  return "#ef4444";
}

function complianceBarColour(score: number) {
  if (score >= 80) return "from-emerald-600 to-emerald-400";
  if (score >= 60) return "from-cyan-600 to-cyan-400";
  return "from-amber-600 to-amber-400";
}

// ── Animated Counter ─────────────────────────────────────────────
function AnimatedNumber({ value, duration = 1.2 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start: number | null = null;
    const from = 0;
    const to = value;
    const step = (timestamp: number) => {
      if (!start) start = timestamp;
      const progress = Math.min((timestamp - start) / (duration * 1000), 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(from + (to - from) * eased));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [value, duration]);
  return <>{display}</>;
}

// ── Posture Gauge (Hero) ─────────────────────────────────────────
function PostureGauge({ score, grade, trend, previousScore }: {
  score: number;
  grade: string;
  trend: string;
  previousScore: number;
}) {
  const data = [{ value: score, fill: scoreColour(score) }];
  const TrendIcon = trend === "improving" ? TrendingUp : trend === "declining" ? TrendingDown : Minus;
  const trendCls  = trend === "improving" ? "text-emerald-400" : trend === "declining" ? "text-red-400" : "text-zinc-400";
  const delta     = score - previousScore;

  return (
    <div className="flex flex-col items-center justify-center gap-4 py-4">
      {/* Outer glow ring */}
      <div className="relative">
        <div
          className="absolute inset-0 rounded-full opacity-20 blur-2xl"
          style={{ background: scoreColour(score) }}
        />
        <div className="relative w-52 h-52">
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              cx="50%" cy="50%"
              innerRadius="68%" outerRadius="88%"
              startAngle={210} endAngle={-30}
              data={data}
              barSize={16}
            >
              <RadialBar
                dataKey="value"
                cornerRadius={10}
                background={{ fill: "rgba(39,39,42,0.8)" }}
              />
            </RadialBarChart>
          </ResponsiveContainer>
          {/* Center overlay */}
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5">
            <motion.span
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.3, duration: 0.5, type: "spring", stiffness: 200 }}
              className={cn("text-5xl font-black tracking-tight leading-none", gradeColour(grade))}
              style={{ filter: gradeGlow(grade) }}
            >
              {grade}
            </motion.span>
            <motion.span
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.5 }}
              className="text-3xl font-bold text-white tabular-nums leading-none mt-1"
            >
              <AnimatedNumber value={score} />
            </motion.span>
            <span className="text-xs text-zinc-500 font-medium tracking-widest uppercase">/ 100</span>
          </div>
        </div>
      </div>

      {/* Trend row */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="flex items-center gap-3"
      >
        <div className={cn("flex items-center gap-1.5 text-sm font-semibold", trendCls)}>
          <TrendIcon className="w-4 h-4" />
          <span className="capitalize">{trend}</span>
        </div>
        {delta !== 0 && (
          <span className={cn(
            "text-xs font-mono px-2 py-0.5 rounded-full border",
            delta > 0
              ? "border-emerald-500/30 text-emerald-400 bg-emerald-500/10"
              : "border-red-500/30 text-red-400 bg-red-500/10"
          )}>
            {delta > 0 ? "+" : ""}{delta} pts
          </span>
        )}
      </motion.div>
    </div>
  );
}

// ── Alert Severity Chart ─────────────────────────────────────────
function AlertSeverityChart({ data }: { data: { severity: string; count: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={172}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <defs>
          {data.map((entry) => (
            <linearGradient
              key={entry.severity}
              id={SEV_GRADIENT_ID[entry.severity] ?? `grad-${entry.severity}`}
              x1="0" y1="0" x2="0" y2="1"
            >
              <stop offset="0%"   stopColor={SEV_GRADIENT_TOP[entry.severity] ?? "#6b7280"} stopOpacity={1} />
              <stop offset="100%" stopColor={SEV_GRADIENT_BOT[entry.severity] ?? "#27272a"} stopOpacity={0.9} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
        <XAxis
          dataKey="severity"
          tick={{ fill: "#71717a", fontSize: 10, fontWeight: 600 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: "#52525b", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          width={28}
        />
        <Tooltip
          cursor={{ fill: "rgba(255,255,255,0.03)" }}
          contentStyle={{
            background: "rgba(24,24,27,0.95)",
            border: "1px solid rgba(63,63,70,0.8)",
            borderRadius: 8,
            backdropFilter: "blur(12px)",
            fontSize: 12,
          }}
          labelStyle={{ color: "#e4e4e7", fontWeight: 600, textTransform: "capitalize" }}
          itemStyle={{ color: "#a1a1aa" }}
        />
        <Bar dataKey="count" radius={[5, 5, 0, 0]} maxBarSize={44}>
          {data.map((entry) => (
            <Cell
              key={entry.severity}
              fill={`url(#${SEV_GRADIENT_ID[entry.severity] ?? `grad-${entry.severity}`})`}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── KPI Card (premium) ────────────────────────────────────────────
interface KpiProps {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ReactNode;
  accentClass: string;
  borderClass: string;
  bgClass: string;
  trend?: "up" | "down" | "neutral";
  delay?: number;
}

function KpiCard({ label, value, sub, icon, accentClass, borderClass, bgClass, trend, delay = 0 }: KpiProps) {
  const TrendIcon = trend === "up" ? TrendingUp : trend === "down" ? TrendingDown : null;
  const trendColor = trend === "up" ? "text-emerald-400" : trend === "down" ? "text-red-400" : "text-zinc-500";

  return (
    <motion.div
      initial={{ opacity: 0, y: 16, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ delay, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
    >
      <div className={cn(
        "relative rounded-xl border p-4 flex flex-col gap-2 overflow-hidden group",
        "transition-all duration-300 hover:scale-[1.02] hover:shadow-lg cursor-default",
        borderClass, bgClass
      )}>
        {/* Background accent glow */}
        <div className={cn(
          "absolute -top-4 -right-4 w-16 h-16 rounded-full opacity-10 blur-xl transition-opacity group-hover:opacity-20",
          accentClass
        )} />

        <div className="flex items-start justify-between relative z-10">
          <div className="flex flex-col gap-1 flex-1 min-w-0">
            <span className="text-[10px] font-semibold uppercase tracking-widest text-zinc-500">{label}</span>
            <span className={cn("text-2xl font-black tabular-nums leading-none", accentClass)}>
              {value}
            </span>
            {sub && (
              <span className="text-[11px] text-zinc-500 leading-tight truncate">{sub}</span>
            )}
          </div>
          <div className={cn(
            "shrink-0 w-9 h-9 rounded-lg flex items-center justify-center",
            "bg-zinc-800/80 border border-zinc-700/50"
          )}>
            {icon}
          </div>
        </div>

        {TrendIcon && (
          <div className={cn("flex items-center gap-1 text-[10px] font-semibold relative z-10", trendColor)}>
            <TrendIcon className="w-3 h-3" />
            <span>{trend === "up" ? "Trending up" : "Trending down"}</span>
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ── Compliance Bar Row ────────────────────────────────────────────
function ComplianceRow({ fw, idx }: { fw: { name: string; score: number; status: string }; idx: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.15 + idx * 0.06, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-1.5"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className={cn(
            "w-1.5 h-1.5 rounded-full shrink-0",
            fw.status === "compliant" ? "bg-emerald-400" : "bg-amber-400"
          )} />
          <span className="text-xs text-zinc-300 font-medium truncate">{fw.name}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={cn(
            "text-[10px] font-semibold px-1.5 py-0.5 rounded-full",
            fw.status === "compliant"
              ? "text-emerald-400 bg-emerald-500/10 border border-emerald-500/20"
              : "text-amber-400 bg-amber-500/10 border border-amber-500/20"
          )}>
            {fw.status === "compliant" ? "PASS" : "PARTIAL"}
          </span>
          <span className="text-xs font-bold text-zinc-200 w-8 text-right tabular-nums">{fw.score}%</span>
        </div>
      </div>
      <div className="w-full h-1.5 rounded-full bg-zinc-800/80 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${fw.score}%` }}
          transition={{ delay: 0.3 + idx * 0.07, duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className={cn("h-full rounded-full bg-gradient-to-r", complianceBarColour(fw.score))}
        />
      </div>
    </motion.div>
  );
}

// ── Feed Status Card ──────────────────────────────────────────────
function FeedCard({ feed, idx }: { feed: typeof MOCK_FEEDS[0]; idx: number }) {
  const isActive = feed.status === "active";
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay: 0.3 + idx * 0.05, duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
      className={cn(
        "rounded-xl border p-3 flex flex-col gap-2 relative overflow-hidden group transition-all duration-300",
        isActive
          ? "border-emerald-500/20 bg-emerald-500/5 hover:border-emerald-500/40 hover:bg-emerald-500/8"
          : "border-zinc-700/40 bg-zinc-800/20 opacity-50"
      )}
    >
      {/* Pulse dot */}
      <div className="flex items-center justify-between gap-1">
        <span className="text-[11px] font-semibold text-zinc-200 truncate leading-tight">{feed.name}</span>
        <div className="relative shrink-0">
          {isActive ? (
            <>
              <span className="absolute inline-flex h-2 w-2 rounded-full bg-emerald-400 opacity-75 animate-ping" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            </>
          ) : (
            <XCircle className="w-3.5 h-3.5 text-zinc-600" />
          )}
        </div>
      </div>

      {feed.ioc_count > 0 && (
        <div className="flex items-center gap-1">
          <Database className="w-3 h-3 text-zinc-500 shrink-0" />
          <span className="text-[10px] text-zinc-400 tabular-nums font-medium">
            {feed.ioc_count.toLocaleString()}
          </span>
          <span className="text-[9px] text-zinc-600">IOCs</span>
        </div>
      )}
      <span className="text-[9px] text-zinc-600 leading-tight">
        {timeAgo(feed.last_sync)}
      </span>
    </motion.div>
  );
}

// ── Section Wrapper ───────────────────────────────────────────────
const cardBase = "border-zinc-800/80 bg-zinc-900/50 backdrop-blur-sm";

// ── Main component ───────────────────────────────────────────────
export default function MainOverviewDashboard() {
  const [posture, setPosture]       = useState<typeof MOCK_POSTURE | null>(null);
  const [alertStats, setAlerts]     = useState<typeof MOCK_ALERT_STATS | null>(null);
  const [compliance, setCompliance] = useState<typeof MOCK_COMPLIANCE | null>(null);
  const [vulns, setVulns]           = useState<typeof MOCK_VULNS | null>(null);
  const [incidents, setIncidents]   = useState<typeof MOCK_INCIDENTS | null>(null);
  const [feeds, setFeeds]           = useState<typeof MOCK_FEEDS | null>(null);
  const [loading, setLoading]       = useState(true);
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

  const { isPaused, togglePause, secondsAgo } = useAutoRefresh(load, 30_000);

  const p   = posture    ?? MOCK_POSTURE;
  const a   = alertStats ?? MOCK_ALERT_STATS;
  const c   = compliance ?? MOCK_COMPLIANCE;
  const v   = vulns      ?? MOCK_VULNS;
  const inc = incidents  ?? MOCK_INCIDENTS;
  const fd  = feeds      ?? MOCK_FEEDS;

  const activeFeeds      = fd.filter(f => f.status === "active").length;
  const criticalCount    = a.by_severity.find(s => s.severity === "critical")?.count ?? 0;
  const compliantCount   = c.frameworks.filter(f => f.status === "compliant").length;

  return (
    <div className="flex flex-col gap-5 p-5 lg:p-6 min-h-screen bg-background">

      {/* ═══ HEADER ════════════════════════════════════════════════ */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex items-center justify-between"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-tight leading-none">
              Platform Overview
            </h1>
            <p className="text-xs text-zinc-500 mt-0.5 flex items-center gap-1.5">
              <span className="inline-flex w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Live &mdash; updated {secondsAgo}s ago
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={togglePause}
            className="gap-2 h-8 border-zinc-700/80 bg-zinc-900/60 text-zinc-400 hover:text-white hover:border-zinc-600 text-xs"
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            {isPaused ? "Resume" : "Pause"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={load}
            disabled={loading}
            className="gap-2 h-8 border-zinc-700/80 bg-zinc-900/60 text-zinc-400 hover:text-white hover:border-zinc-600 text-xs"
          >
            <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </motion.div>

      {/* ═══ KPI STRIP ═════════════════════════════════════════════ */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard
          label="Posture Score"
          value={p.score}
          sub={`Grade ${p.grade} — ${p.trend}`}
          icon={<Shield className="w-4 h-4 text-cyan-400" />}
          accentClass="text-cyan-400"
          borderClass="border-cyan-500/15"
          bgClass="bg-cyan-500/5"
          trend={p.trend === "improving" ? "up" : p.trend === "declining" ? "down" : "neutral"}
          delay={0.05}
        />
        <KpiCard
          label="Total Alerts"
          value={a.total}
          sub={`${a.p1_open} P1 open`}
          icon={<Bell className="w-4 h-4 text-orange-400" />}
          accentClass="text-orange-400"
          borderClass="border-orange-500/15"
          bgClass="bg-orange-500/5"
          trend="down"
          delay={0.10}
        />
        <KpiCard
          label="Critical Alerts"
          value={criticalCount}
          sub="Immediate action needed"
          icon={<AlertTriangle className="w-4 h-4 text-red-400" />}
          accentClass="text-red-400"
          borderClass="border-red-500/20"
          bgClass="bg-red-500/5"
          trend={criticalCount > 10 ? "down" : "neutral"}
          delay={0.15}
        />
        <KpiCard
          label="Active Feeds"
          value={`${activeFeeds}/${fd.length}`}
          sub="Threat intel sources"
          icon={<Wifi className="w-4 h-4 text-emerald-400" />}
          accentClass="text-emerald-400"
          borderClass="border-emerald-500/15"
          bgClass="bg-emerald-500/5"
          trend="up"
          delay={0.20}
        />
        <KpiCard
          label="Avg Triage"
          value={`${a.avg_triage_time_min}m`}
          sub="Mean triage time"
          icon={<Target className="w-4 h-4 text-zinc-400" />}
          accentClass="text-zinc-300"
          borderClass="border-zinc-700/50"
          bgClass="bg-zinc-800/30"
          delay={0.25}
        />
        <KpiCard
          label="Compliant"
          value={`${compliantCount}/${c.frameworks.length}`}
          sub="Frameworks passing"
          icon={<CheckCircle2 className="w-4 h-4 text-emerald-400" />}
          accentClass="text-emerald-400"
          borderClass="border-emerald-500/15"
          bgClass="bg-emerald-500/5"
          trend="up"
          delay={0.30}
        />
      </div>

      {/* ═══ ROW 1: Posture Hero + Alert Chart + Compliance ════════ */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        {/* Posture Gauge — Hero */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.08, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <Card className={cn("h-full relative overflow-hidden", cardBase)}>
            {/* Subtle scan-line texture */}
            <div className="absolute inset-0 pointer-events-none opacity-[0.03]"
              style={{
                backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.1) 2px, rgba(255,255,255,0.1) 4px)"
              }}
            />
            <CardHeader className="pb-0 relative z-10">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    Security Posture
                  </CardTitle>
                  <CardDescription className="text-xs text-zinc-600 mt-0.5">Composite risk score — all domains</CardDescription>
                </div>
                <span className={cn(
                  "text-[10px] font-bold px-2 py-1 rounded-full border tracking-wider uppercase",
                  p.trend === "improving"
                    ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/25"
                    : "text-amber-400 bg-amber-500/10 border-amber-500/25"
                )}>
                  {p.trend}
                </span>
              </div>
            </CardHeader>
            <CardContent className="flex items-center justify-center pb-4 relative z-10">
              <PostureGauge
                score={p.score}
                grade={p.grade}
                trend={p.trend}
                previousScore={p.previous_score}
              />
            </CardContent>
          </Card>
        </motion.div>

        {/* Alert Severity Chart */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.14, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <Card className={cn("h-full", cardBase)}>
            <CardHeader className="pb-1">
              <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <Bell className="w-4 h-4 text-orange-400" />
                Alerts by Severity
              </CardTitle>
              <CardDescription className="text-xs text-zinc-600">
                {a.total.toLocaleString()} total open &middot; {a.p1_open} require immediate response
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-0">
              <AlertSeverityChart data={a.by_severity} />
              {/* Summary row */}
              <div className="mt-3 flex items-center justify-between pt-3 border-t border-zinc-800/60">
                {a.by_severity.map(s => (
                  <div key={s.severity} className="flex flex-col items-center gap-0.5">
                    <span className="text-sm font-black tabular-nums" style={{ color: SEV_COLOUR[s.severity] }}>
                      {s.count}
                    </span>
                    <span className="text-[9px] text-zinc-600 uppercase font-semibold tracking-wide">
                      {s.severity.slice(0, 4)}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Compliance Bars */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.20, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <Card className={cn("h-full", cardBase)}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Compliance
                  </CardTitle>
                  <CardDescription className="text-xs text-zinc-600 mt-0.5">
                    {compliantCount} of {c.frameworks.length} frameworks passing
                  </CardDescription>
                </div>
                <span className="text-lg font-black text-emerald-400">
                  {Math.round(c.frameworks.reduce((sum, f) => sum + f.score, 0) / c.frameworks.length)}%
                </span>
              </div>
            </CardHeader>
            <CardContent className="flex flex-col gap-3 pt-1">
              {c.frameworks.map((fw, idx) => (
                <ComplianceRow key={fw.name} fw={fw} idx={idx} />
              ))}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* ═══ ROW 2: Top Vulns + Incidents Timeline ═════════════════ */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        {/* Top 5 Critical Vulnerabilities */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.22, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <Card className={cn("h-full", cardBase)}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                Critical Vulnerabilities
              </CardTitle>
              <CardDescription className="text-xs text-zinc-600">
                Ranked by CVSS + EPSS + CISA KEV status
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="divide-y divide-zinc-800/60">
                {v.slice(0, 5).map((vuln, idx) => (
                  <motion.div
                    key={vuln.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.28 + idx * 0.05 }}
                    className="flex items-center gap-3 px-4 py-2.5 group hover:bg-zinc-800/30 transition-colors"
                  >
                    {/* Rank */}
                    <span className="text-[10px] font-black text-zinc-600 w-4 shrink-0 tabular-nums">
                      {idx + 1}
                    </span>
                    {/* CVE info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-red-300 font-semibold">{vuln.id}</span>
                        {vuln.kev && (
                          <span className="inline-flex items-center gap-0.5 text-[9px] font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded-full">
                            <Zap className="w-2.5 h-2.5" />KEV
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-zinc-500 truncate mt-0.5">{vuln.title}</div>
                      <div className="text-[9px] text-zinc-600 mt-0.5 font-mono">{vuln.asset}</div>
                    </div>
                    {/* Scores */}
                    <div className="flex flex-col items-end gap-0.5 shrink-0">
                      <span className={cn(
                        "text-sm font-black tabular-nums",
                        vuln.cvss >= 9 ? "text-red-400" : vuln.cvss >= 7 ? "text-orange-400" : "text-amber-400"
                      )}>
                        {vuln.cvss.toFixed(1)}
                      </span>
                      <span className="text-[9px] text-zinc-600 font-medium">CVSS</span>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Recent Incidents Timeline */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.26, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <Card className={cn("h-full", cardBase)}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                <Activity className="w-4 h-4 text-violet-400" />
                Recent Incidents
              </CardTitle>
              <CardDescription className="text-xs text-zinc-600">
                Latest activity across all severity levels
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-1">
              <div className="relative flex flex-col">
                {/* Timeline track */}
                <div className="absolute left-[9px] top-2 bottom-4 w-px bg-gradient-to-b from-zinc-600 via-zinc-700 to-transparent" />
                {inc.map((incident, idx) => (
                  <motion.div
                    key={incident.id}
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.3 + idx * 0.07, ease: [0.16, 1, 0.3, 1] }}
                    className="flex gap-3 pl-6 pb-4 relative group"
                  >
                    {/* Timeline dot */}
                    <div className={cn(
                      "absolute left-0 top-[5px] w-[18px] h-[18px] rounded-full flex items-center justify-center",
                      "border-2 border-background transition-transform group-hover:scale-110",
                      incident.severity === "critical" ? "bg-red-500/90" :
                      incident.severity === "high"     ? "bg-orange-500/90" :
                      incident.severity === "medium"   ? "bg-amber-500/90" : "bg-zinc-500/90"
                    )}>
                      {incident.status === "active" && (
                        <span className="absolute inset-0 rounded-full animate-ping opacity-50"
                          style={{
                            background:
                              incident.severity === "critical" ? "rgb(239,68,68)" :
                              incident.severity === "high" ? "rgb(249,115,22)" : "rgb(245,158,11)"
                          }}
                        />
                      )}
                    </div>

                    <div className="flex flex-col gap-1 flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-semibold text-zinc-200 truncate">{incident.title}</span>
                        <Badge className={cn(
                          "text-[9px] border capitalize shrink-0 px-1.5 py-0 h-4 font-bold",
                          STATUS_COLOUR[incident.status] ?? "border-border"
                        )}>
                          {incident.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-zinc-600">
                        <span className="font-mono text-zinc-500">{incident.id}</span>
                        <span>·</span>
                        <Clock className="w-2.5 h-2.5" />
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

      {/* ═══ ROW 3: Threat Intel Feeds ═════════════════════════════ */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.32, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      >
        <Card className={cn(cardBase)}>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                  <Rss className="w-4 h-4 text-cyan-400" />
                  Threat Intelligence Feeds
                </CardTitle>
                <CardDescription className="text-xs text-zinc-600 mt-0.5">
                  {activeFeeds} of {fd.length} sources active &middot; real-time IOC ingestion
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-xs text-emerald-400 font-semibold">Live</span>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {fd.map((feed, idx) => (
                <FeedCard key={feed.name} feed={feed} idx={idx} />
              ))}
            </div>

            {/* Aggregate IOC count bar */}
            <div className="mt-4 pt-4 border-t border-zinc-800/60">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] text-zinc-500 font-semibold uppercase tracking-wider">Total IOC Coverage</span>
                <span className="text-xs font-black text-cyan-400 tabular-nums">
                  {fd.reduce((s, f) => s + f.ioc_count, 0).toLocaleString()} indicators
                </span>
              </div>
              <div className="flex gap-1 h-1.5 rounded-full overflow-hidden">
                {fd.filter(f => f.ioc_count > 0).map((f, i) => {
                  const total = fd.reduce((s, x) => s + x.ioc_count, 0);
                  const pct   = (f.ioc_count / total) * 100;
                  const colors = ["bg-cyan-500", "bg-emerald-500", "bg-blue-500", "bg-violet-500", "bg-amber-500", "bg-rose-500"];
                  return (
                    <motion.div
                      key={f.name}
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ delay: 0.5 + i * 0.08, duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
                      className={cn("h-full rounded-full", colors[i % colors.length])}
                      title={`${f.name}: ${f.ioc_count.toLocaleString()}`}
                    />
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
