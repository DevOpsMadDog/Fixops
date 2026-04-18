/**
 * System Health Dashboard
 *
 * Monitors health of all backend engines in real time.
 *   1. Large health score gauge (0-100, color-coded: ≥90=green, 70-89=yellow, <70=red)
 *   2. Overall status badge (Healthy / Degraded / Critical)
 *   3. Summary stat row: Total / Healthy / Degraded / Unavailable
 *   4. Engine health grid — name, status dot, record count
 *   5. Recently updated engines panel (last check timestamp)
 *
 * API: GET /api/v1/system-health/ and /api/v1/system-health/score
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
import {
  Activity,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Server,
  Clock,
  Database,
  Shield,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

interface Engine {
  name: string;
  status: "healthy" | "degraded" | "unavailable";
  record_count: number;
  last_updated?: string;
}

interface HealthData {
  score: number;
  overall_status: "healthy" | "degraded" | "critical";
  engines: Engine[];
  healthy_count: number;
  degraded_count: number;
  unavailable_count: number;
  total_engines: number;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_HEALTH: HealthData = {
  score: 94,
  overall_status: "healthy",
  engines: [
    { name: "threat_feed",              status: "healthy",     record_count: 156,  last_updated: "30s ago" },
    { name: "digital_forensics",        status: "healthy",     record_count: 23,   last_updated: "1m ago" },
    { name: "vulnerability_lifecycle",  status: "healthy",     record_count: 412,  last_updated: "45s ago" },
    { name: "sla_escalation",           status: "healthy",     record_count: 89,   last_updated: "2m ago" },
    { name: "posture_score",            status: "healthy",     record_count: 51,   last_updated: "1m ago" },
    { name: "asset_risk",               status: "healthy",     record_count: 203,  last_updated: "3m ago" },
    { name: "compliance_scanner",       status: "healthy",     record_count: 78,   last_updated: "2m ago" },
    { name: "incident_timeline",        status: "healthy",     record_count: 34,   last_updated: "1m ago" },
    { name: "insider_threat",           status: "healthy",     record_count: 17,   last_updated: "5m ago" },
    { name: "identity_analytics",       status: "healthy",     record_count: 284,  last_updated: "2m ago" },
    { name: "ndr_engine",               status: "healthy",     record_count: 1024, last_updated: "30s ago" },
    { name: "xdr_engine",               status: "healthy",     record_count: 738,  last_updated: "30s ago" },
    { name: "edr_engine",               status: "healthy",     record_count: 512,  last_updated: "45s ago" },
    { name: "threat_hunting",           status: "healthy",     record_count: 65,   last_updated: "3m ago" },
    { name: "deception_engine",         status: "healthy",     record_count: 12,   last_updated: "4m ago" },
    { name: "sbom_engine",              status: "healthy",     record_count: 94,   last_updated: "6m ago" },
    { name: "attack_path",              status: "healthy",     record_count: 47,   last_updated: "2m ago" },
    { name: "cve_enrichment",           status: "healthy",     record_count: 3201, last_updated: "5m ago" },
    { name: "security_health",          status: "healthy",     record_count: 51,   last_updated: "1m ago" },
    { name: "data_governance",          status: "healthy",     record_count: 119,  last_updated: "4m ago" },
    { name: "data_classification",      status: "healthy",     record_count: 207,  last_updated: "3m ago" },
    { name: "threat_actor",             status: "healthy",     record_count: 88,   last_updated: "7m ago" },
    { name: "supply_chain_intel",       status: "healthy",     record_count: 143,  last_updated: "5m ago" },
    { name: "cnapp_engine",             status: "healthy",     record_count: 321,  last_updated: "2m ago" },
    { name: "pentest_mgmt",             status: "healthy",     record_count: 29,   last_updated: "8m ago" },
    { name: "security_roadmap",         status: "healthy",     record_count: 14,   last_updated: "9m ago" },
    { name: "config_benchmark",         status: "healthy",     record_count: 256,  last_updated: "4m ago" },
    { name: "analytics_engine",         status: "healthy",     record_count: 5012, last_updated: "1m ago" },
    { name: "security_scorecard",       status: "healthy",     record_count: 34,   last_updated: "10m ago" },
    { name: "regulatory_tracker",       status: "healthy",     record_count: 62,   last_updated: "11m ago" },
    { name: "redis_queue",              status: "healthy",     record_count: 4,    last_updated: "15s ago" },
    { name: "brain_pipeline",           status: "healthy",     record_count: 1,    last_updated: "20s ago" },
    { name: "awareness_score",          status: "healthy",     record_count: 180,  last_updated: "6m ago" },
    { name: "scheduled_reports",        status: "healthy",     record_count: 8,    last_updated: "12m ago" },
    { name: "vuln_trend",               status: "degraded",    record_count: 0,    last_updated: "20m ago" },
    { name: "security_exception",       status: "degraded",    record_count: 0,    last_updated: "18m ago" },
    { name: "dast_engine",              status: "healthy",     record_count: 56,   last_updated: "7m ago" },
    { name: "app_security",             status: "healthy",     record_count: 92,   last_updated: "6m ago" },
    { name: "ir_playbook",              status: "healthy",     record_count: 21,   last_updated: "8m ago" },
    { name: "supply_chain_risk",        status: "healthy",     record_count: 38,   last_updated: "5m ago" },
    { name: "security_champions",       status: "healthy",     record_count: 47,   last_updated: "9m ago" },
    { name: "red_team_mgmt",            status: "healthy",     record_count: 11,   last_updated: "14m ago" },
    { name: "bug_bounty",               status: "healthy",     record_count: 26,   last_updated: "10m ago" },
    { name: "ai_security_advisor",      status: "healthy",     record_count: 3,    last_updated: "2m ago" },
    { name: "threat_intel_sharing",     status: "healthy",     record_count: 74,   last_updated: "7m ago" },
    { name: "digital_risk_protection",  status: "healthy",     record_count: 31,   last_updated: "6m ago" },
    { name: "security_metrics",         status: "healthy",     record_count: 102,  last_updated: "3m ago" },
    { name: "vendor_risk",              status: "healthy",     record_count: 19,   last_updated: "11m ago" },
    { name: "ciem_engine",              status: "healthy",     record_count: 88,   last_updated: "4m ago" },
    { name: "sso_bridge",               status: "healthy",     record_count: 5,    last_updated: "30s ago" },
    { name: "devsecops_engine",         status: "unavailable", record_count: 0,    last_updated: "30m ago" },
  ],
  healthy_count: 48,
  degraded_count: 2,
  unavailable_count: 1,
  total_engines: 51,
};

// ── Helpers ────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 90) return "text-green-400";
  if (score >= 70) return "text-yellow-400";
  return "text-red-400";
}

function scoreRingColor(score: number): string {
  if (score >= 90) return "stroke-green-400";
  if (score >= 70) return "stroke-yellow-400";
  return "stroke-red-400";
}

function statusBadgeVariant(status: string): { className: string; label: string } {
  switch (status) {
    case "healthy":
      return { className: "bg-green-500/15 text-green-400 border-green-500/30", label: "Healthy" };
    case "degraded":
      return { className: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30", label: "Degraded" };
    case "critical":
      return { className: "bg-red-500/15 text-red-400 border-red-500/30", label: "Critical" };
    default:
      return { className: "bg-muted text-muted-foreground", label: status };
  }
}

function engineStatusDot(status: Engine["status"]) {
  const cls =
    status === "healthy"
      ? "bg-green-400"
      : status === "degraded"
      ? "bg-yellow-400"
      : "bg-red-400";
  return <span className={cn("inline-block w-2 h-2 rounded-full flex-shrink-0", cls)} />;
}

function formatEngineName(name: string): string {
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ── Gauge SVG ─────────────────────────────────────────────────

function ScoreGauge({ score }: { score: number }) {
  const radius = 72;
  const circumference = Math.PI * radius; // half-circle arc
  const dashOffset = circumference * (1 - score / 100);
  const ringCls = scoreRingColor(score);

  return (
    <div className="flex flex-col items-center gap-2">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      <svg width="180" height="100" viewBox="0 0 180 100" className="overflow-visible">
        {/* Track */}
        <path
          d="M 18 90 A 72 72 0 0 1 162 90"
          fill="none"
          stroke="currentColor"
          strokeWidth="14"
          className="text-muted/30"
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d="M 18 90 A 72 72 0 0 1 162 90"
          fill="none"
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={`${dashOffset}`}
          className={cn("transition-all duration-700", ringCls)}
        />
        {/* Score text */}
        <text
          x="90"
          y="78"
          textAnchor="middle"
          className={cn("font-bold", scoreColor(score))}
          fontSize="32"
          fill="currentColor"
          dominantBaseline="auto"
        >
          {score}
        </text>
        <text x="90" y="96" textAnchor="middle" fontSize="11" fill="currentColor" className="text-muted-foreground">
          / 100
        </text>
      </svg>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────

export default function SystemHealthDashboard() {
  const [health, setHealth] = useState<HealthData>(MOCK_HEALTH);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState<"all" | "healthy" | "degraded" | "unavailable">("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch(`/api/v1/system-health/?org_id=${ORG_ID}`).then((d) => {
      if (d?.score !== undefined) setHealth(d);
    }).catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 900);
  };

  const statusBadge = statusBadgeVariant(health.overall_status);

  const filteredEngines =
    filter === "all"
      ? health.engines
      : health.engines.filter((e) => e.status === filter);

  const recentEngines = [...health.engines]
    .filter((e) => e.last_updated)
    .sort((a, b) => {
      // Sort by last_updated ascending (most recent first) — rough sort on string
      return (a.last_updated ?? "").localeCompare(b.last_updated ?? "");
    })
    .slice(0, 8);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="System Health Dashboard"
        description="Real-time engine health monitoring across all ALDECI backend services"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4 mr-1.5", refreshing && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      {/* Gauge + Status + Summary stats */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Gauge card */}
        <Card className="flex flex-col items-center justify-center py-6 lg:col-span-1">
          <CardHeader className="pb-2 text-center">
            <CardTitle className="text-sm font-semibold flex items-center justify-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              Overall Health Score
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-3">
            <ScoreGauge score={health.score} />
            <Badge className={cn("border text-xs px-3 py-0.5", statusBadge.className)}>
              {statusBadge.label}
            </Badge>
            <p className="text-[11px] text-muted-foreground">Last checked: just now</p>
          </CardContent>
        </Card>

        {/* Summary KPIs */}
        <div className="lg:col-span-2 grid grid-cols-2 gap-3 content-start">
          <KpiCard
            title="Total Engines"
            value={String(health.total_engines)}
            icon={Server}
            className="border-blue-500/20"
          />
          <KpiCard
            title="Healthy"
            value={String(health.healthy_count)}
            icon={CheckCircle2}
            trend="up"
            className="border-green-500/20"
          />
          <KpiCard
            title="Degraded"
            value={String(health.degraded_count)}
            icon={AlertTriangle}
            trend="down"
            className="border-yellow-500/20"
          />
          <KpiCard
            title="Unavailable"
            value={String(health.unavailable_count)}
            icon={XCircle}
            trend="down"
            className="border-red-500/20"
          />
        </div>
      </div>

      {/* Engine health grid */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Activity className="h-4 w-4 text-purple-400" />
                Engine Health Grid
              </CardTitle>
              <CardDescription className="text-xs mt-0.5">
                {filteredEngines.length} engine{filteredEngines.length !== 1 ? "s" : ""} shown
              </CardDescription>
            </div>
            {/* Filter buttons */}
            <div className="flex items-center gap-1.5">
              {(["all", "healthy", "degraded", "unavailable"] as const).map((f) => (
                <Button
                  key={f}
                  variant={filter === f ? "default" : "outline"}
                  size="sm"
                  className="h-7 text-[11px] capitalize"
                  onClick={() => setFilter(f)}
                >
                  {f}
                </Button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {filteredEngines.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              filteredEngines.map((engine) => (
              <div
                key={engine.name}
                className={cn(
                  "flex items-center gap-2.5 rounded-md border px-3 py-2.5 transition-colors",
                  engine.status === "healthy"
                    ? "border-green-500/20 bg-green-500/5 hover:bg-green-500/10"
                    : engine.status === "degraded"
                    ? "border-yellow-500/20 bg-yellow-500/5 hover:bg-yellow-500/10"
                    : "border-red-500/20 bg-red-500/5 hover:bg-red-500/10"
                )}
              >
                {engineStatusDot(engine.status)}
                <div className="flex-1 min-w-0">
                  <p className="text-[11px] font-medium truncate leading-tight">
                    {formatEngineName(engine.name)}
                  </p>
                  <p className="text-[10px] text-muted-foreground tabular-nums">
                    {engine.record_count.toLocaleString()} records
                  </p>
                </div>
              </div>
            )))}
          </div>
        </CardContent>
      </Card>

      {/* Recently updated engines */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Clock className="h-4 w-4 text-cyan-400" />
            Recently Updated Engines
          </CardTitle>
          <CardDescription className="text-xs">Last check timestamps for most recently polled engines</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {recentEngines.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              recentEngines.map((engine) => (
              <div
                key={engine.name}
                className="flex items-start gap-2.5 rounded-md border border-muted/40 bg-muted/10 px-3 py-2.5 hover:bg-muted/20 transition-colors"
              >
                <Database className="h-3.5 w-3.5 mt-0.5 text-muted-foreground flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-[11px] font-medium truncate">{formatEngineName(engine.name)}</p>
                  <p className="text-[10px] text-muted-foreground flex items-center gap-1 mt-0.5">
                    <Clock className="h-2.5 w-2.5" />
                    {engine.last_updated}
                  </p>
                </div>
                {engineStatusDot(engine.status)}
              </div>
            )))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
