/**
 * Network Traffic Analysis
 * Route: /network-analysis
 *
 * API:
 *   GET /api/v1/ndr/stats          — KPI counts
 *   GET /api/v1/ndr/alerts         — anomaly feed
 *   GET /api/v1/network-monitoring/stats — top-talker flows + protocol breakdown
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertTriangle, Activity, Shield, Globe, Network,
  Radio, Ban, Eye, CheckCircle, Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

async function apiFetch(path: string) {
  const res = await fetch(`${API}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Types ──────────────────────────────────────────────────────────────────────
type ThreatLevel = "critical" | "high" | "medium" | "low";
type FlowAction  = "block" | "monitor" | "allow";

interface TopTalker {
  id: string;
  src: string;
  flag?: string;
  country?: string;
  dst: string;
  proto?: string;
  protocol?: string;
  bytes?: string;
  bytes_transferred?: number;
  score: number;
  threat_score?: number;
  action: FlowAction;
}

interface Anomaly {
  id: string;
  ts?: string;
  timestamp?: string;
  created_at?: string;
  type?: string;
  alert_type?: string;
  src?: string;
  source_ip?: string;
  dst?: string;
  destination_ip?: string;
  severity: ThreatLevel;
}

interface ProtocolEntry {
  label: string;
  pct: number;
  color: string;
}

interface RegionEntry {
  label: string;
  level: string;
  cls: string;
}

// ── Static display constants ──────────────────────────────────────────────────
// Protocol + region are display-only UI scaffolding; no dedicated API endpoint exists.
// They render as informational panels; when real data is available, replace these.
const PROTOCOL_DISPLAY: ProtocolEntry[] = [
  { label: "HTTPS", pct: 67, color: "bg-blue-500"   },
  { label: "DNS",   pct: 12, color: "bg-purple-500" },
  { label: "HTTP",  pct: 8,  color: "bg-orange-500" },
  { label: "Other", pct: 7,  color: "bg-slate-500"  },
  { label: "SSH",   pct: 4,  color: "bg-yellow-500" },
  { label: "RDP",   pct: 2,  color: "bg-red-500"    },
];

const REGION_DISPLAY: RegionEntry[] = [
  { label: "North America", level: "low",    cls: "bg-green-500/20 border-green-500/40"  },
  { label: "Europe",        level: "medium", cls: "bg-yellow-500/20 border-yellow-500/40" },
  { label: "Russia",        level: "high",   cls: "bg-red-500/30 border-red-500/60"      },
  { label: "China",         level: "high",   cls: "bg-red-500/30 border-red-500/60"      },
  { label: "SE Asia",       level: "medium", cls: "bg-yellow-500/20 border-yellow-500/40" },
  { label: "Middle East",   level: "medium", cls: "bg-yellow-500/20 border-yellow-500/40" },
  { label: "Africa",        level: "low",    cls: "bg-green-500/20 border-green-500/40"  },
  { label: "Oceania",       level: "low",    cls: "bg-green-500/20 border-green-500/40"  },
];

const SEV_CLR: Record<ThreatLevel, string> = {
  critical: "text-red-400 bg-red-500/20",
  high:     "text-orange-400 bg-orange-500/20",
  medium:   "text-yellow-400 bg-yellow-500/20",
  low:      "text-green-400 bg-green-500/20",
};

const ACT_CFG: Record<FlowAction, { label: string; cls: string; icon: React.ReactNode }> = {
  block:   { label: "Block",   cls: "text-red-400 bg-red-500/10",      icon: <Ban className="w-3 h-3 mr-1" /> },
  monitor: { label: "Monitor", cls: "text-yellow-400 bg-yellow-500/10", icon: <Eye className="w-3 h-3 mr-1" /> },
  allow:   { label: "Allow",   cls: "text-green-400 bg-green-500/10",  icon: <CheckCircle className="w-3 h-3 mr-1" /> },
};

function normaliseTalker(f: Record<string, unknown>, i: number): TopTalker {
  const score = Number(f.threat_score ?? f.score ?? f.risk_score ?? 0);
  let action: FlowAction = "monitor";
  if (f.action) {
    action = String(f.action) as FlowAction;
  } else if (score >= 80) {
    action = "block";
  } else if (score <= 10) {
    action = "allow";
  }
  const bytesRaw = f.bytes_transferred ?? f.bytes_sent ?? f.bytes ?? 0;
  const bytesStr = typeof bytesRaw === "number"
    ? bytesRaw >= 1e9 ? `${(bytesRaw / 1e9).toFixed(1)} GB`
    : bytesRaw >= 1e6 ? `${(bytesRaw / 1e6).toFixed(1)} MB`
    : bytesRaw >= 1e3 ? `${(bytesRaw / 1e3).toFixed(0)} KB`
    : `${bytesRaw} B`
    : String(bytesRaw);
  return {
    id:      String(f.id ?? f.flow_id ?? i),
    src:     String(f.src ?? f.source_ip ?? f.src_ip ?? "unknown"),
    flag:    String(f.flag ?? ""),
    country: String(f.country ?? f.geo_country ?? ""),
    dst:     String(f.dst ?? f.destination_ip ?? f.dst_ip ?? ""),
    proto:   String(f.proto ?? f.protocol ?? ""),
    bytes:   bytesStr,
    score,
    action,
  };
}

function normaliseAnomaly(a: Record<string, unknown>, i: number): Anomaly {
  const rawSev = String(a.severity ?? a.alert_severity ?? "medium").toLowerCase();
  const severity: ThreatLevel = (["critical","high","medium","low"] as ThreatLevel[]).includes(rawSev as ThreatLevel)
    ? (rawSev as ThreatLevel) : "medium";
  return {
    id:        String(a.id ?? a.alert_id ?? i),
    ts:        String(a.ts ?? a.timestamp ?? a.created_at ?? a.detected_at ?? ""),
    type:      String(a.type ?? a.alert_type ?? a.anomaly_type ?? "Alert"),
    src:       String(a.src ?? a.source_ip ?? ""),
    dst:       String(a.dst ?? a.destination_ip ?? ""),
    severity,
  };
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function NetworkAnalysis() {
  const [search, setSearch] = useState("");

  // NDR stats — KPI row
  const { data: ndrStats } = useQuery({
    queryKey: ["ndr-stats"],
    queryFn:  () => apiFetch("/api/v1/ndr/stats?org_id=default").catch(() => null),
  });

  // NDR alerts — anomaly feed
  const { data: ndrAlerts = [], isLoading: l2 } = useQuery({
    queryKey: ["ndr-alerts"],
    queryFn:  async () => {
      const d = await apiFetch("/api/v1/ndr/alerts?org_id=default&limit=20");
      const arr: unknown[] = Array.isArray(d) ? d : (d.items ?? d.alerts ?? []);
      return (arr as Record<string, unknown>[]).map((a, i) => normaliseAnomaly(a, i));
    },
  });

  // Network-monitoring stats — top talkers (flows)
  const { data: talkers = [], isLoading: l1 } = useQuery({
    queryKey: ["network-monitoring-stats"],
    queryFn:  async () => {
      const d = await apiFetch("/api/v1/network-monitoring/stats?org_id=default");
      // The endpoint returns aggregate stats; if it also carries a flows array, use it.
      const arr: unknown[] = Array.isArray(d)
        ? d
        : (d.flows ?? d.top_talkers ?? d.items ?? []);
      return (arr as Record<string, unknown>[]).map((f, i) => normaliseTalker(f, i));
    },
  });

  const anomalies = ndrAlerts as Anomaly[];
  const flows     = talkers  as TopTalker[];

  const filtered = flows.filter((t) =>
    !search ||
    t.src.includes(search) ||
    (t.country ?? "").toLowerCase().includes(search.toLowerCase())
  );

  const s = ndrStats as Record<string, unknown> | null;

  return (
    <div className="min-h-screen bg-slate-950">
      <PageHeader
        title="Network Traffic Analysis"
        description="Anomaly detection, top talkers, and threat communication monitoring"
        actions={
          <Button className="bg-red-600 hover:bg-red-700">
            <Shield className="w-4 h-4 mr-2" />Block All Threats
          </Button>
        }
      />
      <div className="p-6 max-w-7xl mx-auto space-y-6">

        {/* KPIs */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard title="Alerts Today"        value={Number(s?.open_alerts     ?? s?.total_alerts ?? 0)} trend="up"   trendLabel="from NDR engine"   icon={AlertTriangle} />
          <KpiCard title="C2 Suspects"         value={Number(s?.c2_suspects     ?? 0)}                   trend="up"   trendLabel="Active now"         icon={Activity}     />
          <KpiCard title="Blocked Connections" value={Number(s?.blocked         ?? s?.high_risk_flows ?? 0)} trend="up"   trendLabel="high-risk flows"    icon={Ban}          />
          <KpiCard title="External Flows"      value={Number(s?.external_flows  ?? 0)}                   trend="flat" trendLabel="monitored segments"  icon={Zap}          />
        </div>

        {/* Top Talkers */}
        <Card className="border-slate-700 bg-slate-900/40">
          <CardHeader className="border-b border-slate-700 pb-4">
            <div className="flex items-center justify-between gap-4">
              <CardTitle className="flex items-center gap-2">
                <Network className="w-5 h-5 text-blue-400" />Top Talkers
              </CardTitle>
              <input
                placeholder="Filter IP / country…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="h-8 w-44 rounded border border-slate-700 bg-slate-800/50 px-3 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
          </CardHeader>
          <CardContent className="pt-0 overflow-x-auto">
            {l1 ? (
              <p className="text-slate-400 py-4 px-4">Loading…</p>
            ) : filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-slate-500 gap-2">
                <Network className="w-8 h-8 opacity-30" />
                <p className="text-sm">No flow data available</p>
                <p className="text-xs">Network flows will appear once the monitoring engine collects data</p>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    {["Source IP","Country","Destination","Protocol","Bytes","Threat Score","Action"].map((h) => (
                      <th key={h} className="text-left py-3 px-3 font-semibold text-slate-300 text-xs">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((t, i) => (
                    <motion.tr
                      key={t.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.04 }}
                      className="border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors"
                    >
                      <td className="py-2.5 px-3 font-mono text-slate-200 text-xs">{t.src}</td>
                      <td className="py-2.5 px-3 text-slate-300 text-xs">{t.flag} {t.country}</td>
                      <td className="py-2.5 px-3 font-mono text-slate-400 text-xs">{t.dst}</td>
                      <td className="py-2.5 px-3">
                        <Badge variant="outline" className="border-slate-600 text-slate-300 text-xs">{t.proto}</Badge>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 text-xs">{t.bytes}</td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div
                              className={cn("h-full rounded-full", t.score >= 80 ? "bg-red-500" : t.score >= 40 ? "bg-yellow-500" : "bg-green-500")}
                              style={{ width: `${t.score}%` }}
                            />
                          </div>
                          <span className={cn("text-xs font-semibold", t.score >= 80 ? "text-red-400" : t.score >= 40 ? "text-yellow-400" : "text-green-400")}>
                            {t.score}
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <Badge variant="outline" className={cn("border-0 text-xs flex items-center w-fit", ACT_CFG[t.action]?.cls)}>
                          {ACT_CFG[t.action]?.icon}{ACT_CFG[t.action]?.label}
                        </Badge>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>

        {/* Protocol Distribution + Anomaly Feed */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="border-slate-700 bg-slate-900/40">
            <CardHeader className="border-b border-slate-700 pb-4">
              <CardTitle className="flex items-center gap-2">
                <Radio className="w-5 h-5 text-purple-400" />Protocol Distribution
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-5 space-y-3">
              {PROTOCOL_DISPLAY.map((p, i) => (
                <div key={p.label} className="space-y-1">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-300">{p.label}</span>
                    <span className="text-slate-400 font-semibold">{p.pct}%</span>
                  </div>
                  <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${p.pct}%` }}
                      transition={{ delay: i * 0.05, duration: 0.5 }}
                      className={cn("h-full rounded-full", p.color)}
                    />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <div className="lg:col-span-2">
            <Card className="border-slate-700 bg-slate-900/40 h-full">
              <CardHeader className="border-b border-slate-700 pb-4">
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2">
                    <Zap className="w-5 h-5 text-yellow-400" />Anomaly Feed
                  </CardTitle>
                  <span className="flex items-center gap-1 text-xs text-green-400">
                    <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
                    Real-time
                  </span>
                </div>
              </CardHeader>
              <CardContent className="pt-4 space-y-3">
                {l2 ? (
                  <p className="text-slate-400">Loading…</p>
                ) : anomalies.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-10 text-slate-500 gap-2">
                    <CheckCircle className="w-7 h-7 opacity-30" />
                    <p className="text-sm">No active anomalies</p>
                    <p className="text-xs">Network is clean — no alerts from the NDR engine</p>
                  </div>
                ) : (
                  anomalies.map((a, i) => (
                    <motion.div
                      key={a.id}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.06 }}
                      className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50"
                    >
                      <AlertTriangle className="w-4 h-4 text-orange-400 mt-0.5 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-xs font-semibold text-slate-200">{a.type}</span>
                          <Badge variant="outline" className={cn("border-0 h-5 text-xs", SEV_CLR[a.severity])}>
                            {a.severity.toUpperCase()}
                          </Badge>
                        </div>
                        <p className="text-xs text-slate-400 font-mono truncate">
                          {a.src} {a.dst ? `→ ${a.dst}` : ""}
                        </p>
                      </div>
                      {a.ts && <span className="text-xs text-slate-500 shrink-0">{String(a.ts).slice(11, 19) || a.ts}</span>}
                    </motion.div>
                  ))
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Geo Regions */}
        <Card className="border-slate-700 bg-slate-900/40">
          <CardHeader className="border-b border-slate-700 pb-4">
            <CardTitle className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-cyan-400" />Geo Threat Regions
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <div className="grid grid-cols-4 gap-2">
              {REGION_DISPLAY.map((r, i) => (
                <motion.div
                  key={r.label}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: i * 0.05 }}
                  className={cn("rounded-lg border p-3 text-center", r.cls)}
                >
                  <p className="text-xs font-semibold text-slate-200 leading-tight mb-1">{r.label}</p>
                  <p className={cn(
                    "text-xs capitalize font-medium",
                    r.level === "high" ? "text-red-300" : r.level === "medium" ? "text-yellow-300" : "text-green-300"
                  )}>
                    {r.level}
                  </p>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>

      </div>
    </div>
  );
}
