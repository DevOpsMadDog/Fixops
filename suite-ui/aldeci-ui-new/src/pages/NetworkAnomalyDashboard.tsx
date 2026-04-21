/**
 * Network Anomaly Dashboard
 *
 * Real-time network anomaly detection with baseline comparison and traffic trends.
 * Route: /network-anomaly
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Activity, AlertTriangle, TrendingUp, TrendingDown,
  CheckCircle2, PlusCircle, Network, BarChart2, Wifi,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock Data ──────────────────────────────────────────────────

const MOCK_ANOMALIES = [
  { id: "anm-001", segment: "DMZ", protocol: "TCP", anomaly_type: "spike", severity: "critical", deviation_pct: 340, baseline: 1200, observed: 5280, detected_at: "2026-04-16T10:32:00Z", resolved: false },
  { id: "anm-002", segment: "Corporate LAN", protocol: "UDP", anomaly_type: "spike", severity: "high", deviation_pct: 187, baseline: 3400, observed: 9758, detected_at: "2026-04-16T10:18:00Z", resolved: false },
  { id: "anm-003", segment: "OT Network", protocol: "ICMP", anomaly_type: "drop", severity: "high", deviation_pct: -72, baseline: 820, observed: 230, detected_at: "2026-04-16T09:55:00Z", resolved: false },
  { id: "anm-004", segment: "Cloud VPC", protocol: "HTTPS", anomaly_type: "spike", severity: "medium", deviation_pct: 95, baseline: 14200, observed: 27690, detected_at: "2026-04-16T09:40:00Z", resolved: false },
  { id: "anm-005", segment: "Guest WiFi", protocol: "DNS", anomaly_type: "spike", severity: "medium", deviation_pct: 143, baseline: 680, observed: 1650, detected_at: "2026-04-16T09:22:00Z", resolved: false },
  { id: "anm-006", segment: "Management", protocol: "SSH", anomaly_type: "drop", severity: "low", deviation_pct: -38, baseline: 240, observed: 149, detected_at: "2026-04-16T09:10:00Z", resolved: true },
  { id: "anm-007", segment: "Data Center", protocol: "TCP", anomaly_type: "spike", severity: "critical", deviation_pct: 510, baseline: 8800, observed: 53688, detected_at: "2026-04-16T08:58:00Z", resolved: false },
  { id: "anm-008", segment: "IoT Network", protocol: "MQTT", anomaly_type: "drop", severity: "medium", deviation_pct: -61, baseline: 1100, observed: 429, detected_at: "2026-04-16T08:45:00Z", resolved: false },
];

const MOCK_BASELINES = [
  { id: "bl-001", segment: "DMZ", protocol: "TCP", avg_bytes: 1200, std_dev: 148, sample_count: 8640, baseline_date: "2026-03-16" },
  { id: "bl-002", segment: "Corporate LAN", protocol: "UDP", avg_bytes: 3400, std_dev: 512, sample_count: 8640, baseline_date: "2026-03-16" },
  { id: "bl-003", segment: "OT Network", protocol: "ICMP", avg_bytes: 820, std_dev: 94, sample_count: 8640, baseline_date: "2026-03-16" },
  { id: "bl-004", segment: "Cloud VPC", protocol: "HTTPS", avg_bytes: 14200, std_dev: 2100, sample_count: 8640, baseline_date: "2026-03-16" },
  { id: "bl-005", segment: "Guest WiFi", protocol: "DNS", avg_bytes: 680, std_dev: 87, sample_count: 8640, baseline_date: "2026-03-16" },
  { id: "bl-006", segment: "Data Center", protocol: "TCP", avg_bytes: 8800, std_dev: 1340, sample_count: 8640, baseline_date: "2026-03-16" },
];

const MOCK_TRAFFIC = {
  DMZ: [1100, 1250, 1180, 1300, 5280, 3100, 2400, 1600],
  "Corporate LAN": [3200, 3500, 3400, 3800, 9758, 7200, 5100, 3900],
  "Cloud VPC": [13800, 14100, 14200, 15100, 27690, 21000, 18500, 16200],
  "OT Network": [800, 820, 810, 790, 230, 350, 540, 700],
};

// ── Helpers ────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const ANOMALY_TYPE_COLORS: Record<string, string> = {
  spike: "bg-red-500/15 text-red-400 border-red-500/30",
  drop:  "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

const PROTOCOL_COLORS: Record<string, string> = {
  TCP:   "bg-blue-500/15 text-blue-400 border-blue-500/30",
  UDP:   "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  ICMP:  "bg-teal-500/15 text-teal-400 border-teal-500/30",
  HTTPS: "bg-green-500/15 text-green-400 border-green-500/30",
  DNS:   "bg-purple-500/15 text-purple-400 border-purple-500/30",
  SSH:   "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  MQTT:  "bg-orange-500/15 text-orange-400 border-orange-500/30",
};

function timeAgo(iso: string) {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 60) return `${mins}m ago`;
  return `${Math.round(mins / 60)}h ago`;
}

function BytesBar({ value, max }: { value: number; max: number }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
        <div className="h-full bg-blue-500 rounded-full" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-zinc-400 w-14 text-right font-mono">{value.toLocaleString()}</span>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function NetworkAnomalyDashboard() {
  const [resolvedSet, setResolvedSet] = useState<Set<string>>(new Set(["anm-006"]));
  const [loading, setLoading] = useState(true);
  const [segmentFilter, setSegmentFilter] = useState("DMZ");
  const [showDetectForm, setShowDetectForm] = useState(false);

  const [fetchError, setFetchError] = useState<string | null>(null);

  const loadData = () => {
    setFetchError(null);
    apiFetch(`/api/v1/network-anomaly/anomalies?org_id=${ORG_ID}`).catch((err) => {
      setFetchError(err instanceof Error ? err.message : "Failed to load network anomaly data");
    });
  };

  useEffect(() => {
    loadData();
  }, []);
  const [detectForm, setDetectForm] = useState({ segment: "DMZ", protocol: "TCP", bytes: "", packets: "" });

  const anomalies = MOCK_ANOMALIES.filter(a => !resolvedSet.has(a.id));
  const activeAnomalies = anomalies.length;
  const criticalCount = anomalies.filter(a => a.severity === "critical").length;
  const highCount = anomalies.filter(a => a.severity === "high").length;

  const trafficData = MOCK_TRAFFIC[segmentFilter as keyof typeof MOCK_TRAFFIC] ?? [];
  const maxTraffic = Math.max(...trafficData, 1);

  const sevDist = ["critical", "high", "medium", "low"].map(s => ({
    label: s, count: anomalies.filter(a => a.severity === s).length,
  }));

  const maxSev = Math.max(...sevDist.map(s => s.count), 1);

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <PageHeader
        title="Network Anomaly Detection"
        description="Real-time network traffic anomaly detection and baseline deviation monitoring"
      />

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors">Retry</button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Anomalies" value={MOCK_ANOMALIES.length} icon={<Network className="h-5 w-5" />} />
        <KpiCard title="Active" value={activeAnomalies} icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
        <KpiCard title="Critical" value={criticalCount} icon={<AlertTriangle className="h-5 w-5 text-red-500" />} />
        <KpiCard title="High" value={highCount} icon={<TrendingUp className="h-5 w-5 text-orange-400" />} />
      </div>

      {/* Detect Form */}
      <div className="flex justify-end">
        <Button size="sm" variant="outline" className="border-zinc-700 text-zinc-300 text-xs" onClick={() => setShowDetectForm(v => !v)}>
          <PlusCircle className="h-3 w-3 mr-1" /> Detect Anomaly
        </Button>
      </div>

      {showDetectForm && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">Manual Anomaly Detection</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <div>
                  <label className="text-[10px] text-zinc-500 mb-1 block">Segment</label>
                  <select className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white" value={detectForm.segment} onChange={e => setDetectForm(p => ({ ...p, segment: e.target.value }))}>
                    {Object.keys(MOCK_TRAFFIC).map(s => <option key={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-zinc-500 mb-1 block">Protocol</label>
                  <select className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white" value={detectForm.protocol} onChange={e => setDetectForm(p => ({ ...p, protocol: e.target.value }))}>
                    {["TCP","UDP","ICMP","HTTPS","DNS","SSH","MQTT"].map(p => <option key={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-zinc-500 mb-1 block">Bytes/min</label>
                  <input className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white" placeholder="e.g. 9800" value={detectForm.bytes} onChange={e => setDetectForm(p => ({ ...p, bytes: e.target.value }))} />
                </div>
                <div>
                  <label className="text-[10px] text-zinc-500 mb-1 block">Packets/min</label>
                  <input className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white" placeholder="e.g. 1200" value={detectForm.packets} onChange={e => setDetectForm(p => ({ ...p, packets: e.target.value }))} />
                </div>
              </div>
              <Button size="sm" className="mt-3 bg-red-600 hover:bg-red-700 text-xs" onClick={() => setShowDetectForm(false)}>Run Detection</Button>
            </CardContent>
          </Card>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Anomalies */}
        <div className="lg:col-span-2 space-y-4">
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">Active Anomalies</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-zinc-700">
                      {["Segment", "Protocol", "Type", "Severity", "Deviation", "Baseline", "Observed", "Detected", ""].map(h => (
                        <th key={h} className="text-left py-2 px-2 text-zinc-500 font-medium whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {MOCK_ANOMALIES.filter(a => !resolvedSet.has(a.id)).map(a => (
                      <tr key={a.id} className="border-b border-zinc-700/50 hover:bg-zinc-700/20">
                        <td className="py-2 px-2 text-zinc-300 whitespace-nowrap">{a.segment}</td>
                        <td className="py-2 px-2"><Badge className={cn("text-[9px] border", PROTOCOL_COLORS[a.protocol] ?? "border-zinc-600 text-zinc-400")}>{a.protocol}</Badge></td>
                        <td className="py-2 px-2"><Badge className={cn("text-[9px] border capitalize", ANOMALY_TYPE_COLORS[a.anomaly_type])}>{a.anomaly_type}</Badge></td>
                        <td className="py-2 px-2"><Badge className={cn("text-[9px] border capitalize", SEVERITY_COLORS[a.severity])}>{a.severity}</Badge></td>
                        <td className={cn("py-2 px-2 font-mono font-bold", a.deviation_pct > 0 ? "text-red-400" : "text-blue-400")}>
                          {a.deviation_pct > 0 ? "+" : ""}{a.deviation_pct}%
                        </td>
                        <td className="py-2 px-2 text-zinc-400 font-mono">{a.baseline.toLocaleString()}</td>
                        <td className="py-2 px-2 text-white font-mono">{a.observed.toLocaleString()}</td>
                        <td className="py-2 px-2 text-zinc-500 whitespace-nowrap">{timeAgo(a.detected_at)}</td>
                        <td className="py-2 px-2">
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px] text-green-400 hover:text-green-300"
                            onClick={() => setResolvedSet(s => new Set([...s, a.id]))}>
                            Resolve
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Traffic Trend Chart */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <CardTitle className="text-sm text-zinc-200">Traffic Trend (bytes/min)</CardTitle>
                <select className="ml-auto bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-white"
                  value={segmentFilter} onChange={e => setSegmentFilter(e.target.value)}>
                  {Object.keys(MOCK_TRAFFIC).map(s => <option key={s}>{s}</option>)}
                </select>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex items-end gap-1.5 h-28">
                {trafficData.map((v, i) => {
                  const pct = (v / maxTraffic) * 100;
                  const isSpike = v > maxTraffic * 0.6;

                  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

                  return (
                    <div key={i} className="flex-1 flex flex-col items-center gap-1">
                      <div className={cn("w-full rounded-sm", isSpike ? "bg-red-500" : "bg-blue-500")} style={{ height: `${Math.max(4, pct)}px` }} />
                      <span className="text-[9px] text-zinc-500">T{i + 1}</span>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Panel */}
        <div className="space-y-4">
          {/* Severity Distribution */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">Severity Distribution</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {sevDist.map(s => (
                <div key={s.label}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="capitalize text-zinc-300">{s.label}</span>
                    <span className="text-zinc-400">{s.count}</span>
                  </div>
                  <div className="h-2 bg-zinc-700 rounded-full overflow-hidden">
                    <div className={cn("h-full rounded-full", s.label === "critical" ? "bg-red-500" : s.label === "high" ? "bg-orange-500" : s.label === "medium" ? "bg-yellow-500" : "bg-zinc-500")}
                      style={{ width: `${(s.count / maxSev) * 100}%` }} />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Baseline Health */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">Baseline Health</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {MOCK_BASELINES.map(b => (
                <div key={b.id} className="border border-zinc-700 rounded-lg p-3 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-zinc-300">{b.segment}</span>
                    <Badge className={cn("text-[9px] border", PROTOCOL_COLORS[b.protocol] ?? "border-zinc-600 text-zinc-400")}>{b.protocol}</Badge>
                  </div>
                  <BytesBar value={b.avg_bytes} max={20000} />
                  <div className="flex justify-between text-[10px] text-zinc-500">
                    <span>σ={b.std_dev.toLocaleString()}</span>
                    <Badge className="text-[9px] border border-zinc-600 text-zinc-400">{b.sample_count.toLocaleString()} samples</Badge>
                  </div>
                  <p className="text-[10px] text-zinc-600">Baseline: {b.baseline_date}</p>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
