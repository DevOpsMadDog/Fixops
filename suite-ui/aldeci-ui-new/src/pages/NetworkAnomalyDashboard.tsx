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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

async function apiFetch<T = any>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

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
  const [resolvedSet, setResolvedSet] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [showDetectForm, setShowDetectForm] = useState(false);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [anomalyList, setAnomalyList] = useState<any[]>([]);
  const [baselines, setBaselines] = useState<any[]>([]);
  const [trafficSeries, setTrafficSeries] = useState<Record<string, number[]>>({});
  const [segmentFilter, setSegmentFilter] = useState("");
  const [detectForm, setDetectForm] = useState({ segment: "", protocol: "TCP", bytes: "", packets: "" });

  const loadData = async () => {
    setFetchError(null);
    try {
      const [sumRes, baseRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/network-anomaly/summary"),
        apiFetch<any>("/api/v1/network-anomaly/baselines"),
      ]);
      let aArr: any[] = [];
      if (sumRes.status === "fulfilled") {
        const v = sumRes.value;
        aArr = Array.isArray(v) ? v : (v?.anomalies ?? v?.items ?? []);
        setAnomalyList(aArr);
      } else {
        setFetchError((sumRes.reason as Error).message);
      }
      let bArr: any[] = [];
      if (baseRes.status === "fulfilled") {
        const v = baseRes.value;
        bArr = Array.isArray(v) ? v : (v?.baselines ?? v?.items ?? []);
        setBaselines(bArr);
      }
      const segments = Array.from(new Set([...aArr.map((a: any) => a.segment), ...bArr.map((b: any) => b.segment)].filter(Boolean)));
      if (segments.length && !segmentFilter) {
        setSegmentFilter(segments[0]);
        setDetectForm((f) => ({ ...f, segment: segments[0] }));
      }
      const trendsBySegment: Record<string, number[]> = {};
      await Promise.all(segments.map(async (seg) => {
        try {
          const t = await apiFetch<any>(`/api/v1/network-anomaly/traffic-trend?segment=${encodeURIComponent(seg)}`);
          trendsBySegment[seg] = Array.isArray(t) ? t : (t?.trend ?? t?.data ?? []);
        } catch { trendsBySegment[seg] = []; }
      }));
      setTrafficSeries(trendsBySegment);
    } catch (e) {
      setFetchError(e instanceof Error ? e.message : "Failed to load network anomaly data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, []);

  if (loading) return <PageSkeleton />;

  const anomalies = anomalyList.filter((a) => !resolvedSet.has(a.id));
  const activeAnomalies = anomalies.length;
  const criticalCount = anomalies.filter(a => a.severity === "critical").length;
  const highCount = anomalies.filter(a => a.severity === "high").length;

  const segmentKeys = Object.keys(trafficSeries);
  const trafficData = trafficSeries[segmentFilter] ?? [];
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

      {fetchError && <ErrorState message={fetchError} onRetry={loadData} />}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Anomalies" value={anomalyList.length} icon={<Network className="h-5 w-5" />} />
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
                    {segmentKeys.map(s => <option key={s}>{s}</option>)}
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
              {anomalies.length === 0 && !fetchError ? <EmptyState icon={Activity} title="No anomalies detected" description="Baselines look healthy. Run detection to scan for deviations." /> : (
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
                    {anomalies.map(a => (
                      <tr key={a.id} className="border-b border-zinc-700/50 hover:bg-zinc-700/20">
                        <td className="py-2 px-2 text-zinc-300 whitespace-nowrap">{a.segment ?? "—"}</td>
                        <td className="py-2 px-2"><Badge className={cn("text-[9px] border", PROTOCOL_COLORS[a.protocol] ?? "border-zinc-600 text-zinc-400")}>{a.protocol ?? "—"}</Badge></td>
                        <td className="py-2 px-2"><Badge className={cn("text-[9px] border capitalize", ANOMALY_TYPE_COLORS[a.anomaly_type] ?? "border-zinc-600 text-zinc-400")}>{a.anomaly_type ?? "—"}</Badge></td>
                        <td className="py-2 px-2"><Badge className={cn("text-[9px] border capitalize", SEVERITY_COLORS[a.severity] ?? "border-zinc-600 text-zinc-400")}>{a.severity ?? "—"}</Badge></td>
                        <td className={cn("py-2 px-2 font-mono font-bold", (a.deviation_pct ?? 0) > 0 ? "text-red-400" : "text-blue-400")}>
                          {(a.deviation_pct ?? 0) > 0 ? "+" : ""}{a.deviation_pct ?? 0}%
                        </td>
                        <td className="py-2 px-2 text-zinc-400 font-mono">{(a.baseline ?? 0).toLocaleString()}</td>
                        <td className="py-2 px-2 text-white font-mono">{(a.observed ?? 0).toLocaleString()}</td>
                        <td className="py-2 px-2 text-zinc-500 whitespace-nowrap">{a.detected_at ? timeAgo(a.detected_at) : "—"}</td>
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
              )}
            </CardContent>
          </Card>

          {/* Traffic Trend Chart */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <CardTitle className="text-sm text-zinc-200">Traffic Trend (bytes/min)</CardTitle>
                <select className="ml-auto bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-white"
                  value={segmentFilter} onChange={e => setSegmentFilter(e.target.value)}>
                  {segmentKeys.map(s => <option key={s}>{s}</option>)}
                </select>
              </div>
            </CardHeader>
            <CardContent>
              {trafficData.length === 0 ? <EmptyState icon={BarChart2} title="No traffic data" description="Submit traffic samples for this segment to populate the trend chart." /> : (
              <div className="flex items-end gap-1.5 h-28">
                {trafficData.map((v, i) => {
                  const pct = (v / maxTraffic) * 100;
                  const isSpike = v > maxTraffic * 0.6;
                  return (
                    <div key={i} className="flex-1 flex flex-col items-center gap-1">
                      <div className={cn("w-full rounded-sm", isSpike ? "bg-red-500" : "bg-blue-500")} style={{ height: `${Math.max(4, pct)}px` }} />
                      <span className="text-[9px] text-zinc-500">T{i + 1}</span>
                    </div>
                  );
                })}
              </div>
              )}
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
              {baselines.length === 0 ? <EmptyState icon={Wifi} title="No baselines" description="Update baselines to track normal traffic patterns." /> : baselines.map((b: any) => (
                <div key={b.id ?? `${b.segment}-${b.protocol}`} className="border border-zinc-700 rounded-lg p-3 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-zinc-300">{b.segment}</span>
                    <Badge className={cn("text-[9px] border", PROTOCOL_COLORS[b.protocol] ?? "border-zinc-600 text-zinc-400")}>{b.protocol}</Badge>
                  </div>
                  <BytesBar value={b.avg_bytes ?? 0} max={20000} />
                  <div className="flex justify-between text-[10px] text-zinc-500">
                    <span>σ={(b.std_dev ?? 0).toLocaleString()}</span>
                    <Badge className="text-[9px] border border-zinc-600 text-zinc-400">{(b.sample_count ?? 0).toLocaleString()} samples</Badge>
                  </div>
                  <p className="text-[10px] text-zinc-600">Baseline: {b.baseline_date ?? "—"}</p>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
