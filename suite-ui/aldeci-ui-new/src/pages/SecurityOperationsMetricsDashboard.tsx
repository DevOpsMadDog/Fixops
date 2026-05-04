/**
 * Security Operations Metrics Dashboard
 *
 * MTTD + MTTR SVG arc gauges, 7-day snapshot trend, alert volume cards,
 * analyst leaderboard, alert queue table with ack/resolve actions.
 *
 * Route: /soc-metrics
 * API:   GET /api/v1/soc-metrics
 *        GET /api/v1/soc-metrics/snapshots
 *        GET /api/v1/soc-metrics/analysts
 *        GET /api/v1/soc-metrics/queue
 */

import { useState, useEffect } from "react";
import { Activity, Clock, Users, AlertOctagon, CheckCircle } from "lucide-react";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ── Types ──────────────────────────────────────────────────────────────────────

interface SocStats {
  mttd_minutes: number;
  mttr_minutes: number;
  total_alerts: number;
  critical_alerts: number;
  false_positive_rate: number;
  resolution_rate: number;
}

interface Snapshot { date: string; mttd: number; mttr: number; }

interface Analyst {
  name: string;
  alerts_resolved: number;
  avg_resolution_mins: number;
  efficiency: string;
}

interface Alert {
  id: string;
  severity: string;
  category: string;
  source: string;
  detected_at: string;
  status: string;
  assigned_to: string;
}

const EMPTY_STATS: SocStats = {
  mttd_minutes: 0, mttr_minutes: 0, total_alerts: 0,
  critical_alerts: 0, false_positive_rate: 0, resolution_rate: 0,
};

// ── Helpers ────────────────────────────────────────────────────────────────────

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    low:      "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}

function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    open:         "bg-red-500/20 text-red-400",
    acknowledged: "bg-yellow-500/20 text-yellow-400",
    resolved:     "bg-green-500/20 text-green-400",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}

function EfficiencyBadge({ e }: { e: string }) {
  const cls: Record<string, string> = {
    excellent: "bg-green-500/20 text-green-400",
    good:      "bg-teal-500/20 text-teal-400",
    average:   "bg-yellow-500/20 text-yellow-400",
    below_avg: "bg-red-500/20 text-red-400",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[e] ?? "bg-gray-700 text-gray-300")}>{e.replace("_", " ")}</span>;
}

function timeAge(iso: string) {
  const d = new Date(iso);
  const now = new Date();
  const mins = Math.max(0, Math.round((now.getTime() - d.getTime()) / 60000));
  if (mins < 60) return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ${mins % 60}m ago`;
}

// ── SVG Gauge ──────────────────────────────────────────────────────────────────

function MetricGauge({ label, value, max, unit, color }: {
  label: string; value: number; max: number; unit: string; color: string;
}) {
  const pct = Math.min(value / max, 1);
  const r = 70, cx = 90, cy = 90;
  const startAngle = -210, sweepAngle = 240;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const arcX = (a: number) => cx + r * Math.cos(toRad(a));
  const arcY = (a: number) => cy + r * Math.sin(toRad(a));
  const endAngle = startAngle + sweepAngle * pct;
  const largeArc = sweepAngle * pct > 180 ? 1 : 0;
  const trackEnd = startAngle + sweepAngle;

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 180 140" className="w-44 h-32">
        <path
          d={`M ${arcX(startAngle)} ${arcY(startAngle)} A ${r} ${r} 0 1 1 ${arcX(trackEnd)} ${arcY(trackEnd)}`}
          fill="none" stroke="#1e293b" strokeWidth="14" strokeLinecap="round"
        />
        {pct > 0.01 && (
          <path
            d={`M ${arcX(startAngle)} ${arcY(startAngle)} A ${r} ${r} 0 ${largeArc} 1 ${arcX(endAngle)} ${arcY(endAngle)}`}
            fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
          />
        )}
        <text x="90" y="92" textAnchor="middle" fill={color} fontSize="22" fontWeight="bold">{value}</text>
        <text x="90" y="108" textAnchor="middle" fill="#94a3b8" fontSize="9">{unit}</text>
      </svg>
      <p className="text-sm text-gray-300 font-medium -mt-2">{label}</p>
    </div>
  );
}

// ── Trend bars ────────────────────────────────────────────────────────────────

function TrendChart({ data }: { data: Snapshot[] }) {
  if (!data.length) return <p className="text-xs text-gray-500">No snapshot data available.</p>;
  const maxMttd = Math.max(...data.map(d => d.mttd), 1);
  const maxMttr = Math.max(...data.map(d => d.mttr), 1);
  return (
    <div className="space-y-4">
      {data.map(d => (
        <div key={d.date} className="grid grid-cols-[60px_1fr_1fr] gap-3 items-center text-xs">
          <span className="text-gray-400">{d.date}</span>
          <div className="flex items-center gap-1">
            <div className="flex-1 bg-gray-700 rounded h-2">
              <div className="h-2 rounded bg-teal-500" style={{ width: `${(d.mttd / maxMttd) * 100}%` }} />
            </div>
            <span className="text-teal-400 w-8 text-right">{d.mttd}m</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="flex-1 bg-gray-700 rounded h-2">
              <div className="h-2 rounded bg-orange-500" style={{ width: `${(d.mttr / maxMttr) * 100}%` }} />
            </div>
            <span className="text-orange-400 w-10 text-right">{d.mttr}m</span>
          </div>
        </div>
      ))}
      <div className="grid grid-cols-[60px_1fr_1fr] gap-3 text-xs text-gray-500 border-t border-gray-700 pt-2">
        <span />
        <span className="text-teal-500">MTTD</span>
        <span className="text-orange-500">MTTR</span>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function SecurityOperationsMetricsDashboard() {
  const [loading, setLoading]     = useState(true);
  const [stats, setStats]         = useState<SocStats>(EMPTY_STATS);
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [analysts, setAnalysts]   = useState<Analyst[]>([]);
  const [queue, setQueue]         = useState<Alert[]>([]);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/soc-metrics"),
      apiFetch("/api/v1/soc-metrics/snapshots"),
      apiFetch("/api/v1/soc-metrics/analysts"),
      apiFetch("/api/v1/soc-metrics/queue"),
    ]).then(([statsRes, snapshotsRes, analystsRes, queueRes]) => {
      if (statsRes.status === "fulfilled")     setStats(statsRes.value?.stats ?? statsRes.value ?? EMPTY_STATS);
      if (snapshotsRes.status === "fulfilled") setSnapshots(snapshotsRes.value?.snapshots ?? snapshotsRes.value ?? []);
      if (analystsRes.status === "fulfilled")  setAnalysts(analystsRes.value?.analysts ?? analystsRes.value ?? []);
      if (queueRes.status === "fulfilled")     setQueue(queueRes.value?.alerts ?? queueRes.value ?? []);
    }).finally(() => setLoading(false));
  }, []);

  function ackAlert(id: string) {
    setQueue(prev => prev.map(a => a.id === id && a.status === "open" ? { ...a, status: "acknowledged" } : a));
    fetch(`${API_BASE}/api/v1/soc-metrics/queue/${id}/ack`, {
      method: "POST",
      headers: { "X-API-Key": API_KEY },
    }).catch(() => {});
  }

  function resolveAlert(id: string) {
    setQueue(prev => prev.map(a => a.id === id ? { ...a, status: "resolved" } : a));
    fetch(`${API_BASE}/api/v1/soc-metrics/queue/${id}/resolve`, {
      method: "POST",
      headers: { "X-API-Key": API_KEY },
    }).catch(() => {});
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-500" />
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-teal-500/10 rounded-lg">
          <Activity className="w-6 h-6 text-teal-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">SOC Operations Metrics</h1>
          <p className="text-sm text-gray-400">Mean time to detect &amp; respond, analyst performance, alert queue</p>
        </div>
      </div>

      {/* Alert volume cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Alerts",       value: stats.total_alerts,                       suffix: "",  color: "text-white",      icon: <AlertOctagon className="w-5 h-5 text-gray-400" /> },
          { label: "Critical",           value: stats.critical_alerts,                    suffix: "",  color: "text-red-400",    icon: <AlertOctagon className="w-5 h-5 text-red-400" /> },
          { label: "False Positive Rate",value: stats.false_positive_rate.toFixed(1),     suffix: "%", color: "text-yellow-400", icon: <Clock className="w-5 h-5 text-yellow-400" /> },
          { label: "Resolution Rate",    value: stats.resolution_rate.toFixed(1),         suffix: "%", color: "text-green-400",  icon: <CheckCircle className="w-5 h-5 text-green-400" /> },
        ].map(c => (
          <div key={c.label} className="bg-gray-800 rounded-lg p-4 flex items-center gap-3">
            {c.icon}
            <div>
              <p className="text-xs text-gray-400">{c.label}</p>
              <p className={cn("text-2xl font-bold", c.color)}>{c.value}{c.suffix}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Gauges + trend */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-gray-800 rounded-lg p-6 flex items-center justify-around">
          <MetricGauge label="MTTD" value={stats.mttd_minutes} max={120} unit="minutes" color="#14b8a6" />
          <MetricGauge label="MTTR" value={stats.mttr_minutes} max={480} unit="minutes" color="#f97316" />
        </div>
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">7-Day Snapshot Trend</h2>
          <TrendChart data={snapshots} />
        </div>
      </div>

      {/* Analyst leaderboard */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center gap-2 mb-4">
          <Users className="w-5 h-5 text-blue-400" />
          <h2 className="text-lg font-semibold text-white">Analyst Leaderboard</h2>
        </div>
        {analysts.length === 0 ? (
          <p className="text-sm text-gray-500">No analyst data available.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left text-gray-400 font-medium py-2 pr-4">Rank</th>
                  <th className="text-left text-gray-400 font-medium py-2 pr-4">Analyst</th>
                  <th className="text-left text-gray-400 font-medium py-2 pr-4">Alerts Resolved</th>
                  <th className="text-left text-gray-400 font-medium py-2 pr-4">Avg Resolution</th>
                  <th className="text-left text-gray-400 font-medium py-2">Efficiency</th>
                </tr>
              </thead>
              <tbody>
                {analysts.map((a, i) => (
                  <tr key={a.name} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                    <td className="py-2.5 pr-4">
                      <span className={cn("w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold",
                        i === 0 ? "bg-yellow-500/20 text-yellow-400" : i === 1 ? "bg-gray-400/20 text-gray-300" : "bg-gray-700 text-gray-400"
                      )}>#{i + 1}</span>
                    </td>
                    <td className="py-2.5 pr-4 font-medium text-white">{a.name}</td>
                    <td className="py-2.5 pr-4 text-teal-400 font-bold">{a.alerts_resolved}</td>
                    <td className="py-2.5 pr-4 text-gray-300">{a.avg_resolution_mins} min</td>
                    <td className="py-2.5"><EfficiencyBadge e={a.efficiency} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Alert queue */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Alert Queue</h2>
        {queue.length === 0 ? (
          <p className="text-sm text-gray-500">No alerts in queue.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  {["Severity", "Category", "Source", "Age", "Status", "Assigned To", "Actions"].map(h => (
                    <th key={h} className="text-left text-gray-400 font-medium py-2 pr-4 whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {queue.map(a => (
                  <tr key={a.id} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                    <td className="py-2.5 pr-4"><SeverityBadge s={a.severity} /></td>
                    <td className="py-2.5 pr-4 text-gray-200">{a.category}</td>
                    <td className="py-2.5 pr-4">
                      <span className="px-2 py-0.5 bg-gray-700 rounded text-xs text-gray-300">{a.source}</span>
                    </td>
                    <td className="py-2.5 pr-4 text-xs text-gray-400">{timeAge(a.detected_at)}</td>
                    <td className="py-2.5 pr-4"><StatusBadge s={a.status} /></td>
                    <td className="py-2.5 pr-4 text-xs text-gray-300">{a.assigned_to}</td>
                    <td className="py-2.5 flex gap-1">
                      {a.status === "open" && (
                        <button onClick={() => ackAlert(a.id)} className="px-2 py-0.5 bg-yellow-600/30 hover:bg-yellow-600/50 text-yellow-400 rounded text-xs">Ack</button>
                      )}
                      {a.status !== "resolved" && (
                        <button onClick={() => resolveAlert(a.id)} className="px-2 py-0.5 bg-green-600/30 hover:bg-green-600/50 text-green-400 rounded text-xs">Resolve</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
