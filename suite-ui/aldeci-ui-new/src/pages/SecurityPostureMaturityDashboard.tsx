/**
 * Security Posture Maturity Dashboard
 *
 * Overall maturity level gauge (1.0-5.0), 10-domain breakdown, roadmap table,
 * overdue reviews alert, snapshot sparkline, advance roadmap button.
 *
 * Route: /posture-maturity
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/posture-maturity";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { Shield, Star, AlertTriangle, ChevronRight, TrendingUp, Clock } from "lucide-react";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────────────────────

const MOCK_OVERALL = 3.4;

const MOCK_DOMAINS = [
  { name: "Identity & Access",    avg_level: 4.2, capability_count: 12 },
  { name: "Network Security",     avg_level: 3.8, capability_count: 9  },
  { name: "Endpoint Protection",  avg_level: 3.5, capability_count: 11 },
  { name: "Data Security",        avg_level: 3.2, capability_count: 8  },
  { name: "Cloud Security",       avg_level: 2.9, capability_count: 10 },
  { name: "Application Security", avg_level: 2.7, capability_count: 7  },
  { name: "Threat Intelligence",  avg_level: 3.6, capability_count: 6  },
  { name: "Incident Response",    avg_level: 4.0, capability_count: 9  },
  { name: "Compliance & GRC",     avg_level: 3.1, capability_count: 14 },
  { name: "Supply Chain Risk",    avg_level: 1.8, capability_count: 5  },
];

const MOCK_ROADMAP = [
  { capability: "Zero Trust Network Access",  current: 2, target: 4, priority: "critical", effort: "high",   status: "in_progress", timeline: "Q2 2026", owner: "NetSec Team"   },
  { capability: "SBOM Integration",           current: 1, target: 3, priority: "high",     effort: "medium", status: "planned",     timeline: "Q3 2026", owner: "AppSec Team"   },
  { capability: "Automated Threat Hunting",   current: 2, target: 4, priority: "high",     effort: "high",   status: "in_progress", timeline: "Q2 2026", owner: "SOC Team"      },
  { capability: "Supply Chain Vetting",       current: 1, target: 3, priority: "critical", effort: "medium", status: "planned",     timeline: "Q2 2026", owner: "Risk Team"     },
  { capability: "AI-Assisted Triage",         current: 3, target: 5, priority: "medium",   effort: "low",    status: "in_progress", timeline: "Q1 2026", owner: "SOC Team"      },
  { capability: "Data Classification Engine", current: 2, target: 4, priority: "high",     effort: "medium", status: "completed",   timeline: "Q1 2026", owner: "Data Team"     },
  { capability: "Cloud Posture Benchmarking", current: 2, target: 4, priority: "medium",   effort: "high",   status: "planned",     timeline: "Q4 2026", owner: "Cloud Team"    },
  { capability: "Continuous Pen Testing",     current: 1, target: 3, priority: "high",     effort: "high",   status: "planned",     timeline: "Q3 2026", owner: "Red Team"      },
];

const MOCK_OVERDUE = [
  { domain: "Supply Chain Risk",    last_review: "2025-10-10", days_overdue: 188 },
  { domain: "Application Security", last_review: "2025-12-01", days_overdue: 136 },
  { domain: "Cloud Security",       last_review: "2026-01-15", days_overdue: 91  },
];

const MOCK_HISTORY = [
  { date: "2025-10", level: 2.6 },
  { date: "2025-11", level: 2.8 },
  { date: "2025-12", level: 2.9 },
  { date: "2026-01", level: 3.0 },
  { date: "2026-02", level: 3.1 },
  { date: "2026-03", level: 3.3 },
  { date: "2026-04", level: 3.4 },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

function domainColor(level: number) {
  if (level >= 4) return "text-green-400";
  if (level >= 3) return "text-teal-400";
  if (level >= 2) return "text-yellow-400";
  return "text-red-400";
}

function domainBg(level: number) {
  if (level >= 4) return "bg-green-400";
  if (level >= 3) return "bg-teal-400";
  if (level >= 2) return "bg-yellow-400";
  return "bg-red-400";
}

function priorityBadge(p: string) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    low:      "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  };
  return cls[p] ?? "bg-gray-700 text-gray-300";
}

function effortBadge(e: string) {
  const cls: Record<string, string> = {
    high:   "bg-purple-500/20 text-purple-400",
    medium: "bg-blue-500/20 text-blue-400",
    low:    "bg-gray-700 text-gray-300",
  };
  return cls[e] ?? "bg-gray-700 text-gray-300";
}

function statusBadge(s: string) {
  const cls: Record<string, string> = {
    planned:     "bg-gray-700 text-gray-300",
    in_progress: "bg-blue-500/20 text-blue-400",
    completed:   "bg-green-500/20 text-green-400",
  };
  return cls[s] ?? "bg-gray-700 text-gray-300";
}

function Stars({ level }: { level: number }) {
  return (
    <span className="flex gap-0.5">
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
      {[1,2,3,4,5].map(i => (
        <Star key={i} className={cn("w-3.5 h-3.5", i <= Math.round(level) ? "fill-yellow-400 text-yellow-400" : "text-gray-600")} />
      ))}
    </span>
  );
}

// ── Maturity gauge (SVG arc) ───────────────────────────────────────────────────

function MaturityGauge({ value }: { value: number }) {
  const min = 1, max = 5;
  const pct = (value - min) / (max - min);
  const r = 80, cx = 100, cy = 100;
  const startAngle = -210, sweepAngle = 240;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const arcX = (a: number) => cx + r * Math.cos(toRad(a));
  const arcY = (a: number) => cy + r * Math.sin(toRad(a));
  const endAngle = startAngle + sweepAngle * pct;
  const largeArc = sweepAngle * pct > 180 ? 1 : 0;
  const trackEnd = startAngle + sweepAngle;
  const color = pct >= 0.8 ? "#22c55e" : pct >= 0.6 ? "#14b8a6" : pct >= 0.4 ? "#eab308" : "#ef4444";

  return (
    <svg viewBox="0 0 200 160" className="w-48 h-36">
      <path
        d={`M ${arcX(startAngle)} ${arcY(startAngle)} A ${r} ${r} 0 1 1 ${arcX(trackEnd)} ${arcY(trackEnd)}`}
        fill="none" stroke="#1e293b" strokeWidth="16" strokeLinecap="round"
      />
      {pct > 0.01 && (
        <path
          d={`M ${arcX(startAngle)} ${arcY(startAngle)} A ${r} ${r} 0 ${largeArc} 1 ${arcX(endAngle)} ${arcY(endAngle)}`}
          fill="none" stroke={color} strokeWidth="16" strokeLinecap="round"
        />
      )}
      <text x="100" y="108" textAnchor="middle" fill={color} fontSize="28" fontWeight="bold">{value.toFixed(1)}</text>
      <text x="100" y="125" textAnchor="middle" fill="#94a3b8" fontSize="10">/ 5.0 Maturity</text>
      <text x="30" y="140" fill="#64748b" fontSize="8">1.0</text>
      <text x="162" y="140" fill="#64748b" fontSize="8">5.0</text>
    </svg>
  );
}

// ── Sparkline ─────────────────────────────────────────────────────────────────

function Sparkline({ data }: { data: typeof MOCK_HISTORY }) {
  const vals = data.map(d => d.level);
  const min = Math.min(...vals) - 0.2;
  const max = Math.max(...vals) + 0.2;
  const W = 300, H = 60;
  const pts = data.map((d, i) => {
    const x = (i / (data.length - 1)) * W;
    const y = H - ((d.level - min) / (max - min)) * H;
    return `${x},${y}`;
  });
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-16">
      <polyline points={pts.join(" ")} fill="none" stroke="#14b8a6" strokeWidth="2" strokeLinejoin="round" />
      {data.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
          <p className="text-lg font-medium">No data available</p>
          <p className="text-sm">Data will appear here once available</p>
        </div>
      ) : (
        data.map((d, i) => {
        const x = (i / (data.length - 1)) * W;
        const y = H - ((d.level - min) / (max - min)) * H;
        return (
          <g key={i}>
            <circle cx={x} cy={y} r="3" fill="#14b8a6" />
            <text x={x} y={H - 2} textAnchor="middle" fill="#64748b" fontSize="7">{d.date}</text>
          </g>
        );
      })
      )}
    </svg>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function SecurityPostureMaturityDashboard() {
  const [advanced, setAdvanced] = useState(false);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch(_API_BASE, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-teal-500/10 rounded-lg">
            <Shield className="w-6 h-6 text-teal-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Security Posture Maturity</h1>
            <p className="text-sm text-gray-400">Capability maturity model across 10 security domains</p>
          </div>
        </div>
        <button
          onClick={() => setAdvanced(v => !v)}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            advanced
              ? "bg-teal-600 text-white"
              : "bg-gray-800 text-gray-300 hover:bg-gray-700"
          )}
        >
          <TrendingUp className="inline w-4 h-4 mr-1" />
          {advanced ? "Roadmap Advanced" : "Advance Roadmap"}
        </button>
      </div>

      {/* Top row: gauge + overdue + sparkline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gauge */}
        <div className="bg-gray-800 rounded-lg p-6 flex flex-col items-center justify-center">
          <p className="text-xs text-gray-400 uppercase tracking-wider mb-2">Overall Maturity Level</p>
          <MaturityGauge value={MOCK_OVERALL} />
          <p className="text-sm text-gray-400 mt-2">
            {MOCK_OVERALL >= 4 ? "Optimized" : MOCK_OVERALL >= 3 ? "Defined" : MOCK_OVERALL >= 2 ? "Developing" : "Initial"}
          </p>
        </div>

        {/* Overdue reviews */}
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            <h3 className="font-semibold text-orange-400">Overdue Reviews</h3>
          </div>
          {MOCK_OVERDUE.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            MOCK_OVERDUE.map(o => (
            <div key={o.domain} className="flex items-center justify-between py-2 border-b border-gray-700/50 last:border-0">
              <div>
                <p className="text-sm font-medium text-white">{o.domain}</p>
                <p className="text-xs text-gray-400">Last: {o.last_review}</p>
              </div>
              <span className="px-2 py-1 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                {o.days_overdue}d overdue
              </span>
            </div>
          )))}
        </div>

        {/* Sparkline */}
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-5 h-5 text-teal-400" />
            <h3 className="font-semibold text-white">Maturity Trend</h3>
          </div>
          <Sparkline data={MOCK_HISTORY} />
          <p className="text-xs text-gray-400 mt-2 text-center">
            +{(MOCK_HISTORY[MOCK_HISTORY.length-1].level - MOCK_HISTORY[0].level).toFixed(1)} improvement over 7 months
          </p>
        </div>
      </div>

      {/* Domain breakdown grid */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Domain Breakdown</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {MOCK_DOMAINS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            MOCK_DOMAINS.map(d => (
            <div key={d.name} className="bg-gray-900 rounded-lg p-4">
              <p className="text-xs text-gray-400 mb-1 truncate" title={d.name}>{d.name}</p>
              <p className={cn("text-2xl font-bold", domainColor(d.avg_level))}>{d.avg_level.toFixed(1)}</p>
              <Stars level={d.avg_level} />
              <div className="mt-2 w-full bg-gray-700 rounded-full h-1.5">
                <div
                  )))}
                  style={{ width: `${((d.avg_level - 1) / 4) * 100}%` }}
                />
              </div>
              <p className="text-xs text-gray-500 mt-1">{d.capability_count} capabilities</p>
            </div>
          )))}
        </div>
      </div>

      {/* Roadmap table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Capability Roadmap</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Capability</th>
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Level</th>
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Priority</th>
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Effort</th>
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Status</th>
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Timeline</th>
                <th className="text-left text-gray-400 font-medium py-2">Owner</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_ROADMAP.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                MOCK_ROADMAP.map(r => (
                <tr key={r.capability} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4 font-medium text-white">{r.capability}</td>
                  <td className="py-2.5 pr-4">
                    <div className="flex items-center gap-1 text-xs text-gray-300">
                      <span className="text-yellow-400 font-bold">{r.current}</span>
                      <ChevronRight className="w-3 h-3 text-gray-500" />
                      <span className="text-green-400 font-bold">{r.target}</span>
                    </div>
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium", priorityBadge(r.priority))}>
                      {r.priority}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium", effortBadge(r.effort))}>
                      {r.effort}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium", statusBadge(r.status))}>
                      {r.status.replace("_", " ")}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4 text-gray-300 flex items-center gap-1">
                    <Clock className="w-3 h-3 text-gray-500" />
                    {r.timeline}
                  </td>
                  <td className="py-2.5 text-gray-400 text-xs">{r.owner}</td>
                </tr>
              )))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
