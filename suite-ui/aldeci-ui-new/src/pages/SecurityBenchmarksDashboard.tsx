/**
 * Security Benchmarks Dashboard
 *
 * Compare org security metrics against industry benchmarks (p25/p50/p75/p90).
 * Performance badges, sector filter, source badges, trend lines.
 *
 * Route: /security-benchmarks
 */

import { useState, useEffect } from "react";
import { BarChart2, TrendingUp, TrendingDown, Minus, RefreshCw, Target } from "lucide-react";

// == Types =====================================================================

type Sector = "all" | "financial" | "technology" | "healthcare" | "manufacturing";
type Performance = "above-average" | "average" | "below-average" | "lagging";
type Source = "Gartner" | "Verizon-DBIR" | "SANS" | "NIST" | "Mandiant" | "IBM";

interface BenchmarkMetric {
  id: string;
  metric_name: string;
  category: string;
  our_value: number;
  unit: string;
  p25: number;
  p50: number;
  p75: number;
  p90: number;
  lower_is_better: boolean;
  performance: Performance;
  sectors: Sector[];
  source: Source;
  trend: number[]; // 6-point sparkline values
}

// == Mock data =================================================================

const MOCK_METRICS: BenchmarkMetric[] = [
  { id: "bm-001", metric_name: "Mean Time to Detect (MTTD)",     category: "Incident Response", our_value: 4.2,   unit: "hours",   p25: 24,  p50: 12,   p75: 6,    p90: 3,    lower_is_better: true,  performance: "above-average", sectors: ["financial", "technology"],      source: "IBM",          trend: [18, 14, 11, 8, 5.5, 4.2] },
  { id: "bm-002", metric_name: "Mean Time to Respond (MTTR)",    category: "Incident Response", our_value: 8.1,   unit: "hours",   p25: 48,  p50: 24,   p75: 12,   p90: 6,    lower_is_better: true,  performance: "above-average", sectors: ["financial", "technology"],      source: "IBM",          trend: [36, 28, 19, 14, 10, 8.1] },
  { id: "bm-003", metric_name: "Phishing Click Rate",            category: "Awareness",         our_value: 6.8,   unit: "%",       p25: 18,  p50: 11,   p75: 7,    p90: 4,    lower_is_better: true,  performance: "average",       sectors: ["all"],                          source: "Verizon-DBIR", trend: [14, 12, 10, 9, 8, 6.8] },
  { id: "bm-004", metric_name: "Patch Cadence (Critical)",       category: "Vulnerability",     our_value: 3.2,   unit: "days",    p25: 14,  p50: 7,    p75: 3,    p90: 1,    lower_is_better: true,  performance: "average",       sectors: ["all"],                          source: "NIST",         trend: [12, 9, 7, 5, 4, 3.2] },
  { id: "bm-005", metric_name: "MFA Enrollment Rate",            category: "Identity",          our_value: 94.3,  unit: "%",       p25: 60,  p50: 75,   p75: 88,   p90: 95,   lower_is_better: false, performance: "average",       sectors: ["financial", "technology", "healthcare"], source: "Gartner", trend: [78, 82, 86, 89, 91, 94.3] },
  { id: "bm-006", metric_name: "Security Training Completion",   category: "Awareness",         our_value: 87.5,  unit: "%",       p25: 55,  p50: 70,   p75: 83,   p90: 92,   lower_is_better: false, performance: "average",       sectors: ["all"],                          source: "SANS",         trend: [70, 74, 78, 82, 85, 87.5] },
  { id: "bm-007", metric_name: "Critical Vuln Exposure Days",    category: "Vulnerability",     our_value: 2.8,   unit: "days",    p25: 21,  p50: 10,   p75: 4,    p90: 1,    lower_is_better: true,  performance: "above-average", sectors: ["technology", "financial"],      source: "Mandiant",     trend: [15, 11, 8, 5, 3.5, 2.8] },
  { id: "bm-008", metric_name: "Vendor Risk Assessment Rate",    category: "Supply Chain",      our_value: 58.0,  unit: "%",       p25: 30,  p50: 50,   p75: 68,   p90: 82,   lower_is_better: false, performance: "below-average", sectors: ["all"],                          source: "Gartner",      trend: [40, 45, 48, 52, 55, 58] },
  { id: "bm-009", metric_name: "SOC Alert False Positive Rate",  category: "Operations",        our_value: 42.0,  unit: "%",       p25: 70,  p50: 55,   p75: 40,   p90: 25,   lower_is_better: true,  performance: "average",       sectors: ["technology", "financial"],      source: "SANS",         trend: [62, 58, 54, 50, 46, 42] },
  { id: "bm-010", metric_name: "Security Budget % of IT Spend",  category: "Financial",         our_value: 8.5,   unit: "%",       p25: 5,   p50: 7.5,  p75: 10,   p90: 14,   lower_is_better: false, performance: "average",       sectors: ["all"],                          source: "Gartner",      trend: [6, 6.5, 7, 7.5, 8, 8.5] },
  { id: "bm-011", metric_name: "Pen Test Coverage",              category: "Validation",        our_value: 34.0,  unit: "%",       p25: 20,  p50: 35,   p75: 55,   p90: 75,   lower_is_better: false, performance: "below-average", sectors: ["financial"],                    source: "Mandiant",     trend: [20, 24, 27, 29, 31, 34] },
  { id: "bm-012", metric_name: "Data Loss Incidents / Quarter",  category: "Data Protection",   our_value: 1,     unit: "count",   p25: 8,   p50: 4,    p75: 2,    p90: 0,    lower_is_better: true,  performance: "above-average", sectors: ["all"],                          source: "Verizon-DBIR", trend: [6, 5, 3, 2, 2, 1] },
];

// == Helpers ===================================================================

function performanceBadge(p: Performance): string {
  return p === "above-average"  ? "bg-green-500/20 text-green-300"
       : p === "average"        ? "bg-blue-500/20 text-blue-300"
       : p === "below-average"  ? "bg-amber-500/20 text-amber-300"
       :                          "bg-red-500/20 text-red-300";
}

function sourceBadge(s: Source): string {
  const map: Record<Source, string> = {
    "Gartner":      "bg-purple-500/20 text-purple-300",
    "Verizon-DBIR": "bg-red-500/20 text-red-300",
    "SANS":         "bg-orange-500/20 text-orange-300",
    "NIST":         "bg-blue-500/20 text-blue-300",
    "Mandiant":     "bg-cyan-500/20 text-cyan-300",
    "IBM":          "bg-indigo-500/20 text-indigo-300",
  };
  return map[s];
}

function percentilePosition(metric: BenchmarkMetric): number {
  // Where does our_value sit in the p25-p90 range? Returns 0-100
  const { our_value, p25, p50, p75, p90, lower_is_better } = metric;
  const values = lower_is_better
    ? [p90, p75, p50, p25].map(v => v) // lower = better = p90 is best
    : [p25, p50, p75, p90];             // higher = better
  const range = Math.abs(values[3] - values[0]) || 1;
  const pos = lower_is_better
    ? ((p25 - our_value) / range) * 100 + 50
    : ((our_value - p25) / (p90 - p25)) * 100;
  return Math.min(100, Math.max(0, pos));
}

const SPARKLINE_HEIGHT = 24;

function Sparkline({ values }: { values: number[] }) {
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const points = values.map((v, i) => ({
    x: (i / (values.length - 1)) * 60,
    y: SPARKLINE_HEIGHT - ((v - min) / range) * SPARKLINE_HEIGHT,
  }));
  const path = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
  return (
    <svg width="60" height={SPARKLINE_HEIGHT} className="flex-shrink-0">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between" role="status" aria-live="polite">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
           aria-label="Refresh data">
            Retry
          </button>
        </div>
      )}
      <path d={path} fill="none" stroke="#6366f1" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function GapToMedian({ metric }: { metric: BenchmarkMetric }) {
  const gap = metric.lower_is_better
    ? metric.our_value - metric.p50
    : metric.p50 - metric.our_value;
  if (gap < 0) return <span className="text-green-400 text-xs flex items-center gap-1"><TrendingUp className="w-3 h-3" />{Math.abs(gap).toFixed(1)}{metric.unit} ahead</span>;
  if (gap === 0) return <span className="text-blue-400 text-xs flex items-center gap-1"><Minus className="w-3 h-3" />At median</span>;
  return <span className="text-amber-400 text-xs flex items-center gap-1"><TrendingDown className="w-3 h-3" />{gap.toFixed(1)}{metric.unit} behind</span>;
}

const SECTORS: Sector[] = ["all", "financial", "technology", "healthcare", "manufacturing"];

// == Component =================================================================

export default function SecurityBenchmarksDashboard() {
  const [sectorFilter, setSectorFilter] = useState<Sector>("all");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetch("/api/v1/security-benchmarks", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const filtered = sectorFilter === "all"
    ? MOCK_METRICS
    : MOCK_METRICS.filter(m => m.sectors.includes(sectorFilter) || m.sectors.includes("all"));

  const overallPct = Math.round(
    filtered.reduce((s, m) => s + percentilePosition(m), 0) / (filtered.length || 1)
  );

  const perfCounts = {
    "above-average": filtered.filter(m => m.performance === "above-average").length,
    "average":       filtered.filter(m => m.performance === "average").length,
    "below-average": filtered.filter(m => m.performance === "below-average").length,
    "lagging":       filtered.filter(m => m.performance === "lagging").length,
  };

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Target className="w-6 h-6 text-purple-400" />
            Security Benchmarks
          </h1>
          <p className="text-gray-400 text-sm mt-1">Industry percentile comparison = Gartner, DBIR, SANS, Mandiant</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Overall percentile summary */}
      <div className="bg-gradient-to-r from-purple-900/40 to-indigo-900/40 border border-purple-700/30 rounded-lg p-5">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-gray-400 text-xs mb-1">Overall Security Percentile</div>
            <div className="text-5xl font-bold text-purple-300">{overallPct}<span className="text-2xl text-gray-400">th</span></div>
            <div className="text-gray-400 text-xs mt-1">vs industry peers = {filtered.length} metrics tracked</div>
          </div>
          <div className="grid grid-cols-2 gap-3 text-center">
            {Object.entries(perfCounts).map(([k, v]) => (
              <div key={k}>
                <div className={`text-xl font-bold ${k === "above-average" ? "text-green-400" : k === "average" ? "text-blue-400" : k === "below-average" ? "text-amber-400" : "text-red-400"}`}>{v}</div>
                <div className="text-gray-500 text-xs capitalize">{k.replace("-", " ")}</div>
              </div>
            ))}
          </div>
        </div>
        {/* Percentile bar */}
        <div className="mt-4">
          <div className="relative w-full bg-gray-700 rounded-full h-3">
            <div className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-red-500 via-yellow-400 to-green-500" style={{ width: "100%", opacity: 0.3 }} />
            <div className="absolute top-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-white border-2 border-purple-400 shadow" style={{ left: `calc(${overallPct}% - 6px)` }} />
          </div>
          <div className="flex justify-between text-xs text-gray-500 mt-1">
            <span>p0 (worst)</span><span>p50 (median)</span><span>p100 (best)</span>
          </div>
        </div>
      </div>

      {/* Sector filter */}
      <div className="flex gap-2 flex-wrap">
        {SECTORS.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Data will appear here once available</p>
          </div>
        ) : (
          SECTORS.map(s => (
          <button
            key={s}
            onClick={() => setSectorFilter(s)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${sectorFilter === s ? "bg-purple-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}
          >
            {s === "all" ? "All Sectors" : s}
          </button>
        ))
      )}
      </div>

      {/* Benchmark cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Data will appear here once available</p>
          </div>
        ) : (
          filtered.map(metric => {
          const pct = percentilePosition(metric);
          return (
            <div key={metric.id} className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-start justify-between mb-2">
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-white text-sm truncate">{metric.metric_name}</div>
                  <div className="text-gray-500 text-xs mt-0.5">{metric.category}</div>
                </div>
                <div className="flex flex-col items-end gap-1 ml-2">
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium capitalize ${performanceBadge(metric.performance)}`}>
                    {metric.performance.replace("-", " ")}
                  </span>
                  <span className={`px-2 py-0.5 rounded-full text-xs ${sourceBadge(metric.source)}`}>{metric.source}</span>
                </div>
              </div>

              {/* Our value */}
              <div className="flex items-end gap-1 mb-3">
                <span className="text-2xl font-bold text-white">{metric.our_value}</span>
                <span className="text-gray-400 text-sm mb-0.5">{metric.unit}</span>
              </div>

              {/* Percentile ruler */}
              <div className="mb-2">
                <div className="flex justify-between text-xs text-gray-500 mb-1">
                  <span>p25: {metric.p25}</span>
                  <span>p50: {metric.p50}</span>
                  <span>p75: {metric.p75}</span>
                  <span>p90: {metric.p90}</span>
                </div>
                <div className="relative w-full bg-gray-700 rounded-full h-2">
                  <div className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-red-500 via-yellow-400 to-green-500" style={{ width: "100%", opacity: 0.4 }} />
                  <div
                    className="absolute top-1/2 -translate-y-1/2 w-2.5 h-2.5 rounded-full bg-white border-2 border-indigo-400"
                    style={{ left: `calc(${pct}% - 5px)` }}
                  />
                </div>
              </div>

              {/* Gap to median + sparkline */}
              <div className="flex items-center justify-between mt-2">
                <GapToMedian metric={metric} />
                <Sparkline values={metric.trend} />
              </div>
            </div>
          );
        })
        )}
      </div>
    </div>
  );
}
