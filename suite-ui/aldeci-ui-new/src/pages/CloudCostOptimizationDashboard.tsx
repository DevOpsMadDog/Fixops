/**
 * Cloud Cost Optimization Dashboard
 * Route: /cost-optimization
 * API: /api/v1/cost-optimization
 */
import { useState, useEffect } from "react";
import { DollarSign, TrendingDown, Cloud, RefreshCw, AlertTriangle } from "lucide-react";

const API_BASE = "/api/v1/cost-optimization";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

interface CloudResource {
  id: string;
  resource_name: string;
  resource_type: string;
  provider: string;
  monthly_cost: number;
  annual_cost: number;
  utilization_pct: number;
  underutilized: boolean;
  roi: number;
}

const MOCK_RESOURCES: CloudResource[] = [
  { id: "res-001", resource_name: "prod-eks-cluster-01", resource_type: "kubernetes", provider: "AWS", monthly_cost: 4200, annual_cost: 50400, utilization_pct: 71, underutilized: false, roi: 342 },
  { id: "res-002", resource_name: "dev-ec2-fleet", resource_type: "compute", provider: "AWS", monthly_cost: 1800, annual_cost: 21600, utilization_pct: 18, underutilized: true, roi: 45 },
  { id: "res-003", resource_name: "waf-prod-global", resource_type: "waf", provider: "AWS", monthly_cost: 950, annual_cost: 11400, utilization_pct: 88, underutilized: false, roi: 890 },
  { id: "res-004", resource_name: "azure-sentinel-ws", resource_type: "siem", provider: "Azure", monthly_cost: 3100, annual_cost: 37200, utilization_pct: 62, underutilized: false, roi: 215 },
  { id: "res-005", resource_name: "gcp-staging-vms", resource_type: "compute", provider: "GCP", monthly_cost: 620, annual_cost: 7440, utilization_pct: 9, underutilized: true, roi: 12 },
  { id: "res-006", resource_name: "s3-backup-archive", resource_type: "storage", provider: "AWS", monthly_cost: 180, annual_cost: 2160, utilization_pct: 95, underutilized: false, roi: 680 },
];

const providerColor: Record<string, string> = {
  AWS: "bg-orange-800 text-orange-200",
  Azure: "bg-blue-800 text-blue-200",
  GCP: "bg-green-800 text-green-200",
};

export default function CloudCostOptimizationDashboard() {
  const [resources, setResources] = useState<CloudResource[]>(MOCK_RESOURCES);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [sortBy, setSortBy] = useState<"cost" | "roi" | "utilization">("cost");


  const fetchData = () => {
    setError(null);
    setLoading(true);
    fetch(`${API_BASE}/resources`, { headers: getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => { if (Array.isArray(d)) setResources(d); })
    .catch(err => setError(err.message || 'Failed to load data'))
    .finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const totalMonthly = resources.reduce((s, r) => s + r.monthly_cost, 0);
  const underutilized = resources.filter(r => r.underutilized);
  const wastedMonthly = underutilized.reduce((s, r) => s + r.monthly_cost, 0);
  const highROI = resources.filter(r => r.roi > 100).length;

  const sorted = [...resources].sort((a, b) => {
    if (sortBy === "cost") return b.monthly_cost - a.monthly_cost;
    if (sortBy === "roi") return b.roi - a.roi;
    return b.utilization_pct - a.utilization_pct;
  });

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
          <p className="font-medium">Error loading data</p>
          <p className="text-sm">{error}</p>
          <button onClick={() => { setError(null); fetchData(); }} className="mt-2 text-sm underline">Retry</button>
        </div>
      )}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <DollarSign className="w-6 h-6 text-green-400" /> Cloud Cost Optimization
          </h1>
          <p className="text-gray-400 text-sm mt-1">Resource costs, utilization, ROI analysis, and waste reduction</p>
        </div>
        <button onClick={() => window.location.reload()} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Monthly Spend", value: `$${totalMonthly.toLocaleString()}`, color: "text-blue-400" },
          { label: "Wasted Spend", value: `$${wastedMonthly.toLocaleString()}`, color: "text-red-400" },
          { label: "Underutilized", value: underutilized.length, color: "text-orange-400" },
          { label: "High-ROI (>100%)", value: highROI, color: "text-green-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {underutilized.length > 0 && (
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-300 font-medium mb-2">
            <AlertTriangle className="w-4 h-4" /> {underutilized.length} underutilized resources — estimated ${wastedMonthly.toLocaleString()}/month wasted
          </div>
          <div className="flex flex-wrap gap-2">
            {underutilized.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              underutilized.map(r => (
              <span key={r.id} className="bg-red-900/40 border border-red-700 text-red-300 text-xs px-2 py-1 rounded">
                {r.resource_name} ({r.utilization_pct}% util)
              </span>
            )))}
          </div>
        </div>
      )}

      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Cloud className="w-4 h-4 text-blue-400" /> Cloud Resources
            {loading && <span className="text-xs text-gray-400 ml-2">Loading...</span>}
          </h2>
          <div className="flex gap-2">
            {(["cost", "roi", "utilization"] as const).map(s => (
              <button key={s} onClick={() => setSortBy(s)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${sortBy === s ? "bg-blue-700 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}>
                {s}
              </button>
            )))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-4">Resource</th>
                <th className="text-left pb-2 pr-4">Provider</th>
                <th className="text-left pb-2 pr-4">Monthly Cost</th>
                <th className="text-left pb-2 pr-4">Utilization</th>
                <th className="text-left pb-2 pr-4">ROI</th>
                <th className="text-left pb-2">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {sorted.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                sorted.map(r => (
                <tr key={r.id} className={`hover:bg-gray-700/30 transition-colors ${r.underutilized ? "bg-red-900/10" : ""}`}>
                  <td className="py-3 pr-4">
                    <div className="text-gray-200 font-medium text-sm">{r.resource_name}</div>
                    <div className="text-gray-500 text-xs">{r.resource_type}</div>
                  </td>
                  <td className="py-3 pr-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${providerColor[r.provider] || "bg-gray-700 text-gray-200"}`}>{r.provider}</span>
                  </td>
                  <td className="py-3 pr-4 text-gray-200 font-medium">${r.monthly_cost.toLocaleString()}</td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-gray-700 rounded-full h-1.5">
                        <div className={`h-1.5 rounded-full ${r.utilization_pct < 25 ? "bg-red-500" : r.utilization_pct < 60 ? "bg-amber-400" : "bg-green-500"}`}
                          style={{ width: `${r.utilization_pct}%` }} />
                      </div>
                      <span className="text-gray-400 text-xs">{r.utilization_pct}%</span>
                    </div>
                  </td>
                  <td className={`py-3 pr-4 font-bold ${r.roi > 100 ? "text-green-400" : r.roi > 0 ? "text-amber-400" : "text-red-400"}`}>{r.roi}%</td>
                  <td className="py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${r.underutilized ? "bg-red-800 text-red-200" : "bg-green-800/40 text-green-300"}`}>
                      {r.underutilized ? "Underutilized" : "Healthy"}
                    </span>
                  </td>
                </tr>
              )))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
