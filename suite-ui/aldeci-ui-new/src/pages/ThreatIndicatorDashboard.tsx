/**
 * Threat Indicator Dashboard
 * Route: /threat-indicators
 * API: /api/v1/threat-indicators
 */
import { useState, useEffect } from "react";
import { AlertTriangle, Shield, RefreshCw, Eye } from "lucide-react";

const API_BASE = "/api/v1/threat-indicators";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

interface Indicator {
  id: string;
  indicator_type: string;
  value: string;
  confidence: number;
  active: boolean;
  sighting_count: number;
  created_at: string;
}

const MOCK_INDICATORS: Indicator[] = [
  { id: "ioc-001", indicator_type: "ip", value: "185.220.101.47", confidence: 0.92, active: true, sighting_count: 14, created_at: "2026-04-10" },
  { id: "ioc-002", indicator_type: "domain", value: "evil-update.ru", confidence: 0.87, active: true, sighting_count: 7, created_at: "2026-04-11" },
  { id: "ioc-003", indicator_type: "hash", value: "d41d8cd98f00b204e9800998ecf8427e", confidence: 0.95, active: true, sighting_count: 3, created_at: "2026-04-12" },
  { id: "ioc-004", indicator_type: "url", value: "http://cdn.malware.cc/dropper.exe", confidence: 0.89, active: false, sighting_count: 21, created_at: "2026-04-08" },
  { id: "ioc-005", indicator_type: "email", value: "phish@fake-invoice.xyz", confidence: 0.71, active: true, sighting_count: 5, created_at: "2026-04-13" },
];

const typeColor: Record<string, string> = {
  ip: "bg-red-800 text-red-200",
  domain: "bg-orange-800 text-orange-200",
  hash: "bg-purple-800 text-purple-200",
  url: "bg-blue-800 text-blue-200",
  email: "bg-cyan-800 text-cyan-200",
};

export default function ThreatIndicatorDashboard() {
  const [indicators, setIndicators] = useState<Indicator[]>(MOCK_INDICATORS);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/indicators`, { headers: getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setIndicators(d); })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const filtered = filter === "all" ? indicators : indicators.filter(i => i.indicator_type === filter);
  const active = indicators.filter(i => i.active).length;
  const highConf = indicators.filter(i => i.confidence >= 0.8).length;
  const types = [...new Set(indicators.map(i => i.indicator_type))];

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-orange-400" /> Threat Indicators
          </h1>
          <p className="text-gray-400 text-sm mt-1">IOC lifecycle, sighting tracking, and confidence scoring</p>
        </div>
        <button onClick={() => window.location.reload()} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total IOCs", value: indicators.length, color: "text-blue-400" },
          { label: "Active", value: active, color: "text-green-400" },
          { label: "High Confidence", value: highConf, color: "text-purple-400" },
          { label: "Types", value: types.length, color: "text-amber-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Eye className="w-4 h-4 text-orange-400" /> Indicators
            {loading && <span className="text-xs text-gray-400 ml-2">Loading...</span>}
          </h2>
          <div className="flex gap-2">
            {["all", ...types].map(t => (
              <button key={t} onClick={() => setFilter(t)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${filter === t ? "bg-orange-700 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}>
                {t}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-4">Type</th>
                <th className="text-left pb-2 pr-4">Value</th>
                <th className="text-left pb-2 pr-4">Confidence</th>
                <th className="text-left pb-2 pr-4">Sightings</th>
                <th className="text-left pb-2 pr-4">Status</th>
                <th className="text-left pb-2">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {filtered.map(ioc => (
                <tr key={ioc.id} className="hover:bg-gray-700/30 transition-colors">
                  <td className="py-3 pr-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${typeColor[ioc.indicator_type] || "bg-gray-700 text-gray-200"}`}>
                      {ioc.indicator_type}
                    </span>
                  </td>
                  <td className="py-3 pr-4 text-gray-200 font-mono text-xs">{ioc.value}</td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-gray-700 rounded-full h-1.5">
                        <div className="h-1.5 rounded-full bg-purple-500" style={{ width: `${ioc.confidence * 100}%` }} />
                      </div>
                      <span className="text-gray-400 text-xs">{Math.round(ioc.confidence * 100)}%</span>
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-gray-300">{ioc.sighting_count}</td>
                  <td className="py-3 pr-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${ioc.active ? "bg-green-800 text-green-200" : "bg-gray-700 text-gray-400"}`}>
                      {ioc.active ? "Active" : "Expired"}
                    </span>
                  </td>
                  <td className="py-3 text-gray-400 text-xs">{ioc.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
