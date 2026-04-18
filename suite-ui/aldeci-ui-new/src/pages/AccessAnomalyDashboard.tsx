/**
 * Access Anomaly Dashboard
 * Route: /access-anomaly
 * API: /api/v1/access-anomaly
 */
import { useState, useEffect } from "react";
import { AlertTriangle, Users, Activity, RefreshCw, MapPin } from "lucide-react";

const API_BASE = "/api/v1/access-anomaly";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

interface Anomaly {
  id: string;
  user_id: string;
  anomaly_type: string;
  risk_score: number;
  details: string;
  detected_at: string;
  resolved: boolean;
}

const MOCK_ANOMALIES: Anomaly[] = [
  { id: "ano-001", user_id: "alice@corp.io", anomaly_type: "impossible_travel", risk_score: 95, details: "Login from New York then Tokyo within 2 hours", detected_at: "2026-04-16T08:30:00Z", resolved: false },
  { id: "ano-002", user_id: "bob@corp.io", anomaly_type: "off_hours_access", risk_score: 62, details: "Admin access at 3:17 AM on Sunday", detected_at: "2026-04-15T03:17:00Z", resolved: false },
  { id: "ano-003", user_id: "carol@corp.io", anomaly_type: "new_device", risk_score: 45, details: "First login from unrecognized device in Singapore", detected_at: "2026-04-14T14:22:00Z", resolved: true },
  { id: "ano-004", user_id: "dave@corp.io", anomaly_type: "privilege_escalation", risk_score: 88, details: "Sudden access to production DB not in role", detected_at: "2026-04-13T09:45:00Z", resolved: false },
  { id: "ano-005", user_id: "eve@corp.io", anomaly_type: "bulk_download", risk_score: 78, details: "Downloaded 4.2GB in 30 minutes", detected_at: "2026-04-12T11:00:00Z", resolved: true },
];

const anomalyTypeLabel: Record<string, string> = {
  impossible_travel: "Impossible Travel",
  off_hours_access: "Off-hours Access",
  new_device: "New Device",
  privilege_escalation: "Privilege Escalation",
  bulk_download: "Bulk Download",
};

function riskColor(score: number) {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-amber-400";
  return "text-green-400";
}

export default function AccessAnomalyDashboard() {
  const [anomalies, setAnomalies] = useState<Anomaly[]>(MOCK_ANOMALIES);
  const [loading, setLoading] = useState(true);
  const [showResolved, setShowResolved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/anomalies`, { headers: getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
      .then(d => { if (Array.isArray(d)) setAnomalies(d); })
      .catch(err => setError(err.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const filtered = showResolved ? anomalies : anomalies.filter(a => !a.resolved);
  const highRisk = anomalies.filter(a => a.risk_score >= 80 && !a.resolved).length;
  const uniqueUsers = new Set(anomalies.filter(a => !a.resolved).map(a => a.user_id)).size;

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
            <Activity className="w-6 h-6 text-orange-400" /> Access Anomaly Detection
          </h1>
          <p className="text-gray-400 text-sm mt-1">Impossible travel, off-hours access, and privilege anomalies</p>
        </div>
        <button onClick={() => { setError(null); fetchData(); }} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Open Anomalies", value: anomalies.filter(a => !a.resolved).length, color: "text-orange-400" },
          { label: "High Risk", value: highRisk, color: "text-red-400" },
          { label: "Affected Users", value: uniqueUsers, color: "text-purple-400" },
          { label: "Resolved (7d)", value: anomalies.filter(a => a.resolved).length, color: "text-green-400" },
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
            <AlertTriangle className="w-4 h-4 text-orange-400" /> Anomaly Feed
            {loading && <span className="text-xs text-gray-400 ml-2">Loading...</span>}
          </h2>
          <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
            <input type="checkbox" checked={showResolved} onChange={e => setShowResolved(e.target.checked)} className="rounded" />
            Show resolved
          </label>
        </div>
        <div className="space-y-3">
          {filtered.map(a => (
            <div key={a.id} className={`p-4 rounded-lg border ${a.resolved ? "border-gray-700 bg-gray-700/10 opacity-60" : "border-gray-600 bg-gray-700/30"}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="bg-orange-800/60 text-orange-200 text-xs px-2 py-0.5 rounded font-medium">
                      {anomalyTypeLabel[a.anomaly_type] || a.anomaly_type}
                    </span>
                    <span className="text-gray-300 font-medium text-sm">{a.user_id}</span>
                    {a.resolved && <span className="bg-green-800/40 text-green-300 text-xs px-2 py-0.5 rounded">Resolved</span>}
                  </div>
                  <p className="text-gray-400 text-xs">{a.details}</p>
                  <p className="text-gray-500 text-xs mt-1">{new Date(a.detected_at).toLocaleString()}</p>
                </div>
                <div className="text-right">
                  <div className={`text-xl font-bold ${riskColor(a.risk_score)}`}>{a.risk_score}</div>
                  <div className="text-gray-500 text-xs">risk score</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
