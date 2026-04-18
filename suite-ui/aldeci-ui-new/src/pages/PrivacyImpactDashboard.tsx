/**
 * Privacy Impact Assessment Dashboard
 * Route: /privacy-impact
 * API: /api/v1/privacy-impact
 */
import { useState, useEffect } from "react";
import { Shield, FileText, AlertTriangle, CheckCircle, Clock, RefreshCw } from "lucide-react";

const API_BASE = "/api/v1/privacy-impact";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

interface PIA {
  id: string;
  title: string;
  status: string;
  risk_score: number;
  created_at: string;
  org_id?: string;
}

const MOCK_PIAS: PIA[] = [
  { id: "pia-001", title: "Customer Data Processing Review", status: "approved", risk_score: 42, created_at: "2026-04-10" },
  { id: "pia-002", title: "Employee Monitoring System", status: "in_review", risk_score: 71, created_at: "2026-04-12" },
  { id: "pia-003", title: "Marketing Analytics Platform", status: "draft", risk_score: 58, created_at: "2026-04-14" },
  { id: "pia-004", title: "Third-party Data Sharing Agreement", status: "pending_approval", risk_score: 85, created_at: "2026-04-15" },
  { id: "pia-005", title: "AI-based HR Screening Tool", status: "rejected", risk_score: 92, created_at: "2026-04-08" },
];

const statusColor: Record<string, string> = {
  draft: "bg-gray-600 text-gray-200",
  in_review: "bg-blue-700 text-blue-100",
  pending_approval: "bg-amber-700 text-amber-100",
  approved: "bg-green-700 text-green-100",
  rejected: "bg-red-700 text-red-100",
};

function riskColor(score: number) {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-amber-400";
  return "text-green-400";
}

export default function PrivacyImpactDashboard() {
  const [pias, setPias] = useState<PIA[]>(MOCK_PIAS);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/assessments`, { headers: getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setPias(d); })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const stats = {
    total: pias.length,
    approved: pias.filter(p => p.status === "approved").length,
    pending: pias.filter(p => p.status === "in_review" || p.status === "pending_approval").length,
    highRisk: pias.filter(p => p.risk_score >= 70).length,
  };

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
            <Shield className="w-6 h-6 text-purple-400" /> Privacy Impact Assessments
          </h1>
          <p className="text-gray-400 text-sm mt-1">PIA/DPIA workflow and risk tracking</p>
        </div>
        <button onClick={() => window.location.reload()} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total PIAs", value: stats.total, color: "text-blue-400" },
          { label: "Approved", value: stats.approved, color: "text-green-400" },
          { label: "Pending Review", value: stats.pending, color: "text-amber-400" },
          { label: "High Risk", value: stats.highRisk, color: "text-red-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <FileText className="w-4 h-4 text-purple-400" /> Assessment List
          {loading && <span className="text-xs text-gray-400 ml-2">Loading...</span>}
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-4">Title</th>
                <th className="text-left pb-2 pr-4">Status</th>
                <th className="text-left pb-2 pr-4">Risk Score</th>
                <th className="text-left pb-2">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {pias.map(pia => (
                <tr key={pia.id} className="hover:bg-gray-700/30 transition-colors">
                  <td className="py-3 pr-4 text-gray-200 font-medium">{pia.title}</td>
                  <td className="py-3 pr-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[pia.status] || "bg-gray-600 text-gray-200"}`}>
                      {pia.status.replace("_", " ")}
                    </span>
                  </td>
                  <td className={`py-3 pr-4 font-bold ${riskColor(pia.risk_score)}`}>{pia.risk_score}</td>
                  <td className="py-3 text-gray-400 text-xs">{pia.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
