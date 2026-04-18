/**
 * Ransomware Protection Dashboard
 * Route: /ransomware-protection
 * API: /api/v1/ransomware-protection
 */
import { useState, useEffect } from "react";
import { Shield, AlertTriangle, Lock, RefreshCw, Database } from "lucide-react";

const API_BASE = "/api/v1/ransomware-protection";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

interface DetectionPattern {
  id: string;
  pattern_name: string;
  pattern_type: string;
  severity: string;
  enabled: boolean;
  match_count: number;
}

interface BackupStatus {
  total_systems: number;
  systems_with_backup: number;
  backup_coverage_pct: number;
  last_verified: string;
}

const MOCK_PATTERNS: DetectionPattern[] = [
  { id: "pat-001", pattern_name: "Mass File Encryption", pattern_type: "behavior", severity: "critical", enabled: true, match_count: 3 },
  { id: "pat-002", pattern_name: "Ransom Note Creation", pattern_type: "file_signature", severity: "critical", enabled: true, match_count: 1 },
  { id: "pat-003", pattern_name: "Shadow Copy Deletion", pattern_type: "command", severity: "high", enabled: true, match_count: 0 },
  { id: "pat-004", pattern_name: "C2 Beacon Pattern", pattern_type: "network", severity: "high", enabled: true, match_count: 7 },
  { id: "pat-005", pattern_name: "Lateral Movement via SMB", pattern_type: "network", severity: "medium", enabled: false, match_count: 0 },
];

const MOCK_BACKUP: BackupStatus = {
  total_systems: 248,
  systems_with_backup: 231,
  backup_coverage_pct: 93.1,
  last_verified: "2026-04-16",
};

const severityColor: Record<string, string> = {
  critical: "bg-red-800 text-red-200",
  high: "bg-orange-800 text-orange-200",
  medium: "bg-amber-800 text-amber-200",
  low: "bg-green-800 text-green-200",
};

export default function RansomwareProtectionDashboard() {
  const [patterns, setPatterns] = useState<DetectionPattern[]>(MOCK_PATTERNS);
  const [error, setError] = useState<string | null>(null);
  const [backup, setBackup] = useState<BackupStatus>(MOCK_BACKUP);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      fetch(`${API_BASE}/patterns`, { headers: getHeaders() })
        .then(r => r.ok ? r.json() : Promise.reject())
        .then(d => { if (Array.isArray(d)) setPatterns(d); })
        .catch(() => { setError('Failed to load data'); }),
      fetch(`${API_BASE}/backup-status`, { headers: getHeaders() })
        .then(r => r.ok ? r.json() : Promise.reject())
        .then(d => { if (d && typeof d === "object") setBackup(d); })
        .catch(() => { setError('Failed to load data'); }),
    ]).finally(() => setLoading(false));
  }, []);

  const enabled = patterns.filter(p => p.enabled).length;
  const totalMatches = patterns.reduce((s, p) => s + p.match_count, 0);
  const criticalPatterns = patterns.filter(p => p.severity === "critical").length;

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
            <Lock className="w-6 h-6 text-red-400" /> Ransomware Protection
          </h1>
          <p className="text-gray-400 text-sm mt-1">Detection patterns, backup coverage, and containment status</p>
        </div>
        <button onClick={() => window.location.reload()} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Active Patterns", value: enabled, color: "text-green-400" },
          { label: "Critical Patterns", value: criticalPatterns, color: "text-red-400" },
          { label: "Total Matches (30d)", value: totalMatches, color: "text-orange-400" },
          { label: "Backup Coverage", value: `${backup.backup_coverage_pct.toFixed(1)}%`, color: "text-blue-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Backup Status */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Database className="w-4 h-4 text-blue-400" /> Backup Coverage
        </h2>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <div className="flex justify-between text-sm mb-2">
              <span className="text-gray-400">{backup.systems_with_backup} / {backup.total_systems} systems protected</span>
              <span className="text-blue-400 font-bold">{backup.backup_coverage_pct.toFixed(1)}%</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-3">
              <div className="h-3 rounded-full bg-blue-500 transition-all" style={{ width: `${backup.backup_coverage_pct}%` }} />
            </div>
          </div>
          <div className="text-xs text-gray-500">Last verified: {backup.last_verified}</div>
        </div>
      </div>

      {/* Detection Patterns */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400" /> Detection Patterns
          {loading && <span className="text-xs text-gray-400 ml-2">Loading...</span>}
        </h2>
        <div className="space-y-3">
          {patterns.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            patterns.map(p => (
            <div key={p.id} className={`p-4 rounded-lg border flex items-center justify-between ${p.enabled ? "border-gray-600 bg-gray-700/30" : "border-gray-700 bg-gray-700/10 opacity-60"}`}>
              <div className="flex items-center gap-3">
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${severityColor[p.severity] || "bg-gray-700 text-gray-200"}`}>{p.severity}</span>
                <div>
                  <p className="text-white font-medium text-sm">{p.pattern_name}</p>
                  <p className="text-gray-400 text-xs">{p.pattern_type} · {p.match_count} matches</p>
                </div>
              </div>
              <span className={`text-xs px-2 py-1 rounded ${p.enabled ? "bg-green-800/50 text-green-300" : "bg-gray-700 text-gray-400"}`}>
                {p.enabled ? "Enabled" : "Disabled"}
              </span>
            </div>
          ))}
          )}
        </div>
      </div>
    </div>
  );
}
