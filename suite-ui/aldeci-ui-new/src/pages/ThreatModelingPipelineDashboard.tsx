/**
 * Threat Modeling Pipeline Dashboard
 *
 * Models list with risk gauges, STRIDE coverage grid, unmitigated threats table,
 * threat add panel, mitigate action button, and risk score recompute indicator.
 *
 * Route: /threat-modeling-pipeline
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/threat-modeling-pipeline";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { ShieldOff, Plus, RefreshCw, CheckCircle2, AlertTriangle } from "lucide-react";

// == Types ======================================================

type ModelStatus = "draft" | "in_review" | "finalized" | "archived";
type StrideCategory = "Spoofing" | "Tampering" | "Repudiation" | "InfoDisclosure" | "DoS" | "ElevationOfPrivilege";
type RiskLevel = "critical" | "high" | "medium" | "low";

interface ThreatModel {
  id: string;
  model_name: string;
  methodology: "STRIDE" | "PASTA" | "VAST" | "OCTAVE" | "LINDDUN";
  component_type: "web_app" | "api" | "microservice" | "mobile" | "iot" | "infrastructure";
  risk_score: 1 | 2 | 3 | 4; // 1=low 4=critical
  status: ModelStatus;
  threats_count: number;
  mitigated_count: number;
  last_updated: string;
}

interface StrideStat {
  category: StrideCategory;
  count: number;
  mitigated: number;
  risk_level: RiskLevel;
}

interface UnmitigatedThreat {
  id: string;
  threat_name: string;
  stride_category: StrideCategory;
  likelihood: 1 | 2 | 3 | 4 | 5;
  impact: 1 | 2 | 3 | 4 | 5;
  risk_level: RiskLevel;
  model_name: string;
}

// == Mock data ==================================================

const MODELS: ThreatModel[] = [
  { id: "tm01", model_name: "Customer Auth Service", methodology: "STRIDE", component_type: "api", risk_score: 4, status: "finalized", threats_count: 18, mitigated_count: 14, last_updated: "2026-04-10" },
  { id: "tm02", model_name: "Payment Processing Pipeline", methodology: "PASTA", component_type: "microservice", risk_score: 4, status: "finalized", threats_count: 24, mitigated_count: 20, last_updated: "2026-04-08" },
  { id: "tm03", model_name: "Mobile Banking App", methodology: "STRIDE", component_type: "mobile", risk_score: 3, status: "in_review", threats_count: 15, mitigated_count: 9, last_updated: "2026-04-14" },
  { id: "tm04", model_name: "IoT Sensor Gateway", methodology: "VAST", component_type: "iot", risk_score: 3, status: "draft", threats_count: 8, mitigated_count: 3, last_updated: "2026-04-16" },
  { id: "tm05", model_name: "Admin Web Portal", methodology: "STRIDE", component_type: "web_app", risk_score: 2, status: "finalized", threats_count: 12, mitigated_count: 11, last_updated: "2026-03-28" },
];

const STRIDE_STATS: StrideStat[] = [
  { category: "Spoofing", count: 12, mitigated: 10, risk_level: "high" },
  { category: "Tampering", count: 9, mitigated: 7, risk_level: "critical" },
  { category: "Repudiation", count: 6, mitigated: 6, risk_level: "low" },
  { category: "InfoDisclosure", count: 15, mitigated: 11, risk_level: "critical" },
  { category: "DoS", count: 8, mitigated: 5, risk_level: "high" },
  { category: "ElevationOfPrivilege", count: 7, mitigated: 4, risk_level: "critical" },
];

const UNMITIGATED: UnmitigatedThreat[] = [
  { id: "ut01", threat_name: "JWT token replay attack via stolen refresh token", stride_category: "Spoofing", likelihood: 4, impact: 5, risk_level: "critical", model_name: "Customer Auth Service" },
  { id: "ut02", threat_name: "Parameter tampering in payment amount field", stride_category: "Tampering", likelihood: 3, impact: 5, risk_level: "critical", model_name: "Payment Processing Pipeline" },
  { id: "ut03", threat_name: "Sensitive PII in API response not masked", stride_category: "InfoDisclosure", likelihood: 4, impact: 4, risk_level: "critical", model_name: "Mobile Banking App" },
  { id: "ut04", threat_name: "DDoS via unauthenticated endpoint flood", stride_category: "DoS", likelihood: 4, impact: 3, risk_level: "high", model_name: "Admin Web Portal" },
  { id: "ut05", threat_name: "IDOR allows admin data access from user role", stride_category: "ElevationOfPrivilege", likelihood: 3, impact: 5, risk_level: "critical", model_name: "Mobile Banking App" },
  { id: "ut06", threat_name: "IoT firmware update without signature verification", stride_category: "Tampering", likelihood: 2, impact: 4, risk_level: "high", model_name: "IoT Sensor Gateway" },
];

// == Helpers ====================================================

const RISK_SCORE_CONFIG: Record<number, { label: string; color: string; bg: string }> = {
  1: { label: "Low", color: "text-gray-400", bg: "bg-gray-500/20" },
  2: { label: "Medium", color: "text-yellow-400", bg: "bg-yellow-500/20" },
  3: { label: "High", color: "text-orange-400", bg: "bg-orange-500/20" },
  4: { label: "Critical", color: "text-red-400", bg: "bg-red-500/20" },
};

const RISK_LEVEL_COLOR: Record<RiskLevel, string> = {
  critical: "bg-red-500/20 text-red-300 border border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40",
  low: "bg-gray-600/40 text-gray-400",
};

const STATUS_COLOR: Record<ModelStatus, string> = {
  draft: "bg-gray-600/40 text-gray-400",
  in_review: "bg-yellow-500/20 text-yellow-300",
  finalized: "bg-green-500/20 text-green-300",
  archived: "bg-blue-500/20 text-blue-300",
};

const METHOD_COLOR: Record<string, string> = {
  STRIDE: "bg-blue-500/20 text-blue-300",
  PASTA: "bg-purple-500/20 text-purple-300",
  VAST: "bg-teal-500/20 text-teal-300",
  OCTAVE: "bg-orange-500/20 text-orange-300",
  LINDDUN: "bg-pink-500/20 text-pink-300",
};

const COMP_COLOR: Record<string, string> = {
  web_app: "bg-sky-500/20 text-sky-300",
  api: "bg-teal-500/20 text-teal-300",
  microservice: "bg-violet-500/20 text-violet-300",
  mobile: "bg-pink-500/20 text-pink-300",
  iot: "bg-orange-500/20 text-orange-300",
  infrastructure: "bg-yellow-500/20 text-yellow-300",
};

const STRIDE_COLOR: Record<StrideCategory, string> = {
  Spoofing: "bg-red-500/20 text-red-300",
  Tampering: "bg-orange-500/20 text-orange-300",
  Repudiation: "bg-yellow-500/20 text-yellow-300",
  InfoDisclosure: "bg-pink-500/20 text-pink-300",
  DoS: "bg-purple-500/20 text-purple-300",
  ElevationOfPrivilege: "bg-red-700/30 text-red-200",
};

function RiskGauge({ score }: { score: 1 | 2 | 3 | 4 }) {
  const cfg = RISK_SCORE_CONFIG[score];
  return (
    <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-bold ${cfg.bg} ${cfg.color}`}>
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
      {Array.from({ length: 4 }, (_, i) => (
        <span key={i} className={`w-2 h-2 rounded-sm ${i < score ? "" : "opacity-20"}`}
          style={{ backgroundColor: i < score ? (score === 4 ? "#ef4444" : score === 3 ? "#f97316" : score === 2 ? "#eab308" : "#6b7280") : "#374151" }} />
      ))}
      {cfg.label}
    </div>
  );
}

function MatrixCell({ likelihood, impact }: { likelihood: number; impact: number }) {
  const risk = likelihood * impact;
  const color = risk >= 16 ? "bg-red-600 text-white" :
    risk >= 9 ? "bg-orange-500 text-white" :
    risk >= 4 ? "bg-yellow-500 text-black" : "bg-gray-600 text-gray-200";
  return (
    <span className={`inline-flex items-center justify-center w-8 h-6 rounded text-xs font-bold ${color}`}>
      {risk}
    </span>
  );
}

// == Component ==================================================

export default function ThreatModelingPipelineDashboard() {
  const [showAddPanel, setShowAddPanel] = useState(false);
  useEffect(() => {
    fetch(_API_BASE, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);
  const [mitigating, setMitigating] = useState<string | null>(null);
  const [recomputing, setRecomputing] = useState(false);
  const [mitigatedIds, setMitigatedIds] = useState<Set<string>>(new Set());
  const [newThreat, setNewThreat] = useState({ name: "", stride: "Spoofing", likelihood: "3", impact: "3" });
  const [loading, setLoading] = useState(true);

  function handleMitigate(id: string) {
    setMitigating(id);
    setTimeout(() => {
      setMitigatedIds((prev) => new Set([...prev, id]));
      setMitigating(null);
    }, 800);
  }

  function handleRecompute() {
    setRecomputing(true);
    setTimeout(() => setRecomputing(false), 1200);
  }

  const visibleThreats = UNMITIGATED.filter((t) => !mitigatedIds.has(t.id));

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
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <ShieldOff className="text-violet-400" size={28} />
          <div>
            <h1 className="text-2xl font-bold">Threat Modeling Pipeline</h1>
            <p className="text-gray-400 text-sm">STRIDE/PASTA pipeline, threat coverage, and mitigation tracking</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleRecompute}
            className={`flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-all ${recomputing ? "opacity-70" : ""}`}
          >
            <RefreshCw size={14} className={recomputing ? "animate-spin text-violet-400" : ""} />
            {recomputing ? "Recomputing=" : "Recompute Scores"}
          </button>
          <button
            onClick={() => setShowAddPanel(!showAddPanel)}
            className="flex items-center gap-2 px-4 py-2 bg-violet-700 hover:bg-violet-600 rounded-lg text-sm font-medium transition-colors"
          >
            <Plus size={16} /> Add Threat
          </button>
        </div>
      </div>

      {/* Add threat panel */}
      {showAddPanel && (
        <div className="bg-gray-800 rounded-lg p-6 border border-violet-500/30">
          <h2 className="text-base font-semibold mb-4 flex items-center gap-2"><Plus size={16} className="text-violet-400" /> New Threat Entry</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <input
              className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200 col-span-2"
              placeholder="Threat description"
              value={newThreat.name}
              onChange={(e) => setNewThreat({ ...newThreat, name: e.target.value })}
            />
            <select
              className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200"
              value={newThreat.stride}
              onChange={(e) => setNewThreat({ ...newThreat, stride: e.target.value })}
            >
              {(["Spoofing", "Tampering", "Repudiation", "InfoDisclosure", "DoS", "ElevationOfPrivilege"] as StrideCategory[]).map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
            <div className="flex gap-2">
              <input
                className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200 w-20"
                placeholder="L (1-5)"
                value={newThreat.likelihood}
                onChange={(e) => setNewThreat({ ...newThreat, likelihood: e.target.value })}
              />
              <input
                className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200 w-20"
                placeholder="I (1-5)"
                value={newThreat.impact}
                onChange={(e) => setNewThreat({ ...newThreat, impact: e.target.value })}
              />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button onClick={() => setShowAddPanel(false)} className="px-4 py-2 bg-violet-700 hover:bg-violet-600 rounded text-sm">Save Threat</button>
            <button onClick={() => setShowAddPanel(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm">Cancel</button>
          </div>
        </div>
      )}

      {/* Models list */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Threat Models</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {MODELS.map((m) => {
            const mitPct = Math.round((m.mitigated_count / m.threats_count) * 100);
            return (
              <div key={m.id} className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="font-semibold text-sm text-gray-200">{m.model_name}</span>
                  <RiskGauge score={m.risk_score} />
                </div>
                <div className="flex flex-wrap gap-1.5 mb-3">
                  <span className={`px-2 py-0.5 rounded text-xs ${METHOD_COLOR[m.methodology]}`}>{m.methodology}</span>
                  <span className={`px-2 py-0.5 rounded text-xs ${COMP_COLOR[m.component_type]}`}>{m.component_type}</span>
                  <span className={`px-2 py-0.5 rounded text-xs ${STATUS_COLOR[m.status]}`}>{m.status}</span>
                </div>
                <div className="text-xs text-gray-400 mb-1">
                  {m.mitigated_count}/{m.threats_count} threats mitigated ({mitPct}%)
                </div>
                <div className="bg-gray-700 rounded-full h-1.5">
                  <div
                    className={`h-1.5 rounded-full ${mitPct === 100 ? "bg-green-500" : mitPct >= 70 ? "bg-yellow-500" : "bg-red-500"}`}
                    style={{ width: `${mitPct}%` }}
                  />
                </div>
                <div className="text-xs text-gray-500 mt-2">Updated {m.last_updated}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* STRIDE coverage grid */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">STRIDE Coverage</h2>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {STRIDE_STATS.map((s) => {
            const pct = Math.round((s.mitigated / s.count) * 100);
            return (
              <div key={s.category} className="bg-gray-700/50 rounded-lg p-3 text-center">
                <div className={`text-xs font-bold mb-1 px-1 py-0.5 rounded ${RISK_LEVEL_COLOR[s.risk_level]}`}>
                  {s.risk_level}
                </div>
                <div className={`text-sm font-semibold mt-2 ${STRIDE_COLOR[s.category].split(" ")[1]}`}>{s.category}</div>
                <div className="text-2xl font-bold text-white mt-1">{s.count}</div>
                <div className="text-xs text-gray-400">{s.mitigated} mitigated</div>
                <div className="bg-gray-700 rounded-full h-1 mt-2">
                  <div className="bg-violet-500 h-1 rounded-full" style={{ width: `${pct}%` }} />
                </div>
                <div className="text-xs text-gray-500 mt-0.5">{pct}%</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Unmitigated threats table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <AlertTriangle size={18} className="text-red-400" /> Unmitigated Threats
            {mitigatedIds.size > 0 && (
              <span className="text-xs text-green-400 font-normal ml-2">({mitigatedIds.size} mitigated this session)</span>
            )}
          </h2>
        </div>
        {visibleThreats.length === 0 ? (
          <div className="text-center py-8 text-green-400 flex flex-col items-center gap-2">
            <CheckCircle2 size={32} />
            <p className="font-medium">All threats mitigated!</p>
          </div>
        ) : (
          <table role="table" className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 border-b border-gray-700">
                <th className="text-left py-2">Threat</th>
                <th className="text-left py-2">STRIDE</th>
                <th className="text-center py-2">L=I</th>
                <th className="text-left py-2">Risk</th>
                <th className="text-left py-2">Model</th>
                <th className="text-center py-2">Action</th>
              </tr>
            </thead>
            <tbody>
              {visibleThreats.map((t) => (
                <tr key={t.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-2 text-gray-200 max-w-xs">
                    <span className="line-clamp-2">{t.threat_name}</span>
                  </td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${STRIDE_COLOR[t.stride_category]}`}>
                      {t.stride_category}
                    </span>
                  </td>
                  <td className="py-2 text-center">
                    <MatrixCell likelihood={t.likelihood} impact={t.impact} />
                  </td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${RISK_LEVEL_COLOR[t.risk_level]}`}>
                      {t.risk_level}
                    </span>
                  </td>
                  <td className="py-2 text-gray-400 text-xs">{t.model_name}</td>
                  <td className="py-2 text-center">
                    <button
                      onClick={() => handleMitigate(t.id)}
                      disabled={mitigating === t.id}
                      className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                        mitigating === t.id
                          ? "bg-gray-700 text-gray-500 cursor-wait"
                          : "bg-violet-700 hover:bg-violet-600 text-white"
                      }`}
                    >
                      {mitigating === t.id ? "Mitigating=" : "Mitigate"}
                    </button>
                  </td>
                </tr>
              ))
            )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
