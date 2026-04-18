/**
 * Risk Scenario Dashboard
 *
 * Risk scenario analysis with matrix visualization and mitigation tracking.
 *   1. Risk matrix (2D grid: likelihood 1-10 x impact 1-10, colored quadrants)
 *   2. Scenario list table (name, threat_category, inherent_risk, residual_risk, reduction_pct, risk_level)
 *   3. Mitigation panel per scenario (name, type, effectiveness bar, implemented toggle)
 *   4. Top 10 risks by residual score
 *   5. Risk stats (by level counts, avg inherent vs residual)
 *
 * Route: /risk-scenarios
 * API: GET /api/v1/risk-scenarios
 */

import { useState, useEffect } from "react";
import {
  ShieldAlert, TrendingDown, BarChart2, Target, ChevronDown, ChevronUp, Activity
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

interface RiskScenario {
  id: string;
  scenario_name: string;
  threat_category: string;
  likelihood: number;    // 1-10
  impact: number;        // 1-10
  inherent_risk: number; // likelihood * impact
  residual_risk: number;
  reduction_pct: number;
  risk_level: "critical" | "high" | "medium" | "low";
  mitigations: Mitigation[];
}

interface Mitigation {
  id: string;
  mitigation_name: string;
  type: "preventive" | "detective" | "corrective";
  effectiveness: number; // 0-100
  implemented: boolean;
}

// ── Mock data ──────────────────────────────────────────────────

const SCENARIOS: RiskScenario[] = [
  {
    id: "rs1", scenario_name: "Ransomware Attack on Core Systems", threat_category: "Malware",
    likelihood: 8, impact: 9, inherent_risk: 72, residual_risk: 28, reduction_pct: 61, risk_level: "high",
    mitigations: [
      { id: "m1", mitigation_name: "Endpoint EDR Deployment", type: "detective", effectiveness: 82, implemented: true },
      { id: "m2", mitigation_name: "Offline Backup Strategy", type: "corrective", effectiveness: 75, implemented: true },
      { id: "m3", mitigation_name: "Network Segmentation", type: "preventive", effectiveness: 68, implemented: false },
    ],
  },
  {
    id: "rs2", scenario_name: "Insider Data Exfiltration", threat_category: "Insider Threat",
    likelihood: 6, impact: 8, inherent_risk: 48, residual_risk: 18, reduction_pct: 63, risk_level: "high",
    mitigations: [
      { id: "m4", mitigation_name: "DLP Policy Enforcement", type: "preventive", effectiveness: 71, implemented: true },
      { id: "m5", mitigation_name: "UBA / UEBA Monitoring", type: "detective", effectiveness: 65, implemented: true },
    ],
  },
  {
    id: "rs3", scenario_name: "Supply Chain Software Compromise", threat_category: "Supply Chain",
    likelihood: 5, impact: 9, inherent_risk: 45, residual_risk: 30, reduction_pct: 33, risk_level: "high",
    mitigations: [
      { id: "m6", mitigation_name: "SBOM Verification", type: "preventive", effectiveness: 58, implemented: false },
      { id: "m7", mitigation_name: "Vendor Risk Assessment", type: "detective", effectiveness: 50, implemented: true },
    ],
  },
  {
    id: "rs4", scenario_name: "Cloud Misconfiguration Exposure", threat_category: "Cloud Security",
    likelihood: 7, impact: 7, inherent_risk: 49, residual_risk: 14, reduction_pct: 71, risk_level: "medium",
    mitigations: [
      { id: "m8", mitigation_name: "CSPM Continuous Scanning", type: "detective", effectiveness: 88, implemented: true },
      { id: "m9", mitigation_name: "IaC Policy Gates", type: "preventive", effectiveness: 77, implemented: true },
    ],
  },
  {
    id: "rs5", scenario_name: "Phishing / Credential Theft", threat_category: "Social Engineering",
    likelihood: 9, impact: 7, inherent_risk: 63, residual_risk: 22, reduction_pct: 65, risk_level: "high",
    mitigations: [
      { id: "m10", mitigation_name: "MFA Everywhere", type: "preventive", effectiveness: 90, implemented: true },
      { id: "m11", mitigation_name: "Phishing Simulation Training", type: "preventive", effectiveness: 55, implemented: true },
    ],
  },
  {
    id: "rs6", scenario_name: "Zero-Day Exploit in Public App", threat_category: "Vulnerability",
    likelihood: 4, impact: 10, inherent_risk: 40, residual_risk: 25, reduction_pct: 38, risk_level: "critical",
    mitigations: [
      { id: "m12", mitigation_name: "WAF Virtual Patching", type: "preventive", effectiveness: 60, implemented: true },
      { id: "m13", mitigation_name: "Bug Bounty Program", type: "detective", effectiveness: 45, implemented: false },
    ],
  },
  {
    id: "rs7", scenario_name: "DDoS Against Production APIs", threat_category: "Availability",
    likelihood: 6, impact: 6, inherent_risk: 36, residual_risk: 12, reduction_pct: 67, risk_level: "medium",
    mitigations: [
      { id: "m14", mitigation_name: "CDN + Rate Limiting", type: "preventive", effectiveness: 80, implemented: true },
    ],
  },
  {
    id: "rs8", scenario_name: "Regulatory Non-Compliance Fine", threat_category: "Compliance",
    likelihood: 3, impact: 8, inherent_risk: 24, residual_risk: 8, reduction_pct: 67, risk_level: "low",
    mitigations: [
      { id: "m15", mitigation_name: "Compliance Automation", type: "preventive", effectiveness: 72, implemented: true },
    ],
  },
  {
    id: "rs9", scenario_name: "API Key / Secret Leakage", threat_category: "Secrets Management",
    likelihood: 7, impact: 8, inherent_risk: 56, residual_risk: 20, reduction_pct: 64, risk_level: "high",
    mitigations: [
      { id: "m16", mitigation_name: "Secret Scanner in CI/CD", type: "detective", effectiveness: 84, implemented: true },
      { id: "m17", mitigation_name: "Vault Secret Rotation", type: "corrective", effectiveness: 78, implemented: false },
    ],
  },
  {
    id: "rs10", scenario_name: "Physical Break-In / Device Theft", threat_category: "Physical Security",
    likelihood: 2, impact: 6, inherent_risk: 12, residual_risk: 4, reduction_pct: 67, risk_level: "low",
    mitigations: [
      { id: "m18", mitigation_name: "Full Disk Encryption", type: "preventive", effectiveness: 95, implemented: true },
    ],
  },
];

// ── Helpers ────────────────────────────────────────────────────

const riskColor: Record<RiskScenario["risk_level"], string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-yellow-600 text-black",
  low: "bg-green-600 text-white",
};

const riskText: Record<RiskScenario["risk_level"], string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

const mitTypeColor: Record<Mitigation["type"], string> = {
  preventive: "bg-blue-900 text-blue-300",
  detective: "bg-purple-900 text-purple-300",
  corrective: "bg-teal-900 text-teal-300",
};

function cellColor(l: number, i: number): string {
  const score = l * i;
  if (score >= 64) return "bg-red-700/70";
  if (score >= 36) return "bg-orange-700/60";
  if (score >= 16) return "bg-yellow-700/50";
  return "bg-green-700/40";
}

// ── Component ──────────────────────────────────────────────────

export default function RiskScenarioDashboard() {
  const [selectedScenario, setSelectedScenario] = useState<RiskScenario | null>(SCENARIOS[0]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    fetch("/api/v1/risk-scenarios", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);
  const [sortField, setSortField] = useState<"residual_risk" | "inherent_risk">("residual_risk");
  const [loading, setLoading] = useState(true);

  const avgInherent = Math.round(SCENARIOS.reduce((s, r) => s + r.inherent_risk, 0) / SCENARIOS.length);
  const avgResidual = Math.round(SCENARIOS.reduce((s, r) => s + r.residual_risk, 0) / SCENARIOS.length);
  const byLevel = {
    critical: SCENARIOS.filter(r => r.risk_level === "critical").length,
    high: SCENARIOS.filter(r => r.risk_level === "high").length,
    medium: SCENARIOS.filter(r => r.risk_level === "medium").length,
    low: SCENARIOS.filter(r => r.risk_level === "low").length,
  };

  const topRisks = [...SCENARIOS].sort((a, b) => b.residual_risk - a.residual_risk).slice(0, 10);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
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
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-orange-400" />
            Risk Scenarios
          </h1>
          <p className="text-gray-400 text-sm mt-1">Inherent vs residual risk analysis with mitigation tracking</p>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {(["critical","high","medium","low"] as const).map(lvl => (
          <div key={lvl} className="bg-gray-800 rounded-lg p-5">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-2 capitalize">{lvl} Risk</div>
            <div className={`text-3xl font-bold ${riskText[lvl]}`}>{byLevel[lvl]}</div>
            <div className="text-gray-500 text-xs mt-1">scenarios</div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Risk matrix */}
        <div className="bg-gray-800 rounded-lg p-5">
          <div className="font-semibold mb-4 flex items-center gap-2">
            <Target className="w-4 h-4 text-orange-400" /> Risk Matrix (Likelihood × Impact)
          </div>
          <div className="text-xs text-gray-400 mb-2 text-center">Impact →</div>
          <div className="flex gap-1 items-end">
            <div className="flex flex-col gap-1 items-end mr-1">
              {[10,8,6,4,2].map(l => (
                <div key={l} className="text-xs text-gray-500 h-6 flex items-center">{l}</div>
              ))}
              <div className="text-xs text-gray-400 mt-1" style={{ writingMode: "vertical-rl", transform: "rotate(180deg)" }}>Likelihood</div>
            </div>
            <div className="grid gap-1" style={{ gridTemplateColumns: "repeat(5, 1fr)", gridTemplateRows: "repeat(5, 1fr)" }}>
              {[10,8,6,4,2].map(l =>
                [2,4,6,8,10].map(i => {
                  const dot = SCENARIOS.find(s => Math.abs(s.likelihood - l) <= 1 && Math.abs(s.impact - i) <= 1);
                  return (
                    <div
                      key={`${l}-${i}`}
                      className={`w-10 h-6 rounded flex items-center justify-center ${cellColor(l, i)}`}
                      title={dot ? dot.scenario_name : ""}
                    >
                      {dot && <div className="w-2 h-2 bg-white rounded-full opacity-80" />}
                    </div>
                  );
                })
            </div>
          </div>
          <div className="flex gap-3 mt-4 flex-wrap">
            {[
              { label: "Critical (≥64)", color: "bg-red-700" },
              { label: "High (36-63)", color: "bg-orange-700" },
              { label: "Medium (16-35)", color: "bg-yellow-700" },
              { label: "Low (<16)", color: "bg-green-700" },
            ].map(l => (
              <div key={l.label} className="flex items-center gap-1 text-xs text-gray-400">
                <div className={`w-3 h-3 rounded ${l.color}`} />
                {l.label}
              </div>
            ))}
          </div>
        </div>

        {/* Top 10 risks */}
        <div className="bg-gray-800 rounded-lg p-5">
          <div className="font-semibold mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-red-400" /> Top Risks by Residual Score
          </div>
          <div className="space-y-2">
            {topRisks.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              topRisks.map((r, idx) => (
              <div
                key={r.id}
                onClick={() => setSelectedScenario(r)}
                className={`flex items-center gap-3 p-2 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors ${
                  selectedScenario?.id === r.id ? "bg-blue-900/30" : ""
                }`}
              >
                <span className="text-gray-500 text-xs w-4">{idx + 1}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">{r.scenario_name}</div>
                  <div className="w-full bg-gray-700 rounded-full h-1 mt-1">
                    <div
                      className={`h-1 rounded-full ${r.risk_level === "critical" ? "bg-red-500" : r.risk_level === "high" ? "bg-orange-500" : r.risk_level === "medium" ? "bg-yellow-500" : "bg-green-500"}`}
                      style={{ width: `${(r.residual_risk / 100) * 100}%` }}
                    />
                  </div>
                </div>
                <span className={`text-xs font-bold ${riskText[r.risk_level]}`}>{r.residual_risk}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Stats */}
        <div className="bg-gray-800 rounded-lg p-5 space-y-4">
          <div className="font-semibold flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-blue-400" /> Risk Reduction Stats
          </div>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs text-gray-400 mb-1">
                <span>Avg Inherent Risk</span><span className="text-orange-400 font-bold">{avgInherent}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div className="h-2 bg-orange-500 rounded-full" style={{ width: `${avgInherent}%` }} />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-xs text-gray-400 mb-1">
                <span>Avg Residual Risk</span><span className="text-green-400 font-bold">{avgResidual}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div className="h-2 bg-green-500 rounded-full" style={{ width: `${avgResidual}%` }} />
              </div>
            </div>
            <div className="pt-2 border-t border-gray-700">
              <div className="flex justify-between text-xs text-gray-400 mb-1">
                <span>Avg Reduction</span>
                <span className="text-blue-400 font-bold">
                  {Math.round(SCENARIOS.reduce((s, r) => s + r.reduction_pct, 0) / SCENARIOS.length)}%
                </span>
              </div>
            </div>
          </div>
          {/* Level distribution bars */}
          <div className="pt-2 border-t border-gray-700 space-y-2">
            <div className="text-xs text-gray-400 font-medium mb-2">Distribution by Level</div>
            {(["critical","high","medium","low"] as const).map(lvl => {
              const pct = Math.round((byLevel[lvl] / SCENARIOS.length) * 100);
              return (
                <div key={lvl}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className={`capitalize ${riskText[lvl]}`}>{lvl}</span>
                    <span className="text-gray-400">{byLevel[lvl]}</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full ${lvl === "critical" ? "bg-red-500" : lvl === "high" ? "bg-orange-500" : lvl === "medium" ? "bg-yellow-500" : "bg-green-500"}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Scenario table + mitigation panel */}
      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700 font-semibold flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-orange-400" /> Scenario List
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-700/50">
                <tr>
                  {["Scenario","Category","Inherent","Residual","Reduction","Level"].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {SCENARIOS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  SCENARIOS.map(s => (
                  <tr
                    key={s.id}
                    onClick={() => setSelectedScenario(s)}
                    className={`border-t border-gray-700 hover:bg-gray-700/40 cursor-pointer transition-colors ${
                      selectedScenario?.id === s.id ? "bg-blue-900/20" : ""
                    }`}
                  >
                    <td className="px-4 py-3 font-medium text-sm">{s.scenario_name}</td>
                    <td className="px-4 py-3">
                      <span className="bg-indigo-900 text-indigo-300 px-2 py-0.5 rounded text-xs">{s.threat_category}</span>
                    </td>
                    <td className="px-4 py-3 text-orange-400 font-bold">{s.inherent_risk}</td>
                    <td className="px-4 py-3 text-green-400 font-bold">{s.residual_risk}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-gray-700 rounded-full h-1.5">
                          <div className="h-1.5 bg-blue-500 rounded-full" style={{ width: `${s.reduction_pct}%` }} />
                        </div>
                        <span className="text-xs text-blue-300">{s.reduction_pct}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${riskColor[s.risk_level]}`}>
                        {s.risk_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Mitigation panel */}
        <div className="bg-gray-800 rounded-lg p-4 space-y-3">
          <div className="font-semibold flex items-center gap-2">
            <TrendingDown className="w-4 h-4 text-green-400" />
            {selectedScenario ? `Mitigations: ${selectedScenario.scenario_name.slice(0, 30)}...` : "Select a scenario"}
          </div>
          {selectedScenario ? (
            <div className="space-y-3">
              {selectedScenario.mitigations.map(m => (
                <div key={m.id} className="bg-gray-700/50 rounded-lg p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{m.mitigation_name}</span>
                    <span className={`w-2 h-2 rounded-full ${m.implemented ? "bg-green-400" : "bg-gray-500"}`} />
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${mitTypeColor[m.type]}`}>{m.type}</span>
                    <span className={`text-xs ${m.implemented ? "text-green-400" : "text-gray-500"}`}>
                      {m.implemented ? "Implemented" : "Planned"}
                    </span>
                  </div>
                  <div>
                    <div className="flex justify-between text-xs text-gray-400 mb-1">
                      <span>Effectiveness</span><span>{m.effectiveness}%</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-1.5">
                      <div
                        className={`h-1.5 rounded-full ${m.effectiveness >= 75 ? "bg-green-500" : m.effectiveness >= 50 ? "bg-yellow-500" : "bg-red-500"}`}
                        style={{ width: `${m.effectiveness}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-sm">Click on a scenario to view its mitigations.</p>
          )}
        </div>
      </div>
    </div>
  );
}
