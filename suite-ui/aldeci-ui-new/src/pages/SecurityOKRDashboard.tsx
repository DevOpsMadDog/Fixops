/**
 * Security OKR Dashboard
 *
 * Objectives and Key Results tracking for security program goals.
 * Shows objectives with progress, key results, period filter, team view,
 * and KR update form.
 *
 * Route: /security-okrs
 * API: GET /api/v1/security-okrs
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/security-okrs";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });


// ── Types ──────────────────────────────────────────────────────

type Period = "Q1 2026" | "Q2 2026" | "Q3 2026" | "Q4 2026";
type KRStatus = "on_track" | "at_risk" | "off_track" | "completed";

interface KeyResult {
  id: string;
  objective_id: string;
  title: string;
  target: number;
  current: number;
  unit: string;
  status: KRStatus;
  owner: string;
  notes: string;
}

interface Objective {
  id: string;
  title: string;
  period: Period;
  owner: string;
  team: string;
  overall_progress: number;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_OBJECTIVES: Objective[] = [
  { id: "obj-001", title: "Reduce critical vulnerability exposure time",      period: "Q2 2026", owner: "CISO",         team: "Security Ops",  overall_progress: 72 },
  { id: "obj-002", title: "Achieve SOC 2 Type II readiness",                 period: "Q2 2026", owner: "GRC Lead",     team: "GRC",           overall_progress: 58 },
  { id: "obj-003", title: "Mature identity and access management program",   period: "Q2 2026", owner: "IAM Lead",     team: "Identity",      overall_progress: 84 },
  { id: "obj-004", title: "Improve security awareness across all employees", period: "Q2 2026", owner: "HR Security",  team: "Awareness",     overall_progress: 45 },
  { id: "obj-005", title: "Build cloud-native security posture to 85+",      period: "Q2 2026", owner: "Cloud SecEng", team: "Cloud Security", overall_progress: 67 },
  { id: "obj-006", title: "Establish threat intelligence sharing program",   period: "Q2 2026", owner: "Threat Intel", team: "CTI",           overall_progress: 30 },
];

const MOCK_KEY_RESULTS: KeyResult[] = [
  // obj-001
  { id: "kr-001", objective_id: "obj-001", title: "Reduce P1 vuln MTTR",          target: 24,  current: 31,  unit: "hours",   status: "at_risk",   owner: "SecOps",      notes: "Working on automation pipeline" },
  { id: "kr-002", objective_id: "obj-001", title: "Patch critical CVEs",           target: 100, current: 87,  unit: "%",       status: "on_track",  owner: "PatchTeam",   notes: "On schedule" },
  { id: "kr-003", objective_id: "obj-001", title: "Eliminate unpatched CVSS≥9",   target: 0,   current: 4,   unit: "vulns",   status: "at_risk",   owner: "SecOps",      notes: "4 remaining in prod" },
  // obj-002
  { id: "kr-004", objective_id: "obj-002", title: "Complete SOC 2 evidence mapping", target: 114, current: 67, unit: "controls", status: "on_track", owner: "GRC Analyst", notes: "On track for June audit" },
  { id: "kr-005", objective_id: "obj-002", title: "Remediate audit gaps",          target: 0,   current: 12,  unit: "gaps",    status: "at_risk",   owner: "GRC Lead",    notes: "12 gaps remain" },
  // obj-003
  { id: "kr-006", objective_id: "obj-003", title: "Enforce MFA for all users",     target: 100, current: 98,  unit: "%",       status: "on_track",  owner: "IAM Team",    notes: "2 execs pending" },
  { id: "kr-007", objective_id: "obj-003", title: "Complete access review",        target: 100, current: 100, unit: "%",       status: "completed", owner: "IAM Lead",    notes: "Completed 2026-04-10" },
  { id: "kr-008", objective_id: "obj-003", title: "Deploy PAM for admins",         target: 50,  current: 42,  unit: "accounts", status: "on_track", owner: "IAM Eng",     notes: "8 remaining" },
  // obj-004
  { id: "kr-009", objective_id: "obj-004", title: "Security training completion",  target: 95,  current: 61,  unit: "%",       status: "off_track", owner: "HR Sec",      notes: "Reminder campaign launching next week" },
  { id: "kr-010", objective_id: "obj-004", title: "Phishing sim click rate",       target: 5,   current: 11,  unit: "%",       status: "off_track", owner: "Awareness",   notes: "Extra training for high-click teams" },
  // obj-005
  { id: "kr-011", objective_id: "obj-005", title: "Cloud posture score",           target: 85,  current: 74,  unit: "score",   status: "on_track",  owner: "Cloud Sec",   notes: "Improving by 2pts/week" },
  { id: "kr-012", objective_id: "obj-005", title: "Misconfigured resources",       target: 0,   current: 18,  unit: "resources", status: "at_risk", owner: "Cloud Sec",   notes: "18 S3/GCS buckets flagged" },
  // obj-006
  { id: "kr-013", objective_id: "obj-006", title: "CTI sharing partnerships",      target: 5,   current: 1,   unit: "orgs",    status: "off_track", owner: "CTI Lead",    notes: "ISAC application submitted" },
  { id: "kr-014", objective_id: "obj-006", title: "IOC distribution per month",    target: 500, current: 120, unit: "IOCs",    status: "off_track", owner: "CTI Analyst", notes: "Feed integration in progress" },
];

// ── Helpers ────────────────────────────────────────────────────

function progressColor(pct: number) {
  if (pct >= 70) return "bg-green-500";
  if (pct >= 30) return "bg-amber-500";
  return "bg-red-500";
}

function progressTextColor(pct: number) {
  if (pct >= 70) return "text-green-400";
  if (pct >= 30) return "text-amber-400";
  return "text-red-400";
}

const krStatusConfig: Record<KRStatus, { label: string; color: string }> = {
  on_track:  { label: "On Track",  color: "bg-green-700 text-green-100" },
  at_risk:   { label: "At Risk",   color: "bg-amber-700 text-amber-100" },
  off_track: { label: "Off Track", color: "bg-red-700 text-red-100" },
  completed: { label: "Completed", color: "bg-blue-700 text-blue-100" },
};

function krProgress(kr: KeyResult) {
  if (kr.unit === "hours" || (kr.target === 0 && kr.current >= 0)) {
    // Lower is better
    if (kr.target === 0) return kr.current === 0 ? 100 : Math.max(0, 100 - kr.current * 10);
    return Math.max(0, Math.min(100, ((kr.target * 2 - kr.current) / (kr.target * 2)) * 100));
  }
  return Math.min(100, Math.round((kr.current / kr.target) * 100));
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityOKRDashboard() {
  const [objectives, setObjectives] = useState(MOCK_OBJECTIVES);

  useEffect(() => {
    fetch(`${_API_BASE}/objectives`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setObjectives(d); })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const [period, setPeriod] = useState<Period>("Q2 2026");
  const [selectedObjective, setSelectedObjective] = useState<string>(MOCK_OBJECTIVES[0].id);
  const [updateKR, setUpdateKR] = useState<string | null>(null);
  const [updateValue, setUpdateValue] = useState("");
  useEffect(() => {
    fetch(`${_API_BASE}/objectives`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setObjectives(d); })
      .catch(() => { setError('Failed to load data'); });
  }, []);
  const [updateNotes, setUpdateNotes] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(true);

  const filteredObjectives = MOCK_OBJECTIVES.filter(o => o.period === period);

  const onTrack  = filteredObjectives.filter(o => o.overall_progress >= 70).length;
  const atRisk   = filteredObjectives.filter(o => o.overall_progress >= 30 && o.overall_progress < 70).length;
  const offTrack = filteredObjectives.filter(o => o.overall_progress < 30).length;

  const selectedObj = filteredObjectives.find(o => o.id === selectedObjective);
  const selectedKRs = MOCK_KEY_RESULTS.filter(kr => kr.objective_id === selectedObjective);

  // Team OKR view
  const teams = [...new Set(filteredObjectives.map(o => o.team))];

  function handleUpdateSubmit() {
    if (updateValue.trim()) {
      setSubmitted(true);
      setTimeout(() => { setSubmitted(false); setUpdateKR(null); setUpdateValue(""); setUpdateNotes(""); }, 3000);
    }
  }

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

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
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security OKRs</h1>
          <p className="text-gray-400 mt-1">Objectives and Key Results for the security program</p>
        </div>
        {/* Period Filter */}
        <div className="flex gap-2 bg-gray-800 rounded-lg p-1">
          {(["Q1 2026", "Q2 2026", "Q3 2026", "Q4 2026"] as Period[]).map(p => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                period === p ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Period Summary */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "On Track",  value: onTrack,  color: "text-green-400", border: "border-green-800" },
          { label: "At Risk",   value: atRisk,   color: "text-amber-400", border: "border-amber-800" },
          { label: "Off Track", value: offTrack, color: "text-red-400",   border: "border-red-800" },
        ].map(s => (
          <div key={s.label} className={`bg-gray-800 rounded-lg p-6 border ${s.border}`}>
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-4xl font-bold mt-1 ${s.color}`}>{s.value}</p>
            <p className="text-gray-500 text-xs mt-1">objective{s.value !== 1 ? "s" : ""}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Objectives List */}
        <div className="lg:col-span-1 space-y-3">
          <h2 className="text-lg font-semibold text-white">Objectives</h2>
          {filteredObjectives.length === 0 ? (
            <p className="text-gray-500 text-sm">No objectives for {period}</p>
          ) : (
            filteredObjectives.map(obj => (
              <div
                key={obj.id}
                onClick={() => setSelectedObjective(obj.id)}
                className={`bg-gray-800 rounded-lg p-4 cursor-pointer transition-all border-2 ${
                  selectedObjective === obj.id ? "border-blue-500" : "border-transparent hover:border-gray-600"
                }`}
              >
                <p className="text-white text-sm font-medium leading-snug">{obj.title}</p>
                <p className="text-gray-500 text-xs mt-1">{obj.team} · {obj.owner}</p>
                <div className="mt-3 flex items-center gap-2">
                  <div className="flex-1 bg-gray-700 rounded-full h-2">
                    <div className={`h-2 rounded-full ${progressColor(obj.overall_progress)}`} style={{ width: `${obj.overall_progress}%` }} />
                  </div>
                  <span className={`text-xs font-bold ${progressTextColor(obj.overall_progress)}`}>{obj.overall_progress}%</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Key Results */}
        <div className="lg:col-span-2 space-y-4">
          <h2 className="text-lg font-semibold text-white">
            Key Results — {selectedObj?.title.slice(0, 50)}{(selectedObj?.title.length ?? 0) > 50 ? "…" : ""}
          </h2>
          {selectedKRs.length === 0 ? (
            <p className="text-gray-500 text-sm">No key results for this objective.</p>
          ) : (
            selectedKRs.map(kr => {
              const progress = krProgress(kr);
              return (
                <div key={kr.id} className="bg-gray-800 rounded-lg p-5 space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1">
                      <p className="text-white font-medium">{kr.title}</p>
                      <p className="text-gray-400 text-xs mt-0.5">Owner: {kr.owner}</p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium shrink-0 ${krStatusConfig[kr.status].color}`}>
                      {krStatusConfig[kr.status].label}
                    </span>
                  </div>
                  {/* Target vs Current */}
                  <div className="flex items-center gap-4 text-sm">
                    <div>
                      <p className="text-gray-500 text-xs">Current</p>
                      <p className={`font-bold text-lg ${progressTextColor(progress)}`}>{kr.current} <span className="text-xs font-normal text-gray-400">{kr.unit}</span></p>
                    </div>
                    <div className="flex-1 flex items-center gap-1 text-gray-600">
                      <div className="flex-1 h-px bg-gray-700" />
                      <span className="text-xs">→</span>
                      <div className="flex-1 h-px bg-gray-700" />
                    </div>
                    <div className="text-right">
                      <p className="text-gray-500 text-xs">Target</p>
                      <p className="font-bold text-lg text-gray-300">{kr.target} <span className="text-xs font-normal text-gray-400">{kr.unit}</span></p>
                    </div>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className={`h-2 rounded-full ${progressColor(progress)}`} style={{ width: `${Math.min(100, progress)}%` }} />
                  </div>
                  {kr.notes && <p className="text-gray-400 text-xs italic">{kr.notes}</p>}
                  <button
                    onClick={() => setUpdateKR(updateKR === kr.id ? null : kr.id)}
                    className="text-blue-400 hover:text-blue-300 text-xs font-medium transition-colors"
                  >
                    {updateKR === kr.id ? "Cancel update" : "Update KR"}
                  </button>

                  {/* Update form */}
                  {updateKR === kr.id && (
                    <div className="bg-gray-900 rounded-lg p-4 space-y-3 border border-gray-700">
                      {submitted && (
                        <p className="text-green-400 text-sm">Update submitted!</p>
                      )}
                      <div>
                        <label className="text-gray-400 text-xs block mb-1">New Current Value ({kr.unit})</label>
                        <input
                          type="number"
                          value={updateValue}
                          onChange={e => setUpdateValue(e.target.value)}
                          placeholder={String(kr.current)}
                          className="w-full bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500"
                        />
                      </div>
                      <div>
                        <label className="text-gray-400 text-xs block mb-1">Notes</label>
                        <textarea
                          value={updateNotes}
                          onChange={e => setUpdateNotes(e.target.value)}
                          placeholder="Add context or blockers..."
                          rows={2}
                          className="w-full bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 resize-none"
                        />
                      </div>
                      <button
                        onClick={handleUpdateSubmit}
                        className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium transition-colors"
                      >
                        Save Update
                      </button>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Team OKR View */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Team OKR View</h2>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {teams.map(team => {
            const teamObjs = filteredObjectives.filter(o => o.team === team);
            const avg = Math.round(teamObjs.reduce((s, o) => s + o.overall_progress, 0) / (teamObjs.length || 1));
            return (
              <div key={team} className="bg-gray-700/50 rounded-lg p-4 text-center">
                <p className="text-gray-300 text-xs font-medium mb-2">{team}</p>
                <div className="relative w-16 h-16 mx-auto">
                  <svg viewBox="0 0 36 36" className="w-16 h-16 -rotate-90">
                    <circle cx="18" cy="18" r="15.9" fill="none" stroke="#374151" strokeWidth="3" />
                    <circle
                      cx="18" cy="18" r="15.9" fill="none"
                      stroke={avg >= 70 ? "#22c55e" : avg >= 30 ? "#f59e0b" : "#ef4444"}
                      strokeWidth="3"
                      strokeDasharray={`${avg} 100`}
                      strokeLinecap="round"
                    />
                  </svg>
                  <span className="absolute inset-0 flex items-center justify-center text-white text-xs font-bold">{avg}%</span>
                </div>
                <p className="text-gray-500 text-xs mt-2">{teamObjs.length} objective{teamObjs.length !== 1 ? "s" : ""}</p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
