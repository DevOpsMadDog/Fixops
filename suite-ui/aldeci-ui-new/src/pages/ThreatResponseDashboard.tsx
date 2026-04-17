/**
 * Threat Response Dashboard
 *
 * Active incidents, action logs, resolve controls, and playbook performance.
 *   1. KPIs: total_playbooks / active_incidents / resolved_incidents / avg_resolution_mins
 *   2. Active incidents table with action progress bars
 *   3. Per-incident action log
 *   4. Resolve incident button
 *   5. Playbook performance table
 *
 * Route: /threat-response
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/threat-response";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { motion } from "framer-motion";
import { Swords, Clock, CheckCircle, XCircle, AlertTriangle, Play, BarChart2 } from "lucide-react";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_INCIDENTS = [
  { id: "inc-001", incident_name: "Ransomware Activity on HR-Server-02",   threat_type: "Ransomware",      severity: "critical", started_at: "2026-04-16T08:12:00Z", triggered_by: "EDR Alert #8821",  actions_completed: 6,  actions_total: 12 },
  { id: "inc-002", incident_name: "Credential Stuffing — Auth API",         threat_type: "Brute Force",     severity: "high",     started_at: "2026-04-16T09:05:00Z", triggered_by: "WAF Rule #4412",   actions_completed: 4,  actions_total: 8  },
  { id: "inc-003", incident_name: "APT Lateral Movement Detected",          threat_type: "APT",             severity: "critical", started_at: "2026-04-16T07:44:00Z", triggered_by: "NDR Anomaly",      actions_completed: 9,  actions_total: 15 },
  { id: "inc-004", incident_name: "Phishing Campaign — Finance Dept",       threat_type: "Phishing",        severity: "high",     started_at: "2026-04-16T09:33:00Z", triggered_by: "Email Filter",     actions_completed: 3,  actions_total: 6  },
  { id: "inc-005", incident_name: "Suspicious Cloud Egress — S3 Bucket",    threat_type: "Data Exfiltration",severity: "high",    started_at: "2026-04-16T08:57:00Z", triggered_by: "CSPM Alert",       actions_completed: 2,  actions_total: 7  },
];

type ActionStatus = "pending" | "in_progress" | "completed" | "failed";

const MOCK_ACTIONS: Record<string, { action_name: string; type: string; status: ActionStatus; executed_by: string; duration: string }[]> = {
  "inc-001": [
    { action_name: "Isolate Host",               type: "containment",   status: "completed",  executed_by: "AutoPlaybook", duration: "00:02" },
    { action_name: "Capture Memory Dump",        type: "forensics",     status: "completed",  executed_by: "alice@aldeci.io", duration: "00:08" },
    { action_name: "Identify Ransomware Variant",type: "analysis",      status: "completed",  executed_by: "AutoPlaybook", duration: "00:03" },
    { action_name: "Block C2 IPs at Firewall",   type: "containment",   status: "completed",  executed_by: "AutoPlaybook", duration: "00:01" },
    { action_name: "Notify Security Leadership", type: "communication", status: "completed",  executed_by: "AutoPlaybook", duration: "00:00" },
    { action_name: "Restore from Backup",        type: "recovery",      status: "completed",  executed_by: "bob@aldeci.io", duration: "00:22" },
    { action_name: "Patch Vulnerability",        type: "remediation",   status: "in_progress",executed_by: "carol@aldeci.io", duration: "" },
    { action_name: "Full Endpoint Scan",         type: "analysis",      status: "pending",    executed_by: "",             duration: "" },
  ],
  "inc-002": [
    { action_name: "Rate Limit Auth Endpoint",   type: "containment",   status: "completed",  executed_by: "AutoPlaybook", duration: "00:01" },
    { action_name: "Block Top 100 Attacker IPs", type: "containment",   status: "completed",  executed_by: "AutoPlaybook", duration: "00:02" },
    { action_name: "Reset Compromised Accounts", type: "remediation",   status: "completed",  executed_by: "alice@aldeci.io", duration: "00:15" },
    { action_name: "Enable CAPTCHA",             type: "hardening",     status: "completed",  executed_by: "AutoPlaybook", duration: "00:01" },
    { action_name: "Notify Affected Users",      type: "communication", status: "in_progress",executed_by: "dave@aldeci.io", duration: "" },
    { action_name: "Forensic Log Review",        type: "analysis",      status: "pending",    executed_by: "",             duration: "" },
  ],
};

const MOCK_PLAYBOOKS = [
  { id: "pb-001", playbook_name: "Ransomware IR",              threat_type: "Ransomware",       execution_count: 14, avg_resolution_mins:  87, step_count: 12 },
  { id: "pb-002", playbook_name: "Credential Attack Response", threat_type: "Brute Force",      execution_count: 34, avg_resolution_mins:  32, step_count:  8 },
  { id: "pb-003", playbook_name: "APT Lateral Movement IR",    threat_type: "APT",              execution_count:  5, avg_resolution_mins: 142, step_count: 15 },
  { id: "pb-004", playbook_name: "Phishing Response",          threat_type: "Phishing",         execution_count: 78, avg_resolution_mins:  18, step_count:  6 },
  { id: "pb-005", playbook_name: "Data Exfiltration Response", threat_type: "Data Exfiltration",execution_count: 11, avg_resolution_mins:  55, step_count:  7 },
  { id: "pb-006", playbook_name: "DDoS Mitigation",            threat_type: "DDoS",             execution_count: 22, avg_resolution_mins:  23, step_count:  5 },
];

// ── Helpers ────────────────────────────────────────────────────

function age(iso: string) {
  const mins = Math.floor((new Date("2026-04-16T10:00:00Z").getTime() - new Date(iso).getTime()) / 60000);
  if (mins < 60) return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ${mins % 60}m ago`;
}

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    low:      "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium capitalize", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}

function ThreatBadge({ t }: { t: string }) {
  const colors = ["bg-red-500/20 text-red-300", "bg-orange-500/20 text-orange-300", "bg-purple-500/20 text-purple-300", "bg-pink-500/20 text-pink-300", "bg-yellow-500/20 text-yellow-300"];
  const idx = t.length % colors.length;
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", colors[idx])}>{t}</span>;
}

function ActionTypeBadge({ t }: { t: string }) {
  const cls: Record<string, string> = {
    containment:   "bg-red-500/20 text-red-400",
    forensics:     "bg-purple-500/20 text-purple-400",
    analysis:      "bg-blue-500/20 text-blue-400",
    communication: "bg-teal-500/20 text-teal-400",
    recovery:      "bg-emerald-500/20 text-emerald-400",
    remediation:   "bg-cyan-500/20 text-cyan-400",
    hardening:     "bg-indigo-500/20 text-indigo-400",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium capitalize", cls[t] ?? "bg-gray-700 text-gray-300")}>{t}</span>;
}

function ActionStatusBadge({ s }: { s: ActionStatus }) {
  const cls: Record<ActionStatus, string> = {
    pending:     "bg-gray-500/20 text-gray-400",
    in_progress: "bg-blue-500/20 text-blue-400",
    completed:   "bg-emerald-500/20 text-emerald-400",
    failed:      "bg-red-500/20 text-red-400",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium capitalize", cls[s])}>{s.replace(/_/g, " ")}</span>;
}

function KpiCard({ icon: Icon, label, value, sub, color }: { icon: React.ElementType; label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className="bg-gray-800 rounded-lg p-6 flex items-start gap-4">
      <div className={cn("p-3 rounded-lg", color)}><Icon className="w-5 h-5" /></div>
      <div>
        <p className="text-gray-400 text-sm">{label}</p>
        <p className="text-2xl font-bold text-white mt-0.5">{value}</p>
        {sub && <p className="text-gray-500 text-xs mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function ThreatResponseDashboard() {
  const [selectedIncident, setSelectedIncident] = useState(MOCK_INCIDENTS[0]);
  useEffect(() => {
    fetch(_API_BASE, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setSelectedIncident(d); })
      .catch(() => {});
  }, []);
  const [resolved, setResolved] = useState<Set<string>>(new Set());
  const [resolveMsg, setResolveMsg] = useState("");

  const actions = MOCK_ACTIONS[selectedIncident.id] ?? [];
  const activeIncidents = MOCK_INCIDENTS.filter(i => !resolved.has(i.id));

  function resolveIncident() {
    setResolved(prev => new Set([...prev, selectedIncident.id]));
    setResolveMsg(`Incident "${selectedIncident.incident_name}" marked as resolved.`);
    const next = MOCK_INCIDENTS.find(i => i.id !== selectedIncident.id && !resolved.has(i.id));
    if (next) setSelectedIncident(next);
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Swords className="w-6 h-6 text-red-400" /> Threat Response</h1>
          <p className="text-gray-400 text-sm mt-1">Active incident management, playbook execution, and resolution tracking</p>
        </div>
      </div>

      {resolveMsg && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
          className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-lg text-sm flex items-center gap-2">
          <CheckCircle className="w-4 h-4" /> {resolveMsg}
        </motion.div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard icon={Play}         label="Total Playbooks"      value={MOCK_PLAYBOOKS.length}  color="bg-blue-500/20 text-blue-400" />
        <KpiCard icon={AlertTriangle} label="Active Incidents"    value={activeIncidents.length} color="bg-red-500/20 text-red-400" />
        <KpiCard icon={CheckCircle}  label="Resolved"             value={resolved.size}           sub="this session"                 color="bg-emerald-500/20 text-emerald-400" />
        <KpiCard icon={Clock}        label="Avg Resolution"       value="47m"                     sub="last 30 days"                 color="bg-yellow-500/20 text-yellow-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Incidents */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Active Incidents</h2>
            <div className="space-y-3">
              {MOCK_INCIDENTS.map(inc => {
                const isResolved = resolved.has(inc.id);
                return (
                  <button key={inc.id} onClick={() => !isResolved && setSelectedIncident(inc)}
                    className={cn("w-full bg-gray-900 rounded-lg px-4 py-3 text-left transition-all border",
                      isResolved           ? "opacity-40 border-transparent cursor-default" :
                      selectedIncident.id === inc.id ? "border-red-500/50" : "border-transparent hover:border-gray-600")}>
                    <div className="flex items-center gap-3 flex-wrap">
                      <SeverityBadge s={inc.severity} />
                      <ThreatBadge t={inc.threat_type} />
                      <span className="text-white text-xs font-semibold flex-1 truncate">{inc.incident_name}</span>
                      <span className="text-gray-500 text-xs">{age(inc.started_at)}</span>
                      {isResolved && <span className="text-emerald-400 text-xs font-bold">RESOLVED</span>}
                    </div>
                    <div className="mt-2">
                      <div className="flex items-center justify-between text-[10px] text-gray-500 mb-1">
                        <span>Actions: {inc.actions_completed}/{inc.actions_total}</span>
                        <span>{Math.round((inc.actions_completed / inc.actions_total) * 100)}%</span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-1.5">
                        <div className={cn("h-1.5 rounded-full", isResolved ? "bg-emerald-500" : "bg-blue-500")}
                          style={{ width: `${(inc.actions_completed / inc.actions_total) * 100}%` }} />
                      </div>
                    </div>
                    <p className="text-gray-500 text-[10px] mt-1">Triggered by: {inc.triggered_by}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Playbook Performance */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-blue-400" /> Playbook Performance
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                    <th className="text-left pb-2 pr-4">Playbook</th>
                    <th className="text-left pb-2 pr-4">Threat Type</th>
                    <th className="text-left pb-2 pr-4">Executions</th>
                    <th className="text-left pb-2 pr-4">Avg Resolution</th>
                    <th className="text-left pb-2">Steps</th>
                  </tr>
                </thead>
                <tbody>
                  {MOCK_PLAYBOOKS.map(pb => (
                    <tr key={pb.id} className="border-b border-gray-700/50 hover:bg-gray-700/20">
                      <td className="py-2.5 pr-4 text-white text-xs font-semibold">{pb.playbook_name}</td>
                      <td className="py-2.5 pr-4"><ThreatBadge t={pb.threat_type} /></td>
                      <td className="py-2.5 pr-4 text-gray-300">{pb.execution_count}</td>
                      <td className="py-2.5 pr-4">
                        <span className={cn("text-xs font-semibold",
                          pb.avg_resolution_mins < 30 ? "text-emerald-400" :
                          pb.avg_resolution_mins < 60 ? "text-yellow-400" : "text-red-400")}>
                          {pb.avg_resolution_mins}m
                        </span>
                      </td>
                      <td className="py-2.5 text-gray-400">{pb.step_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Action Log */}
        <div className="bg-gray-800 rounded-lg p-6 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Action Log</h2>
            {!resolved.has(selectedIncident.id) && (
              <button onClick={resolveIncident}
                className="flex items-center gap-1 bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded text-xs font-medium transition-colors">
                <CheckCircle className="w-3.5 h-3.5" /> Resolve
              </button>
            )}
          </div>
          <p className="text-xs text-gray-400 mb-3 truncate">
            <span className="text-white font-semibold">{selectedIncident.incident_name}</span>
          </p>
          <div className="space-y-2 flex-1 overflow-y-auto max-h-[480px]">
            {actions.map((a, i) => (
              <div key={i} className={cn("bg-gray-900 rounded-lg px-3 py-2.5",
                a.status === "completed"  && "border-l-2 border-emerald-500/50",
                a.status === "in_progress"&& "border-l-2 border-blue-500/50",
                a.status === "failed"     && "border-l-2 border-red-500/50",
                a.status === "pending"    && "border-l-2 border-gray-600/50")}>
                <div className="flex items-center gap-2 mb-1">
                  {a.status === "completed"   && <CheckCircle className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />}
                  {a.status === "in_progress" && <Play        className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />}
                  {a.status === "failed"      && <XCircle     className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />}
                  {a.status === "pending"     && <Clock       className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />}
                  <span className="text-xs text-white font-medium">{a.action_name}</span>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <ActionTypeBadge t={a.type} />
                  <ActionStatusBadge s={a.status} />
                  {a.duration && <span className="text-[10px] text-gray-500 ml-auto">{a.duration}</span>}
                </div>
                {a.executed_by && (
                  <p className="text-[10px] text-gray-600 mt-1">{a.executed_by}</p>
                )}
              </div>
            ))}
            {actions.length === 0 && (
              <p className="text-gray-500 text-sm text-center py-8">No actions logged for this incident.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
