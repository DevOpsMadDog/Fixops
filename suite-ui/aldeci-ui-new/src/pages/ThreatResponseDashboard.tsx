/**
 * Threat Response Dashboard - Live API
 * Route: /threat-response
 * API: GET /api/v1/threat-response/incidents/active
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Swords, Clock, CheckCircle, XCircle, AlertTriangle, Play, BarChart2, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

type ActionStatus = "pending" | "in_progress" | "completed" | "failed";

function age(iso: string) {
  try {
    const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
    if (mins < 60) return `${mins}m ago`;
    return `${Math.floor(mins / 60)}h ${mins % 60}m ago`;
  } catch { return iso; }
}

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border border-red-500/30", high: "bg-orange-500/20 text-orange-400 border border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30", low: "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30" };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium capitalize", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}
function ThreatBadge({ t }: { t: string }) {
  const colors = ["bg-red-500/20 text-red-300", "bg-orange-500/20 text-orange-300", "bg-purple-500/20 text-purple-300", "bg-pink-500/20 text-pink-300", "bg-yellow-500/20 text-yellow-300"];
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", colors[(t || "").length % colors.length])}>{t}</span>;
}
function ActionTypeBadge({ t }: { t: string }) {
  const cls: Record<string, string> = { containment: "bg-red-500/20 text-red-400", forensics: "bg-purple-500/20 text-purple-400", analysis: "bg-blue-500/20 text-blue-400", communication: "bg-teal-500/20 text-teal-400", recovery: "bg-emerald-500/20 text-emerald-400", remediation: "bg-cyan-500/20 text-cyan-400", hardening: "bg-indigo-500/20 text-indigo-400" };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium capitalize", cls[t] ?? "bg-gray-700 text-gray-300")}>{t}</span>;
}
function ActionStatusBadge({ s }: { s: ActionStatus }) {
  const cls: Record<ActionStatus, string> = { pending: "bg-gray-500/20 text-gray-400", in_progress: "bg-blue-500/20 text-blue-400", completed: "bg-emerald-500/20 text-emerald-400", failed: "bg-red-500/20 text-red-400" };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium capitalize", cls[s])}>{(s ?? "pending").replace(/_/g, " ")}</span>;
}
function KpiCard({ icon: Icon, label, value, sub, color }: { icon: React.ElementType; label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className="bg-gray-800 rounded-lg p-6 flex items-start gap-4">
      <div className={cn("p-3 rounded-lg", color)}><Icon className="w-5 h-5" /></div>
      <div><p className="text-gray-400 text-sm">{label}</p><p className="text-2xl font-bold text-white mt-0.5">{value}</p>{sub && <p className="text-gray-500 text-xs mt-0.5">{sub}</p>}</div>
    </div>
  );
}

export default function ThreatResponseDashboard() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [actionsByInc, setActionsByInc] = useState<Record<string, any[]>>({});
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [resolved, setResolved] = useState<Set<string>>(new Set());
  const [resolveMsg, setResolveMsg] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [incRes, pbRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/threat-response/incidents/active"),
        apiFetch<any>("/api/v1/threat-response/playbooks"),
      ]);
      if (incRes.status === "fulfilled") {
        const v = incRes.value;
        const arr = Array.isArray(v) ? v : (v.incidents ?? v.items ?? []);
        setIncidents(arr);
        const amap: Record<string, any[]> = {};
        arr.forEach((i: any) => { if (Array.isArray(i.actions)) amap[i.id] = i.actions; });
        setActionsByInc(amap);
        if (arr.length && !selectedIncident) setSelectedIncident(arr[0]);
      }
      if (pbRes.status === "fulfilled") {
        const v = pbRes.value;
        setPlaybooks(Array.isArray(v) ? v : (v.playbooks ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const actions = selectedIncident ? (actionsByInc[selectedIncident.id] ?? []) : [];
  const activeIncidents = incidents.filter(i => !resolved.has(i.id));

  function resolveIncident() {
    if (!selectedIncident) return;
    setResolved(prev => new Set([...prev, selectedIncident.id]));
    setResolveMsg(`Incident "${selectedIncident.incident_name ?? selectedIncident.name}" marked as resolved.`);
    const next = incidents.find(i => i.id !== selectedIncident.id && !resolved.has(i.id));
    if (next) setSelectedIncident(next);
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Swords className="w-6 h-6 text-red-400" /> Threat Response</h1>
          <p className="text-gray-400 text-sm mt-1">Active incident management, playbook execution, and resolution tracking</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : incidents.length === 0 && playbooks.length === 0 ? <EmptyState icon={Swords} title="No active incidents" description="No threat incidents or playbooks recorded yet." />
        : <>
          {resolveMsg && <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-lg text-sm flex items-center gap-2"><CheckCircle className="w-4 h-4" /> {resolveMsg}</motion.div>}

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <KpiCard icon={Play} label="Total Playbooks" value={playbooks.length} color="bg-blue-500/20 text-blue-400" />
            <KpiCard icon={AlertTriangle} label="Active Incidents" value={activeIncidents.length} color="bg-red-500/20 text-red-400" />
            <KpiCard icon={CheckCircle} label="Resolved" value={resolved.size} sub="this session" color="bg-emerald-500/20 text-emerald-400" />
            <KpiCard icon={Clock} label="Total Incidents" value={incidents.length} color="bg-yellow-500/20 text-yellow-400" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-4">
              {incidents.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Active Incidents</h2>
                <div className="space-y-3">{incidents.map(inc => {
                  const isResolved = resolved.has(inc.id);
                  const total = inc.actions_total ?? 0;
                  const completed = inc.actions_completed ?? 0;
                  const pct = total > 0 ? (completed / total) * 100 : 0;
                  return (
                    <button key={inc.id} onClick={() => !isResolved && setSelectedIncident(inc)}
                      className={cn("w-full bg-gray-900 rounded-lg px-4 py-3 text-left border", isResolved ? "opacity-40 border-transparent cursor-default" : selectedIncident?.id === inc.id ? "border-red-500/50" : "border-transparent hover:border-gray-600")}>
                      <div className="flex items-center gap-3 flex-wrap">
                        <SeverityBadge s={inc.severity ?? "medium"} />
                        <ThreatBadge t={inc.threat_type ?? "—"} />
                        <span className="text-white text-xs font-semibold flex-1 truncate">{inc.incident_name ?? inc.name}</span>
                        <span className="text-gray-500 text-xs">{inc.started_at ? age(inc.started_at) : ""}</span>
                        {isResolved && <span className="text-emerald-400 text-xs font-bold">RESOLVED</span>}
                      </div>
                      {total > 0 && <div className="mt-2">
                        <div className="flex items-center justify-between text-[10px] text-gray-500 mb-1"><span>Actions: {completed}/{total}</span><span>{Math.round(pct)}%</span></div>
                        <div className="w-full bg-gray-700 rounded-full h-1.5"><div className={cn("h-1.5 rounded-full", isResolved ? "bg-emerald-500" : "bg-blue-500")} style={{ width: `${pct}%` }} /></div>
                      </div>}
                      {inc.triggered_by && <p className="text-gray-500 text-[10px] mt-1">Triggered by: {inc.triggered_by}</p>}
                    </button>
                  );
                })}</div>
              </div>}

              {playbooks.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2"><BarChart2 className="w-4 h-4 text-blue-400" /> Playbook Performance</h2>
                <div className="overflow-x-auto"><table className="w-full text-sm">
                  <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Playbook</th><th className="text-left pb-2 pr-4">Threat Type</th><th className="text-left pb-2 pr-4">Executions</th><th className="text-left pb-2 pr-4">Avg Resolution</th><th className="text-left pb-2">Steps</th></tr></thead>
                  <tbody>{playbooks.map(pb => (
                    <tr key={pb.id} className="border-b border-gray-700/50 hover:bg-gray-700/20">
                      <td className="py-2.5 pr-4 text-white text-xs font-semibold">{pb.playbook_name ?? pb.name}</td>
                      <td className="py-2.5 pr-4"><ThreatBadge t={pb.threat_type ?? "—"} /></td>
                      <td className="py-2.5 pr-4 text-gray-300">{pb.execution_count ?? 0}</td>
                      <td className="py-2.5 pr-4"><span className={cn("text-xs font-semibold", (pb.avg_resolution_mins ?? 0) < 30 ? "text-emerald-400" : (pb.avg_resolution_mins ?? 0) < 60 ? "text-yellow-400" : "text-red-400")}>{pb.avg_resolution_mins ?? 0}m</span></td>
                      <td className="py-2.5 text-gray-400">{pb.step_count ?? 0}</td>
                    </tr>
                  ))}</tbody>
                </table></div>
              </div>}
            </div>

            {selectedIncident && <div className="bg-gray-800 rounded-lg p-6 flex flex-col">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Action Log</h2>
                {!resolved.has(selectedIncident.id) && <button onClick={resolveIncident} className="flex items-center gap-1 bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded text-xs font-medium"><CheckCircle className="w-3.5 h-3.5" /> Resolve</button>}
              </div>
              <p className="text-xs text-gray-400 mb-3 truncate"><span className="text-white font-semibold">{selectedIncident.incident_name ?? selectedIncident.name}</span></p>
              <div className="space-y-2 flex-1 overflow-y-auto max-h-[480px]">
                {actions.length === 0 ? <p className="text-gray-500 text-sm text-center py-8">No actions logged for this incident.</p>
                  : actions.map((a: any, i: number) => (
                    <div key={i} className={cn("bg-gray-900 rounded-lg px-3 py-2.5", a.status === "completed" && "border-l-2 border-emerald-500/50", a.status === "in_progress" && "border-l-2 border-blue-500/50", a.status === "failed" && "border-l-2 border-red-500/50", a.status === "pending" && "border-l-2 border-gray-600/50")}>
                      <div className="flex items-center gap-2 mb-1">
                        {a.status === "completed" && <CheckCircle className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />}
                        {a.status === "in_progress" && <Play className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />}
                        {a.status === "failed" && <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />}
                        {a.status === "pending" && <Clock className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />}
                        <span className="text-xs text-white font-medium">{a.action_name ?? a.name}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <ActionTypeBadge t={a.type ?? "—"} />
                        <ActionStatusBadge s={a.status ?? "pending"} />
                        {a.duration && <span className="text-[10px] text-gray-500 ml-auto">{a.duration}</span>}
                      </div>
                      {a.executed_by && <p className="text-[10px] text-gray-600 mt-1">{a.executed_by}</p>}
                    </div>
                  ))}
              </div>
            </div>}
          </div>
        </>}
    </div>
  );
}
