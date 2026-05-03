// FOLDED into NetworkMonitoringHub hero (threats tab) 2026-05-02 — preserve for git history
/**
 * Network Threats Dashboard - Live API
 * Route: /network-threats
 * API: GET /api/v1/network-threats/threats/active
 */

import { useState, useEffect } from "react";
import { Network, RefreshCw } from "lucide-react";
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

const threatTypeConfig: Record<string, { label: string; color: string }> = {
  intrusion: { label: "Intrusion", color: "bg-red-700 text-red-100" },
  exfiltration: { label: "Exfiltration", color: "bg-orange-700 text-orange-100" },
  c2: { label: "C2", color: "bg-purple-700 text-purple-100" },
  lateral_movement: { label: "Lateral Movement", color: "bg-pink-700 text-pink-100" },
  dos: { label: "DoS", color: "bg-yellow-700 text-yellow-100" },
  scan: { label: "Scan", color: "bg-cyan-700 text-cyan-100" },
  malware: { label: "Malware", color: "bg-red-900 text-red-200" },
  anomaly: { label: "Anomaly", color: "bg-gray-600 text-gray-200" },
};
const severityConfig: Record<string, { label: string; badge: string }> = {
  critical: { label: "Critical", badge: "bg-red-700 text-red-100" },
  high: { label: "High", badge: "bg-orange-700 text-orange-100" },
  medium: { label: "Medium", badge: "bg-amber-700 text-amber-100" },
  low: { label: "Low", badge: "bg-green-700 text-green-100" },
};
const ruleTypeConfig: Record<string, { label: string; color: string }> = {
  signature: { label: "Signature", color: "bg-blue-700 text-blue-100" },
  behavioral: { label: "Behavioral", color: "bg-purple-700 text-purple-100" },
  threshold: { label: "Threshold", color: "bg-amber-700 text-amber-100" },
  ml_model: { label: "ML Model", color: "bg-cyan-700 text-cyan-100" },
};
const actionConfig: Record<string, { label: string; color: string }> = {
  alert: { label: "Alert", color: "bg-amber-800 text-amber-200" },
  block: { label: "Block", color: "bg-red-800 text-red-200" },
  quarantine: { label: "Quarantine", color: "bg-purple-800 text-purple-200" },
  log: { label: "Log", color: "bg-gray-700 text-gray-300" },
};

function topSourceIPs(threats: any[]): { ip: string; count: number }[] {
  const counts: Record<string, number> = {};
  threats.forEach(t => { if (t.source_ip) counts[t.source_ip] = (counts[t.source_ip] ?? 0) + 1; });
  return Object.entries(counts).map(([ip, count]) => ({ ip, count })).sort((a, b) => b.count - a.count).slice(0, 5);
}

export default function NetworkThreatsDashboard() {
  const [threats, setThreats] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [baselines, setBaselines] = useState<any[]>([]);
  const [filterStatus, setFilterStatus] = useState<"all" | "active" | "resolved">("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [threatsRes, rulesRes, baseRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/network-threats/threats/active"),
        apiFetch<any>("/api/v1/network-threats/rules"),
        apiFetch<any>("/api/v1/network-threats/baselines"),
      ]);
      if (threatsRes.status === "fulfilled") {
        const v = threatsRes.value;
        setThreats(Array.isArray(v) ? v : (v.threats ?? v.items ?? []));
      }
      if (rulesRes.status === "fulfilled") {
        const v = rulesRes.value;
        setRules(Array.isArray(v) ? v : (v.rules ?? v.items ?? []));
      }
      if (baseRes.status === "fulfilled") {
        const v = baseRes.value;
        setBaselines(Array.isArray(v) ? v : (v.baselines ?? v.anomalies ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filteredThreats = filterStatus === "all" ? threats : threats.filter(t => t.status === filterStatus);
  const activeThreats = threats.filter(t => t.status === "active").length;
  const resolvedThreats = threats.filter(t => t.status === "resolved").length;
  const topIPs = topSourceIPs(threats);
  const isEmpty = threats.length === 0 && rules.length === 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Network className="w-6 h-6 text-cyan-400" /> Network Threats</h1>
          <p className="text-gray-400 mt-1">Active network threats, detection rules, baseline anomalies, and top attackers</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : isEmpty ? <EmptyState icon={Network} title="No network threats" description="No network threats or detection rules recorded yet." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total Threats", value: threats.length, color: "text-blue-400" },
              { label: "Active", value: activeThreats, color: "text-red-400" },
              { label: "Resolved", value: resolvedThreats, color: "text-green-400" },
              { label: "Active Rules", value: rules.filter(r => r.enabled).length, color: "text-cyan-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5">
                <p className="text-gray-400 text-sm">{s.label}</p>
                <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
              </div>
            ))}
          </div>

          {baselines.length > 0 && (
            <div className="bg-red-900/20 border border-red-700 rounded-lg p-5">
              <p className="text-red-400 font-semibold text-sm mb-3">Anomalous Baselines Detected ({baselines.length})</p>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">{baselines.map(b => (
                <div key={b.id} className="bg-red-900/30 rounded-lg p-3">
                  <p className="text-red-200 text-xs font-semibold">{b.metric_name}</p>
                  <div className="flex items-baseline gap-1 mt-1"><span className="text-white font-bold text-lg">{Number(b.current_value ?? 0).toLocaleString()}</span><span className="text-gray-400 text-xs">{b.unit}</span></div>
                  <div className="flex items-center justify-between mt-1 text-xs"><span className="text-gray-500">Baseline: {Number(b.baseline_value ?? 0).toLocaleString()}</span><span className="text-red-400 font-bold">+{Number(b.deviation_pct ?? 0).toFixed(0)}%</span></div>
                </div>
              ))}</div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {threats.length > 0 && <div className="lg:col-span-3 bg-gray-800 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-white">Active Threats</h2>
                <div className="flex gap-2 bg-gray-700 rounded-lg p-1">{(["all", "active", "resolved"] as const).map(f => (
                  <button key={f} onClick={() => setFilterStatus(f)} className={`px-3 py-1 rounded text-xs font-medium capitalize ${filterStatus === f ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}>{f}</button>
                ))}</div>
              </div>
              <div className="overflow-x-auto"><table className="w-full text-xs">
                <thead><tr className="text-gray-500 uppercase border-b border-gray-700"><th className="text-left pb-2 pr-2">Threat</th><th className="text-left pb-2 pr-2">Type</th><th className="text-left pb-2 pr-2">Source IP</th><th className="text-left pb-2 pr-2">Dest IP:Port</th><th className="text-left pb-2 pr-2">Proto</th><th className="text-left pb-2 pr-2">Severity</th><th className="text-left pb-2 pr-2">Packets</th><th className="text-left pb-2">Confidence</th></tr></thead>
                <tbody className="divide-y divide-gray-700/50">{filteredThreats.map(t => {
                  const tt = threatTypeConfig[t.threat_type] ?? { label: t.threat_type ?? "—", color: "bg-gray-700 text-gray-300" };
                  const sev = severityConfig[t.severity] ?? { label: t.severity ?? "—", badge: "bg-gray-700 text-gray-300" };
                  return (
                    <tr key={t.id} className={`hover:bg-gray-700/30 ${t.status === "resolved" ? "opacity-50" : ""}`}>
                      <td className="py-2 pr-2 text-gray-200 font-medium max-w-[160px] truncate">{t.threat_name}</td>
                      <td className="py-2 pr-2"><span className={`px-1.5 py-0.5 rounded text-xs font-bold ${tt.color}`}>{tt.label}</span></td>
                      <td className="py-2 pr-2 font-mono text-gray-300">{t.source_ip}</td>
                      <td className="py-2 pr-2 font-mono text-gray-400">{t.dest_ip}:{t.dest_port || "*"}</td>
                      <td className="py-2 pr-2 text-gray-400">{t.protocol}</td>
                      <td className="py-2 pr-2"><span className={`px-1.5 py-0.5 rounded text-xs font-bold ${sev.badge}`}>{sev.label}</span></td>
                      <td className="py-2 pr-2 text-gray-300">{Number(t.packet_count ?? 0).toLocaleString()}</td>
                      <td className="py-2"><div className="flex items-center gap-1.5"><div className="w-14 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${(t.confidence ?? 0) >= 90 ? "bg-green-500" : (t.confidence ?? 0) >= 70 ? "bg-amber-500" : "bg-red-500"}`} style={{ width: `${t.confidence ?? 0}%` }} /></div><span className="text-gray-400">{t.confidence ?? 0}%</span></div></td>
                    </tr>
                  );
                })}</tbody>
              </table></div>
            </div>}

            {topIPs.length > 0 && <div className="lg:col-span-1 bg-gray-800 rounded-lg p-5">
              <h2 className="text-sm font-semibold text-white mb-4">Top Source IPs</h2>
              <div className="space-y-3">{topIPs.map((ip, idx) => (
                <div key={ip.ip} className="flex items-center gap-2">
                  <span className="text-gray-600 text-xs w-4">{idx + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-gray-300 font-mono text-xs truncate">{ip.ip}</p>
                    <div className="w-full bg-gray-700 rounded-full h-1 mt-1"><div className="h-1 rounded-full bg-red-500" style={{ width: `${(ip.count / topIPs[0].count) * 100}%` }} /></div>
                  </div>
                  <span className="text-red-400 text-xs font-bold shrink-0">{ip.count}</span>
                </div>
              ))}</div>
            </div>}
          </div>

          {rules.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Threat Detection Rules</h2>
            <div className="space-y-3">{rules.map(rule => {
              const rt = ruleTypeConfig[rule.rule_type] ?? { label: rule.rule_type ?? "—", color: "bg-gray-700 text-gray-300" };
              const ac = actionConfig[rule.action] ?? { label: rule.action ?? "—", color: "bg-gray-700 text-gray-300" };
              return (
                <div key={rule.id} className={`flex items-center gap-4 p-3 rounded-lg border ${rule.enabled ? "border-gray-700 bg-gray-700/30" : "border-gray-700/50 bg-gray-700/10 opacity-60"}`}>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${rt.color}`}>{rt.label}</span>
                      <p className="text-gray-200 text-sm font-medium">{rule.rule_name}</p>
                    </div>
                    <p className="text-gray-500 text-xs">Last triggered: {rule.last_triggered ?? "—"}</p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${ac.color}`}>{ac.label}</span>
                    <span className="text-gray-400 text-xs font-medium">{rule.match_count ?? 0} matches</span>
                    <span className={`flex items-center gap-1 text-xs font-medium ${rule.enabled ? "text-green-400" : "text-gray-500"}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? "bg-green-400" : "bg-gray-500"}`} />
                      {rule.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                </div>
              );
            })}</div>
          </div>}
        </>}
    </div>
  );
}
