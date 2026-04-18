/**
 * Network Threats Dashboard
 *
 * Shows active network threats table, threat rules list, anomalous baselines
 * alert, top source IPs, and threat stats panel.
 *
 * Route: /network-threats
 * API: GET /api/v1/network-threats
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/network-threats";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });


// ── Types ──────────────────────────────────────────────────────

type ThreatType = "intrusion" | "exfiltration" | "c2" | "lateral_movement" | "dos" | "scan" | "malware" | "anomaly";
type ThreatSeverity = "critical" | "high" | "medium" | "low";
type RuleType = "signature" | "behavioral" | "threshold" | "ml_model";
type RuleAction = "alert" | "block" | "quarantine" | "log";

interface NetworkThreat {
  id: string;
  threat_name: string;
  threat_type: ThreatType;
  source_ip: string;
  dest_ip: string;
  dest_port: number;
  protocol: string;
  severity: ThreatSeverity;
  packet_count: number;
  confidence: number;
  detected_at: string;
  status: "active" | "resolved";
}

interface ThreatRule {
  id: string;
  rule_name: string;
  rule_type: RuleType;
  action: RuleAction;
  match_count: number;
  enabled: boolean;
  last_triggered: string;
}

interface BaselineAnomaly {
  id: string;
  metric_name: string;
  baseline_value: number;
  current_value: number;
  deviation_pct: number;
  unit: string;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_THREATS: NetworkThreat[] = [
  { id: "nt-001", threat_name: "Outbound C2 Beacon",          threat_type: "c2",              source_ip: "10.0.4.22",   dest_ip: "185.234.219.11", dest_port: 443,  protocol: "HTTPS", severity: "critical", packet_count: 14821, confidence: 96, detected_at: "2026-04-16 08:12", status: "active" },
  { id: "nt-002", threat_name: "Internal Port Sweep",         threat_type: "scan",            source_ip: "10.0.2.105",  dest_ip: "10.0.0.0/24",    dest_port: 0,    protocol: "TCP",   severity: "high",     packet_count: 3204,  confidence: 88, detected_at: "2026-04-16 09:44", status: "active" },
  { id: "nt-003", threat_name: "Lateral RDP Brute Force",     threat_type: "lateral_movement",source_ip: "10.0.1.78",   dest_ip: "10.0.5.12",      dest_port: 3389, protocol: "RDP",   severity: "critical", packet_count: 8903,  confidence: 91, detected_at: "2026-04-16 10:05", status: "active" },
  { id: "nt-004", threat_name: "DNS Exfiltration Attempt",    threat_type: "exfiltration",    source_ip: "10.0.3.44",   dest_ip: "8.8.4.4",        dest_port: 53,   protocol: "DNS",   severity: "high",     packet_count: 22110, confidence: 84, detected_at: "2026-04-16 07:30", status: "active" },
  { id: "nt-005", threat_name: "SYN Flood — Ingress",         threat_type: "dos",             source_ip: "203.45.12.7", dest_ip: "192.168.1.1",    dest_port: 80,   protocol: "TCP",   severity: "high",     packet_count: 450200,confidence: 99, detected_at: "2026-04-16 11:02", status: "active" },
  { id: "nt-006", threat_name: "Malware Download Detected",   threat_type: "malware",         source_ip: "10.0.2.33",   dest_ip: "91.108.4.45",    dest_port: 80,   protocol: "HTTP",  severity: "critical", packet_count: 621,   confidence: 93, detected_at: "2026-04-16 06:55", status: "active" },
  { id: "nt-007", threat_name: "Anomalous SSH Tunnel",        threat_type: "anomaly",         source_ip: "10.0.6.19",   dest_ip: "52.14.88.201",   dest_port: 22,   protocol: "SSH",   severity: "medium",   packet_count: 4412,  confidence: 72, detected_at: "2026-04-16 05:18", status: "resolved" },
  { id: "nt-008", threat_name: "Unauthorized Service Intrusion",threat_type: "intrusion",     source_ip: "172.16.0.55", dest_ip: "10.0.1.200",     dest_port: 8080, protocol: "HTTP",  severity: "high",     packet_count: 1843,  confidence: 87, detected_at: "2026-04-16 12:00", status: "active" },
];

const MOCK_RULES: ThreatRule[] = [
  { id: "rule-001", rule_name: "Outbound C2 Beacon Detection",    rule_type: "behavioral",  action: "block",      match_count: 14, enabled: true,  last_triggered: "2026-04-16 08:12" },
  { id: "rule-002", rule_name: "Internal Network Scan Threshold", rule_type: "threshold",   action: "alert",      match_count: 42, enabled: true,  last_triggered: "2026-04-16 09:44" },
  { id: "rule-003", rule_name: "Malware Signature: Cobalt Strike",rule_type: "signature",   action: "quarantine", match_count: 3,  enabled: true,  last_triggered: "2026-04-15 22:11" },
  { id: "rule-004", rule_name: "DNS Tunneling ML Model",          rule_type: "ml_model",    action: "alert",      match_count: 7,  enabled: true,  last_triggered: "2026-04-16 07:30" },
  { id: "rule-005", rule_name: "RDP Brute Force Detector",        rule_type: "threshold",   action: "block",      match_count: 28, enabled: true,  last_triggered: "2026-04-16 10:05" },
  { id: "rule-006", rule_name: "SMB Relay Attack Signature",      rule_type: "signature",   action: "block",      match_count: 0,  enabled: false, last_triggered: "2026-04-01 14:22" },
];

const MOCK_BASELINES: BaselineAnomaly[] = [
  { id: "ba-001", metric_name: "Outbound DNS Queries/min",     baseline_value: 120,  current_value: 4820,  deviation_pct: 3917, unit: "queries/min" },
  { id: "ba-002", metric_name: "East-West Bandwidth",          baseline_value: 850,  current_value: 2340,  deviation_pct: 175,  unit: "Mbps" },
  { id: "ba-003", metric_name: "Failed Auth Attempts/hr",      baseline_value: 25,   current_value: 1204,  deviation_pct: 4716, unit: "attempts/hr" },
  { id: "ba-004", metric_name: "New External Connections/min", baseline_value: 40,   current_value: 98,    deviation_pct: 145,  unit: "conns/min" },
];

// ── Helpers ────────────────────────────────────────────────────

const threatTypeConfig: Record<ThreatType, { label: string; color: string }> = {
  intrusion:        { label: "Intrusion",         color: "bg-red-700 text-red-100" },
  exfiltration:     { label: "Exfiltration",      color: "bg-orange-700 text-orange-100" },
  c2:               { label: "C2",                color: "bg-purple-700 text-purple-100" },
  lateral_movement: { label: "Lateral Movement",  color: "bg-pink-700 text-pink-100" },
  dos:              { label: "DoS",               color: "bg-yellow-700 text-yellow-100" },
  scan:             { label: "Scan",              color: "bg-cyan-700 text-cyan-100" },
  malware:          { label: "Malware",           color: "bg-red-900 text-red-200" },
  anomaly:          { label: "Anomaly",           color: "bg-gray-600 text-gray-200" },
};

const severityConfig: Record<ThreatSeverity, { label: string; badge: string; text: string }> = {
  critical: { label: "Critical", badge: "bg-red-700 text-red-100",      text: "text-red-400" },
  high:     { label: "High",     badge: "bg-orange-700 text-orange-100", text: "text-orange-400" },
  medium:   { label: "Medium",   badge: "bg-amber-700 text-amber-100",   text: "text-amber-400" },
  low:      { label: "Low",      badge: "bg-green-700 text-green-100",   text: "text-green-400" },
};

const ruleTypeConfig: Record<RuleType, { label: string; color: string }> = {
  signature:  { label: "Signature",  color: "bg-blue-700 text-blue-100" },
  behavioral: { label: "Behavioral", color: "bg-purple-700 text-purple-100" },
  threshold:  { label: "Threshold",  color: "bg-amber-700 text-amber-100" },
  ml_model:   { label: "ML Model",   color: "bg-cyan-700 text-cyan-100" },
};

const actionConfig: Record<RuleAction, { label: string; color: string }> = {
  alert:      { label: "Alert",      color: "bg-amber-800 text-amber-200" },
  block:      { label: "Block",      color: "bg-red-800 text-red-200" },
  quarantine: { label: "Quarantine", color: "bg-purple-800 text-purple-200" },
  log:        { label: "Log",        color: "bg-gray-700 text-gray-300" },
};

// Top source IPs
function topSourceIPs(threats: NetworkThreat[]): { ip: string; count: number }[] {
  const counts: Record<string, number> = {};
  threats.forEach(t => { counts[t.source_ip] = (counts[t.source_ip] ?? 0) + 1; });
  return Object.entries(counts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
}

// ── Component ──────────────────────────────────────────────────

export default function NetworkThreatsDashboard() {
  const [threats] = useState<NetworkThreat[]>(MOCK_THREATS);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const loadData = () => {
    setFetchError(null);
    fetch(_API_BASE, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`${r.status}`)))
      .then(d => {
        void d;
      })
      .catch((err) => {
        setFetchError(err instanceof Error ? err.message : "Failed to load network threats data");
      });
  };

  useEffect(() => {
    loadData();
  
    setLoading(false);}, []);

  const [filterStatus, setFilterStatus] = useState<"all" | "active" | "resolved">("all");
  const [loading, setLoading] = useState(true);

  const filteredThreats = filterStatus === "all"
    ? threats
    : threats.filter(t => t.status === filterStatus);

  const activeThreats  = threats.filter(t => t.status === "active").length;
  const resolvedThreats = threats.filter(t => t.status === "resolved").length;
  const totalThreats   = threats.length;
  const topIPs = topSourceIPs(threats);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */
    setLoading(false);}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Network Threats</h1>
          <p className="text-gray-400 mt-1">Active network threats, detection rules, baseline anomalies, and top attackers</p>
        </div>
      </div>

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors">Retry</button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Threats",    value: totalThreats,   color: "text-blue-400" },
          { label: "Active",           value: activeThreats,  color: "text-red-400" },
          { label: "Resolved",         value: resolvedThreats,color: "text-green-400" },
          { label: "Active Rules",     value: MOCK_RULES.filter(r => r.enabled).length, color: "text-cyan-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Baseline Anomalies Alert */}
      {MOCK_BASELINES.length > 0 && (
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-5">
          <p className="text-red-400 font-semibold text-sm mb-3">Anomalous Baselines Detected ({MOCK_BASELINES.length})</p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {MOCK_BASELINES.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              MOCK_BASELINES.map(b => (
              <div key={b.id} className="bg-red-900/30 rounded-lg p-3">
                <p className="text-red-200 text-xs font-semibold">{b.metric_name}</p>
                <div className="flex items-baseline gap-1 mt-1">
                  <span className="text-white font-bold text-lg">{b.current_value.toLocaleString()}</span>
                  <span className="text-gray-400 text-xs">{b.unit}</span>
                </div>
                <div className="flex items-center justify-between mt-1 text-xs">
                  <span className="text-gray-500">Baseline: {b.baseline_value.toLocaleString()}</span>
                  <span className="text-red-400 font-bold">+{b.deviation_pct.toFixed(0)}%</span>
                </div>
              </div>
            ))}
            )}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Active Threats Table */}
        <div className="lg:col-span-3 bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Active Threats</h2>
            <div className="flex gap-2 bg-gray-700 rounded-lg p-1">
              {(["all", "active", "resolved"] as const).map(f => (
                <button
                  key={f}
                  onClick={() => setFilterStatus(f)}
                  className={`px-3 py-1 rounded text-xs font-medium capitalize transition-colors ${
                    filterStatus === f ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"
                  }`}
                >
                  {f}
                </button>
              ))}
            )}
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-500 uppercase border-b border-gray-700">
                  <th className="text-left pb-2 pr-2">Threat</th>
                  <th className="text-left pb-2 pr-2">Type</th>
                  <th className="text-left pb-2 pr-2">Source IP</th>
                  <th className="text-left pb-2 pr-2">Dest IP:Port</th>
                  <th className="text-left pb-2 pr-2">Proto</th>
                  <th className="text-left pb-2 pr-2">Severity</th>
                  <th className="text-left pb-2 pr-2">Packets</th>
                  <th className="text-left pb-2">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {filteredThreats.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  filteredThreats.map(t => (
                  <tr key={t.id} className={`hover:bg-gray-700/30 transition-colors ${t.status === "resolved" ? "opacity-50" : ""}`}>
                    <td className="py-2 pr-2 text-gray-200 font-medium max-w-[160px] truncate">{t.threat_name}</td>
                    <td className="py-2 pr-2">
                      <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${threatTypeConfig[t.threat_type].color}`}>
                        {threatTypeConfig[t.threat_type].label}
                      </span>
                    </td>
                    <td className="py-2 pr-2 font-mono text-gray-300">{t.source_ip}</td>
                    <td className="py-2 pr-2 font-mono text-gray-400">{t.dest_ip}:{t.dest_port || "*"}</td>
                    <td className="py-2 pr-2 text-gray-400">{t.protocol}</td>
                    <td className="py-2 pr-2">
                      <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${severityConfig[t.severity].badge}`}>
                        {severityConfig[t.severity].label}
                      </span>
                    </td>
                    <td className="py-2 pr-2 text-gray-300">{t.packet_count.toLocaleString()}</td>
                    <td className="py-2">
                      <div className="flex items-center gap-1.5">
                        <div className="w-14 bg-gray-700 rounded-full h-1.5">
                          <div
                            className={`h-1.5 rounded-full ${t.confidence >= 90 ? "bg-green-500" : t.confidence >= 70 ? "bg-amber-500" : "bg-red-500"}`}
                            style={{ width: `${t.confidence}%` }}
                          />
                        </div>
                        <span className="text-gray-400">{t.confidence}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Source IPs */}
        <div className="lg:col-span-1 bg-gray-800 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-white mb-4">Top Source IPs</h2>
          <div className="space-y-3">
            {topIPs.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              topIPs.map((ip, idx) => (
              <div key={ip.ip} className="flex items-center gap-2">
                <span className="text-gray-600 text-xs w-4">{idx + 1}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-gray-300 font-mono text-xs truncate">{ip.ip}</p>
                  <div className="w-full bg-gray-700 rounded-full h-1 mt-1">
                    <div
                      className="h-1 rounded-full bg-red-500"
                      style={{ width: `${(ip.count / topIPs[0].count) * 100}%` }}
                    />
                  </div>
                </div>
                <span className="text-red-400 text-xs font-bold shrink-0">{ip.count}</span>
              </div>
            ))}
            )}
          </div>
        </div>
      </div>

      {/* Threat Rules */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Threat Detection Rules</h2>
        <div className="space-y-3">
          {MOCK_RULES.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            MOCK_RULES.map(rule => (
            <div key={rule.id} className={`flex items-center gap-4 p-3 rounded-lg border transition-opacity ${rule.enabled ? "border-gray-700 bg-gray-700/30" : "border-gray-700/50 bg-gray-700/10 opacity-60"}`}>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${ruleTypeConfig[rule.rule_type].color}`}>
                    {ruleTypeConfig[rule.rule_type].label}
                  </span>
                  <p className="text-gray-200 text-sm font-medium">{rule.rule_name}</p>
                </div>
                <p className="text-gray-500 text-xs">Last triggered: {rule.last_triggered}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${actionConfig[rule.action].color}`}>
                  {actionConfig[rule.action].label}
                </span>
                <span className="text-gray-400 text-xs font-medium">{rule.match_count} matches</span>
                <span className={`flex items-center gap-1 text-xs font-medium ${rule.enabled ? "text-green-400" : "text-gray-500"}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? "bg-green-400" : "bg-gray-500"}`} />
                  {rule.enabled ? "Enabled" : "Disabled"}
                </span>
              </div>
            </div>
          ))}
          )}
        </div>
      </div>
    </div>
  );
}
