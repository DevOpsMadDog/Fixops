/**
 * Alert Enrichment Dashboard
 *
 * Enrichment queue, history, source reliability, and high-risk alert panel.
 *   1. KPIs: total / enriched / failed / high_risk
 *   2. Enrichment queue (sorted critical-first)
 *   3. Per-alert enrichment history
 *   4. Source reliability table
 *   5. High-risk alerts panel (risk_score ≥ 7.0)
 *
 * Route: /alert-enrichment
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Zap, Shield, AlertTriangle, CheckCircle, XCircle, RefreshCw, ToggleLeft, ToggleRight } from "lucide-react";
import { cn } from "@/lib/utils";

const API_BASE = "/api/v1/alert-enrichment";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

// ── Mock data ──────────────────────────────────────────────────

const MOCK_QUEUE = [
  { id: "alr-001", source: "SIEM",    severity: "critical", indicator_type: "IP",     raw_indicator: "185.220.101.47",                        confidence_score: 92, risk_score: 9.4, status: "pending",  enriched: false },
  { id: "alr-002", source: "EDR",     severity: "critical", indicator_type: "Hash",   raw_indicator: "d41d8cd98f00b204e9800998ecf8427e",        confidence_score: 88, risk_score: 8.9, status: "pending",  enriched: false },
  { id: "alr-003", source: "NDR",     severity: "high",     indicator_type: "Domain", raw_indicator: "update.evil-domain.ru",                   confidence_score: 76, risk_score: 7.8, status: "pending",  enriched: false },
  { id: "alr-004", source: "WAF",     severity: "high",     indicator_type: "URL",    raw_indicator: "http://cdn.malware.cc/payload/dropper.exe", confidence_score: 84, risk_score: 7.2, status: "enriched", enriched: true  },
  { id: "alr-005", source: "CASB",    severity: "medium",   indicator_type: "Email",  raw_indicator: "phish@fake-invoice.xyz",                  confidence_score: 71, risk_score: 6.1, status: "enriched", enriched: true  },
  { id: "alr-006", source: "Firewall",severity: "medium",   indicator_type: "IP",     raw_indicator: "91.108.4.0",                              confidence_score: 63, risk_score: 5.5, status: "failed",   enriched: false },
  { id: "alr-007", source: "MDM",     severity: "low",      indicator_type: "Domain", raw_indicator: "analytics.trackersite.io",                confidence_score: 45, risk_score: 3.2, status: "enriched", enriched: true  },
  { id: "alr-008", source: "SIEM",    severity: "critical", indicator_type: "Hash",   raw_indicator: "5d41402abc4b2a76b9719d911017c592",        confidence_score: 95, risk_score: 9.1, status: "pending",  enriched: false },
];

const MOCK_HISTORY: Record<string, { source: string; result_type: string; enriched_at: string }[]> = {
  "alr-004": [
    { source: "VirusTotal", result_type: "malware",      enriched_at: "2026-04-16T09:45:00Z" },
    { source: "URLhaus",    result_type: "c2_server",    enriched_at: "2026-04-16T09:45:10Z" },
    { source: "OTX",        result_type: "threat_intel", enriched_at: "2026-04-16T09:45:20Z" },
  ],
  "alr-005": [
    { source: "PhishTank",  result_type: "phishing",     enriched_at: "2026-04-16T09:30:00Z" },
    { source: "AbuseIPDB",  result_type: "spam",         enriched_at: "2026-04-16T09:30:15Z" },
  ],
  "alr-007": [
    { source: "URLhaus",    result_type: "tracker",      enriched_at: "2026-04-16T09:10:00Z" },
  ],
};

const MOCK_SOURCES = [
  { id: "src-001", source_name: "VirusTotal",  type: "reputation", reliability_score: 97, success_count: 14320, error_count:  43, enabled: true  },
  { id: "src-002", source_name: "AbuseIPDB",   type: "reputation", reliability_score: 94, success_count:  9871, error_count:  88, enabled: true  },
  { id: "src-003", source_name: "URLhaus",     type: "malware",    reliability_score: 91, success_count:  7234, error_count: 156, enabled: true  },
  { id: "src-004", source_name: "OTX AlienVault", type: "threat_intel", reliability_score: 88, success_count: 5412, error_count: 210, enabled: true  },
  { id: "src-005", source_name: "PhishTank",   type: "phishing",   reliability_score: 85, success_count:  3891, error_count: 322, enabled: true  },
  { id: "src-006", source_name: "Shodan",      type: "recon",      reliability_score: 82, success_count:  2100, error_count: 198, enabled: false },
];

// ── Helpers ────────────────────────────────────────────────────

function fmt(iso: string) {
  return new Date(iso).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
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

function SourceBadge({ s }: { s: string }) {
  const colors = ["bg-blue-500/20 text-blue-400", "bg-purple-500/20 text-purple-400", "bg-cyan-500/20 text-cyan-400", "bg-pink-500/20 text-pink-400"];
  const idx = s.length % colors.length;
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", colors[idx])}>{s}</span>;
}

function IndicatorBadge({ t }: { t: string }) {
  const cls: Record<string, string> = {
    IP:     "bg-orange-500/20 text-orange-300",
    Hash:   "bg-violet-500/20 text-violet-300",
    Domain: "bg-teal-500/20 text-teal-300",
    URL:    "bg-sky-500/20 text-sky-300",
    Email:  "bg-pink-500/20 text-pink-300",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", cls[t] ?? "bg-gray-700 text-gray-300")}>{t}</span>;
}

function ResultTypeBadge({ r }: { r: string }) {
  return <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-medium capitalize">{r.replace(/_/g, " ")}</span>;
}

function TypeBadge({ t }: { t: string }) {
  return <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-400 font-medium capitalize">{t.replace(/_/g, " ")}</span>;
}

function KpiCard({ icon: Icon, label, value, color }: { icon: React.ElementType; label: string; value: string | number; color: string }) {
  return (
    <div className="bg-gray-800 rounded-lg p-6 flex items-start gap-4">
      <div className={cn("p-3 rounded-lg", color)}><Icon className="w-5 h-5" /></div>
      <div>
        <p className="text-gray-400 text-sm">{label}</p>
        <p className="text-2xl font-bold text-white mt-0.5">{value}</p>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function AlertEnrichmentDashboard() {
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sources, setSources] = useState(MOCK_SOURCES);
  const [queue, setQueue] = useState(MOCK_QUEUE);


  const fetchData = () => {
    setError(null);
    fetch(`${API_BASE}/alerts`, { headers: getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => { if (Array.isArray(d)) setQueue(d); })
    .catch(err => setError(err.message || 'Failed to load data'));
    fetch(`${API_BASE}/sources`, { headers: getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => { if (Array.isArray(d)) setSources(d); })
    .catch(err => setError(err.message || 'Failed to load data'));
  };

  useEffect(() => { fetchData(); }, []);

  const sortedQueue = [...queue].sort((a, b) => b.risk_score - a.risk_score);
  const enriched  = queue.filter(a => a.status === "enriched").length;
  const failed    = queue.filter(a => a.status === "failed").length;
  const highRisk  = queue.filter(a => a.risk_score >= 7.0);

  function toggleSource(id: string) {
    setSources(prev => prev.map(s => s.id === id ? { ...s, enabled: !s.enabled } : s));
  }

  function riskColor(score: number) {
    if (score >= 7) return "text-red-400";
    if (score >= 5) return "text-orange-400";
    return "text-yellow-400";
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
          <p className="font-medium">Error loading data</p>
          <p className="text-sm">{error}</p>
          <button onClick={() => { setError(null); fetchData(); }} className="mt-2 text-sm underline">Retry</button>
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Zap className="w-6 h-6 text-yellow-400" /> Alert Enrichment</h1>
          <p className="text-gray-400 text-sm mt-1">Automated IOC enrichment from multiple threat intelligence sources</p>
        </div>
        <button className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh Queue
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard icon={Zap}           label="Total Alerts"   value={queue.length} color="bg-yellow-500/20 text-yellow-400" />
        <KpiCard icon={CheckCircle}   label="Enriched"       value={enriched}           color="bg-emerald-500/20 text-emerald-400" />
        <KpiCard icon={XCircle}       label="Failed"         value={failed}             color="bg-red-500/20 text-red-400" />
        <KpiCard icon={AlertTriangle} label="High Risk (≥7)" value={highRisk.length}    color="bg-orange-500/20 text-orange-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Enrichment Queue */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Enrichment Queue — Critical First</h2>
          <div className="space-y-2">
            {sortedQueue.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              sortedQueue.map(alert => (
              <div key={alert.id}>
                <div
                  className={cn("bg-gray-900 rounded-lg px-4 py-3 cursor-pointer hover:bg-gray-700/40 transition-all",
                    alert.risk_score >= 7 && "border border-red-500/20")}
                  onClick={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)}>
                  <div className="flex items-center gap-3 flex-wrap">
                    <code className="text-[10px] text-gray-500 w-16">{alert.id}</code>
                    <SourceBadge s={alert.source} />
                    <SeverityBadge s={alert.severity} />
                    <IndicatorBadge t={alert.indicator_type} />
                    <code className="text-xs text-gray-300 font-mono flex-1 truncate">{alert.raw_indicator}</code>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      <div className="flex items-center gap-1">
                        <div className="w-16 bg-gray-700 rounded-full h-1">
                          <div className="h-1 bg-blue-500 rounded-full" style={{ width: `${alert.confidence_score}%` }} />
                        </div>
                        <span className="text-[10px] text-blue-400">{alert.confidence_score}%</span>
                      </div>
                      <span className={cn("text-sm font-bold", riskColor(alert.risk_score))}>{alert.risk_score.toFixed(1)}</span>
                      {!alert.enriched && alert.status !== "failed" && (
                        <button className="text-[10px] bg-yellow-600/20 hover:bg-yellow-600/40 text-yellow-400 px-2 py-0.5 rounded transition-colors">Enrich</button>
                      )}
                      {alert.status === "failed" && <XCircle className="w-4 h-4 text-red-400" />}
                      {alert.status === "enriched" && <CheckCircle className="w-4 h-4 text-emerald-400" />}
                    </div>
                  </div>
                </div>
                {expandedAlert === alert.id && MOCK_HISTORY[alert.id] && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}
                    className="bg-gray-900/60 border-l-2 border-emerald-500/40 ml-4 px-4 py-3 rounded-b-lg">
                    <p className="text-[10px] text-gray-500 uppercase font-semibold mb-2">Enrichment History</p>
                    {MOCK_HISTORY[alert.id].map((h, i) => (
                      <div key={i} className="flex items-center gap-3 text-xs text-gray-300 py-1">
                        <SourceBadge s={h.source} />
                        <ResultTypeBadge r={h.result_type} />
                        <span className="text-gray-500 ml-auto">{fmt(h.enriched_at)}</span>
                      </div>
                    ))}
                  </motion.div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-6">
          {/* High Risk Panel */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" /> High Risk Alerts (≥7.0)
            </h2>
            <div className="space-y-2">
              {highRisk.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                highRisk.map(a => (
                <div key={a.id} className="bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                  <div className="flex items-center justify-between">
                    <IndicatorBadge t={a.indicator_type} />
                    <span className="text-red-400 font-bold text-sm">{a.risk_score.toFixed(1)}</span>
                  </div>
                  <p className="text-xs text-gray-300 font-mono mt-1 truncate">{a.raw_indicator}</p>
                  <div className="flex gap-2 mt-1">
                    <SourceBadge s={a.source} />
                    <SeverityBadge s={a.severity} />
                  </div>
                </div>
              ))
            )}
            </div>
          </div>

          {/* Source Reliability */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">Source Reliability</h2>
            <div className="space-y-3">
              {sources.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                sources.map(src => (
                <div key={src.id} className="bg-gray-900 rounded-lg px-3 py-2">
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-xs text-white font-medium">{src.source_name}</p>
                    <button onClick={() => toggleSource(src.id)} className="text-gray-400 hover:text-white transition-colors">
                      {src.enabled ? <ToggleRight className="w-4 h-4 text-emerald-400" /> : <ToggleLeft className="w-4 h-4 text-gray-600" />}
                    </button>
                  </div>
                  <TypeBadge t={src.type} />
                  <div className="flex items-center gap-2 mt-2">
                    <div className="flex-1 bg-gray-700 rounded-full h-1">
                      <div className="h-1 bg-emerald-500 rounded-full" style={{ width: `${src.reliability_score}%` }} />
                    </div>
                    <span className="text-[10px] text-emerald-400 w-8">{src.reliability_score}%</span>
                  </div>
                  <div className="flex gap-3 mt-1 text-[10px]">
                    <span className="text-emerald-400">{src.success_count.toLocaleString()} ok</span>
                    <span className="text-red-400">{src.error_count} err</span>
                  </div>
                </div>
              ))
            )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
