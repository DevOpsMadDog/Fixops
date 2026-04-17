/**
 * Hunting Automation Dashboard
 *
 * Threat hunting hypotheses, automated queries, and execution history.
 * Route: /hunting-automation
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Search, CheckCircle2, Clock, AlertTriangle, Play,
  Code2, Database, BarChart2, Zap, Filter, ChevronDown, ChevronRight,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock Data ──────────────────────────────────────────────────

const MOCK_HYPOTHESES = [
  {
    id: "hyp-001",
    hypothesis: "Adversaries are using LOLBins (Living off the Land Binaries) to evade detection during lateral movement across domain controllers",
    threat_category: "lateral-movement",
    mitre_technique: "T1218",
    confidence: "high",
    validated: true,
    queries: [
      { id: "q-001", query_name: "LOLBin Execution on DCs", language: "KQL", data_source: "EDR", execution_count: 48, findings_count: 7, avg_execution_secs: 3.2, last_executed: "2026-04-16T10:40:00Z" },
      { id: "q-002", query_name: "Unusual Parent Processes", language: "KQL", data_source: "SIEM", execution_count: 32, findings_count: 12, avg_execution_secs: 5.1, last_executed: "2026-04-16T10:38:00Z" },
    ],
    executions: [
      { id: "ex-001", status: "completed", records_scanned: 2400000, findings: 7, notes: "7 events on DC-01 matching LOLBin patterns", ran_at: "2026-04-16T10:40:00Z" },
      { id: "ex-002", status: "completed", records_scanned: 1800000, findings: 0, notes: "Clean run on secondary DC", ran_at: "2026-04-16T09:00:00Z" },
    ],
  },
  {
    id: "hyp-002",
    hypothesis: "Threat actor is staging data exfiltration via DNS tunneling from compromised workstations in the Finance department",
    threat_category: "exfiltration",
    mitre_technique: "T1048.003",
    confidence: "medium",
    validated: false,
    queries: [
      { id: "q-003", query_name: "DNS TXT Record Volume", language: "SPL", data_source: "DNS Logs", execution_count: 24, findings_count: 3, avg_execution_secs: 8.4, last_executed: "2026-04-16T09:55:00Z" },
      { id: "q-004", query_name: "High-freq DNS to External", language: "SQL", data_source: "Firewall", execution_count: 18, findings_count: 0, avg_execution_secs: 12.1, last_executed: "2026-04-16T08:30:00Z" },
      { id: "q-005", query_name: "YARA DNS Tunnel Pattern", language: "YARA", data_source: "PCAP", execution_count: 6, findings_count: 1, avg_execution_secs: 45.8, last_executed: "2026-04-15T22:00:00Z" },
    ],
    executions: [
      { id: "ex-003", status: "running", records_scanned: 500000, findings: 0, notes: "In progress — scanning Finance VLAN", ran_at: "2026-04-16T10:45:00Z" },
      { id: "ex-004", status: "failed", records_scanned: 0, findings: 0, notes: "Data source timeout — DNS logs unavailable", ran_at: "2026-04-16T09:55:00Z" },
    ],
  },
  {
    id: "hyp-003",
    hypothesis: "Supply chain compromise: suspect npm package is executing encoded PowerShell during CI/CD build pipeline runs",
    threat_category: "supply-chain",
    mitre_technique: "T1195.002",
    confidence: "high",
    validated: true,
    queries: [
      { id: "q-006", query_name: "Encoded PS in CI Jobs", language: "KQL", data_source: "SIEM", execution_count: 72, findings_count: 4, avg_execution_secs: 2.8, last_executed: "2026-04-16T10:30:00Z" },
      { id: "q-007", query_name: "npm postinstall hooks", language: "sigma", data_source: "EDR", execution_count: 15, findings_count: 2, avg_execution_secs: 6.3, last_executed: "2026-04-16T10:00:00Z" },
    ],
    executions: [
      { id: "ex-005", status: "completed", records_scanned: 900000, findings: 4, notes: "4 builds triggered encoded PS — package react-loader-v2", ran_at: "2026-04-16T10:30:00Z" },
    ],
  },
  {
    id: "hyp-004",
    hypothesis: "Insider threat: employee with terminated access still authenticating via VPN using stale session tokens",
    threat_category: "insider-threat",
    mitre_technique: "T1078.004",
    confidence: "low",
    validated: false,
    queries: [
      { id: "q-008", query_name: "VPN Auth After Term Date", language: "EQL", data_source: "IAM", execution_count: 10, findings_count: 0, avg_execution_secs: 14.2, last_executed: "2026-04-15T18:00:00Z" },
    ],
    executions: [
      { id: "ex-006", status: "completed", records_scanned: 240000, findings: 0, notes: "No matches found — investigating token lifespan settings", ran_at: "2026-04-15T18:00:00Z" },
    ],
  },
];

// ── Helpers ────────────────────────────────────────────────────

const CATEGORY_COLORS: Record<string, string> = {
  "lateral-movement": "bg-red-500/15 text-red-400 border-red-500/30",
  "exfiltration":     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  "supply-chain":     "bg-purple-500/15 text-purple-400 border-purple-500/30",
  "insider-threat":   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  "persistence":      "bg-rose-500/15 text-rose-400 border-rose-500/30",
  "defense-evasion":  "bg-pink-500/15 text-pink-400 border-pink-500/30",
};

const CONFIDENCE_COLORS: Record<string, string> = {
  high:   "bg-green-500/15 text-green-400 border-green-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:    "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const LANG_COLORS: Record<string, string> = {
  KQL:   "bg-blue-500/15 text-blue-400 border-blue-500/30",
  SPL:   "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  SQL:   "bg-green-500/15 text-green-400 border-green-500/30",
  EQL:   "bg-teal-500/15 text-teal-400 border-teal-500/30",
  YARA:  "bg-orange-500/15 text-orange-400 border-orange-500/30",
  sigma: "bg-purple-500/15 text-purple-400 border-purple-500/30",
};

const SOURCE_COLORS: Record<string, string> = {
  EDR:      "bg-red-500/15 text-red-400 border-red-500/30",
  SIEM:     "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  "DNS Logs":"bg-teal-500/15 text-teal-400 border-teal-500/30",
  Firewall: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  PCAP:     "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  IAM:      "bg-purple-500/15 text-purple-400 border-purple-500/30",
};

const EXEC_STATUS_COLORS: Record<string, string> = {
  running:   "bg-blue-500/15 text-blue-400 border-blue-500/30",
  completed: "bg-green-500/15 text-green-400 border-green-500/30",
  failed:    "bg-red-500/15 text-red-400 border-red-500/30",
};

function timeAgo(iso: string) {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

// ── Main Component ─────────────────────────────────────────────

export default function HuntingAutomationDashboard() {
  const [selectedHyp, setSelectedHyp] = useState(MOCK_HYPOTHESES[0]);
  const [expandedHyp, setExpandedHyp] = useState<string | null>("hyp-001");

  useEffect(() => {
    apiFetch(`/api/v1/hunting-automation/hypotheses?org_id=${ORG_ID}`).catch(() => {});
  }, []);

  const totalHypotheses = MOCK_HYPOTHESES.length;
  const validated = MOCK_HYPOTHESES.filter(h => h.validated).length;
  const totalQueries = MOCK_HYPOTHESES.flatMap(h => h.queries).length;
  const totalFindings = MOCK_HYPOTHESES.flatMap(h => h.queries).reduce((a, q) => a + q.findings_count, 0);

  const allQueries = MOCK_HYPOTHESES.flatMap(h => h.queries);
  const highYieldQueries = allQueries.filter(q => q.findings_count >= 1).sort((a, b) => b.findings_count - a.findings_count);

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <PageHeader
        title="Hunting Automation"
        description="Automated threat hunting hypotheses, queries, and execution management"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Hypotheses" value={totalHypotheses} icon={<BarChart2 className="h-5 w-5" />} />
        <KpiCard title="Validated" value={validated} icon={<CheckCircle2 className="h-5 w-5 text-green-400" />} />
        <KpiCard title="Total Queries" value={totalQueries} icon={<Code2 className="h-5 w-5 text-blue-400" />} />
        <KpiCard title="Total Findings" value={totalFindings} icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Hypotheses List */}
        <div className="lg:col-span-2 space-y-3">
          {MOCK_HYPOTHESES.map(h => (
            <Card key={h.id} className={cn("bg-gray-800 border-zinc-700 cursor-pointer transition-all", selectedHyp.id === h.id && "border-cyan-500/40")}>
              <div className="p-4 space-y-3" onClick={() => { setSelectedHyp(h); setExpandedHyp(h.id); }}>
                {/* Hypothesis header */}
                <div className="flex items-start gap-3">
                  <button className="mt-0.5 shrink-0" onClick={e => { e.stopPropagation(); setExpandedHyp(expandedHyp === h.id ? null : h.id); }}>
                    {expandedHyp === h.id ? <ChevronDown className="h-4 w-4 text-zinc-400" /> : <ChevronRight className="h-4 w-4 text-zinc-400" />}
                  </button>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-zinc-300 leading-relaxed line-clamp-2">{h.hypothesis}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      <Badge className={cn("text-[9px] border", CATEGORY_COLORS[h.threat_category] ?? "border-zinc-600 text-zinc-400")}>{h.threat_category.replace("-"," ")}</Badge>
                      <Badge className="text-[9px] border border-zinc-600 text-zinc-400">{h.mitre_technique}</Badge>
                      <Badge className={cn("text-[9px] border capitalize", CONFIDENCE_COLORS[h.confidence])}>{h.confidence} confidence</Badge>
                      {h.validated
                        ? <Badge className="text-[9px] border border-green-500/30 text-green-400 bg-green-500/10"><CheckCircle2 className="h-2.5 w-2.5 mr-0.5" />Validated</Badge>
                        : <Badge className="text-[9px] border border-zinc-600 text-zinc-400"><Clock className="h-2.5 w-2.5 mr-0.5" />Pending</Badge>
                      }
                    </div>
                  </div>
                </div>

                {/* Queries */}
                {expandedHyp === h.id && (
                  <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} className="space-y-2 mt-1">
                    <p className="text-[10px] text-zinc-500 uppercase tracking-wider font-medium pl-7">Queries</p>
                    {h.queries.map(q => (
                      <div key={q.id} className="ml-7 bg-zinc-900 rounded-lg p-3 border border-zinc-700">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs text-zinc-200">{q.query_name}</span>
                          <div className="flex gap-1">
                            <Badge className={cn("text-[9px] border", LANG_COLORS[q.language] ?? "border-zinc-600 text-zinc-400")}>{q.language}</Badge>
                            <Badge className={cn("text-[9px] border", SOURCE_COLORS[q.data_source] ?? "border-zinc-600 text-zinc-400")}>{q.data_source}</Badge>
                          </div>
                        </div>
                        <div className="flex items-center gap-4 text-[10px] text-zinc-500">
                          <span>{q.execution_count} execs</span>
                          <span className={cn("font-semibold", q.findings_count > 0 ? "text-red-400" : "text-zinc-500")}>{q.findings_count} findings</span>
                          <span>{q.avg_execution_secs}s avg</span>
                          <span className="ml-auto">{timeAgo(q.last_executed)}</span>
                        </div>
                      </div>
                    ))}

                    {/* Execution History */}
                    <p className="text-[10px] text-zinc-500 uppercase tracking-wider font-medium pl-7 mt-2">Executions</p>
                    {h.executions.map(ex => (
                      <div key={ex.id} className="ml-7 flex items-start gap-3 bg-zinc-900 rounded-lg p-3 border border-zinc-700">
                        <Badge className={cn("text-[9px] border capitalize shrink-0", EXEC_STATUS_COLORS[ex.status])}>{ex.status}</Badge>
                        <div className="flex-1 min-w-0">
                          <p className="text-[10px] text-zinc-400 truncate">{ex.notes}</p>
                          <div className="flex gap-3 mt-1 text-[10px] text-zinc-600">
                            <span>{(ex.records_scanned / 1000000).toFixed(1)}M records</span>
                            <span className={cn(ex.findings > 0 ? "text-red-400" : "text-zinc-600")}>{ex.findings} findings</span>
                            <span className="ml-auto">{timeAgo(ex.ran_at)}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </motion.div>
                )}
              </div>
            </Card>
          ))}
        </div>

        {/* High-yield Queries Panel */}
        <div className="space-y-4">
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-200 flex items-center gap-2">
                <Zap className="h-4 w-4 text-yellow-400" /> High-Yield Queries
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {highYieldQueries.map(q => (
                <div key={q.id} className="bg-zinc-900 rounded-lg p-3 border border-zinc-700 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-xs text-zinc-200 leading-tight">{q.query_name}</p>
                    <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10 shrink-0">{q.findings_count} findings</Badge>
                  </div>
                  <div className="flex gap-1">
                    <Badge className={cn("text-[9px] border", LANG_COLORS[q.language] ?? "border-zinc-600 text-zinc-400")}>{q.language}</Badge>
                    <Badge className={cn("text-[9px] border", SOURCE_COLORS[q.data_source] ?? "border-zinc-600 text-zinc-400")}>{q.data_source}</Badge>
                  </div>
                  <div className="flex justify-between text-[10px] text-zinc-600">
                    <span>{q.execution_count} runs</span>
                    <span>{q.avg_execution_secs}s</span>
                  </div>
                  <Button size="sm" variant="outline" className="w-full h-6 text-[10px] border-zinc-600 text-zinc-400 hover:text-white">
                    <Play className="h-2.5 w-2.5 mr-1" /> Run Now
                  </Button>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
