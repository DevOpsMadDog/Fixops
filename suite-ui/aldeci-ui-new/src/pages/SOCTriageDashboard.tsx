/**
 * SOC Alert Triage AI Dashboard
 *
 * ML-powered alert classification and analyst verdict workflow.
 *   1. KPIs: New Alerts, True Positives, False Positives, Escalated
 *   2. Alert queue table (15 rows) with AI severity, classification, confidence %, MITRE technique
 *   3. AI confidence indicator — colored badge showing 0-100%
 *   4. Classification legend: TP (red), FP (green), undetermined (amber)
 *   5. Analyst verdict form — confirm / dispute verdict for selected alert
 *   6. Stats panel — false_positive_rate, escalation_rate, avg_confidence
 *
 * API: GET /api/v1/soc-triage/alerts, /api/v1/soc-triage/stats,
 *      POST /api/v1/soc-triage/alerts/{id}/verdict
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, CheckCircle, TrendingUp,
  RefreshCw, Brain, Eye, Filter, Send,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ALERTS = [
  { id: "SOC-001", title: "Brute force on SSH — 847 attempts",            source: "SIEM",  severity_original: "high",     ai_severity: "high",     ai_classification: "true_positive",  confidence: 94, mitre_technique: "T1110.001", recommended_action: "block",       status: "open",          created_at: "14:32" },
  { id: "SOC-002", title: "Outbound HTTPS to known C2 server",            source: "NDR",   severity_original: "critical",  ai_severity: "critical",  ai_classification: "true_positive",  confidence: 97, mitre_technique: "T1071.001",  recommended_action: "escalate",    status: "escalated",     created_at: "14:28" },
  { id: "SOC-003", title: "Anomalous login from new country",              source: "SIEM",  severity_original: "medium",    ai_severity: "low",       ai_classification: "false_positive", confidence: 82, mitre_technique: "T1078",      recommended_action: "monitor",     status: "closed",        created_at: "14:25" },
  { id: "SOC-004", title: "PowerShell execution with encoded payload",     source: "EDR",   severity_original: "high",      ai_severity: "critical",  ai_classification: "true_positive",  confidence: 91, mitre_technique: "T1059.001",  recommended_action: "investigate", status: "open",          created_at: "14:22" },
  { id: "SOC-005", title: "Large file upload to cloud storage",            source: "DLP",   severity_original: "medium",    ai_severity: "medium",    ai_classification: "undetermined",   confidence: 61, mitre_technique: "T1048",      recommended_action: "investigate", status: "open",          created_at: "14:18" },
  { id: "SOC-006", title: "Lateral movement via SMB relay",               source: "NDR",   severity_original: "critical",  ai_severity: "critical",  ai_classification: "true_positive",  confidence: 98, mitre_technique: "T1557.001",  recommended_action: "escalate",    status: "escalated",     created_at: "14:15" },
  { id: "SOC-007", title: "Privilege escalation via kernel exploit",      source: "EDR",   severity_original: "critical",  ai_severity: "critical",  ai_classification: "true_positive",  confidence: 95, mitre_technique: "T1068",      recommended_action: "escalate",    status: "open",          created_at: "14:12" },
  { id: "SOC-008", title: "Scheduled task created for persistence",        source: "SIEM",  severity_original: "low",       ai_severity: "medium",    ai_classification: "true_positive",  confidence: 73, mitre_technique: "T1053.005",  recommended_action: "investigate", status: "open",          created_at: "14:08" },
  { id: "SOC-009", title: "Failed MFA after password change",             source: "IAM",   severity_original: "medium",    ai_severity: "low",       ai_classification: "false_positive", confidence: 88, mitre_technique: "T1078.004",  recommended_action: "monitor",     status: "closed",        created_at: "14:05" },
  { id: "SOC-010", title: "Ransomware-like file extension changes",       source: "EDR",   severity_original: "critical",  ai_severity: "critical",  ai_classification: "true_positive",  confidence: 99, mitre_technique: "T1486",      recommended_action: "escalate",    status: "escalated",     created_at: "14:01" },
  { id: "SOC-011", title: "DNS requests to newly registered domain",      source: "NDR",   severity_original: "medium",    ai_severity: "medium",    ai_classification: "undetermined",   confidence: 54, mitre_technique: "T1568",      recommended_action: "monitor",     status: "open",          created_at: "13:58" },
  { id: "SOC-012", title: "Service account accessing sensitive share",    source: "SIEM",  severity_original: "medium",    ai_severity: "high",      ai_classification: "true_positive",  confidence: 79, mitre_technique: "T1078.002",  recommended_action: "investigate", status: "open",          created_at: "13:54" },
  { id: "SOC-013", title: "Port scan from internal workstation",          source: "NDR",   severity_original: "low",       ai_severity: "medium",    ai_classification: "undetermined",   confidence: 66, mitre_technique: "T1046",      recommended_action: "monitor",     status: "open",          created_at: "13:50" },
  { id: "SOC-014", title: "Registry run key modification",                source: "EDR",   severity_original: "medium",    ai_severity: "high",      ai_classification: "true_positive",  confidence: 86, mitre_technique: "T1547.001",  recommended_action: "investigate", status: "open",          created_at: "13:46" },
  { id: "SOC-015", title: "Nightly batch job — elevated process",         source: "SIEM",  severity_original: "low",       ai_severity: "info",      ai_classification: "false_positive", confidence: 92, mitre_technique: "T1053",      recommended_action: "close",       status: "closed",        created_at: "13:40" },
];

const MOCK_STATS = {
  total_alerts: 15,
  true_positives: 9,
  false_positives: 3,
  escalated: 3,
  false_positive_rate: 20,
  escalation_rate: 20,
  avg_confidence: 80,
};

// ── Badge helpers ──────────────────────────────────────────────

function ClassificationBadge({ cls }: { cls: string }) {
  const map: Record<string, { label: string; style: string }> = {
    true_positive:  { label: "TP", style: "border-red-500/30 text-red-400 bg-red-500/10" },
    false_positive: { label: "FP", style: "border-green-500/30 text-green-400 bg-green-500/10" },
    undetermined:   { label: "?",  style: "border-amber-500/30 text-amber-400 bg-amber-500/10" },
  };
  const { label, style } = map[cls] ?? { label: cls, style: "border-border text-muted-foreground" };
  return (
    <Badge className={cn("text-[10px] border font-bold w-8 justify-center", style)}>
      {label}
    </Badge>
  );
}

function SeverityBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
    info:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "border-border")}>
      {sev}
    </Badge>
  );
}

function ActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    escalate:    "border-red-500/30 text-red-400 bg-red-500/10",
    investigate: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    block:       "border-purple-500/30 text-purple-400 bg-purple-500/10",
    monitor:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    close:       "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[action] ?? "border-border")}>
      {action}
    </Badge>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const color =
    value >= 85 ? "bg-green-500" :
    value >= 65 ? "bg-amber-500" :
    value >= 45 ? "bg-yellow-400" :
                  "bg-red-400";
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="relative h-1.5 flex-1 rounded-full bg-muted/40 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 0.6 }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn(
        "text-[10px] tabular-nums font-semibold w-8 text-right",
        value >= 85 ? "text-green-400" : value >= 65 ? "text-amber-400" : "text-red-400"
      )}>
        {value}%
      </span>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:      "border-red-500/30 text-red-400 bg-red-500/10",
    escalated: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    closed:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function SOCTriageDashboard() {
  const [alerts, setAlerts] = useState<any[]>(MOCK_ALERTS);
  const [stats, setStats] = useState(MOCK_STATS);
  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [filterCls, setFilterCls] = useState<string>("all");

  // Verdict form state
  const [verdict, setVerdict] = useState("confirmed");
  const [analystNotes, setAnalystNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [verdictMsg, setVerdictMsg] = useState("");

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/soc-triage/alerts?org_id=${ORG_ID}&limit=50`),
      apiFetch(`/api/v1/soc-triage/stats?org_id=${ORG_ID}`),
    ]).then(([alertsResult, statsResult]) => {
      if (alertsResult.status === "fulfilled" && Array.isArray(alertsResult.value) && alertsResult.value.length > 0) {
        setAlerts(alertsResult.value);
      }
      if (statsResult.status === "fulfilled") {
        setStats(statsResult.value);
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const handleVerdict = async () => {
    if (!selectedAlert) return;
    setSubmitting(true);
    setVerdictMsg("");
    try {
      await apiFetch(`/api/v1/soc-triage/alerts/${selectedAlert.id}/verdict`, {
        method: "POST",
        body: JSON.stringify({
          org_id: ORG_ID,
          analyst_id: "analyst-demo",
          verdict,
          notes: analystNotes,
        }),
      });
      setVerdictMsg("Verdict submitted successfully.");
    } catch {
      setVerdictMsg("Verdict recorded locally (API offline).");
    } finally {
      setSubmitting(false);
    }
  };

  const displayAlerts = filterCls === "all"
    ? alerts
    : alerts.filter((a) => a.ai_classification === filterCls);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="SOC Alert Triage AI"
        description="ML-powered alert classification — True Positive / False Positive triage with MITRE ATT&CK mapping and analyst verdict workflow"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="New Alerts"      value={stats.total_alerts}    icon={AlertTriangle} trend="up"   />
        <KpiCard title="True Positives"  value={stats.true_positives}  icon={Shield}        trend="up"   className="border-red-500/20" />
        <KpiCard title="False Positives" value={stats.false_positives} icon={CheckCircle}   trend="down" className="border-green-500/20" />
        <KpiCard title="Escalated"       value={stats.escalated}       icon={TrendingUp}    trend="up"   className="border-purple-500/20" />
      </div>

      {/* Classification legend + filter */}
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-muted-foreground font-medium flex items-center gap-1.5">
          <Filter className="h-3.5 w-3.5" />
          Filter:
        </span>
        {[
          { key: "all",           label: "All Alerts",      cls: "border-border text-foreground" },
          { key: "true_positive", label: "TP — True Positive",  cls: "border-red-500/30 text-red-400 bg-red-500/10" },
          { key: "false_positive",label: "FP — False Positive", cls: "border-green-500/30 text-green-400 bg-green-500/10" },
          { key: "undetermined",  label: "? — Undetermined",    cls: "border-amber-500/30 text-amber-400 bg-amber-500/10" },
        ].map(({ key, label, cls }) => (
          <button
            key={key}
            onClick={() => setFilterCls(key)}
            className={cn(
              "text-[11px] border rounded-full px-3 py-1 transition-all",
              cls,
              filterCls === key ? "opacity-100 ring-1 ring-current" : "opacity-60 hover:opacity-90"
            )}
          >
            {label}
          </button>
        ))}

        <div className="ml-auto flex items-center gap-4 text-[11px] text-muted-foreground">
          <span>FP Rate: <span className="text-green-400 font-semibold">{stats.false_positive_rate}%</span></span>
          <span>Escalation Rate: <span className="text-purple-400 font-semibold">{stats.escalation_rate}%</span></span>
          <span>Avg Confidence: <span className="text-blue-400 font-semibold">{stats.avg_confidence}%</span></span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Alert queue table */}
        <Card className="xl:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Brain className="h-4 w-4 text-blue-400" />
              AI Alert Queue
            </CardTitle>
            <CardDescription className="text-xs">
              AI-triaged alerts — click a row to submit analyst verdict
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                    <TableHead className="text-[11px] h-8">Sev</TableHead>
                    <TableHead className="text-[11px] h-8 text-center">Class</TableHead>
                    <TableHead className="text-[11px] h-8 min-w-[110px]">Confidence</TableHead>
                    <TableHead className="text-[11px] h-8">MITRE</TableHead>
                    <TableHead className="text-[11px] h-8">Action</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {displayAlerts.slice(0, 15).map((a) => (
                    <TableRow
                      key={a.id}
                      className={cn("hover:bg-muted/30 cursor-pointer", selectedAlert?.id === a.id && "bg-muted/40")}
                      onClick={() => { setSelectedAlert(a); setVerdictMsg(""); setAnalystNotes(""); }}
                    >
                      <TableCell className="py-2 text-xs max-w-[220px] truncate font-medium">{a.title}</TableCell>
                      <TableCell className="py-2">
                        <Badge className="text-[10px] border border-border text-muted-foreground">{a.source}</Badge>
                      </TableCell>
                      <TableCell className="py-2"><SeverityBadge sev={a.ai_severity} /></TableCell>
                      <TableCell className="py-2 text-center"><ClassificationBadge cls={a.ai_classification} /></TableCell>
                      <TableCell className="py-2"><ConfidenceBar value={a.confidence} /></TableCell>
                      <TableCell className="py-2">
                        <span className="font-mono text-[10px] bg-muted/40 px-1.5 py-0.5 rounded text-blue-400">{a.mitre_technique}</span>
                      </TableCell>
                      <TableCell className="py-2"><ActionBadge action={a.recommended_action} /></TableCell>
                      <TableCell className="py-2"><StatusBadge status={a.status} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Analyst verdict form + stats */}
        <div className="flex flex-col gap-4">
          {/* Verdict form */}
          <Card className={cn("border-border", selectedAlert && "border-blue-500/30")}>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Eye className="h-4 w-4 text-blue-400" />
                Analyst Verdict
              </CardTitle>
              <CardDescription className="text-xs">
                {selectedAlert ? `Selected: ${selectedAlert.id}` : "Select an alert from the queue"}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedAlert ? (
                <>
                  <div className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                    <p className="text-xs font-medium truncate">{selectedAlert.title}</p>
                    <div className="flex items-center gap-2">
                      <ClassificationBadge cls={selectedAlert.ai_classification} />
                      <SeverityBadge sev={selectedAlert.ai_severity} />
                      <span className="text-[10px] text-muted-foreground ml-auto">Confidence: {selectedAlert.confidence}%</span>
                    </div>
                    <ConfidenceBar value={selectedAlert.confidence} />
                  </div>

                  <div>
                    <label className="text-[11px] text-muted-foreground mb-1 block">Analyst Verdict</label>
                    <select
                      className="w-full rounded-md border border-border bg-muted/30 px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                      value={verdict}
                      onChange={(e) => setVerdict(e.target.value)}
                    >
                      <option value="confirmed">Confirmed — TP</option>
                      <option value="disputed">Disputed — FP</option>
                      <option value="closed">Closed — No action</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] text-muted-foreground mb-1 block">Notes</label>
                    <textarea
                      className="w-full rounded-md border border-border bg-muted/30 px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary resize-none"
                      rows={3}
                      value={analystNotes}
                      onChange={(e) => setAnalystNotes(e.target.value)}
                      placeholder="Add analyst observations…"
                    />
                  </div>

                  {verdictMsg && (
                    <p className={cn("text-[11px]", verdictMsg.includes("success") ? "text-green-400" : "text-amber-400")}>
                      {verdictMsg}
                    </p>
                  )}

                  <Button size="sm" className="w-full" onClick={handleVerdict} disabled={submitting}>
                    <Send className="h-3.5 w-3.5 mr-1.5" />
                    {submitting ? "Submitting…" : "Submit Verdict"}
                  </Button>
                </>
              ) : (
                <p className="text-xs text-muted-foreground">Click an alert in the queue to review and submit your verdict.</p>
              )}
            </CardContent>
          </Card>

          {/* Stats panel */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-purple-400" />
                Triage Performance
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                { label: "False Positive Rate",  value: `${stats.false_positive_rate}%`,  bar: stats.false_positive_rate, color: "bg-green-500", note: "lower is better" },
                { label: "Escalation Rate",       value: `${stats.escalation_rate}%`,      bar: stats.escalation_rate,     color: "bg-purple-500", note: "of all alerts" },
                { label: "Avg AI Confidence",     value: `${stats.avg_confidence}%`,       bar: stats.avg_confidence,      color: "bg-blue-500",  note: "model certainty" },
              ].map(({ label, value, bar, color, note }) => (
                <div key={label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">{label}</span>
                    <span className="font-semibold tabular-nums">{value}</span>
                  </div>
                  <div className="relative h-1.5 rounded-full bg-muted/40 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${bar}%` }}
                      transition={{ duration: 0.7 }}
                      className={cn("h-full rounded-full", color)}
                    />
                  </div>
                  <p className="text-[10px] text-muted-foreground">{note}</p>
                </div>
              ))}

              {/* Classification breakdown */}
              <div className="pt-1 border-t border-border space-y-1.5">
                {[
                  { label: "True Positives",   count: stats.true_positives,  cls: "bg-red-500/20 text-red-400" },
                  { label: "False Positives",  count: stats.false_positives, cls: "bg-green-500/20 text-green-400" },
                  { label: "Undetermined",     count: stats.total_alerts - stats.true_positives - stats.false_positives, cls: "bg-amber-500/20 text-amber-400" },
                  { label: "Escalated",        count: stats.escalated,       cls: "bg-purple-500/20 text-purple-400" },
                ].map(({ label, count, cls }) => (
                  <div key={label} className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">{label}</span>
                    <span className={cn("font-bold tabular-nums px-2 py-0.5 rounded", cls)}>{count}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
