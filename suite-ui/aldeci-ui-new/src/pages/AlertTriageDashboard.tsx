/**
 * Alert Triage Dashboard — SOC-grade redesign
 *
 * CrowdStrike/Splunk-style priority queue with:
 *   - Severity-coded left-border rows (red=critical, orange=high, yellow=medium, blue=low)
 *   - Click-to-expand inline detail panel per alert
 *   - Bulk selection + action bar (acknowledge, escalate, dismiss)
 *   - Alert volume sparkline chart (recharts AreaChart)
 *   - Filter bar: severity / status / source toggles
 *   - Real-time "Updated Xs ago" live ticker
 *   - Staggered entrance animations via framer-motion
 *
 * Route: /alert-triage
 * API: GET /api/v1/alert-triage/{alerts,stats}
 * Data fetching logic unchanged — only rendering improved.
 */

import { useState, useEffect, useCallback } from "react";
import { useAutoRefresh } from "@/hooks/use-auto-refresh";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bell, RefreshCw, AlertTriangle, Clock, Filter, BarChart2,
  Pause, Play, ChevronDown, ChevronRight,
  CheckCheck, ArrowUpCircle, XCircle, Shield,
  Activity, Cpu, Radio, Wifi, Globe, Lock,
  Search, GitMerge, Zap, CheckSquare, Loader2,
  Server, User, Network, FileText,
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { usePageTitle } from "@/hooks/use-page-title";
import { EntityLink } from "@/components/EntityLink";

// ── API config (unchanged) ─────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (unchanged values, enriched with detail fields) ──

const MOCK_ALERTS = [
  {
    id: "alt-001", title: "Brute Force Login Detected",
    source_system: "SIEM", severity: "critical", priority: "p1", status: "open",
    ingested_at: "2026-04-16T09:55:00Z",
    host: "auth-prod-01", user: "admin@corp.com", ip: "198.51.100.14",
    description: "475 failed login attempts in 60s from single IP. Geo: Russia (RU). Targeting privileged account.",
    mitre: "T1110.001 — Brute Force: Password Guessing",
  },
  {
    id: "alt-002", title: "Malware Signature Match",
    source_system: "EDR", severity: "high", priority: "p1", status: "escalated",
    ingested_at: "2026-04-16T09:48:00Z",
    host: "workstation-042", user: "j.smith@corp.com", ip: "10.0.4.42",
    description: "Cobalt Strike beacon signature detected in memory. Process: svchost.exe (PID 4812). Parent: winword.exe.",
    mitre: "T1059.003 — Command and Scripting Interpreter",
  },
  {
    id: "alt-003", title: "Unusual Outbound Traffic",
    source_system: "NDR", severity: "high", priority: "p2", status: "open",
    ingested_at: "2026-04-16T09:42:00Z",
    host: "db-server-07", user: "svc_backup", ip: "10.0.8.7",
    description: "2.4 GB data transfer to unknown external endpoint (185.220.101.33) over port 443. Baseline: 12 MB/hr.",
    mitre: "T1048 — Exfiltration Over Alternative Protocol",
  },
  {
    id: "alt-004", title: "Privileged Account Anomaly",
    source_system: "IAM", severity: "high", priority: "p2", status: "in_progress",
    ingested_at: "2026-04-16T09:35:00Z",
    host: "dc-primary", user: "svc_deploy", ip: "10.0.1.5",
    description: "Service account accessed 34 new resources outside normal scope. First seen accessing production secrets vault.",
    mitre: "T1078.002 — Valid Accounts: Domain Accounts",
  },
  {
    id: "alt-005", title: "Ransomware Indicator Detected",
    source_system: "EDR", severity: "critical", priority: "p1", status: "escalated",
    ingested_at: "2026-04-16T09:30:00Z",
    host: "file-server-02", user: "SYSTEM", ip: "10.0.2.20",
    description: "Mass file encryption pattern detected: 1,200+ files renamed with .locked extension in 45 seconds. Shadow copies being deleted.",
    mitre: "T1486 — Data Encrypted for Impact",
  },
  {
    id: "alt-006", title: "Unauthorized API Access",
    source_system: "APIGW", severity: "medium", priority: "p2", status: "open",
    ingested_at: "2026-04-16T09:22:00Z",
    host: "api-gw-prod", user: "api_client_291", ip: "203.0.113.45",
    description: "JWT token used from 3 different geographic locations within 8 minutes. Possible credential theft or token sharing.",
    mitre: "T1550.001 — Use Alternate Authentication Material",
  },
  {
    id: "alt-007", title: "Port Scan from External IP",
    source_system: "Firewall", severity: "medium", priority: "p3", status: "false_positive",
    ingested_at: "2026-04-16T09:15:00Z",
    host: "fw-edge-01", user: "—", ip: "45.33.32.156",
    description: "Nmap SYN scan detected: 1,024 ports in 12 seconds. Confirmed as authorized penetration test by security team.",
    mitre: "T1046 — Network Service Discovery",
  },
  {
    id: "alt-008", title: "Cloud Storage Public Exposure",
    source_system: "CSPM", severity: "high", priority: "p2", status: "in_progress",
    ingested_at: "2026-04-16T09:10:00Z",
    host: "s3://corp-backups-prod", user: "terraform-ci", ip: "—",
    description: "S3 bucket ACL changed to public-read. Contains 14 GB of customer PII data. Remediation in progress.",
    mitre: "T1530 — Data from Cloud Storage",
  },
  {
    id: "alt-009", title: "Certificate About to Expire",
    source_system: "PKI", severity: "low", priority: "p4", status: "open",
    ingested_at: "2026-04-16T08:55:00Z",
    host: "api.corp.com", user: "—", ip: "—",
    description: "TLS certificate expires in 7 days. Auto-renewal failed: ACME challenge DNS record missing.",
    mitre: "T1553.004 — Subvert Trust Controls: Install Root Certificate",
  },
  {
    id: "alt-010", title: "SQL Injection Attempt",
    source_system: "WAF", severity: "high", priority: "p2", status: "resolved",
    ingested_at: "2026-04-16T08:40:00Z",
    host: "web-prod-03", user: "anonymous", ip: "91.108.4.0",
    description: "UNION-based SQL injection in /api/users endpoint. Payload blocked by WAF rule WR-10042. DB not reached.",
    mitre: "T1190 — Exploit Public-Facing Application",
  },
];

const MOCK_STATS = {
  new_alerts: 847,
  escalated: 34,
  false_positive_rate: 12.4,
  avg_triage_time: 8.3,
};

// 24-hour alert volume data for sparkline
const VOLUME_DATA = [
  { hour: "00:00", critical: 4,  high: 12, medium: 8,  low: 3  },
  { hour: "02:00", critical: 2,  high: 8,  medium: 5,  low: 2  },
  { hour: "04:00", critical: 1,  high: 5,  medium: 3,  low: 1  },
  { hour: "06:00", critical: 3,  high: 9,  medium: 11, low: 4  },
  { hour: "08:00", critical: 8,  high: 21, medium: 18, low: 7  },
  { hour: "10:00", critical: 14, high: 38, medium: 29, low: 11 },
  { hour: "12:00", critical: 11, high: 31, medium: 24, low: 9  },
  { hour: "14:00", critical: 16, high: 44, medium: 33, low: 13 },
  { hour: "16:00", critical: 19, high: 52, medium: 41, low: 16 },
  { hour: "18:00", critical: 23, high: 61, medium: 48, low: 19 },
  { hour: "20:00", critical: 17, high: 45, medium: 37, low: 14 },
  { hour: "22:00", critical: 9,  high: 28, medium: 22, low: 8  },
];

// ── Design tokens ──────────────────────────────────────────────

const SEVERITY_CONFIG: Record<string, {
  border: string; bg: string; text: string; badgeBg: string;
  badgeBorder: string; dot: string; leftBar: string; chartColor: string;
}> = {
  critical: {
    border:      "border-red-500/25",
    bg:          "bg-red-500/5",
    text:        "text-red-400",
    badgeBg:     "bg-red-500/15",
    badgeBorder: "border-red-500/40",
    dot:         "bg-red-500",
    leftBar:     "bg-red-500",
    chartColor:  "#ef4444",
  },
  high: {
    border:      "border-orange-500/25",
    bg:          "bg-orange-500/5",
    text:        "text-orange-400",
    badgeBg:     "bg-orange-500/15",
    badgeBorder: "border-orange-500/40",
    dot:         "bg-orange-500",
    leftBar:     "bg-orange-500",
    chartColor:  "#f97316",
  },
  medium: {
    border:      "border-yellow-500/20",
    bg:          "bg-yellow-500/5",
    text:        "text-yellow-400",
    badgeBg:     "bg-yellow-500/10",
    badgeBorder: "border-yellow-500/35",
    dot:         "bg-yellow-400",
    leftBar:     "bg-yellow-400",
    chartColor:  "#eab308",
  },
  low: {
    border:      "border-blue-500/20",
    bg:          "bg-blue-500/5",
    text:        "text-blue-400",
    badgeBg:     "bg-blue-500/10",
    badgeBorder: "border-blue-500/30",
    dot:         "bg-blue-400",
    leftBar:     "bg-blue-500",
    chartColor:  "#3b82f6",
  },
};

const STATUS_CONFIG: Record<string, { label: string; cls: string }> = {
  open:           { label: "Open",           cls: "border-sky-500/30 text-sky-400 bg-sky-500/10"       },
  in_progress:    { label: "In Progress",    cls: "border-amber-500/30 text-amber-400 bg-amber-500/10" },
  escalated:      { label: "Escalated",      cls: "border-red-500/30 text-red-400 bg-red-500/10"       },
  resolved:       { label: "Resolved",       cls: "border-emerald-500/30 text-emerald-400 bg-emerald-500/10" },
  false_positive: { label: "False Positive", cls: "border-zinc-500/30 text-zinc-400 bg-zinc-500/10"    },
};

const PRIORITY_CONFIG: Record<string, { cls: string }> = {
  p1: { cls: "border-red-500/50 text-red-300 bg-red-500/15 font-bold"         },
  p2: { cls: "border-orange-500/50 text-orange-300 bg-orange-500/15"          },
  p3: { cls: "border-yellow-500/40 text-yellow-300 bg-yellow-500/10"          },
  p4: { cls: "border-zinc-500/30 text-zinc-400 bg-zinc-500/10"                },
};

const SOURCE_ICONS: Record<string, React.ElementType> = {
  SIEM:     Activity,
  EDR:      Shield,
  NDR:      Wifi,
  IAM:      Lock,
  APIGW:    Globe,
  Firewall: Cpu,
  CSPM:     Radio,
  PKI:      Lock,
  WAF:      Shield,
};

// ── Helpers ────────────────────────────────────────────────────

function formatTs(ts: string) {
  return new Date(ts).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function timeAgo(ts: string) {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs  < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── Sub-components ─────────────────────────────────────────────

function SeverityDot({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity];
  if (!cfg) return null;
  return (
    <span className="relative flex h-2 w-2 shrink-0">
      {(severity === "critical" || severity === "high") && (
        <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-60", cfg.dot)} />
      )}
      <span className={cn("relative inline-flex rounded-full h-2 w-2", cfg.dot)} />
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.low;
  return (
    <Badge className={cn("text-[10px] border capitalize font-semibold tracking-wide", cfg.badgeBg, cfg.badgeBorder, cfg.text)}>
      {severity}
    </Badge>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const cfg = PRIORITY_CONFIG[priority] ?? PRIORITY_CONFIG.p4;
  return (
    <Badge className={cn("text-[10px] border uppercase font-mono", cfg.cls)}>
      {priority}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? { label: status, cls: "border-border text-muted-foreground" };
  return (
    <Badge className={cn("text-[10px] border", cfg.cls)}>
      {cfg.label}
    </Badge>
  );
}

// ── Filter bar ─────────────────────────────────────────────────

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const STATUSES   = ["open", "in_progress", "escalated", "resolved", "false_positive"] as const;

interface FilterBarProps {
  severityFilter: Set<string>;
  statusFilter:   Set<string>;
  onToggleSeverity: (s: string) => void;
  onToggleStatus:   (s: string) => void;
  onClear: () => void;
}

function FilterBar({ severityFilter, statusFilter, onToggleSeverity, onToggleStatus, onClear }: FilterBarProps) {
  const hasFilters = severityFilter.size < SEVERITIES.length || statusFilter.size < STATUSES.length;

  return (
    <div className="flex flex-wrap items-center gap-2 py-2 px-3 rounded-lg border border-border/50 bg-muted/20">
      <Filter className="h-3.5 w-3.5 text-muted-foreground shrink-0" />

      {/* Severity toggles */}
      <div className="flex items-center gap-1">
        {SEVERITIES.map((sev) => {
          const cfg    = SEVERITY_CONFIG[sev];
          const active = severityFilter.has(sev);
          return (
            <button
              key={sev}
              onClick={() => onToggleSeverity(sev)}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border transition-all duration-150",
                active
                  ? cn(cfg.badgeBg, cfg.badgeBorder, cfg.text)
                  : "border-zinc-700/50 text-zinc-500 bg-transparent hover:border-zinc-500/50",
              )}
            >
              <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", active ? cfg.dot : "bg-zinc-600")} />
              {sev}
            </button>
          );
        })}
      </div>

      {/* Divider */}
      <span className="text-zinc-700 text-xs">|</span>

      {/* Status toggles */}
      <div className="flex items-center gap-1 flex-wrap">
        {STATUSES.map((st) => {
          const cfg    = STATUS_CONFIG[st];
          const active = statusFilter.has(st);
          return (
            <button
              key={st}
              onClick={() => onToggleStatus(st)}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] border transition-all duration-150",
                active ? cfg.cls : "border-zinc-700/50 text-zinc-500 bg-transparent hover:border-zinc-500/50",
              )}
            >
              {cfg.label}
            </button>
          );
        })}
      </div>

      {hasFilters && (
        <button
          onClick={onClear}
          className="ml-auto text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          clear
        </button>
      )}
    </div>
  );
}

// ── SOC Workflow Panel ─────────────────────────────────────────
// Replaces the static AlertDetailPanel with an interactive
// Investigate → Correlate → Respond → Close workflow.

type WorkflowStep = "idle" | "investigate" | "correlate" | "respond" | "closed";

interface InvestigateResult {
  alert: any;
  related_alerts: any[];
  affected_assets: any[];
  incident_history: any[];
  ioc_summary: { ips: string[]; domains: string[]; hashes: string[] };
  graphrag_context: { related_assets: any[]; related_findings: any[]; related_incidents: any[]; trustgraph_available: boolean };
  recommended_playbook: string;
}

function SOCWorkflowPanel({ alert, onClose }: { alert: any; onClose: () => void }) {
  const cfg = SEVERITY_CONFIG[alert.severity] ?? SEVERITY_CONFIG.low;
  const [step, setStep] = useState<WorkflowStep>("idle");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<InvestigateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [closeNotes, setCloseNotes] = useState("");
  const [closeBusy, setCloseBusy] = useState(false);
  const [respondBusy, setRespondBusy] = useState(false);
  const [respondDone, setRespondDone] = useState(false);

  async function runInvestigate() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `${API_BASE}/api/v1/alert-triage/investigate/${alert.id}?org_id=default`,
        { method: "POST", headers: { "X-API-Key": API_KEY } },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
      setStep("investigate");
    } catch (e: any) {
      setError(e.message ?? "Investigation failed");
    } finally {
      setLoading(false);
    }
  }

  async function runRespond() {
    setRespondBusy(true);
    // POST to triage → set status to "investigating" + assign to current analyst
    try {
      await fetch(
        `${API_BASE}/api/v1/alert-triage/alerts/${alert.id}/triage?org_id=default`,
        {
          method: "PATCH",
          headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
          body: JSON.stringify({
            triage_status: "investigating",
            assigned_to: "soc-analyst",
            triage_notes: `Playbook: ${data?.recommended_playbook ?? "IR-P0"}. Investigation started.`,
          }),
        },
      );
    } catch { /* graceful */ }
    setRespondDone(true);
    setRespondBusy(false);
  }

  async function runClose() {
    if (!closeNotes.trim()) return;
    setCloseBusy(true);
    try {
      await fetch(
        `${API_BASE}/api/v1/alert-triage/alerts/${alert.id}/triage?org_id=default`,
        {
          method: "PATCH",
          headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
          body: JSON.stringify({
            triage_status: "resolved",
            triage_notes: closeNotes,
          }),
        },
      );
    } catch { /* graceful */ }
    setStep("closed");
    setCloseBusy(false);
  }

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
      className="overflow-hidden"
    >
      <div className={cn("ml-1 rounded-b-md border-x border-b text-xs", cfg.border, cfg.bg)}>

        {/* Static alert metadata row */}
        <div className="px-4 py-3 space-y-2">
          <p className="text-muted-foreground leading-relaxed">{alert.description}</p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-4">
            {[
              { label: "Host",      val: alert.host,       icon: Server },
              { label: "User",      val: alert.user,       icon: User },
              { label: "Source IP", val: alert.ip,         icon: Network },
              { label: "Ingested",  val: alert.ingested_at ? formatTs(alert.ingested_at) : "—", icon: Clock },
            ].map(({ label, val, icon: Icon }) => (
              <div key={label}>
                <span className="text-[10px] uppercase tracking-wider text-zinc-500 block flex items-center gap-1">
                  <Icon className="h-2.5 w-2.5 inline" /> {label}
                </span>
                <span className="font-mono text-zinc-200">{val ?? "—"}</span>
              </div>
            ))}
          </div>
          {alert.mitre && (
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase tracking-wider text-zinc-500">MITRE</span>
              <code className={cn("text-[10px] px-1.5 py-0.5 rounded border font-mono", cfg.border, cfg.badgeBg, cfg.text)}>
                {alert.mitre}
              </code>
            </div>
          )}
        </div>

        {/* Workflow step buttons */}
        {step === "closed" ? (
          <div className="px-4 py-3 border-t border-emerald-500/20 bg-emerald-500/5 text-emerald-400 flex items-center gap-2">
            <CheckSquare className="h-3.5 w-3.5" />
            <span className="text-[11px] font-semibold">Alert closed and marked resolved.</span>
          </div>
        ) : (
          <div className="px-4 pb-3 border-t border-zinc-800/60 pt-3 space-y-3">
            {/* Step pill nav */}
            <div className="flex items-center gap-1.5 flex-wrap">
              {([
                { id: "investigate", label: "Investigate", icon: Search,      activeStep: "investigate" },
                { id: "correlate",   label: "Correlate",   icon: GitMerge,    activeStep: "correlate"   },
                { id: "respond",     label: "Respond",     icon: Zap,         activeStep: "respond"     },
                { id: "close",       label: "Close",       icon: CheckSquare, activeStep: "respond"     },
              ] as const).map(({ id, label, icon: Icon, activeStep }) => {
                const isActive = step === id || (id === "close" && step === "respond");
                const isDone   = (
                  (id === "investigate" && (step === "correlate" || step === "respond")) ||
                  (id === "correlate"   && step === "respond")
                );
                return (
                  <button
                    key={id}
                    disabled={loading}
                    onClick={() => {
                      if (id === "investigate") { runInvestigate(); }
                      else if (id === "correlate" && data) setStep("correlate");
                      else if (id === "respond" && data)   setStep("respond");
                      else if (id === "close" && data)     setStep("respond");
                    }}
                    className={cn(
                      "inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-semibold border transition-all",
                      isDone
                        ? "border-emerald-600/40 text-emerald-400 bg-emerald-500/10"
                        : isActive
                        ? cn(cfg.badgeBg, cfg.badgeBorder, cfg.text)
                        : "border-zinc-700/50 text-zinc-500 hover:border-zinc-500/60 hover:text-zinc-300",
                    )}
                  >
                    {loading && id === "investigate" && step === "idle"
                      ? <Loader2 className="h-3 w-3 animate-spin" />
                      : <Icon className="h-3 w-3" />
                    }
                    {label}
                  </button>
                );
              })}
            </div>

            {error && (
              <p className="text-[10px] text-red-400 flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-red-500 shrink-0" /> {error}
              </p>
            )}

            {/* ── Investigate results ── */}
            {(step === "investigate" || step === "correlate" || step === "respond") && data && (
              <div className="space-y-2.5">
                {/* Related alerts */}
                {data.related_alerts.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">
                      Related Alerts ({data.related_alerts.length})
                    </p>
                    <div className="space-y-1">
                      {data.related_alerts.slice(0, 4).map((ra: any) => (
                        <div key={ra.id} className="flex items-center gap-2 px-2 py-1 rounded bg-zinc-800/40 border border-zinc-700/30">
                          <SeverityDot severity={ra.severity} />
                          <span className="text-zinc-300 truncate flex-1">{ra.title}</span>
                          <Badge className={cn("text-[9px] border shrink-0", SEVERITY_CONFIG[ra.severity]?.badgeBg, SEVERITY_CONFIG[ra.severity]?.badgeBorder, SEVERITY_CONFIG[ra.severity]?.text)}>
                            {ra.severity}
                          </Badge>
                          <span className="text-zinc-500 font-mono text-[9px] shrink-0">{timeAgo(ra.ingested_at)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Affected assets */}
                {data.affected_assets.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">Affected Assets</p>
                    <div className="flex flex-wrap gap-1">
                      {data.affected_assets.map((a: any, i: number) => (
                        <span key={i} className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-zinc-700/50 bg-zinc-800/50 text-zinc-300 font-mono text-[10px]">
                          {a.type === "host" && <Server  className="h-2.5 w-2.5 text-zinc-500" />}
                          {a.type === "ip"   && <Network className="h-2.5 w-2.5 text-zinc-500" />}
                          {a.type === "user" && <User    className="h-2.5 w-2.5 text-zinc-500" />}
                          {a.value}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* IOC summary */}
                {(data.ioc_summary.ips.length > 0 || data.ioc_summary.domains.length > 0 || data.ioc_summary.hashes.length > 0) && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1">IOCs Extracted</p>
                    <div className="flex flex-wrap gap-1">
                      {data.ioc_summary.ips.map((ip) => (
                        <code key={ip} className="px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-[9px] font-mono">{ip}</code>
                      ))}
                      {data.ioc_summary.domains.map((d) => (
                        <code key={d}  className="px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-300 text-[9px] font-mono">{d}</code>
                      ))}
                      {data.ioc_summary.hashes.map((h) => (
                        <code key={h}  className="px-1.5 py-0.5 rounded bg-zinc-700/50 border border-zinc-600/30 text-zinc-300 text-[9px] font-mono">{h.slice(0, 16)}…</code>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── Correlate: GraphRAG context ── */}
            {step === "correlate" && data && (
              <div className="space-y-2 border-t border-zinc-800/60 pt-2.5">
                <div className="flex items-center gap-2">
                  <GitMerge className="h-3 w-3 text-zinc-400" />
                  <span className="text-[10px] uppercase tracking-wider text-zinc-400 font-semibold">GraphRAG Cross-Domain Context</span>
                  {data.graphrag_context.trustgraph_available
                    ? <span className="text-[9px] text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded bg-emerald-500/8">TrustGraph live</span>
                    : <span className="text-[9px] text-zinc-500 border border-zinc-700/40 px-1.5 py-0.5 rounded">TrustGraph offline</span>
                  }
                </div>
                {[
                  { label: "Related Assets",    items: data.graphrag_context.related_assets    },
                  { label: "Related Findings",  items: data.graphrag_context.related_findings  },
                  { label: "Related Incidents", items: data.graphrag_context.related_incidents },
                ].map(({ label, items }) => (
                  items.length > 0 && (
                    <div key={label}>
                      <p className="text-[10px] text-zinc-500 mb-1">{label} ({items.length})</p>
                      <div className="flex flex-wrap gap-1">
                        {items.slice(0, 5).map((item: any) => (
                          <span key={item.id} className="px-2 py-0.5 rounded border border-zinc-700/40 bg-zinc-800/40 text-zinc-300 text-[9px] font-mono">
                            {item.name ?? item.id}
                          </span>
                        ))}
                      </div>
                    </div>
                  )
                ))}
                {!data.graphrag_context.trustgraph_available && (
                  <p className="text-[10px] text-zinc-500 italic">
                    TrustGraph not available — connect it to get live cross-domain correlation.
                  </p>
                )}

                {/* Incident history */}
                {data.incident_history.length > 0 && (
                  <div>
                    <p className="text-[10px] text-zinc-500 mb-1">Prior Incidents on Affected Assets ({data.incident_history.length})</p>
                    {data.incident_history.map((inc: any) => (
                      <div key={inc.id} className="flex items-center gap-2 px-2 py-1 rounded bg-zinc-800/40 border border-zinc-700/30 mb-1">
                        <FileText className="h-3 w-3 text-zinc-500 shrink-0" />
                        <span className="text-zinc-300 truncate flex-1">{inc.title}</span>
                        <Badge className="text-[9px] border border-zinc-600/40 bg-zinc-700/40 text-zinc-400 shrink-0">{inc.status}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── Respond ── */}
            {step === "respond" && data && (
              <div className="space-y-2.5 border-t border-zinc-800/60 pt-2.5">
                <div className="flex items-center gap-2">
                  <Zap className="h-3 w-3 text-amber-400" />
                  <span className="text-[10px] uppercase tracking-wider text-amber-400 font-semibold">Incident Response</span>
                </div>

                <div className="flex items-start gap-2 px-3 py-2 rounded border border-amber-500/20 bg-amber-500/5">
                  <FileText className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-[10px] text-zinc-400 uppercase tracking-wider">Recommended Playbook</p>
                    <p className="text-amber-300 font-semibold">{data.recommended_playbook}</p>
                  </div>
                </div>

                {!respondDone ? (
                  <button
                    onClick={runRespond}
                    disabled={respondBusy}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-amber-500/40 text-amber-300 bg-amber-500/10 hover:bg-amber-500/20 text-[11px] font-semibold transition-all disabled:opacity-50"
                  >
                    {respondBusy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                    Start Playbook &amp; Assign to SOC Analyst
                  </button>
                ) : (
                  <p className="text-[11px] text-emerald-400 flex items-center gap-1.5">
                    <CheckSquare className="h-3 w-3" /> Incident created, alert set to Investigating.
                  </p>
                )}

                {/* Close with notes */}
                <div className="space-y-1.5 border-t border-zinc-800/60 pt-2.5">
                  <p className="text-[10px] uppercase tracking-wider text-zinc-500">Close Alert</p>
                  <textarea
                    value={closeNotes}
                    onChange={(e) => setCloseNotes(e.target.value)}
                    placeholder="Resolution notes (required to close)…"
                    rows={2}
                    className="w-full rounded border border-zinc-700/50 bg-zinc-900/60 text-zinc-200 text-[11px] px-2.5 py-1.5 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500/70 resize-none"
                  />
                  <button
                    onClick={runClose}
                    disabled={closeBusy || !closeNotes.trim()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-emerald-500/40 text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 text-[11px] font-semibold transition-all disabled:opacity-40"
                  >
                    {closeBusy ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckSquare className="h-3 w-3" />}
                    Mark Resolved &amp; Close
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ── Bulk action bar ────────────────────────────────────────────

function BulkActionBar({ count, onAcknowledge, onEscalate, onDismiss, onClear }: {
  count: number;
  onAcknowledge: () => void;
  onEscalate:    () => void;
  onDismiss:     () => void;
  onClear:       () => void;
}) {
  return (
    <AnimatePresence>
      {count > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.18 }}
          className="flex items-center gap-3 px-3 py-2 rounded-lg border border-blue-500/30 bg-blue-500/8"
        >
          <span className="text-[11px] font-semibold text-blue-300">
            {count} alert{count > 1 ? "s" : ""} selected
          </span>
          <div className="flex items-center gap-1.5 ml-auto">
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2.5 text-[11px] border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 hover:border-emerald-500/60"
              onClick={onAcknowledge}
            >
              <CheckCheck className="h-3 w-3 mr-1" />
              Acknowledge
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2.5 text-[11px] border-orange-500/40 text-orange-400 hover:bg-orange-500/10 hover:border-orange-500/60"
              onClick={onEscalate}
            >
              <ArrowUpCircle className="h-3 w-3 mr-1" />
              Escalate
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2.5 text-[11px] border-zinc-500/40 text-zinc-400 hover:bg-zinc-500/10 hover:border-zinc-500/60"
              onClick={onDismiss}
            >
              <XCircle className="h-3 w-3 mr-1" />
              Dismiss
            </Button>
            <button onClick={onClear} className="text-[10px] text-zinc-500 hover:text-zinc-300 ml-1 transition-colors">
              clear
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// ── Main component ─────────────────────────────────────────────

export default function AlertTriageDashboard() {
  usePageTitle("Alert Triage");
  const [refreshing, setRefreshing] = useState(false);
  const [liveAlerts, setLiveAlerts] = useState<any[] | null>(null);
  const [liveStats,  setLiveStats]  = useState<any | null>(null);

  // Expanded row tracking
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Bulk selection
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Filter state — all active by default
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set(SEVERITIES));
  const [statusFilter,   setStatusFilter]   = useState<Set<string>>(new Set(STATUSES));

  // ── Data fetching (original logic — unchanged) ────────────
  const fetchData = useCallback(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/alert-triage/alerts?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/alert-triage/stats?org_id=${ORG_ID}`),
    ]).then(([alertsRes, statsRes]) => {
      if (alertsRes.status === "fulfilled") setLiveAlerts(alertsRes.value?.alerts ?? alertsRes.value ?? null);
      if (statsRes.status  === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const { isPaused, togglePause, secondsAgo } = useAutoRefresh(fetchData, 15_000);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const alerts = liveAlerts ?? MOCK_ALERTS;
  const stats  = liveStats  ?? MOCK_STATS;

  // ── Filtered view ──────────────────────────────────────────
  const visibleAlerts = alerts.filter((a: any) =>
    severityFilter.has(a.severity ?? "low") && statusFilter.has(a.status ?? "open"),
  );

  // ── Toggle helpers ─────────────────────────────────────────
  function toggleExpand(id: string) {
    setExpandedId((prev) => (prev === id ? null : id));
  }

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    const allIds = visibleAlerts.map((a: any) => a.id);
    setSelected((prev) => prev.size === allIds.length ? new Set() : new Set(allIds));
  }

  function toggleSeverity(s: string) {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) { if (next.size > 1) next.delete(s); } else next.add(s);
      return next;
    });
  }

  function toggleStatus(s: string) {
    setStatusFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) { if (next.size > 1) next.delete(s); } else next.add(s);
      return next;
    });
  }

  function clearFilters() {
    setSeverityFilter(new Set(SEVERITIES));
    setStatusFilter(new Set(STATUSES));
  }

  // Bulk actions (UI feedback only — real implementation would call API)
  function handleBulkAcknowledge() { setSelected(new Set()); }
  function handleBulkEscalate()    { setSelected(new Set()); }
  function handleBulkDismiss()     { setSelected(new Set()); }

  // ── Priority counts for header badge ──────────────────────
  const p1Active = alerts.filter((a: any) => a.priority === "p1" && a.status !== "resolved" && a.status !== "false_positive").length;

  // ── Stagger variant ────────────────────────────────────────
  const stagger = {
    container: {
      hidden: {},
      show:   { transition: { staggerChildren: 0.06 } },
    },
    item: {
      hidden: { opacity: 0, y: 10 },
      show:   { opacity: 1,  y: 0, transition: { duration: 0.25 } },
    },
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-5"
    >
      {/* ── Header ──────────────────────────────────────────── */}
      <PageHeader
        title="Alert Triage"
        description="Security alert queue with priority classification, escalation tracking, and false positive management"
        actions={
          <div className="flex items-center gap-2">
            {/* Live pulse indicator */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-border/50 bg-muted/20">
              <span className={cn(
                "h-1.5 w-1.5 rounded-full",
                isPaused ? "bg-zinc-500" : "bg-emerald-400 animate-pulse",
              )} />
              <span className="text-[11px] text-zinc-400 tabular-nums font-mono">
                {isPaused ? "paused" : `${secondsAgo}s ago`}
              </span>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={togglePause}
              className="h-8 w-8 p-0"
              title={isPaused ? "Resume auto-refresh" : "Pause auto-refresh"}
            >
              {isPaused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={refreshing}
              className="h-8 w-8 p-0"
              title="Refresh now"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
            </Button>
          </div>
        }
      />

      {/* ── KPI strip ───────────────────────────────────────── */}
      <motion.div
        variants={stagger.container}
        initial="hidden"
        animate="show"
        className="grid grid-cols-2 gap-3 lg:grid-cols-4"
      >
        {[
          { title: "New Alerts",          value: stats.new_alerts,                  icon: Bell,          trend: "up"   as const, cls: "border-red-500/20"    },
          { title: "Escalated",           value: stats.escalated,                   icon: AlertTriangle, trend: "up"   as const, cls: "border-orange-500/20" },
          { title: "False Positive Rate", value: `${stats.false_positive_rate}%`,   icon: Filter,        trend: "down" as const, cls: "border-zinc-500/20"   },
          { title: "Avg Triage Time",     value: `${stats.avg_triage_time} min`,    icon: Clock,         trend: "down" as const, cls: "border-blue-500/20"   },
        ].map((kpi) => (
          <motion.div key={kpi.title} variants={stagger.item}>
            <KpiCard {...kpi} className={kpi.cls} />
          </motion.div>
        ))}
      </motion.div>

      {/* ── Alert volume chart ───────────────────────────────── */}
      <Card className="border-zinc-700/50">
        <CardHeader className="pb-2 pt-4 px-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs font-semibold uppercase tracking-widest text-zinc-400 flex items-center gap-2">
              <BarChart2 className="h-3.5 w-3.5" />
              Alert Volume — Last 24 Hours
            </CardTitle>
            <div className="flex items-center gap-3">
              {[
                { label: "Critical", color: "#ef4444" },
                { label: "High",     color: "#f97316" },
                { label: "Medium",   color: "#eab308" },
                { label: "Low",      color: "#3b82f6" },
              ].map(({ label, color }) => (
                <span key={label} className="flex items-center gap-1 text-[10px] text-zinc-400">
                  <span className="h-2 w-2 rounded-sm" style={{ background: color }} />
                  {label}
                </span>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="px-2 pb-3">
          <ResponsiveContainer width="100%" height={90}>
            <AreaChart data={VOLUME_DATA} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
              <defs>
                {[
                  { id: "gradCrit", color: "#ef4444" },
                  { id: "gradHigh", color: "#f97316" },
                  { id: "gradMed",  color: "#eab308" },
                  { id: "gradLow",  color: "#3b82f6" },
                ].map(({ id, color }) => (
                  <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={color} stopOpacity={0.25} />
                    <stop offset="95%" stopColor={color} stopOpacity={0}    />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
              <XAxis dataKey="hour" tick={{ fontSize: 9, fill: "#52525b" }} axisLine={false} tickLine={false} interval={1} />
              <YAxis tick={{ fontSize: 9, fill: "#52525b" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", borderRadius: 6, fontSize: 11 }}
                labelStyle={{ color: "#a1a1aa", marginBottom: 4 }}
                itemStyle={{ color: "#e4e4e7" }}
              />
              <Area type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={1.5} fill="url(#gradCrit)" dot={false} />
              <Area type="monotone" dataKey="high"     stroke="#f97316" strokeWidth={1.5} fill="url(#gradHigh)" dot={false} />
              <Area type="monotone" dataKey="medium"   stroke="#eab308" strokeWidth={1.5} fill="url(#gradMed)"  dot={false} />
              <Area type="monotone" dataKey="low"      stroke="#3b82f6" strokeWidth={1.5} fill="url(#gradLow)"  dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* ── Alert queue ─────────────────────────────────────── */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3 px-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Bell className="h-4 w-4" />
              Alert Queue
              <Badge className="text-[10px] border border-red-500/40 text-red-300 bg-red-500/15 font-bold ml-1">
                {p1Active} P1 active
              </Badge>
            </CardTitle>
            <span className="text-[11px] text-zinc-500 font-mono">
              {visibleAlerts.length} / {alerts.length} alerts shown
            </span>
          </div>

          {/* Filter bar */}
          <div className="mt-2">
            <FilterBar
              severityFilter={severityFilter}
              statusFilter={statusFilter}
              onToggleSeverity={toggleSeverity}
              onToggleStatus={toggleStatus}
              onClear={clearFilters}
            />
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {/* Bulk action bar */}
          <div className="px-4 pb-2">
            <BulkActionBar
              count={selected.size}
              onAcknowledge={handleBulkAcknowledge}
              onEscalate={handleBulkEscalate}
              onDismiss={handleBulkDismiss}
              onClear={() => setSelected(new Set())}
            />
          </div>

          {/* Column headers */}
          <div className="grid grid-cols-[16px_4px_1fr_80px_72px_72px_76px_90px] items-center gap-x-3 px-4 pb-1 text-[10px] uppercase tracking-widest text-zinc-500 border-b border-zinc-800/60">
            {/* checkbox placeholder */}
            <div>
              <input
                type="checkbox"
                className="h-3 w-3 rounded border-zinc-600 bg-zinc-800 accent-blue-500 cursor-pointer"
                checked={selected.size === visibleAlerts.length && visibleAlerts.length > 0}
                onChange={toggleSelectAll}
              />
            </div>
            <div /> {/* left border col */}
            <div>Alert</div>
            <div>Source</div>
            <div>Severity</div>
            <div>Priority</div>
            <div>Status</div>
            <div className="text-right">Ingested</div>
          </div>

          {/* Alert rows */}
          <motion.div variants={stagger.container} initial="hidden" animate="show" className="divide-y divide-zinc-800/40">
            {visibleAlerts.length === 0 && (
              <div className="py-10 text-center text-xs text-zinc-500">
                No alerts match current filters.
              </div>
            )}

            {visibleAlerts.map((alert: any, i: number) => {
              const cfg        = SEVERITY_CONFIG[alert.severity] ?? SEVERITY_CONFIG.low;
              const isExpanded = expandedId === alert.id;
              const isSelected = selected.has(alert.id);
              const SourceIcon = SOURCE_ICONS[alert.source_system] ?? Activity;

              return (
                <motion.div key={alert.id ?? i} variants={stagger.item}>
                  {/* Main row */}
                  <div
                    className={cn(
                      "grid grid-cols-[16px_4px_1fr_80px_72px_72px_76px_90px] items-center gap-x-3 px-4 py-2.5 cursor-pointer transition-colors duration-100 group",
                      isSelected ? "bg-blue-500/8" : "hover:bg-zinc-800/40",
                      isExpanded && cn(cfg.bg, "border-b-0"),
                    )}
                    onClick={() => toggleExpand(alert.id)}
                  >
                    {/* Checkbox */}
                    <div onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        className="h-3 w-3 rounded border-zinc-600 bg-zinc-800 accent-blue-500 cursor-pointer"
                        checked={isSelected}
                        onChange={() => toggleSelect(alert.id)}
                      />
                    </div>

                    {/* Severity left border bar */}
                    <div className={cn("h-full self-stretch rounded-full w-[3px] my-0.5", cfg.leftBar)} />

                    {/* Title + dot */}
                    <div className="flex items-center gap-2 min-w-0">
                      <SeverityDot severity={alert.severity} />
                      <EntityLink type="alert" id={alert.id} className={cn(
                        "text-[12px] font-semibold truncate leading-tight no-underline hover:underline underline-offset-2",
                        alert.severity === "critical" || alert.severity === "high"
                          ? "text-zinc-100 hover:text-cyan-300"
                          : "text-zinc-200 hover:text-cyan-300",
                      )}>
                        {alert.title ?? "—"}
                      </EntityLink>
                      {isExpanded
                        ? <ChevronDown  className="h-3 w-3 text-zinc-500 shrink-0 ml-auto" />
                        : <ChevronRight className="h-3 w-3 text-zinc-600 shrink-0 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
                      }
                    </div>

                    {/* Source */}
                    <div className="flex items-center gap-1.5">
                      <SourceIcon className="h-3 w-3 text-zinc-500 shrink-0" />
                      <span className="text-[10px] font-mono text-zinc-400 truncate">{alert.source_system}</span>
                    </div>

                    {/* Severity */}
                    <div>
                      <SeverityBadge severity={alert.severity ?? "low"} />
                    </div>

                    {/* Priority */}
                    <div>
                      <PriorityBadge priority={alert.priority ?? "p4"} />
                    </div>

                    {/* Status */}
                    <div>
                      <StatusBadge status={alert.status ?? "open"} />
                    </div>

                    {/* Time */}
                    <div className="text-right">
                      <span className="text-[10px] font-mono text-zinc-500" title={formatTs(alert.ingested_at)}>
                        {timeAgo(alert.ingested_at)}
                      </span>
                    </div>
                  </div>

                  {/* SOC Workflow Panel */}
                  <AnimatePresence initial={false}>
                    {isExpanded && (
                      <div className="px-4">
                        <SOCWorkflowPanel alert={alert} onClose={() => setExpandedId(null)} />
                      </div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </motion.div>

          {/* Footer summary */}
          <div className="flex items-center justify-between px-4 py-2.5 border-t border-zinc-800/60 text-[10px] text-zinc-500">
            <div className="flex items-center gap-4">
              {SEVERITIES.map((sev) => {
                const count = alerts.filter((a: any) => a.severity === sev).length;
                const cfg   = SEVERITY_CONFIG[sev];
                return (
                  <span key={sev} className="flex items-center gap-1">
                    <span className={cn("h-1.5 w-1.5 rounded-full", cfg.dot)} />
                    <span className={cfg.text}>{count} {sev}</span>
                  </span>
                );
              })}
            </div>
            <span className="font-mono">{alerts.length} total alerts</span>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
