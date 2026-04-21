/**
 * Security Playbook Library
 *
 * Automated response playbooks for common security scenarios:
 *   1. KPIs: Total Playbooks, Active, Executions Today, Avg Execution Time
 *   2. Playbook cards grid (8 cards) with status toggle, Run Now, Edit buttons
 *   3. Recent Executions table with clickable rows
 *   4. Execution Detail panel: step-by-step log
 *   5. Create Playbook panel (placeholder)
 *
 * Route: /playbooks
 * API: GET /api/v1/playbooks, GET /api/v1/playbooks/executions (mock fallback)
 */

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import {
  BookOpen,
  Play,
  Edit2,
  Plus,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Calendar,
  Zap,
  User,
  ChevronRight,
  X,
  Terminal,
  AlertTriangle,
  Shield,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type TriggerType = "Auto" | "Manual" | "Scheduled";
type ExecStatus = "Success" | "Failed" | "In Progress";

interface Playbook {
  id: string;
  name: string;
  trigger_type: TriggerType;
  trigger_desc: string;
  last_executed: string;
  executions_count: number;
  enabled: boolean;
}

interface Execution {
  id: string;
  playbook_name: string;
  trigger_reason: string;
  start_time: string;
  duration: string;
  status: ExecStatus;
  steps_completed: number;
  steps_total: number;
}

interface ExecStep {
  timestamp: string;
  step_name: string;
  action: string;
  result: string;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_PLAYBOOKS: Playbook[] = [
  {
    id: "PB-001",
    name: "Ransomware Response",
    trigger_type: "Auto",
    trigger_desc: "EDR critical alert",
    last_executed: "2026-04-16 09:14",
    executions_count: 12,
    enabled: true,
  },
  {
    id: "PB-002",
    name: "Phishing Response",
    trigger_type: "Auto",
    trigger_desc: "email gateway alert",
    last_executed: "2026-04-16 11:42",
    executions_count: 45,
    enabled: true,
  },
  {
    id: "PB-003",
    name: "Credential Stuffing",
    trigger_type: "Auto",
    trigger_desc: ">10 auth failures",
    last_executed: "2026-04-15 22:07",
    executions_count: 8,
    enabled: true,
  },
  {
    id: "PB-004",
    name: "Data Exfiltration Alert",
    trigger_type: "Auto",
    trigger_desc: "DLP critical",
    last_executed: "2026-04-14 16:30",
    executions_count: 3,
    enabled: true,
  },
  {
    id: "PB-005",
    name: "Privilege Escalation",
    trigger_type: "Auto",
    trigger_desc: "UEBA high risk",
    last_executed: "2026-04-15 08:55",
    executions_count: 6,
    enabled: true,
  },
  {
    id: "PB-006",
    name: "Weekly Vuln Scan",
    trigger_type: "Scheduled",
    trigger_desc: "Monday 2am",
    last_executed: "2026-04-14 02:00",
    executions_count: 52,
    enabled: true,
  },
  {
    id: "PB-007",
    name: "New Critical CVE",
    trigger_type: "Auto",
    trigger_desc: "threat intel",
    last_executed: "2026-04-16 07:33",
    executions_count: 27,
    enabled: true,
  },
  {
    id: "PB-008",
    name: "User Offboarding",
    trigger_type: "Manual",
    trigger_desc: "HR API",
    last_executed: "2026-04-16 10:15",
    executions_count: 89,
    enabled: false,
  },
];

const MOCK_EXECUTIONS: Execution[] = [
  {
    id: "EX-001",
    playbook_name: "Phishing Response",
    trigger_reason: "Suspicious link in email to finance@",
    start_time: "2026-04-16 11:42",
    duration: "3m 12s",
    status: "Success",
    steps_completed: 7,
    steps_total: 7,
  },
  {
    id: "EX-002",
    playbook_name: "Ransomware Response",
    trigger_reason: "EDR: lateral movement detected on host WIN-042",
    start_time: "2026-04-16 09:14",
    duration: "6m 51s",
    status: "Success",
    steps_completed: 9,
    steps_total: 9,
  },
  {
    id: "EX-003",
    playbook_name: "New Critical CVE",
    trigger_reason: "CVE-2026-1337 CVSS 9.8 published",
    start_time: "2026-04-16 07:33",
    duration: "2m 05s",
    status: "In Progress",
    steps_completed: 3,
    steps_total: 5,
  },
  {
    id: "EX-004",
    playbook_name: "User Offboarding",
    trigger_reason: "HR offboarding ticket #1892",
    start_time: "2026-04-16 10:15",
    duration: "1m 44s",
    status: "Failed",
    steps_completed: 2,
    steps_total: 6,
  },
  {
    id: "EX-005",
    playbook_name: "Credential Stuffing",
    trigger_reason: "15 failed logins from 203.0.113.44",
    start_time: "2026-04-15 22:07",
    duration: "0m 58s",
    status: "Success",
    steps_completed: 4,
    steps_total: 4,
  },
  {
    id: "EX-006",
    playbook_name: "Privilege Escalation",
    trigger_reason: "UEBA: anomalous sudo usage by svc_jenkins",
    start_time: "2026-04-15 08:55",
    duration: "4m 20s",
    status: "Success",
    steps_completed: 6,
    steps_total: 6,
  },
  {
    id: "EX-007",
    playbook_name: "Weekly Vuln Scan",
    trigger_reason: "Scheduled: Monday 02:00",
    start_time: "2026-04-14 02:00",
    duration: "18m 33s",
    status: "Success",
    steps_completed: 5,
    steps_total: 5,
  },
];

const MOCK_STEPS: Record<string, ExecStep[]> = {
  "EX-001": [
    { timestamp: "11:42:01", step_name: "Alert Ingestion", action: "Parse email gateway webhook", result: "Parsed: phishing URL list (3 IOCs)" },
    { timestamp: "11:42:04", step_name: "IOC Extraction", action: "Extract URLs from alert payload", result: "IOCs: hxxps://malicious[.]example/login" },
    { timestamp: "11:42:08", step_name: "Threat Intel Lookup", action: "Query ThreatGraph for IOC reputation", result: "Match: known phishing kit (confidence 94%)" },
    { timestamp: "11:42:15", step_name: "User Isolation", action: "Suspend user session tokens", result: "Suspended: 1 active session for user@company.com" },
    { timestamp: "11:42:22", step_name: "Email Quarantine", action: "Move emails to quarantine folder", result: "Quarantined: 12 emails matching IOC" },
    { timestamp: "11:43:30", step_name: "Notification", action: "Alert SOC via Slack #incidents", result: "Notified: @soc-oncall, ticket INC-2841 created" },
    { timestamp: "11:45:13", step_name: "Report", action: "Generate incident summary", result: "Report saved to EvidenceVault #EV-8821" },
  ],
  "EX-002": [
    { timestamp: "09:14:02", step_name: "Alert Ingestion", action: "Parse EDR critical alert", result: "Host: WIN-042, Process: cmd.exe → psexec" },
    { timestamp: "09:14:08", step_name: "Host Isolation", action: "Network-isolate WIN-042 via EDR API", result: "Isolated: WIN-042 removed from prod VLAN" },
    { timestamp: "09:14:20", step_name: "Snapshot", action: "Capture memory + disk snapshot", result: "Snapshot stored: forensics/WIN-042-20260416" },
    { timestamp: "09:15:01", step_name: "Lateral Movement Check", action: "Query BFS attack-path engine", result: "2 additional hosts at risk: WIN-019, WIN-055" },
    { timestamp: "09:16:30", step_name: "Scope Expansion", action: "Isolate WIN-019, WIN-055", result: "Isolated: 2 additional hosts" },
    { timestamp: "09:18:10", step_name: "C2 Blocklist", action: "Add C2 IPs to firewall deny-list", result: "Blocked: 198.51.100.22, 198.51.100.45" },
    { timestamp: "09:19:00", step_name: "Notification", action: "Page incident commander", result: "Paged: incident-commander on-call (PD)" },
    { timestamp: "09:20:22", step_name: "Ticket", action: "Create P1 incident ticket", result: "Created: INC-2842 (P1, assigned to IR team)" },
    { timestamp: "09:20:55", step_name: "Report", action: "Generate ransomware response summary", result: "Report saved to EvidenceVault #EV-8822" },
  ],
  "EX-003": [
    { timestamp: "07:33:01", step_name: "CVE Ingestion", action: "Parse NVD feed: CVE-2026-1337", result: "CVSS 9.8, affects OpenSSL 3.x" },
    { timestamp: "07:33:10", step_name: "Asset Scan", action: "Query asset inventory for affected software", result: "Found: 14 hosts running OpenSSL 3.x" },
    { timestamp: "07:34:05", step_name: "EPSS Check", action: "Fetch EPSS exploit probability", result: "EPSS: 0.87 (87% exploit probability)" },
    { timestamp: "07:35:00", step_name: "Patch Ticket", action: "Create patch tickets in Jira", result: "In progress..." },
  ],
  "EX-004": [
    { timestamp: "10:15:01", step_name: "HR Webhook", action: "Parse HR offboarding event", result: "User: j.doe@company.com, dept: Engineering" },
    { timestamp: "10:15:05", step_name: "AD Disable", action: "Disable Active Directory account", result: "Failed: AD API timeout (connection refused)" },
  ],
  "EX-005": [
    { timestamp: "22:07:01", step_name: "Auth Alert", action: "Parse auth failure threshold alert", result: "15 failures from 203.0.113.44 in 60s" },
    { timestamp: "22:07:04", step_name: "IP Reputation", action: "Query AbuseIPDB + ThreatGraph", result: "Score: 98/100 — known attacker IP" },
    { timestamp: "22:07:10", step_name: "IP Block", action: "Add IP to WAF deny-list", result: "Blocked: 203.0.113.44 on WAF + firewall" },
    { timestamp: "22:07:58", step_name: "Notification", action: "Alert SOC and affected user", result: "User notified via email, SOC ticket INC-2839 created" },
  ],
};

// ══════════════════════════════════════════════════════════════
// Styling helpers
// ══════════════════════════════════════════════════════════════

const TRIGGER_STYLES: Record<TriggerType, string> = {
  Auto: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  Manual: "bg-purple-500/10 text-purple-400 border-purple-500/30",
  Scheduled: "bg-amber-500/10 text-amber-400 border-amber-500/30",
};

const TRIGGER_ICONS: Record<TriggerType, typeof Zap> = {
  Auto: Zap,
  Manual: User,
  Scheduled: Calendar,
};

const STATUS_STYLES: Record<ExecStatus, string> = {
  Success: "bg-green-500/10 text-green-400 border-green-500/30",
  Failed: "bg-red-500/10 text-red-400 border-red-500/30",
  "In Progress": "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
};

const STATUS_ICONS: Record<ExecStatus, typeof CheckCircle2> = {
  Success: CheckCircle2,
  Failed: XCircle,
  "In Progress": Loader2,
};

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function PlaybookLibrary() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>(MOCK_PLAYBOOKS);
  const [loading, setLoading] = useState(true);
  const [selectedExec, setSelectedExec] = useState<Execution | null>(null);
  const [showCreatePanel, setShowCreatePanel] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/security-playbooks/playbooks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-playbooks/executions?org_id=${ORG_ID}&limit=50`),
    ]).then(([playbooksRes, executionsRes]) => {
      const apiPlaybooks  = playbooksRes.status  === "fulfilled" ? playbooksRes.value  : null;
      const apiExecutions = executionsRes.status === "fulfilled" ? executionsRes.value : null;
      if (apiPlaybooks || apiExecutions) {
        setLiveData({ apiPlaybooks, apiExecutions });
        // Map API playbooks to UI shape if available
        if (Array.isArray(apiPlaybooks) && apiPlaybooks.length > 0) {
          const mapped: Playbook[] = apiPlaybooks.map((p: any) => ({
            id:               p.playbook_id ?? p.id ?? "?",
            name:             p.name ?? "Unnamed",
            trigger_type:     (p.trigger_type === "auto_alert" ? "Auto" : p.trigger_type === "scheduled" ? "Scheduled" : "Manual") as TriggerType,
            trigger_desc:     p.trigger_conditions ? JSON.stringify(p.trigger_conditions) : "—",
            last_executed:    p.last_executed ?? "—",
            executions_count: p.executions_count ?? 0,
            enabled:          p.enabled ?? true,
          }));
          setPlaybooks(mapped);
        }
      }
    });
    setLoading(false);
  }, []);

  const activeCount = playbooks.filter((p) => p.enabled).length;
  const executionsToday = liveData?.apiExecutions?.length ?? 7;

  const togglePlaybook = (id: string) => {
    setPlaybooks((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p))
    );
  };

  const execSteps = selectedExec ? (MOCK_STEPS[selectedExec.id] ?? []) : [];

  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <PageHeader
          title="Security Playbooks"
          description="Automated response playbooks for common security scenarios"
        />
        <Button
          onClick={() => setShowCreatePanel(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white gap-2"
        >
          <Plus className="w-4 h-4" />
          Create Playbook
        </Button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Playbooks" value={liveData?.apiPlaybooks?.length ?? playbooks.length} icon={BookOpen} />
        <KpiCard title="Active (Enabled)" value={activeCount} icon={Shield} />
        <KpiCard title="Executions Today" value={executionsToday} icon={Activity} />
        <KpiCard title="Avg Execution Time" value="4.2 min" icon={Clock} />
      </div>

      {/* Playbook Cards Grid */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <h2 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-blue-400" />
          Playbook Library
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {playbooks.map((pb, idx) => {
            const TriggerIcon = TRIGGER_ICONS[pb.trigger_type];
            return (
              <motion.div
                key={pb.id}
                initial={{ opacity: 0, scale: 0.97 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.05 + idx * 0.04 }}
                className={cn(
                  "p-4 rounded-xl border-2 transition-all bg-slate-800/50",
                  pb.enabled
                    ? "border-slate-600 hover:border-blue-500/50"
                    : "border-slate-700/50 opacity-60"
                )}
              >
                {/* Top row: name + trigger badge */}
                <div className="flex items-start justify-between gap-2 mb-3">
                  <h3 className="font-semibold text-slate-100 text-sm leading-snug">
                    {pb.name}
                  </h3>
                  <Badge
                    className={cn(
                      "text-xs shrink-0 border",
                      TRIGGER_STYLES[pb.trigger_type]
                    )}
                  >
                    <TriggerIcon className="w-3 h-3 mr-1" />
                    {pb.trigger_type}
                  </Badge>
                </div>

                {/* Trigger description */}
                <p className="text-xs text-slate-400 mb-3">
                  Trigger: {pb.trigger_desc}
                </p>

                {/* Stats */}
                <div className="flex items-center justify-between text-xs text-slate-500 mb-4">
                  <span className="flex items-center gap-1">
                    <Activity className="w-3 h-3" />
                    {pb.executions_count} runs
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {pb.last_executed.split(" ")[1]}
                  </span>
                </div>

                {/* Status toggle */}
                <div className="flex items-center justify-between mb-3">
                  <button
                    onClick={() => togglePlaybook(pb.id)}
                    className={cn(
                      "flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded-full transition-colors",
                      pb.enabled
                        ? "bg-green-500/10 text-green-400 hover:bg-green-500/20"
                        : "bg-slate-700 text-slate-400 hover:bg-slate-600"
                    )}
                  >
                    {pb.enabled ? (
                      <CheckCircle2 className="w-3 h-3" />
                    ) : (
                      <XCircle className="w-3 h-3" />
                    )}
                    {pb.enabled ? "Enabled" : "Disabled"}
                  </button>
                </div>

                {/* Action buttons */}
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    className="flex-1 h-7 text-xs bg-blue-600/80 hover:bg-blue-600 text-white gap-1"
                  >
                    <Play className="w-3 h-3" />
                    Run Now
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 text-xs border-slate-600 text-slate-300 hover:bg-slate-700 gap-1"
                  >
                    <Edit2 className="w-3 h-3" />
                    Edit
                  </Button>
                </div>
              </motion.div>
            );
          })}
        </div>
      </motion.div>

      {/* Recent Executions Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              Recent Executions
              <span className="text-sm font-normal text-slate-400 ml-1">
                — click a row to view step log
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Playbook</TableHead>
                    <TableHead className="text-slate-300">Trigger Reason</TableHead>
                    <TableHead className="text-slate-300">Start Time</TableHead>
                    <TableHead className="text-slate-300">Duration</TableHead>
                    <TableHead className="text-slate-300">Steps</TableHead>
                    <TableHead className="text-slate-300 text-right">Status</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {MOCK_EXECUTIONS.map((exec, idx) => {
                    const StatusIcon = STATUS_ICONS[exec.status];
                    const isSelected = selectedExec?.id === exec.id;

                    if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

                    return (
                      <motion.tr
                        key={exec.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.2 + idx * 0.04 }}
                        onClick={() =>
                          setSelectedExec(isSelected ? null : exec)
                        }
                        className={cn(
                          "border-b border-slate-700/50 cursor-pointer transition-colors",
                          isSelected
                            ? "bg-blue-500/10"
                            : "hover:bg-slate-800/40"
                        )}
                      >
                        <TableCell className="font-medium text-slate-200">
                          {exec.playbook_name}
                        </TableCell>
                        <TableCell className="text-slate-400 text-sm max-w-[220px] truncate">
                          {exec.trigger_reason}
                        </TableCell>
                        <TableCell className="text-slate-300 font-mono text-sm">
                          <Clock className="w-3.5 h-3.5 inline mr-1.5 text-slate-500" />
                          {exec.start_time}
                        </TableCell>
                        <TableCell className="text-slate-300 text-sm">
                          {exec.duration}
                        </TableCell>
                        <TableCell className="text-slate-300 text-sm">
                          {exec.steps_completed}/{exec.steps_total}
                        </TableCell>
                        <TableCell className="text-right">
                          <Badge
                            className={cn(
                              "text-xs border",
                              STATUS_STYLES[exec.status]
                            )}
                          >
                            <StatusIcon
                              className={cn(
                                "w-3 h-3 mr-1",
                                exec.status === "In Progress" && "animate-spin"
                              )}
                            />
                            {exec.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <ChevronRight
                            className={cn(
                              "w-4 h-4 text-slate-500 transition-transform",
                              isSelected && "rotate-90 text-blue-400"
                            )}
                          />
                        </TableCell>
                      </motion.tr>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Execution Detail Panel */}
      <AnimatePresence>
        {selectedExec && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 8 }}
            transition={{ duration: 0.2 }}
          >
            <Card className="border-blue-500/30 bg-slate-800/60">
              <CardHeader className="border-b border-slate-700 flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Terminal className="w-4 h-4 text-blue-400" />
                  {selectedExec.playbook_name} — Execution {selectedExec.id}
                  <Badge
                    className={cn(
                      "text-xs border ml-2",
                      STATUS_STYLES[selectedExec.status]
                    )}
                  >
                    {selectedExec.status}
                  </Badge>
                </CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedExec(null)}
                  className="text-slate-400 hover:text-slate-200 h-7 w-7 p-0"
                >
                  <X className="w-4 h-4" />
                </Button>
              </CardHeader>
              <CardContent className="p-6">
                {execSteps.length === 0 ? (
                  <p className="text-slate-400 text-sm">
                    No step log available for this execution.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {execSteps.map((step, idx) => (
                      <motion.div
                        key={idx}
                        initial={{ opacity: 0, x: -4 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.05 }}
                        className="flex gap-4 items-start"
                      >
                        {/* Timeline dot */}
                        <div className="flex flex-col items-center">
                          <div
                            className={cn(
                              "w-2.5 h-2.5 rounded-full mt-1 shrink-0",
                              idx < execSteps.length - 1 ||
                                selectedExec.status === "Success"
                                ? "bg-green-400"
                                : selectedExec.status === "Failed"
                                  ? "bg-red-400"
                                  : "bg-yellow-400 animate-pulse"
                            )}
                          />
                          {idx < execSteps.length - 1 && (
                            <div className="w-px flex-1 bg-slate-700 mt-1 h-6" />
                          )}
                        </div>

                        {/* Step content */}
                        <div className="flex-1 pb-2">
                          <div className="flex items-center gap-3 mb-0.5">
                            <span className="font-mono text-xs text-slate-500">
                              {step.timestamp}
                            </span>
                            <span className="font-semibold text-slate-200 text-sm">
                              {step.step_name}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 mb-0.5">
                            {step.action}
                          </p>
                          <p className="text-xs text-green-300/80">
                            ↳ {step.result}
                          </p>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Create Playbook Panel (placeholder) */}
      <AnimatePresence>
        {showCreatePanel && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4"
            onClick={() => setShowCreatePanel(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-slate-800 border border-slate-600 rounded-2xl p-6 w-full max-w-lg shadow-2xl"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                  <Plus className="w-5 h-5 text-blue-400" />
                  Create Playbook
                </h3>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowCreatePanel(false)}
                  className="text-slate-400 hover:text-slate-200 h-7 w-7 p-0"
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">
                    Playbook Name
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Brute Force Response"
                    className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-slate-200 text-sm placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">
                    Trigger Type
                  </label>
                  <select className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-slate-200 text-sm focus:outline-none focus:border-blue-500">
                    <option>Auto</option>
                    <option>Manual</option>
                    <option>Scheduled</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">
                    Trigger Condition
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. EDR critical alert, >5 auth failures"
                    className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-slate-200 text-sm placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Steps Builder
                  </label>
                  <div className="bg-slate-700/50 border border-dashed border-slate-600 rounded-lg p-4 text-center">
                    <AlertTriangle className="w-6 h-6 text-amber-400 mx-auto mb-2" />
                    <p className="text-sm text-slate-400">
                      Visual steps builder coming soon.
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                      Use the API at{" "}
                      <span className="font-mono text-blue-400">
                        POST /api/v1/playbooks
                      </span>{" "}
                      to create playbooks programmatically.
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex gap-3 mt-6">
                <Button
                  variant="outline"
                  className="flex-1 border-slate-600 text-slate-300 hover:bg-slate-700"
                  onClick={() => setShowCreatePanel(false)}
                >
                  Cancel
                </Button>
                <Button
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white"
                  onClick={() => setShowCreatePanel(false)}
                >
                  Save Playbook
                </Button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
