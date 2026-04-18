/**
 * Incident Response Timeline — Forensic Incident Chronicle
 *
 * Chronicle and reconstruct security incidents with forensic precision:
 *   1. KPI row — Active Incidents, MTTD, MTTC, Incidents This Month
 *   2. Active Incidents panel — severity, phase, team, affected systems
 *   3. Timeline View — vertical event log for selected incident, color-coded by type
 *   4. Incident Summary — root cause, MITRE ATT&CK, lessons learned
 *   5. MTTR Breakdown — phase-by-phase time bars
 *
 * API: GET /api/v1/incidents, GET /api/v1/incidents/{id}/timeline
 * Fallback: mock data when API is unavailable
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle, Clock, Activity, ChevronRight, ChevronDown,
  Shield, Users, FileSearch, Bell, ArrowRight, CheckCircle2,
  AlertCircle, Info, Zap, BookOpen, Eye, Target,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type Phase = "Detection" | "Containment" | "Eradication" | "Recovery" | "Closed";
type EventType = "detection" | "alert" | "escalation" | "action" | "note" | "resolution";

interface Incident {
  id: string;
  title: string;
  severity: Severity;
  current_phase: Phase;
  assigned_team: string;
  affected_systems: string[];
  created_at: string;
  updated_at: string;
}

interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: EventType;
  actor: string;
  description: string;
  evidence_attached: boolean;
  evidence_detail?: string;
}

interface IncidentDetail {
  id: string;
  title: string;
  severity: Severity;
  affected_systems: string[];
  containment_status: string;
  root_cause: string;
  lessons_learned: string[];
  mitre_techniques: string[];
  phase_durations: {
    detection: number;
    containment: number;
    eradication: number;
    recovery: number;
  };
  timeline: TimelineEvent[];
}

interface IncidentsData {
  incidents: Incident[];
  active_incidents: number;
  mttd_hours: number;
  mttc_hours: number;
  incidents_this_month: number;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_INCIDENTS_DATA: IncidentsData = {
  active_incidents: 3,
  mttd_hours: 4.2,
  mttc_hours: 18.5,
  incidents_this_month: 12,
  incidents: [
    {
      id: "INC-2026-001",
      title: "Ransomware attempt on finance workstation",
      severity: "CRITICAL",
      current_phase: "Containment",
      assigned_team: "IR Team Alpha",
      affected_systems: ["fin-ws-042", "fin-fs-001", "domain-ctrl-02"],
      created_at: "2026-04-15T08:23:00Z",
      updated_at: "2026-04-16T03:41:00Z",
    },
    {
      id: "INC-2026-002",
      title: "Suspicious API access from unknown IP",
      severity: "HIGH",
      current_phase: "Detection",
      assigned_team: "SOC T1",
      affected_systems: ["api-gateway-01", "auth-service"],
      created_at: "2026-04-16T01:15:00Z",
      updated_at: "2026-04-16T04:50:00Z",
    },
    {
      id: "INC-2026-003",
      title: "Insider data exfiltration attempt",
      severity: "HIGH",
      current_phase: "Eradication",
      assigned_team: "IR Team Beta",
      affected_systems: ["hr-workstation-07", "sharepoint-prod", "s3-hr-docs"],
      created_at: "2026-04-14T14:05:00Z",
      updated_at: "2026-04-16T02:10:00Z",
    },
  ],
};

const MOCK_INCIDENT_DETAILS: Record<string, IncidentDetail> = {
  "INC-2026-001": {
    id: "INC-2026-001",
    title: "Ransomware attempt on finance workstation",
    severity: "CRITICAL",
    affected_systems: ["fin-ws-042", "fin-fs-001", "domain-ctrl-02"],
    containment_status: "Partially contained — network segment isolated",
    root_cause: "Phishing email delivered malicious macro-enabled Excel attachment. User executed macro which downloaded and staged Ryuk ransomware loader. EDR caught pre-encryption phase.",
    lessons_learned: [
      "Enable macro execution policy via GPO to block unsigned macros",
      "Improve phishing simulation training frequency",
      "Ensure EDR is deployed on all finance workstations",
    ],
    mitre_techniques: ["T1566.001 (Spearphishing Attachment)", "T1204.002 (Malicious File)", "T1486 (Data Encrypted for Impact)"],
    phase_durations: { detection: 2.1, containment: 8.4, eradication: 0, recovery: 0 },
    timeline: [
      {
        id: "e1",
        timestamp: "2026-04-15T08:23:00Z",
        event_type: "detection",
        actor: "EDR / CrowdStrike",
        description: "Suspicious process tree detected: EXCEL.EXE spawned cmd.exe then PowerShell with encoded payload.",
        evidence_attached: true,
        evidence_detail: "Process tree dump: PID 4421 -> 8831 -> 9024. Encoded PS: base64 decode reveals meterpreter stager.",
      },
      {
        id: "e2",
        timestamp: "2026-04-15T08:31:00Z",
        event_type: "alert",
        actor: "ALDECI SIEM",
        description: "High severity alert correlated: 3 IoCs matched Ryuk ransomware signatures (C2 domain, hash, network beacon).",
        evidence_attached: true,
        evidence_detail: "C2 domain: updates-service[.]net — matches Ryuk known C2. File hash: 3a4f9c... matches VirusTotal 58/72.",
      },
      {
        id: "e3",
        timestamp: "2026-04-15T08:45:00Z",
        event_type: "escalation",
        actor: "SOC T1 Analyst (Chen)",
        description: "Escalated to IR Team Alpha. Incident declared P1-CRITICAL. CISO notified.",
        evidence_attached: false,
      },
      {
        id: "e4",
        timestamp: "2026-04-15T09:12:00Z",
        event_type: "action",
        actor: "IR Lead (Martinez)",
        description: "Network segment containing fin-ws-042 isolated at switch level. VLAN 120 quarantined.",
        evidence_attached: true,
        evidence_detail: "Switch config change logged: interface Gi0/24 -> vlan 999 (quarantine). Timestamp: 09:12:44 UTC.",
      },
      {
        id: "e5",
        timestamp: "2026-04-15T10:30:00Z",
        event_type: "action",
        actor: "IR Lead (Martinez)",
        description: "Memory forensics initiated on fin-ws-042. Volatile memory captured (32GB). Preliminary analysis shows injected shellcode in svchost.exe.",
        evidence_attached: true,
        evidence_detail: "Volatility output: malfind found 4 suspicious regions in PID 832 (svchost.exe). PE header signatures present.",
      },
      {
        id: "e6",
        timestamp: "2026-04-15T14:00:00Z",
        event_type: "note",
        actor: "IR Analyst (Okafor)",
        description: "Lateral movement attempted to fin-fs-001 and domain-ctrl-02 via pass-the-hash. Both systems added to scope.",
        evidence_attached: true,
        evidence_detail: "Event ID 4624 (Logon Type 3) from fin-ws-042 IP to domain-ctrl-02 at 13:58 UTC. NTLM auth with compromised hash.",
      },
      {
        id: "e7",
        timestamp: "2026-04-16T03:41:00Z",
        event_type: "action",
        actor: "IR Lead (Martinez)",
        description: "Persistence mechanisms identified and removed: 2 scheduled tasks, 1 registry run key. Credential reset initiated for 14 affected accounts.",
        evidence_attached: true,
        evidence_detail: "Scheduled tasks: 'WindowsDefenderUpdateTask', 'AdobeFlashUpdater' — both malicious. Registry: HKLM\\Run\\svcupd.",
      },
    ],
  },
  "INC-2026-002": {
    id: "INC-2026-002",
    title: "Suspicious API access from unknown IP",
    severity: "HIGH",
    affected_systems: ["api-gateway-01", "auth-service"],
    containment_status: "Under investigation — monitoring active",
    root_cause: "Under investigation. Anomalous API key usage from IP 45.33.32.156 (Shodan scan node). Possible key leak via public repository.",
    lessons_learned: [
      "Implement API key rotation every 90 days",
      "Add geo-blocking for API endpoints",
    ],
    mitre_techniques: ["T1078.004 (Valid Accounts: Cloud Accounts)", "T1190 (Exploit Public-Facing Application)"],
    phase_durations: { detection: 4.2, containment: 0, eradication: 0, recovery: 0 },
    timeline: [
      {
        id: "e1",
        timestamp: "2026-04-16T01:15:00Z",
        event_type: "detection",
        actor: "Rate Limiter / ALDECI",
        description: "API key sk-prod-8f2... triggered 847 requests/min from IP 45.33.32.156. Threshold is 100/min.",
        evidence_attached: true,
        evidence_detail: "Rate limit logs: X-RateLimit-Remaining: 0, 429 responses issued. IP geolocation: Fremont, CA (known Shodan scanner).",
      },
      {
        id: "e2",
        timestamp: "2026-04-16T01:22:00Z",
        event_type: "alert",
        actor: "ALDECI Threat Intel",
        description: "Source IP 45.33.32.156 matched AbuseIPDB score 98/100 — confirmed scanner/attacker node.",
        evidence_attached: false,
      },
      {
        id: "e3",
        timestamp: "2026-04-16T01:35:00Z",
        event_type: "action",
        actor: "SOC T1 Analyst (Park)",
        description: "API key sk-prod-8f2... revoked. IP blocked at WAF. Audit of all requests made in 24h window initiated.",
        evidence_attached: true,
        evidence_detail: "Accessed endpoints: /api/v1/findings (412x), /api/v1/assets (288x), /api/v1/users (147x). No writes detected.",
      },
      {
        id: "e4",
        timestamp: "2026-04-16T04:50:00Z",
        event_type: "note",
        actor: "SOC T1 Analyst (Park)",
        description: "GitHub secret scanning triggered — API key found in public fork of internal repo (user: dev-contractor-22). Key created 2025-11-14.",
        evidence_attached: true,
        evidence_detail: "GitHub URL: github.com/dev-contractor-22/aldeci-fork/blob/main/.env.example. Key exposed for 5 months.",
      },
    ],
  },
  "INC-2026-003": {
    id: "INC-2026-003",
    title: "Insider data exfiltration attempt",
    severity: "HIGH",
    affected_systems: ["hr-workstation-07", "sharepoint-prod", "s3-hr-docs"],
    containment_status: "Contained — employee account suspended",
    root_cause: "Terminated contractor (effective 2026-04-13) retained active credentials for 36 hours post-termination. Downloaded 4.2GB of HR documents to personal USB device before DLP triggered.",
    lessons_learned: [
      "Automate credential revocation on HR system termination event",
      "Enable USB write blocking for contractor workstations",
      "Deploy DLP rules for bulk document downloads",
    ],
    mitre_techniques: ["T1078 (Valid Accounts)", "T1052.001 (Exfiltration Over Physical Medium: USB)", "T1005 (Data from Local System)"],
    phase_durations: { detection: 6.5, containment: 4.2, eradication: 3.8, recovery: 0 },
    timeline: [
      {
        id: "e1",
        timestamp: "2026-04-14T14:05:00Z",
        event_type: "detection",
        actor: "DLP / ALDECI",
        description: "DLP policy 'Bulk Download HR Documents' triggered. User jsmith@contractor.io downloaded 847 files (4.2GB) in 22 minutes.",
        evidence_attached: true,
        evidence_detail: "DLP log: user=jsmith@contractor.io, files=847, bytes=4,512,083,200, duration=22min, destination=USB\\VendorID_0781.",
      },
      {
        id: "e2",
        timestamp: "2026-04-14T14:18:00Z",
        event_type: "alert",
        actor: "Insider Threat Engine",
        description: "Behavioral anomaly: user jsmith has 0 prior bulk downloads in 6-month history. Activity at 14:05 on a Monday anomalous vs baseline (typically Tue-Thu, 9-17 UTC).",
        evidence_attached: false,
      },
      {
        id: "e3",
        timestamp: "2026-04-14T14:35:00Z",
        event_type: "escalation",
        actor: "SOC T1 Analyst (Rodriguez)",
        description: "Cross-referenced with HR system: jsmith termination date 2026-04-13 (yesterday). Active account not revoked. Escalated to HR + Legal + IR.",
        evidence_attached: false,
      },
      {
        id: "e4",
        timestamp: "2026-04-14T15:10:00Z",
        event_type: "action",
        actor: "IT Admin (Thompson)",
        description: "Account jsmith@contractor.io suspended in AD and Azure AD. All active sessions terminated (4 sessions killed).",
        evidence_attached: true,
        evidence_detail: "AD: userAccountControl set to ACCOUNTDISABLE. Azure AD: sign-in blocked, 4 refresh tokens revoked.",
      },
      {
        id: "e5",
        timestamp: "2026-04-15T09:00:00Z",
        event_type: "action",
        actor: "IR Lead (Martinez)",
        description: "Forensic image of hr-workstation-07 captured. Physical USB device confiscated with HR cooperation. Chain of custody established.",
        evidence_attached: true,
        evidence_detail: "USB SN: VID_0781&PID_5581\\1234567890. Disk image SHA256: a8f3bc... Files confirmed: 847 HR records including salary data, SSNs.",
      },
      {
        id: "e6",
        timestamp: "2026-04-15T14:30:00Z",
        event_type: "action",
        actor: "IR Analyst (Okafor)",
        description: "SharePoint audit logs reviewed. No external sharing detected. S3 bucket access logs confirm no upload to external storage.",
        evidence_attached: false,
      },
      {
        id: "e7",
        timestamp: "2026-04-16T02:10:00Z",
        event_type: "note",
        actor: "Legal / Compliance",
        description: "Privacy counsel notified. Data breach assessment initiated — 847 employee records potentially compromised. GDPR/CCPA notification timeline triggered (72h).",
        evidence_attached: false,
      },
    ],
  },
};

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function getSeverityStyle(severity: Severity) {
  switch (severity) {
    case "CRITICAL": return "bg-red-500/20 text-red-400 border-red-500/40";
    case "HIGH":     return "bg-orange-500/20 text-orange-400 border-orange-500/40";
    case "MEDIUM":   return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
    case "LOW":      return "bg-blue-500/20 text-blue-400 border-blue-500/40";
  }
}

function getPhaseStyle(phase: Phase) {
  switch (phase) {
    case "Detection":   return "bg-yellow-500/15 text-yellow-300 border-yellow-500/30";
    case "Containment": return "bg-orange-500/15 text-orange-300 border-orange-500/30";
    case "Eradication": return "bg-purple-500/15 text-purple-300 border-purple-500/30";
    case "Recovery":    return "bg-green-500/15 text-green-300 border-green-500/30";
    case "Closed":      return "bg-slate-500/15 text-slate-300 border-slate-500/30";
  }
}

function getEventTypeConfig(type: EventType) {
  switch (type) {
    case "detection":
      return { color: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40", icon: Eye, label: "Detection" };
    case "alert":
      return { color: "text-red-400 bg-red-500/20 border-red-500/40", icon: Bell, label: "Alert" };
    case "escalation":
      return { color: "text-orange-400 bg-orange-500/20 border-orange-500/40", icon: ArrowRight, label: "Escalation" };
    case "action":
      return { color: "text-blue-400 bg-blue-500/20 border-blue-500/40", icon: Zap, label: "Action" };
    case "note":
      return { color: "text-slate-400 bg-slate-500/20 border-slate-500/40", icon: Info, label: "Note" };
    case "resolution":
      return { color: "text-green-400 bg-green-500/20 border-green-500/40", icon: CheckCircle2, label: "Resolution" };
  }
}

function formatTs(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleString("en-US", {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
    hour12: false,
  });
}

// ══════════════════════════════════════════════════════════════
// Phase Progress Bar
// ══════════════════════════════════════════════════════════════

const PHASE_ORDER: Phase[] = ["Detection", "Containment", "Eradication", "Recovery"];

const PhaseProgress = ({ current }: { current: Phase }) => {
  const idx = PHASE_ORDER.indexOf(current);
  return (
    <div className="flex items-center gap-1">
      {PHASE_ORDER.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
          <p className="text-lg font-medium">No data available</p>
          <p className="text-sm">Data will appear here once available</p>
        </div>
      ) : (
        PHASE_ORDER.map((phase, i) => (
        <div key={phase} className="flex items-center gap-1">
          <div
            className={cn(
              "h-2 rounded-full transition-all",
              i <= idx ? "bg-blue-500" : "bg-slate-700",
              i === idx ? "w-16" : "w-8"
            )}
          />
          {i < PHASE_ORDER.length - 1 && (
            <ChevronRight className="w-3 h-3 text-slate-600" />
          )}
        </div>
      ))
      )}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// MTTR Breakdown Bar
// ══════════════════════════════════════════════════════════════

const MTTRBreakdown = ({ durations }: { durations: IncidentDetail["phase_durations"] }) => {
  const total = durations.detection + durations.containment + durations.eradication + durations.recovery;
  if (total === 0) return <p className="text-sm text-gray-400">Timeline in progress</p>;

  const phases = [
    { label: "Detection",   hours: durations.detection,   color: "bg-yellow-500" },
    { label: "Containment", hours: durations.containment, color: "bg-orange-500" },
    { label: "Eradication", hours: durations.eradication, color: "bg-purple-500" },
    { label: "Recovery",    hours: durations.recovery,    color: "bg-green-500" },
  ].filter(p => p.hours > 0);

  return (
    <div className="space-y-3">
      <div className="flex h-6 rounded-full overflow-hidden gap-0.5">
        {phases.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Data will appear here once available</p>
          </div>
        ) : (
          phases.map(p => (
          <div
            key={p.label}
            className={cn("h-full transition-all", p.color)}
            style={{ width: `${(p.hours / total) * 100}%` }}
            title={`${p.label}: ${p.hours}h`}
          />
        ))
        )}
      </div>
      <div className="flex flex-wrap gap-4">
        {phases.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Data will appear here once available</p>
          </div>
        ) : (
          phases.map(p => (
          <div key={p.label} className="flex items-center gap-2">
            <div className={cn("w-3 h-3 rounded-full", p.color)} />
            <span className="text-sm text-gray-300">{p.label}</span>
            <span className="text-sm font-semibold text-white">{p.hours}h</span>
          </div>
        ))
        )}
        <div className="ml-auto flex items-center gap-2">
          <span className="text-sm text-gray-400">Total MTTR:</span>
          <span className="text-sm font-bold text-blue-400">{total.toFixed(1)}h</span>
        </div>
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// Timeline Event Row
// ══════════════════════════════════════════════════════════════

const TimelineEventRow = ({ event, isLast }: { event: TimelineEvent; isLast: boolean }) => {
  const [expanded, setExpanded] = useState(false);
  const cfg = getEventTypeConfig(event.event_type);
  const Icon = cfg.icon;

  return (
    <div className="flex gap-4">
      {/* Spine */}
      <div className="flex flex-col items-center">
        <div className={cn("w-9 h-9 rounded-full border flex items-center justify-center flex-shrink-0", cfg.color)}>
          <Icon className="w-4 h-4" />
        </div>
        {!isLast && <div className="w-0.5 flex-1 bg-slate-700/60 my-1" />}
      </div>

      {/* Content */}
      <div className="flex-1 pb-6">
        <div className="flex items-start justify-between gap-2 flex-wrap mb-1">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className={cn("text-xs border", cfg.color)}>
              {cfg.label}
            </Badge>
            <span className="text-xs text-gray-400">{formatTs(event.timestamp)}</span>
            <span className="text-xs text-gray-500">· {event.actor}</span>
          </div>
          {event.evidence_attached && (
            <Badge className="bg-blue-500/15 text-blue-400 border-blue-500/30 border text-xs gap-1">
              <FileSearch className="w-3 h-3" />
              Evidence
            </Badge>
          )}
        </div>
        <p className="text-sm text-gray-200 leading-relaxed">{event.description}</p>

        {event.evidence_attached && event.evidence_detail && (
          <div className="mt-2">
            <button
              onClick={() => setExpanded(v => !v)}
              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
              {expanded ? "Hide" : "Show"} evidence
            </button>
            <AnimatePresence>
              {expanded && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <pre className="mt-2 p-3 rounded-lg bg-slate-900/80 border border-slate-700/50 text-xs text-gray-300 font-mono whitespace-pre-wrap leading-relaxed">
                    {event.evidence_detail}
                  </pre>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function IncidentTimeline() {
  const [selectedId, setSelectedId] = useState<string>("INC-2026-001");

  // Fetch incidents list
  const { data: incidentsData, isLoading } = useQuery({
    queryKey: ["incidents"],
    queryFn: async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/incidents`);
        if (!res.ok) throw new Error("Failed to fetch");
        return await res.json() as IncidentsData;
      } catch {
        return MOCK_INCIDENTS_DATA;
      }
    },
    staleTime: 2 * 60 * 1000,
  });

  // Fetch selected incident detail + timeline
  const { data: incidentDetail } = useQuery({
    queryKey: ["incident-timeline", selectedId],
    queryFn: async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/incidents/${selectedId}/timeline`);
        if (!res.ok) throw new Error("Failed to fetch");
        return await res.json() as IncidentDetail;
      } catch {
        return MOCK_INCIDENT_DETAILS[selectedId] ?? null;
      }
    },
    enabled: !!selectedId,
    staleTime: 2 * 60 * 1000,
  });

  if (isLoading) return <PageSkeleton />;

  const data = incidentsData ?? MOCK_INCIDENTS_DATA;
  const detail = incidentDetail ?? MOCK_INCIDENT_DETAILS[selectedId];

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <PageHeader
        title="Incident Response Timeline"
        subtitle="Chronicle and reconstruct security incidents with forensic precision"
        icon={Activity}
      />

      {/* ── KPI Row ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <div className="grid grid-cols-4 gap-4">
          <KpiCard
            title="Active Incidents"
            value={data.active_incidents}
            subtitle="Requiring active response"
            icon={AlertCircle}
            trend={{ value: -1, label: "vs last week" }}
          />
          <KpiCard
            title="Mean Time to Detect"
            value={`${data.mttd_hours}h`}
            subtitle="Avg detection latency"
            icon={Eye}
            trend={{ value: -0.8, label: "vs last month" }}
          />
          <KpiCard
            title="Mean Time to Contain"
            value={`${data.mttc_hours}h`}
            subtitle="Avg containment duration"
            icon={Clock}
            trend={{ value: -2.1, label: "vs last month" }}
          />
          <KpiCard
            title="Incidents This Month"
            value={data.incidents_this_month}
            subtitle="Apr 2026"
            icon={AlertTriangle}
            trend={{ value: 2, label: "vs Mar 2026" }}
          />
        </div>
      </motion.div>

      {/* ── Main Grid: Incidents + Timeline ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="grid grid-cols-12 gap-6"
      >
        {/* ── Left: Active Incidents Panel ── */}
        <div className="col-span-4 space-y-3">
          <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Shield className="w-4 h-4 text-orange-400" />
                Active Incidents
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {data.incidents.map(inc => (
                <button
                  key={inc.id}
                  onClick={() => setSelectedId(inc.id)}
                  className={cn(
                    "w-full text-left p-3 rounded-lg border transition-all",
                    selectedId === inc.id
                      ? "bg-blue-500/15 border-blue-500/50"
                      : "bg-slate-800/30 border-slate-700/50 hover:border-slate-600"
                  )}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-xs font-mono text-gray-400">{inc.id}</span>
                    <Badge variant="outline" className={cn("text-xs border", getSeverityStyle(inc.severity))}>
                      {inc.severity}
                    </Badge>
                  </div>
                  <p className="text-sm text-white font-medium leading-snug mb-2">{inc.title}</p>
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-1.5">
                      <Target className="w-3 h-3 text-gray-500" />
                      <span className="text-xs text-gray-400">
                        {inc.affected_systems.length} system{inc.affected_systems.length !== 1 ? "s" : ""}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Users className="w-3 h-3 text-gray-500" />
                      <span className="text-xs text-gray-400">{inc.assigned_team}</span>
                    </div>
                  </div>
                  <div className="mt-2 pt-2 border-t border-slate-700/40 flex items-center justify-between">
                    <Badge variant="outline" className={cn("text-xs border", getPhaseStyle(inc.current_phase))}>
                      {inc.current_phase}
                    </Badge>
                    <PhaseProgress current={inc.current_phase} />
                  </div>
                </button>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* ── Right: Timeline View ── */}
        <div className="col-span-8">
          {detail ? (
            <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
              <CardHeader className="pb-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-xs font-mono text-gray-400 mb-1">{detail.id}</p>
                    <CardTitle className="text-base leading-snug">{detail.title}</CardTitle>
                  </div>
                  <Badge variant="outline" className={cn("border flex-shrink-0", getSeverityStyle(detail.severity))}>
                    {detail.severity}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-0">
                  {detail.timeline.map((event, idx) => (
                    <TimelineEventRow
                      key={event.id}
                      event={event}
                      isLast={idx === detail.timeline.length - 1}
                    />
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50 h-full flex items-center justify-center">
              <CardContent>
                <p className="text-gray-400 text-sm">Select an incident to view its timeline</p>
              </CardContent>
            </Card>
          )}
        </div>
      </motion.div>

      {/* ── Bottom Row: Summary + MTTR ── */}
      {detail && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="grid grid-cols-2 gap-6"
        >
          {/* Incident Summary */}
          <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <BookOpen className="w-4 h-4 text-blue-400" />
                Incident Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Affected Systems</p>
                <div className="flex flex-wrap gap-1.5">
                  {detail.affected_systems.map(sys => (
                    <Badge key={sys} variant="outline" className="bg-slate-800 text-slate-300 border-slate-600 font-mono text-xs">
                      {sys}
                    </Badge>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Containment Status</p>
                <p className="text-sm text-gray-200">{detail.containment_status}</p>
              </div>

              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Root Cause</p>
                <p className="text-sm text-gray-200 leading-relaxed">{detail.root_cause}</p>
              </div>

              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">MITRE ATT&CK Techniques</p>
                <div className="space-y-1">
                  {detail.mitre_techniques.map(t => (
                    <div key={t} className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-red-400 flex-shrink-0" />
                      <span className="text-xs text-gray-300 font-mono">{t}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Lessons Learned</p>
                <div className="space-y-1.5">
                  {detail.lessons_learned.map((lesson, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-400 flex-shrink-0 mt-0.5" />
                      <span className="text-xs text-gray-300 leading-relaxed">{lesson}</span>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* MTTR Breakdown */}
          <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Clock className="w-4 h-4 text-purple-400" />
                MTTR Phase Breakdown
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <MTTRBreakdown durations={detail.phase_durations} />

              <div className="space-y-3 pt-2 border-t border-slate-700/40">
                {[
                  { phase: "Detection",   hours: detail.phase_durations.detection,   color: "bg-yellow-500/20 border-yellow-500/30 text-yellow-300" },
                  { phase: "Containment", hours: detail.phase_durations.containment, color: "bg-orange-500/20 border-orange-500/30 text-orange-300" },
                  { phase: "Eradication", hours: detail.phase_durations.eradication, color: "bg-purple-500/20 border-purple-500/30 text-purple-300" },
                  { phase: "Recovery",    hours: detail.phase_durations.recovery,    color: "bg-green-500/20 border-green-500/30 text-green-300" },
                ].map(({ phase, hours, color }) => (
                  <div key={phase} className="flex items-center gap-3">
                    <Badge variant="outline" className={cn("text-xs border w-28 justify-center", color)}>
                      {phase}
                    </Badge>
                    <div className="flex-1 h-2.5 bg-slate-700 rounded-full overflow-hidden">
                      <div
                        className={cn(
                          "h-full rounded-full transition-all",
                          phase === "Detection"   ? "bg-yellow-500" :
                          phase === "Containment" ? "bg-orange-500" :
                          phase === "Eradication" ? "bg-purple-500" : "bg-green-500"
                        )}
                        style={{
                          width: hours > 0
                            ? `${(hours / Math.max(detail.phase_durations.detection, detail.phase_durations.containment, detail.phase_durations.eradication, detail.phase_durations.recovery, 1)) * 100}%`
                            : "0%"
                        }}
                      />
                    </div>
                    <span className="text-sm font-semibold text-white w-12 text-right">
                      {hours > 0 ? `${hours}h` : <span className="text-gray-600">—</span>}
                    </span>
                  </div>
                ))}
              </div>

              <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-700/40">
                <p className="text-xs text-gray-400 leading-relaxed">
                  Phase durations reflect time from phase entry to exit. Ongoing phases show elapsed time.
                  Target MTTC: &lt;24h (Critical), &lt;72h (High).
                </p>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="flex items-center justify-between text-sm text-gray-400 pb-4"
      >
        <p>Incident data sourced from ALDECI SIEM, EDR, and DLP event streams.</p>
        <Button variant="outline" size="sm" className="gap-2 text-xs" disabled>
          <FileSearch className="w-3.5 h-3.5" />
          Export Report
        </Button>
      </motion.div>
    </div>
  );
}
