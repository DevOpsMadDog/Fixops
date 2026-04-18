/**
 * Incident Response — IR Command Center
 *
 * Designed for SOC T2/T3 and IR leads managing active security incidents.
 * State machine lifecycle, step checklists, assignees, timeline, linked findings.
 * Dark-first, information-dense, high-signal visual hierarchy.
 *
 * Route: /incidents
 */

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Siren,
  ShieldAlert,
  Bug,
  Cloud,
  KeyRound,
  Container,
  Server,
  Network,
  Lock,
  Globe,
  ChevronRight,
  Clock,
  User,
  CheckSquare,
  Square,
  AlertTriangle,
  Activity,
  FileText,
  Link2,
  Calendar,
  ArrowRight,
  Search,
  Filter,
  Plus,
  ExternalLink,
  Circle,
  CheckCircle2,
  Loader2,
  XCircle,
  Crosshair,
  Zap,
  Database,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low";
type IRState =
  | "DETECTED"
  | "TRIAGING"
  | "CONTAINING"
  | "ERADICATING"
  | "RECOVERING"
  | "CLOSED";

type IncidentType =
  | "ransomware"
  | "data_breach"
  | "supply_chain"
  | "insider_threat"
  | "ddos"
  | "credential_compromise"
  | "lateral_movement"
  | "zero_day";

interface ChecklistItem {
  id: string;
  label: string;
  assignee?: string;
  done: boolean;
  phase: IRState;
}

interface TimelineEvent {
  id: string;
  ts: Date;
  actor: string;
  action: string;
  detail?: string;
  type: "detection" | "action" | "escalation" | "update" | "resolution";
}

interface LinkedFinding {
  id: string;
  title: string;
  severity: Severity;
  source: string;
  cve?: string;
}

interface Incident {
  id: string;
  title: string;
  type: IncidentType;
  severity: Severity;
  state: IRState;
  summary: string;
  affectedAssets: string[];
  owner: string;
  team: string[];
  detectedAt: Date;
  updatedAt: Date;
  sla_breach_at: Date;
  checklist: ChecklistItem[];
  timeline: TimelineEvent[];
  findings: LinkedFinding[];
  mttr_est_hours: number;
  tags: string[];
}

// ═══════════════════════════════════════════════════════════
// State machine config
// ═══════════════════════════════════════════════════════════

const IR_STATES: IRState[] = [
  "DETECTED",
  "TRIAGING",
  "CONTAINING",
  "ERADICATING",
  "RECOVERING",
  "CLOSED",
];

const STATE_META: Record<
  IRState,
  { label: string; color: string; bg: string; description: string }
> = {
  DETECTED: {
    label: "Detected",
    color: "text-red-400",
    bg: "bg-red-400/10 border-red-400/30",
    description: "Incident identified, initial assessment underway",
  },
  TRIAGING: {
    label: "Triaging",
    color: "text-orange-400",
    bg: "bg-orange-400/10 border-orange-400/30",
    description: "Scope, impact, and severity being assessed",
  },
  CONTAINING: {
    label: "Containing",
    color: "text-yellow-400",
    bg: "bg-yellow-400/10 border-yellow-400/30",
    description: "Active threat being isolated to prevent spread",
  },
  ERADICATING: {
    label: "Eradicating",
    color: "text-blue-400",
    bg: "bg-blue-400/10 border-blue-400/30",
    description: "Root cause and malicious artifacts being removed",
  },
  RECOVERING: {
    label: "Recovering",
    color: "text-emerald-400",
    bg: "bg-emerald-400/10 border-emerald-400/30",
    description: "Systems being restored and validated",
  },
  CLOSED: {
    label: "Closed",
    color: "text-muted-foreground",
    bg: "bg-muted/20 border-border",
    description: "Incident resolved, post-mortem complete",
  },
};

// ═══════════════════════════════════════════════════════════
// Incident type config
// ═══════════════════════════════════════════════════════════

const TYPE_META: Record<
  IncidentType,
  { label: string; icon: React.ComponentType<{ className?: string }> }
> = {
  ransomware: { label: "Ransomware", icon: Lock },
  data_breach: { label: "Data Breach", icon: Database },
  supply_chain: { label: "Supply Chain", icon: Link2 },
  insider_threat: { label: "Insider Threat", icon: User },
  ddos: { label: "DDoS", icon: Network },
  credential_compromise: { label: "Credential Compromise", icon: KeyRound },
  lateral_movement: { label: "Lateral Movement", icon: Crosshair },
  zero_day: { label: "Zero Day", icon: Zap },
};

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const now = new Date();
const minsAgo = (m: number) => new Date(now.getTime() - m * 60_000);
const hoursAgo = (h: number) => new Date(now.getTime() - h * 3_600_000);
const hoursFromNow = (h: number) => new Date(now.getTime() + h * 3_600_000);

const MOCK_INCIDENTS: Incident[] = [
  {
    id: "INC-2024-0041",
    title: "XZ Utils Backdoor: Active Exploitation Attempt on prod-api-01",
    type: "supply_chain",
    severity: "critical",
    state: "CONTAINING",
    summary:
      "CVE-2024-3094 actively exploited against prod-api-01. Attacker established C2 channel via liblzma.so backdoor. SSH brute-force traffic observed from 185.220.101.x. Container quarantined; lateral movement to prod-db-02 suspected.",
    affectedAssets: ["prod-api-01", "aldeci-api:v2.3.1", "prod-db-02 (suspected)"],
    owner: "jsmith",
    team: ["jsmith", "mchen", "t.okonkwo"],
    detectedAt: minsAgo(112),
    updatedAt: minsAgo(8),
    sla_breach_at: hoursFromNow(2),
    mttr_est_hours: 6,
    tags: ["supply-chain", "rce", "c2", "critical-path"],
    checklist: [
      { id: "c1", label: "Isolate affected container from network", assignee: "jsmith", done: true, phase: "CONTAINING" },
      { id: "c2", label: "Revoke compromised SSH keys", assignee: "mchen", done: true, phase: "CONTAINING" },
      { id: "c3", label: "Block C2 IPs at perimeter (185.220.101.0/24)", assignee: "jsmith", done: false, phase: "CONTAINING" },
      { id: "c4", label: "Forensic memory dump of prod-api-01", assignee: "t.okonkwo", done: false, phase: "CONTAINING" },
      { id: "c5", label: "Scan all containers for xz-utils 5.6.0-5.6.1", assignee: "mchen", done: false, phase: "ERADICATING" },
      { id: "c6", label: "Rebuild base images from debian:bookworm-slim", assignee: "jsmith", done: false, phase: "ERADICATING" },
      { id: "c7", label: "Validate prod-db-02 integrity", assignee: "t.okonkwo", done: false, phase: "ERADICATING" },
      { id: "c8", label: "Restore prod-api-01 from clean image", assignee: "jsmith", done: false, phase: "RECOVERING" },
      { id: "c9", label: "24-hour enhanced monitoring post-restore", assignee: "mchen", done: false, phase: "RECOVERING" },
      { id: "c10", label: "Draft post-mortem and lessons learned", assignee: "t.okonkwo", done: false, phase: "CLOSED" },
    ],
    timeline: [
      { id: "t1", ts: minsAgo(112), actor: "Trivy Scanner", action: "CVE-2024-3094 detected in aldeci-api:v2.3.1", type: "detection" },
      { id: "t2", ts: minsAgo(105), actor: "ALDECI Brain", action: "LLM Council verdict: BLOCK (98% confidence)", detail: "4/4 models in agreement. Immediate isolation recommended.", type: "escalation" },
      { id: "t3", ts: minsAgo(98), actor: "jsmith", action: "Incident declared INC-2024-0041 — Severity CRITICAL", type: "action" },
      { id: "t4", ts: minsAgo(91), actor: "jsmith", action: "Container prod-api-01 quarantined", detail: "Network policy applied. Container isolated in quarantine namespace.", type: "action" },
      { id: "t5", ts: minsAgo(84), actor: "mchen", action: "SSH key rotation initiated", detail: "17 keys revoked across production fleet.", type: "action" },
      { id: "t6", ts: minsAgo(67), actor: "Network IDS", action: "C2 traffic detected from prod-api-01 → 185.220.101.42:4444", detail: "Beaconing at 5-minute intervals. Consistent with XZ backdoor C2 protocol.", type: "detection" },
      { id: "t7", ts: minsAgo(58), actor: "jsmith", action: "Escalated to CISO — active exploitation confirmed", type: "escalation" },
      { id: "t8", ts: minsAgo(32), actor: "t.okonkwo", action: "Lateral movement indicators on prod-db-02", detail: "Unusual auth attempts from quarantined prod-api-01 IP prior to isolation.", type: "update" },
      { id: "t9", ts: minsAgo(8), actor: "mchen", action: "State advanced: TRIAGING → CONTAINING", type: "update" },
    ],
    findings: [
      { id: "ALT-0041", title: "CVE-2024-3094: XZ Utils Backdoor in Base Image", severity: "critical", source: "Trivy", cve: "CVE-2024-3094" },
      { id: "ALT-0036", title: "Suspicious outbound C2 traffic on port 4444", severity: "critical", source: "Network IDS" },
      { id: "ALT-0033", title: "Unauthorized auth attempts on prod-db-02", severity: "high", source: "SIEM" },
    ],
  },
  {
    id: "INC-2024-0040",
    title: "Hardcoded AWS Credentials Exposed — Active Key Detected in Prod",
    type: "credential_compromise",
    severity: "critical",
    state: "ERADICATING",
    summary:
      "AWS_SECRET_ACCESS_KEY found in plaintext in production Dockerfile. Key confirmed active with S3:* and EC2:* permissions. GitLeaks scan shows key committed 23 days ago. Rotation completed; auditing for unauthorized access in CloudTrail.",
    affectedAssets: ["services/api/Dockerfile", "AWS IAM key AKIA3X7ZL2Q9", "S3://aldeci-prod-backups"],
    owner: "mchen",
    team: ["mchen", "jsmith"],
    detectedAt: hoursAgo(4),
    updatedAt: minsAgo(23),
    sla_breach_at: hoursFromNow(8),
    mttr_est_hours: 4,
    tags: ["secrets", "iam", "aws", "data-exposure"],
    checklist: [
      { id: "c1", label: "Rotate compromised AWS key immediately", assignee: "mchen", done: true, phase: "CONTAINING" },
      { id: "c2", label: "Revoke all sessions for AKIA3X7ZL2Q9", assignee: "mchen", done: true, phase: "CONTAINING" },
      { id: "c3", label: "Remove secret from Dockerfile + git history", assignee: "jsmith", done: true, phase: "ERADICATING" },
      { id: "c4", label: "Audit CloudTrail for unauthorized API calls", assignee: "mchen", done: false, phase: "ERADICATING" },
      { id: "c5", label: "Verify S3 bucket ACLs and access logs", assignee: "jsmith", done: false, phase: "ERADICATING" },
      { id: "c6", label: "Migrate secret to AWS Secrets Manager", assignee: "mchen", done: false, phase: "RECOVERING" },
      { id: "c7", label: "Add pre-commit hook for secret scanning", assignee: "jsmith", done: false, phase: "RECOVERING" },
    ],
    timeline: [
      { id: "t1", ts: hoursAgo(4), actor: "Semgrep", action: "Hardcoded credential pattern detected in Dockerfile", type: "detection" },
      { id: "t2", ts: hoursAgo(3.8), actor: "ALDECI Brain", action: "LLM Council: BLOCK (99% confidence). Active key confirmed via AWS STS GetCallerIdentity.", type: "escalation" },
      { id: "t3", ts: hoursAgo(3.5), actor: "mchen", action: "Key rotated — new key provisioned via Vault", type: "action" },
      { id: "t4", ts: hoursAgo(2.5), actor: "jsmith", action: "Git history rewritten with BFG Repo Cleaner", detail: "Force-pushed to all branches. GitHub informed for cache purge.", type: "action" },
      { id: "t5", ts: minsAgo(23), actor: "mchen", action: "CloudTrail audit in progress — 3 suspicious GetObject calls identified", type: "update" },
    ],
    findings: [
      { id: "ALT-0040", title: "Hardcoded AWS Credentials in Production Dockerfile", severity: "critical", source: "Semgrep" },
      { id: "ALT-0029", title: "S3 bucket aldeci-prod-backups: 3 unexpected GetObject", severity: "high", source: "CloudTrail" },
    ],
  },
  {
    id: "INC-2024-0039",
    title: "Suspected Insider Data Exfiltration — HR Records",
    type: "insider_threat",
    severity: "high",
    state: "TRIAGING",
    summary:
      "Anomalous bulk export of HR records (2,847 employee records) detected by DLP. User account u.patel accessed /api/v1/hr/bulk-export 14 times in 6 hours — 400x above baseline. Account suspended; legal hold initiated.",
    affectedAssets: ["HR DB", "u.patel (account suspended)", "/api/v1/hr/bulk-export"],
    owner: "t.okonkwo",
    team: ["t.okonkwo", "legal-team", "hr-security"],
    detectedAt: hoursAgo(7),
    updatedAt: hoursAgo(1),
    sla_breach_at: hoursFromNow(17),
    mttr_est_hours: 24,
    tags: ["insider", "dlp", "pii", "legal-hold"],
    checklist: [
      { id: "c1", label: "Suspend u.patel account and terminate sessions", assignee: "t.okonkwo", done: true, phase: "CONTAINING" },
      { id: "c2", label: "Initiate legal hold on u.patel workstation", assignee: "legal-team", done: true, phase: "TRIAGING" },
      { id: "c3", label: "Pull SIEM logs for all u.patel activity (90 days)", assignee: "t.okonkwo", done: false, phase: "TRIAGING" },
      { id: "c4", label: "Identify all data accessed and exfiltration vectors", assignee: "t.okonkwo", done: false, phase: "TRIAGING" },
      { id: "c5", label: "Notify DPO — potential GDPR breach", assignee: "legal-team", done: false, phase: "TRIAGING" },
    ],
    timeline: [
      { id: "t1", ts: hoursAgo(7), actor: "DLP Engine", action: "Bulk HR record export anomaly — 2,847 records in 6h", type: "detection" },
      { id: "t2", ts: hoursAgo(6.5), actor: "SIEM", action: "UBA alert: 400x API call rate anomaly for u.patel", type: "detection" },
      { id: "t3", ts: hoursAgo(6), actor: "t.okonkwo", action: "Account u.patel suspended, all sessions revoked", type: "action" },
      { id: "t4", ts: hoursAgo(5), actor: "t.okonkwo", action: "Legal team notified, legal hold initiated", type: "escalation" },
      { id: "t5", ts: hoursAgo(1), actor: "t.okonkwo", action: "Log extraction complete, analysis in progress", type: "update" },
    ],
    findings: [
      { id: "UBA-0012", title: "Anomalous bulk export: 2,847 HR records", severity: "high", source: "DLP" },
      { id: "UBA-0011", title: "API rate anomaly: 400x baseline for u.patel", severity: "high", source: "SIEM" },
    ],
  },
  {
    id: "INC-2024-0037",
    title: "DDoS: ALB Under Volumetric Attack — 3.2Gbps Sustained",
    type: "ddos",
    severity: "high",
    state: "RECOVERING",
    summary:
      "Application Load Balancer receiving 3.2Gbps sustained UDP flood from 47 source ASNs. AWS Shield Advanced mitigating ~85%. Origin IPs partially exposed. Cloudflare WAF rules deployed. Traffic normalizing.",
    affectedAssets: ["aldeci-prod-alb", "api.aldeci.io", "Cloudflare WAF"],
    owner: "jsmith",
    team: ["jsmith", "cloud-ops"],
    detectedAt: hoursAgo(9),
    updatedAt: minsAgo(45),
    sla_breach_at: hoursFromNow(3),
    mttr_est_hours: 2,
    tags: ["ddos", "availability", "aws-shield", "cloudflare"],
    checklist: [
      { id: "c1", label: "Enable AWS Shield Advanced rate limiting", assignee: "jsmith", done: true, phase: "CONTAINING" },
      { id: "c2", label: "Deploy Cloudflare WAF volumetric rules", assignee: "cloud-ops", done: true, phase: "CONTAINING" },
      { id: "c3", label: "Geo-block 12 high-volume source countries", assignee: "jsmith", done: true, phase: "CONTAINING" },
      { id: "c4", label: "Scale ALB capacity +200%", assignee: "cloud-ops", done: true, phase: "RECOVERING" },
      { id: "c5", label: "Monitor traffic for 4h post-mitigation", assignee: "jsmith", done: false, phase: "RECOVERING" },
      { id: "c6", label: "File AWS abuse report for bot ASNs", assignee: "cloud-ops", done: false, phase: "RECOVERING" },
    ],
    timeline: [
      { id: "t1", ts: hoursAgo(9), actor: "AWS CloudWatch", action: "ALB 5xx rate exceeded 40% — DDoS suspected", type: "detection" },
      { id: "t2", ts: hoursAgo(8.5), actor: "AWS Shield", action: "Volumetric attack confirmed: 3.2Gbps UDP flood from 47 ASNs", type: "detection" },
      { id: "t3", ts: hoursAgo(8), actor: "jsmith", action: "AWS Shield Advanced rules activated", type: "action" },
      { id: "t4", ts: hoursAgo(7), actor: "cloud-ops", action: "Cloudflare WAF rules deployed — blocking 60% of malicious traffic", type: "action" },
      { id: "t5", ts: hoursAgo(5), actor: "jsmith", action: "Geo-blocking applied to 12 source countries", type: "action" },
      { id: "t6", ts: minsAgo(45), actor: "cloud-ops", action: "Traffic normalizing — ALB error rate below 2%", type: "update" },
    ],
    findings: [
      { id: "NET-0019", title: "Volumetric UDP flood: 3.2Gbps to ALB", severity: "high", source: "AWS Shield" },
      { id: "NET-0018", title: "ALB 5xx rate spike: 42% error rate", severity: "high", source: "CloudWatch" },
    ],
  },
  {
    id: "INC-2024-0035",
    title: "Zero-Day: Remote Code Execution in OpenSSH 9.7p1",
    type: "zero_day",
    severity: "critical",
    state: "CLOSED",
    summary:
      "CVE-2024-6387 (regreSSHion) exploited against 3 legacy jump hosts. Unauthenticated RCE achieved via race condition in signal handler. All affected hosts patched and re-imaged. No data exfiltration confirmed.",
    affectedAssets: ["jump-01 (patched)", "jump-02 (patched)", "jump-03 (patched)"],
    owner: "mchen",
    team: ["mchen", "jsmith", "t.okonkwo"],
    detectedAt: hoursAgo(48),
    updatedAt: hoursAgo(6),
    sla_breach_at: hoursAgo(40),
    mttr_est_hours: 8,
    tags: ["zero-day", "rce", "openssh", "jump-host"],
    checklist: [
      { id: "c1", label: "Emergency patch OpenSSH to 9.8p1 on all hosts", assignee: "mchen", done: true, phase: "ERADICATING" },
      { id: "c2", label: "Re-image all 3 affected jump hosts", assignee: "jsmith", done: true, phase: "ERADICATING" },
      { id: "c3", label: "Rotate all SSH credentials fleet-wide", assignee: "mchen", done: true, phase: "RECOVERING" },
      { id: "c4", label: "Enable login_grace_time 0 as temporary mitigation", assignee: "jsmith", done: true, phase: "CONTAINING" },
      { id: "c5", label: "Post-mortem published to security@", assignee: "t.okonkwo", done: true, phase: "CLOSED" },
    ],
    timeline: [
      { id: "t1", ts: hoursAgo(48), actor: "Threat Intel Feed", action: "CVE-2024-6387 PoC published — regreSSHion", type: "detection" },
      { id: "t2", ts: hoursAgo(46), actor: "SIEM", action: "Exploit attempt pattern matched on jump-01/02/03", type: "detection" },
      { id: "t3", ts: hoursAgo(44), actor: "mchen", action: "Temporary mitigation: login_grace_time 0 applied fleet-wide", type: "action" },
      { id: "t4", ts: hoursAgo(36), actor: "mchen", action: "Patch deployed — OpenSSH 9.8p1 on all hosts", type: "action" },
      { id: "t5", ts: hoursAgo(24), actor: "jsmith", action: "Jump hosts re-imaged and validated", type: "action" },
      { id: "t6", ts: hoursAgo(6), actor: "t.okonkwo", action: "Post-mortem published. Incident CLOSED.", type: "resolution" },
    ],
    findings: [
      { id: "ALT-0035", title: "CVE-2024-6387: regreSSHion on jump-01/02/03", severity: "critical", source: "Threat Intel", cve: "CVE-2024-6387" },
    ],
  },
  {
    id: "INC-2024-0034",
    title: "Lateral Movement: Compromised Service Account Pivoting in EKS",
    type: "lateral_movement",
    severity: "high",
    state: "DETECTED",
    summary:
      "Service account aldeci-scanner-sa exhibiting anomalous kubectl exec commands across 6 pods. RBAC permissions far exceed least privilege. Active investigation underway.",
    affectedAssets: ["aldeci-scanner-sa", "EKS cluster prod-k8s-01", "6 pods (suspected)"],
    owner: "t.okonkwo",
    team: ["t.okonkwo"],
    detectedAt: minsAgo(18),
    updatedAt: minsAgo(5),
    sla_breach_at: hoursFromNow(6),
    mttr_est_hours: 3,
    tags: ["lateral-movement", "kubernetes", "rbac", "service-account"],
    checklist: [
      { id: "c1", label: "Revoke aldeci-scanner-sa token immediately", assignee: "t.okonkwo", done: false, phase: "CONTAINING" },
      { id: "c2", label: "Capture pod logs before termination", assignee: "t.okonkwo", done: false, phase: "TRIAGING" },
      { id: "c3", label: "Audit RBAC permissions for all service accounts", assignee: "t.okonkwo", done: false, phase: "ERADICATING" },
    ],
    timeline: [
      { id: "t1", ts: minsAgo(18), actor: "Falco", action: "Anomalous kubectl exec detected from aldeci-scanner-sa", type: "detection" },
      { id: "t2", ts: minsAgo(12), actor: "ALDECI Brain", action: "Lateral movement pattern confirmed — 6 pods affected", type: "escalation" },
      { id: "t3", ts: minsAgo(5), actor: "t.okonkwo", action: "Incident INC-2024-0034 declared — investigation started", type: "action" },
    ],
    findings: [
      { id: "K8S-0007", title: "Anomalous kubectl exec: aldeci-scanner-sa across 6 pods", severity: "high", source: "Falco" },
    ],
  },
  {
    id: "INC-2024-0031",
    title: "Ransomware Precursor: Cobalt Strike Beacon on dev-workstation-07",
    type: "ransomware",
    severity: "critical",
    state: "ERADICATING",
    summary:
      "CrowdStrike detected Cobalt Strike beacon on dev-workstation-07. C2 communication established to known ransomware-as-a-service infrastructure (Lockbit 3.0). Machine isolated. No encryption observed yet.",
    affectedAssets: ["dev-workstation-07", "developer d.rivera account"],
    owner: "jsmith",
    team: ["jsmith", "mchen", "endpoint-team"],
    detectedAt: hoursAgo(6),
    updatedAt: hoursAgo(1),
    sla_breach_at: hoursFromNow(1),
    mttr_est_hours: 8,
    tags: ["ransomware", "cobalt-strike", "c2", "endpoint"],
    checklist: [
      { id: "c1", label: "Isolate dev-workstation-07 from network", assignee: "jsmith", done: true, phase: "CONTAINING" },
      { id: "c2", label: "Block Lockbit C2 IPs at perimeter", assignee: "mchen", done: true, phase: "CONTAINING" },
      { id: "c3", label: "Forensic image of workstation disk", assignee: "endpoint-team", done: true, phase: "TRIAGING" },
      { id: "c4", label: "Kill beacon process and remove persistence", assignee: "endpoint-team", done: false, phase: "ERADICATING" },
      { id: "c5", label: "Scan all developer machines for IOCs", assignee: "jsmith", done: false, phase: "ERADICATING" },
      { id: "c6", label: "Re-image dev-workstation-07", assignee: "endpoint-team", done: false, phase: "RECOVERING" },
    ],
    timeline: [
      { id: "t1", ts: hoursAgo(6), actor: "CrowdStrike", action: "Cobalt Strike beacon detected — Lockbit 3.0 IOC match", type: "detection" },
      { id: "t2", ts: hoursAgo(5.8), actor: "jsmith", action: "Workstation isolated from network", type: "action" },
      { id: "t3", ts: hoursAgo(4), actor: "endpoint-team", action: "Forensic disk image captured", type: "action" },
      { id: "t4", ts: hoursAgo(1), actor: "mchen", action: "Perimeter C2 blocks confirmed active", type: "action" },
    ],
    findings: [
      { id: "EDR-0004", title: "Cobalt Strike beacon: Lockbit 3.0 IOC match", severity: "critical", source: "CrowdStrike" },
      { id: "NET-0016", title: "C2 beaconing to 91.92.251.x (Lockbit infrastructure)", severity: "critical", source: "Network IDS" },
    ],
  },
  {
    id: "INC-2024-0028",
    title: "Data Breach: Customer PII Exposed via Misconfigured S3 Bucket",
    type: "data_breach",
    severity: "high",
    state: "CLOSED",
    summary:
      "S3 bucket aldeci-customer-exports left publicly accessible for 11 days. Contains customer names, emails, and subscription data for 12,400 accounts. Bucket secured. GDPR 72-hour notification sent. Customers notified.",
    affectedAssets: ["S3://aldeci-customer-exports", "12,400 customer records"],
    owner: "mchen",
    team: ["mchen", "legal-team", "customer-success"],
    detectedAt: hoursAgo(72),
    updatedAt: hoursAgo(24),
    sla_breach_at: hoursAgo(48),
    mttr_est_hours: 16,
    tags: ["data-breach", "s3", "pii", "gdpr", "customer-data"],
    checklist: [
      { id: "c1", label: "Set S3 bucket to private + block public access", assignee: "mchen", done: true, phase: "CONTAINING" },
      { id: "c2", label: "Audit S3 access logs for external access", assignee: "mchen", done: true, phase: "TRIAGING" },
      { id: "c3", label: "GDPR 72-hour DPA notification filed", assignee: "legal-team", done: true, phase: "ERADICATING" },
      { id: "c4", label: "Customer breach notification sent", assignee: "customer-success", done: true, phase: "RECOVERING" },
      { id: "c5", label: "S3 public access audit across all buckets", assignee: "mchen", done: true, phase: "ERADICATING" },
      { id: "c6", label: "Post-mortem + policy update", assignee: "mchen", done: true, phase: "CLOSED" },
    ],
    timeline: [
      { id: "t1", ts: hoursAgo(72), actor: "AWS Config", action: "S3 bucket aldeci-customer-exports marked public — rule violation", type: "detection" },
      { id: "t2", ts: hoursAgo(71), actor: "mchen", action: "Bucket secured — public access disabled", type: "action" },
      { id: "t3", ts: hoursAgo(60), actor: "mchen", action: "Access log analysis: 3 external IPs accessed bucket during exposure", type: "update" },
      { id: "t4", ts: hoursAgo(48), actor: "legal-team", action: "GDPR DPA notification filed", type: "action" },
      { id: "t5", ts: hoursAgo(24), actor: "customer-success", action: "12,400 customer notifications sent. Incident CLOSED.", type: "resolution" },
    ],
    findings: [
      { id: "CSP-0009", title: "S3 bucket publicly accessible: aldeci-customer-exports", severity: "critical", source: "AWS Config" },
      { id: "CSP-0008", title: "3 external IPs accessed PII during 11-day exposure", severity: "high", source: "S3 Access Logs" },
    ],
  },
];

// ═══════════════════════════════════════════════════════════
// Helper components
// ═══════════════════════════════════════════════════════════

function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  }[severity];
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border", cfg)}>
      {severity}
    </span>
  );
}

function StateBadge({ state }: { state: IRState }) {
  const meta = STATE_META[state];
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border", meta.bg, meta.color)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
      {meta.label}
    </span>
  );
}

function TimeAgo({ date }: { date: Date }) {
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays > 0) return <span>{diffDays}d ago</span>;
  if (diffHours > 0) return <span>{diffHours}h {diffMins % 60}m ago</span>;
  return <span>{diffMins}m ago</span>;
}

function SLABadge({ sla_breach_at }: { sla_breach_at: Date }) {
  const diffMs = sla_breach_at.getTime() - now.getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  const diffHours = Math.floor(diffMins / 60);
  const breached = diffMs < 0;
  const urgent = !breached && diffHours < 2;

  if (breached) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/40">
        <XCircle className="h-3 w-3" /> SLA BREACHED
      </span>
    );
  }
  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border",
      urgent
        ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
        : "bg-muted/30 text-muted-foreground border-border"
    )}>
      <Clock className="h-3 w-3" />
      {urgent ? `${diffHours}h ${diffMins % 60}m` : `${diffHours}h`} left
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// State Machine Progress
// ═══════════════════════════════════════════════════════════

function IRStateMachine({ state }: { state: IRState }) {
  const currentIdx = IR_STATES.indexOf(state);

  return (
    <div className="flex items-center gap-0 w-full">
      {IR_STATES.map((s, idx) => {
        const meta = STATE_META[s];
        const isActive = idx === currentIdx;
        const isPast = idx < currentIdx;
        const isFuture = idx > currentIdx;

        return (
          <div key={s} className="flex items-center flex-1">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="flex flex-col items-center gap-1.5 flex-1">
                    <div
                      className={cn(
                        "h-7 w-7 rounded-full flex items-center justify-center border-2 transition-all duration-300",
                        isActive && cn("border-current ring-2 ring-offset-1 ring-offset-background", meta.color),
                        isPast && "border-emerald-500/50 bg-emerald-500/15",
                        isFuture && "border-muted-foreground/20 bg-muted/10"
                      )}
                    >
                      {isPast ? (
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                      ) : isActive ? (
                        <div className={cn("h-2 w-2 rounded-full bg-current animate-pulse", meta.color)} />
                      ) : (
                        <Circle className="h-3 w-3 text-muted-foreground/30" />
                      )}
                    </div>
                    <span
                      className={cn(
                        "text-[9px] font-bold uppercase tracking-wider text-center leading-tight",
                        isActive && meta.color,
                        isPast && "text-emerald-400/70",
                        isFuture && "text-muted-foreground/30"
                      )}
                    >
                      {meta.label}
                    </span>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="text-xs">{meta.description}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            {idx < IR_STATES.length - 1 && (
              <div
                className={cn(
                  "h-px flex-1 mx-1 transition-colors duration-300",
                  idx < currentIdx ? "bg-emerald-500/40" : "bg-muted/30"
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Timeline panel
// ═══════════════════════════════════════════════════════════

const TIMELINE_TYPE_STYLE: Record<TimelineEvent["type"], { dot: string; icon: React.ComponentType<{ className?: string }> }> = {
  detection: { dot: "bg-red-400", icon: AlertTriangle },
  action: { dot: "bg-blue-400", icon: Activity },
  escalation: { dot: "bg-orange-400", icon: Siren },
  update: { dot: "bg-muted-foreground", icon: FileText },
  resolution: { dot: "bg-emerald-400", icon: CheckCircle2 },
};

function TimelinePanel({ events }: { events: TimelineEvent[] }) {
  const sorted = [...events].sort((a, b) => b.ts.getTime() - a.ts.getTime());
  return (
    <div className="relative pl-5">
      <div className="absolute left-2 top-0 bottom-0 w-px bg-border" />
      {sorted.map((ev, idx) => {
        const style = TIMELINE_TYPE_STYLE[ev.type];
        const Icon = style.icon;
        return (
          <motion.div
            key={ev.id}
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.04 }}
            className="relative mb-4 last:mb-0"
          >
            <div className={cn("absolute -left-5 mt-1 h-3 w-3 rounded-full border-2 border-background", style.dot)} />
            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <Icon className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-xs font-medium text-foreground">{ev.action}</span>
              </div>
              {ev.detail && (
                <p className="text-[11px] text-muted-foreground leading-relaxed pl-5">{ev.detail}</p>
              )}
              <div className="flex items-center gap-2 pl-5">
                <span className="text-[10px] font-medium text-muted-foreground/70">{ev.actor}</span>
                <span className="text-[10px] text-muted-foreground/40">·</span>
                <span className="text-[10px] text-muted-foreground/60 tabular-nums">
                  <TimeAgo date={ev.ts} />
                </span>
              </div>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Checklist panel
// ═══════════════════════════════════════════════════════════

function ChecklistPanel({ items, currentState }: { items: ChecklistItem[]; currentState: IRState }) {
  const [checked, setChecked] = useState<Record<string, boolean>>(
    Object.fromEntries(items.map((i) => [i.id, i.done]))
  );

  const byPhase = useMemo(() => {
    const phases: Partial<Record<IRState, ChecklistItem[]>> = {};
    for (const item of items) {
      if (!phases[item.phase]) phases[item.phase] = [];
      phases[item.phase]!.push(item);
    }
    return phases;
  }, [items]);

  const currentPhaseIdx = IR_STATES.indexOf(currentState);

  return (
    <div className="space-y-4">
      {IR_STATES.filter((s) => byPhase[s]).map((phase) => {
        const phaseIdx = IR_STATES.indexOf(phase);
        const isPast = phaseIdx < currentPhaseIdx;
        const isCurrent = phaseIdx === currentPhaseIdx;
        const meta = STATE_META[phase];
        const phaseItems = byPhase[phase]!;
        const doneCount = phaseItems.filter((i) => checked[i.id]).length;

        return (
          <div key={phase} className={cn("rounded-lg border p-3", isCurrent ? meta.bg : "border-border/50")}>
            <div className="flex items-center justify-between mb-2.5">
              <div className="flex items-center gap-2">
                <span className={cn("text-[10px] font-bold uppercase tracking-wider", isCurrent ? meta.color : isPast ? "text-emerald-400/70" : "text-muted-foreground/40")}>
                  {meta.label}
                </span>
                {isPast && <CheckCircle2 className="h-3 w-3 text-emerald-400" />}
              </div>
              <span className="text-[10px] text-muted-foreground tabular-nums">{doneCount}/{phaseItems.length}</span>
            </div>
            <div className="space-y-1.5">
              {phaseItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setChecked((prev) => ({ ...prev, [item.id]: !prev[item.id] }))}
                  className="flex items-start gap-2.5 w-full text-left group"
                >
                  <div className="mt-0.5 shrink-0">
                    {checked[item.id] ? (
                      <CheckSquare className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <Square className="h-3.5 w-3.5 text-muted-foreground/40 group-hover:text-muted-foreground/70 transition-colors" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <span className={cn("text-xs leading-relaxed", checked[item.id] && "line-through text-muted-foreground/50")}>
                      {item.label}
                    </span>
                    {item.assignee && (
                      <div className="flex items-center gap-1 mt-0.5">
                        <User className="h-2.5 w-2.5 text-muted-foreground/40" />
                        <span className="text-[10px] text-muted-foreground/50">{item.assignee}</span>
                      </div>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Linked findings panel
// ═══════════════════════════════════════════════════════════

function FindingsPanel({ findings }: { findings: LinkedFinding[] }) {
  return (
    <div className="space-y-2">
      {findings.map((f) => (
        <div key={f.id} className="flex items-center gap-3 p-2.5 rounded-lg bg-muted/20 border border-border/50 hover:border-border transition-colors group">
          <SeverityBadge severity={f.severity} />
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium truncate">{f.title}</p>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-[10px] text-muted-foreground">{f.id}</span>
              <span className="text-[10px] text-muted-foreground/40">·</span>
              <span className="text-[10px] text-muted-foreground">{f.source}</span>
              {f.cve && (
                <>
                  <span className="text-[10px] text-muted-foreground/40">·</span>
                  <span className="text-[10px] font-mono text-blue-400">{f.cve}</span>
                </>
              )}
            </div>
          </div>
          <ExternalLink className="h-3 w-3 text-muted-foreground/30 group-hover:text-muted-foreground/70 shrink-0 transition-colors" />
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Incident detail panel
// ═══════════════════════════════════════════════════════════

function IncidentDetail({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const TypeIcon = TYPE_META[incident.type].icon;

  return (
    <motion.div
      initial={{ opacity: 0, x: 24 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 24 }}
      transition={{ duration: 0.2 }}
      className="flex flex-col h-full"
    >
      {/* Detail header */}
      <div className="p-5 border-b border-border space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <div className="h-9 w-9 rounded-lg bg-muted/30 border border-border flex items-center justify-center shrink-0 mt-0.5">
              <TypeIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono text-muted-foreground">{incident.id}</span>
                <SeverityBadge severity={incident.severity} />
                <StateBadge state={incident.state} />
              </div>
              <h2 className="text-sm font-semibold mt-1 leading-snug">{incident.title}</h2>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} className="shrink-0 h-7 w-7">
            <XCircle className="h-4 w-4" />
          </Button>
        </div>

        {/* State machine */}
        <IRStateMachine state={incident.state} />

        {/* Meta row */}
        <div className="flex items-center gap-4 flex-wrap text-[11px] text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <User className="h-3 w-3" />
            <span>{incident.owner}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="h-3 w-3" />
            <TimeAgo date={incident.detectedAt} />
          </div>
          <div className="flex items-center gap-1.5">
            <Activity className="h-3 w-3" />
            <span>~{incident.mttr_est_hours}h MTTR</span>
          </div>
          <SLABadge sla_breach_at={incident.sla_breach_at} />
        </div>

        {/* Summary */}
        <p className="text-xs text-muted-foreground leading-relaxed">{incident.summary}</p>

        {/* Affected assets */}
        <div className="space-y-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Affected Assets</span>
          <div className="flex flex-wrap gap-1.5">
            {incident.affectedAssets.map((a) => (
              <span key={a} className="px-2 py-0.5 rounded bg-muted/30 border border-border text-[10px] font-mono">{a}</span>
            ))}
          </div>
        </div>

        {/* Team */}
        <div className="space-y-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Response Team</span>
          <div className="flex flex-wrap gap-1.5">
            {incident.team.map((m) => (
              <span key={m} className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-muted/20 border border-border text-[11px]">
                <div className="h-3.5 w-3.5 rounded-full bg-primary/20 flex items-center justify-center text-[8px] font-bold text-primary">
                  {m[0]?.toUpperCase()}
                </div>
                {m}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex-1 overflow-hidden">
        <Tabs defaultValue="checklist" className="flex flex-col h-full">
          <TabsList className="mx-5 mt-3 w-auto justify-start shrink-0">
            <TabsTrigger value="checklist" className="text-xs gap-1.5">
              <CheckSquare className="h-3 w-3" />
              Steps
            </TabsTrigger>
            <TabsTrigger value="timeline" className="text-xs gap-1.5">
              <Clock className="h-3 w-3" />
              Timeline
            </TabsTrigger>
            <TabsTrigger value="findings" className="text-xs gap-1.5">
              <Link2 className="h-3 w-3" />
              Findings
            </TabsTrigger>
          </TabsList>

          <ScrollArea className="flex-1 mt-3">
            <div className="px-5 pb-6">
              <TabsContent value="checklist" className="mt-0">
                <ChecklistPanel items={incident.checklist} currentState={incident.state} />
              </TabsContent>
              <TabsContent value="timeline" className="mt-0">
                <TimelinePanel events={incident.timeline} />
              </TabsContent>
              <TabsContent value="findings" className="mt-0">
                <FindingsPanel findings={incident.findings} />
              </TabsContent>
            </div>
          </ScrollArea>
        </Tabs>
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Incident list row
// ═══════════════════════════════════════════════════════════

function IncidentRow({
  incident,
  isSelected,
  onClick,
}: {
  incident: Incident;
  isSelected: boolean;
  onClick: () => void;
}) {
  const TypeIcon = TYPE_META[incident.type].icon;
  const progress = incident.checklist.filter((c) => c.done).length / Math.max(incident.checklist.length, 1);

  return (
    <motion.button
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={onClick}
      className={cn(
        "w-full text-left p-4 rounded-lg border transition-all duration-150 group",
        isSelected
          ? "border-primary/40 bg-primary/5"
          : "border-border/60 bg-card hover:border-border hover:bg-muted/10"
      )}
    >
      <div className="flex items-start gap-3">
        <div className={cn(
          "h-8 w-8 rounded-md flex items-center justify-center shrink-0 mt-0.5 border",
          isSelected ? "bg-primary/10 border-primary/30" : "bg-muted/20 border-border"
        )}>
          <TypeIcon className="h-3.5 w-3.5 text-muted-foreground" />
        </div>

        <div className="flex-1 min-w-0 space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-mono text-muted-foreground/60">{incident.id}</span>
            <SeverityBadge severity={incident.severity} />
            <StateBadge state={incident.state} />
          </div>
          <p className="text-sm font-medium leading-snug group-hover:text-primary transition-colors line-clamp-2">
            {incident.title}
          </p>
          <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
            <div className="flex items-center gap-1">
              <User className="h-2.5 w-2.5" />
              {incident.owner}
            </div>
            <div className="flex items-center gap-1">
              <Clock className="h-2.5 w-2.5" />
              <TimeAgo date={incident.detectedAt} />
            </div>
            <SLABadge sla_breach_at={incident.sla_breach_at} />
          </div>

          {/* Progress bar */}
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1 rounded-full bg-muted/30 overflow-hidden">
              <motion.div
                className="h-full bg-emerald-500/60 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${progress * 100}%` }}
                transition={{ duration: 0.6, ease: "easeOut" }}
              />
            </div>
            <span className="text-[10px] text-muted-foreground/60 tabular-nums shrink-0">
              {incident.checklist.filter((c) => c.done).length}/{incident.checklist.length}
            </span>
          </div>
        </div>

        <ChevronRight className={cn(
          "h-4 w-4 shrink-0 mt-1 transition-all duration-150",
          isSelected ? "text-primary rotate-90" : "text-muted-foreground/30 group-hover:text-muted-foreground"
        )} />
      </div>
    </motion.button>
  );
}

// ═══════════════════════════════════════════════════════════
// Main page
// ═══════════════════════════════════════════════════════════

export default function IncidentResponse() {
  const [selectedId, setSelectedId] = useState<string | null>(MOCK_INCIDENTS[0].id);
  const [search, setSearch] = useState("");
  const [filterState, setFilterState] = useState<IRState | "ALL">("ALL");
  const [filterSeverity, setFilterSeverity] = useState<Severity | "ALL">("ALL");

  const selectedIncident = useMemo(
    () => MOCK_INCIDENTS.find((i) => i.id === selectedId) ?? null,
    [selectedId]
  );

  const filtered = useMemo(() => {
    return MOCK_INCIDENTS.filter((inc) => {
      if (filterState !== "ALL" && inc.state !== filterState) return false;
      if (filterSeverity !== "ALL" && inc.severity !== filterSeverity) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          inc.title.toLowerCase().includes(q) ||
          inc.id.toLowerCase().includes(q) ||
          inc.summary.toLowerCase().includes(q) ||
          inc.tags.some((t) => t.includes(q))
        );
      }
      return true;
    });
  }, [search, filterState, filterSeverity]);

  // KPI counts
  const kpis = useMemo(() => ({
    active: MOCK_INCIDENTS.filter((i) => i.state !== "CLOSED").length,
    critical: MOCK_INCIDENTS.filter((i) => i.severity === "critical" && i.state !== "CLOSED").length,
    slaBreached: MOCK_INCIDENTS.filter((i) => i.sla_breach_at.getTime() < now.getTime() && i.state !== "CLOSED").length,
    avgMttr: Math.round(
      MOCK_INCIDENTS.filter((i) => i.state === "CLOSED").reduce((acc, i) => acc + i.mttr_est_hours, 0) /
        Math.max(MOCK_INCIDENTS.filter((i) => i.state === "CLOSED").length, 1)
    ),
  }), []);

  return (
    <TooltipProvider>
      <div className="flex flex-col h-full min-h-0 p-6 gap-6">
        {/* Page header */}
        <PageHeader
          title="Incident Response"
          description="Active security incidents — detection to closure. State machine lifecycle, evidence chain, and team coordination."
          badge="IR"
          actions={
            <Button size="sm" className="gap-1.5">
              <Plus className="h-3.5 w-3.5" />
              Declare Incident
            </Button>
          }
        />

        {/* KPIs */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 shrink-0">
          <KpiCard
            title="Active Incidents"
            value={kpis.active}
            icon={Siren}
            trend="down"
            trendLabel="vs last week"
            description="Open across all phases"
          />
          <KpiCard
            title="Critical Open"
            value={kpis.critical}
            icon={ShieldAlert}
            trend={kpis.critical > 2 ? "down" : "flat"}
            description="Requiring immediate action"
          />
          <KpiCard
            title="SLA Breached"
            value={kpis.slaBreached}
            icon={AlertTriangle}
            trend="flat"
            description="Resolution time exceeded"
          />
          <KpiCard
            title="Avg MTTR"
            value={`${kpis.avgMttr}h`}
            icon={Clock}
            trend="up"
            trendLabel="vs baseline"
            description="Mean time to resolve (closed)"
          />
        </div>

        {/* Main split layout */}
        <div className="flex gap-4 flex-1 min-h-0">
          {/* Left: incident list */}
          <div className={cn(
            "flex flex-col gap-3 transition-all duration-300",
            selectedIncident ? "w-[42%] shrink-0" : "flex-1"
          )}>
            {/* Filters */}
            <div className="flex items-center gap-2 shrink-0">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search incidents..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8 h-8 text-xs"
                />
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                {(["ALL", "DETECTED", "TRIAGING", "CONTAINING", "ERADICATING", "RECOVERING"] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setFilterState(s)}
                    className={cn(
                      "px-2 py-1 rounded text-[10px] font-semibold uppercase tracking-wider border transition-colors",
                      filterState === s
                        ? "bg-primary/15 border-primary/40 text-primary"
                        : "border-border/50 text-muted-foreground/60 hover:border-border hover:text-muted-foreground"
                    )}
                  >
                    {s === "ALL" ? "All" : STATE_META[s].label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-1.5 shrink-0">
              <Filter className="h-3 w-3 text-muted-foreground" />
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Severity:</span>
              {(["ALL", "critical", "high", "medium", "low"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setFilterSeverity(s)}
                  className={cn(
                    "px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border transition-colors",
                    filterSeverity === s
                      ? "bg-primary/15 border-primary/40 text-primary"
                      : "border-border/50 text-muted-foreground/50 hover:border-border"
                  )}
                >
                  {s}
                </button>
              ))}
              <span className="ml-auto text-[10px] text-muted-foreground/50">
                {filtered.length} of {MOCK_INCIDENTS.length}
              </span>
            </div>

            {/* List */}
            <ScrollArea className="flex-1">
              <div className="space-y-2 pr-2">
                <AnimatePresence mode="popLayout">
                  {filtered.length === 0 ? (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="flex flex-col items-center justify-center py-16 text-muted-foreground/40"
                    >
                      <ShieldAlert className="h-10 w-10 mb-3" />
                      <p className="text-sm">No incidents match filters</p>
                    </motion.div>
                  ) : (
                    filtered.map((inc) => (
                      <IncidentRow
                        key={inc.id}
                        incident={inc}
                        isSelected={selectedId === inc.id}
                        onClick={() => setSelectedId(selectedId === inc.id ? null : inc.id)}
                      />
                    ))}
                  </AnimatePresence>
              </div>
            </ScrollArea>
          </div>

          {/* Right: detail panel */}
          <AnimatePresence>
            {selectedIncident && (
              <motion.div
                key={selectedIncident.id}
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: "auto" }}
                exit={{ opacity: 0, width: 0 }}
                className="flex-1 min-w-0 overflow-hidden"
              >
                <Card className="h-full overflow-hidden flex flex-col">
                  <IncidentDetail
                    incident={selectedIncident}
                    onClose={() => setSelectedId(null)}
                  />
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </TooltipProvider>
  );
}
