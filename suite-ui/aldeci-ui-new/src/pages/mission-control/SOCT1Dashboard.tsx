/**
 * SOC Tier-1 Alert Triage Dashboard — P03 "The Hunter"
 *
 * Three-panel layout built for wall displays and analyst workstations:
 *   [Alert Queue] | [LLM Council Verdicts Panel] + [Detail Drawer]
 *
 * Differentiates from SOCDashboard (/mission-control/soc) by:
 *   - Persistent side panel showing full LLM Council breakdown for selected alert
 *   - Right-side detail drawer (not dialog) with timeline, CVEs, quick actions
 *   - Four specific KPIs: open count+trend, MTTT, FP rate 30d, LLM accuracy
 *   - One-click triage: Accept LLM verdict or Override
 *   - API-backed via GET /api/v1/incidents with mock fallback
 *
 * Route: /mission-control/soc-t1
 */

import { useState, useMemo, useEffect, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, AlertTriangle, Clock, CheckCircle2, XCircle,
  ChevronUp, ChevronDown, Search, RefreshCw,
  ArrowUpRight, Flame, Eye, Terminal, Server, Package, Cloud,
  Bug, Code, KeyRound, Container, SlidersHorizontal,
  CircleCheck, Ban, Activity, Timer, TrendingUp, TrendingDown,
  Minus, ChevronRight, X, Ticket, UserPlus, Lock,
  Zap, ShieldAlert, Brain, BarChart3, Crosshair,
  ExternalLink, GitBranch, FileText, Network, ChevronsRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "";

// ═══════════════════════════════════════════════════════════
// Types — matches GET /api/v1/incidents response shape
// ═══════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low";
type TriageVerdict = "ESCALATE" | "INVESTIGATE" | "FALSE_POSITIVE";
type ModelVerdict = "BLOCK" | "REVIEW" | "ALLOW";
type AlertStatus = "new" | "in_progress" | "resolved" | "false_positive";

interface CouncilVote {
  model: string;      // "Qwen 3.6+", "Kimi K2", "Gemma 4", "Opus"
  verdict: ModelVerdict;
  confidence: number; // 0–100
  reasoning: string;
}

interface TimelineEvent {
  ts: Date;
  actor: string;
  action: string;
  type: "detection" | "action" | "escalation" | "update";
}

interface RelatedCve {
  id: string;
  cvss: number;
  description: string;
}

interface Alert {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  source: string;
  triage_verdict: TriageVerdict;   // recommended action
  council_votes: CouncilVote[];    // 4 model votes
  agreement_pct: number;           // 0–100 consensus meter
  cvss: number;
  cve?: string;
  discovered_at: Date;
  status: AlertStatus;
  assignee?: string;
  asset: string;
  asset_type: "container" | "code" | "cloud" | "secrets" | "iac" | "package";
  affected_assets: string[];
  related_cves: RelatedCve[];
  timeline: TimelineEvent[];
  tags: string[];
  remediation_hint?: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data — realistic SOC T1 queue
// ═══════════════════════════════════════════════════════════

const now = new Date();
const minsAgo = (m: number) => new Date(now.getTime() - m * 60_000);
const hoursAgo = (h: number) => new Date(now.getTime() - h * 3_600_000);
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000);

const MOCK_ALERTS: Alert[] = [
  {
    id: "INC-0041",
    severity: "critical",
    title: "CVE-2024-3094: XZ Utils Backdoor in Production Image",
    description:
      "liblzma.so in aldeci-api:v2.3.1 matches the XZ Utils backdoor signature (CVE-2024-3094). Systemd-linked hosts at immediate RCE risk. All 4 models unanimous.",
    source: "Trivy",
    triage_verdict: "ESCALATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "BLOCK", confidence: 99, reasoning: "Backdoor signature confirmed. Critical supply chain compromise. Immediate isolation required." },
      { model: "Kimi K2",   verdict: "BLOCK", confidence: 98, reasoning: "CVE-2024-3094 CVSS 10.0. RCE via systemd authentication bypass confirmed in this version." },
      { model: "Gemma 4",   verdict: "BLOCK", confidence: 97, reasoning: "Hash match on liblzma.so payload. Production container must be pulled immediately." },
      { model: "Opus",      verdict: "BLOCK", confidence: 99, reasoning: "Consensus: escalate to T2/IR. Invoke incident response playbook for supply chain compromise." },
    ],
    agreement_pct: 99,
    cvss: 10.0,
    cve: "CVE-2024-3094",
    discovered_at: minsAgo(8),
    status: "new",
    asset: "aldeci-api:v2.3.1",
    asset_type: "container",
    affected_assets: ["aldeci-api:v2.3.1", "aldeci-worker:v2.3.1", "k8s/prod/api-deployment.yaml"],
    related_cves: [
      { id: "CVE-2024-3094", cvss: 10.0, description: "XZ Utils backdoor — remote code execution via systemd" },
      { id: "CVE-2023-44487", cvss: 7.5, description: "HTTP/2 Rapid Reset DDoS amplification" },
    ],
    timeline: [
      { ts: minsAgo(8), actor: "Trivy", action: "Backdoor signature detected in container scan", type: "detection" },
      { ts: minsAgo(7), actor: "LLM Council", action: "4/4 models returned BLOCK verdict", type: "action" },
      { ts: minsAgo(6), actor: "System", action: "Alert created — awaiting T1 triage", type: "update" },
    ],
    tags: ["supply-chain", "rce", "container", "cve-critical"],
    remediation_hint: "1. kubectl rollout undo deployment/aldeci-api  2. Rebuild from debian:bookworm-slim  3. Remove xz-utils 5.6.0–5.6.1  4. Rotate all secrets in affected containers",
  },
  {
    id: "INC-0040",
    severity: "critical",
    title: "Hardcoded AWS Credentials in Production Dockerfile",
    description:
      "AWS_SECRET_ACCESS_KEY found in plaintext in services/api/Dockerfile:L47. Key is active with s3:*, ec2:* permissions. Immediate rotation required.",
    source: "Semgrep",
    triage_verdict: "ESCALATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "BLOCK", confidence: 100, reasoning: "Active IAM key with broad permissions in VCS. Treat as compromised immediately." },
      { model: "Kimi K2",   verdict: "BLOCK", confidence: 99,  reasoning: "Key validated via AWS STS — active. OWASP A02 credential exposure." },
      { model: "Gemma 4",   verdict: "BLOCK", confidence: 99,  reasoning: "Git history shows key committed 3 days ago. Assume exposure window." },
      { model: "Opus",      verdict: "BLOCK", confidence: 98,  reasoning: "Rotate immediately, revoke, audit CloudTrail for 72h usage, remove from git history." },
    ],
    agreement_pct: 99,
    cvss: 9.8,
    discovered_at: minsAgo(23),
    status: "in_progress",
    assignee: "jsmith",
    asset: "services/api/Dockerfile",
    asset_type: "secrets",
    affected_assets: ["services/api/Dockerfile", "s3://aldeci-prod-data", "ec2/prod-cluster"],
    related_cves: [],
    timeline: [
      { ts: minsAgo(23), actor: "Semgrep", action: "AWS credential pattern matched at Dockerfile:L47", type: "detection" },
      { ts: minsAgo(21), actor: "LLM Council", action: "Unanimous BLOCK — credential validated active", type: "action" },
      { ts: minsAgo(15), actor: "jsmith", action: "Assigned — key rotation in progress", type: "update" },
    ],
    tags: ["secrets", "iam", "aws", "owasp-a02"],
    remediation_hint: "1. aws iam delete-access-key  2. git-secrets / BFG to purge history  3. Migrate to AWS Secrets Manager  4. Audit CloudTrail for 72h",
  },
  {
    id: "INC-0039",
    severity: "critical",
    title: "SQL Injection via Unsanitized ORM Filter in Findings API",
    description:
      "User-controlled input passed directly to SQLAlchemy filter() in /api/v1/findings. Confirmed exploitable via blind UNION injection. No authentication required.",
    source: "Semgrep",
    triage_verdict: "ESCALATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "BLOCK", confidence: 97, reasoning: "SQLi confirmed exploitable. Unauthenticated endpoint. Data exfil risk is severe." },
      { model: "Kimi K2",   verdict: "BLOCK", confidence: 96, reasoning: "UNION injection bypasses ORM protections. CVSS AV:N/AC:L — remote, no auth." },
      { model: "Gemma 4",   verdict: "REVIEW", confidence: 72, reasoning: "Exploit confirmed but impact scope unclear. Needs WAF analysis before blocking." },
      { model: "Opus",      verdict: "BLOCK", confidence: 94, reasoning: "3/4 BLOCK. Escalate. Apply parameterized queries, rate-limit endpoint immediately." },
    ],
    agreement_pct: 90,
    cvss: 9.1,
    discovered_at: minsAgo(47),
    status: "new",
    asset: "suite-api/routers/findings_router.py",
    asset_type: "code",
    affected_assets: ["suite-api/routers/findings_router.py", "GET /api/v1/findings"],
    related_cves: [{ id: "CWE-89", cvss: 9.1, description: "SQL Injection via ORM filter bypass" }],
    timeline: [
      { ts: minsAgo(47), actor: "Semgrep", action: "SQLi pattern matched — findings_router.py:L203", type: "detection" },
      { ts: minsAgo(45), actor: "LLM Council", action: "3/4 BLOCK, 1 REVIEW — high consensus", type: "action" },
      { ts: minsAgo(44), actor: "System", action: "Alert queued for T1 triage", type: "update" },
    ],
    tags: ["injection", "api", "owasp-a03", "sqli"],
    remediation_hint: "Use SQLAlchemy bindparam() for all user inputs. Add WAF rule blocking UNION keywords on /api/v1/findings.",
  },
  {
    id: "INC-0038",
    severity: "high",
    title: "Unauthenticated Prometheus Metrics Endpoint Exposed",
    description:
      "Node exporter metrics on port 9100 accessible without auth. Leaks internal hostnames, service topology, resource usage. External reachability confirmed.",
    source: "Trivy",
    triage_verdict: "INVESTIGATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "BLOCK", confidence: 91, reasoning: "External exposure of internal topology. Reconnaissance risk. Close immediately." },
      { model: "Kimi K2",   verdict: "BLOCK", confidence: 89, reasoning: "Prometheus metrics reveal service mesh layout. Useful for lateral movement planning." },
      { model: "Gemma 4",   verdict: "BLOCK", confidence: 85, reasoning: "Port 9100 has no auth. NetworkPolicy needed to restrict to monitoring namespace." },
      { model: "Opus",      verdict: "REVIEW", confidence: 78, reasoning: "Confirm external reachability before escalating. May be internal-only depending on VPC config." },
    ],
    agreement_pct: 88,
    cvss: 7.5,
    discovered_at: hoursAgo(2),
    status: "new",
    asset: "k8s/monitoring/prometheus-node-exporter.yaml",
    asset_type: "iac",
    affected_assets: ["k8s/monitoring/prometheus-node-exporter.yaml", "node:9100/metrics"],
    related_cves: [],
    timeline: [
      { ts: hoursAgo(2), actor: "Trivy", action: "Open port 9100 without auth policy detected", type: "detection" },
      { ts: hoursAgo(2), actor: "LLM Council", action: "3/4 BLOCK, 1 REVIEW — investigate exposure scope", type: "action" },
    ],
    tags: ["exposure", "kubernetes", "monitoring", "reconnaissance"],
    remediation_hint: "Add NetworkPolicy restricting port 9100 to monitoring namespace. Add basic auth to Prometheus node exporter.",
  },
  {
    id: "INC-0037",
    severity: "high",
    title: "CVE-2024-21762: Fortinet FortiOS RCE in Dependency Chain",
    description:
      "fortios-sdk-python 7.4.2 in requirements.txt triggers CVE-2024-21762 (out-of-bounds write). SDK wraps affected FortiOS management API endpoints.",
    source: "Snyk",
    triage_verdict: "INVESTIGATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "BLOCK", confidence: 85, reasoning: "CVSS 9.6, RCE via FortiOS API. SDK transitive risk if management endpoints reachable." },
      { model: "Kimi K2",   verdict: "REVIEW", confidence: 80, reasoning: "Exploitability depends on FortiOS endpoint exposure. Upgrade path available — investigate first." },
      { model: "Gemma 4",   verdict: "REVIEW", confidence: 79, reasoning: "SDK usage in prod unclear. If management endpoints internal-only, risk is lower." },
      { model: "Opus",      verdict: "REVIEW", confidence: 82, reasoning: "Mixed verdict. Investigate FortiOS endpoint exposure before escalating. Upgrade available." },
    ],
    agreement_pct: 79,
    cvss: 9.6,
    cve: "CVE-2024-21762",
    discovered_at: hoursAgo(3),
    status: "in_progress",
    assignee: "mchen",
    asset: "requirements.txt → fortios-sdk-python 7.4.2",
    asset_type: "package",
    affected_assets: ["requirements.txt", "suite-core/connectors/fortinet_connector.py"],
    related_cves: [{ id: "CVE-2024-21762", cvss: 9.6, description: "Fortinet FortiOS out-of-bounds write — RCE via management API" }],
    timeline: [
      { ts: hoursAgo(3), actor: "Snyk", action: "CVE-2024-21762 matched in requirements.txt", type: "detection" },
      { ts: hoursAgo(3), actor: "LLM Council", action: "Split verdict: 1 BLOCK, 3 REVIEW — investigate exposure", type: "action" },
      { ts: hoursAgo(2), actor: "mchen", action: "Investigating FortiOS endpoint exposure scope", type: "update" },
    ],
    tags: ["cve", "supply-chain", "rce", "fortinet"],
    remediation_hint: "Upgrade fortios-sdk-python to >=7.4.3. Verify FortiOS management endpoints are not externally reachable.",
  },
  {
    id: "INC-0036",
    severity: "high",
    title: "S3 Bucket with Public Read ACL — Production Exports",
    description:
      "s3://aldeci-prod-exports has AllUsers READ permission. Contains CSV exports of finding data potentially including PII. 14 GB exposed.",
    source: "Prowler",
    triage_verdict: "ESCALATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "BLOCK", confidence: 96, reasoning: "Public S3 with PII exports. GDPR Article 32 violation. Must restrict immediately." },
      { model: "Kimi K2",   verdict: "BLOCK", confidence: 94, reasoning: "14 GB findings data publicly readable. Regulatory exposure is severe." },
      { model: "Gemma 4",   verdict: "BLOCK", confidence: 93, reasoning: "S3 Block Public Access not enabled at account level. All buckets at risk." },
      { model: "Opus",      verdict: "BLOCK", confidence: 92, reasoning: "Unanimous. Enable S3 BPA account-wide. Audit all buckets. Notify DPO." },
    ],
    agreement_pct: 94,
    cvss: 7.2,
    discovered_at: hoursAgo(5),
    status: "new",
    asset: "s3://aldeci-prod-exports",
    asset_type: "cloud",
    affected_assets: ["s3://aldeci-prod-exports", "s3://aldeci-prod-backups"],
    related_cves: [],
    timeline: [
      { ts: hoursAgo(5), actor: "Prowler", action: "Public ACL detected on aldeci-prod-exports", type: "detection" },
      { ts: hoursAgo(5), actor: "LLM Council", action: "4/4 BLOCK — regulatory exposure confirmed", type: "action" },
    ],
    tags: ["s3", "public-exposure", "gdpr", "pii"],
    remediation_hint: "1. aws s3api put-bucket-acl --acl private  2. aws s3control put-public-access-block (account-level)  3. Notify DPO of potential breach window",
  },
  {
    id: "INC-0035",
    severity: "high",
    title: "Dependency Confusion: 'aldeci-core' Squatted on PyPI",
    description:
      "Package 'aldeci-core' registered on public PyPI by unknown third party. Internal package with same name in private registry. Dependency confusion attack vector.",
    source: "Snyk",
    triage_verdict: "INVESTIGATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "REVIEW", confidence: 80, reasoning: "Name squatting confirmed. Investigate if any CI/CD pipelines pull from public PyPI first." },
      { model: "Kimi K2",   verdict: "BLOCK", confidence: 82, reasoning: "If CI uses default pip index, malicious package could be installed. Block public package." },
      { model: "Gemma 4",   verdict: "REVIEW", confidence: 72, reasoning: "Risk depends on pip index-url configuration in all build environments." },
      { model: "Opus",      verdict: "ALLOW", confidence: 55, reasoning: "Low confidence. Needs investigation of pip config before escalating. May be harmless." },
    ],
    agreement_pct: 72,
    cvss: 8.1,
    discovered_at: hoursAgo(7),
    status: "new",
    asset: "pypi://aldeci-core",
    asset_type: "package",
    affected_assets: ["pypi://aldeci-core", "requirements.txt", ".github/workflows/ci.yml"],
    related_cves: [],
    timeline: [
      { ts: hoursAgo(7), actor: "Snyk", action: "Public PyPI name collision with internal package", type: "detection" },
      { ts: hoursAgo(7), actor: "LLM Council", action: "Split verdict: 1 BLOCK, 2 REVIEW, 1 ALLOW — investigate", type: "action" },
    ],
    tags: ["supply-chain", "dependency-confusion", "pypi"],
    remediation_hint: "1. Claim aldeci-core on PyPI immediately  2. Set --index-url to private registry in all pip calls  3. Audit CI/CD pip configuration",
  },
  {
    id: "INC-0034",
    severity: "medium",
    title: "Missing HSTS Header on Public API Gateway",
    description:
      "api.aldeci.internal does not send Strict-Transport-Security header. Allows TLS downgrade attacks on connections from non-HSTS clients.",
    source: "Semgrep",
    triage_verdict: "INVESTIGATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "REVIEW", confidence: 75, reasoning: "Missing HSTS is a real risk but medium severity. Apply header, no urgent escalation needed." },
      { model: "Kimi K2",   verdict: "REVIEW", confidence: 70, reasoning: "OWASP A05. Fix in next sprint. No active exploit detected." },
      { model: "Gemma 4",   verdict: "ALLOW", confidence: 60, reasoning: "Internal API with TLS already. HSTS adds defence-in-depth but not urgent." },
      { model: "Opus",      verdict: "REVIEW", confidence: 68, reasoning: "Apply HSTS header in middleware. Medium priority. Tag for next sprint." },
    ],
    agreement_pct: 68,
    cvss: 5.3,
    discovered_at: hoursAgo(12),
    status: "in_progress",
    assignee: "agarcia",
    asset: "suite-api/middleware/security_headers.py",
    asset_type: "code",
    affected_assets: ["suite-api/middleware/security_headers.py"],
    related_cves: [],
    timeline: [
      { ts: hoursAgo(12), actor: "Semgrep", action: "Missing HSTS header detected in middleware scan", type: "detection" },
      { ts: hoursAgo(12), actor: "LLM Council", action: "2 REVIEW, 1 ALLOW, 1 REVIEW — low urgency", type: "action" },
      { ts: hoursAgo(6),  actor: "agarcia",    action: "PR raised — adding HSTS middleware", type: "update" },
    ],
    tags: ["tls", "headers", "owasp-a05"],
    remediation_hint: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to FastAPI middleware.",
  },
  {
    id: "INC-0033",
    severity: "medium",
    title: "Terraform State in Unencrypted S3 — Contains Secrets",
    description:
      "terraform.tfstate in s3://aldeci-infra-state without SSE-KMS. File contains IAM keys, RDS passwords, and Vault tokens in plaintext.",
    source: "Checkov",
    triage_verdict: "INVESTIGATE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "REVIEW", confidence: 72, reasoning: "Unencrypted state with credentials. Enable SSE-KMS and restrict bucket access." },
      { model: "Kimi K2",   verdict: "REVIEW", confidence: 68, reasoning: "Terraform state exposure is a known risk pattern. Encrypt and restrict." },
      { model: "Gemma 4",   verdict: "REVIEW", confidence: 65, reasoning: "Medium severity. Rotate secrets in state file and enable encryption." },
      { model: "Opus",      verdict: "ALLOW", confidence: 58, reasoning: "If bucket is private and access-logged, current risk is manageable. But encrypt regardless." },
    ],
    agreement_pct: 66,
    cvss: 6.1,
    discovered_at: hoursAgo(18),
    status: "new",
    asset: "s3://aldeci-infra-state/terraform.tfstate",
    asset_type: "iac",
    affected_assets: ["s3://aldeci-infra-state/terraform.tfstate", "infra/terraform/backend.tf"],
    related_cves: [],
    timeline: [
      { ts: hoursAgo(18), actor: "Checkov", action: "Unencrypted S3 backend detected for Terraform state", type: "detection" },
      { ts: hoursAgo(18), actor: "LLM Council", action: "3 REVIEW, 1 ALLOW — medium urgency", type: "action" },
    ],
    tags: ["iac", "terraform", "secrets-exposure", "s3"],
    remediation_hint: "1. Enable SSE-KMS on aldeci-infra-state bucket  2. Restrict bucket policy to CI/CD role only  3. Rotate all credentials present in state",
  },
  {
    id: "INC-0031",
    severity: "low",
    title: "Outdated OpenSSL in Alpine Base (3.1.4 → 3.3.1)",
    description:
      "Alpine 3.18 container uses OpenSSL 3.1.4. Latest stable is 3.3.1. No active critical CVEs but hygiene issue creates drift from hardened baseline.",
    source: "Trivy",
    triage_verdict: "FALSE_POSITIVE",
    council_votes: [
      { model: "Qwen 3.6+", verdict: "ALLOW", confidence: 90, reasoning: "No critical CVEs in 3.1.4. Update in next scheduled maintenance window." },
      { model: "Kimi K2",   verdict: "ALLOW", confidence: 88, reasoning: "Version drift is hygiene issue only. Schedule upgrade, not urgent." },
      { model: "Gemma 4",   verdict: "ALLOW", confidence: 87, reasoning: "Agree — maintenance-level item. Mark for next container rebuild cycle." },
      { model: "Opus",      verdict: "REVIEW", confidence: 55, reasoning: "Track in backlog. If any CVE published for 3.1.x, re-triage immediately." },
    ],
    agreement_pct: 89,
    cvss: 3.1,
    discovered_at: daysAgo(2),
    status: "resolved",
    assignee: "mchen",
    asset: "docker/base/Dockerfile",
    asset_type: "container",
    affected_assets: ["docker/base/Dockerfile"],
    related_cves: [],
    timeline: [
      { ts: daysAgo(2), actor: "Trivy", action: "OpenSSL version drift detected — 3.1.4 vs 3.3.1", type: "detection" },
      { ts: daysAgo(2), actor: "LLM Council", action: "3 ALLOW, 1 REVIEW — low priority", type: "action" },
      { ts: daysAgo(1), actor: "mchen",      action: "Scheduled for next container rebuild cycle", type: "update" },
    ],
    tags: ["dependency-update", "openssl", "hygiene"],
    remediation_hint: "Update FROM alpine:3.18 to alpine:3.20 in docker/base/Dockerfile. Rebuild and push.",
  },
];

// ═══════════════════════════════════════════════════════════
// Utility helpers
// ═══════════════════════════════════════════════════════════

function formatAge(date: Date): string {
  const diffMs = Date.now() - date.getTime();
  const mins = Math.floor(diffMs / 60_000);
  const hours = Math.floor(mins / 60);
  const days = Math.floor(hours / 24);
  if (days > 0) return `${days}d`;
  if (hours > 0) return `${hours}h`;
  return `${mins}m`;
}

function formatTs(date: Date): string {
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const VERDICT_CONFIG: Record<TriageVerdict, { label: string; className: string; icon: React.ReactNode }> = {
  ESCALATE:      { label: "ESCALATE",      className: "bg-red-500/15 text-red-400 border-red-500/25 border",      icon: <ArrowUpRight className="h-2.5 w-2.5" /> },
  INVESTIGATE:   { label: "INVESTIGATE",   className: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25 border", icon: <Eye className="h-2.5 w-2.5" /> },
  FALSE_POSITIVE:{ label: "FALSE POS",     className: "bg-muted text-muted-foreground border border-border",       icon: <CircleCheck className="h-2.5 w-2.5" /> },
};

const MODEL_VERDICT_COLOR: Record<ModelVerdict, string> = {
  BLOCK:  "text-red-400",
  REVIEW: "text-yellow-400",
  ALLOW:  "text-green-400",
};

const MODEL_VERDICT_BAR: Record<ModelVerdict, string> = {
  BLOCK:  "bg-red-500",
  REVIEW: "bg-yellow-500",
  ALLOW:  "bg-green-500",
};

// ═══════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════

function SeverityBadge({ severity }: { severity: Severity }) {
  const configs: Record<Severity, { label: string; className: string; pulse?: boolean }> = {
    critical: { label: "CRIT",   className: "bg-red-500/20 text-red-400 border-red-500/30 border font-mono font-bold tracking-widest", pulse: true },
    high:     { label: "HIGH",   className: "bg-orange-500/20 text-orange-400 border-orange-500/30 border font-mono font-semibold tracking-wider" },
    medium:   { label: "MED",    className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30 border font-mono tracking-wide" },
    low:      { label: "LOW",    className: "bg-blue-500/20 text-blue-400 border-blue-500/30 border font-mono" },
  };
  const cfg = configs[severity];
  return (
    <span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px]", cfg.className)}>
      {cfg.pulse && (
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-red-500" />
        </span>
      )}
      {cfg.label}
    </span>
  );
}

function TriageVerdictChip({ verdict }: { verdict: TriageVerdict }) {
  const cfg = VERDICT_CONFIG[verdict];
  return (
    <span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold", cfg.className)}>
      {cfg.icon}
      {cfg.label}
    </span>
  );
}

function AssetIcon({ type }: { type: Alert["asset_type"] }) {
  const icons: Record<Alert["asset_type"], React.ReactNode> = {
    container: <Container className="h-3 w-3" />,
    code:      <Code className="h-3 w-3" />,
    cloud:     <Cloud className="h-3 w-3" />,
    secrets:   <KeyRound className="h-3 w-3" />,
    iac:       <Server className="h-3 w-3" />,
    package:   <Package className="h-3 w-3" />,
  };
  return <span className="text-muted-foreground shrink-0">{icons[type]}</span>;
}

function StatusBadge({ status }: { status: AlertStatus }) {
  const configs: Record<AlertStatus, { label: string; className: string }> = {
    new:           { label: "New",      className: "bg-blue-500/15 text-blue-400" },
    in_progress:   { label: "Active",   className: "bg-yellow-500/15 text-yellow-400" },
    resolved:      { label: "Resolved", className: "bg-green-500/15 text-green-400" },
    false_positive:{ label: "FP",       className: "bg-muted text-muted-foreground" },
  };
  const cfg = configs[status];
  return (
    <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium", cfg.className)}>
      {cfg.label}
    </span>
  );
}

function AgreementMeter({ pct, verdict }: { pct: number; verdict: TriageVerdict }) {
  const color =
    verdict === "ESCALATE" ? "bg-red-500" :
    verdict === "INVESTIGATE" ? "bg-yellow-500" :
    "bg-green-500";

  const textColor =
    verdict === "ESCALATE" ? "text-red-400" :
    verdict === "INVESTIGATE" ? "text-yellow-400" :
    "text-green-400";

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Consensus</span>
        <span className={cn("text-sm font-bold tabular-nums font-mono", textColor)}>{pct}%</span>
      </div>
      <div className="h-2 rounded-full bg-muted overflow-hidden">
        <motion.div
          className={cn("h-full rounded-full", color)}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        />
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// LLM Council Panel — persistent side panel
// ═══════════════════════════════════════════════════════════

function CouncilPanel({
  alert,
  onAccept,
  onOverride,
}: {
  alert: Alert | null;
  onAccept: (id: string) => void;
  onOverride: (id: string, v: TriageVerdict) => void;
}) {
  const [overrideOpen, setOverrideOpen] = useState(false);

  useEffect(() => { setOverrideOpen(false); }, [alert?.id]);

  if (!alert) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground py-16">
        <Brain className="h-10 w-10 opacity-20" />
        <p className="text-sm text-center leading-relaxed">
          Select an alert from the queue<br />to see the LLM Council verdict
        </p>
      </div>
    );
  }

  const { council_votes, triage_verdict, agreement_pct } = alert;

  const modelIconMap: Record<string, string> = {
    "Qwen 3.6+": "Q",
    "Kimi K2":   "K",
    "Gemma 4":   "G",
    "Opus":      "O",
  };

  const OTHER_VERDICTS: TriageVerdict[] = (["ESCALATE", "INVESTIGATE", "FALSE_POSITIVE"] as TriageVerdict[]).filter(
    (v) => v !== triage_verdict
  );

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 pt-4 pb-3 border-b border-border/60">
        <div className="flex items-center gap-2 mb-3">
          <div className="rounded-md bg-primary/10 p-1.5">
            <Brain className="h-4 w-4 text-primary" />
          </div>
          <div>
            <p className="text-xs font-semibold tracking-wide">LLM Council</p>
            <p className="text-[10px] text-muted-foreground font-mono">{alert.id}</p>
          </div>
        </div>

        {/* Consensus verdict */}
        <div className="rounded-lg border border-border/60 bg-card p-3 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Recommended Action</span>
            <TriageVerdictChip verdict={triage_verdict} />
          </div>
          <AgreementMeter pct={agreement_pct} verdict={triage_verdict} />
        </div>
      </div>

      {/* Per-model votes */}
      <ScrollArea className="flex-1 min-h-0">
        <div className="px-4 py-3 space-y-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
            Model Votes — {council_votes.length} models
          </p>
          {council_votes.map((vote) => (
            <motion.div
              key={vote.model}
              initial={{ opacity: 0, x: 8 }}
              animate={{ opacity: 1, x: 0 }}
              className="rounded-lg border border-border/60 bg-card p-3 space-y-2"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "flex h-6 w-6 items-center justify-center rounded-md text-[10px] font-bold font-mono shrink-0",
                      vote.verdict === "BLOCK"  ? "bg-red-500/15 text-red-400" :
                      vote.verdict === "REVIEW" ? "bg-yellow-500/15 text-yellow-400" :
                                                  "bg-green-500/15 text-green-400"
                    )}
                  >
                    {modelIconMap[vote.model] ?? vote.model[0]}
                  </span>
                  <span className="text-xs font-medium">{vote.model}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className={cn("text-[10px] font-mono font-bold", MODEL_VERDICT_COLOR[vote.verdict])}>
                    {vote.verdict}
                  </span>
                  <span className="text-[10px] text-muted-foreground tabular-nums">{vote.confidence}%</span>
                </div>
              </div>

              {/* Confidence bar */}
              <div className="h-1 rounded-full bg-muted overflow-hidden">
                <motion.div
                  className={cn("h-full rounded-full", MODEL_VERDICT_BAR[vote.verdict])}
                  initial={{ width: 0 }}
                  animate={{ width: `${vote.confidence}%` }}
                  transition={{ duration: 0.5, ease: "easeOut" }}
                />
              </div>

              {/* Reasoning */}
              <p className="text-[10px] text-muted-foreground leading-relaxed line-clamp-3">
                {vote.reasoning}
              </p>
            </motion.div>
          ))}
        </div>
      </ScrollArea>

      {/* Triage actions */}
      <div className="px-4 pb-4 pt-3 border-t border-border/60 space-y-2">
        <Button
          className="w-full h-8 text-xs gap-1.5"
          size="sm"
          onClick={() => onAccept(alert.id)}
        >
          <CheckCircle2 className="h-3.5 w-3.5" />
          Accept — {VERDICT_CONFIG[triage_verdict].label}
        </Button>

        <div className="relative">
          <Button
            variant="outline"
            className="w-full h-8 text-xs gap-1.5"
            size="sm"
            onClick={() => setOverrideOpen((o) => !o)}
          >
            <Zap className="h-3.5 w-3.5" />
            Override Verdict
            <ChevronDown className={cn("h-3 w-3 ml-auto transition-transform", overrideOpen && "rotate-180")} />
          </Button>

          <AnimatePresence>
            {overrideOpen && (
              <motion.div
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                className="absolute bottom-full mb-1 left-0 right-0 rounded-md border border-border bg-popover shadow-lg z-10 overflow-hidden"
              >
                {OTHER_VERDICTS.map((v) => (
                  <button
                    key={v}
                    className="w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-muted/60 transition-colors text-left"
                    onClick={() => { onOverride(alert.id, v); setOverrideOpen(false); }}
                  >
                    <span>{VERDICT_CONFIG[v].icon}</span>
                    <span>{VERDICT_CONFIG[v].label}</span>
                  </button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Alert Detail Drawer — slides in from right
// ═══════════════════════════════════════════════════════════

function AlertDetailDrawer({
  alert,
  onClose,
  onAccept,
  onOverride,
}: {
  alert: Alert | null;
  onClose: () => void;
  onAccept: (id: string) => void;
  onOverride: (id: string, v: TriageVerdict) => void;
}) {
  const overlayRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <AnimatePresence>
      {alert && (
        <>
          {/* Backdrop */}
          <motion.div
            ref={overlayRef}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[1px]"
            onClick={onClose}
          />

          {/* Drawer */}
          <motion.aside
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", stiffness: 380, damping: 38 }}
            className="fixed top-0 right-0 z-50 h-full w-full max-w-xl bg-background border-l border-border shadow-2xl flex flex-col"
            aria-title="Alert detail"
            role="dialog"
          >
            {/* Drawer header */}
            <div className="flex items-start gap-3 px-5 pt-5 pb-4 border-b border-border/60 shrink-0">
              <div className="flex-1 min-w-0 space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <SeverityBadge severity={alert.severity} />
                  <span className="font-mono text-[10px] text-muted-foreground">{alert.id}</span>
                  <StatusBadge status={alert.status} />
                </div>
                <h2 className="text-sm font-semibold leading-snug">{alert.title}</h2>
              </div>
              <button
                onClick={onClose}
                className="shrink-0 rounded-md p-1.5 hover:bg-muted/60 transition-colors"
                aria-title="Close drawer"
              >
                <X className="h-4 w-4 text-muted-foreground" />
              </button>
            </div>

            <ScrollArea className="flex-1 min-h-0">
              <div className="px-5 py-4 space-y-5">
                {/* Quick metrics */}
                <div className="grid grid-cols-3 gap-2.5">
                  {[
                    { label: "CVSS", value: alert.cvss.toFixed(1) },
                    { label: "Age",  value: formatAge(alert.discovered_at) },
                    { label: "Source", value: alert.source },
                  ].map(({ label, value }) => (
                    <div key={label} className="rounded-lg bg-muted/40 p-3 space-y-1">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
                      <p className="text-lg font-bold tabular-nums font-mono leading-none">{value}</p>
                    </div>
                  ))}
                </div>

                {/* Description */}
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Description</p>
                  <p className="text-xs text-foreground leading-relaxed">{alert.description}</p>
                </div>

                <Separator />

                {/* Affected assets */}
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                    Affected Assets ({alert.affected_assets.length})
                  </p>
                  <div className="space-y-1.5">
                    {alert.affected_assets.map((a) => (
                      <div key={a} className="flex items-center gap-2 rounded-md bg-muted/40 px-2.5 py-1.5">
                        <AssetIcon type={alert.asset_type} />
                        <code className="text-[10px] font-mono text-foreground break-all">{a}</code>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Related CVEs from TrustGraph */}
                {alert.related_cves.length > 0 && (
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                        Related CVEs — TrustGraph
                      </p>
                      <span className="rounded bg-primary/10 px-1 py-0.5 text-[9px] font-mono text-primary">
                        KG
                      </span>
                    </div>
                    <div className="space-y-2">
                      {alert.related_cves.map((cve) => (
                        <div
                          key={cve.id}
                          className="flex items-start gap-3 rounded-md border border-border/60 p-2.5"
                        >
                          <div className="shrink-0 flex flex-col items-center gap-0.5">
                            <span className="font-mono text-[10px] font-bold text-orange-400">{cve.id}</span>
                            <span
                              className={cn(
                                "text-[10px] font-mono font-bold",
                                cve.cvss >= 9 ? "text-red-400" :
                                cve.cvss >= 7 ? "text-orange-400" :
                                cve.cvss >= 4 ? "text-yellow-400" : "text-muted-foreground"
                              )}
                            >
                              {cve.cvss.toFixed(1)}
                            </span>
                          </div>
                          <p className="text-[10px] text-muted-foreground leading-relaxed">{cve.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Remediation */}
                {alert.remediation_hint && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Remediation</p>
                    <div className="flex items-start gap-2 rounded-md border border-primary/20 bg-primary/5 px-3 py-2.5">
                      <Terminal className="h-3.5 w-3.5 text-primary mt-0.5 shrink-0" />
                      <p className="text-[10px] text-foreground leading-relaxed whitespace-pre-line">
                        {alert.remediation_hint}
                      </p>
                    </div>
                  </div>
                )}

                {/* Timeline */}
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Timeline</p>
                  <div className="relative pl-4">
                    <div className="absolute left-1.5 top-0 bottom-0 w-px bg-border/60" />
                    <div className="space-y-3">
                      {alert.timeline.map((ev, i) => (
                        <div key={i} className="relative flex items-start gap-2.5">
                          <div
                            className={cn(
                              "absolute -left-[11px] top-1 h-2 w-2 rounded-full ring-2 ring-background",
                              ev.type === "detection"  ? "bg-orange-500" :
                              ev.type === "escalation" ? "bg-red-500" :
                              ev.type === "action"     ? "bg-blue-500" : "bg-muted-foreground"
                            )}
                          />
                          <div className="space-y-0.5 min-w-0">
                            <p className="text-[10px] text-foreground font-medium leading-snug">{ev.action}</p>
                            <p className="text-[10px] text-muted-foreground">
                              {ev.actor} · {formatTs(ev.ts)}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Tags */}
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Tags</p>
                  <div className="flex flex-wrap gap-1.5">
                    {alert.tags.map((t) => (
                      <span
                        key={t}
                        className="rounded bg-muted px-2 py-0.5 text-[10px] font-mono text-muted-foreground"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                <Separator />

                {/* Quick actions */}
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Quick Actions</p>
                  <div className="grid grid-cols-2 gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-[10px] gap-1.5 justify-start"
                      onClick={() => {
                        // Jira integration placeholder
                      }}
                    >
                      <Ticket className="h-3 w-3" /> Create Jira
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-[10px] gap-1.5 justify-start"
                      onClick={() => {
                        // Assign to analyst placeholder
                      }}
                    >
                      <UserPlus className="h-3 w-3" /> Assign Analyst
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-[10px] gap-1.5 justify-start border-red-500/30 text-red-400 hover:bg-red-500/10"
                      onClick={() => {
                        // Quarantine placeholder
                      }}
                    >
                      <Lock className="h-3 w-3" /> Quarantine Asset
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-[10px] gap-1.5 justify-start"
                      onClick={() => window.open(`/incidents?alert=${alert.id}`, "_blank")}
                    >
                      <ExternalLink className="h-3 w-3" /> Open in IR
                    </Button>
                  </div>
                </div>

                {/* Triage in drawer too */}
                <div className="grid grid-cols-2 gap-2 pb-2">
                  <Button
                    size="sm"
                    className="h-8 text-xs gap-1.5"
                    onClick={() => { onAccept(alert.id); onClose(); }}
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Accept Verdict
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-xs gap-1.5 border-orange-500/30 text-orange-400 hover:bg-orange-500/10"
                    onClick={() => { onOverride(alert.id, "ESCALATE"); onClose(); }}
                  >
                    <ArrowUpRight className="h-3.5 w-3.5" />
                    Escalate T2
                  </Button>
                </div>
              </div>
            </ScrollArea>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

// ═══════════════════════════════════════════════════════════
// Shift clock
// ═══════════════════════════════════════════════════════════

function ShiftClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  const hour = time.getHours();
  const shift = hour >= 6 && hour < 14 ? "Alpha" : hour >= 14 && hour < 22 ? "Bravo" : "Charlie";
  return (
    <div className="flex items-center gap-2.5 text-xs text-muted-foreground">
      <span className="flex items-center gap-1.5">
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-60" />
          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-green-500" />
        </span>
        <span className="text-green-400 font-medium">LIVE</span>
      </span>
      <Separator orientation="vertical" className="h-3" />
      <span className="font-mono tabular-nums">
        {time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
      </span>
      <span className="text-muted-foreground/60">·</span>
      <span>Shift <span className="font-medium text-foreground">{shift}</span></span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Stats bar KPI card (inline, not KpiCard component — tighter)
// ═══════════════════════════════════════════════════════════

function StatCard({
  label,
  value,
  sub,
  trend,
  icon: Icon,
  className,
}: {
  label: string;
  value: string | number;
  sub?: string;
  trend?: "up" | "down" | "flat";
  icon: React.ElementType;
  className?: string;
}) {
  return (
    <Card className={cn("p-4", className)}>
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-1.5 min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
          <p className="text-2xl font-bold tabular-nums tracking-tight font-mono">{value}</p>
          {sub && (
            <div className="flex items-center gap-1 text-xs">
              {trend === "up" && <TrendingUp className="h-3 w-3 text-green-400" />}
              {trend === "down" && <TrendingDown className="h-3 w-3 text-red-400" />}
              {trend === "flat" && <Minus className="h-3 w-3 text-muted-foreground" />}
              <span className={cn(
                "font-medium",
                trend === "up" ? "text-green-400" :
                trend === "down" ? "text-red-400" :
                "text-muted-foreground"
              )}>
                {sub}
              </span>
            </div>
          )}
        </div>
        <div className="rounded-lg bg-primary/10 p-2.5 shrink-0">
          <Icon className="h-4 w-4 text-primary" />
        </div>
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Main component
// ═══════════════════════════════════════════════════════════

type SortField = "severity" | "age" | "cvss";
type SortDir = "asc" | "desc";

export default function SOCT1Dashboard() {
  const navigate = useNavigate();

  // State
  const [alerts, setAlerts] = useState<Alert[]>(MOCK_ALERTS);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [drawerAlert, setDrawerAlert] = useState<Alert | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "all">("all");
  const [verdictFilter, setVerdictFilter] = useState<TriageVerdict | "all">("all");
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Try to fetch from API, fall back to mock
  useEffect(() => {
    const controller = new AbortController();
    fetch(`${API}/api/v1/incidents?limit=50`, { signal: controller.signal })
      .then((r) => r.ok ? r.json() : null)
      .then((data) => {
        if (data?.incidents?.length) {
          // Map API shape to our local Alert type as best as possible
          // API may return different field names — defensive mapping
          const mapped: Alert[] = data.incidents.map((inc: Record<string, unknown>) => ({
            id: (inc.id as string) ?? (inc.incident_id as string) ?? "INC-????",
            severity: (inc.severity as Severity) ?? "medium",
            title: (inc.title as string) ?? (inc.name as string) ?? "Untitled",
            description: (inc.description as string) ?? "",
            source: (inc.source as string) ?? "API",
            triage_verdict: (inc.triage_verdict as TriageVerdict) ?? "INVESTIGATE",
            council_votes: (inc.council_votes as CouncilVote[]) ?? [],
            agreement_pct: (inc.agreement_pct as number) ?? 0,
            cvss: (inc.cvss as number) ?? 0,
            cve: inc.cve as string | undefined,
            discovered_at: new Date((inc.created_at as string) ?? (inc.discovered_at as string) ?? Date.now()),
            status: (inc.status as AlertStatus) ?? "new",
            assignee: inc.assignee as string | undefined,
            asset: (inc.asset as string) ?? "",
            asset_type: (inc.asset_type as Alert["asset_type"]) ?? "code",
            affected_assets: (inc.affected_assets as string[]) ?? [],
            related_cves: (inc.related_cves as RelatedCve[]) ?? [],
            timeline: (inc.timeline as TimelineEvent[]) ?? [],
            tags: (inc.tags as string[]) ?? [],
            remediation_hint: inc.remediation_hint as string | undefined,
          }));
          setAlerts(mapped);
        }
      })
      .catch(() => { /* silent — use mock */ });
    return () => controller.abort();
  }, [lastRefresh]);

  const handleRefresh = useCallback(() => {
    setIsRefreshing(true);
    setLastRefresh(new Date());
    setTimeout(() => setIsRefreshing(false), 600);
  }, []);

  // Stats
  const stats = useMemo(() => {
    const active = alerts.filter((a) => a.status !== "resolved" && a.status !== "false_positive");
    const resolved24h = alerts.filter(
      (a) =>
        a.status === "resolved" &&
        Date.now() - a.discovered_at.getTime() < 86_400_000
    );
    const fp30d = alerts.filter((a) => a.status === "false_positive").length;
    const total30d = alerts.filter(
      (a) => Date.now() - a.discovered_at.getTime() < 30 * 86_400_000
    ).length;
    const highConfidence = alerts.filter((a) => a.agreement_pct >= 90).length;

    return {
      openCount: active.length,
      openTrend: "+3 vs yesterday" as string,
      mttt: "34m",
      mtttTrend: "below 60m SLA" as string,
      fpRate: total30d > 0 ? `${Math.round((fp30d / total30d) * 100)}%` : "0%",
      fpTrend: "30 day window" as string,
      llmAccuracy: alerts.length > 0 ? `${Math.round((highConfidence / alerts.length) * 100)}%` : "—",
      llmTrend: "≥90% consensus" as string,
    };
  }, [alerts]);

  // Filtered + sorted
  const filtered = useMemo(() => {
    const result = alerts.filter((a) => {
      if (severityFilter !== "all" && a.severity !== severityFilter) return false;
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (verdictFilter !== "all" && a.triage_verdict !== verdictFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        if (
          !a.title.toLowerCase().includes(q) &&
          !a.id.toLowerCase().includes(q) &&
          !a.asset.toLowerCase().includes(q) &&
          !(a.cve?.toLowerCase().includes(q) ?? false)
        )
          return false;
      }
      return true;
    });

    result.sort((a, b) => {
      let cmp = 0;
      if (sortField === "severity") cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      else if (sortField === "age")  cmp = b.discovered_at.getTime() - a.discovered_at.getTime();
      else if (sortField === "cvss") cmp = b.cvss - a.cvss;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return result;
  }, [alerts, severityFilter, statusFilter, verdictFilter, search, sortField, sortDir]);

  const toggleSort = useCallback((field: SortField) => {
    if (sortField === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortField(field); setSortDir("asc"); }
  }, [sortField]);

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <Minus className="h-2.5 w-2.5 opacity-30" />;
    return sortDir === "asc"
      ? <ChevronUp className="h-2.5 w-2.5 text-primary" />
      : <ChevronDown className="h-2.5 w-2.5 text-primary" />;
  };

  const handleAccept = useCallback((id: string) => {
    setAlerts((prev) =>
      prev.map((a) =>
        a.id === id ? { ...a, status: a.status === "new" ? "in_progress" : a.status } : a
      )
    );
    setSelectedAlert((prev) => prev?.id === id ? { ...prev, status: "in_progress" } : prev);
  }, []);

  const handleOverride = useCallback((id: string, verdict: TriageVerdict) => {
    setAlerts((prev) =>
      prev.map((a) =>
        a.id === id ? { ...a, triage_verdict: verdict, status: "in_progress" } : a
      )
    );
    setSelectedAlert((prev) =>
      prev?.id === id ? { ...prev, triage_verdict: verdict, status: "in_progress" } : prev
    );
  }, []);

  return (
    <TooltipProvider delayDuration={120}>
      <div className="flex flex-col h-full min-h-0 gap-4">

        {/* ── Header ── */}
        <PageHeader
          title="SOC T1 Alert Triage"
          description="P03 · The Hunter — LLM Council verdicts · split-panel triage"
          badge="T1"
        >
          <ShiftClock />
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            className="h-8 gap-1.5 text-xs"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isRefreshing && "animate-spin")} />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 text-xs"
            onClick={() => navigate("/mission-control/live-feed")}
          >
            <Activity className="h-3.5 w-3.5" />
            Live Feed
          </Button>
        </PageHeader>

        {/* ── Stats Bar ── */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="grid grid-cols-2 lg:grid-cols-4 gap-3"
        >
          <StatCard
            label="Open Alerts"
            value={stats.openCount}
            sub={stats.openTrend}
            trend="down"
            icon={AlertTriangle}
          />
          <StatCard
            label="Mean Time to Triage"
            value={stats.mttt}
            sub={stats.mtttTrend}
            trend="up"
            icon={Timer}
          />
          <StatCard
            label="False Positive Rate"
            value={stats.fpRate}
            sub={stats.fpTrend}
            trend="flat"
            icon={BarChart3}
          />
          <StatCard
            label="LLM Accuracy"
            value={stats.llmAccuracy}
            sub={stats.llmTrend}
            trend="up"
            icon={Brain}
          />
        </motion.div>

        {/* ── Filters ── */}
        <Card>
          <CardContent className="pt-3 pb-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative flex-1 min-w-[160px]">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search alerts, CVEs, assets..."
                  className="pl-8 h-8 text-xs"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>

              <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as Severity | "all")}>
                <SelectTrigger className="h-8 w-28 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>

              <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as AlertStatus | "all")}>
                <SelectTrigger className="h-8 w-28 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="new">New</SelectItem>
                  <SelectItem value="in_progress">In Progress</SelectItem>
                  <SelectItem value="resolved">Resolved</SelectItem>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                </SelectContent>
              </Select>

              <Select value={verdictFilter} onValueChange={(v) => setVerdictFilter(v as TriageVerdict | "all")}>
                <SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Verdict" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Verdicts</SelectItem>
                  <SelectItem value="ESCALATE">Escalate</SelectItem>
                  <SelectItem value="INVESTIGATE">Investigate</SelectItem>
                  <SelectItem value="FALSE_POSITIVE">False Positive</SelectItem>
                </SelectContent>
              </Select>

              <Select value={sortField} onValueChange={(v) => setSortField(v as SortField)}>
                <SelectTrigger className="h-8 w-32 text-xs">
                  <SlidersHorizontal className="h-3 w-3 mr-1.5 shrink-0" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="severity">Severity</SelectItem>
                  <SelectItem value="age">Age</SelectItem>
                  <SelectItem value="cvss">CVSS Score</SelectItem>
                </SelectContent>
              </Select>

              <div className="flex-1" />
              <span className="text-xs text-muted-foreground tabular-nums shrink-0">
                {filtered.length} / {alerts.length}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* ── Main split: Queue | Council Panel ── */}
        <div className="flex gap-4 flex-1 min-h-0">

          {/* Left: Alert Queue */}
          <div className="flex-1 min-w-0">
            <Card className="h-full flex flex-col">
              <div className="overflow-x-auto flex-1">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-card z-10">
                    <tr className="border-b border-border">
                      {/* Severity */}
                      <th className="px-3 py-2.5 text-left">
                        <button
                          onClick={() => toggleSort("severity")}
                          className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
                        >
                          Sev <SortIcon field="severity" />
                        </button>
                      </th>
                      {/* Alert title */}
                      <th className="px-3 py-2.5 text-left">
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Alert</span>
                      </th>
                      {/* Type */}
                      <th className="px-3 py-2.5 text-left hidden md:table-cell">
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Type</span>
                      </th>
                      {/* Verdict */}
                      <th className="px-3 py-2.5 text-left">
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Verdict</span>
                      </th>
                      {/* CVSS */}
                      <th className="px-3 py-2.5 text-left hidden lg:table-cell">
                        <button
                          onClick={() => toggleSort("cvss")}
                          className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
                        >
                          CVSS <SortIcon field="cvss" />
                        </button>
                      </th>
                      {/* Age */}
                      <th className="px-3 py-2.5 text-left">
                        <button
                          onClick={() => toggleSort("age")}
                          className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
                        >
                          Age <SortIcon field="age" />
                        </button>
                      </th>
                      {/* Status */}
                      <th className="px-3 py-2.5 text-left hidden sm:table-cell">
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Status</span>
                      </th>
                      {/* Actions */}
                      <th className="px-3 py-2.5 text-right">
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Actions</span>
                      </th>
                    </tr>
                  </thead>

                  <tbody>
                    <AnimatePresence initial={false}>
                      {filtered.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="py-16 text-center text-sm text-muted-foreground">
                            No alerts match the current filters.
                          </td>
                        </tr>
                      ) : (
                        filtered.map((alert, i) => {
                          const isSelected = selectedAlert?.id === alert.id;
                          const isCritical = alert.severity === "critical";

                          return (
                            <motion.tr
                              key={alert.id}
                              initial={{ opacity: 0, y: 4 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0 }}
                              transition={{ duration: 0.12, delay: i * 0.015 }}
                              className={cn(
                                "border-b border-border/50 transition-colors cursor-pointer group",
                                isSelected && "bg-primary/8 border-l-2 border-l-primary",
                                !isSelected && isCritical && "bg-red-500/[0.03]",
                                !isSelected && "hover:bg-muted/30"
                              )}
                              onClick={() => setSelectedAlert(isSelected ? null : alert)}
                            >
                              {/* Severity */}
                              <td className="px-3 py-2.5">
                                <SeverityBadge severity={alert.severity} />
                              </td>

                              {/* Alert */}
                              <td className="px-3 py-2.5 min-w-[220px] max-w-[320px]">
                                <div className="space-y-0.5">
                                  <div className="flex items-center gap-1.5">
                                    <span className="font-mono text-[10px] text-muted-foreground">{alert.id}</span>
                                    {alert.cve && (
                                      <span className="font-mono text-[9px] bg-orange-500/15 text-orange-400 px-1 rounded">
                                        {alert.cve}
                                      </span>
                                    )}
                                  </div>
                                  <p className="text-xs font-medium leading-snug line-clamp-2 text-foreground group-hover:text-foreground/90">
                                    {alert.title}
                                  </p>
                                </div>
                              </td>

                              {/* Asset type */}
                              <td className="px-3 py-2.5 hidden md:table-cell">
                                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                  <AssetIcon type={alert.asset_type} />
                                  <span className="capitalize">{alert.asset_type}</span>
                                </div>
                              </td>

                              {/* Verdict */}
                              <td className="px-3 py-2.5">
                                <TriageVerdictChip verdict={alert.triage_verdict} />
                              </td>

                              {/* CVSS */}
                              <td className="px-3 py-2.5 hidden lg:table-cell">
                                <span
                                  className={cn(
                                    "font-mono text-xs font-bold tabular-nums",
                                    alert.cvss >= 9 ? "text-red-400" :
                                    alert.cvss >= 7 ? "text-orange-400" :
                                    alert.cvss >= 4 ? "text-yellow-400" : "text-muted-foreground"
                                  )}
                                >
                                  {alert.cvss.toFixed(1)}
                                </span>
                              </td>

                              {/* Age */}
                              <td className="px-3 py-2.5">
                                <span className="font-mono text-xs text-muted-foreground tabular-nums">
                                  {formatAge(alert.discovered_at)}
                                </span>
                              </td>

                              {/* Status */}
                              <td className="px-3 py-2.5 hidden sm:table-cell">
                                <StatusBadge status={alert.status} />
                              </td>

                              {/* Actions */}
                              <td className="px-3 py-2.5" onClick={(e) => e.stopPropagation()}>
                                <div className="flex items-center gap-1 justify-end opacity-0 group-hover:opacity-100 transition-opacity">
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <button
                                        className="rounded p-1 hover:bg-muted/60 transition-colors"
                                        onClick={() => setDrawerAlert(alert)}
                                        aria-title="Open detail"
                                      >
                                        <ChevronsRight className="h-3.5 w-3.5 text-muted-foreground" />
                                      </button>
                                    </TooltipTrigger>
                                    <TooltipContent side="left">Open detail drawer</TooltipContent>
                                  </Tooltip>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <button
                                        className="rounded p-1 hover:bg-green-500/10 transition-colors"
                                        onClick={() => handleAccept(alert.id)}
                                        aria-title="Accept verdict"
                                      >
                                        <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                                      </button>
                                    </TooltipTrigger>
                                    <TooltipContent side="left">Accept LLM verdict</TooltipContent>
                                  </Tooltip>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <button
                                        className="rounded p-1 hover:bg-muted/60 transition-colors"
                                        onClick={() => handleOverride(alert.id, "FALSE_POSITIVE")}
                                        aria-title="Mark false positive"
                                      >
                                        <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                                      </button>
                                    </TooltipTrigger>
                                    <TooltipContent side="left">Mark false positive</TooltipContent>
                                  </Tooltip>
                                </div>
                              </td>
                            </motion.tr>
                          );
                        })
                      )}
                    </AnimatePresence>
                  </tbody>
                </table>
              </div>
            </Card>
          </div>

          {/* Right: LLM Council Panel — sticky */}
          <motion.div
            initial={{ opacity: 0, x: 12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3, delay: 0.1 }}
            className="w-72 xl:w-80 shrink-0"
          >
            <Card className="h-full flex flex-col overflow-hidden">
              <CardHeader className="py-3 px-4 border-b border-border/60 shrink-0">
                <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                  <ShieldAlert className="h-3.5 w-3.5 text-primary" />
                  Council Verdict
                  {selectedAlert && (
                    <span className="ml-auto font-mono text-[10px] text-muted-foreground font-normal">
                      {selectedAlert.id}
                    </span>
                  )}
                </CardTitle>
              </CardHeader>
              <div className="flex-1 min-h-0 overflow-hidden">
                <AnimatePresence mode="wait">
                  <motion.div
                    key={selectedAlert?.id ?? "empty"}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.18 }}
                    className="h-full"
                  >
                    <CouncilPanel
                      alert={selectedAlert}
                      onAccept={handleAccept}
                      onOverride={handleOverride}
                    />
                  </motion.div>
                </AnimatePresence>
              </div>
            </Card>
          </motion.div>
        </div>
      </div>

      {/* Detail Drawer — portal-like, fixed overlay */}
      <AlertDetailDrawer
        alert={drawerAlert}
        onClose={() => setDrawerAlert(null)}
        onAccept={handleAccept}
        onOverride={handleOverride}
      />
    </TooltipProvider>
  );
}
