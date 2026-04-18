/**
 * Findings Explorer — Universal Finding Triage Page
 *
 * The core page every persona lands on. Engineered for SOC T1, AppSec,
 * CloudSec, DevSec, CISO, and Compliance personas simultaneously.
 *
 * Features:
 *   - Paginated findings table (severity, title, source scanner, CVE, CVSS,
 *     status, age, risk score)
 *   - Advanced filter bar (severity, scanner, status, date range, search)
 *   - Finding detail slide-out panel (full details, LLM Council verdict,
 *     remediation steps, related findings, timeline)
 *   - Bulk actions (acknowledge, assign, export)
 *
 * Design: information-dense, dark-first, surgical precision over decoration.
 * One memorable thing: the Council verdict section with model-level breakdown
 * is shown directly in the slide-out — no modal-within-modal.
 *
 * Route: /findings
 */

import { useState, useMemo, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  SlidersHorizontal,
  Download,
  RefreshCw,
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  X,
  CheckCircle2,
  UserCheck,
  Archive,
  AlertTriangle,
  Shield,
  Bug,
  Code,
  KeyRound,
  Server,
  Cloud,
  Container,
  Package,
  Flame,
  Clock,
  CalendarDays,
  Zap,
  Brain,
  GitBranch,
  Terminal,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Activity,
  FileText,
  TriangleAlert,
  Layers,
  Users,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low" | "info";
type FindingStatus =
  | "open"
  | "in_progress"
  | "acknowledged"
  | "resolved"
  | "false_positive"
  | "accepted_risk";
type Verdict = "BLOCK" | "REVIEW" | "ALLOW" | "PENDING";
type AssetType =
  | "container"
  | "code"
  | "cloud"
  | "secrets"
  | "iac"
  | "package"
  | "dependency"
  | "api";

interface CouncilModel {
  name: string;
  verdict: Verdict;
  confidence: number;
  reasoning: string;
}

interface TimelineEvent {
  at: Date;
  actor: string;
  action: string;
  detail?: string;
}

interface RelatedFinding {
  id: string;
  title: string;
  severity: Severity;
}

interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  source: string;
  asset: string;
  asset_type: AssetType;
  cve?: string;
  cvss?: number;
  epss?: number;
  status: FindingStatus;
  discovered_at: Date;
  updated_at: Date;
  assignee?: string;
  risk_score: number;
  verdict: Verdict;
  verdict_confidence: number;
  council_models: CouncilModel[];
  remediation: string[];
  related: RelatedFinding[];
  timeline: TimelineEvent[];
  tags: string[];
  kev?: boolean;
  reachable?: boolean;
  file_path?: string;
  line?: number;
  component?: string;
  fix_version?: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data — 24 diverse realistic findings
// ═══════════════════════════════════════════════════════════

const now = new Date("2026-04-12T10:00:00Z");
const minsAgo = (m: number) => new Date(now.getTime() - m * 60_000);
const hoursAgo = (h: number) => new Date(now.getTime() - h * 3_600_000);
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000);

const MOCK_FINDINGS: Finding[] = [
  {
    id: "FND-0041",
    severity: "critical",
    title: "CVE-2024-3094: XZ Utils Backdoor in Base Image",
    description:
      "liblzma.so linked in production container matches the CVE-2024-3094 backdoor signature. Remote code execution is possible on any systemd-linked host. Immediate containment required.",
    source: "Trivy",
    asset: "aldeci-api:v2.3.1",
    asset_type: "container",
    cve: "CVE-2024-3094",
    cvss: 10.0,
    epss: 0.97,
    status: "open",
    discovered_at: minsAgo(12),
    updated_at: minsAgo(12),
    risk_score: 98,
    verdict: "BLOCK",
    verdict_confidence: 99,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 100, reasoning: "Known active backdoor with confirmed RCE. No false-positive scenario possible." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 99, reasoning: "CVE confirmed by CISA KEV. Supply-chain impact is severe." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 98, reasoning: "Backdoor hash matches known malicious xz-utils 5.6.0." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 97, reasoning: "Active exploitation in the wild. CVSS 10.0 confirmed." },
    ],
    remediation: [
      "Immediately stop and remove the affected container image.",
      "Rebuild from debian:bookworm-slim (xz-utils 5.4.x or later).",
      "Rotate all credentials that may have been exposed on affected hosts.",
      "Audit all container images in the registry for xz-utils versions 5.6.0–5.6.1.",
      "Add a CI gate blocking builds containing xz-utils 5.6.0–5.6.1.",
    ],
    related: [
      { id: "FND-0039", title: "Outdated liblzma in worker image", severity: "high" },
      { id: "FND-0022", title: "Container registry lacks image signing", severity: "medium" },
    ],
    timeline: [
      { at: minsAgo(12), actor: "Trivy Scanner", action: "Finding created", detail: "Automated scan detected backdoor signature." },
      { at: minsAgo(10), actor: "LLM Council", action: "Verdict issued", detail: "BLOCK — unanimous 4/4 models." },
    ],
    tags: ["supply-chain", "rce", "container", "kev"],
    kev: true,
    reachable: true,
    component: "xz-utils 5.6.1",
    fix_version: "xz-utils 5.4.6",
  },
  {
    id: "FND-0040",
    severity: "critical",
    title: "Hardcoded AWS Credentials in Dockerfile",
    description:
      "AWS_SECRET_ACCESS_KEY found in plaintext inside Dockerfile used in the production build pipeline. The key has active S3 + EC2 permissions and has been present for 14 days.",
    source: "Semgrep",
    asset: "docker/prod/Dockerfile",
    asset_type: "secrets",
    cve: undefined,
    cvss: undefined,
    epss: undefined,
    status: "in_progress",
    discovered_at: hoursAgo(3),
    updated_at: hoursAgo(1),
    assignee: "alex.chen",
    risk_score: 95,
    verdict: "BLOCK",
    verdict_confidence: 100,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 100, reasoning: "Active credential with broad blast radius. Immediate revocation required." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 100, reasoning: "Plaintext secrets in VCS history are a critical data exfiltration risk." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 99, reasoning: "Key is valid and active per AWS IAM check." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 98, reasoning: "Dockerfile is committed to git, expanding exposure to all repo cloners." },
    ],
    remediation: [
      "Immediately rotate the exposed AWS key via IAM console.",
      "Remove the key from Dockerfile and all git history (git-filter-repo).",
      "Move secrets to AWS Secrets Manager or HashiCorp Vault.",
      "Add pre-commit hook using detect-secrets or trufflehog.",
      "Audit S3 access logs for the past 14 days for unauthorized access.",
    ],
    related: [
      { id: "FND-0038", title: "GCP service account key in env file", severity: "critical" },
      { id: "FND-0031", title: "Secret scanning not enabled on repo", severity: "medium" },
    ],
    timeline: [
      { at: hoursAgo(3), actor: "Semgrep CI", action: "Finding created" },
      { at: hoursAgo(2), actor: "LLM Council", action: "Verdict: BLOCK" },
      { at: hoursAgo(1), actor: "alex.chen", action: "Assigned", detail: "Working on key rotation." },
    ],
    tags: ["secrets", "credentials", "aws", "iac"],
    kev: false,
    reachable: true,
    file_path: "docker/prod/Dockerfile",
    line: 14,
  },
  {
    id: "FND-0039",
    severity: "high",
    title: "CVE-2023-44487 (HTTP/2 Rapid Reset) in Envoy Proxy",
    description:
      "Envoy proxy version 1.27.0 is vulnerable to CVE-2023-44487. A remote attacker can send rapid HTTP/2 RST_STREAM frames to exhaust server resources and cause denial of service.",
    source: "Grype",
    asset: "envoy:1.27.0",
    asset_type: "container",
    cve: "CVE-2023-44487",
    cvss: 7.5,
    epss: 0.72,
    status: "open",
    discovered_at: hoursAgo(8),
    updated_at: hoursAgo(8),
    risk_score: 82,
    verdict: "REVIEW",
    verdict_confidence: 84,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 88, reasoning: "Widely exploited DoS vector. Patch is available." },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 82, reasoning: "Severity depends on internet exposure of the proxy endpoint." },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 78, reasoning: "Rate limiting mitigates risk if proxy is internal-only." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 85, reasoning: "CISA KEV listed. Patch immediately." },
    ],
    remediation: [
      "Upgrade Envoy to 1.27.1 or later which patches CVE-2023-44487.",
      "Enable HTTP/2 stream reset rate limiting in Envoy config.",
      "Restrict internet exposure of the affected proxy endpoint.",
    ],
    related: [
      { id: "FND-0041", title: "XZ Utils Backdoor in Base Image", severity: "critical" },
    ],
    timeline: [
      { at: hoursAgo(8), actor: "Grype Scanner", action: "Finding created" },
      { at: hoursAgo(6), actor: "LLM Council", action: "Verdict: REVIEW (split)" },
    ],
    tags: ["dos", "http2", "proxy", "kev"],
    kev: true,
    reachable: true,
    component: "envoy 1.27.0",
    fix_version: "envoy 1.27.1",
  },
  {
    id: "FND-0038",
    severity: "critical",
    title: "GCP Service Account Key Committed to Repository",
    description:
      "A GCP service account JSON key with roles/editor was committed to the main branch of the backend repo. The key grants broad access to production GCP project resources.",
    source: "TruffleHog",
    asset: "backend/.gcp/sa-key.json",
    asset_type: "secrets",
    cvss: undefined,
    status: "acknowledged",
    discovered_at: daysAgo(1),
    updated_at: hoursAgo(4),
    assignee: "priya.sharma",
    risk_score: 93,
    verdict: "BLOCK",
    verdict_confidence: 97,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 98, reasoning: "Editor role on production project is a full compromise." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 97, reasoning: "GCP APIs confirm the key is still active." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 96, reasoning: "Git history shows key was present for 72+ hours." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 95, reasoning: "Blast radius includes Cloud SQL, GCS, and Pub/Sub." },
    ],
    remediation: [
      "Revoke the service account key immediately via GCP Console > IAM.",
      "Purge from git history using git-filter-repo.",
      "Audit GCP audit logs for suspicious API calls using the compromised key.",
      "Use Workload Identity Federation instead of key files.",
    ],
    related: [
      { id: "FND-0040", title: "Hardcoded AWS Credentials in Dockerfile", severity: "critical" },
    ],
    timeline: [
      { at: daysAgo(1), actor: "TruffleHog", action: "Finding created" },
      { at: hoursAgo(20), actor: "LLM Council", action: "Verdict: BLOCK" },
      { at: hoursAgo(4), actor: "priya.sharma", action: "Acknowledged", detail: "Key revocation in progress." },
    ],
    tags: ["secrets", "gcp", "credentials"],
    file_path: "backend/.gcp/sa-key.json",
  },
  {
    id: "FND-0037",
    severity: "high",
    title: "SQL Injection via Unsanitized ORM Filter Parameter",
    description:
      "The /api/v2/findings endpoint accepts an unsanitized `filter` query parameter that is interpolated directly into a raw SQL query. Demonstrated PoC extracts all rows from the findings table.",
    source: "Semgrep",
    asset: "suite-api/routers/findings_router.py",
    asset_type: "code",
    cvss: 8.8,
    epss: 0.43,
    status: "open",
    discovered_at: daysAgo(2),
    updated_at: daysAgo(2),
    risk_score: 79,
    verdict: "BLOCK",
    verdict_confidence: 92,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 94, reasoning: "Confirmed injection via PoC. Auth bypass possible." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 93, reasoning: "Raw string interpolation in ORM is a classic injection vector." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 90, reasoning: "CVSS 8.8. Patch before next deploy." },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 82, reasoning: "Endpoint requires auth token — reduces but doesn't eliminate risk." },
    ],
    remediation: [
      "Replace raw SQL with parameterized ORM queries (SQLAlchemy `.filter()`).",
      "Add input validation using Pydantic strict typing on the filter parameter.",
      "Deploy a WAF rule blocking SQL metacharacters in query params immediately.",
      "Rotate API keys that could have been extracted via the injection.",
    ],
    related: [
      { id: "FND-0033", title: "NoSQL injection in threat feed endpoint", severity: "medium" },
    ],
    timeline: [
      { at: daysAgo(2), actor: "Semgrep", action: "Finding created" },
      { at: daysAgo(2), actor: "LLM Council", action: "Verdict: BLOCK" },
    ],
    tags: ["sqli", "injection", "api", "appsec"],
    file_path: "suite-api/routers/findings_router.py",
    line: 87,
    reachable: true,
  },
  {
    id: "FND-0036",
    severity: "high",
    title: "S3 Bucket Publicly Readable — Evidence Vault",
    description:
      "The S3 bucket `aldeci-evidence-prod` has a bucket policy granting s3:GetObject to Principal '*'. Any unauthenticated actor can read compliance evidence artifacts including SOC2 reports.",
    source: "Prowler",
    asset: "s3://aldeci-evidence-prod",
    asset_type: "cloud",
    cvss: 7.5,
    status: "open",
    discovered_at: hoursAgo(14),
    updated_at: hoursAgo(14),
    risk_score: 76,
    verdict: "BLOCK",
    verdict_confidence: 96,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 97, reasoning: "Public S3 bucket with sensitive compliance data is an immediate breach risk." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 96, reasoning: "SOC2 reports contain auditor findings — PII and competitive data." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 95, reasoning: "Remove public access block override immediately." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 94, reasoning: "AWS Config rule S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED violated." },
    ],
    remediation: [
      "Enable S3 Block Public Access at account level.",
      "Remove the `Principal: *` statement from the bucket policy.",
      "Enable S3 server-side encryption with KMS.",
      "Audit S3 access logs for unauthorized downloads.",
      "Add AWS Config rule to prevent future public bucket creation.",
    ],
    related: [
      { id: "FND-0029", title: "CloudTrail logging disabled in eu-west-1", severity: "high" },
    ],
    timeline: [
      { at: hoursAgo(14), actor: "Prowler", action: "Finding created" },
      { at: hoursAgo(13), actor: "LLM Council", action: "Verdict: BLOCK" },
    ],
    tags: ["s3", "public-access", "cloud", "data-exposure"],
    reachable: true,
  },
  {
    id: "FND-0035",
    severity: "high",
    title: "Log4Shell (CVE-2021-44228) in Legacy Audit Service",
    description:
      "log4j-core 2.14.1 detected in the audit-service JAR. The JNDI lookup vector is reachable via the HTTP User-Agent header which is passed to log4j for audit logging.",
    source: "Grype",
    asset: "audit-service:v1.4.2",
    asset_type: "container",
    cve: "CVE-2021-44228",
    cvss: 10.0,
    epss: 0.97,
    status: "in_progress",
    discovered_at: daysAgo(3),
    updated_at: daysAgo(1),
    assignee: "omar.hassan",
    risk_score: 88,
    verdict: "BLOCK",
    verdict_confidence: 99,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 99, reasoning: "Log4Shell with confirmed reachable vector. CVSS 10.0." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 99, reasoning: "User-Agent passed to log4j is a confirmed JNDI injection path." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 98, reasoning: "Patch to log4j 2.17.1+. Workaround: set log4j2.formatMsgNoLookups=true." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 98, reasoning: "KEV listed. No acceptable delay." },
    ],
    remediation: [
      "Upgrade log4j-core to 2.17.1 or later.",
      "Set JVM flag `-Dlog4j2.formatMsgNoLookups=true` as immediate workaround.",
      "Block outbound LDAP/RMI from the service at network level.",
      "Audit DNS and LDAP logs for JNDI callback indicators.",
    ],
    related: [
      { id: "FND-0041", title: "XZ Utils Backdoor in Base Image", severity: "critical" },
    ],
    timeline: [
      { at: daysAgo(3), actor: "Grype", action: "Finding created" },
      { at: daysAgo(3), actor: "LLM Council", action: "Verdict: BLOCK" },
      { at: daysAgo(1), actor: "omar.hassan", action: "Mitigation applied", detail: "JVM flag set. Patch in progress." },
    ],
    tags: ["log4shell", "rce", "jndi", "java", "kev"],
    kev: true,
    reachable: true,
    component: "log4j-core 2.14.1",
    fix_version: "log4j-core 2.17.1",
  },
  {
    id: "FND-0034",
    severity: "medium",
    title: "Terraform S3 Backend Lacks Encryption at Rest",
    description:
      "The Terraform remote state S3 bucket `tf-state-aldeci-prod` does not have SSE-KMS configured. State files contain plaintext resource metadata and may include sensitive outputs.",
    source: "Checkov",
    asset: "infra/terraform/backend.tf",
    asset_type: "iac",
    cvss: 5.5,
    status: "open",
    discovered_at: daysAgo(4),
    updated_at: daysAgo(4),
    risk_score: 48,
    verdict: "REVIEW",
    verdict_confidence: 71,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 74, reasoning: "Missing encryption is a compliance violation, not active exploitation." },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 72, reasoning: "State files may contain sensitive outputs. Medium priority." },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 60, reasoning: "S3 default encryption is enabled. KMS adds defense-in-depth only." },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 78, reasoning: "SOC2 CC6.1 requires encryption of sensitive data at rest." },
    ],
    remediation: [
      "Add `server_side_encryption_configuration` block to the S3 bucket resource.",
      "Use aws_kms_key for customer-managed encryption.",
      "Enable S3 Versioning to protect against state corruption.",
      "Restrict bucket access to Terraform role only.",
    ],
    related: [
      { id: "FND-0036", title: "S3 Bucket Publicly Readable", severity: "high" },
    ],
    timeline: [
      { at: daysAgo(4), actor: "Checkov", action: "Finding created" },
      { at: daysAgo(4), actor: "LLM Council", action: "Verdict: REVIEW (split)" },
    ],
    tags: ["iac", "terraform", "encryption", "s3"],
    file_path: "infra/terraform/backend.tf",
    line: 12,
  },
  {
    id: "FND-0033",
    severity: "medium",
    title: "Prototype Pollution in lodash < 4.17.21",
    description:
      "lodash 4.17.11 is bundled in the frontend. The `_.zipObjectDeep` and `_.set` functions are vulnerable to prototype pollution which can lead to RCE or DoS in Node.js contexts.",
    source: "npm audit",
    asset: "suite-ui/aldeci-ui-new",
    asset_type: "package",
    cve: "CVE-2020-8203",
    cvss: 7.4,
    epss: 0.31,
    status: "resolved",
    discovered_at: daysAgo(7),
    updated_at: daysAgo(2),
    assignee: "sarah.kim",
    risk_score: 42,
    verdict: "REVIEW",
    verdict_confidence: 68,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 70, reasoning: "Frontend-only usage limits RCE. DoS via user input is still possible." },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 68, reasoning: "Prototype pollution in browser context has limited impact." },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 65, reasoning: "No server-side lodash usage detected. Risk is low." },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 72, reasoning: "Update to 4.17.21 is trivial. No reason not to patch." },
    ],
    remediation: [
      "Upgrade lodash to 4.17.21 via `npm update lodash`.",
      "Audit code for direct use of `_.merge`, `_.set`, `_.zipObjectDeep`.",
    ],
    related: [],
    timeline: [
      { at: daysAgo(7), actor: "npm audit", action: "Finding created" },
      { at: daysAgo(5), actor: "LLM Council", action: "Verdict: REVIEW" },
      { at: daysAgo(2), actor: "sarah.kim", action: "Resolved", detail: "Upgraded to lodash 4.17.21." },
    ],
    tags: ["npm", "prototype-pollution", "frontend"],
    component: "lodash 4.17.11",
    fix_version: "lodash 4.17.21",
  },
  {
    id: "FND-0032",
    severity: "medium",
    title: "Missing HSTS Header on API Gateway",
    description:
      "The API gateway at api.aldeci.io does not return a Strict-Transport-Security header. Without HSTS, browsers may silently downgrade HTTPS to HTTP on subsequent requests.",
    source: "ZAP",
    asset: "api.aldeci.io",
    asset_type: "api",
    cvss: 5.0,
    status: "open",
    discovered_at: daysAgo(5),
    updated_at: daysAgo(5),
    risk_score: 35,
    verdict: "REVIEW",
    verdict_confidence: 65,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 67, reasoning: "HSTS is a best practice. Low active exploitation risk." },
      { name: "Claude 3.5", verdict: "ALLOW", confidence: 60, reasoning: "TLS is enforced at load balancer. HSTS adds defense-in-depth." },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 65, reasoning: "Required for PCI-DSS and SOC2 compliance." },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 68, reasoning: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains" },
    ],
    remediation: [
      "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to all API responses.",
      "Verify TLS enforcement at load balancer level.",
      "Submit domain to HSTS preload list at hstspreload.org.",
    ],
    related: [],
    timeline: [
      { at: daysAgo(5), actor: "ZAP Scanner", action: "Finding created" },
      { at: daysAgo(5), actor: "LLM Council", action: "Verdict: REVIEW (split)" },
    ],
    tags: ["headers", "tls", "api", "web"],
  },
  {
    id: "FND-0031",
    severity: "high",
    title: "Kubernetes RBAC: ClusterAdmin Granted to CI Service Account",
    description:
      "The CI/CD service account `github-actions-runner` has been granted `cluster-admin` ClusterRole. Any compromised pipeline has full control over the production Kubernetes cluster.",
    source: "kube-bench",
    asset: "k8s://cluster-prod/sa/github-actions-runner",
    asset_type: "iac",
    cvss: 8.8,
    status: "open",
    discovered_at: daysAgo(2),
    updated_at: daysAgo(2),
    risk_score: 84,
    verdict: "BLOCK",
    verdict_confidence: 93,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 95, reasoning: "Cluster-admin on CI account violates least privilege. Critical blast radius." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 93, reasoning: "Supply-chain attack on CI pipeline = full cluster compromise." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 90, reasoning: "Revoke and replace with scoped Role for specific namespaces." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 94, reasoning: "CIS Kubernetes Benchmark 5.1.1 violation." },
    ],
    remediation: [
      "Revoke ClusterRoleBinding for the CI service account immediately.",
      "Create a scoped Role limited to the deployment namespace.",
      "Implement OPA Gatekeeper policy blocking cluster-admin grants.",
      "Audit all ClusterRoleBindings for over-privileged accounts.",
    ],
    related: [],
    timeline: [
      { at: daysAgo(2), actor: "kube-bench", action: "Finding created" },
      { at: daysAgo(2), actor: "LLM Council", action: "Verdict: BLOCK" },
    ],
    tags: ["k8s", "rbac", "least-privilege", "cicd"],
    reachable: true,
  },
  {
    id: "FND-0030",
    severity: "low",
    title: "Outdated npm Package: axios 0.27.2",
    description:
      "axios 0.27.2 is used in the frontend build. While no critical CVEs are present, versions prior to 1.x have known SSRF vectors in server-side configurations.",
    source: "npm audit",
    asset: "suite-ui/aldeci-ui-new",
    asset_type: "package",
    cvss: 3.7,
    status: "accepted_risk",
    discovered_at: daysAgo(10),
    updated_at: daysAgo(5),
    risk_score: 18,
    verdict: "ALLOW",
    verdict_confidence: 82,
    council_models: [
      { name: "GPT-4o", verdict: "ALLOW", confidence: 85, reasoning: "Frontend-only. No SSRF vector in browser context." },
      { name: "Claude 3.5", verdict: "ALLOW", confidence: 82, reasoning: "Low CVSS. Browser sandbox mitigates SSRF risk." },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 80, reasoning: "Schedule upgrade in next sprint." },
      { name: "DeepSeek V3", verdict: "ALLOW", confidence: 82, reasoning: "No active exploitation. Update recommended but not urgent." },
    ],
    remediation: ["Upgrade axios to 1.7.x in the next planned sprint."],
    related: [],
    timeline: [
      { at: daysAgo(10), actor: "npm audit", action: "Finding created" },
      { at: daysAgo(8), actor: "LLM Council", action: "Verdict: ALLOW" },
      { at: daysAgo(5), actor: "sarah.kim", action: "Accepted risk", detail: "Scheduled for next sprint." },
    ],
    tags: ["npm", "outdated", "frontend"],
    component: "axios 0.27.2",
    fix_version: "axios 1.7.x",
  },
  {
    id: "FND-0029",
    severity: "high",
    title: "CloudTrail Logging Disabled in eu-west-1",
    description:
      "AWS CloudTrail is not enabled in the eu-west-1 region. All API activity in this region is unaudited, including potential lateral movement by an attacker.",
    source: "Prowler",
    asset: "aws://eu-west-1",
    asset_type: "cloud",
    cvss: 7.5,
    status: "open",
    discovered_at: daysAgo(1),
    updated_at: daysAgo(1),
    risk_score: 71,
    verdict: "BLOCK",
    verdict_confidence: 89,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 91, reasoning: "Audit gap violates SOC2 CC7.2 and ISO 27001 A.12.4." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 89, reasoning: "Unaudited region is a blind spot for incident response." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 87, reasoning: "Enable multi-region CloudTrail immediately." },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 80, reasoning: "Verify if any workloads actually run in eu-west-1." },
    ],
    remediation: [
      "Enable AWS CloudTrail with multi-region coverage.",
      "Configure CloudTrail to deliver logs to S3 with SSE-KMS.",
      "Set up CloudWatch Alarms for suspicious API activity.",
      "Add AWS Config rule CLOUD_TRAIL_ENABLED.",
    ],
    related: [
      { id: "FND-0036", title: "S3 Bucket Publicly Readable", severity: "high" },
    ],
    timeline: [
      { at: daysAgo(1), actor: "Prowler", action: "Finding created" },
      { at: daysAgo(1), actor: "LLM Council", action: "Verdict: BLOCK" },
    ],
    tags: ["cloudtrail", "logging", "aws", "compliance"],
  },
  {
    id: "FND-0028",
    severity: "medium",
    title: "Dependency Confusion Risk: Internal Package Not Scoped",
    description:
      "Internal npm package `aldeci-core` is published without an npm scope (@org/). An attacker can publish a higher-version public `aldeci-core` to npm, causing dependency confusion.",
    source: "Semgrep",
    asset: "suite-ui/aldeci-ui-new/package.json",
    asset_type: "package",
    cvss: 6.5,
    status: "open",
    discovered_at: daysAgo(6),
    updated_at: daysAgo(6),
    risk_score: 55,
    verdict: "REVIEW",
    verdict_confidence: 76,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 78, reasoning: "Dependency confusion can lead to supply-chain compromise." },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 76, reasoning: "Scope the package and configure private registry resolution." },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 74, reasoning: "Add npmrc config pointing internal packages to private registry." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 80, reasoning: "Several high-profile breaches used this exact vector." },
    ],
    remediation: [
      "Rename internal package to @aldeci/core.",
      "Configure .npmrc to resolve @aldeci/* from private registry only.",
      "Register the unscoped package name on public npm to prevent squatting.",
    ],
    related: [],
    timeline: [
      { at: daysAgo(6), actor: "Semgrep", action: "Finding created" },
      { at: daysAgo(6), actor: "LLM Council", action: "Verdict: REVIEW" },
    ],
    tags: ["supply-chain", "npm", "dependency-confusion"],
  },
  {
    id: "FND-0027",
    severity: "low",
    title: "TLS 1.0/1.1 Enabled on Internal Admin Port",
    description:
      "The internal admin interface on port 8443 accepts TLS 1.0 and 1.1 connections. These protocol versions have known weaknesses (BEAST, POODLE) and are deprecated.",
    source: "ZAP",
    asset: "internal-admin:8443",
    asset_type: "api",
    cvss: 4.3,
    status: "open",
    discovered_at: daysAgo(8),
    updated_at: daysAgo(8),
    risk_score: 25,
    verdict: "REVIEW",
    verdict_confidence: 62,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 64, reasoning: "Internal interface. Low internet exposure. Medium priority." },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 62, reasoning: "TLS 1.2+ only. Required for PCI-DSS 4.0." },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 55, reasoning: "Network-internal only. Threat model is limited." },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 65, reasoning: "Fix is trivial: set minimum TLS version in nginx config." },
    ],
    remediation: [
      "Set `ssl_protocols TLSv1.2 TLSv1.3;` in nginx config.",
      "Verify clients support TLS 1.2 before disabling older protocols.",
    ],
    related: [],
    timeline: [
      { at: daysAgo(8), actor: "ZAP Scanner", action: "Finding created" },
      { at: daysAgo(8), actor: "LLM Council", action: "Verdict: REVIEW" },
    ],
    tags: ["tls", "ssl", "deprecation", "web"],
  },
  {
    id: "FND-0026",
    severity: "info",
    title: "Docker Image Running as Root",
    description:
      "The aldeci-worker container image does not define a USER directive, defaulting to root. If the container is compromised, the attacker has root-level filesystem access.",
    source: "Trivy",
    asset: "aldeci-worker:latest",
    asset_type: "container",
    cvss: 2.5,
    status: "open",
    discovered_at: daysAgo(12),
    updated_at: daysAgo(12),
    risk_score: 12,
    verdict: "ALLOW",
    verdict_confidence: 75,
    council_models: [
      { name: "GPT-4o", verdict: "ALLOW", confidence: 77, reasoning: "Container is not internet-facing. Root in container is low risk." },
      { name: "Claude 3.5", verdict: "ALLOW", confidence: 75, reasoning: "Running as non-root is a best practice but not exploitable on its own." },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 74, reasoning: "Address in next image rebuild cycle." },
      { name: "DeepSeek V3", verdict: "ALLOW", confidence: 76, reasoning: "No direct attack vector. Defense-in-depth improvement." },
    ],
    remediation: [
      "Add `USER 1001` directive to Dockerfile before the CMD/ENTRYPOINT.",
      "Create a dedicated non-root user with minimum required permissions.",
    ],
    related: [],
    timeline: [
      { at: daysAgo(12), actor: "Trivy", action: "Finding created" },
      { at: daysAgo(12), actor: "LLM Council", action: "Verdict: ALLOW" },
    ],
    tags: ["docker", "rootless", "container", "hardening"],
  },
  {
    id: "FND-0025",
    severity: "medium",
    title: "Missing Rate Limiting on /auth/login Endpoint",
    description:
      "The /auth/login endpoint has no rate limiting. A brute-force attack can attempt unlimited password guesses without triggering any lockout or throttling mechanism.",
    source: "ZAP",
    asset: "suite-api/routers/auth_router.py",
    asset_type: "api",
    cvss: 6.5,
    status: "in_progress",
    discovered_at: daysAgo(3),
    updated_at: hoursAgo(6),
    assignee: "alex.chen",
    risk_score: 58,
    verdict: "BLOCK",
    verdict_confidence: 85,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 88, reasoning: "Brute force on login with no lockout is a critical auth weakness." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 85, reasoning: "OWASP A07:2021. Add slowloris + exponential backoff." },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 75, reasoning: "MFA adoption rate affects actual risk." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 86, reasoning: "Implement Redis-backed rate limiter with IP + user-level limits." },
    ],
    remediation: [
      "Implement rate limiting using slowapi (FastAPI): 5 attempts per 15 minutes per IP.",
      "Add exponential backoff for repeated failures.",
      "Enable account lockout after 10 failed attempts.",
      "Deploy CAPTCHA for login attempts beyond threshold.",
    ],
    related: [],
    timeline: [
      { at: daysAgo(3), actor: "ZAP Scanner", action: "Finding created" },
      { at: daysAgo(3), actor: "LLM Council", action: "Verdict: BLOCK" },
      { at: hoursAgo(6), actor: "alex.chen", action: "In progress", detail: "Implementing slowapi middleware." },
    ],
    tags: ["auth", "brute-force", "rate-limiting", "appsec"],
    file_path: "suite-api/routers/auth_router.py",
    line: 42,
    reachable: true,
  },
  {
    id: "FND-0024",
    severity: "high",
    title: "ReDoS Vulnerability in SAST Rule Regex Engine",
    description:
      "The custom regex used in the SAST rule engine for detecting SQL injection patterns is vulnerable to catastrophic backtracking (ReDoS). A crafted input can hang the scanner for minutes.",
    source: "Semgrep",
    asset: "suite-core/core/scanner_parsers.py",
    asset_type: "code",
    cvss: 7.5,
    status: "open",
    discovered_at: daysAgo(4),
    updated_at: daysAgo(4),
    risk_score: 65,
    verdict: "REVIEW",
    verdict_confidence: 78,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 80, reasoning: "DoS via scanner is a product integrity concern, not a direct breach." },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 78, reasoning: "Use re2 library instead of Python's re for untrusted input." },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 76, reasoning: "Attacker needs ability to submit findings — access controlled." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 82, reasoning: "Scanner DoS can mask real findings. Treat as high." },
    ],
    remediation: [
      "Replace backtracking regex with re2 (`pip install google-re2`).",
      "Add input length limits before regex evaluation.",
      "Add scanner timeout at 30s per file.",
    ],
    related: [
      { id: "FND-0037", title: "SQL Injection via ORM Filter", severity: "high" },
    ],
    timeline: [
      { at: daysAgo(4), actor: "Semgrep", action: "Finding created" },
      { at: daysAgo(4), actor: "LLM Council", action: "Verdict: REVIEW" },
    ],
    tags: ["regex", "redos", "dos", "appsec"],
    file_path: "suite-core/core/scanner_parsers.py",
    line: 312,
  },
  {
    id: "FND-0023",
    severity: "low",
    title: "CSP Header Missing on Dashboard Routes",
    description:
      "The Content-Security-Policy header is absent on all /mission-control/* routes. Without CSP, XSS attacks have broader impact as they can load external scripts.",
    source: "ZAP",
    asset: "suite-ui/aldeci-ui-new",
    asset_type: "api",
    cvss: 3.5,
    status: "open",
    discovered_at: daysAgo(9),
    updated_at: daysAgo(9),
    risk_score: 20,
    verdict: "ALLOW",
    verdict_confidence: 70,
    council_models: [
      { name: "GPT-4o", verdict: "ALLOW", confidence: 72, reasoning: "No known XSS vectors. CSP is defense-in-depth." },
      { name: "Claude 3.5", verdict: "ALLOW", confidence: 70, reasoning: "Internal tool. Authenticated users only." },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 65, reasoning: "Add CSP in report-only mode first, then enforce." },
      { name: "DeepSeek V3", verdict: "ALLOW", confidence: 71, reasoning: "Low risk. Add to backlog." },
    ],
    remediation: [
      "Add Content-Security-Policy header via nginx or Vite middleware.",
      "Start with CSP in report-only mode and review violations.",
      "Enforce strict CSP: `default-src 'self'; script-src 'self';`",
    ],
    related: [],
    timeline: [
      { at: daysAgo(9), actor: "ZAP Scanner", action: "Finding created" },
      { at: daysAgo(9), actor: "LLM Council", action: "Verdict: ALLOW" },
    ],
    tags: ["csp", "headers", "xss", "web"],
  },
  {
    id: "FND-0022",
    severity: "medium",
    title: "Container Registry Lacks Image Signing Policy",
    description:
      "The production container registry does not enforce Notary v2 / Sigstore image signing. Unsigned images can be deployed without provenance verification.",
    source: "Trivy",
    asset: "registry.aldeci.io",
    asset_type: "container",
    cvss: 6.0,
    status: "open",
    discovered_at: daysAgo(5),
    updated_at: daysAgo(5),
    risk_score: 52,
    verdict: "REVIEW",
    verdict_confidence: 72,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 74, reasoning: "SLSA level 2 requires signed provenance." },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 72, reasoning: "Deploy cosign signing in CI and add admission controller." },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 70, reasoning: "Gatekeeper policy can block unsigned images at admission." },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 73, reasoning: "Supply chain integrity improvement. Medium urgency." },
    ],
    remediation: [
      "Implement cosign for signing images in CI pipeline.",
      "Deploy Kyverno or OPA Gatekeeper policy to enforce signed images.",
      "Add Sigstore transparency log verification.",
    ],
    related: [
      { id: "FND-0041", title: "XZ Utils Backdoor in Base Image", severity: "critical" },
    ],
    timeline: [
      { at: daysAgo(5), actor: "Trivy", action: "Finding created" },
      { at: daysAgo(5), actor: "LLM Council", action: "Verdict: REVIEW" },
    ],
    tags: ["supply-chain", "container", "signing", "slsa"],
  },
  {
    id: "FND-0021",
    severity: "high",
    title: "Insecure Deserialization in Scanner Result Parser",
    description:
      "The scanner result parser uses `pickle.loads()` to deserialize incoming scanner payloads. An attacker controlling a scanner agent can achieve arbitrary code execution on the backend.",
    source: "Semgrep",
    asset: "suite-core/core/scanner_parsers.py",
    asset_type: "code",
    cvss: 9.8,
    epss: 0.61,
    status: "open",
    discovered_at: hoursAgo(2),
    updated_at: hoursAgo(2),
    risk_score: 91,
    verdict: "BLOCK",
    verdict_confidence: 96,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 97, reasoning: "pickle.loads on attacker-controlled data = instant RCE. No mitigation." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 96, reasoning: "Replace with JSON + schema validation. Never use pickle with external input." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 95, reasoning: "CVSS 9.8. Highest priority after CVE-2024-3094." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 97, reasoning: "Python pickle is fundamentally unsafe with untrusted input." },
    ],
    remediation: [
      "Replace `pickle.loads()` with `json.loads()` + Pydantic schema validation.",
      "Add scanner agent authentication to prevent untrusted payload injection.",
      "Audit all other uses of pickle in the codebase.",
    ],
    related: [
      { id: "FND-0037", title: "SQL Injection via ORM Filter", severity: "high" },
    ],
    timeline: [
      { at: hoursAgo(2), actor: "Semgrep", action: "Finding created" },
      { at: hoursAgo(1), actor: "LLM Council", action: "Verdict: BLOCK" },
    ],
    tags: ["deserialization", "rce", "pickle", "appsec"],
    file_path: "suite-core/core/scanner_parsers.py",
    line: 204,
    reachable: true,
  },
  {
    id: "FND-0020",
    severity: "medium",
    title: "Exposed Kubernetes Dashboard Without Authentication",
    description:
      "The Kubernetes dashboard is exposed on NodePort 30000 without authentication enabled. The skip-login token allows full cluster read access to anyone on the internal network.",
    source: "kube-bench",
    asset: "k8s://cluster-prod/kubernetes-dashboard",
    asset_type: "iac",
    cvss: 6.5,
    status: "false_positive",
    discovered_at: daysAgo(15),
    updated_at: daysAgo(10),
    risk_score: 30,
    verdict: "ALLOW",
    verdict_confidence: 62,
    council_models: [
      { name: "GPT-4o", verdict: "ALLOW", confidence: 65, reasoning: "Dashboard was removed in last patch. Likely stale finding." },
      { name: "Claude 3.5", verdict: "ALLOW", confidence: 62, reasoning: "Verify dashboard removal before closing." },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 60, reasoning: "Confirm via kubectl get pod -n kubernetes-dashboard." },
      { name: "DeepSeek V3", verdict: "ALLOW", confidence: 63, reasoning: "If removed, mark false positive." },
    ],
    remediation: ["Verify dashboard removal. If still present, enable RBAC auth or remove the NodePort service."],
    related: [
      { id: "FND-0031", title: "Kubernetes RBAC: ClusterAdmin on CI SA", severity: "high" },
    ],
    timeline: [
      { at: daysAgo(15), actor: "kube-bench", action: "Finding created" },
      { at: daysAgo(13), actor: "LLM Council", action: "Verdict: ALLOW (likely stale)" },
      { at: daysAgo(10), actor: "omar.hassan", action: "Marked false positive", detail: "Dashboard removed in k8s v1.24 upgrade." },
    ],
    tags: ["k8s", "dashboard", "auth", "network"],
  },
  {
    id: "FND-0019",
    severity: "low",
    title: "Unused IAM Role with Broad Permissions",
    description:
      "IAM role `aldeci-legacy-migration-role` has not been used in 180+ days but retains AdministratorAccess policy. Dormant but exploitable if credentials are leaked.",
    source: "Prowler",
    asset: "aws://iam/role/aldeci-legacy-migration-role",
    asset_type: "cloud",
    cvss: 3.5,
    status: "accepted_risk",
    discovered_at: daysAgo(20),
    updated_at: daysAgo(14),
    risk_score: 15,
    verdict: "ALLOW",
    verdict_confidence: 80,
    council_models: [
      { name: "GPT-4o", verdict: "ALLOW", confidence: 82, reasoning: "Unused role. Delete it to eliminate the risk entirely." },
      { name: "Claude 3.5", verdict: "ALLOW", confidence: 80, reasoning: "No recent activity. Low exploitability." },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 79, reasoning: "Add IAM Access Analyzer rule to auto-flag stale roles." },
      { name: "DeepSeek V3", verdict: "ALLOW", confidence: 81, reasoning: "Delete or scope down. Accepted risk is appropriate if documented." },
    ],
    remediation: [
      "Delete the unused IAM role.",
      "If needed, re-create with least-privilege permissions.",
      "Enable IAM Access Analyzer to detect future unused access.",
    ],
    related: [],
    timeline: [
      { at: daysAgo(20), actor: "Prowler", action: "Finding created" },
      { at: daysAgo(18), actor: "LLM Council", action: "Verdict: ALLOW" },
      { at: daysAgo(14), actor: "priya.sharma", action: "Accepted risk", detail: "Documented. Migration complete Q1." },
    ],
    tags: ["iam", "aws", "unused", "least-privilege"],
  },
  {
    id: "FND-0018",
    severity: "high",
    title: "CORS Misconfiguration Allows Arbitrary Origin",
    description:
      "The FastAPI backend reflects the Origin header verbatim with `Access-Control-Allow-Credentials: true`. This allows any origin to make authenticated cross-site requests.",
    source: "ZAP",
    asset: "suite-api/app.py",
    asset_type: "api",
    cvss: 8.1,
    epss: 0.38,
    status: "open",
    discovered_at: daysAgo(3),
    updated_at: daysAgo(3),
    risk_score: 77,
    verdict: "BLOCK",
    verdict_confidence: 91,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 93, reasoning: "Wildcard CORS + credentials is a textbook CSRF amplification path." },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 91, reasoning: "Set allow_origins to explicit list. Never use wildcard with credentials." },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 89, reasoning: "OWASP A05:2021. Fix before next deploy." },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 92, reasoning: "Authenticated cross-origin requests are exploitable via phishing." },
    ],
    remediation: [
      "Replace `allow_origins=['*']` with explicit `['https://app.aldeci.io']`.",
      "Remove `allow_credentials=True` if wildcard origins are needed.",
      "Add CSRF token protection as defense-in-depth.",
    ],
    related: [
      { id: "FND-0032", title: "Missing HSTS Header", severity: "medium" },
    ],
    timeline: [
      { at: daysAgo(3), actor: "ZAP Scanner", action: "Finding created" },
      { at: daysAgo(3), actor: "LLM Council", action: "Verdict: BLOCK" },
    ],
    tags: ["cors", "csrf", "api", "appsec"],
    file_path: "suite-api/app.py",
    line: 28,
    reachable: true,
  },
];

// ═══════════════════════════════════════════════════════════
// Helper components
// ═══════════════════════════════════════════════════════════

const SCANNERS = ["All", "Trivy", "Semgrep", "Grype", "Prowler", "Checkov", "ZAP", "kube-bench", "TruffleHog", "npm audit"];
const STATUSES: FindingStatus[] = ["open", "in_progress", "acknowledged", "resolved", "false_positive", "accepted_risk"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SOURCE_ICON: Record<string, React.ReactNode> = {
  container: <Container className="h-3.5 w-3.5" />,
  code: <Code className="h-3.5 w-3.5" />,
  cloud: <Cloud className="h-3.5 w-3.5" />,
  secrets: <KeyRound className="h-3.5 w-3.5" />,
  iac: <Server className="h-3.5 w-3.5" />,
  package: <Package className="h-3.5 w-3.5" />,
  dependency: <GitBranch className="h-3.5 w-3.5" />,
  api: <Terminal className="h-3.5 w-3.5" />,
};

function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    info: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  return (
    <Badge className={cn("border text-[10px] font-bold uppercase tracking-widest px-1.5 py-0", styles[severity])}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: FindingStatus }) {
  const styles: Record<FindingStatus, string> = {
    open: "bg-red-500/10 text-red-400 border-red-500/20",
    in_progress: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    acknowledged: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    resolved: "bg-green-500/10 text-green-400 border-green-500/20",
    false_positive: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    accepted_risk: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  };
  const labels: Record<FindingStatus, string> = {
    open: "Open",
    in_progress: "In Progress",
    acknowledged: "Acknowledged",
    resolved: "Resolved",
    false_positive: "False +",
    accepted_risk: "Risk Accepted",
  };
  return (
    <Badge className={cn("border text-[10px]", styles[status])}>
      {labels[status]}
    </Badge>
  );
}

function VerdictBadge({ verdict, confidence }: { verdict: Verdict; confidence: number }) {
  const styles: Record<Verdict, string> = {
    BLOCK: "bg-red-600/20 text-red-300 border-red-600/40",
    REVIEW: "bg-yellow-600/20 text-yellow-300 border-yellow-600/40",
    ALLOW: "bg-green-600/20 text-green-300 border-green-600/40",
    PENDING: "bg-slate-600/20 text-slate-300 border-slate-600/40",
  };
  return (
    <Badge className={cn("border text-[10px] font-bold gap-1", styles[verdict])}>
      <Brain className="h-2.5 w-2.5" />
      {verdict}
      <span className="opacity-70">{confidence}%</span>
    </Badge>
  );
}

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 80 ? "text-red-400"
    : score >= 60 ? "text-orange-400"
    : score >= 35 ? "text-yellow-400"
    : "text-green-400";
  return <span className={cn("text-xs font-bold tabular-nums", color)}>{score}</span>;
}

function AgeBadge({ date }: { date: Date }) {
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  const diffHours = Math.floor(diffMs / 3_600_000);
  const diffDays = Math.floor(diffMs / 86_400_000);
  let label: string;
  if (diffMins < 60) label = `${diffMins}m`;
  else if (diffHours < 24) label = `${diffHours}h`;
  else label = `${diffDays}d`;
  return (
    <span className="text-xs text-muted-foreground tabular-nums">{label}</span>
  );
}

function SortIcon({ field, sortField, sortDir }: { field: string; sortField: string | null; sortDir: "asc" | "desc" | null }) {
  if (sortField !== field) return <ChevronsUpDown className="h-3 w-3 ml-1 opacity-30" />;
  if (sortDir === "asc") return <ChevronUp className="h-3 w-3 ml-1 text-primary" />;
  return <ChevronDown className="h-3 w-3 ml-1 text-primary" />;
}

// ═══════════════════════════════════════════════════════════
// Detail Slide-out Panel
// ═══════════════════════════════════════════════════════════

function DetailPanel({ finding, onClose, onStatusChange }: {
  finding: Finding;
  onClose: () => void;
  onStatusChange: (id: string, status: FindingStatus) => void;
}) {
  return (
    <motion.div
      initial={{ x: "100%", opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: "100%", opacity: 0 }}
      transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
      className="fixed inset-y-0 right-0 z-50 flex w-[520px] flex-col border-l border-border bg-card shadow-xl"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-mono text-muted-foreground">{finding.id}</span>
            <SeverityBadge severity={finding.severity} />
            {finding.kev && (
              <Badge className="border bg-red-700/25 text-red-300 border-red-700/50 text-[10px] font-bold gap-1">
                <TriangleAlert className="h-2.5 w-2.5" /> KEV
              </Badge>
            )}
          </div>
          <h2 className="text-sm font-semibold leading-snug line-clamp-2">{finding.title}</h2>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 rounded-md p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
         aria-label="Close"><X className="h-4 w-4" /></button>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-5 space-y-5">
          {/* Meta row */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="space-y-0.5">
              <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Status</span>
              <div><StatusBadge status={finding.status} /></div>
            </div>
            <div className="space-y-0.5">
              <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Risk Score</span>
              <div className="text-lg font-bold"><RiskScore score={finding.risk_score} /></div>
            </div>
            <div className="space-y-0.5">
              <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Scanner</span>
              <div className="font-medium">{finding.source}</div>
            </div>
            <div className="space-y-0.5">
              <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Asset</span>
              <div className="font-medium font-mono text-xs truncate" title={finding.asset}>{finding.asset}</div>
            </div>
            {finding.cve && (
              <div className="space-y-0.5">
                <span className="text-muted-foreground uppercase tracking-wider text-[10px]">CVE</span>
                <div className="flex items-center gap-1">
                  <span className="font-mono text-xs">{finding.cve}</span>
                  <ExternalLink className="h-3 w-3 text-muted-foreground" />
                </div>
              </div>
            )}
            {finding.cvss != null && (
              <div className="space-y-0.5">
                <span className="text-muted-foreground uppercase tracking-wider text-[10px]">CVSS</span>
                <div className={cn(
                  "font-bold tabular-nums text-sm",
                  finding.cvss >= 9 ? "text-red-400" : finding.cvss >= 7 ? "text-orange-400" : finding.cvss >= 4 ? "text-yellow-400" : "text-green-400"
                )}>{finding.cvss.toFixed(1)}</div>
              </div>
            )}
            {finding.epss != null && (
              <div className="space-y-0.5">
                <span className="text-muted-foreground uppercase tracking-wider text-[10px]">EPSS</span>
                <div className="font-medium">{Math.round(finding.epss * 100)}%</div>
              </div>
            )}
            {finding.assignee && (
              <div className="space-y-0.5">
                <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Assignee</span>
                <div className="flex items-center gap-1.5">
                  <div className="h-4 w-4 rounded-full bg-primary/20 flex items-center justify-center text-[8px] font-bold text-primary">
                    {finding.assignee[0].toUpperCase()}
                  </div>
                  <span className="font-medium">{finding.assignee}</span>
                </div>
              </div>
            )}
          </div>

          {/* Description */}
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Description</p>
            <p className="text-sm text-muted-foreground leading-relaxed">{finding.description}</p>
          </div>

          {finding.file_path && (
            <div className="rounded-lg bg-muted/40 px-3 py-2.5 font-mono text-xs text-muted-foreground flex items-center gap-2">
              <FileText className="h-3.5 w-3.5 shrink-0" />
              <span className="truncate">{finding.file_path}</span>
              {finding.line && <span className="shrink-0 text-primary">:{finding.line}</span>}
            </div>
          )}

          <Separator />

          {/* LLM Council Verdict */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                <Brain className="h-3.5 w-3.5 text-primary" />
                LLM Council Verdict
              </p>
              <VerdictBadge verdict={finding.verdict} confidence={finding.verdict_confidence} />
            </div>
            <div className="space-y-2">
              {finding.council_models.map((model) => (
                <div key={model.name} className="rounded-lg border border-border bg-muted/20 p-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-semibold">{model.name}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-muted-foreground tabular-nums">{model.confidence}%</span>
                      <VerdictBadge verdict={model.verdict} confidence={model.confidence} />
                    </div>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">{model.reasoning}</p>
                </div>
              ))}
            </div>
          </div>

          <Separator />

          {/* Remediation steps */}
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-3">Remediation Steps</p>
            <ol className="space-y-2">
              {finding.remediation.map((step, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  <span className="shrink-0 h-5 w-5 rounded-full bg-primary/10 text-primary text-[10px] font-bold flex items-center justify-center mt-0.5">
                    {i + 1}
                  </span>
                  <span className="text-muted-foreground leading-relaxed">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* Tags */}
          {finding.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {finding.tags.map((tag) => (
                <span key={tag} className="rounded-md bg-muted/50 px-2 py-0.5 text-[10px] text-muted-foreground font-mono">
                  #{tag}
                </span>
              ))}
            </div>
          )}

          {/* Related findings */}
          {finding.related.length > 0 && (
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Related Findings</p>
              <div className="space-y-1.5">
                {finding.related.map((rel) => (
                  <div key={rel.id} className="flex items-center gap-2 rounded-md border border-border px-3 py-2">
                    <SeverityBadge severity={rel.severity} />
                    <span className="text-xs font-mono text-muted-foreground">{rel.id}</span>
                    <span className="text-xs text-foreground truncate flex-1">{rel.title}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <Separator />

          {/* Timeline */}
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-3">Timeline</p>
            <div className="relative pl-4">
              <div className="absolute left-1.5 top-0 bottom-0 w-px bg-border" />
              <div className="space-y-4">
                {finding.timeline.map((event, i) => (
                  <div key={i} className="relative">
                    <div className="absolute -left-[11px] top-1 h-2 w-2 rounded-full bg-primary ring-2 ring-background" />
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-xs font-medium">{event.action}</span>
                        <span className="text-[10px] text-muted-foreground">by {event.actor}</span>
                      </div>
                      {event.detail && (
                        <p className="text-[11px] text-muted-foreground">{event.detail}</p>
                      )}
                      <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                        {event.at.toLocaleString()}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </ScrollArea>

      {/* Footer actions */}
      <div className="border-t border-border p-4">
        <div className="flex items-center gap-2">
          <Select
            value={finding.status}
            onValueChange={(v) => onStatusChange(finding.id, v as FindingStatus)}
          >
            <SelectTrigger className="h-8 text-xs flex-1">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map((s) => (
                <SelectItem key={s} value={s} className="text-xs">
                  {s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button size="sm" variant="outline" className="h-8 text-xs gap-1.5">
            <UserCheck className="h-3.5 w-3.5" />
            Assign
          </Button>
          <Button size="sm" className="h-8 text-xs gap-1.5">
            <ExternalLink className="h-3.5 w-3.5" />
            Open Ticket
          </Button>
        </div>
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

const PAGE_SIZE = 10;

export default function FindingsExplorer() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [scannerFilter, setScannerFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "all">("all");
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "all">("all");
  const [sortField, setSortField] = useState<string | null>("risk_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc" | null>("desc");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [activeDetail, setActiveDetail] = useState<Finding | null>(null);
  const [findings, setFindings] = useState<Finding[]>(MOCK_FINDINGS);
  const [showFilters, setShowFilters] = useState(false);

  // Derived KPIs
  const kpis = useMemo(() => {
    const critical = findings.filter((f) => f.severity === "critical").length;
    const high = findings.filter((f) => f.severity === "high").length;
    const open = findings.filter((f) => f.status === "open").length;
    const kev = findings.filter((f) => f.kev).length;
    const blocked = findings.filter((f) => f.verdict === "BLOCK").length;
    const avgRisk = findings.length
      ? Math.round(findings.reduce((acc, f) => acc + f.risk_score, 0) / findings.length)
      : 0;
    return { critical, high, open, kev, blocked, avgRisk };
  }, [findings]);

  // Filter + sort
  const filtered = useMemo(() => {
    let result = findings.filter((f) => {
      if (search) {
        const q = search.toLowerCase();
        if (
          !f.title.toLowerCase().includes(q) &&
          !f.id.toLowerCase().includes(q) &&
          !(f.cve?.toLowerCase().includes(q)) &&
          !f.asset.toLowerCase().includes(q) &&
          !f.source.toLowerCase().includes(q)
        ) return false;
      }
      if (severityFilter !== "all" && f.severity !== severityFilter) return false;
      if (scannerFilter !== "All" && f.source !== scannerFilter) return false;
      if (statusFilter !== "all" && f.status !== statusFilter) return false;
      if (verdictFilter !== "all" && f.verdict !== verdictFilter) return false;
      return true;
    });

    if (sortField) {
      result = [...result].sort((a, b) => {
        let av: number | string, bv: number | string;
        if (sortField === "risk_score") { av = a.risk_score; bv = b.risk_score; }
        else if (sortField === "cvss") { av = a.cvss ?? -1; bv = b.cvss ?? -1; }
        else if (sortField === "discovered_at") { av = a.discovered_at.getTime(); bv = b.discovered_at.getTime(); }
        else if (sortField === "severity") {
          const order: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          av = order[a.severity] ?? 0; bv = order[b.severity] ?? 0;
        }
        else { av = a.id; bv = b.id; }
        const cmp = typeof av === "number" ? av - (bv as number) : (av as string).localeCompare(bv as string);
        return sortDir === "asc" ? cmp : -cmp;
      });
    }

    return result;
  }, [findings, search, severityFilter, scannerFilter, statusFilter, verdictFilter, sortField, sortDir]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const allOnPageSelected = paginated.length > 0 && paginated.every((f) => selected.has(f.id));

  const toggleSort = useCallback((field: string) => {
    if (sortField !== field) { setSortField(field); setSortDir("desc"); }
    else if (sortDir === "desc") setSortDir("asc");
    else { setSortField(null); setSortDir(null); }
    setPage(1);
  }, [sortField, sortDir]);

  const toggleSelectAll = useCallback(() => {
    if (allOnPageSelected) {
      setSelected((prev) => { const next = new Set(prev); paginated.forEach((f) => next.delete(f.id)); return next; });
    } else {
      setSelected((prev) => { const next = new Set(prev); paginated.forEach((f) => next.add(f.id)); return next; });
    }
  }, [allOnPageSelected, paginated]);

  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => { const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next; });
  }, []);

  const handleStatusChange = useCallback((id: string, status: FindingStatus) => {
    setFindings((prev) => prev.map((f) => f.id === id ? { ...f, status } : f));
    if (activeDetail?.id === id) setActiveDetail((prev) => prev ? { ...prev, status } : prev);
  }, [activeDetail]);

  const bulkAcknowledge = useCallback(() => {
    setFindings((prev) => prev.map((f) => selected.has(f.id) ? { ...f, status: "acknowledged" } : f));
    setSelected(new Set());
  }, [selected]);

  const bulkResolve = useCallback(() => {
    setFindings((prev) => prev.map((f) => selected.has(f.id) ? { ...f, status: "resolved" } : f));
    setSelected(new Set());
  }, [selected]);

  // Close detail when clicking outside
  useEffect(() => {
    if (!activeDetail) return;
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") setActiveDetail(null); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [activeDetail]);

  return (
    <TooltipProvider>
      <div className="space-y-6 pb-16">
        {/* Header */}
        <PageHeader
          title="Findings Explorer"
          description="Unified view of all security findings across scanners, clouds, and code. Every persona's ground truth."
          badge="CORE"
          actions={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5">
                <RefreshCw className="h-3.5 w-3.5" />
                Refresh
              </Button>
              <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5">
                <Download className="h-3.5 w-3.5" />
                Export
              </Button>
            </div>
          }
        />

        {/* KPI Strip */}
        <motion.div
          className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, staggerChildren: 0.05 }}
        >
          <KpiCard
            title="Critical"
            value={kpis.critical}
            icon={Flame}
            trendLabel="Requires immediate action"
            trend="down"
            className="border-red-500/20"
            onClick={() => { setSeverityFilter("critical"); setPage(1); }}
          />
          <KpiCard
            title="High"
            value={kpis.high}
            icon={TriangleAlert}
            trendLabel="High severity findings"
            trend="down"
            className="border-orange-500/20"
            onClick={() => { setSeverityFilter("high"); setPage(1); }}
          />
          <KpiCard
            title="Open"
            value={kpis.open}
            icon={CircleDot}
            trendLabel="Awaiting triage"
            className="border-border"
            onClick={() => { setStatusFilter("open"); setPage(1); }}
          />
          <KpiCard
            title="KEV Listed"
            value={kpis.kev}
            icon={Zap}
            trendLabel="CISA Known Exploited"
            trend="down"
            className="border-red-500/20"
          />
          <KpiCard
            title="BLOCK Verdict"
            value={kpis.blocked}
            icon={Shield}
            trendLabel="LLM Council: stop deployment"
            trend="down"
            className="border-border"
            onClick={() => { setVerdictFilter("BLOCK"); setPage(1); }}
          />
          <KpiCard
            title="Avg Risk Score"
            value={kpis.avgRisk}
            icon={Activity}
            trendLabel="Composite across all findings"
            className="border-border"
          />
        </motion.div>

        {/* Filter Bar */}
        <Card className="p-0 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
              <Input
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search findings, CVE, asset, scanner..."
                className="pl-9 h-8 text-xs"
              />
              {search && (
                <button
                  onClick={() => { setSearch(""); setPage(1); }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>

            <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v as Severity | "all"); setPage(1); }}>
              <SelectTrigger className="h-8 w-[120px] text-xs">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All Severities</SelectItem>
                {SEVERITIES.map((s) => <SelectItem key={s} value={s} className="text-xs capitalize">{s}</SelectItem>)}
              </SelectContent>
            </Select>

            <Select value={scannerFilter} onValueChange={(v) => { setScannerFilter(v); setPage(1); }}>
              <SelectTrigger className="h-8 w-[130px] text-xs">
                <SelectValue placeholder="Scanner" />
              </SelectTrigger>
              <SelectContent>
                {SCANNERS.map((s) => <SelectItem key={s} value={s} className="text-xs">{s}</SelectItem>)}
              </SelectContent>
            </Select>

            <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v as FindingStatus | "all"); setPage(1); }}>
              <SelectTrigger className="h-8 w-[140px] text-xs">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All Statuses</SelectItem>
                {STATUSES.map((s) => (
                  <SelectItem key={s} value={s} className="text-xs">
                    {s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={verdictFilter} onValueChange={(v) => { setVerdictFilter(v as Verdict | "all"); setPage(1); }}>
              <SelectTrigger className="h-8 w-[120px] text-xs">
                <SelectValue placeholder="Verdict" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All Verdicts</SelectItem>
                {(["BLOCK", "REVIEW", "ALLOW", "PENDING"] as Verdict[]).map((v) => (
                  <SelectItem key={v} value={v} className="text-xs">{v}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
              <span>{filtered.length} findings</span>
              {(severityFilter !== "all" || scannerFilter !== "All" || statusFilter !== "all" || verdictFilter !== "all" || search) && (
                <button
                  onClick={() => { setSeverityFilter("all"); setScannerFilter("All"); setStatusFilter("all"); setVerdictFilter("all"); setSearch(""); setPage(1); }}
                  className="flex items-center gap-1 text-primary hover:text-primary/80 transition-colors"
                >
                  <X className="h-3 w-3" /> Clear
                </button>
              )}
            </div>
          </div>

          {/* Bulk action bar */}
          <AnimatePresence>
            {selected.size > 0 && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="flex items-center gap-3 px-4 py-2.5 bg-primary/5 border-b border-primary/20">
                  <span className="text-xs font-medium text-primary">
                    {selected.size} selected
                  </span>
                  <Separator orientation="vertical" className="h-4" />
                  <button
                    onClick={bulkAcknowledge}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Acknowledge
                  </button>
                  <button
                    onClick={bulkResolve}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <Archive className="h-3.5 w-3.5" />
                    Mark Resolved
                  </button>
                  <button className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
                    <UserCheck className="h-3.5 w-3.5" />
                    Assign
                  </button>
                  <button className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
                    <Download className="h-3.5 w-3.5" />
                    Export
                  </button>
                  <button
                    onClick={() => setSelected(new Set())}
                    className="ml-auto text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Table */}
          <div className="overflow-x-auto">
            <table role="table" className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/20">
                  <th className="px-4 py-2.5 w-10">
                    <Checkbox
                      checked={allOnPageSelected}
                      onCheckedChange={toggleSelectAll}
                      className="h-3.5 w-3.5"
                    />
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    ID
                  </th>
                  <th
                    className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px] cursor-pointer hover:text-foreground"
                    onClick={() => toggleSort("severity")}
                  >
                    <span className="flex items-center">
                      Severity <SortIcon field="severity" sortField={sortField} sortDir={sortDir} />
                    </span>
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    Title
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    Scanner
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    CVE
                  </th>
                  <th
                    className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px] cursor-pointer hover:text-foreground"
                    onClick={() => toggleSort("cvss")}
                  >
                    <span className="flex items-center">
                      CVSS <SortIcon field="cvss" sortField={sortField} sortDir={sortDir} />
                    </span>
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    Status
                  </th>
                  <th
                    className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px] cursor-pointer hover:text-foreground"
                    onClick={() => toggleSort("discovered_at")}
                  >
                    <span className="flex items-center">
                      Age <SortIcon field="discovered_at" sortField={sortField} sortDir={sortDir} />
                    </span>
                  </th>
                  <th
                    className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px] cursor-pointer hover:text-foreground"
                    onClick={() => toggleSort("risk_score")}
                  >
                    <span className="flex items-center">
                      Risk <SortIcon field="risk_score" sortField={sortField} sortDir={sortDir} />
                    </span>
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    Verdict
                  </th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {paginated.map((finding, i) => (
                    <motion.tr
                      key={finding.id}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15, delay: i * 0.02 }}
                      onClick={() => setActiveDetail(finding)}
                      className={cn(
                        "border-b border-border/50 cursor-pointer transition-colors",
                        selected.has(finding.id) ? "bg-primary/5" : "hover:bg-muted/30",
                        activeDetail?.id === finding.id && "bg-primary/8 border-l-2 border-l-primary"
                      )}
                    >
                      <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={selected.has(finding.id)}
                          onCheckedChange={() => toggleSelect(finding.id)}
                          className="h-3.5 w-3.5"
                        />
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="font-mono text-muted-foreground">{finding.id}</span>
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="px-3 py-2.5 max-w-[280px]">
                        <div className="flex items-start gap-2">
                          <span className="shrink-0 text-muted-foreground mt-0.5">
                            {SOURCE_ICON[finding.asset_type]}
                          </span>
                          <div className="min-w-0">
                            <div className="truncate font-medium text-foreground">{finding.title}</div>
                            <div className="truncate text-muted-foreground text-[10px] mt-0.5">{finding.asset}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="text-muted-foreground">{finding.source}</span>
                      </td>
                      <td className="px-3 py-2.5">
                        {finding.cve ? (
                          <span className="font-mono text-[10px] text-cyan-400">{finding.cve}</span>
                        ) : (
                          <span className="text-muted-foreground/40">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        {finding.cvss != null ? (
                          <span className={cn(
                            "font-bold tabular-nums",
                            finding.cvss >= 9 ? "text-red-400" : finding.cvss >= 7 ? "text-orange-400" : finding.cvss >= 4 ? "text-yellow-400" : "text-green-400"
                          )}>
                            {finding.cvss.toFixed(1)}
                          </span>
                        ) : (
                          <span className="text-muted-foreground/40">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <StatusBadge status={finding.status} />
                      </td>
                      <td className="px-3 py-2.5">
                        <AgeBadge date={finding.discovered_at} />
                      </td>
                      <td className="px-3 py-2.5">
                        <RiskScore score={finding.risk_score} />
                      </td>
                      <td className="px-3 py-2.5">
                        <VerdictBadge verdict={finding.verdict} confidence={finding.verdict_confidence} />
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>

                {paginated.length === 0 && (
                  <tr>
                    <td colSpan={11} className="px-4 py-16 text-center text-muted-foreground">
                      <div className="flex flex-col items-center gap-3">
                        <Shield className="h-10 w-10 opacity-20" />
                        <span className="text-sm">No findings match the current filters.</span>
                        <button
                          onClick={() => { setSeverityFilter("all"); setScannerFilter("All"); setStatusFilter("all"); setVerdictFilter("all"); setSearch(""); }}
                          className="text-xs text-primary hover:text-primary/80 transition-colors"
                        >
                          Clear all filters
                        </button>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-border">
              <span className="text-xs text-muted-foreground">
                Showing {Math.min((page - 1) * PAGE_SIZE + 1, filtered.length)}–{Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length}
              </span>
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </Button>
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let pageNum: number;
                  if (totalPages <= 5) pageNum = i + 1;
                  else if (page <= 3) pageNum = i + 1;
                  else if (page >= totalPages - 2) pageNum = totalPages - 4 + i;
                  else pageNum = page - 2 + i;
                  return (
                    <Button
                      key={pageNum}
                      variant={page === pageNum ? "default" : "ghost"}
                      size="icon"
                      className="h-7 w-7 text-xs"
                      onClick={() => setPage(pageNum)}
                    >
                      {pageNum}
                    </Button>
                  );
                })}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* Detail Slide-out */}
      <AnimatePresence>
        {activeDetail && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
              onClick={() => setActiveDetail(null)}
            />
            <DetailPanel
              finding={activeDetail}
              onClose={() => setActiveDetail(null)}
              onStatusChange={handleStatusChange}
            />
          </>
        )}
      </AnimatePresence>
    </TooltipProvider>
  );
}
