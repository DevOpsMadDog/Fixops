/**
 * SOC Tier 1 Alert Triage Dashboard — P03 Persona
 *
 * Designed for SOC analysts running long shifts on wall displays and laptops.
 * Information-dense, dark-first, high-contrast severity signals.
 * LLM Council verdicts shown inline with model-agreement tooltips.
 *
 * Route: /mission-control/soc
 */

import { useState, useMemo, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, AlertTriangle, Clock, CheckCircle2, XCircle,
  ChevronUp, ChevronDown, Search, Filter, RefreshCw,
  ArrowUpRight, Minus, ChevronsUp, Flame, User, Eye,
  GitBranch, Layers, Terminal, Server, Package, Cloud,
  Bug, Code, KeyRound, Container, SlidersHorizontal,
  CircleCheck, Ban,
  TriangleAlert, Activity, Timer,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low";
type Verdict = "BLOCK" | "REVIEW" | "ALLOW";
type AlertStatus = "new" | "in_progress" | "resolved" | "false_positive";

interface CouncilModel {
  name: string;
  verdict: Verdict;
  confidence: number;
}

interface Alert {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  source: string;
  source_icon: string;
  verdict: Verdict;
  verdict_confidence: number;
  council_models: CouncilModel[];
  cvss: number;
  cve?: string;
  discovered_at: Date;
  status: AlertStatus;
  assignee?: string;
  asset: string;
  asset_type: "container" | "code" | "cloud" | "secrets" | "iac" | "package";
  remediation_hint?: string;
  tags: string[];
}

// ═══════════════════════════════════════════════════════════
// Mock data — realistic SOC alert queue
// ═══════════════════════════════════════════════════════════

const now = new Date();
const minsAgo = (m: number) => new Date(now.getTime() - m * 60_000);
const hoursAgo = (h: number) => new Date(now.getTime() - h * 3_600_000);
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000);

const MOCK_ALERTS: Alert[] = [
  {
    id: "ALT-0041",
    severity: "critical",
    title: "CVE-2024-3094: XZ Utils Backdoor Detected in Base Image",
    description: "liblzma.so linked in production container image aldeci-api:v2.3.1 matches known backdoor signature. Remote code execution risk on systemd-linked hosts.",
    source: "Trivy",
    source_icon: "trivy",
    verdict: "BLOCK",
    verdict_confidence: 98,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 99 },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 98 },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 97 },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 96 },
    ],
    cvss: 10.0,
    cve: "CVE-2024-3094",
    discovered_at: minsAgo(8),
    status: "new",
    asset: "aldeci-api:v2.3.1",
    asset_type: "container",
    remediation_hint: "Rebuild image from debian:bookworm-slim base. Remove xz-utils 5.6.0-5.6.1.",
    tags: ["supply-chain", "rce", "container"],
  },
  {
    id: "ALT-0040",
    severity: "critical",
    title: "Hardcoded AWS Credentials in Production Dockerfile",
    description: "AWS_SECRET_ACCESS_KEY found in plaintext in Dockerfile. Key is active with broad S3 and EC2 permissions. Immediate rotation required.",
    source: "Semgrep",
    source_icon: "semgrep",
    verdict: "BLOCK",
    verdict_confidence: 99,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 100 },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 99 },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 99 },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 98 },
    ],
    cvss: 9.8,
    discovered_at: minsAgo(23),
    status: "in_progress",
    assignee: "jsmith",
    asset: "services/api/Dockerfile",
    asset_type: "secrets",
    remediation_hint: "Rotate key immediately. Move to AWS Secrets Manager or environment injection.",
    tags: ["secrets", "iam", "critical-path"],
  },
  {
    id: "ALT-0039",
    severity: "critical",
    title: "SQL Injection via Unsanitized ORM Filter",
    description: "User-controlled input passed directly to SQLAlchemy filter() in /api/v1/findings endpoint. Confirmed exploitable via blind UNION injection.",
    source: "Semgrep",
    source_icon: "semgrep",
    verdict: "BLOCK",
    verdict_confidence: 95,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 97 },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 96 },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 72 },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 94 },
    ],
    cvss: 9.1,
    discovered_at: minsAgo(47),
    status: "new",
    asset: "suite-api/routers/findings_router.py",
    asset_type: "code",
    remediation_hint: "Use parameterized queries. Apply SQLAlchemy bindparam() for all user inputs.",
    tags: ["injection", "api", "owasp-a03"],
  },
  {
    id: "ALT-0038",
    severity: "high",
    title: "Unauthenticated Prometheus Metrics Endpoint Exposed",
    description: "Node exporter metrics endpoint accessible without auth on port 9100. Leaks internal hostnames, resource usage, and service topology.",
    source: "Trivy",
    source_icon: "trivy",
    verdict: "BLOCK",
    verdict_confidence: 88,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 91 },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 89 },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 85 },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 78 },
    ],
    cvss: 7.5,
    discovered_at: hoursAgo(2),
    status: "new",
    asset: "k8s/monitoring/prometheus-node-exporter.yaml",
    asset_type: "iac",
    remediation_hint: "Add NetworkPolicy to restrict port 9100 to monitoring namespace only.",
    tags: ["exposure", "kubernetes", "monitoring"],
  },
  {
    id: "ALT-0037",
    severity: "high",
    title: "CVE-2024-21762: Fortinet FortiOS Out-of-Bounds Write",
    description: "Fortinet FortiOS 7.4.2 detected in SBOM dependency chain via fortios-sdk-python. Out-of-bounds write vulnerability enabling RCE.",
    source: "Snyk",
    source_icon: "snyk",
    verdict: "REVIEW",
    verdict_confidence: 82,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 85 },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 80 },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 79 },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 82 },
    ],
    cvss: 9.6,
    cve: "CVE-2024-21762",
    discovered_at: hoursAgo(3),
    status: "in_progress",
    assignee: "mchen",
    asset: "requirements.txt → fortios-sdk-python",
    asset_type: "package",
    remediation_hint: "Upgrade fortios-sdk-python to >=7.4.3. Verify transitive deps.",
    tags: ["cve", "supply-chain", "rce"],
  },
  {
    id: "ALT-0036",
    severity: "high",
    title: "S3 Bucket with Public Read ACL — Production Data",
    description: "S3 bucket aldeci-prod-exports has AllUsers READ permission. Contains CSV exports of finding data, which may include PII.",
    source: "Prowler",
    source_icon: "prowler",
    verdict: "BLOCK",
    verdict_confidence: 94,
    council_models: [
      { name: "GPT-4o", verdict: "BLOCK", confidence: 96 },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 94 },
      { name: "Gemini 1.5", verdict: "BLOCK", confidence: 93 },
      { name: "DeepSeek V3", verdict: "BLOCK", confidence: 92 },
    ],
    cvss: 7.2,
    discovered_at: hoursAgo(5),
    status: "new",
    asset: "s3://aldeci-prod-exports",
    asset_type: "cloud",
    remediation_hint: "Set bucket ACL to private. Enable S3 Block Public Access at account level.",
    tags: ["s3", "public-exposure", "gdpr"],
  },
  {
    id: "ALT-0035",
    severity: "high",
    title: "Dependency Confusion Risk: Internal Package Name Squatted",
    description: "Package 'aldeci-core' registered on public PyPI by unknown actor. Typosquatting or dependency confusion attack vector detected.",
    source: "Snyk",
    source_icon: "snyk",
    verdict: "REVIEW",
    verdict_confidence: 76,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 80 },
      { name: "Claude 3.5", verdict: "BLOCK", confidence: 82 },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 72 },
      { name: "DeepSeek V3", verdict: "ALLOW", confidence: 55 },
    ],
    cvss: 8.1,
    discovered_at: hoursAgo(7),
    status: "new",
    asset: "pypi://aldeci-core",
    asset_type: "package",
    remediation_hint: "Claim package on PyPI. Pin all internal packages to private registry.",
    tags: ["supply-chain", "dependency-confusion"],
  },
  {
    id: "ALT-0034",
    severity: "medium",
    title: "Missing HSTS Header on Public API Gateway",
    description: "api.aldeci.internal does not send Strict-Transport-Security header. Allows downgrade attacks on TLS connections.",
    source: "Semgrep",
    source_icon: "semgrep",
    verdict: "REVIEW",
    verdict_confidence: 71,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 75 },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 70 },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 60 },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 68 },
    ],
    cvss: 5.3,
    discovered_at: hoursAgo(12),
    status: "in_progress",
    assignee: "agarcia",
    asset: "suite-api/middleware/security_headers.py",
    asset_type: "code",
    remediation_hint: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    tags: ["tls", "headers", "owasp-a05"],
  },
  {
    id: "ALT-0033",
    severity: "medium",
    title: "Terraform State File in Unencrypted S3 Bucket",
    description: "terraform.tfstate found in s3://aldeci-infra-state without server-side encryption. Contains IAM keys and database passwords.",
    source: "Checkov",
    source_icon: "checkov",
    verdict: "REVIEW",
    verdict_confidence: 68,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 72 },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 68 },
      { name: "Gemini 1.5", verdict: "REVIEW", confidence: 65 },
      { name: "DeepSeek V3", verdict: "ALLOW", confidence: 58 },
    ],
    cvss: 6.1,
    discovered_at: hoursAgo(18),
    status: "new",
    asset: "infra/terraform/backend.tf",
    asset_type: "iac",
    remediation_hint: "Enable S3 SSE-KMS. Move secrets to Vault or AWS Secrets Manager.",
    tags: ["iac", "terraform", "secrets-exposure"],
  },
  {
    id: "ALT-0032",
    severity: "medium",
    title: "React XSS via dangerouslySetInnerHTML in Copilot Sidebar",
    description: "dangerouslySetInnerHTML used with unsanitized LLM response content in CopilotSidebar component. Potential stored XSS if LLM output is compromised.",
    source: "Semgrep",
    source_icon: "semgrep",
    verdict: "REVIEW",
    verdict_confidence: 64,
    council_models: [
      { name: "GPT-4o", verdict: "REVIEW", confidence: 68 },
      { name: "Claude 3.5", verdict: "REVIEW", confidence: 65 },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 55 },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 62 },
    ],
    cvss: 5.8,
    discovered_at: daysAgo(1),
    status: "in_progress",
    assignee: "jsmith",
    asset: "suite-ui/aldeci-ui-new/src/components/layout/CopilotSidebar.tsx",
    asset_type: "code",
    remediation_hint: "Use DOMPurify.sanitize() before dangerouslySetInnerHTML. Prefer markdown renderer.",
    tags: ["xss", "frontend", "owasp-a03"],
  },
  {
    id: "ALT-0031",
    severity: "low",
    title: "Outdated OpenSSL Version in Alpine Base (3.1.4 → 3.3.1)",
    description: "Container base image uses Alpine 3.18 with OpenSSL 3.1.4. Latest is 3.3.1. No known critical CVEs but security hygiene issue.",
    source: "Trivy",
    source_icon: "trivy",
    verdict: "ALLOW",
    verdict_confidence: 89,
    council_models: [
      { name: "GPT-4o", verdict: "ALLOW", confidence: 90 },
      { name: "Claude 3.5", verdict: "ALLOW", confidence: 88 },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 87 },
      { name: "DeepSeek V3", verdict: "REVIEW", confidence: 55 },
    ],
    cvss: 3.1,
    discovered_at: daysAgo(2),
    status: "resolved",
    assignee: "mchen",
    asset: "docker/base/Dockerfile",
    asset_type: "container",
    remediation_hint: "Update base to alpine:3.20. Rebuild and push.",
    tags: ["dependency-update", "openssl"],
  },
  {
    id: "ALT-0030",
    severity: "low",
    title: "Debug Logging Enabled in Production Config",
    description: "LOG_LEVEL=DEBUG set in production .env. May expose sensitive request payloads and stack traces in log aggregators.",
    source: "Semgrep",
    source_icon: "semgrep",
    verdict: "ALLOW",
    verdict_confidence: 92,
    council_models: [
      { name: "GPT-4o", verdict: "ALLOW", confidence: 93 },
      { name: "Claude 3.5", verdict: "ALLOW", confidence: 92 },
      { name: "Gemini 1.5", verdict: "ALLOW", confidence: 91 },
      { name: "DeepSeek V3", verdict: "ALLOW", confidence: 90 },
    ],
    cvss: 2.1,
    discovered_at: daysAgo(3),
    status: "false_positive",
    asset: "docker/production/.env.example",
    asset_type: "code",
    tags: ["config", "logging"],
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

function ageUrgency(date: Date): "fresh" | "aging" | "stale" {
  const hours = (Date.now() - date.getTime()) / 3_600_000;
  if (hours < 1) return "fresh";
  if (hours < 24) return "aging";
  return "stale";
}

// ═══════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════

function SeverityBadge({ severity }: { severity: Severity }) {
  const configs: Record<Severity, { label: string; className: string; pulse?: boolean }> = {
    critical: {
      label: "CRITICAL",
      className: "bg-red-500/20 text-red-400 border-red-500/30 border font-mono font-bold tracking-widest",
      pulse: true,
    },
    high: {
      label: "HIGH",
      className: "bg-orange-500/20 text-orange-400 border-orange-500/30 border font-mono font-semibold tracking-wider",
    },
    medium: {
      label: "MED",
      className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30 border font-mono tracking-wide",
    },
    low: {
      label: "LOW",
      className: "bg-blue-500/20 text-blue-400 border-blue-500/30 border font-mono",
    },
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

function VerdictChip({
  verdict,
  confidence,
  models,
}: {
  verdict: Verdict;
  confidence: number;
  models: CouncilModel[];
}) {
  const configs: Record<Verdict, { label: string; className: string; icon: React.ReactNode }> = {
    BLOCK: {
      label: "BLOCK",
      className: "bg-red-500/15 text-red-400 border-red-500/25 border",
      icon: <Ban className="h-2.5 w-2.5" />,
    },
    REVIEW: {
      label: "REVIEW",
      className: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25 border",
      icon: <Eye className="h-2.5 w-2.5" />,
    },
    ALLOW: {
      label: "ALLOW",
      className: "bg-green-500/15 text-green-400 border-green-500/25 border",
      icon: <CircleCheck className="h-2.5 w-2.5" />,
    },
  };
  const cfg = configs[verdict];
  const agreementCount = models.filter((m) => m.verdict === verdict).length;

  return (
    <TooltipProvider delayDuration={120}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold cursor-help",
              cfg.className
            )}
          >
            {cfg.icon}
            {cfg.label}
            <span className="opacity-60 tabular-nums">{confidence}%</span>
          </span>
        </TooltipTrigger>
        <TooltipContent side="left" className="p-3 w-56">
          <p className="text-xs font-semibold mb-2 text-muted-foreground uppercase tracking-wider">
            LLM Council — {agreementCount}/{models.length} agree
          </p>
          <div className="space-y-1.5">
            {models.map((m) => (
              <div key={m.name} className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{m.name}</span>
                <div className="flex items-center gap-1.5">
                  <span
                    className={cn(
                      "font-mono font-semibold text-[10px]",
                      m.verdict === "BLOCK"
                        ? "text-red-400"
                        : m.verdict === "REVIEW"
                          ? "text-yellow-400"
                          : "text-green-400"
                    )}
                  >
                    {m.verdict}
                  </span>
                  <span className="text-muted-foreground tabular-nums">{m.confidence}%</span>
                </div>
              </div>
            ))}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

function SourceIcon({ source }: { source: string }) {
  const iconMap: Record<string, React.ReactNode> = {
    Trivy: <Container className="h-3 w-3" />,
    Semgrep: <Code className="h-3 w-3" />,
    Snyk: <Package className="h-3 w-3" />,
    Prowler: <Cloud className="h-3 w-3" />,
    Checkov: <Server className="h-3 w-3" />,
  };
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
      {iconMap[source] ?? <Bug className="h-3 w-3" />}
      {source}
    </span>
  );
}

function AssetTypeIcon({ type }: { type: Alert["asset_type"] }) {
  const icons: Record<Alert["asset_type"], React.ReactNode> = {
    container: <Container className="h-3 w-3" />,
    code: <Code className="h-3 w-3" />,
    cloud: <Cloud className="h-3 w-3" />,
    secrets: <KeyRound className="h-3 w-3" />,
    iac: <Server className="h-3 w-3" />,
    package: <Package className="h-3 w-3" />,
  };
  return <span className="text-muted-foreground">{icons[type]}</span>;
}

function StatusBadge({ status }: { status: AlertStatus }) {
  const configs: Record<AlertStatus, { label: string; className: string }> = {
    new: { label: "New", className: "bg-blue-500/15 text-blue-400" },
    in_progress: { label: "Active", className: "bg-yellow-500/15 text-yellow-400" },
    resolved: { label: "Resolved", className: "bg-green-500/15 text-green-400" },
    false_positive: { label: "FP", className: "bg-muted text-muted-foreground" },
  };
  const cfg = configs[status];
  return (
    <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium", cfg.className)}>
      {cfg.label}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// Alert Detail Panel
// ═══════════════════════════════════════════════════════════

function AlertDetailPanel({
  alert,
  onClose,
  onAcknowledge,
  onEscalate,
  onDismiss,
}: {
  alert: Alert | null;
  onClose: () => void;
  onAcknowledge: (id: string) => void;
  onEscalate: (id: string) => void;
  onDismiss: (id: string) => void;
}) {
  if (!alert) return null;

  return (
    <Dialog open={!!alert} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-start gap-3 pr-8">
            <SeverityBadge severity={alert.severity} />
            <span className="text-base font-semibold leading-tight">{alert.title}</span>
          </DialogTitle>
        </DialogHeader>

        <ScrollArea className="max-h-[70vh]">
          <div className="space-y-5 pr-2">
            {/* Quick stats row */}
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-lg bg-muted/40 p-3 space-y-1">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">CVSS</p>
                <p className="text-2xl font-bold tabular-nums font-mono text-foreground">
                  {alert.cvss.toFixed(1)}
                </p>
              </div>
              <div className="rounded-lg bg-muted/40 p-3 space-y-1">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Age</p>
                <p className="text-2xl font-bold tabular-nums font-mono text-foreground">
                  {formatAge(alert.discovered_at)}
                </p>
              </div>
              <div className="rounded-lg bg-muted/40 p-3 space-y-1">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Council</p>
                <VerdictChip
                  verdict={alert.verdict}
                  confidence={alert.verdict_confidence}
                  models={alert.council_models}
                />
              </div>
            </div>

            {/* Description */}
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Description</p>
              <p className="text-sm text-foreground leading-relaxed">{alert.description}</p>
            </div>

            {/* Asset */}
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Affected Asset</p>
              <div className="flex items-center gap-2 rounded-md bg-muted/40 px-3 py-2">
                <AssetTypeIcon type={alert.asset_type} />
                <code className="text-xs font-mono text-foreground break-all">{alert.asset}</code>
              </div>
            </div>

            {/* CVE */}
            {alert.cve && (
              <div>
                <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">CVE Reference</p>
                <Badge variant="critical" className="font-mono">{alert.cve}</Badge>
              </div>
            )}

            {/* LLM Council detail */}
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">LLM Council Breakdown</p>
              <div className="space-y-2">
                {alert.council_models.map((m) => (
                  <div key={m.name} className="flex items-center gap-3">
                    <span className="w-28 text-xs text-muted-foreground truncate">{m.name}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                      <div
                        className={cn(
                          "h-full rounded-full transition-all",
                          m.verdict === "BLOCK"
                            ? "bg-red-500"
                            : m.verdict === "REVIEW"
                              ? "bg-yellow-500"
                              : "bg-green-500"
                        )}
                        style={{ width: `${m.confidence}%` }}
                      />
                    </div>
                    <span
                      className={cn(
                        "w-14 text-right text-xs font-mono font-semibold",
                        m.verdict === "BLOCK"
                          ? "text-red-400"
                          : m.verdict === "REVIEW"
                            ? "text-yellow-400"
                            : "text-green-400"
                      )}
                    >
                      {m.verdict}
                    </span>
                    <span className="w-8 text-right text-xs text-muted-foreground tabular-nums">
                      {m.confidence}%
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Remediation hint */}
            {alert.remediation_hint && (
              <div>
                <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Recommended Action</p>
                <div className="flex items-start gap-2 rounded-md border border-primary/20 bg-primary/5 px-3 py-2.5">
                  <Terminal className="h-3.5 w-3.5 text-primary mt-0.5 shrink-0" />
                  <p className="text-xs text-foreground leading-relaxed">{alert.remediation_hint}</p>
                </div>
              </div>
            )}

            {/* Tags */}
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Tags</p>
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

            {/* Actions */}
            <div className="flex gap-2 pb-2">
              <Button
                size="sm"
                variant="outline"
                className="flex-1"
                onClick={() => { onAcknowledge(alert.id); onClose(); }}
              >
                <CheckCircle2 className="h-3.5 w-3.5 mr-1.5" /> Acknowledge
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="flex-1 border-orange-500/30 text-orange-400 hover:bg-orange-500/10"
                onClick={() => { onEscalate(alert.id); onClose(); }}
              >
                <ArrowUpRight className="h-3.5 w-3.5 mr-1.5" /> Escalate to T2
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="flex-1 border-muted text-muted-foreground hover:bg-muted/50"
                onClick={() => { onDismiss(alert.id); onClose(); }}
              >
                <XCircle className="h-3.5 w-3.5 mr-1.5" /> False Positive
              </Button>
            </div>
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════
// Shift indicator
// ═══════════════════════════════════════════════════════════

function ShiftClock() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const hour = time.getHours();
  const shift =
    hour >= 6 && hour < 14
      ? "Alpha"
      : hour >= 14 && hour < 22
        ? "Bravo"
        : "Charlie";

  return (
    <div className="flex items-center gap-3 text-xs text-muted-foreground">
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
// Sort state type
// ═══════════════════════════════════════════════════════════

type SortField = "severity" | "age" | "cvss" | "confidence";
type SortDir = "asc" | "desc";

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// ═══════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════

export default function SOCDashboard() {
  const navigate = useNavigate();

  // Filter / sort state
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "all">("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "all">("all");
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  // Selection + detail
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [detailAlert, setDetailAlert] = useState<Alert | null>(null);

  // Local alert state (for status changes)
  const [alerts, setAlerts] = useState<Alert[]>(MOCK_ALERTS);

  const sources = useMemo(
    () => ["all", ...Array.from(new Set(MOCK_ALERTS.map((a) => a.source)))],
    []
  );

  // Filtering + sorting
  const filtered = useMemo(() => {
    let result = alerts.filter((a) => {
      if (severityFilter !== "all" && a.severity !== severityFilter) return false;
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (sourceFilter !== "all" && a.source !== sourceFilter) return false;
      if (verdictFilter !== "all" && a.verdict !== verdictFilter) return false;
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
      else if (sortField === "age") cmp = b.discovered_at.getTime() - a.discovered_at.getTime();
      else if (sortField === "cvss") cmp = b.cvss - a.cvss;
      else if (sortField === "confidence") cmp = b.verdict_confidence - a.verdict_confidence;
      return sortDir === "asc" ? cmp : -cmp;
    });

    return result;
  }, [alerts, severityFilter, statusFilter, sourceFilter, verdictFilter, search, sortField, sortDir]);

  // Stats
  const stats = useMemo(() => {
    const active = alerts.filter((a) => a.status !== "resolved" && a.status !== "false_positive");
    return {
      total: active.length,
      critical: active.filter((a) => a.severity === "critical").length,
      high: active.filter((a) => a.severity === "high").length,
      medium: active.filter((a) => a.severity === "medium").length,
      low: active.filter((a) => a.severity === "low").length,
      avgResponseMins: 34,
    };
  }, [alerts]);

  const toggleSort = useCallback(
    (field: SortField) => {
      if (sortField === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      else { setSortField(field); setSortDir("asc"); }
    },
    [sortField]
  );

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <Minus className="h-3 w-3 opacity-30" />;
    return sortDir === "asc" ? (
      <ChevronUp className="h-3 w-3 text-primary" />
    ) : (
      <ChevronDown className="h-3 w-3 text-primary" />
    );
  };

  // Bulk actions
  const bulkAcknowledge = () => {
    setAlerts((prev) =>
      prev.map((a) => (selectedIds.has(a.id) && a.status === "new" ? { ...a, status: "in_progress" } : a))
    );
    setSelectedIds(new Set());
  };

  const bulkEscalate = () => {
    setAlerts((prev) =>
      prev.map((a) =>
        selectedIds.has(a.id) ? { ...a, status: "in_progress", assignee: "t2-team" } : a
      )
    );
    setSelectedIds(new Set());
  };

  const bulkFalsePositive = () => {
    setAlerts((prev) =>
      prev.map((a) => (selectedIds.has(a.id) ? { ...a, status: "false_positive" } : a))
    );
    setSelectedIds(new Set());
  };

  const handleAcknowledge = (id: string) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id && a.status === "new" ? { ...a, status: "in_progress" } : a))
    );
  };

  const handleEscalate = (id: string) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: "in_progress", assignee: "t2-team" } : a))
    );
  };

  const handleDismiss = (id: string) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: "false_positive" } : a))
    );
  };

  const allFilteredSelected =
    filtered.length > 0 && filtered.every((a) => selectedIds.has(a.id));

  const toggleAll = () => {
    if (allFilteredSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((a) => a.id)));
    }
  };

  return (
    <div className="space-y-5">
      {/* ── Header ── */}
      <PageHeader
        title="SOC Alert Triage"
        description="Tier 1 analyst queue — LLM Council verdicts · real-time ingestion"
        badge="P03"
      >
        <ShiftClock />
        <Button
          variant="outline"
          size="sm"
          onClick={() => navigate("/mission-control/live-feed")}
        >
          <Activity className="h-3.5 w-3.5 mr-1.5" />
          Live Feed
        </Button>
      </PageHeader>

      {/* ── KPI Stats Bar ── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard
          title="Total Alerts"
          value={stats.total}
          icon={AlertTriangle}
          trendLabel="Active queue"
        />
        <KpiCard
          title="Critical"
          value={stats.critical}
          icon={Flame}         trend={stats.critical > 0 ? "down" : "up"}
          trendLabel={stats.critical > 0 ? "Needs attention" : "Clear"}
        />
        <KpiCard
          title="High"
          value={stats.high}
          icon={ChevronsUp}
          trendLabel="Severity 7–9.9"
        />
        <KpiCard
          title="Medium"
          value={stats.medium}
          icon={TriangleAlert}
          trendLabel="Severity 4–6.9"
        />
        <KpiCard
          title="Low"
          value={stats.low}
          icon={ArrowUpRight}
          trendLabel="Severity 0–3.9"
        />
        <KpiCard
          title="Avg Response"
          value={`${stats.avgResponseMins}m`}
          icon={Timer}         trend="up"
          trendLabel="Below 60m SLA"
        />
      </div>

      {/* ── Filters + Bulk Actions ── */}
      <Card>
        <CardContent className="pt-4 pb-3">
          <div className="flex flex-wrap items-center gap-2">
            {/* Search */}
            <div className="relative flex-1 min-w-[180px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search alerts, CVEs, assets..."
                className="pl-8 h-8 text-xs"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            {/* Severity filter */}
            <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as Severity | "all")}>
              <SelectTrigger className="h-8 w-28 text-xs">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>

            {/* Status filter */}
            <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as AlertStatus | "all")}>
              <SelectTrigger className="h-8 w-28 text-xs">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="new">New</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
              </SelectContent>
            </Select>

            {/* Source filter */}
            <Select value={sourceFilter} onValueChange={setSourceFilter}>
              <SelectTrigger className="h-8 w-28 text-xs">
                <SelectValue placeholder="Source" />
              </SelectTrigger>
              <SelectContent>
                {sources.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s === "all" ? "All Sources" : s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Verdict filter */}
            <Select value={verdictFilter} onValueChange={(v) => setVerdictFilter(v as Verdict | "all")}>
              <SelectTrigger className="h-8 w-24 text-xs">
                <SelectValue placeholder="Verdict" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Verdicts</SelectItem>
                <SelectItem value="BLOCK">BLOCK</SelectItem>
                <SelectItem value="REVIEW">REVIEW</SelectItem>
                <SelectItem value="ALLOW">ALLOW</SelectItem>
              </SelectContent>
            </Select>

            {/* Sort */}
            <Select value={sortField} onValueChange={(v) => setSortField(v as SortField)}>
              <SelectTrigger className="h-8 w-32 text-xs">
                <SlidersHorizontal className="h-3 w-3 mr-1.5 shrink-0" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="severity">Sort: Severity</SelectItem>
                <SelectItem value="age">Sort: Age</SelectItem>
                <SelectItem value="cvss">Sort: CVSS</SelectItem>
                <SelectItem value="confidence">Sort: Confidence</SelectItem>
              </SelectContent>
            </Select>

            <div className="flex-1" />

            {/* Bulk action bar */}
            <AnimatePresence>
              {selectedIds.size > 0 && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="flex items-center gap-2"
                >
                  <span className="text-xs text-muted-foreground font-medium">
                    {selectedIds.size} selected
                  </span>
                  <Button size="sm" variant="outline" className="h-7 text-xs" onClick={bulkAcknowledge}>
                    <CheckCircle2 className="h-3 w-3 mr-1" /> Ack
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 text-xs border-orange-500/30 text-orange-400 hover:bg-orange-500/10"
                    onClick={bulkEscalate}
                  >
                    <ArrowUpRight className="h-3 w-3 mr-1" /> Escalate T2
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 text-xs text-muted-foreground"
                    onClick={bulkFalsePositive}
                  >
                    <XCircle className="h-3 w-3 mr-1" /> Mark FP
                  </Button>
                </motion.div>
              )}
            </AnimatePresence>

            <span className="text-xs text-muted-foreground tabular-nums">
              {filtered.length} / {alerts.length}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* ── Alert Queue Table ── */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            {/* Header */}
            <thead>
              <tr className="border-b border-border">
                <th className="w-10 px-4 py-2.5">
                  <Checkbox
                    checked={allFilteredSelected}
                    onCheckedChange={toggleAll}
                    aria-label="Select all"
                  />
                </th>
                <th className="px-3 py-2.5 text-left">
                  <button
                    onClick={() => toggleSort("severity")}
                    className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
                  >
                    SEV <SortIcon field="severity" />
                  </button>
                </th>
                <th className="px-3 py-2.5 text-left min-w-[280px]">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Alert</span>
                </th>
                <th className="px-3 py-2.5 text-left">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Source</span>
                </th>
                <th className="px-3 py-2.5 text-left">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Council Verdict</span>
                </th>
                <th className="px-3 py-2.5 text-left">
                  <button
                    onClick={() => toggleSort("cvss")}
                    className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
                  >
                    CVSS <SortIcon field="cvss" />
                  </button>
                </th>
                <th className="px-3 py-2.5 text-left">
                  <button
                    onClick={() => toggleSort("age")}
                    className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
                  >
                    Age <SortIcon field="age" />
                  </button>
                </th>
                <th className="px-3 py-2.5 text-left">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Status</span>
                </th>
                <th className="px-3 py-2.5 text-left">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Assignee</span>
                </th>
                <th className="px-3 py-2.5 text-right">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Actions</span>
                </th>
              </tr>
            </thead>

            <tbody>
              <AnimatePresence initial={false}>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="py-16 text-center text-sm text-muted-foreground">
                      No alerts match the current filters.
                    </td>
                  </tr>
                ) : (
                  filtered.map((alert, i) => {
                    const isSelected = selectedIds.has(alert.id);
                    const urgency = ageUrgency(alert.discovered_at);
                    const isCritical = alert.severity === "critical";

                    return (
                      <motion.tr
                        key={alert.id}
                        initial={{ opacity: 0, y: 4 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.15, delay: i * 0.02 }}
                        className={cn(
                          "border-b border-border/50 transition-colors group cursor-pointer",
                          isSelected && "bg-primary/5",
                          isCritical && !isSelected && "bg-red-500/[0.03]",
                          "hover:bg-muted/30"
                        )}
                        onClick={(e) => {
                          // Don't open detail if clicking checkbox or action buttons
                          const target = e.target as HTMLElement;
                          if (target.closest('button') || target.closest('[role="checkbox"]')) return;
                          setDetailAlert(alert);
                        }}
                      >
                        {/* Checkbox */}
                        <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
                          <Checkbox
                            checked={isSelected}
                            onCheckedChange={(checked) => {
                              setSelectedIds((prev) => {
                                const next = new Set(prev);
                                if (checked) next.add(alert.id);
                                else next.delete(alert.id);
                                return next;
                              });
                            }}
                            aria-label={`Select ${alert.id}`}
                          />
                        </td>

                        {/* Severity */}
                        <td className="px-3 py-2.5">
                          <SeverityBadge severity={alert.severity} />
                        </td>

                        {/* Title */}
                        <td className="px-3 py-2.5">
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] font-mono text-muted-foreground/60">
                                {alert.id}
                              </span>
                              {alert.cve && (
                                <Badge variant="critical" className="text-[9px] px-1 py-0 font-mono">
                                  {alert.cve}
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs font-medium text-foreground leading-snug line-clamp-1 group-hover:text-primary transition-colors">
                              {alert.title}
                            </p>
                            <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                              <AssetTypeIcon type={alert.asset_type} />
                              <span className="font-mono truncate max-w-[200px]">{alert.asset}</span>
                            </div>
                          </div>
                        </td>

                        {/* Source */}
                        <td className="px-3 py-2.5">
                          <SourceIcon source={alert.source} />
                        </td>

                        {/* Verdict */}
                        <td className="px-3 py-2.5">
                          <VerdictChip
                            verdict={alert.verdict}
                            confidence={alert.verdict_confidence}
                            models={alert.council_models}
                          />
                        </td>

                        {/* CVSS */}
                        <td className="px-3 py-2.5">
                          <span
                            className={cn(
                              "font-mono text-xs font-bold tabular-nums",
                              alert.cvss >= 9
                                ? "text-red-400"
                                : alert.cvss >= 7
                                  ? "text-orange-400"
                                  : alert.cvss >= 4
                                    ? "text-yellow-400"
                                    : "text-blue-400"
                            )}
                          >
                            {alert.cvss.toFixed(1)}
                          </span>
                        </td>

                        {/* Age */}
                        <td className="px-3 py-2.5">
                          <span
                            className={cn(
                              "text-xs font-mono tabular-nums",
                              urgency === "fresh"
                                ? "text-green-400"
                                : urgency === "aging"
                                  ? "text-yellow-400"
                                  : "text-muted-foreground"
                            )}
                          >
                            {formatAge(alert.discovered_at)}
                          </span>
                        </td>

                        {/* Status */}
                        <td className="px-3 py-2.5">
                          <StatusBadge status={alert.status} />
                        </td>

                        {/* Assignee */}
                        <td className="px-3 py-2.5">
                          {alert.assignee ? (
                            <span className="flex items-center gap-1 text-xs text-muted-foreground">
                              <User className="h-3 w-3" />
                              {alert.assignee}
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground/40">—</span>
                          )}
                        </td>

                        {/* Actions */}
                        <td
                          className="px-3 py-2.5 text-right"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            <TooltipProvider delayDuration={100}>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button
                                    size="icon"
                                    variant="ghost"
                                    className="h-6 w-6"
                                    onClick={() => handleAcknowledge(alert.id)}
                                  >
                                    <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>Acknowledge</TooltipContent>
                              </Tooltip>

                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button
                                    size="icon"
                                    variant="ghost"
                                    className="h-6 w-6"
                                    onClick={() => handleEscalate(alert.id)}
                                  >
                                    <ArrowUpRight className="h-3.5 w-3.5 text-orange-400" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>Escalate to T2</TooltipContent>
                              </Tooltip>

                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button
                                    size="icon"
                                    variant="ghost"
                                    className="h-6 w-6"
                                    onClick={() => handleDismiss(alert.id)}
                                  >
                                    <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>Mark False Positive</TooltipContent>
                              </Tooltip>

                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button
                                    size="icon"
                                    variant="ghost"
                                    className="h-6 w-6"
                                    onClick={() => setDetailAlert(alert)}
                                  >
                                    <Eye className="h-3.5 w-3.5 text-primary" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>View Details</TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
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

      {/* ── Alert Detail Dialog ── */}
      <AlertDetailPanel
        alert={detailAlert}
        onClose={() => setDetailAlert(null)}
        onAcknowledge={handleAcknowledge}
        onEscalate={handleEscalate}
        onDismiss={handleDismiss}
      />
    </div>
  );
}
