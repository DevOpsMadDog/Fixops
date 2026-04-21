/**
 * API Explorer — Developer tool
 *
 * 3-panel layout:
 *   Left:   Domain-grouped endpoint list (50 top endpoints pre-loaded)
 *   Center: Request builder — method, path, params, body, Send button
 *   Right:  JSON response viewer with syntax highlighting, status, timing
 *
 * Route: /api-explorer
 */

import { useState, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Play, ChevronRight, ChevronDown, Clock, CheckCircle2,
  XCircle, Copy, RefreshCw, Search, Code2, Zap,
  Shield, Cloud, AlertTriangle, Eye, Lock, Database,
  Network, Activity, Users, Settings, Globe,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

// ── Constants ─────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL || "";

// ── Types ─────────────────────────────────────────────────────

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH";

interface Param {
  name: string;
  type: "string" | "number" | "boolean";
  required: boolean;
  default?: string;
  description: string;
  location: "query" | "body" | "path";
}

interface EndpointDef {
  id: string;
  method: HttpMethod;
  path: string;
  summary: string;
  domain: string;
  params: Param[];
  sampleBody?: Record<string, unknown>;
  responseSchema?: string;
}

interface ResponseState {
  status: number | null;
  data: unknown;
  ms: number | null;
  error: string | null;
}

// ── Endpoint definitions (top 50) ────────────────────────────

const ENDPOINTS: EndpointDef[] = [
  // ── ASPM / Findings ──────────────────────────────────────
  {
    id: "findings-list",
    method: "GET",
    path: "/api/v1/findings",
    summary: "List security findings",
    domain: "ASPM",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
      { name: "severity", type: "string", required: false, description: "Filter by severity", location: "query" },
    ],
    responseSchema: '{ "findings": [...], "total": number }',
  },
  {
    id: "findings-stats",
    method: "GET",
    path: "/api/v1/findings/stats",
    summary: "Findings statistics",
    domain: "ASPM",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "critical": number, "high": number, "medium": number, "low": number }',
  },
  {
    id: "attack-paths-list",
    method: "GET",
    path: "/api/v1/attack-paths",
    summary: "List attack paths",
    domain: "ASPM",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "10", description: "Max paths", location: "query" },
    ],
    responseSchema: '{ "paths": [...] }',
  },
  {
    id: "sbom-list",
    method: "GET",
    path: "/api/v1/sbom",
    summary: "List SBOM components",
    domain: "ASPM",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "components": [...] }',
  },
  // ── CSPM ─────────────────────────────────────────────────
  {
    id: "cloud-findings-list",
    method: "GET",
    path: "/api/v1/cloud-findings",
    summary: "Cloud security findings",
    domain: "CSPM",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
      { name: "provider", type: "string", required: false, description: "aws | gcp | azure", location: "query" },
    ],
    responseSchema: '{ "findings": [...], "total": number }',
  },
  {
    id: "cloud-posture-score",
    method: "GET",
    path: "/api/v1/cloud-posture/score",
    summary: "Cloud posture score",
    domain: "CSPM",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "score": number, "grade": string }',
  },
  {
    id: "cloud-compliance-list",
    method: "GET",
    path: "/api/v1/cloud-compliance/frameworks",
    summary: "Cloud compliance frameworks",
    domain: "CSPM",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "frameworks": [...] }',
  },
  {
    id: "cloud-drift-list",
    method: "GET",
    path: "/api/v1/cloud-drift/drifts",
    summary: "IaC drift detections",
    domain: "CSPM",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "drifts": [...] }',
  },
  // ── Threat Intel ─────────────────────────────────────────
  {
    id: "threat-indicators",
    method: "GET",
    path: "/api/v1/threat-indicators/indicators",
    summary: "List threat indicators",
    domain: "Threat Intel",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "indicators": [...] }',
  },
  {
    id: "threat-indicators-create",
    method: "POST",
    path: "/api/v1/threat-indicators/indicators",
    summary: "Create threat indicator",
    domain: "Threat Intel",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    sampleBody: {
      indicator_type: "ip",
      value: "1.2.3.4",
      confidence: 0.85,
      source: "osint",
      ttl_days: 30,
    },
    responseSchema: '{ "id": string, "value": string, "active": boolean }',
  },
  {
    id: "dark-web-mentions",
    method: "GET",
    path: "/api/v1/dark-web/mentions",
    summary: "Dark web mentions",
    domain: "Threat Intel",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "mentions": [...] }',
  },
  {
    id: "ransomware-patterns",
    method: "GET",
    path: "/api/v1/ransomware-protection/patterns",
    summary: "Ransomware detection patterns",
    domain: "Threat Intel",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "patterns": [...] }',
  },
  // ── Vulnerability Management ──────────────────────────────
  {
    id: "cve-search",
    method: "GET",
    path: "/api/v1/cve/search",
    summary: "CVE search with EPSS/KEV",
    domain: "Vulnerabilities",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "q", type: "string", required: false, description: "CVE ID or keyword", location: "query" },
      { name: "limit", type: "number", required: false, default: "10", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "cves": [...] }',
  },
  {
    id: "vuln-lifecycle-list",
    method: "GET",
    path: "/api/v1/vuln-lifecycle/vulns",
    summary: "Vulnerability lifecycle tracker",
    domain: "Vulnerabilities",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "vulns": [...] }',
  },
  {
    id: "vuln-scan-create",
    method: "POST",
    path: "/api/v1/vuln-scans/scans",
    summary: "Start vulnerability scan",
    domain: "Vulnerabilities",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    sampleBody: {
      scanner_type: "nessus",
      target: "10.0.0.0/24",
      scan_name: "Weekly network scan",
    },
    responseSchema: '{ "id": string, "status": string }',
  },
  {
    id: "vuln-prioritization-queue",
    method: "GET",
    path: "/api/v1/vuln-prioritization/queue",
    summary: "Prioritised remediation queue",
    domain: "Vulnerabilities",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "queue": [...] }',
  },
  // ── Identity & Access ─────────────────────────────────────
  {
    id: "identity-lifecycle-list",
    method: "GET",
    path: "/api/v1/identity-lifecycle/identities",
    summary: "Identity lifecycle list",
    domain: "Identity",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "identities": [...] }',
  },
  {
    id: "access-anomaly-list",
    method: "GET",
    path: "/api/v1/access-anomaly/anomalies",
    summary: "Access anomaly detections",
    domain: "Identity",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "anomalies": [...] }',
  },
  {
    id: "mfa-list",
    method: "GET",
    path: "/api/v1/mfa/enrollments",
    summary: "MFA enrollment status",
    domain: "Identity",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "enrollments": [...] }',
  },
  {
    id: "iam-analyze",
    method: "POST",
    path: "/api/v1/iam-policy/analyze",
    summary: "Analyze IAM policy",
    domain: "Identity",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    sampleBody: {
      policy_document: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
      policy_name: "AdminPolicy",
    },
    responseSchema: '{ "findings": [...], "risk_score": number }',
  },
  // ── Compliance ────────────────────────────────────────────
  {
    id: "compliance-frameworks",
    method: "GET",
    path: "/api/v1/compliance/frameworks",
    summary: "Compliance frameworks",
    domain: "Compliance",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "frameworks": [...] }',
  },
  {
    id: "compliance-calendar-events",
    method: "GET",
    path: "/api/v1/compliance-calendar/events",
    summary: "Compliance calendar events",
    domain: "Compliance",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "events": [...] }',
  },
  {
    id: "control-testing-list",
    method: "GET",
    path: "/api/v1/control-testing/tests",
    summary: "Control test results",
    domain: "Compliance",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "tests": [...] }',
  },
  {
    id: "gdpr-dsr-list",
    method: "GET",
    path: "/api/v1/gdpr/dsr-requests",
    summary: "GDPR data subject requests",
    domain: "Compliance",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "requests": [...] }',
  },
  // ── Incident Response ────────────────────────────────────
  {
    id: "incidents-list",
    method: "GET",
    path: "/api/v1/incident-orchestration/incidents",
    summary: "List incidents",
    domain: "Incidents",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "incidents": [...] }',
  },
  {
    id: "incidents-create",
    method: "POST",
    path: "/api/v1/incident-orchestration/incidents",
    summary: "Create incident",
    domain: "Incidents",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    sampleBody: {
      title: "Suspicious login from unknown IP",
      severity: "high",
      description: "Multiple failed logins followed by successful auth from new country",
    },
    responseSchema: '{ "id": string, "status": string }',
  },
  {
    id: "incident-metrics",
    method: "GET",
    path: "/api/v1/incident-metrics/metrics",
    summary: "Incident MTTR/MTTD metrics",
    domain: "Incidents",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "mttr_hours": number, "mttd_hours": number }',
  },
  // ── Risk Management ───────────────────────────────────────
  {
    id: "risk-register-list",
    method: "GET",
    path: "/api/v1/risk-register-engine/risks",
    summary: "Risk register entries",
    domain: "Risk",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "risks": [...] }',
  },
  {
    id: "risk-aggregator-score",
    method: "GET",
    path: "/api/v1/risk-aggregator/org-risk",
    summary: "Organisation risk score",
    domain: "Risk",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "composite_score": number, "grade": string }',
  },
  {
    id: "security-posture-score",
    method: "GET",
    path: "/api/v1/posture-scoring/score",
    summary: "Security posture score",
    domain: "Risk",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "score": number, "score_level": string }',
  },
  // ── Network Security ──────────────────────────────────────
  {
    id: "network-threats-list",
    method: "GET",
    path: "/api/v1/network-threats/threats",
    summary: "Network threats",
    domain: "Network",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "threats": [...] }',
  },
  {
    id: "ip-reputation-check",
    method: "POST",
    path: "/api/v1/ip-reputation/check",
    summary: "Check IP reputation",
    domain: "Network",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    sampleBody: { ip: "1.2.3.4" },
    responseSchema: '{ "ip": string, "risk_score": number, "category": string }',
  },
  {
    id: "firewall-rules",
    method: "GET",
    path: "/api/v1/firewall-policy/rules",
    summary: "Firewall policy rules",
    domain: "Network",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "rules": [...] }',
  },
  {
    id: "passive-dns-lookup",
    method: "GET",
    path: "/api/v1/passive-dns/lookup",
    summary: "Passive DNS lookup",
    domain: "Network",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "domain", type: "string", required: true, default: "example.com", description: "Domain to look up", location: "query" },
    ],
    responseSchema: '{ "records": [...] }',
  },
  // ── Endpoint Security ─────────────────────────────────────
  {
    id: "endpoint-hunting-list",
    method: "GET",
    path: "/api/v1/endpoint-hunting/hunts",
    summary: "Endpoint threat hunts",
    domain: "Endpoint",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "hunts": [...] }',
  },
  {
    id: "patch-management-list",
    method: "GET",
    path: "/api/v1/patch-management/patches",
    summary: "Patch management status",
    domain: "Endpoint",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "20", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "patches": [...] }',
  },
  {
    id: "container-security-images",
    method: "GET",
    path: "/api/v1/container-registry-security/images",
    summary: "Container image scan results",
    domain: "Endpoint",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "images": [...] }',
  },
  // ── Security Operations ───────────────────────────────────
  {
    id: "kpi-list",
    method: "GET",
    path: "/api/v1/kpi/kpis",
    summary: "Security KPIs",
    domain: "Operations",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "kpis": [...] }',
  },
  {
    id: "alert-triage-queue",
    method: "GET",
    path: "/api/v1/alert-triage/queue",
    summary: "Alert triage queue",
    domain: "Operations",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "alerts": [...] }',
  },
  {
    id: "soc-metrics",
    method: "GET",
    path: "/api/v1/soc-metrics/summary",
    summary: "SOC operational metrics",
    domain: "Operations",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "mttd": number, "mttr": number, "alert_volume": number }',
  },
  {
    id: "security-okrs",
    method: "GET",
    path: "/api/v1/security-okrs/objectives",
    summary: "Security OKRs",
    domain: "Operations",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "objectives": [...] }',
  },
  // ── Cloud Infrastructure ──────────────────────────────────
  {
    id: "cloud-accounts-list",
    method: "GET",
    path: "/api/v1/cloud-accounts/accounts",
    summary: "Cloud accounts",
    domain: "Cloud",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "accounts": [...] }',
  },
  {
    id: "cloud-ir-incidents",
    method: "GET",
    path: "/api/v1/cloud-ir/incidents",
    summary: "Cloud IR incidents",
    domain: "Cloud",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "incidents": [...] }',
  },
  {
    id: "cost-optimization-list",
    method: "GET",
    path: "/api/v1/cost-optimization/tools",
    summary: "Cloud cost optimization tools",
    domain: "Cloud",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "tools": [...] }',
  },
  // ── Privacy & Data ────────────────────────────────────────
  {
    id: "privacy-impact-list",
    method: "GET",
    path: "/api/v1/privacy-impact/assessments",
    summary: "Privacy impact assessments",
    domain: "Privacy",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "assessments": [...] }',
  },
  {
    id: "data-discovery-datastores",
    method: "GET",
    path: "/api/v1/data-discovery/datastores",
    summary: "Sensitive data discovery",
    domain: "Privacy",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "datastores": [...] }',
  },
  // ── Training & Awareness ──────────────────────────────────
  {
    id: "training-effectiveness-list",
    method: "GET",
    path: "/api/v1/training-effectiveness/programs",
    summary: "Training effectiveness programs",
    domain: "Training",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "programs": [...] }',
  },
  {
    id: "awareness-metrics-list",
    method: "GET",
    path: "/api/v1/awareness-metrics/metrics",
    summary: "Security awareness metrics",
    domain: "Training",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
    ],
    responseSchema: '{ "metrics": [...] }',
  },
  // ── Misc / Platform ───────────────────────────────────────
  {
    id: "health-check",
    method: "GET",
    path: "/health",
    summary: "API health check",
    domain: "Platform",
    params: [],
    responseSchema: '{ "status": "ok" }',
  },
  {
    id: "version",
    method: "GET",
    path: "/api/v1/version",
    summary: "API version info",
    domain: "Platform",
    params: [],
    responseSchema: '{ "version": string, "build": string }',
  },
  {
    id: "posture-advisor",
    method: "GET",
    path: "/api/v1/posture-advisor/recommendations",
    summary: "Posture improvement recommendations",
    domain: "Platform",
    params: [
      { name: "org_id", type: "string", required: true, default: "default", description: "Organisation ID", location: "query" },
      { name: "limit", type: "number", required: false, default: "10", description: "Max results", location: "query" },
    ],
    responseSchema: '{ "recommendations": [...] }',
  },
];

// ── Domain config ─────────────────────────────────────────────

const DOMAIN_ICONS: Record<string, React.ReactNode> = {
  ASPM:        <Shield className="w-3.5 h-3.5" />,
  CSPM:        <Cloud className="w-3.5 h-3.5" />,
  "Threat Intel": <Eye className="w-3.5 h-3.5" />,
  Vulnerabilities: <AlertTriangle className="w-3.5 h-3.5" />,
  Identity:    <Users className="w-3.5 h-3.5" />,
  Compliance:  <Lock className="w-3.5 h-3.5" />,
  Incidents:   <Zap className="w-3.5 h-3.5" />,
  Risk:        <Activity className="w-3.5 h-3.5" />,
  Network:     <Network className="w-3.5 h-3.5" />,
  Endpoint:    <Database className="w-3.5 h-3.5" />,
  Operations:  <Settings className="w-3.5 h-3.5" />,
  Cloud:       <Cloud className="w-3.5 h-3.5" />,
  Privacy:     <Lock className="w-3.5 h-3.5" />,
  Training:    <Users className="w-3.5 h-3.5" />,
  Platform:    <Globe className="w-3.5 h-3.5" />,
};

const DOMAIN_ORDER = [
  "ASPM", "CSPM", "Threat Intel", "Vulnerabilities", "Identity",
  "Compliance", "Incidents", "Risk", "Network", "Endpoint",
  "Operations", "Cloud", "Privacy", "Training", "Platform",
];

// ── Helpers ───────────────────────────────────────────────────

function methodColor(m: HttpMethod) {
  switch (m) {
    case "GET":    return "text-blue-400 border-blue-500/30 bg-blue-500/10";
    case "POST":   return "text-green-400 border-green-500/30 bg-green-500/10";
    case "PUT":    return "text-yellow-400 border-yellow-500/30 bg-yellow-500/10";
    case "DELETE": return "text-red-400 border-red-500/30 bg-red-500/10";
    case "PATCH":  return "text-purple-400 border-purple-500/30 bg-purple-500/10";
  }
}

function statusColor(code: number) {
  if (code >= 200 && code < 300) return "text-green-400";
  if (code >= 400 && code < 500) return "text-yellow-400";
  return "text-red-400";
}

function syntaxHighlight(json: unknown): string {
  if (json === null || json === undefined) return "null";
  const str = JSON.stringify(json, null, 2);
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
      (match) => {
        let cls = "text-amber-300"; // number
        if (/^"/.test(match)) {
          cls = /:$/.test(match) ? "text-blue-300" : "text-green-300"; // key vs string
        } else if (/true|false/.test(match)) {
          cls = "text-purple-300";
        } else if (/null/.test(match)) {
          cls = "text-red-300";
        }
        return `<span class="${cls}">${match}</span>`;
      }
    );
}

// ── Main Component ────────────────────────────────────────────

export default function APIExplorer() {
  const [selectedId, setSelectedId]     = useState<string>("health-check");
  const [paramValues, setParamValues]   = useState<Record<string, string>>({});
  const [bodyText, setBodyText]         = useState<string>("");
  const [apiKey, setApiKey]             = useState<string>(
    (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) || "dev-key"
  );
  const [response, setResponse]         = useState<ResponseState>({ status: null, data: null, ms: null, error: null });
  const [loading, setLoading]           = useState(false);
  const [search, setSearch]             = useState("");
  const [collapsedDomains, setCollapsedDomains] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab]       = useState<"params" | "body" | "schema">("params");

  const selected = ENDPOINTS.find((e) => e.id === selectedId) ?? ENDPOINTS[0];

  // Group by domain
  const grouped = DOMAIN_ORDER.reduce<Record<string, EndpointDef[]>>((acc, domain) => {
    const eps = ENDPOINTS.filter((e) => e.domain === domain && (
      !search ||
      e.summary.toLowerCase().includes(search.toLowerCase()) ||
      e.path.toLowerCase().includes(search.toLowerCase())
    ));
    if (eps.length) acc[domain] = eps;
    return acc;
  }, {});

  // When endpoint changes, seed defaults
  const selectEndpoint = useCallback((ep: EndpointDef) => {
    setSelectedId(ep.id);
    const defaults: Record<string, string> = {};
    ep.params.forEach((p) => { if (p.default) defaults[p.name] = p.default; });
    setParamValues(defaults);
    setBodyText(ep.sampleBody ? JSON.stringify(ep.sampleBody, null, 2) : "");
    setResponse({ status: null, data: null, ms: null, error: null });
    setActiveTab(ep.method !== "GET" && ep.sampleBody ? "body" : "params");
  }, []);

  const toggleDomain = (domain: string) => {
    setCollapsedDomains((prev) => {
      const next = new Set(prev);
      next.has(domain) ? next.delete(domain) : next.add(domain);
      return next;
    });
  };

  const sendRequest = async () => {
    if (!selected) return;
    setLoading(true);
    setResponse({ status: null, data: null, ms: null, error: null });

    // Build URL
    const queryParams = new URLSearchParams();
    selected.params
      .filter((p) => p.location === "query")
      .forEach((p) => {
        const val = paramValues[p.name];
        if (val) queryParams.set(p.name, val);
      });

    // Inject path params
    let path = selected.path;
    selected.params
      .filter((p) => p.location === "path")
      .forEach((p) => {
        path = path.replace(`{${p.name}}`, paramValues[p.name] ?? p.name);
      });

    const url = `${API_BASE}${path}${queryParams.toString() ? "?" + queryParams.toString() : ""}`;

    const t0 = performance.now();
    try {
      const opts: RequestInit = {
        method: selected.method,
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
        },
      };
      if (selected.method !== "GET" && bodyText.trim()) {
        opts.body = bodyText;
      }
      const res = await fetch(url, opts);
      const ms = Math.round(performance.now() - t0);
      let data: unknown;
      try { data = await res.json(); } catch { data = await res.text(); }
      setResponse({ status: res.status, data, ms, error: null });
    } catch (err) {
      const ms = Math.round(performance.now() - t0);
      setResponse({ status: 0, data: null, ms, error: String(err) });
    } finally {
      setLoading(false);
    }
  };

  const copyResponse = () => {
    if (response.data !== null) {
      navigator.clipboard.writeText(JSON.stringify(response.data, null, 2));
      toast.success("Copied to clipboard");
    }
  };

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-background">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border/50 shrink-0">
        <PageHeader
          title="API Explorer"
          description="Live API testing — select an endpoint, configure params, and send requests"
          badge="Developer"
          actions={
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-muted-foreground" />
              <Input
                className="w-64 h-8 font-mono text-xs"
                placeholder="API Key"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </div>
          }
        />
      </div>

      {/* 3-column body */}
      <div className="flex flex-1 overflow-hidden">

        {/* ── LEFT PANEL: Endpoint List ── */}
        <div className="w-72 border-r border-border/50 flex flex-col shrink-0">
          <div className="px-3 py-2 border-b border-border/50 shrink-0">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input
                className="pl-7 h-8 text-xs"
                placeholder="Search endpoints…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <p className="text-[10px] text-muted-foreground mt-1.5 pl-0.5">
              {ENDPOINTS.filter((e) => !search || e.path.toLowerCase().includes(search.toLowerCase()) || e.summary.toLowerCase().includes(search.toLowerCase())).length} / {ENDPOINTS.length} endpoints
            </p>
          </div>

          <ScrollArea className="flex-1">
            <div className="py-2">
              {Object.entries(grouped).map(([domain, eps]) => (
                <div key={domain} className="mb-1">
                  {/* Domain header */}
                  <button
                    onClick={() => toggleDomain(domain)}
                    className="w-full flex items-center gap-2 px-3 py-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
                  >
                    <span className="text-muted-foreground">
                      {DOMAIN_ICONS[domain]}
                    </span>
                    <span className="flex-1 text-left uppercase tracking-wider text-[10px]">{domain}</span>
                    <span className="text-[10px] opacity-60">{eps.length}</span>
                    {collapsedDomains.has(domain)
                      ? <ChevronRight className="w-3 h-3" />
                      : <ChevronDown className="w-3 h-3" />}
                  </button>

                  {/* Endpoints */}
                  {!collapsedDomains.has(domain) && (
                    <div>
                      {eps.map((ep) => (
                        <button
                          key={ep.id}
                          onClick={() => selectEndpoint(ep)}
                          className={cn(
                            "w-full flex items-start gap-2 px-3 py-2 text-left transition-colors hover:bg-muted/40",
                            selectedId === ep.id && "bg-muted/60 border-l-2 border-primary"
                          )}
                        >
                          <span className={cn(
                            "shrink-0 mt-0.5 text-[9px] font-bold border rounded px-1 py-0.5 font-mono leading-none",
                            methodColor(ep.method)
                          )}>
                            {ep.method}
                          </span>
                          <div className="min-w-0">
                            <p className="text-[11px] font-medium truncate leading-tight">{ep.summary}</p>
                            <p className="text-[10px] text-muted-foreground font-mono truncate mt-0.5">{ep.path}</p>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>

        {/* ── CENTER PANEL: Request Builder ── */}
        <div className="flex-1 flex flex-col overflow-hidden border-r border-border/50 min-w-0">
          {selected && (
            <>
              {/* Endpoint URL bar */}
              <div className="px-4 py-3 border-b border-border/50 shrink-0">
                <div className="flex items-center gap-2">
                  <span className={cn(
                    "shrink-0 text-xs font-bold font-mono border rounded px-2 py-1",
                    methodColor(selected.method)
                  )}>
                    {selected.method}
                  </span>
                  <code className="flex-1 text-sm font-mono text-foreground/90 truncate bg-muted/40 px-3 py-1.5 rounded border border-border/50">
                    {API_BASE}{selected.path}
                  </code>
                  <Button
                    size="sm"
                    onClick={sendRequest}
                    disabled={loading}
                    className="shrink-0 h-8 gap-1.5"
                  >
                    {loading
                      ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      : <Play className="w-3.5 h-3.5" />}
                    Send
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground mt-1.5">{selected.summary}</p>
              </div>

              {/* Tabs: Params / Body / Schema */}
              <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as typeof activeTab)} className="flex-1 flex flex-col overflow-hidden">
                <TabsList className="mx-4 mt-3 mb-0 shrink-0 w-fit">
                  <TabsTrigger value="params" className="text-xs">Params</TabsTrigger>
                  <TabsTrigger
                    value="body"
                    disabled={selected.method === "GET"}
                    className="text-xs"
                  >
                    Body
                  </TabsTrigger>
                  <TabsTrigger value="schema" className="text-xs">Schema</TabsTrigger>
                </TabsList>

                {/* Params tab */}
                <TabsContent value="params" className="flex-1 overflow-auto px-4 pb-4 mt-3">
                  {selected.params.filter((p) => p.location !== "body").length === 0 ? (
                    <p className="text-xs text-muted-foreground mt-4">No parameters for this endpoint.</p>
                  ) : (
                    <div className="space-y-3">
                      {selected.params
                        .filter((p) => p.location !== "body")
                        .map((p) => (
                          <div key={p.name} className="flex flex-col gap-1">
                            <label className="flex items-center gap-2 text-xs font-medium">
                              <code className="text-blue-300 font-mono">{p.name}</code>
                              <span className="text-muted-foreground font-mono text-[10px]">{p.type}</span>
                              <span className="text-[10px] text-muted-foreground capitalize border border-border/50 px-1 rounded">
                                {p.location}
                              </span>
                              {p.required && (
                                <span className="text-red-400 text-[10px]">required</span>
                              )}
                            </label>
                            <p className="text-[11px] text-muted-foreground">{p.description}</p>
                            <Input
                              className="h-8 text-xs font-mono"
                              placeholder={p.default ?? p.name}
                              value={paramValues[p.name] ?? ""}
                              onChange={(e) =>
                                setParamValues((prev) => ({ ...prev, [p.name]: e.target.value }))
                              }
                            />
                          </div>
                        ))}
                    </div>
                  )}
                </TabsContent>

                {/* Body tab */}
                <TabsContent value="body" className="flex-1 overflow-auto px-4 pb-4 mt-3 flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">Request body (JSON)</p>
                    {selected.sampleBody && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 text-[10px]"
                        onClick={() => setBodyText(JSON.stringify(selected.sampleBody, null, 2))}
                      >
                        Load sample
                      </Button>
                    )}
                  </div>
                  <Textarea
                    className="flex-1 font-mono text-xs resize-none min-h-[200px]"
                    placeholder='{"key": "value"}'
                    value={bodyText}
                    onChange={(e) => setBodyText(e.target.value)}
                  />
                </TabsContent>

                {/* Schema tab */}
                <TabsContent value="schema" className="flex-1 overflow-auto px-4 pb-4 mt-3">
                  <div className="space-y-4">
                    <div>
                      <p className="text-xs font-semibold mb-2 text-muted-foreground uppercase tracking-wider">Expected Response Shape</p>
                      <pre className="bg-muted/40 border border-border/50 rounded p-3 text-xs font-mono text-green-300 whitespace-pre-wrap">
                        {selected.responseSchema ?? "No schema defined"}
                      </pre>
                    </div>
                    {selected.sampleBody && (
                      <div>
                        <p className="text-xs font-semibold mb-2 text-muted-foreground uppercase tracking-wider">Sample Request Body</p>
                        <pre className="bg-muted/40 border border-border/50 rounded p-3 text-xs font-mono text-amber-300 whitespace-pre-wrap">
                          {JSON.stringify(selected.sampleBody, null, 2)}
                        </pre>
                      </div>
                    )}
                    <div>
                      <p className="text-xs font-semibold mb-2 text-muted-foreground uppercase tracking-wider">Query Parameters</p>
                      <div className="border border-border/50 rounded overflow-hidden">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b border-border/50 bg-muted/30">
                              <th className="text-left px-3 py-1.5 font-medium text-muted-foreground">Name</th>
                              <th className="text-left px-3 py-1.5 font-medium text-muted-foreground">Type</th>
                              <th className="text-left px-3 py-1.5 font-medium text-muted-foreground">Required</th>
                              <th className="text-left px-3 py-1.5 font-medium text-muted-foreground">Description</th>
                            </tr>
                          </thead>
                          <tbody>
                            {selected.params.length === 0 ? (
                              <tr><td colSpan={4} className="px-3 py-2 text-muted-foreground">None</td></tr>
                            ) : selected.params.map((p) => (
                              <tr key={p.name} className="border-b border-border/30 last:border-0">
                                <td className="px-3 py-1.5 font-mono text-blue-300">{p.name}</td>
                                <td className="px-3 py-1.5 text-muted-foreground">{p.type}</td>
                                <td className="px-3 py-1.5">{p.required ? <span className="text-red-400">yes</span> : <span className="text-muted-foreground">no</span>}</td>
                                <td className="px-3 py-1.5 text-muted-foreground">{p.description}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </>
          )}
        </div>

        {/* ── RIGHT PANEL: Response Viewer ── */}
        <div className="w-[420px] shrink-0 flex flex-col overflow-hidden">
          {/* Status bar */}
          <div className="px-4 py-3 border-b border-border/50 shrink-0 flex items-center gap-3 min-h-[52px]">
            {response.status === null && !loading && (
              <p className="text-xs text-muted-foreground">Hit "Send" to see the response</p>
            )}
            {loading && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                Sending request…
              </div>
            )}
            {response.status !== null && !loading && (
              <>
                {response.status >= 200 && response.status < 300
                  ? <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
                  : <XCircle className="w-4 h-4 text-red-400 shrink-0" />}
                <span className={cn("text-sm font-bold font-mono", statusColor(response.status))}>
                  {response.status || "ERR"}
                </span>
                {response.ms !== null && (
                  <span className="flex items-center gap-1 text-xs text-muted-foreground ml-1">
                    <Clock className="w-3 h-3" />
                    {response.ms}ms
                  </span>
                )}
                <div className="ml-auto">
                  <Button variant="ghost" size="sm" className="h-6 gap-1 text-[10px]" onClick={copyResponse}>
                    <Copy className="w-3 h-3" /> Copy
                  </Button>
                </div>
              </>
            )}
          </div>

          {/* JSON body */}
          <ScrollArea className="flex-1">
            <div className="p-4">
              {response.error && (
                <div className="bg-red-500/10 border border-red-500/30 rounded p-3 text-xs text-red-300 font-mono whitespace-pre-wrap">
                  {response.error}
                </div>
              )}
              {response.data !== null && !response.error && (
                <AnimatePresence mode="wait">
                  <motion.pre
                    key={selectedId + response.ms}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.15 }}
                    className="text-xs font-mono leading-relaxed whitespace-pre-wrap break-all"
                    dangerouslySetInnerHTML={{ __html: syntaxHighlight(response.data) }}
                  />
                </AnimatePresence>
              )}
              {response.status === null && !loading && (
                <div className="flex flex-col items-center justify-center h-48 gap-3 text-muted-foreground">
                  <Code2 className="w-10 h-10 opacity-20" />
                  <p className="text-xs">Response will appear here</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </div>
      </div>
    </div>
  );
}
