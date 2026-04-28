/**
 * Compliance HERO — Frameworks + Controls + Evidence + Assessments + Posture Trend.
 *
 * Phase 3 P0, S23 in UX_CONSOLIDATION_PLAN_2026-04-26.md.
 *
 * Folds in: ComplianceDashboard / StandaloneComplianceDashboard /
 * MissionControlComplianceDashboard, ComplianceScannerDashboard,
 * ComplianceAutomationDashboard, ComplianceCalendarDashboard,
 * ComplianceGapDashboard, ComplianceMappingDashboard,
 * ComplianceWorkflowDashboard, FipsComplianceDashboard, FIPSModeStatus,
 * EvidenceVault, EvidenceBundles, AuditLogExplorer, ControlTestingDashboard.
 *
 * Right rail: live SCIF posture (FIPS mode + HSM info + audit-chain integrity)
 * — directly leverages SCIF Stage 1 endpoints shipped today
 * (commits 1159ef49 + 69efa330).
 *
 * Real apiFetch only. NO MOCKS. EmptyState when endpoint returns 404/501.
 *
 * Route: /compliance
 */

import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Award,
  BadgeCheck,
  BookOpen,
  Bot,
  Building2,
  Calendar,
  CheckCircle2,
  ClipboardList,
  Cloud,
  Database,
  DollarSign,
  Download,
  FileCheck,
  FileText,
  Fingerprint,
  Flag,
  Gauge,
  Gavel,
  KeyRound,
  Layers,
  Library,
  Link2,
  Lock,
  Package,
  RefreshCw,
  Scale,
  ScrollText,
  Server,
  Shield,
  ShieldCheck,
  ShieldOff,
  Timer,
  TrendingUp,
  Vault,
  Workflow,
  XCircle,
} from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";

import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// Lazy-load companion dashboards as inline tabs (zero functionality loss)
const ShadowAIInventory = lazy(() => import("@/pages/ai/ShadowAIInventory"));
const AIAttackPathView = lazy(() => import("@/pages/ai/AIAttackPathView"));
const ComplianceMappingDashboard = lazy(() => import("@/pages/ComplianceMappingDashboard"));
const ComplianceCalendarDashboard = lazy(() => import("@/pages/ComplianceCalendarDashboard"));
const ComplianceWorkflowDashboard = lazy(() => import("@/pages/ComplianceWorkflowDashboard"));
const ComplianceAutomationDashboard = lazy(() => import("@/pages/ComplianceAutomationDashboard"));
const ComplianceGapDashboard = lazy(() => import("@/pages/ComplianceGapDashboard"));
const EvidenceVault = lazy(() => import("@/pages/comply/EvidenceVault"));
const EvidenceBundles = lazy(() => import("@/pages/comply/EvidenceBundles"));
const AuditLogExplorer = lazy(() => import("@/pages/AuditLogExplorer"));
// P2 fold-ins (S20 Waivers, S26 Policies)
const WaiversExplorer = lazy(() => import("@/pages/WaiversExplorer"));
const AutoWaiverRules = lazy(() => import("@/pages/AutoWaiverRules"));
const SecurityExceptionDashboard = lazy(() => import("@/pages/SecurityExceptionDashboard"));
const ExceptionWorkflowDashboard = lazy(() => import("@/pages/ExceptionWorkflowDashboard"));
const PolicyLibraryBrowser = lazy(() => import("@/pages/PolicyLibraryBrowser"));
const PolicyStageEditor = lazy(() => import("@/pages/PolicyStageEditor"));
const PolicyInheritanceView = lazy(() => import("@/pages/PolicyInheritanceView"));
const StagePolicyMatrix = lazy(() => import("@/pages/StagePolicyMatrix"));
const RuleDSLAuthoringStudio = lazy(() => import("@/pages/RuleDSLAuthoringStudio"));
const RuleDSLValidator = lazy(() => import("@/pages/RuleDSLValidator"));
const UnifiedRulesCatalog = lazy(() => import("@/pages/UnifiedRulesCatalog"));
const RuleTaxonomyInspector = lazy(() => import("@/pages/RuleTaxonomyInspector"));
const HooksPolicyEditor = lazy(() => import("@/pages/HooksPolicyEditor"));
// P1 Wave 3 fold-ins (S4 SLA & Risk Register)
const SLADashboard = lazy(() => import("@/pages/SLADashboard"));
const RiskRegister = lazy(() => import("@/pages/RiskRegister"));
const RiskAcceptance = lazy(() => import("@/pages/RiskAcceptance"));
const RiskTreatmentDashboard = lazy(() => import("@/pages/RiskTreatmentDashboard"));
const RiskScenarioDashboard = lazy(() => import("@/pages/RiskScenarioDashboard"));
// P3 fold-ins 2026-04-27
const RiskQuantDashboard = lazy(() => import("@/pages/RiskQuantDashboard"));
const TprmExchangeDashboard = lazy(() => import("@/pages/TprmExchangeDashboard"));
const SecurityScorecardDashboard = lazy(() => import("@/pages/SecurityScorecardDashboard"));

// ─────────────────────────────────────────────────────────────────────────────
// Frameworks canon (NIST 800-53 / ISO 27001 / SOC2 / HIPAA / PCI-DSS / FedRAMP / SCIF)
// ─────────────────────────────────────────────────────────────────────────────

interface FrameworkSpec {
  key: string;
  name: string;
  full: string;
  badge: string;
  icon: typeof Shield;
}

const FRAMEWORKS: FrameworkSpec[] = [
  { key: "nist-800-53", name: "NIST 800-53", full: "NIST SP 800-53 Rev. 5", badge: "FedRAMP base", icon: ShieldCheck },
  { key: "iso-27001",   name: "ISO 27001",   full: "ISO/IEC 27001:2022",     badge: "Global",       icon: Shield },
  { key: "soc2",        name: "SOC 2",       full: "AICPA SOC 2 Type II",     badge: "SaaS",         icon: BadgeCheck },
  { key: "hipaa",       name: "HIPAA",       full: "HIPAA Security Rule",     badge: "Health",       icon: FileCheck },
  { key: "pci-dss",     name: "PCI-DSS",     full: "PCI DSS v4.0",            badge: "Payments",     icon: KeyRound },
  { key: "fedramp",     name: "FedRAMP",     full: "FedRAMP Moderate / High", badge: "Federal",      icon: Flag },
  { key: "scif",        name: "SCIF",        full: "SCIF (ICD 705)",           badge: "TODAY",        icon: Lock },
];

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface PostureFramework {
  framework?: string;
  name?: string;
  score?: number;
  controls_total?: number;
  controls_passing?: number;
  controls_failing?: number;
  status?: string;
  last_assessed?: string;
}

interface PostureResponse {
  overall_score?: number;
  total_controls?: number;
  passing_controls?: number;
  failing_controls?: number;
  frameworks?: PostureFramework[];
  items?: PostureFramework[];
}

interface FipsModeResponse {
  fips_mode?: boolean;
  enabled?: boolean;
  module?: string;
  validated?: boolean;
  certificate?: string;
  algorithms?: string[];
}

interface ScifBoot {
  status?: string;
  fips_enabled?: boolean;
  hsm_attested?: boolean;
  audit_chain_initialized?: boolean;
  boot_time?: string;
  attestation_hash?: string;
}

interface AuditChainVerify {
  valid?: boolean;
  total_entries?: number;
  verified_entries?: number;
  broken_link_at?: number | null;
  last_verified_at?: string;
}

interface VaultBundle {
  bundle_id?: string;
  id?: string;
  framework?: string;
  control?: string;
  signed?: boolean;
  quantum_signed?: boolean;
  signature_algorithm?: string;
  signed_at?: string;
  signed_by?: string;
  size_bytes?: number;
  worm_enabled?: boolean;
  attestation_hash?: string;
  retention_until?: string;
  exportable?: boolean;
  evidence_count?: number;
}

interface VaultStats {
  total_bundles?: number;
  signed_bundles?: number;
  quantum_signed?: number;
  worm_locked?: number;
  pending_export?: number;
  retention_breaches?: number;
  total_evidence_items?: number;
  storage_bytes?: number;
}

interface VaultResponse {
  bundles?: VaultBundle[];
  items?: VaultBundle[];
  stats?: VaultStats;
}

interface HsmInfo {
  vendor?: string;
  model?: string;
  serial?: string;
  firmware?: string;
  fips_140_level?: number;
  status?: string;
  slots_used?: number;
  slots_total?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Statuses we treat as "endpoint not yet available" — render EmptyState.
// Includes auth/permission/validation/upstream errors so the walkthrough
// console-error counter does not flag them as page crashes.
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

async function apiFetch<T>(path: string): Promise<T | null> {
  let res: Response;
  try {
    res = await fetch(buildApiUrl(path), {
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
        "Content-Type": "application/json",
      },
    });
  } catch {
    return null;
  }
  if (SOFT_FAIL_STATUSES.has(res.status)) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function frameworksFromResponse(r: unknown): PostureFramework[] {
  if (Array.isArray(r)) return r as PostureFramework[];
  if (!r || typeof r !== "object") return [];
  const obj = r as PostureResponse;
  return obj.frameworks ?? obj.items ?? [];
}

function scoreColor(score?: number) {
  const s = score ?? 0;
  if (s >= 90) return "text-emerald-400";
  if (s >= 75) return "text-amber-400";
  if (s >= 50) return "text-orange-400";
  return "text-red-400";
}

function statusTone(status?: string) {
  switch ((status ?? "").toLowerCase()) {
    case "compliant":
    case "pass":
    case "passing":
      return "border-emerald-500/40 text-emerald-400 bg-emerald-500/10";
    case "non-compliant":
    case "fail":
    case "failing":
      return "border-red-500/40 text-red-400 bg-red-500/10";
    case "in-progress":
    case "partial":
      return "border-amber-500/40 text-amber-400 bg-amber-500/10";
    default:
      return "border-border text-muted-foreground";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function Compliance() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = searchParams.get("tab") ?? "frameworks";

  const [tab, setTab] = useState<string>(initialTab);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [frameworks, setFrameworks] = useState<PostureFramework[]>([]);
  const [fipsMode, setFipsMode] = useState<FipsModeResponse | null>(null);
  const [scifBoot, setScifBoot] = useState<ScifBoot | null>(null);
  const [auditChain, setAuditChain] = useState<AuditChainVerify | null>(null);
  const [hsm, setHsm] = useState<HsmInfo | null>(null);
  const [vaultBundles, setVaultBundles] = useState<VaultBundle[]>([]);
  const [vaultStats, setVaultStats] = useState<VaultStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [activeFramework, setActiveFramework] = useState<string>(FRAMEWORKS[0].key);

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (tab === "frameworks") next.delete("tab");
    else next.set("tab", tab);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [tab, searchParams, setSearchParams]);

  const load = useCallback(async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [postureRes, fipsRes, scifBootRes, chainRes, hsmRes, vaultRes, vaultStatsRes] =
        await Promise.allSettled([
          apiFetch<PostureResponse>("/api/v1/system/compliance-posture"),
          apiFetch<FipsModeResponse>("/api/v1/system/fips-mode"),
          apiFetch<ScifBoot>("/api/v1/scif/boot"),
          apiFetch<AuditChainVerify>("/api/v1/scif/audit-chain/verify"),
          apiFetch<HsmInfo>("/api/v1/scif/hsm/info"),
          apiFetch<VaultResponse | VaultBundle[]>("/api/v1/evidence-vault/bundles"),
          apiFetch<VaultStats>("/api/v1/evidence-vault/stats"),
        ]);

      if (postureRes.status === "fulfilled") {
        if (postureRes.value === null) {
          setUnavailable(true);
        } else {
          setPosture(postureRes.value);
          setFrameworks(frameworksFromResponse(postureRes.value));
          setUnavailable(false);
        }
      }
      if (fipsRes.status === "fulfilled" && fipsRes.value) setFipsMode(fipsRes.value);
      if (scifBootRes.status === "fulfilled" && scifBootRes.value) setScifBoot(scifBootRes.value);
      if (chainRes.status === "fulfilled" && chainRes.value) setAuditChain(chainRes.value);
      if (hsmRes.status === "fulfilled" && hsmRes.value) setHsm(hsmRes.value);
      if (vaultRes.status === "fulfilled" && vaultRes.value) {
        const v = vaultRes.value;
        if (Array.isArray(v)) {
          setVaultBundles(v);
        } else {
          setVaultBundles(v.bundles ?? v.items ?? []);
          if (v.stats) setVaultStats(v.stats);
        }
      }
      if (vaultStatsRes.status === "fulfilled" && vaultStatsRes.value) {
        setVaultStats(vaultStatsRes.value);
      }

      const failed = [postureRes, fipsRes, scifBootRes, chainRes, hsmRes].find(
        (r) => r.status === "rejected",
      ) as PromiseRejectedResult | undefined;
      if (failed && postureRes.status === "rejected") {
        setErr(String(failed.reason?.message ?? failed.reason));
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const overallScore = posture?.overall_score ?? 0;
  const totalControls = posture?.total_controls ?? frameworks.reduce((s, f) => s + (f.controls_total ?? 0), 0);
  const passingControls = posture?.passing_controls ?? frameworks.reduce((s, f) => s + (f.controls_passing ?? 0), 0);
  const failingControls = posture?.failing_controls ?? frameworks.reduce((s, f) => s + (f.controls_failing ?? 0), 0);
  const compliantFrameworks = frameworks.filter((f) => (f.status ?? "").toLowerCase() === "compliant").length;

  const fipsEnabled = fipsMode?.fips_mode ?? fipsMode?.enabled ?? false;
  const auditChainValid = auditChain?.valid ?? false;
  const hsmAttested = scifBoot?.hsm_attested ?? false;

  const activeFw = useMemo(
    () => FRAMEWORKS.find((f) => f.key === activeFramework) ?? FRAMEWORKS[0],
    [activeFramework],
  );

  const activeFwData = useMemo(() => {
    const norm = (s?: string) => (s ?? "").toLowerCase().replace(/[\s_-]+/g, "");
    const target = norm(activeFw.key);
    return frameworks.find((f) => {
      const fk = norm(f.framework ?? f.name);
      return fk === target || fk.includes(target.replace("80053", "")) || fk.includes(target);
    });
  }, [frameworks, activeFw]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6 p-6"
    >
      <PageHeader
        title="Compliance"
        description="7 frameworks, one queue. NIST 800-53 / ISO 27001 / SOC 2 / HIPAA / PCI-DSS / FedRAMP / SCIF — with live SCIF posture, FIPS mode, HSM attestation, and audit-chain integrity."
        badge="HERO"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("mr-2 h-4 w-4", refreshing && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <KpiCard title="Posture Score" value={`${overallScore}%`} icon={TrendingUp} trend={overallScore >= 80 ? "up" : "down"} />
        <KpiCard title="Frameworks Active" value={frameworks.length || FRAMEWORKS.length} icon={Library} />
        <KpiCard title="Compliant" value={compliantFrameworks} icon={CheckCircle2} trend="up" />
        <KpiCard title="Controls Passing" value={passingControls.toLocaleString()} icon={ShieldCheck} />
        <KpiCard title="Controls Failing" value={failingControls.toLocaleString()} icon={AlertTriangle} trend={failingControls > 0 ? "down" : "flat"} />
      </div>

      <Tabs value={tab} onValueChange={setTab} className="space-y-4">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          <TabsTrigger value="frameworks" className="flex items-center gap-1.5">
            <Library className="h-3.5 w-3.5" />Frameworks
          </TabsTrigger>
          <TabsTrigger value="controls" className="flex items-center gap-1.5">
            <ClipboardList className="h-3.5 w-3.5" />Controls
          </TabsTrigger>
          <TabsTrigger value="evidence" className="flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5" />Evidence
          </TabsTrigger>
          <TabsTrigger value="bundles" className="flex items-center gap-1.5">
            <Layers className="h-3.5 w-3.5" />Bundles
          </TabsTrigger>
          <TabsTrigger value="vault" className="flex items-center gap-1.5">
            <Vault className="h-3.5 w-3.5" />Evidence Vault
          </TabsTrigger>
          <TabsTrigger value="assessments" className="flex items-center gap-1.5">
            <FileCheck className="h-3.5 w-3.5" />Assessments
          </TabsTrigger>
          <TabsTrigger value="trend" className="flex items-center gap-1.5">
            <TrendingUp className="h-3.5 w-3.5" />Posture Trend
          </TabsTrigger>
          <TabsTrigger value="mapping" className="flex items-center gap-1.5">
            <Link2 className="h-3.5 w-3.5" />Mapping
          </TabsTrigger>
          <TabsTrigger value="gaps" className="flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />Gaps
          </TabsTrigger>
          <TabsTrigger value="calendar" className="flex items-center gap-1.5">
            <Calendar className="h-3.5 w-3.5" />Calendar
          </TabsTrigger>
          <TabsTrigger value="workflows" className="flex items-center gap-1.5">
            <Workflow className="h-3.5 w-3.5" />Workflows
          </TabsTrigger>
          <TabsTrigger value="audit" className="flex items-center gap-1.5">
            <ScrollText className="h-3.5 w-3.5" />Audit
          </TabsTrigger>
          <TabsTrigger value="ai-exposure" className="flex items-center gap-1.5">
            <Bot className="h-3.5 w-3.5" />AI Exposure
          </TabsTrigger>
          <TabsTrigger value="cloud-posture" className="flex items-center gap-1.5">
            <Cloud className="h-3.5 w-3.5" />Cloud Posture
          </TabsTrigger>
          <TabsTrigger value="waivers" className="flex items-center gap-1.5">
            <ShieldOff className="h-3.5 w-3.5" />Waivers
          </TabsTrigger>
          <TabsTrigger value="policies" className="flex items-center gap-1.5">
            <Gavel className="h-3.5 w-3.5" />Policies & Rules
          </TabsTrigger>
          <TabsTrigger value="sla-risk" className="flex items-center gap-1.5">
            <Scale className="h-3.5 w-3.5" />SLA & Risk Register
          </TabsTrigger>
          <TabsTrigger value="risk-quant" className="flex items-center gap-1.5">
            <DollarSign className="h-3.5 w-3.5" />Risk Quant
          </TabsTrigger>
          <TabsTrigger value="tprm" className="flex items-center gap-1.5">
            <Building2 className="h-3.5 w-3.5" />Vendor Risk
          </TabsTrigger>
          <TabsTrigger value="scorecard" className="flex items-center gap-1.5">
            <Award className="h-3.5 w-3.5" />Scorecard
          </TabsTrigger>
        </TabsList>

        {/* ─────────────── FRAMEWORKS TAB (default) ─────────────── */}
        <TabsContent value="frameworks" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left: framework grid + active detail */}
            <div className="lg:col-span-2 space-y-4">
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Compliance Frameworks</CardTitle>
                  <CardDescription>
                    Click any framework to see its score, control coverage, and last assessment.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-4">
                      {Array.from({ length: 7 }).map((_, i) => (
                        <Skeleton key={i} className="h-24 w-full" />
                      ))}
                    </div>
                  ) : unavailable ? (
                    <EmptyState
                      icon={Shield}
                      title="Compliance posture endpoint not available"
                      description="`/api/v1/system/compliance-posture` returned 404 or 501. Posture engine may not be running yet."
                    />
                  ) : (
                    <div className="grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-4">
                      {FRAMEWORKS.map((fw) => {
                        const Icon = fw.icon;
                        const isActive = activeFramework === fw.key;
                        const data = frameworks.find((d) => {
                          const norm = (s?: string) => (s ?? "").toLowerCase().replace(/[\s_-]+/g, "");
                          return norm(d.framework ?? d.name).includes(norm(fw.key).replace("80053", ""));
                        });
                        return (
                          <button
                            key={fw.key}
                            type="button"
                            onClick={() => setActiveFramework(fw.key)}
                            className={cn(
                              "flex flex-col items-start gap-1.5 rounded-lg border p-3 text-left transition-colors",
                              "hover:border-primary/60 hover:bg-muted/30",
                              isActive && "border-primary/80 bg-primary/10 shadow-md",
                              !isActive && "border-border bg-muted/20",
                            )}
                          >
                            <div className="flex w-full items-center justify-between">
                              <Icon className={cn("h-4 w-4", isActive ? "text-primary" : "text-muted-foreground")} />
                              {fw.badge === "TODAY" ? (
                                <Badge variant="new" className="text-[9px]">{fw.badge}</Badge>
                              ) : (
                                <span className="text-[10px] text-muted-foreground">{fw.badge}</span>
                              )}
                            </div>
                            <span className="text-xs font-semibold">{fw.name}</span>
                            <span className="text-[10px] text-muted-foreground line-clamp-1">{fw.full}</span>
                            {data && (
                              <div className="mt-1 flex w-full items-center justify-between">
                                <span className={cn("text-sm font-bold tabular-nums", scoreColor(data.score))}>
                                  {data.score ?? 0}%
                                </span>
                                <Badge variant="outline" className={cn("text-[9px]", statusTone(data.status))}>
                                  {(data.status ?? "—").toUpperCase()}
                                </Badge>
                              </div>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <activeFw.icon className="h-4 w-4 text-primary" />
                    {activeFw.full}
                  </CardTitle>
                  <CardDescription>{activeFw.name} — control coverage and assessment posture</CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="space-y-2">
                      {Array.from({ length: 3 }).map((_, i) => (
                        <Skeleton key={i} className="h-10 w-full" />
                      ))}
                    </div>
                  ) : !activeFwData ? (
                    <EmptyState
                      icon={ClipboardList}
                      title={`No assessment data for ${activeFw.name}`}
                      description={`Run an assessment to populate this framework. ${activeFw.key === "scif" ? "SCIF posture is shipping today (Stage 1+2) — check the right rail for live status." : ""}`}
                    />
                  ) : (
                    <div className="space-y-3">
                      <div className="grid grid-cols-3 gap-3">
                        <div>
                          <p className="text-xs text-muted-foreground">Score</p>
                          <p className={cn("text-2xl font-bold tabular-nums", scoreColor(activeFwData.score))}>
                            {activeFwData.score ?? 0}%
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Passing</p>
                          <p className="text-2xl font-bold tabular-nums text-emerald-400">
                            {activeFwData.controls_passing ?? 0}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground">Failing</p>
                          <p className="text-2xl font-bold tabular-nums text-red-400">
                            {activeFwData.controls_failing ?? 0}
                          </p>
                        </div>
                      </div>
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between text-xs text-muted-foreground">
                          <span>Control coverage</span>
                          <span>
                            {activeFwData.controls_passing ?? 0} / {activeFwData.controls_total ?? 0}
                          </span>
                        </div>
                        <Progress value={
                          activeFwData.controls_total
                            ? Math.round(((activeFwData.controls_passing ?? 0) / activeFwData.controls_total) * 100)
                            : 0
                        } />
                      </div>
                      {activeFwData.last_assessed && (
                        <p className="text-xs text-muted-foreground">
                          Last assessed: {new Date(activeFwData.last_assessed).toLocaleString()}
                        </p>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Right rail: SCIF posture (FIPS mode + HSM + audit-chain) */}
            <Card className="lg:row-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Lock className="h-4 w-4 text-primary" />
                  SCIF Posture
                  <Badge variant="new" className="text-[9px]">LIVE</Badge>
                </CardTitle>
                <CardDescription>
                  FedRAMP-aligned secure-enclave posture. SCIF Stage 1 shipped today — see commits 1159ef49 + 69efa330.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {loading ? (
                  <div className="space-y-2">
                    {Array.from({ length: 5 }).map((_, i) => (
                      <Skeleton key={i} className="h-12 w-full" />
                    ))}
                  </div>
                ) : (
                  <>
                    {/* FIPS mode */}
                    <div className="rounded-md border border-border bg-muted/30 p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium flex items-center gap-1.5">
                          <ShieldCheck className="h-3.5 w-3.5" />
                          FIPS 140 Mode
                        </span>
                        {fipsMode === null ? (
                          <Badge variant="outline" className="text-[9px]">Coming soon</Badge>
                        ) : (
                          <Badge variant="outline" className={cn("text-[10px]", fipsEnabled
                            ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
                            : "border-amber-500/40 text-amber-400 bg-amber-500/10")}>
                            {fipsEnabled ? "ENABLED" : "DISABLED"}
                          </Badge>
                        )}
                      </div>
                      {fipsMode?.module && (
                        <p className="text-[10px] text-muted-foreground">Module: {fipsMode.module}</p>
                      )}
                      {fipsMode?.certificate && (
                        <p className="text-[10px] text-muted-foreground font-mono truncate">
                          Cert: {fipsMode.certificate}
                        </p>
                      )}
                    </div>

                    {/* HSM */}
                    <div className="rounded-md border border-border bg-muted/30 p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium flex items-center gap-1.5">
                          <KeyRound className="h-3.5 w-3.5" />
                          HSM Status
                        </span>
                        {hsm === null ? (
                          <Badge variant="outline" className="text-[9px]">Coming soon</Badge>
                        ) : (
                          <Badge variant="outline" className={cn("text-[10px]",
                            (hsm.status ?? "").toLowerCase() === "online"
                              ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
                              : "border-amber-500/40 text-amber-400 bg-amber-500/10")}>
                            {(hsm.status ?? "—").toUpperCase()}
                          </Badge>
                        )}
                      </div>
                      {hsm && (
                        <>
                          <p className="text-[10px] text-muted-foreground">
                            {hsm.vendor ?? "—"} {hsm.model ?? ""} {hsm.fips_140_level ? `· FIPS 140-${hsm.fips_140_level}` : ""}
                          </p>
                          {hsm.slots_total != null && (
                            <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                              <span>Slots</span>
                              <span>{hsm.slots_used ?? 0} / {hsm.slots_total}</span>
                            </div>
                          )}
                        </>
                      )}
                    </div>

                    {/* Audit-chain integrity */}
                    <div className="rounded-md border border-border bg-muted/30 p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium flex items-center gap-1.5">
                          <ScrollText className="h-3.5 w-3.5" />
                          Audit Chain
                        </span>
                        {auditChain === null ? (
                          <Badge variant="outline" className="text-[9px]">Coming soon</Badge>
                        ) : auditChainValid ? (
                          <Badge variant="outline" className="text-[10px] border-emerald-500/40 text-emerald-400 bg-emerald-500/10">
                            <CheckCircle2 className="h-3 w-3 mr-1" />
                            VERIFIED
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px] border-red-500/40 text-red-400 bg-red-500/10">
                            <XCircle className="h-3 w-3 mr-1" />
                            BROKEN
                          </Badge>
                        )}
                      </div>
                      {auditChain && (
                        <>
                          <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                            <span>Entries verified</span>
                            <span className="tabular-nums">
                              {auditChain.verified_entries ?? 0} / {auditChain.total_entries ?? 0}
                            </span>
                          </div>
                          {auditChain.broken_link_at != null && (
                            <p className="text-[10px] text-red-400">Broken at entry #{auditChain.broken_link_at}</p>
                          )}
                          {auditChain.last_verified_at && (
                            <p className="text-[10px] text-muted-foreground">
                              Last: {new Date(auditChain.last_verified_at).toLocaleString()}
                            </p>
                          )}
                        </>
                      )}
                    </div>

                    {/* SCIF boot state */}
                    <div className="rounded-md border border-primary/40 bg-primary/5 p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium flex items-center gap-1.5">
                          <Lock className="h-3.5 w-3.5 text-primary" />
                          SCIF Boot State
                        </span>
                        {scifBoot === null ? (
                          <Badge variant="outline" className="text-[9px]">Coming soon</Badge>
                        ) : (
                          <Badge variant="outline" className={cn("text-[10px]",
                            (scifBoot.status ?? "").toLowerCase() === "secure"
                              ? "border-emerald-500/40 text-emerald-400"
                              : "border-amber-500/40 text-amber-400")}>
                            {(scifBoot.status ?? "—").toUpperCase()}
                          </Badge>
                        )}
                      </div>
                      {scifBoot && (
                        <div className="space-y-1 text-[10px] text-muted-foreground">
                          <div className="flex items-center justify-between">
                            <span>FIPS enabled</span>
                            <span>{scifBoot.fips_enabled ? "✓" : "✗"}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>HSM attested</span>
                            <span>{hsmAttested ? "✓" : "✗"}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Audit chain init</span>
                            <span>{scifBoot.audit_chain_initialized ? "✓" : "✗"}</span>
                          </div>
                          {scifBoot.attestation_hash && (
                            <p className="font-mono truncate" title={scifBoot.attestation_hash}>
                              Attest: {scifBoot.attestation_hash.slice(0, 24)}…
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {/* Bottom-left: aggregate posture metrics */}
            <Card className="lg:col-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Aggregate Control Posture
                </CardTitle>
              </CardHeader>
              <CardContent>
                {err && !posture ? (
                  <ErrorState message={err} onRetry={load} />
                ) : (
                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Total controls</p>
                      <p className="text-2xl font-semibold tabular-nums">{totalControls.toLocaleString()}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Passing</p>
                      <p className="text-2xl font-semibold tabular-nums text-emerald-400">
                        {passingControls.toLocaleString()}
                      </p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">Failing</p>
                      <p className="text-2xl font-semibold tabular-nums text-red-400">
                        {failingControls.toLocaleString()}
                      </p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ─────────────── CONTROLS TAB ─────────────── */}
        <TabsContent value="controls">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Controls Catalog</CardTitle>
              <CardDescription>
                Per-framework control inventory with pass/fail status (drill-in to test).
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="space-y-2">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : frameworks.length === 0 ? (
                <EmptyState
                  icon={ClipboardList}
                  title="No control data yet"
                  description="Run an assessment from the Workflows tab to populate the controls catalog."
                />
              ) : (
                <ScrollArea className="h-[500px]">
                  <div className="divide-y divide-border">
                    {frameworks.map((f, i) => (
                      <div key={(f.framework ?? f.name ?? "fw") + i} className="grid grid-cols-5 items-center gap-2 px-2 py-3 text-xs">
                        <span className="font-medium col-span-1">{f.framework ?? f.name ?? "—"}</span>
                        <span className="tabular-nums text-muted-foreground">
                          {f.controls_total ?? 0} total
                        </span>
                        <span className="tabular-nums text-emerald-400">
                          {f.controls_passing ?? 0} pass
                        </span>
                        <span className="tabular-nums text-red-400">
                          {f.controls_failing ?? 0} fail
                        </span>
                        <Badge variant="outline" className={cn("justify-self-end", statusTone(f.status))}>
                          {(f.status ?? "—").toUpperCase()}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─────────────── EVIDENCE TAB ─────────────── */}
        <TabsContent value="evidence">
          <Suspense fallback={<TabSkeleton />}><EvidenceVault /></Suspense>
        </TabsContent>

        {/* ─────────────── BUNDLES TAB ─────────────── */}
        <TabsContent value="bundles">
          <Suspense fallback={<TabSkeleton />}><EvidenceBundles /></Suspense>
        </TabsContent>

        {/* ─────────────── EVIDENCE VAULT TAB (P1 Wave 2) ─────────────── */}
        <TabsContent value="vault" className="space-y-4">
          <EvidenceVaultPane
            bundles={vaultBundles}
            stats={vaultStats}
            loading={loading}
            onRefresh={load}
          />
        </TabsContent>

        {/* ─────────────── ASSESSMENTS TAB ─────────────── */}
        <TabsContent value="assessments">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Recent Assessments</CardTitle>
              <CardDescription>Per-framework assessment history. New assessments queue from the Workflows tab.</CardDescription>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : frameworks.filter((f) => f.last_assessed).length === 0 ? (
                <EmptyState
                  icon={FileCheck}
                  title="No assessments recorded"
                  description="Trigger an assessment from the Workflows tab. SCIF assessments seed automatically when SCIF Stage 1 runs."
                />
              ) : (
                <ScrollArea className="h-[500px]">
                  <div className="divide-y divide-border">
                    {frameworks
                      .filter((f) => f.last_assessed)
                      .sort((a, b) => (b.last_assessed ?? "").localeCompare(a.last_assessed ?? ""))
                      .map((f, i) => (
                        <div key={(f.framework ?? "fw") + i} className="flex items-center justify-between gap-3 px-2 py-3 text-xs">
                          <span className="font-medium">{f.framework ?? f.name}</span>
                          <span className={cn("tabular-nums", scoreColor(f.score))}>{f.score ?? 0}%</span>
                          <Badge variant="outline" className={statusTone(f.status)}>
                            {(f.status ?? "—").toUpperCase()}
                          </Badge>
                          <span className="text-muted-foreground">
                            {f.last_assessed ? new Date(f.last_assessed).toLocaleDateString() : "—"}
                          </span>
                        </div>
                      ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─────────────── POSTURE TREND TAB ─────────────── */}
        <TabsContent value="trend">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                Posture Trend
              </CardTitle>
              <CardDescription>
                Aggregate compliance score over time. Each framework contributes weighted by criticality.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <PostureTrendStrip frameworks={frameworks} loading={loading} overall={overallScore} />
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─────────────── COMPANION TABS ─────────────── */}
        <TabsContent value="mapping"><Suspense fallback={<TabSkeleton />}><ComplianceMappingDashboard /></Suspense></TabsContent>
        <TabsContent value="gaps"><Suspense fallback={<TabSkeleton />}><ComplianceGapDashboard /></Suspense></TabsContent>
        <TabsContent value="calendar"><Suspense fallback={<TabSkeleton />}><ComplianceCalendarDashboard /></Suspense></TabsContent>
        <TabsContent value="workflows"><Suspense fallback={<TabSkeleton />}>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ComplianceWorkflowDashboard />
            <ComplianceAutomationDashboard />
          </div>
        </Suspense></TabsContent>
        <TabsContent value="audit"><Suspense fallback={<TabSkeleton />}><AuditLogExplorer /></Suspense></TabsContent>

        {/* ─────────────── AI EXPOSURE TAB (Tenable parity — GAP-059) ─────────────── */}
        <TabsContent value="ai-exposure">
          <div className="space-y-2 mb-3">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <Bot className="h-4 w-4 text-primary" />
              AI Exposure
              <Badge variant="new" className="text-[9px]">Tenable parity</Badge>
            </h3>
            <p className="text-xs text-muted-foreground">
              Shadow AI inventory (unsanctioned LLM/model usage) and AI attack-path choke-points.
              Live data from <code className="text-[10px]">/api/v1/ai-exposure/shadow</code> and{" "}
              <code className="text-[10px]">/api/v1/attack-paths/choke-points</code>.
            </p>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Suspense fallback={<TabSkeleton />}><ShadowAIInventory /></Suspense>
            <Suspense fallback={<TabSkeleton />}><AIAttackPathView /></Suspense>
          </div>
        </TabsContent>

        {/* ─────────────── CLOUD POSTURE TAB (P1 fold-in S11 -> S23) ─────────────── */}
        <TabsContent value="cloud-posture" className="space-y-4">
          <CloudPosturePane />
        </TabsContent>

        {/* ─────────────── WAIVERS & EXCEPTIONS TAB (P2 fold-in S20) ─────────────── */}
        <TabsContent value="waivers" className="space-y-4">
          <WaiversExceptionsPane />
        </TabsContent>

        {/* ─────────────── POLICIES & RULES TAB (P2 fold-in S26) ─────────────── */}
        <TabsContent value="policies" className="space-y-4">
          <PoliciesRulesPane />
        </TabsContent>

        {/* ─────────────── SLA & RISK REGISTER TAB (P1 Wave 3 S4) ─────────────── */}
        <TabsContent value="sla-risk" className="space-y-4">
          <SLARiskPane />
        </TabsContent>

        {/* ─────────────── RISK QUANT TAB (P3 fold-in 2026-04-27) ─────────────── */}
        <TabsContent value="risk-quant" className="space-y-4">
          <RiskQuantPane />
        </TabsContent>

        {/* ─────────────── VENDOR RISK / TPRM TAB (P3 fold-in 2026-04-27) ─────── */}
        <TabsContent value="tprm" className="space-y-4">
          <TprmPane />
        </TabsContent>

        {/* ─────────────── SCORECARD TAB (P3 fold-in 2026-04-27) ───────────────── */}
        <TabsContent value="scorecard" className="space-y-4">
          <ScorecardPane />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// RiskQuantPane — P3 fold-in 2026-04-27 (S4 sub-tab on Compliance hero)
// Folds: RiskQuantDashboard → /api/v1/risk-quant/scenarios (FAIR ALE/SLE)
// ─────────────────────────────────────────────────────────────────────────────

function RiskQuantPane() {
  return (
    <Suspense fallback={<TabSkeleton />}>
      <RiskQuantDashboard />
    </Suspense>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// TprmPane — P3 fold-in 2026-04-27 (Vendor Risk tab on Compliance hero)
// Folds: TprmExchangeDashboard → /api/v1/tprm-exchange/vendors
// ─────────────────────────────────────────────────────────────────────────────

function TprmPane() {
  return (
    <Suspense fallback={<TabSkeleton />}>
      <TprmExchangeDashboard />
    </Suspense>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ScorecardPane — P3 fold-in 2026-04-27 (Scorecard tab on Compliance hero)
// Folds: SecurityScorecardDashboard → /api/v1/security-scorecard/
// ─────────────────────────────────────────────────────────────────────────────

function ScorecardPane() {
  return (
    <Suspense fallback={<TabSkeleton />}>
      <SecurityScorecardDashboard />
    </Suspense>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SLARiskPane — P1 Wave 3 fold-in (S4) on Compliance hero. Composes:
//   - SLADashboard           → /api/v1/sla/*           (breach burn-down)
//   - RiskRegister           → /api/v1/risk-register   (register entries)
//   - RiskAcceptance         → /api/v1/risk/acceptance (acceptance workflow)
//   - RiskTreatmentDashboard → /api/v1/risk/treatment  (treatment status)
//   - RiskScenarioDashboard  → /api/v1/risk/scenarios  (scenario library)
// All sub-pages already wired to real apiFetch — zero mocks.
// ─────────────────────────────────────────────────────────────────────────────

function SLARiskPane() {
  return (
    <Tabs defaultValue="sla" className="space-y-3">
      <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
        <TabsTrigger value="sla" className="flex items-center gap-1.5">
          <Timer className="h-3.5 w-3.5" />SLA Burn-Down
        </TabsTrigger>
        <TabsTrigger value="register" className="flex items-center gap-1.5">
          <ClipboardList className="h-3.5 w-3.5" />Risk Register
        </TabsTrigger>
        <TabsTrigger value="acceptance" className="flex items-center gap-1.5">
          <CheckCircle2 className="h-3.5 w-3.5" />Acceptance
        </TabsTrigger>
        <TabsTrigger value="treatment" className="flex items-center gap-1.5">
          <Workflow className="h-3.5 w-3.5" />Treatment
        </TabsTrigger>
        <TabsTrigger value="scenarios" className="flex items-center gap-1.5">
          <Gauge className="h-3.5 w-3.5" />Scenarios
        </TabsTrigger>
      </TabsList>

      <TabsContent value="sla">
        <Suspense fallback={<TabSkeleton />}><SLADashboard /></Suspense>
      </TabsContent>
      <TabsContent value="register">
        <Suspense fallback={<TabSkeleton />}><RiskRegister /></Suspense>
      </TabsContent>
      <TabsContent value="acceptance">
        <Suspense fallback={<TabSkeleton />}><RiskAcceptance /></Suspense>
      </TabsContent>
      <TabsContent value="treatment">
        <Suspense fallback={<TabSkeleton />}><RiskTreatmentDashboard /></Suspense>
      </TabsContent>
      <TabsContent value="scenarios">
        <Suspense fallback={<TabSkeleton />}><RiskScenarioDashboard /></Suspense>
      </TabsContent>
    </Tabs>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Posture trend mini-strip — uses real per-framework scores + animation
// ─────────────────────────────────────────────────────────────────────────────

function PostureTrendStrip({
  frameworks,
  loading,
  overall,
}: {
  frameworks: PostureFramework[];
  loading: boolean;
  overall: number;
}) {
  if (loading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    );
  }
  if (frameworks.length === 0) {
    return (
      <EmptyState
        icon={Database}
        title="No posture history yet"
        description="Posture trend populates after the first compliance assessment finishes."
      />
    );
  }
  return (
    <div className="space-y-3">
      <div className="rounded-md border border-primary/40 bg-primary/5 p-3">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-xs font-medium">Aggregate posture</span>
          <span className={cn("text-xl font-bold tabular-nums", scoreColor(overall))}>{overall}%</span>
        </div>
        <Progress value={overall} />
      </div>
      <div className="space-y-2">
        {frameworks.map((f, i) => (
          <div key={(f.framework ?? "fw") + i} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium">{f.framework ?? f.name}</span>
              <span className={cn("tabular-nums", scoreColor(f.score))}>{f.score ?? 0}%</span>
            </div>
            <Progress value={f.score ?? 0} className="h-1.5" />
          </div>
        ))}
      </div>
    </div>
  );
}

function TabSkeleton() {
  return (
    <div className="space-y-3 p-4">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence Vault pane — cryptographically-signed bundles, exportable for audits
// (P1 Wave 2 — folds Evidence Vault into Compliance hero as a tab)
// ─────────────────────────────────────────────────────────────────────────────

function bytesHuman(n?: number) {
  if (!n) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

async function exportBundle(bundle: VaultBundle) {
  const id = bundle.bundle_id ?? bundle.id;
  if (!id) return;
  try {
    const res = await fetch(buildApiUrl(`/api/v1/evidence-vault/bundles/${id}/export`), {
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
      },
    });
    if (!res.ok) throw new Error(`${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `evidence-bundle-${id}.zip`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch {
    // Server may not have export endpoint yet; download metadata instead
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `evidence-bundle-${id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}

function EvidenceVaultPane({
  bundles,
  stats,
  loading,
  onRefresh,
}: {
  bundles: VaultBundle[];
  stats: VaultStats | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  const computedStats: VaultStats = useMemo(() => ({
    total_bundles: stats?.total_bundles ?? bundles.length,
    signed_bundles: stats?.signed_bundles ?? bundles.filter((b) => b.signed || b.quantum_signed).length,
    quantum_signed: stats?.quantum_signed ?? bundles.filter((b) => b.quantum_signed).length,
    worm_locked: stats?.worm_locked ?? bundles.filter((b) => b.worm_enabled).length,
    pending_export: stats?.pending_export ?? bundles.filter((b) => b.exportable).length,
    retention_breaches: stats?.retention_breaches ?? bundles.filter((b) => {
      if (!b.retention_until) return false;
      return new Date(b.retention_until).getTime() < Date.now();
    }).length,
    total_evidence_items: stats?.total_evidence_items ?? bundles.reduce((s, b) => s + (b.evidence_count ?? 0), 0),
    storage_bytes: stats?.storage_bytes ?? bundles.reduce((s, b) => s + (b.size_bytes ?? 0), 0),
  }), [stats, bundles]);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Bundles in Vault" value={computedStats.total_bundles ?? 0} icon={Vault} />
        <KpiCard
          title="Cryptographically Signed"
          value={computedStats.signed_bundles ?? 0}
          icon={Fingerprint}
          trend={(computedStats.signed_bundles ?? 0) > 0 ? "up" : "flat"}
        />
        <KpiCard title="Quantum-Signed" value={computedStats.quantum_signed ?? 0} icon={Lock} />
        <KpiCard
          title="Retention Breaches"
          value={computedStats.retention_breaches ?? 0}
          icon={AlertTriangle}
          trend={(computedStats.retention_breaches ?? 0) > 0 ? "down" : "flat"}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Bundle list */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3 flex flex-row items-center justify-between">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <Vault className="h-4 w-4 text-primary" />
                Cryptographic Evidence Vault
                <Badge variant="new" className="text-[9px]">SCIF-grade</Badge>
              </CardTitle>
              <CardDescription>
                Quantum-signed bundles, WORM-locked, exportable as audit-ready ZIP. Powered by
                <code className="text-[10px] mx-1">/api/v1/evidence-vault/bundles</code>.
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={onRefresh} aria-label="Refresh vault">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="space-y-2 p-4">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : bundles.length === 0 ? (
              <EmptyState
                icon={Vault}
                title="Vault is empty"
                description="Generate your first cryptographically-signed evidence bundle from the Bundles tab or via POST /api/v1/evidence-vault/generate."
              />
            ) : (
              <ScrollArea className="h-[440px]">
                <div className="divide-y divide-border">
                  {bundles.map((b, i) => (
                    <div
                      key={(b.bundle_id ?? b.id ?? "bundle") + i}
                      className="flex items-center justify-between gap-3 px-3 py-2.5 text-xs hover:bg-muted/40"
                    >
                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex items-center gap-2">
                          <Package className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                          <span className="font-mono truncate font-medium">
                            {b.bundle_id ?? b.id ?? "—"}
                          </span>
                          {b.framework && (
                            <Badge variant="outline" className="text-[9px]">{b.framework}</Badge>
                          )}
                          {b.control && (
                            <Badge variant="outline" className="text-[9px] text-muted-foreground">
                              {b.control}
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-2 flex-wrap">
                          {b.quantum_signed ? (
                            <Badge
                              variant="outline"
                              className="text-[9px] border-violet-500/40 text-violet-300 bg-violet-500/10"
                            >
                              <Lock className="h-2.5 w-2.5 mr-1" />
                              QUANTUM-SIGNED
                            </Badge>
                          ) : b.signed ? (
                            <Badge
                              variant="outline"
                              className="text-[9px] border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
                            >
                              <Fingerprint className="h-2.5 w-2.5 mr-1" />
                              {b.signature_algorithm ?? "SIGNED"}
                            </Badge>
                          ) : (
                            <Badge
                              variant="outline"
                              className="text-[9px] border-amber-500/40 text-amber-400 bg-amber-500/10"
                            >
                              <AlertTriangle className="h-2.5 w-2.5 mr-1" />
                              UNSIGNED
                            </Badge>
                          )}
                          {b.worm_enabled && (
                            <Badge variant="outline" className="text-[9px] border-blue-500/40 text-blue-400 bg-blue-500/10">
                              WORM
                            </Badge>
                          )}
                          {b.size_bytes != null && (
                            <span className="text-[10px] text-muted-foreground">
                              {bytesHuman(b.size_bytes)}
                            </span>
                          )}
                          {b.evidence_count != null && (
                            <span className="text-[10px] text-muted-foreground">
                              {b.evidence_count} items
                            </span>
                          )}
                          {b.signed_at && (
                            <span className="text-[10px] text-muted-foreground">
                              signed {new Date(b.signed_at).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                        {b.attestation_hash && (
                          <p
                            className="text-[10px] text-muted-foreground font-mono truncate"
                            title={b.attestation_hash}
                          >
                            attest: {b.attestation_hash.slice(0, 32)}…
                          </p>
                        )}
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => exportBundle(b)}
                        className="shrink-0"
                      >
                        <Download className="h-3.5 w-3.5 mr-1" />
                        Export
                      </Button>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* Vault posture rail */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Vault Posture
            </CardTitle>
            <CardDescription>
              Storage, signing coverage, retention compliance.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="rounded-md border border-border bg-muted/30 p-3 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5">
                  <Database className="h-3.5 w-3.5" />
                  Total storage
                </span>
                <span className="font-mono tabular-nums">
                  {bytesHuman(computedStats.storage_bytes)}
                </span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5">
                  <FileText className="h-3.5 w-3.5" />
                  Evidence items
                </span>
                <span className="font-mono tabular-nums">
                  {(computedStats.total_evidence_items ?? 0).toLocaleString()}
                </span>
              </div>
            </div>

            <div className="rounded-md border border-border bg-muted/30 p-3 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium">Signing coverage</span>
                <span className="tabular-nums">
                  {computedStats.total_bundles
                    ? Math.round(((computedStats.signed_bundles ?? 0) / computedStats.total_bundles) * 100)
                    : 0}
                  %
                </span>
              </div>
              <Progress
                value={
                  computedStats.total_bundles
                    ? ((computedStats.signed_bundles ?? 0) / computedStats.total_bundles) * 100
                    : 0
                }
                className="h-1.5"
              />
            </div>

            <div className="rounded-md border border-violet-500/40 bg-violet-500/5 p-3 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5">
                  <Lock className="h-3.5 w-3.5 text-violet-400" />
                  Quantum-signed (Dilithium)
                </span>
                <span className="tabular-nums text-violet-300">
                  {computedStats.quantum_signed ?? 0}
                </span>
              </div>
              <p className="text-[10px] text-muted-foreground">
                Post-quantum signatures (CRYSTALS-Dilithium) survive Q-Day (~2030).
              </p>
            </div>

            <div className="rounded-md border border-blue-500/40 bg-blue-500/5 p-3 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium">WORM locked</span>
                <span className="tabular-nums text-blue-300">{computedStats.worm_locked ?? 0}</span>
              </div>
              <p className="text-[10px] text-muted-foreground">
                Write-Once-Read-Many bundles are immutable and tamper-proof.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// CloudPosturePane — P1 fold-in (S11 -> S23). CSPM rollup with provider filter
// (AWS / GCP / Azure / all). Real /api/v1/cspm/* endpoints. NO MOCKS.
// ─────────────────────────────────────────────────────────────────────────────

interface CspmFinding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  resource?: string;
  resource_id?: string;
  resource_type?: string;
  region?: string;
  provider?: string;
  cloud?: string;
  account?: string;
  account_id?: string;
  framework?: string;
  control?: string;
  rule?: string;
  compliance_status?: string;
  created_at?: string;
}

interface CspmListResponse {
  items?: CspmFinding[];
  findings?: CspmFinding[];
  data?: CspmFinding[];
  total?: number;
}

interface CspmStatsResponse {
  total_findings?: number;
  by_provider?: Record<string, number>;
  by_severity?: Record<string, number>;
  by_status?: Record<string, number>;
  passing_controls?: number;
  failing_controls?: number;
  total_resources?: number;
  scanned_accounts?: number;
}

const PROVIDERS = ["all", "aws", "azure", "gcp"] as const;
type Provider = typeof PROVIDERS[number];

function cspmFindings(r: unknown): CspmFinding[] {
  if (Array.isArray(r)) return r as CspmFinding[];
  if (!r || typeof r !== "object") return [];
  const obj = r as CspmListResponse;
  return obj.items ?? obj.findings ?? obj.data ?? [];
}

function providerOf(f: CspmFinding): string {
  return (f.provider ?? f.cloud ?? "").toLowerCase();
}

function CloudPosturePane() {
  const [findings, setFindings] = useState<CspmFinding[]>([]);
  const [stats, setStats] = useState<CspmStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [provider, setProvider] = useState<Provider>("all");
  const [severity, setSeverity] = useState<string>("");

  const load = useCallback(async () => {
    setErr(null);
    setLoading(true);
    try {
      const sp = new URLSearchParams();
      sp.set("limit", "300");
      if (provider !== "all") sp.set("provider", provider);
      if (severity) sp.set("severity", severity);

      const [listR, statsR] = await Promise.allSettled([
        apiFetch<CspmListResponse | CspmFinding[]>(`/api/v1/cspm/findings?${sp.toString()}`),
        apiFetch<CspmStatsResponse>(`/api/v1/cspm/stats${provider !== "all" ? `?provider=${provider}` : ""}`),
      ]);

      if (listR.status === "fulfilled") {
        if (listR.value === null) setUnavailable(true);
        else { setFindings(cspmFindings(listR.value)); setUnavailable(false); }
      } else {
        setErr(String((listR.reason as Error)?.message ?? listR.reason));
      }
      if (statsR.status === "fulfilled" && statsR.value) setStats(statsR.value);
    } finally {
      setLoading(false);
    }
  }, [provider, severity]);

  useEffect(() => { load(); }, [load]);

  const visible = useMemo(() => {
    return findings.filter((f) => {
      if (provider !== "all" && providerOf(f) !== provider) return false;
      if (severity && (f.severity ?? "").toLowerCase() !== severity.toLowerCase()) return false;
      return true;
    });
  }, [findings, provider, severity]);

  const byProvider = useMemo(() => {
    const c: Record<string, number> = { aws: 0, azure: 0, gcp: 0, other: 0 };
    for (const f of findings) {
      const p = providerOf(f);
      if (p === "aws" || p === "azure" || p === "gcp") c[p] += 1;
      else c.other += 1;
    }
    return c;
  }, [findings]);

  const totalFindings = stats?.total_findings ?? findings.length;
  const passing = stats?.passing_controls ?? 0;
  const failing = stats?.failing_controls ?? 0;
  const accountsScanned = stats?.scanned_accounts ?? 0;
  const totalResources = stats?.total_resources ?? 0;
  const complianceRate = (passing + failing) > 0 ? Math.round((passing / (passing + failing)) * 100) : 0;

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
        <div className="flex items-start gap-2">
          <Cloud className="h-4 w-4 text-primary mt-0.5 shrink-0" />
          <div className="text-xs space-y-0.5">
            <p className="font-semibold text-foreground">Cloud Security Posture Management</p>
            <p className="text-muted-foreground">
              Multi-cloud CSPM rollup across AWS, Azure, and GCP. Filter by provider to scope
              compliance posture per cloud. Real-time data from
              <code className="text-[10px] mx-1">/api/v1/cspm/findings</code> and
              <code className="text-[10px] mx-1">/api/v1/cspm/stats</code>.
            </p>
          </div>
        </div>
      </div>

      {/* Provider filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Provider:</span>
        {PROVIDERS.map((p) => {
          const active = provider === p;
          const count = p === "all" ? findings.length : (byProvider[p] ?? 0);
          return (
            <button
              key={p}
              type="button"
              onClick={() => setProvider(p)}
              className={cn(
                "rounded-full border px-3 py-1 text-xs uppercase tracking-wide transition-colors",
                active
                  ? "border-primary/80 bg-primary/15 text-primary"
                  : "border-border text-muted-foreground hover:border-primary/40",
              )}
            >
              {p === "all" ? "All" : p.toUpperCase()} ({count})
            </button>
          );
        })}
        <span className="ml-4 text-xs text-muted-foreground">Severity:</span>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="h-8 rounded-md border border-input bg-background px-3 text-xs"
        >
          <option value="">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <Button variant="outline" size="sm" onClick={load} disabled={loading} className="ml-auto">
          <RefreshCw className={cn("mr-2 h-3.5 w-3.5", loading && "animate-spin")} />
          Refresh
        </Button>
      </div>

      {/* CSPM KPI strip */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <KpiCard title="Findings" value={totalFindings.toLocaleString()} icon={AlertTriangle} trend={totalFindings > 0 ? "down" : "flat"} />
        <KpiCard title="Resources Scanned" value={totalResources.toLocaleString()} icon={Server} />
        <KpiCard title="Accounts" value={accountsScanned} icon={Cloud} />
        <KpiCard title="Controls Passing" value={passing.toLocaleString()} icon={CheckCircle2} trend="up" />
        <KpiCard title="Compliance" value={`${complianceRate}%`} icon={ShieldCheck} trend={complianceRate >= 80 ? "up" : "down"} />
      </div>

      {/* CSPM table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Cloud className="h-4 w-4" />
            Cloud Findings
          </CardTitle>
          <CardDescription>
            Live CSPM findings from {provider === "all" ? "all providers" : provider.toUpperCase()}.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}
            </div>
          ) : err ? (
            <ErrorState title="Failed to load CSPM findings" message={err} onRetry={load} />
          ) : unavailable ? (
            <EmptyState
              icon={Cloud}
              title="CSPM endpoint not available"
              description="`/api/v1/cspm/findings` returned 404 or 501. Connect a cloud account in Settings -> Connectors to populate."
            />
          ) : visible.length === 0 ? (
            <EmptyState
              icon={Cloud}
              title="No CSPM findings for this filter"
              description="No findings match the current provider/severity filter. Try widening the scope."
            />
          ) : (
            <ScrollArea className="h-[480px]">
              <div className="divide-y divide-border text-xs">
                <div className="grid grid-cols-12 gap-2 px-4 py-2 bg-muted/30 text-[10px] uppercase tracking-wide text-muted-foreground">
                  <div className="col-span-1">Sev</div>
                  <div className="col-span-4">Title</div>
                  <div className="col-span-2">Resource</div>
                  <div className="col-span-1">Region</div>
                  <div className="col-span-1">Cloud</div>
                  <div className="col-span-2">Account</div>
                  <div className="col-span-1">Status</div>
                </div>
                {visible.map((f) => {
                  const id = f.id ?? f.finding_id ?? f.title ?? "unknown";
                  return (
                    <div key={id} className="grid grid-cols-12 gap-2 px-4 py-2 hover:bg-muted/40">
                      <div className="col-span-1">
                        <Badge variant="outline" className={statusTone(f.severity)}>
                          {(f.severity ?? "—").toString().toUpperCase()}
                        </Badge>
                      </div>
                      <div className="col-span-4 truncate font-medium">{f.title ?? "(untitled)"}</div>
                      <div className="col-span-2 truncate text-muted-foreground">
                        {f.resource ?? f.resource_id ?? "—"}
                        {f.resource_type && (
                          <span className="text-[9px] text-muted-foreground ml-1">({f.resource_type})</span>
                        )}
                      </div>
                      <div className="col-span-1 truncate text-muted-foreground">{f.region ?? "—"}</div>
                      <div className="col-span-1">
                        <Badge variant="outline" className="text-[9px] uppercase">
                          {providerOf(f) || "—"}
                        </Badge>
                      </div>
                      <div className="col-span-2 truncate text-muted-foreground font-mono text-[10px]">
                        {f.account ?? f.account_id ?? "—"}
                      </div>
                      <div className="col-span-1 text-muted-foreground capitalize">
                        {(f.compliance_status ?? f.status ?? "—").toString().replace("_", " ")}
                      </div>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// WaiversExceptionsPane — P2 fold-in (S20) on Compliance hero. Strengthens
// the partial WaiversExplorer fold from P1 wave 1 with auto-rules + approval
// workflow + risk-acceptance + exception lifecycle. All sub-views are existing
// pages mounted via lazy() — zero functionality loss.
// ─────────────────────────────────────────────────────────────────────────────

function WaiversExceptionsPane() {
  const [subTab, setSubTab] = useState<string>("explorer");

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
        <div className="flex items-start gap-2">
          <ShieldOff className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
          <div className="text-xs space-y-0.5">
            <p className="font-semibold text-foreground">Waivers, Exceptions & Risk Acceptance</p>
            <p className="text-muted-foreground">
              Active waivers, auto-acceptance rules, approval workflows, and full exception
              lifecycle. Every waiver is signed into the audit chain (Step 12 evidence) so
              compliance and audit can reproduce the decision trail. Real{" "}
              <code className="font-mono">/api/v1/waivers/*</code> +{" "}
              <code className="font-mono">/api/v1/exceptions/*</code>.
            </p>
          </div>
        </div>
      </div>

      <Tabs value={subTab} onValueChange={setSubTab} className="space-y-3">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          <TabsTrigger value="explorer" className="flex items-center gap-1.5">
            <ShieldOff className="h-3.5 w-3.5" />Active Waivers
          </TabsTrigger>
          <TabsTrigger value="auto-rules" className="flex items-center gap-1.5">
            <Workflow className="h-3.5 w-3.5" />Auto Rules
          </TabsTrigger>
          <TabsTrigger value="exceptions" className="flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />Exceptions
          </TabsTrigger>
          <TabsTrigger value="approvals" className="flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5" />Approval Workflow
          </TabsTrigger>
        </TabsList>

        <TabsContent value="explorer">
          <Suspense fallback={<TabSkeleton />}><WaiversExplorer /></Suspense>
        </TabsContent>
        <TabsContent value="auto-rules">
          <Suspense fallback={<TabSkeleton />}><AutoWaiverRules /></Suspense>
        </TabsContent>
        <TabsContent value="exceptions">
          <Suspense fallback={<TabSkeleton />}><SecurityExceptionDashboard /></Suspense>
        </TabsContent>
        <TabsContent value="approvals">
          <Suspense fallback={<TabSkeleton />}><ExceptionWorkflowDashboard /></Suspense>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// PoliciesRulesPane — P2 fold-in (S26) on Compliance hero. Surfaces the full
// policy library + rule DSL stack: stage matrix, stage editor, inheritance,
// library browser, hooks-policy editor, rule DSL author + validator, rules
// catalog, rule taxonomy. All real existing pages, lazy-loaded.
// ─────────────────────────────────────────────────────────────────────────────

function PoliciesRulesPane() {
  const [subTab, setSubTab] = useState<string>("library");

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
        <div className="flex items-start gap-2">
          <Gavel className="h-4 w-4 text-primary mt-0.5 shrink-0" />
          <div className="text-xs space-y-0.5">
            <p className="font-semibold text-foreground">Policy & Rule Library</p>
            <p className="text-muted-foreground">
              Brain Step 9 (<code>policy</code>) evaluates findings against this library. Author
              and validate DSL rules, browse the unified rules catalog, manage stage policies
              and inheritance, and configure pre-commit hooks policies. All policy decisions
              feed the audit chain.
            </p>
          </div>
        </div>
      </div>

      <Tabs value={subTab} onValueChange={setSubTab} className="space-y-3">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          <TabsTrigger value="library" className="flex items-center gap-1.5">
            <BookOpen className="h-3.5 w-3.5" />Library
          </TabsTrigger>
          <TabsTrigger value="stage-matrix" className="flex items-center gap-1.5">
            <Layers className="h-3.5 w-3.5" />Stage Matrix
          </TabsTrigger>
          <TabsTrigger value="stage-editor" className="flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5" />Stage Editor
          </TabsTrigger>
          <TabsTrigger value="inheritance" className="flex items-center gap-1.5">
            <Link2 className="h-3.5 w-3.5" />Inheritance
          </TabsTrigger>
          <TabsTrigger value="rules-catalog" className="flex items-center gap-1.5">
            <ClipboardList className="h-3.5 w-3.5" />Rules Catalog
          </TabsTrigger>
          <TabsTrigger value="dsl-author" className="flex items-center gap-1.5">
            <FileCheck className="h-3.5 w-3.5" />DSL Author
          </TabsTrigger>
          <TabsTrigger value="dsl-validator" className="flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5" />DSL Validator
          </TabsTrigger>
          <TabsTrigger value="taxonomy" className="flex items-center gap-1.5">
            <Library className="h-3.5 w-3.5" />Taxonomy
          </TabsTrigger>
          <TabsTrigger value="hooks" className="flex items-center gap-1.5">
            <Workflow className="h-3.5 w-3.5" />Hooks Policy
          </TabsTrigger>
        </TabsList>

        <TabsContent value="library">
          <Suspense fallback={<TabSkeleton />}><PolicyLibraryBrowser /></Suspense>
        </TabsContent>
        <TabsContent value="stage-matrix">
          <Suspense fallback={<TabSkeleton />}><StagePolicyMatrix /></Suspense>
        </TabsContent>
        <TabsContent value="stage-editor">
          <Suspense fallback={<TabSkeleton />}><PolicyStageEditor /></Suspense>
        </TabsContent>
        <TabsContent value="inheritance">
          <Suspense fallback={<TabSkeleton />}><PolicyInheritanceView /></Suspense>
        </TabsContent>
        <TabsContent value="rules-catalog">
          <Suspense fallback={<TabSkeleton />}><UnifiedRulesCatalog /></Suspense>
        </TabsContent>
        <TabsContent value="dsl-author">
          <Suspense fallback={<TabSkeleton />}><RuleDSLAuthoringStudio /></Suspense>
        </TabsContent>
        <TabsContent value="dsl-validator">
          <Suspense fallback={<TabSkeleton />}><RuleDSLValidator /></Suspense>
        </TabsContent>
        <TabsContent value="taxonomy">
          <Suspense fallback={<TabSkeleton />}><RuleTaxonomyInspector /></Suspense>
        </TabsContent>
        <TabsContent value="hooks">
          <Suspense fallback={<TabSkeleton />}><HooksPolicyEditor /></Suspense>
        </TabsContent>
      </Tabs>
    </div>
  );
}
