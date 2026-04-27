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
  BadgeCheck,
  Bot,
  Calendar,
  CheckCircle2,
  ClipboardList,
  Database,
  FileCheck,
  FileText,
  Flag,
  KeyRound,
  Layers,
  Library,
  Link2,
  Lock,
  RefreshCw,
  ScrollText,
  Shield,
  ShieldCheck,
  TrendingUp,
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

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return null;
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
      const [postureRes, fipsRes, scifBootRes, chainRes, hsmRes] = await Promise.allSettled([
        apiFetch<PostureResponse>("/api/v1/system/compliance-posture"),
        apiFetch<FipsModeResponse>("/api/v1/system/fips-mode"),
        apiFetch<ScifBoot>("/api/v1/scif/boot"),
        apiFetch<AuditChainVerify>("/api/v1/scif/audit-chain/verify"),
        apiFetch<HsmInfo>("/api/v1/scif/hsm/info"),
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
      </Tabs>
    </motion.div>
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
