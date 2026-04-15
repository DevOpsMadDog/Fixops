/**
 * CNAPP Dashboard
 *
 * Unified CSPM + CWPP + CIEM cloud security posture.
 *   1. Posture score trio (CSPM / CWPP / CIEM circles)
 *   2. KPIs: Cloud Workloads, Critical Findings, Privileged Containers, Policies Active
 *   3. Workload inventory (12 rows)
 *   4. CNAPP findings heatmap (6 categories × 4 severities)
 *   5. Cloud policy table (8 policies)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cloud, AlertTriangle, Container, Shield, RefreshCw, Server, BarChart3, Lock } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const SCORES = [
  { label: "CSPM",  score: 74, grade: "C", color: "text-amber-400", ring: "stroke-amber-500", subtitle: "Cloud Security Posture" },
  { label: "CWPP",  score: 81, grade: "B", color: "text-green-400",  ring: "stroke-green-500",  subtitle: "Workload Protection" },
  { label: "CIEM",  score: 68, grade: "D", color: "text-red-400",    ring: "stroke-red-500",    subtitle: "Entitlement Mgmt" },
];

const WORKLOADS = [
  { name: "api-gateway-prod",    type: "k8s_pod",    provider: "AWS",   region: "us-east-1",  running: true,  privileged: false, score: 42 },
  { name: "db-primary",          type: "VM",         provider: "Azure", region: "eastus",      running: true,  privileged: false, score: 28 },
  { name: "ml-trainer",          type: "container",  provider: "GCP",   region: "us-central1", running: true,  privileged: true,  score: 85 },
  { name: "batch-processor",     type: "serverless", provider: "AWS",   region: "us-west-2",   running: true,  privileged: false, score: 33 },
  { name: "frontend-deploy",     type: "k8s_pod",    provider: "AWS",   region: "eu-west-1",   running: true,  privileged: false, score: 21 },
  { name: "redis-cluster",       type: "VM",         provider: "AWS",   region: "us-east-1",  running: true,  privileged: false, score: 55 },
  { name: "log-aggregator",      type: "container",  provider: "GCP",   region: "europe-west1",running: true,  privileged: true,  score: 78 },
  { name: "auth-service",        type: "k8s_pod",    provider: "Azure", region: "westeurope",  running: true,  privileged: false, score: 48 },
  { name: "data-pipeline",       type: "serverless", provider: "GCP",   region: "us-east1",    running: false, privileged: false, score: 61 },
  { name: "pentest-runner",      type: "VM",         provider: "AWS",   region: "us-east-1",  running: false, privileged: true,  score: 92 },
  { name: "cdn-edge",            type: "serverless", provider: "AWS",   region: "global",      running: true,  privileged: false, score: 17 },
  { name: "analytics-worker",    type: "container",  provider: "Azure", region: "eastus2",     running: true,  privileged: true,  score: 74 },
];

const HEATMAP_CATS = ["misconfiguration", "vulnerability", "secret_exposure", "excessive_permission", "network_exposure", "compliance"];
const HEATMAP_SEVS = ["Critical", "High", "Medium", "Low"];
const HEATMAP_DATA: Record<string, number[]> = {
  misconfiguration:      [5,  12, 28, 41],
  vulnerability:         [3,  18, 44, 62],
  secret_exposure:       [4,   7, 11, 19],
  excessive_permission:  [2,   9, 17, 33],
  network_exposure:      [1,   5, 14, 28],
  compliance:            [3,  11, 22, 38],
};

const POLICIES = [
  { name: "No Public S3 Buckets",            type: "CSPM", action: "block", provider: "AWS",   enabled: true,  violations: 2 },
  { name: "Require Encryption at Rest",       type: "CSPM", action: "alert", provider: "Azure", enabled: true,  violations: 7 },
  { name: "No Privileged Containers",         type: "CWPP", action: "block", provider: "ALL",   enabled: true,  violations: 7 },
  { name: "IAM Least Privilege Enforce",      type: "CIEM", action: "alert", provider: "AWS",   enabled: true,  violations: 14 },
  { name: "No Root Account Usage",            type: "CIEM", action: "block", provider: "AWS",   enabled: true,  violations: 0 },
  { name: "MFA on Cloud Console",             type: "CSPM", action: "audit", provider: "GCP",   enabled: false, violations: 3 },
  { name: "Network Segmentation Policy",      type: "CWPP", action: "alert", provider: "Azure", enabled: true,  violations: 5 },
  { name: "Container Image Signing",          type: "CWPP", action: "block", provider: "GCP",   enabled: false, violations: 0 },
];

// ── Helpers ────────────────────────────────────────────────────

function ProviderBadge({ p }: { p: string }) {
  const map: Record<string, string> = {
    AWS:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    Azure: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    GCP:   "border-green-500/30 text-green-400 bg-green-500/10",
    ALL:   "border-border text-muted-foreground bg-muted/20",
  };
  return <Badge className={cn("text-[10px] border", map[p] ?? "")}>{p}</Badge>;
}

function WorkloadTypeBadge({ t }: { t: string }) {
  const map: Record<string, string> = {
    VM:         "border-slate-500/30 text-slate-400 bg-slate-500/10",
    container:  "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    serverless: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    k8s_pod:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[t] ?? "")}>{t.replace("_", " ")}</Badge>;
}

function ActionBadge({ a }: { a: string }) {
  const map: Record<string, string> = {
    block: "border-red-500/30 text-red-400 bg-red-500/10",
    alert: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    audit: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[a] ?? "")}>{a}</Badge>;
}

function cellIntensity(count: number): string {
  if (count === 0) return "bg-muted/10 text-muted-foreground";
  if (count <= 3)  return "bg-red-500/20 text-red-300";
  if (count <= 10) return "bg-red-500/35 text-red-200";
  if (count <= 25) return "bg-amber-500/35 text-amber-200";
  return "bg-amber-500/20 text-amber-300";
}

function ScoreCircle({ label, score, grade, color, ring, subtitle }: {
  label: string; score: number; grade: string; color: string; ring: string; subtitle: string;
}) {
  const r = 38;
  const circ = 2 * Math.PI * r;
  const dash = circ * (1 - score / 100);
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative w-24 h-24">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r={r} fill="none" stroke="currentColor" strokeWidth="8" className="text-muted/20" />
          <motion.circle
            cx="50" cy="50" r={r} fill="none"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circ}
            initial={{ strokeDashoffset: circ }}
            animate={{ strokeDashoffset: dash }}
            transition={{ duration: 1, ease: "easeOut" }}
            className={ring}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn("text-xl font-bold", color)}>{score}</span>
          <span className={cn("text-xs font-bold", color)}>{grade}</span>
        </div>
      </div>
      <span className="text-sm font-semibold">{label}</span>
      <span className="text-[10px] text-muted-foreground text-center">{subtitle}</span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function CNAPPDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/cnapp/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cnapp/findings?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/cnapp/workloads?org_id=${ORG_ID}`),
    ]).then(([statsResult, findingsResult, workloadsResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const findings  = findingsResult.status  === "fulfilled" ? findingsResult.value  : null;
      const workloads = workloadsResult.status === "fulfilled" ? workloadsResult.value : null;
      if (stats || findings || workloads) {
        setLiveData({ stats, findings, workloads });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const cspmScore = liveData?.stats?.cspm_score ?? 74;
  const cwppScore = liveData?.stats?.cwpp_score ?? 81;
  const ciemScore = liveData?.stats?.ciem_score ?? 68;
  const compositeScore = Math.round((cspmScore + cwppScore + ciemScore) / 3);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Cloud Native Application Protection"
        description="Unified CSPM + CWPP + CIEM cloud security posture"
        actions={
          <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* Posture Score Trio */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-400" />
            Cloud Security Posture Scores
          </CardTitle>
          <CardDescription className="text-xs">Composite view of CSPM, CWPP, and CIEM posture</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-around flex-wrap gap-6 py-2">
            {[
              { label: "CSPM",  score: cspmScore, grade: cspmScore >= 90 ? "A" : cspmScore >= 80 ? "B" : cspmScore >= 70 ? "C" : "D", color: cspmScore >= 80 ? "text-green-400" : "text-amber-400", ring: cspmScore >= 80 ? "stroke-green-500" : "stroke-amber-500", subtitle: "Cloud Security Posture" },
              { label: "CWPP",  score: cwppScore, grade: cwppScore >= 90 ? "A" : cwppScore >= 80 ? "B" : cwppScore >= 70 ? "C" : "D", color: cwppScore >= 80 ? "text-green-400" : "text-amber-400", ring: cwppScore >= 80 ? "stroke-green-500" : "stroke-amber-500", subtitle: "Workload Protection" },
              { label: "CIEM",  score: ciemScore, grade: ciemScore >= 90 ? "A" : ciemScore >= 80 ? "B" : ciemScore >= 70 ? "C" : "D", color: ciemScore >= 70 ? "text-amber-400" : "text-red-400",   ring: ciemScore >= 70 ? "stroke-amber-500" : "stroke-red-500",   subtitle: "Entitlement Mgmt" },
            ].map((s) => (
              <ScoreCircle key={s.label} {...s} />
            ))}
          </div>
          <div className="flex justify-center mt-4">
            <Badge className="text-sm px-4 py-1 border border-amber-500/30 text-amber-400 bg-amber-500/10 font-semibold">
              Composite Score: {compositeScore} / 100
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Cloud Workloads"       value={liveData?.stats?.total_workloads ?? 342}         icon={Cloud}         trend="up" />
        <KpiCard title="Critical Findings"     value={liveData?.stats?.critical_findings ?? 18}        icon={AlertTriangle} trend="up"      className="border-red-500/20" />
        <KpiCard title="Privileged Containers" value={liveData?.stats?.privileged_containers ?? 7}     icon={Container}     trend="up"      className="border-amber-500/20" />
        <KpiCard title="Policies Active"       value={liveData?.stats?.active_policies ?? 34}          icon={Lock}          trend="neutral" />
      </div>

      {/* Workload Inventory */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Server className="h-4 w-4 text-cyan-400" />
            Workload Inventory
          </CardTitle>
          <CardDescription className="text-xs">All tracked cloud workloads with risk scoring</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Provider</TableHead>
                  <TableHead className="text-[11px] h-8">Region</TableHead>
                  <TableHead className="text-[11px] h-8">Running</TableHead>
                  <TableHead className="text-[11px] h-8">Privileged</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Scanned</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.workloads?.items ?? liveData?.workloads ?? WORKLOADS).map((w: any) => (
                  <TableRow key={w.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5 max-w-[160px] truncate">{w.name}</TableCell>
                    <TableCell className="py-2.5"><WorkloadTypeBadge t={w.type} /></TableCell>
                    <TableCell className="py-2.5"><ProviderBadge p={w.provider} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{w.region}</TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-xs font-bold", w.running ? "text-green-400" : "text-muted-foreground")}>
                        {w.running ? "Running" : "Stopped"}
                      </span>
                    </TableCell>
                    <TableCell className="py-2.5">
                      {w.privileged
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Privileged</Badge>
                        : <span className="text-[10px] text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="relative h-1.5 w-16 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", w.score >= 80 ? "bg-red-500" : w.score >= 60 ? "bg-amber-500" : w.score >= 40 ? "bg-yellow-500" : "bg-green-500")}
                            style={{ width: `${w.score}%` }}
                          />
                        </div>
                        <span className="text-xs tabular-nums">{w.score}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">5m ago</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Findings Heatmap */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-red-400" />
            CNAPP Findings Heatmap
          </CardTitle>
          <CardDescription className="text-xs">Finding counts by category and severity</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr>
                  <th className="text-left pb-2 pr-4 text-[11px] text-muted-foreground font-medium w-40">Category</th>
                  {HEATMAP_SEVS.map((s) => (
                    <th key={s} className="pb-2 px-2 text-[11px] text-center font-medium text-muted-foreground">{s}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {HEATMAP_CATS.map((cat) => (
                  <tr key={cat}>
                    <td className="pr-4 py-1.5 text-[11px] text-muted-foreground capitalize">{cat.replace(/_/g, " ")}</td>
                    {(HEATMAP_DATA[cat] ?? []).map((count, ci) => (
                      <td key={ci} className="px-2 py-1.5 text-center">
                        <span className={cn("inline-block rounded px-2 py-0.5 text-[11px] font-bold min-w-[32px]", cellIntensity(count))}>
                          {count}
                        </span>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Cloud Policy Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-purple-400" />
              Cloud Policies
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">New Policy</Button>
          </div>
          <CardDescription className="text-xs">Active and inactive cloud security policies</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Policy Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">Provider</TableHead>
                  <TableHead className="text-[11px] h-8">Enabled</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Violations</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {POLICIES.map((p, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs py-2.5 max-w-[220px] truncate font-medium">{p.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className="text-[10px] border border-border text-muted-foreground">{p.type}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5"><ActionBadge a={p.action} /></TableCell>
                    <TableCell className="py-2.5"><ProviderBadge p={p.provider} /></TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-xs font-medium", p.enabled ? "text-green-400" : "text-muted-foreground")}>
                        {p.enabled ? "On" : "Off"}
                      </span>
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      {p.violations > 0
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{p.violations}</Badge>
                        : <span className="text-xs text-muted-foreground">0</span>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
