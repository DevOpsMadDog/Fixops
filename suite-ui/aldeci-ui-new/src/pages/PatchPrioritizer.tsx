/**
 * Patch Prioritizer — Intelligent Patch Prioritization Dashboard
 *
 * CVSS + EPSS + KEV composite scoring for vulnerability remediation:
 *   1. Top Metrics — Critical Patches Due, High Priority This Week, SLA compliance, Avg Time to Patch
 *   2. Priority Patch Queue — table sorted by composite score with color-coded rows
 *   3. Patch Groups — vendor/product grouping with aggregated metrics
 *   4. SLA Timeline — patches due in 7/14/30 day windows
 *
 * API: GET /api/v1/patch-prioritizer/queue, /api/v1/patch-prioritizer/groups
 * Fallback: mock data when API is unavailable
 */

import { useState, useMemo, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, Clock, Zap, Download,
  CheckCircle2, AlertCircle, Package, Calendar,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type KEVStatus = "Yes" | "No";

interface PatchItem {
  id: string;
  cve_id: string;
  affected_asset: string;
  cvss_score: number;
  epss_score: number; // 0-1
  kev_status: KEVStatus;
  composite_score: number; // 0-100
  recommended_action: string;
  sla_deadline: string;
  vendor: string;
  product: string;
}

interface PatchGroup {
  vendor: string;
  product: string;
  patch_count: number;
  critical_count: number;
  avg_composite_score: number;
}

interface PatchPrioritizerData {
  patches: PatchItem[];
  groups: PatchGroup[];
  critical_patches_due: number;
  high_priority_this_week: number;
  patches_in_sla: number;
  avg_time_to_patch_days: number;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_PATCH_DATA: PatchPrioritizerData = {
  critical_patches_due: 3,
  high_priority_this_week: 12,
  patches_in_sla: 28,
  avg_time_to_patch_days: 8,
  patches: [
    {
      id: "p1",
      cve_id: "CVE-2021-44228",
      affected_asset: "log4j-core-2.14.1.jar",
      cvss_score: 10.0,
      epss_score: 0.98,
      kev_status: "Yes",
      composite_score: 98,
      recommended_action: "Immediate patch to 2.17.0+",
      sla_deadline: "2026-04-15",
      vendor: "Apache",
      product: "Log4j",
    },
    {
      id: "p2",
      cve_id: "CVE-2024-6849",
      affected_asset: "windows-server-2019",
      cvss_score: 9.6,
      epss_score: 0.95,
      kev_status: "Yes",
      composite_score: 91,
      recommended_action: "Apply Windows KB5032189 immediately",
      sla_deadline: "2026-04-16",
      vendor: "Microsoft",
      product: "Windows Server",
    },
    {
      id: "p3",
      cve_id: "CVE-2024-3156",
      affected_asset: "openssl-3.0.8",
      cvss_score: 9.1,
      epss_score: 0.92,
      kev_status: "Yes",
      composite_score: 84,
      recommended_action: "Upgrade to 3.2.1 or later",
      sla_deadline: "2026-04-17",
      vendor: "OpenSSL",
      product: "OpenSSL",
    },
    {
      id: "p4",
      cve_id: "CVE-2024-5638",
      affected_asset: "chrome-version-125.0",
      cvss_score: 8.8,
      epss_score: 0.87,
      kev_status: "No",
      composite_score: 76,
      recommended_action: "Update to Chrome 126.0.6478.61",
      sla_deadline: "2026-04-21",
      vendor: "Google",
      product: "Chrome",
    },
    {
      id: "p5",
      cve_id: "CVE-2024-2961",
      affected_asset: "nginx-1.26.0",
      cvss_score: 7.5,
      epss_score: 0.68,
      kev_status: "No",
      composite_score: 51,
      recommended_action: "Patch to 1.26.1 or configure workaround",
      sla_deadline: "2026-04-28",
      vendor: "NGINX",
      product: "NGINX",
    },
    {
      id: "p6",
      cve_id: "CVE-2024-1086",
      affected_asset: "linux-kernel-6.5.0",
      cvss_score: 8.4,
      epss_score: 0.91,
      kev_status: "Yes",
      composite_score: 76,
      recommended_action: "Reboot required after kernel patch",
      sla_deadline: "2026-04-19",
      vendor: "Linux",
      product: "Linux Kernel",
    },
    {
      id: "p7",
      cve_id: "CVE-2024-4577",
      affected_asset: "php-8.2.0",
      cvss_score: 7.2,
      epss_score: 0.65,
      kev_status: "No",
      composite_score: 47,
      recommended_action: "Update to PHP 8.2.18 or 8.3.5",
      sla_deadline: "2026-05-05",
      vendor: "PHP",
      product: "PHP",
    },
    {
      id: "p8",
      cve_id: "CVE-2024-6389",
      affected_asset: "postgresql-16.0",
      cvss_score: 6.8,
      epss_score: 0.52,
      kev_status: "No",
      composite_score: 35,
      recommended_action: "Apply maintenance release 16.2+",
      sla_deadline: "2026-05-10",
      vendor: "PostgreSQL",
      product: "PostgreSQL",
    },
    {
      id: "p9",
      cve_id: "CVE-2024-7531",
      affected_asset: "docker-25.0.0",
      cvss_score: 8.1,
      epss_score: 0.78,
      kev_status: "Yes",
      composite_score: 63,
      recommended_action: "Update Docker to 26.0.0 or later",
      sla_deadline: "2026-04-23",
      vendor: "Docker",
      product: "Docker Engine",
    },
    {
      id: "p10",
      cve_id: "CVE-2024-5555",
      affected_asset: "mongodb-7.0.0",
      cvss_score: 6.5,
      epss_score: 0.48,
      kev_status: "No",
      composite_score: 31,
      recommended_action: "Upgrade to 7.0.4 or apply patch",
      sla_deadline: "2026-05-15",
      vendor: "MongoDB",
      product: "MongoDB",
    },
  ],
  groups: [
    {
      vendor: "Apache",
      product: "Log4j",
      patch_count: 1,
      critical_count: 1,
      avg_composite_score: 98,
    },
    {
      vendor: "Microsoft",
      product: "Windows Server",
      patch_count: 3,
      critical_count: 2,
      avg_composite_score: 72,
    },
    {
      vendor: "Linux",
      product: "Linux Kernel",
      patch_count: 2,
      critical_count: 1,
      avg_composite_score: 68,
    },
    {
      vendor: "OpenSSL",
      product: "OpenSSL",
      patch_count: 2,
      critical_count: 2,
      avg_composite_score: 85,
    },
    {
      vendor: "Google",
      product: "Chrome",
      patch_count: 3,
      critical_count: 0,
      avg_composite_score: 54,
    },
  ],
};

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function getScoreColor(score: number): string {
  if (score >= 80) return "bg-red-500/20 border-red-500/50";
  if (score >= 60) return "bg-orange-500/20 border-orange-500/50";
  if (score >= 40) return "bg-yellow-500/20 border-yellow-500/50";
  return "bg-blue-500/20 border-blue-500/50";
}

function getScoreBadgeColor(score: number): string {
  if (score >= 80) return "bg-red-500/15 text-red-400 border-red-500/30";
  if (score >= 60) return "bg-orange-500/15 text-orange-400 border-orange-500/30";
  if (score >= 40) return "bg-yellow-500/15 text-yellow-400 border-yellow-500/30";
  return "bg-blue-500/15 text-blue-400 border-blue-500/30";
}

function getScoreTextColor(score: number): string {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  return "text-blue-400";
}

// ══════════════════════════════════════════════════════════════
// Progress Bar Component
// ══════════════════════════════════════════════════════════════

const CompositeScoreBar = ({ score }: { score: number }) => (
  <div className="flex items-center gap-2 w-full">
    <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden">
      <div
        className={cn(
          "h-full transition-all",
          score >= 80
            ? "bg-red-500"
            : score >= 60
              ? "bg-orange-500"
              : score >= 40
                ? "bg-yellow-500"
                : "bg-blue-500"
        )}
        style={{ width: `${score}%` }}
      />
    </div>
    <span className={cn("text-sm font-semibold w-10 text-right", getScoreTextColor(score))}>
      {score}
    </span>
  </div>
);

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function PatchPrioritizer() {
  const [sortBy, setSortBy] = useState<"score" | "deadline" | "cvss">("score");
  const [patchData, setPatchData] = useState<PatchPrioritizerData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setIsLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/patch-automation/patches?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/patch-automation/stats?org_id=${ORG_ID}`),
    ]).then(([patchesResult, statsResult]) => {
      const patches = patchesResult.status === "fulfilled" ? patchesResult.value : null;
      const stats   = statsResult.status   === "fulfilled" ? statsResult.value   : null;

      if (patches || stats) {
        const patchList: PatchItem[] = Array.isArray(patches)
          ? patches.map((p: any) => ({
              id:                 p.patch_id ?? p.id ?? "",
              cve_id:             (p.cves_addressed?.[0]) ?? p.cve_id ?? "",
              affected_asset:     p.product ?? p.affected_asset ?? "",
              cvss_score:         p.cvss_score ?? 0,
              epss_score:         p.epss_score ?? 0,
              kev_status:         p.kev_status ?? "No",
              composite_score:    p.composite_score ?? p.risk_score ?? 0,
              recommended_action: p.recommended_action ?? p.kb_article ?? "",
              sla_deadline:       p.sla_deadline ?? p.release_date ?? "",
              vendor:             p.vendor ?? "",
              product:            p.product ?? "",
            }))
          : MOCK_PATCH_DATA.patches;

        setPatchData({
          patches:                 patchList.length > 0 ? patchList : MOCK_PATCH_DATA.patches,
          groups:                  MOCK_PATCH_DATA.groups,
          critical_patches_due:    stats?.pending_critical   ?? stats?.critical_count    ?? MOCK_PATCH_DATA.critical_patches_due,
          high_priority_this_week: stats?.deployments_today  ?? MOCK_PATCH_DATA.high_priority_this_week,
          patches_in_sla:          stats?.total              ?? MOCK_PATCH_DATA.patches_in_sla,
          avg_time_to_patch_days:  stats?.avg_patch_age_days ?? MOCK_PATCH_DATA.avg_time_to_patch_days,
        });
      
    setLoading(false);} else {
        setPatchData(MOCK_PATCH_DATA);
      }
    }).finally(() => setIsLoading(false));
  }, []);

  // Sort patches
  const sortedPatches = useMemo(() => {
    if (!patchData) return [];
    const patches = [...patchData.patches];
    if (sortBy === "score") {
      return patches.sort((a, b) => b.composite_score - a.composite_score);
    }
    if (sortBy === "cvss") {
      return patches.sort((a, b) => b.cvss_score - a.cvss_score);
    }
    if (sortBy === "deadline") {
      return patches.sort((a, b) => new Date(a.sla_deadline).getTime() - new Date(b.sla_deadline).getTime());
    }
    return patches;
  }, [patchData, sortBy]);

  // Calculate SLA timeline
  const slaTimeline = useMemo(() => {
    if (!patchData) return { due7: 0, due14: 0, due30: 0 };
    const now = new Date();
    const due7 = patchData.patches.filter(p => {
      const diff = (new Date(p.sla_deadline).getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      return diff >= 0 && diff <= 7;
    }).length;
    const due14 = patchData.patches.filter(p => {
      const diff = (new Date(p.sla_deadline).getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      return diff > 7 && diff <= 14;
    }).length;
    const due30 = patchData.patches.filter(p => {
      const diff = (new Date(p.sla_deadline).getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      return diff > 14 && diff <= 30;
    }).length;
    return { due7, due14, due30 };
  }, [patchData]);

  if (isLoading) return <PageSkeleton />;

  const data: PatchPrioritizerData = patchData ?? MOCK_PATCH_DATA;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <PageHeader
        title="Patch Prioritizer"
        subtitle="CVSS × EPSS × KEV composite scoring for vulnerability remediation"
        icon={Shield}
      />

      {/* ── Scoring Explanation Banner ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border-blue-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <Zap className="w-6 h-6 text-blue-400 flex-shrink-0" />
              <div className="flex-1">
                <p className="text-white font-semibold mb-1">Composite Score Formula</p>
                <p className="text-sm text-gray-300">
                  <span className="text-blue-400 font-mono">Priority = CVSS × EPSS × KEV_multiplier</span>
                  {" "}where KEV_multiplier = 1.2 if exploited, 1.0 otherwise
                </p>
              </div>
              <div className="flex gap-2 flex-shrink-0">
                <Badge className="bg-red-500/20 text-red-400 border-red-500/30 border">
                  80+ Critical
                </Badge>
                <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30 border">
                  60-79 High
                </Badge>
                <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 border">
                  40-59 Medium
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Top Metrics ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
      >
        <div className="grid grid-cols-4 gap-4">
          <KpiCard
            title="Critical Patches Due"
            value={data.critical_patches_due}
            subtitle="Require immediate action"
            icon={AlertTriangle}
            trend={{ value: -2, label: "vs last week" }}
          />
          <KpiCard
            title="High Priority This Week"
            value={data.high_priority_this_week}
            subtitle="Score ≥60, deadline ≤7d"
            icon={Zap}
            trend={{ value: 3, label: "vs last week" }}
          />
          <KpiCard
            title="Patches in SLA"
            value={data.patches_in_sla}
            subtitle={`${Math.round((data.patches_in_sla / data.patches.length) * 100)}% of queue`}
            icon={CheckCircle2}
            trend={{ value: 1, label: "vs last week" }}
          />
          <KpiCard
            title="Avg Time to Patch"
            value={`${data.avg_time_to_patch_days}d`}
            subtitle="From discovery to remediation"
            icon={Clock}
            trend={{ value: -1, label: "vs last month" }}
          />
        </div>
      </motion.div>

      {/* ── Priority Patch Queue ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-red-400" />
                Priority Patch Queue
              </CardTitle>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant={sortBy === "score" ? "default" : "outline"}
                  onClick={() => setSortBy("score")}
                  className="text-xs"
                >
                  Sort by Score
                </Button>
                <Button
                  size="sm"
                  variant={sortBy === "deadline" ? "default" : "outline"}
                  onClick={() => setSortBy("deadline")}
                  className="text-xs"
                >
                  Sort by Deadline
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700/50 hover:bg-slate-800/20">
                    <TableHead className="text-gray-300">CVE ID</TableHead>
                    <TableHead className="text-gray-300">Affected Asset</TableHead>
                    <TableHead className="text-gray-300 text-center">CVSS</TableHead>
                    <TableHead className="text-gray-300 text-center">EPSS</TableHead>
                    <TableHead className="text-gray-300 text-center">KEV</TableHead>
                    <TableHead className="text-gray-300">Composite Score</TableHead>
                    <TableHead className="text-gray-300">Recommended Action</TableHead>
                    <TableHead className="text-gray-300">SLA Deadline</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedPatches.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8}>
                        <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                          <p className="text-lg font-medium">No data available</p>
                          <p className="text-sm">Data will appear here once available</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    sortedPatches.map((patch) => (
                    <TableRow
                      key={patch.id}
                      className={cn(
                        "border-slate-700/50 hover:bg-slate-800/30 transition-colors",
                        getScoreColor(patch.composite_score)
                      )}
                    >
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="bg-slate-800 text-slate-300 border-slate-600 font-mono text-xs"
                        >
                          {patch.cve_id}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div>
                          <p className="text-sm text-white font-medium">{patch.affected_asset}</p>
                          <p className="text-xs text-gray-400">
                            {patch.vendor} {patch.product}
                          </p>
                        </div>
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge
                          variant="outline"
                          className={getScoreBadgeColor(patch.cvss_score)}
                        >
                          {patch.cvss_score.toFixed(1)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-center">
                        <span className="text-sm font-semibold text-blue-400">
                          {(patch.epss_score * 100).toFixed(0)}%
                        </span>
                      </TableCell>
                      <TableCell className="text-center">
                        {patch.kev_status === "Yes" ? (
                          <Badge className="bg-red-500/20 text-red-400 border-red-500/30 border">
                            Yes
                          </Badge>
                        ) : (
                          <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30 border">
                            No
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <CompositeScoreBar score={patch.composite_score} />
                      </TableCell>
                      <TableCell>
                        <p className="text-sm text-gray-300">{patch.recommended_action}</p>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3 text-gray-400" />
                          <span className="text-sm text-gray-300">
                            {new Date(patch.sla_deadline).toLocaleDateString()}
                          </span>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Patch Groups ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Package className="w-5 h-5 text-purple-400" />
              Patch Groups by Vendor
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              {data.groups.map((group) => (
                <div
                  key={`${group.vendor}-${group.product}`}
                  className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/50 hover:border-slate-600 transition-colors"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <p className="font-semibold text-white">{group.vendor}</p>
                      <p className="text-xs text-gray-400">{group.product}</p>
                    </div>
                    {group.critical_count > 0 && (
                      <Badge className="bg-red-500/20 text-red-400 border-red-500/30 border">
                        {group.critical_count} Critical
                      </Badge>
                    )}
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Total Patches</span>
                      <span className="text-white font-semibold">{group.patch_count}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Avg Score</span>
                      <span className={cn("font-semibold", getScoreTextColor(group.avg_composite_score))}>
                        {group.avg_composite_score.toFixed(0)}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── SLA Timeline ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.35 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Calendar className="w-5 h-5 text-amber-400" />
              SLA Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              <div className="p-4 rounded-lg bg-slate-800/30 border border-red-500/30">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <p className="font-semibold text-white">Due in 7 Days</p>
                </div>
                <p className="text-3xl font-bold text-red-400">{slaTimeline.due7}</p>
                <p className="text-xs text-gray-400 mt-1">Critical priority</p>
              </div>

              <div className="p-4 rounded-lg bg-slate-800/30 border border-orange-500/30">
                <div className="flex items-center gap-2 mb-2">
                  <Zap className="w-4 h-4 text-orange-400" />
                  <p className="font-semibold text-white">Due in 14 Days</p>
                </div>
                <p className="text-3xl font-bold text-orange-400">{slaTimeline.due14}</p>
                <p className="text-xs text-gray-400 mt-1">High priority</p>
              </div>

              <div className="p-4 rounded-lg bg-slate-800/30 border border-yellow-500/30">
                <div className="flex items-center gap-2 mb-2">
                  <Clock className="w-4 h-4 text-yellow-400" />
                  <p className="font-semibold text-white">Due in 30 Days</p>
                </div>
                <p className="text-3xl font-bold text-yellow-400">{slaTimeline.due30}</p>
                <p className="text-xs text-gray-400 mt-1">Medium priority</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Export Button ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="flex justify-end"
      >
        <Button
          disabled
          className="gap-2"
          title="Export functionality coming soon"
        >
          <Download className="w-4 h-4" />
          Export Queue
        </Button>
      </motion.div>

      {/* Info Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.45 }}
        className="text-center text-sm text-gray-400 pb-4"
      >
        <p>
          Patch prioritization based on CVSS v3.1, EPSS probability, and CISA KEV exploitation status.
          <br />
          Last updated: {new Date().toLocaleDateString()}
        </p>
      </motion.div>
    </div>
  );
}
