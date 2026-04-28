// FOLDED into Brain hero 2026-04-27 — access via /brain?tab=mitre
// Wave 3 Phase 3 UX consolidation fold (target: 30 screens)
/**
 * MITRE ATT&CK Dashboard
 *
 * Coverage heatmap, gap analysis, and detection stats across 14 MITRE tactics.
 *
 * Data sources:
 *   GET /api/v1/mitre-attack/coverage?org_id=default
 *   GET /api/v1/mitre-attack/gaps?org_id=default
 *   GET /api/v1/mitre-attack/stats?org_id=default
 *
 * Route: /mitre-attack
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  Target,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

async function apiFetch<T = any>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Types ────────────────────────────────────────────────────────────────────
interface Tactic {
  tactic_id: string;
  tactic_name: string;
  technique_count: number;
  detected_count: number;
  coverage_pct: number;
}

interface CoverageData {
  coverage_pct: number;
  total_techniques: number;
  detected_techniques: number;
  tactics: Tactic[];
}

interface Gap {
  tactic_id: string;
  technique_id: string;
  technique_name: string;
  severity: string;
  recommendation: string;
}

interface GapsData {
  gaps: Gap[];
}

interface StatsData {
  total_mappings: number;
  tactics_covered: number;
  techniques_covered: number;
}

const EMPTY_COVERAGE: CoverageData = { coverage_pct: 0, total_techniques: 0, detected_techniques: 0, tactics: [] };
const EMPTY_STATS: StatsData = { total_mappings: 0, tactics_covered: 0, techniques_covered: 0 };

// ── Helpers ──────────────────────────────────────────────────────────────────
function coverageColor(pct: number): string {
  if (pct >= 70) return "bg-emerald-500";
  if (pct >= 40) return "bg-amber-500";
  return "bg-red-500";
}

function coverageTextColor(pct: number): string {
  if (pct >= 70) return "text-emerald-400";
  if (pct >= 40) return "text-amber-400";
  return "text-red-400";
}

function severityVariant(sev: string): "destructive" | "secondary" | "outline" {
  if (sev === "critical") return "destructive";
  if (sev === "high")     return "secondary";
  return "outline";
}

function severityLabel(sev: string): string {
  return sev.charAt(0).toUpperCase() + sev.slice(1);
}

// ── Component ────────────────────────────────────────────────────────────────
export default function MITREAttackDashboard() {
  const [coverage, setCoverage]     = useState<CoverageData>(EMPTY_COVERAGE);
  const [gaps, setGaps]             = useState<Gap[]>([]);
  const [stats, setStats]           = useState<StatsData>(EMPTY_STATS);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [coverageRes, gapsRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/mitre-attack/coverage"),
        apiFetch<any>("/api/v1/mitre-attack/gaps"),
      ]);
      if (coverageRes.status === "fulfilled") {
        const v = coverageRes.value;
        const tactics = Array.isArray(v?.tactics) ? v.tactics : [];
        setCoverage({
          coverage_pct: v?.coverage_pct ?? 0,
          total_techniques: v?.total_techniques ?? 0,
          detected_techniques: v?.detected_techniques ?? 0,
          tactics,
        });
        setStats({
          total_mappings: v?.total_mappings ?? tactics.reduce((s: number, t: any) => s + (t.technique_count ?? 0), 0),
          tactics_covered: tactics.filter((t: any) => (t.detected_count ?? 0) > 0).length,
          techniques_covered: v?.detected_techniques ?? 0,
        });
      } else {
        setError((coverageRes.reason as Error).message);
      }
      if (gapsRes.status === "fulfilled") {
        const v = gapsRes.value;
        setGaps(Array.isArray(v) ? v : (v?.gaps ?? v?.items ?? []));
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLastRefresh(new Date());
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) return <PageSkeleton />;

  const openGaps = gaps.filter((g) =>
    g.severity === "critical" || g.severity === "high"
  ).length;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="MITRE ATT&CK Coverage"
        description="Detection coverage mapped across 14 ATT&CK tactics and technique gaps"
        actions={
          <div className="flex items-center gap-3">
            <span className="text-xs text-muted-foreground">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={load}
              disabled={loading}
              className="gap-2"
            >
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
              Refresh
            </Button>
          </div>
        }
      />

      {error && <ErrorState message={error} onRetry={load} />}

      {/* KPI Row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard
          title="Coverage"
          value={`${coverage.coverage_pct}%`}
          icon={<Shield className="h-5 w-5 text-blue-400" />}
          trend={coverage.coverage_pct >= 50 ? "up" : "down"}
          trendLabel={coverage.coverage_pct >= 50 ? "On track" : "Below target"}
        />
        <KpiCard
          title="Total Techniques"
          value={coverage.total_techniques}
          icon={<Target className="h-5 w-5 text-purple-400" />}
        />
        <KpiCard
          title="Detected"
          value={coverage.detected_techniques}
          icon={<CheckCircle2 className="h-5 w-5 text-emerald-400" />}
        />
        <KpiCard
          title="Open Gaps"
          value={openGaps}
          icon={<AlertTriangle className="h-5 w-5 text-red-400" />}
          trend="down"
          trendLabel="Require remediation"
        />
      </div>

      {/* Tactic Coverage Table */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4 text-blue-400" />
              Tactic Coverage
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {coverage.tactics.length === 0 && !error ? <EmptyState icon={Shield} title="No coverage data" description="Seed MITRE ATT&CK techniques via /api/v1/mitre-attack/seed to populate this view." /> : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tactic Name</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead className="text-right">Techniques</TableHead>
                  <TableHead className="text-right">Detected</TableHead>
                  <TableHead>Coverage</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {coverage.tactics.map((tactic) => (
                  <TableRow key={tactic.tactic_id}>
                    <TableCell className="font-medium">
                      {tactic.tactic_name}
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs text-muted-foreground">
                        {tactic.tactic_id}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      {tactic.technique_count}
                    </TableCell>
                    <TableCell className="text-right">
                      <span className={coverageTextColor(tactic.coverage_pct)}>
                        {tactic.detected_count}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2 min-w-[140px]">
                        <div className="relative flex-1 h-2 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn(
                              "absolute inset-y-0 left-0 rounded-full transition-all duration-500",
                              coverageColor(tactic.coverage_pct)
                            )}
                            style={{ width: `${tactic.coverage_pct}%` }}
                          />
                        </div>
                        <span
                          className={cn(
                            "text-xs font-semibold w-9 text-right tabular-nums",
                            coverageTextColor(tactic.coverage_pct)
                          )}
                        >
                          {tactic.coverage_pct}%
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Gaps Table */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Detection Gaps
              <Badge variant="secondary" className="ml-auto">
                {gaps.length} gaps
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {gaps.length === 0 && !error ? <EmptyState icon={AlertTriangle} title="No detection gaps" description="No high-severity coverage gaps detected." /> : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Technique</TableHead>
                  <TableHead>Tactic</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Recommendation</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {gaps.map((gap) => (
                  <TableRow key={gap.technique_id}>
                    <TableCell>
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium text-sm">
                          {gap.technique_name}
                        </span>
                        <span className="font-mono text-xs text-muted-foreground">
                          {gap.technique_id}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs text-muted-foreground">
                        {gap.tactic_id}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={severityVariant(gap.severity)}
                        className={cn(
                          "capitalize",
                          gap.severity === "high" &&
                            "bg-orange-500/15 text-orange-400 border-orange-500/30",
                          gap.severity === "medium" &&
                            "bg-amber-500/15 text-amber-400 border-amber-500/30"
                        )}
                      >
                        {severityLabel(gap.severity)}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-sm text-sm text-muted-foreground">
                      {gap.recommendation.length > 80
                        ? `${gap.recommendation.slice(0, 80)}…`
                        : gap.recommendation}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Stats Footer */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Total Mappings",      value: stats.total_mappings },
          { label: "Tactics Covered",     value: `${stats.tactics_covered} / 14` },
          { label: "Techniques Covered",  value: stats.techniques_covered },
        ].map((item) => (
          <Card key={item.label}>
            <CardContent className="flex flex-col items-center justify-center py-5 gap-1">
              <span className="text-2xl font-bold tabular-nums">{item.value}</span>
              <span className="text-xs text-muted-foreground">{item.label}</span>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
