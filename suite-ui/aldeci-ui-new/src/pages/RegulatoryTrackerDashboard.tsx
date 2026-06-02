// FOLDED into Compliance hero 2026-04-27 — preserve for git history
// Tab path: /compliance?tab=regulatory-tracker
/**
 * RegulatoryTrackerDashboard
 *
 * Multi-jurisdiction change tracking, obligations, and compliance assessments.
 *   1. KPIs: Active Regulations, Pending Changes, Overdue Obligations, Avg Compliance
 *   2. Upcoming changes timeline — 10 regulatory changes
 *   3. Obligations table — 12 rows
 *   4. Assessment history — 8 assessments
 *   5. Regulation catalog — 10 regulations
 */

import { useState, useEffect } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import { ScrollText, AlertTriangle, ClipboardCheck, BarChart3, RefreshCw, Globe, Calendar, Inbox } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY;
const ORG_ID = (getStoredOrgId() ?? "default");

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
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── Mock data ───────────────────────────────────────────────────





// ── Helpers ─────────────────────────────────────────────────────

function ChangeTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    new_requirement: "border-red-500/30 text-red-400 bg-red-500/10",
    amendment:       "border-amber-500/30 text-amber-400 bg-amber-500/10",
    clarification:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    deadline:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
    enforcement:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  const label: Record<string, string> = {
    new_requirement: "New Req",
    amendment:       "Amendment",
    clarification:   "Clarification",
    deadline:        "Deadline",
    enforcement:     "Enforcement",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{label[type] ?? type}</Badge>;
}

function ImpactBadge({ impact }: { impact: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[impact] ?? "border-border text-muted-foreground")}>{impact}</Badge>;
}

function ObligStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    on_track:     "border-green-500/30 text-green-400 bg-green-500/10",
    at_risk:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    overdue:      "border-red-500/30 text-red-400 bg-red-500/10",
    planned:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  const label: Record<string, string> = { on_track: "On Track", at_risk: "At Risk", overdue: "Overdue", planned: "Planned" };
  return <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>{label[status] ?? status}</Badge>;
}

function ObligTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    technical:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    administrative: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    operational:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function JurisdictionBadge({ j }: { j: string }) {
  const map: Record<string, string> = {
    EU:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    US:   "border-red-500/30 text-red-400 bg-red-500/10",
    UK:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    APAC: "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[j] ?? "border-border text-muted-foreground")}>{j}</Badge>;
}

function CategoryBadge({ cat }: { cat: string }) {
  const map: Record<string, string> = {
    privacy:      "border-pink-500/30 text-pink-400 bg-pink-500/10",
    cybersecurity:"border-red-500/30 text-red-400 bg-red-500/10",
    financial:    "border-green-500/30 text-green-400 bg-green-500/10",
    healthcare:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    "AI/ML":      "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[cat] ?? "border-border text-muted-foreground")}>{cat}</Badge>;
}

function DaysUntilChip({ days }: { days: number }) {
  const cls = days < 30 ? "text-red-400" : days < 90 ? "text-amber-400" : "text-green-400";
  return <span className={cn("text-xs font-bold tabular-nums", cls)}>{days}d</span>;
}

function ComplianceBar({ pct }: { pct: number }) {
  const color = pct >= 90 ? "bg-green-500" : pct >= 75 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums w-8 text-right", pct >= 90 ? "text-green-400" : pct >= 75 ? "text-amber-400" : "text-red-400")}>{pct}%</span>
    </div>
  );
}

// ── Component ───────────────────────────────────────────────────

const arr = (v: any): any[] => (Array.isArray(v) ? v : []);
export default function RegulatoryTrackerDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/regulatory/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/regulatory/regulations/upcoming?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/regulatory/regulations/active?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, upcomingResult, activeResult]) => {
      const stats    = statsResult.status    === "fulfilled" ? statsResult.value    : null;
      const upcoming = upcomingResult.status === "fulfilled" ? upcomingResult.value : null;
      const active   = activeResult.status   === "fulfilled" ? activeResult.value   : null;
      if (stats || upcoming || active) {
        setLiveData({ stats, upcoming, active });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Regulatory Tracker"
        description="Multi-jurisdiction change tracking, obligations, and compliance assessments"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Regulations"   value={liveData?.stats?.total_regulations ?? liveData?.active?.length ?? 24}    icon={ScrollText}     className="border-blue-500/20" />
        <KpiCard title="Pending Changes"      value={liveData?.stats?.pending_changes ?? liveData?.upcoming?.length ?? 8}     icon={Calendar}       trend="up" className="border-amber-500/20" />
        <KpiCard title="Overdue Obligations"  value={liveData?.stats?.overdue_obligations ?? 3}     icon={AlertTriangle}  trend="up" className="border-red-500/20" />
        <KpiCard title="Avg Compliance"       value={liveData?.stats?.avg_compliance ? `${liveData.stats.avg_compliance}%` : "78%"}   icon={BarChart3}      trend="down" className="border-yellow-500/20" />
      </div>

      {/* Upcoming changes timeline */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Calendar className="h-4 w-4 text-blue-400" />
              Upcoming Regulatory Changes
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{(liveData?.upcoming ?? []).length} changes</Badge>
          </div>
          <CardDescription className="text-xs">Sorted by effective date — impact to your compliance posture</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Regulation</TableHead>
                  <TableHead className="text-[11px] h-8">Change Type</TableHead>
                  <TableHead className="text-[11px] h-8">Impact</TableHead>
                  <TableHead className="text-[11px] h-8">Affected Domains</TableHead>
                  <TableHead className="text-[11px] h-8">Effective</TableHead>
                  <TableHead className="text-[11px] h-8">Days Until</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.upcoming ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">No upcoming regulatory changes yet</TableCell></TableRow>
                ) : (arr(liveData?.upcoming ?? [])).map((row: any, idx: number) => (
                  <TableRow key={row.id ?? idx} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{row.reg ?? row.regulation_name ?? row.name}</TableCell>
                    <TableCell className="py-2.5"><ChangeTypeBadge type={row.changeType ?? row.change_type ?? "amendment"} /></TableCell>
                    <TableCell className="py-2.5"><ImpactBadge impact={row.impact ?? row.impact_level ?? "medium"} /></TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {(arr(row.domains ?? row.affected_domains ?? [])).map((d: string) => (
                          <span key={d} className="text-[10px] rounded bg-muted/50 px-1.5 py-0.5 text-muted-foreground">{d}</span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.effectiveAt ?? row.effective_date ?? row.effective_at}</TableCell>
                    <TableCell className="py-2.5"><DaysUntilChip days={row.daysUntil ?? row.days_until ?? 0} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Obligations table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ClipboardCheck className="h-4 w-4 text-purple-400" />
              Compliance Obligations
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {(liveData?.stats?.obligations ?? []).filter((o: any) => o.status === "overdue").length} overdue
            </Badge>
          </div>
          <CardDescription className="text-xs">Active obligations across all tracked regulations</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Obligation</TableHead>
                  <TableHead className="text-[11px] h-8">Regulation</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Deadline</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.stats?.obligations ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">No obligations yet</TableCell></TableRow>
                ) : (arr(liveData?.stats?.obligations ?? [])).map((row: any, i: number) => (
                  <TableRow key={i} className={cn("hover:bg-muted/30", row.status === "overdue" && "bg-red-500/5")}>
                    <TableCell className="text-xs py-2.5 max-w-[220px] truncate font-medium">{row.title}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.reg ?? row.regulation}</TableCell>
                    <TableCell className="py-2.5"><ObligTypeBadge type={row.type ?? row.obligation_type ?? "operational"} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.deadline ?? row.due_date}</TableCell>
                    <TableCell className="py-2.5"><ObligStatusBadge status={row.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.owner}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Assessment history + Catalog */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Assessment history */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-green-400" />
              Assessment History
            </CardTitle>
            <CardDescription className="text-xs">Recent compliance assessments with gap counts</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {(liveData?.stats?.assessments ?? []).length === 0 ? (
              <EmptyState icon={BarChart3} title="No assessments yet" description="Compliance assessments will appear here once completed." />
            ) : (arr(liveData?.stats?.assessments ?? [])).map((a: any, i: number) => (
              <div key={i} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{a.reg ?? a.regulation_name ?? a.framework}</span>
                    {(a.critGaps ?? a.critical_gaps ?? 0) > 0 && (
                      <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{a.critGaps ?? a.critical_gaps} critical</Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <span>{a.gaps ?? a.gap_count ?? 0} gaps</span>
                    <span>·</span>
                    <span>{a.assessedAt ?? a.assessed_at}</span>
                  </div>
                </div>
                <ComplianceBar pct={a.compliancePct ?? a.compliance_pct ?? a.compliance_score ?? 0} />
                <p className="text-[10px] text-muted-foreground">Assessed by: {a.assessor}</p>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Regulation catalog */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-400" />
              Regulation Catalog
            </CardTitle>
            <CardDescription className="text-xs">All tracked regulations by jurisdiction and category</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Regulation</TableHead>
                  <TableHead className="text-[11px] h-8">Jurisdiction</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.active ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">No regulations tracked yet</TableCell></TableRow>
                ) : (arr(liveData?.active ?? [])).map((reg: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2">{reg.name ?? reg.regulation_name}</TableCell>
                    <TableCell className="py-2"><JurisdictionBadge j={reg.jurisdiction ?? reg.jurisdiction_code ?? "—"} /></TableCell>
                    <TableCell className="py-2"><CategoryBadge cat={reg.category ?? reg.regulation_type ?? "—"} /></TableCell>
                    <TableCell className="py-2">
                      <Badge className={cn("text-[10px] border capitalize",
                        reg.status === "active" ? "border-green-500/30 text-green-400 bg-green-500/10" : "border-amber-500/30 text-amber-400 bg-amber-500/10"
                      )}>{reg.status ?? "active"}</Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2 text-muted-foreground font-mono">{reg.version ?? reg.regulation_version ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
