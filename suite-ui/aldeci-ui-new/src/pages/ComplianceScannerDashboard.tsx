/**
 * Compliance Scanner Dashboard
 *
 * Automated multi-framework scanning and remediation.
 *   1. KPIs: Scan Profiles, Avg Score, Open Tasks, Critical Failures
 *   2. Scan profiles table (6 rows)
 *   3. Latest scan results (8 control checks)
 *   4. Remediation task list (10 tasks)
 *   5. Compliance score by framework (6 bars)
 *
 * API stubs: GET /api/v1/compliance-scanner/profiles, /api/v1/compliance-scanner/results
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ClipboardCheck, AlertTriangle, RefreshCw, BarChart3, CheckCircle, XCircle, AlertCircle, Play, Inbox } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
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
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── Static config (badge colour maps — not domain data) ──

// ── Helpers ────────────────────────────────────────────────────

function FrameworkBadge({ fw }: { fw: string }) {
  const map: Record<string, string> = {
    SOC2:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    ISO27001:"border-green-500/30 text-green-400 bg-green-500/10",
    NIST:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    PCI:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    HIPAA:   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    GDPR:    "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  };
  return <Badge key={fw} className={cn("text-[9px] border mr-0.5", map[fw] ?? "border-border text-muted-foreground")}>{fw}</Badge>;
}

function ProfileStatus({ s }: { s: string }) {
  const map: Record<string, string> = {
    passing: "border-green-500/30 text-green-400 bg-green-500/10",
    warning: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    failing: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[s] ?? "border-border text-muted-foreground")}>{s}</Badge>;
}

function ControlStatus({ status }: { status: string }) {
  if (status === "pass") return <CheckCircle className="h-4 w-4 text-green-400" />;
  if (status === "fail") return <XCircle className="h-4 w-4 text-red-400" />;
  return <AlertCircle className="h-4 w-4 text-amber-400" />;
}

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function PriorityBadge({ p }: { p: string }) {
  const cls =
    p === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    p === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    p === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                       "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{p}</Badge>;
}

function TaskStatusBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    overdue:     "border-red-500/30 text-red-400 bg-red-500/10",
    in_progress: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    open:        "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border", map[s] ?? "")}>{s.replace("_", " ")}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function ComplianceScannerDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/compliance-scanner/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/compliance-scanner/profiles?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/compliance-scanner/results?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/compliance-scanner/tasks?org_id=${ORG_ID}`),
    ]).then(([statsRes, profilesRes, resultsRes, tasksRes]) => {
      const stats    = statsRes.status    === "fulfilled" ? statsRes.value    : null;
      const profiles = profilesRes.status === "fulfilled" ? profilesRes.value : null;
      const results  = resultsRes.status  === "fulfilled" ? resultsRes.value  : null;
      const tasks    = tasksRes.status    === "fulfilled" ? tasksRes.value    : null;
      if (stats || profiles || results || tasks) {
        setLiveData({ stats, profiles, results, tasks });
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
      {/* Header */}
      <PageHeader
        title="Compliance Scanner"
        description="Automated multi-framework scanning and remediation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Scan Profiles"    value={liveData?.stats?.total_profiles ?? liveData?.profiles?.length ?? "—"}                      icon={ClipboardCheck} className="border-blue-500/20" />
        <KpiCard title="Avg Score"        value={liveData?.stats?.avg_score != null ? `${liveData.stats.avg_score}%` : "—"}                  icon={BarChart3}      trend="up"   className="border-green-500/20" />
        <KpiCard title="Open Tasks"       value={liveData?.stats?.open_tasks ?? liveData?.stats?.total_open_tasks ?? "—"}                    icon={AlertTriangle}  trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Failures" value={liveData?.stats?.critical_failures ?? liveData?.stats?.failed_critical ?? "—"}             icon={XCircle}        trend="down" className="border-red-500/20" />
      </div>

      {/* Scan Profiles */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4 text-blue-400" />
            Scan Profiles
          </CardTitle>
          <CardDescription className="text-xs">Multi-framework compliance scan configurations</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Profile</TableHead>
                  <TableHead className="text-[11px] h-8">Frameworks</TableHead>
                  <TableHead className="text-[11px] h-8">Last Scan</TableHead>
                  <TableHead className="text-[11px] h-8">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.profiles ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="py-6"><EmptyState icon={ClipboardCheck} title="No scan profiles yet" description="Profiles will appear once compliance scans have been configured." /></TableCell></TableRow>
                ) : (liveData.profiles as any[]).map((row: any) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{row.name}</TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex flex-wrap gap-0.5">
                        {(row.frameworks as string[]).map((fw: string) => <FrameworkBadge key={fw} fw={fw} />)}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.last_scan}</TableCell>
                    <TableCell className="py-2.5 w-36">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-muted/40 overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${row.score}%` }}
                            transition={{ duration: 0.7, ease: "easeOut" }}
                            className={cn("h-full rounded-full",
                              row.score >= 80 ? "bg-green-500" : row.score >= 60 ? "bg-amber-500" : "bg-red-500"
                            )}
                          />
                        </div>
                        <span className={cn("text-xs font-bold tabular-nums w-8",
                          row.score >= 80 ? "text-green-400" : row.score >= 60 ? "text-amber-400" : "text-red-400"
                        )}>{row.score}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2.5"><ProfileStatus s={row.status} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                        <Play className="h-3 w-3 mr-1" />Scan Now
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Scan Results + Framework Scores */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Latest Scan Results */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-400" />
              Latest Control Results
            </CardTitle>
            <CardDescription className="text-xs">Most recent framework control check outcomes</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8 w-8" />
                    <TableHead className="text-[11px] h-8">Control ID</TableHead>
                    <TableHead className="text-[11px] h-8">Control Name</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Remediation</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.results?.items ?? liveData?.results ?? []).length === 0 ? (
                    <TableRow><TableCell colSpan={6} className="py-6"><EmptyState icon={CheckCircle} title="No control results yet" description="Control check outcomes will appear after a scan runs." /></TableCell></TableRow>
                  ) : (liveData?.results?.items ?? liveData?.results as any[]).map((row: any) => (
                    <TableRow key={row.control_id} className="hover:bg-muted/30">
                      <TableCell className="py-2.5 pl-4"><ControlStatus status={row.status} /></TableCell>
                      <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{row.control_id}</TableCell>
                      <TableCell className="text-xs py-2.5 font-medium max-w-[160px] truncate">{row.control_name}</TableCell>
                      <TableCell className="py-2.5"><SeverityBadge sev={row.severity} /></TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">{row.category}</TableCell>
                      <TableCell className="text-xs py-2.5 max-w-[200px] truncate text-muted-foreground">{row.remediation}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Framework score bars */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              Score by Framework
            </CardTitle>
            <CardDescription className="text-xs">Current compliance posture per standard</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {(liveData?.stats?.framework_scores ?? []).length === 0 ? (
              <EmptyState icon={BarChart3} title="No framework scores yet" description="Scores will appear once compliance scans complete." />
            ) : (liveData.stats.framework_scores as any[]).map((fw: any) => {
              const score: number = fw.score ?? fw.compliance_score ?? 0;
              const barColor = score >= 80 ? "bg-green-500" : score >= 60 ? "bg-amber-500" : "bg-red-500";
              return (
                <div key={fw.name ?? fw.framework} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium">{fw.name ?? fw.framework}</span>
                    <span className={cn("font-bold tabular-nums",
                      score >= 80 ? "text-green-400" : score >= 60 ? "text-amber-400" : "text-red-400"
                    )}>{score}%</span>
                  </div>
                  <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${score}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full", barColor)}
                    />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>

      {/* Remediation Tasks */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Remediation Tasks
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{(liveData?.tasks ?? []).length} tasks</Badge>
          </div>
          <CardDescription className="text-xs">Open compliance remediation items sorted by priority</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8">Task</TableHead>
                  <TableHead className="text-[11px] h-8">Assigned To</TableHead>
                  <TableHead className="text-[11px] h-8">Due Date</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Days Left</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.tasks ?? []).length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="py-6"><EmptyState icon={AlertTriangle} title="No remediation tasks yet" description="Tasks will appear once compliance scan failures generate action items." /></TableCell></TableRow>
                ) : (liveData.tasks as any[]).map((row: any) => (
                  <TableRow key={row.id} className={cn("hover:bg-muted/30", row.days < 0 && "bg-red-500/5")}>
                    <TableCell className="py-2.5"><PriorityBadge p={row.priority} /></TableCell>
                    <TableCell className="text-xs py-2.5 font-medium max-w-[220px] truncate">{row.title}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.assigned}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.due}</TableCell>
                    <TableCell className="py-2.5"><TaskStatusBadge s={row.status} /></TableCell>
                    <TableCell className={cn("text-xs py-2.5 text-right font-bold tabular-nums",
                      row.days < 0 ? "text-red-400" : row.days < 7 ? "text-amber-400" : "text-muted-foreground"
                    )}>
                      {row.days < 0 ? `${Math.abs(row.days)}d overdue` : `${row.days}d`}
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
