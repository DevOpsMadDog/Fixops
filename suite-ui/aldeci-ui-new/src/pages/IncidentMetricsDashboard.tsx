// FOLDED into IncidentKnowledgeHub at /remediate/incidents/knowledge?tab=metrics 2026-05-02 — preserve for git history (lazy-imported by hub)
/**
 * Incident Metrics Dashboard
 *
 * Operational metrics for incident management and SLA tracking.
 *   1. KPI cards: Total Incidents, Open Incidents, Avg MTTR (hours), SLA Breach Count
 *   2. Recent incidents table with MTTR and SLA breach status
 *
 * API: GET /api/v1/incident-metrics/{stats,incidents}
 */

import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  AlertCircle, RefreshCw, Clock, AlertTriangle, CheckCircle, TrendingDown,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

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

// ── Badge helpers ──────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function IncidentStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:       "border-red-500/30 text-red-400 bg-red-500/10",
    resolved:   "border-green-500/30 text-green-400 bg-green-500/10",
    in_progress: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    closed:     "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ── Component ──────────────────────────────────────────────────

export default function IncidentMetricsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    incidents: any[] | null;
  }>({ stats: null, incidents: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/incident-metrics/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/incident-metrics/incidents?org_id=${ORG_ID}`),
    ]).then(([statsRes, incidentsRes]) => {
      setLiveData({
        stats:     statsRes.status     === "fulfilled" ? statsRes.value     : null,
        incidents: incidentsRes.status === "fulfilled" ? incidentsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats     = liveData.stats     ?? null;
  const incidents = liveData.incidents ?? [];
  const hasAnyData = Boolean(stats) || incidents.length > 0;

  if (!hasAnyData) return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Incident Metrics"
        description="Operational metrics, MTTR tracking, and SLA compliance for incident management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />
      <EmptyState
        icon={AlertCircle}
        title="No incident metrics yet"
        description="Resolve incidents through the response workflow to populate MTTR and SLA metrics."
        action={
          <Link to="/onboarding" className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500">
            Start onboarding
          </Link>
        }
      />
    </motion.div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Incident Metrics"
        description="Operational metrics, MTTR tracking, and SLA compliance for incident management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Incidents"   value={stats?.total_incidents ?? "—"}                            icon={AlertCircle}   trend="up"   />
        <KpiCard title="Open Incidents"    value={stats?.open_incidents ?? "—"}                             icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Avg MTTR (hours)"  value={stats?.avg_mttr_hours != null ? `${stats.avg_mttr_hours}h` : "—"} icon={Clock}         trend="down" className="border-blue-500/20" />
        <KpiCard title="SLA Breaches"      value={stats?.sla_breach_count ?? "—"}                           icon={TrendingDown}  trend="up"   className="border-red-500/20" />
      </div>

      {/* Incidents Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-orange-400" />
              Recent Incidents
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {incidents.length} records
            </Badge>
          </div>
          <CardDescription className="text-xs">All incidents with MTTR and SLA breach indicators</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">MTTR</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">SLA Breached</TableHead>
                  <TableHead className="text-[11px] h-8">Reported</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={7} className="p-0">
                      <EmptyState
                        icon={AlertCircle}
                        title="No incidents recorded"
                        description="Incidents resolved through the response workflow will appear here."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  incidents.map((inc: any, i: number) => (
                    <TableRow key={inc.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{inc.id}</TableCell>
                      <TableCell className="py-2"><SeverityBadge severity={inc.severity ?? "medium"} /></TableCell>
                      <TableCell className="py-2 text-[11px] capitalize">{(inc.category ?? "").replace(/_/g, " ")}</TableCell>
                      <TableCell className="py-2"><IncidentStatusBadge status={inc.status ?? "open"} /></TableCell>
                      <TableCell className="py-2 font-mono text-[11px]">
                        {inc.mttr_hours != null ? `${inc.mttr_hours}h` : <span className="text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell className="py-2 text-center">
                        {inc.sla_breached
                          ? <AlertTriangle className="h-3.5 w-3.5 text-red-400 inline" />
                          : <CheckCircle   className="h-3.5 w-3.5 text-green-400 inline" />}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(inc.reported_at)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
