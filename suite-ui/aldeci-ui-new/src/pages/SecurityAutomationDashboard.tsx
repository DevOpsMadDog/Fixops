/**
 * Security Automation Dashboard
 *
 * Route: /security-automation
 * API: GET /api/v1/security-automation/stats, /api/v1/security-automation/executions
 *
 * KPIs: Automation Rules, Executions Today, Success Rate, Avg Duration
 * Table: Recent executions — rule name, trigger type, status badge, actions taken, duration
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Zap, Play, CheckCircle2, Timer, RefreshCw, ListChecks } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}


// ── Badge helpers ──────────────────────────────────────────────

function TriggerBadge({ trigger }: { trigger: string }) {
  const map: Record<string, string> = {
    threshold:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    alert:       "border-red-500/30 text-red-400 bg-red-500/10",
    schedule:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    secret_scan: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    cve_feed:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    uba:         "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    event:       "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[trigger] ?? "border-border text-muted-foreground")}>
      {trigger.replace(/_/g, " ")}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    success: "border-green-500/30 text-green-400 bg-green-500/10",
    failed:  "border-red-500/30 text-red-400 bg-red-500/10",
    skipped: "border-slate-500/30 text-slate-400 bg-slate-500/10",
    running: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityAutomationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats]           = useState<{ total_rules: number; executions_today: number; success_rate: number; avg_duration_ms: number }>({ total_rules: 0, executions_today: 0, success_rate: 0, avg_duration_ms: 0 });
  const [executions, setExecutions] = useState<any[]>([]);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/security-automation/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-automation/executions?org_id=${ORG_ID}&limit=10`),
    ]).then(([statsRes, execRes]) => {
      if (statsRes.status === "fulfilled" && statsRes.value) setStats(statsRes.value);
      if (execRes.status === "fulfilled" && execRes.value) setExecutions(execRes.value);
    });
    setLoading(false);
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const successRatePct = `${Math.round((stats.success_rate ?? 0) * 100)}%`;
  const avgDuration    = `${stats.avg_duration_ms ?? 0}ms`;


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Security Automation"
        description="Automated response rules, playbook executions, and remediation workflows"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Automation Rules"   value={stats.total_rules}       icon={Zap}         trend="up" />
        <KpiCard title="Executions Today"   value={stats.executions_today}  icon={Play}        trend="up" className="border-blue-500/20" />
        <KpiCard title="Success Rate"       value={successRatePct}          icon={CheckCircle2} trend="up" className="border-green-500/20" />
        <KpiCard title="Avg Duration"       value={avgDuration}             icon={Timer}       trend="flat" />
      </div>

      {/* Executions Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-blue-400" />
              Recent Executions
            </CardTitle>
            <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">
              {executions.length} shown
            </Badge>
          </div>
          <CardDescription className="text-xs">Last 10 automation rule executions with outcomes</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Rule Name</TableHead>
                  <TableHead className="text-[11px] h-8">Trigger</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Actions</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Duration</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {executions.map((exec: any) => (
                  <TableRow key={exec.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium max-w-[220px] truncate">{exec.rule_name}</TableCell>
                    <TableCell className="py-2"><TriggerBadge trigger={exec.trigger} /></TableCell>
                    <TableCell className="py-2"><StatusBadge status={exec.status} /></TableCell>
                    <TableCell className="py-2 text-right">
                      <span className={cn(
                        "text-xs tabular-nums font-semibold",
                        exec.actions_taken > 0 ? "text-green-400" : "text-muted-foreground"
                      )}>
                        {exec.actions_taken}
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-right font-mono text-[11px] text-muted-foreground">
                      {exec.duration_ms}ms
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
