/**
 * Threat Intel Automation Dashboard
 *
 * Automation rules, feed enrichments, trigger stats for the TI Automation engine.
 *   1. KPIs: Total Rules, Active Rules, Triggers Today, IOCs Enriched
 *   2. Automation rules table (name, trigger, action, last_run, status)
 *
 * Route: /threat-intel-automation
 * API: GET /api/v1/ti-automation/automations
 *      GET /api/v1/ti-automation/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Zap, RefreshCw, CheckCircle2, Activity, ListChecks } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import api from "@/lib/api";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

interface AutomationRule {
  id?: string;
  name?: string;
  trigger?: string;
  trigger_type?: string;
  action?: string;
  action_type?: string;
  last_run?: string;
  last_triggered?: string;
  status?: string;
}

interface TiStats {
  total_rules?: number;
  active_rules?: number;
  triggers_today?: number;
  iocs_enriched?: number;
}

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active: "border-violet-500/30 text-violet-400 bg-violet-500/10",
    paused: "border-slate-500/30 text-slate-400 bg-slate-500/10",
    error:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function TriggerBadge({ trigger }: { trigger: string }) {
  return (
    <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10 font-mono">
      {trigger.replace(/_/g, " ")}
    </Badge>
  );
}

function ActionBadge({ action }: { action: string }) {
  return (
    <Badge className="text-[10px] border border-violet-500/30 text-violet-300 bg-violet-500/10 font-mono">
      {action.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Skeleton loader ────────────────────────────────────────────

function TableSkeleton() {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: 5 }).map((_, i) => (
        <Skeleton key={i} className="h-8 w-full rounded" />
      ))}
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatIntelAutomation() {
  const [refreshKey, setRefreshKey] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rules, setRules] = useState<AutomationRule[]>([]);
  const [stats, setStats] = useState<TiStats>({});

  useEffect(() => {
    setLoading(true);
    setError(null);

    Promise.allSettled([
      api.get("/api/v1/ti-automation/automations"),
      api.get("/api/v1/ti-automation/stats"),
    ]).then(([rulesRes, statsRes]) => {
      if (rulesRes.status === "fulfilled") {
        const d = rulesRes.value.data;
        setRules(Array.isArray(d) ? d : (d?.automations ?? d?.items ?? []));
      } else {
        setError("Failed to load automation rules.");
      }
      if (statsRes.status === "fulfilled") {
        setStats(statsRes.value.data ?? {});
      }
      setLoading(false);
    });
  }, [refreshKey]);

  const handleRefresh = () => {
    setRefreshing(true);
    setRefreshKey((k) => k + 1);
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
        title="Threat Intel Automation"
        description="Automated enrichment, IOC processing, and threat intelligence pipeline rules"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || loading}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Rules"    value={stats.total_rules    ?? rules.length} icon={ListChecks}   trend="flat" />
        <KpiCard title="Active Rules"   value={stats.active_rules   ?? rules.filter((r) => r.status === "active").length} icon={CheckCircle2} trend="up" className="border-violet-500/20" />
        <KpiCard title="Triggers Today" value={stats.triggers_today ?? 0}            icon={Zap}          trend="up"   className="border-purple-500/20" />
        <KpiCard title="IOCs Enriched"  value={stats.iocs_enriched  ?? 0}            icon={Activity}     trend="up"   className="border-violet-500/20" />
      </div>

      {/* Rules Table */}
      <Card className="border-violet-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-violet-400">
            <Zap className="h-4 w-4" />
            Automation Rules
          </CardTitle>
          <CardDescription className="text-xs">
            Active automation rules — trigger → action pipeline
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <TableSkeleton />
          ) : error ? (
            <EmptyState
              icon={Zap}
              title="Could not load automation rules"
              description={error}
            />
          ) : rules.length === 0 ? (
            <EmptyState
              icon={ListChecks}
              title="No automation rules yet"
              description="Create your first automation rule to start processing threat intelligence automatically."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">ID</TableHead>
                    <TableHead className="text-[11px] h-8">Name</TableHead>
                    <TableHead className="text-[11px] h-8">Trigger</TableHead>
                    <TableHead className="text-[11px] h-8">Action</TableHead>
                    <TableHead className="text-[11px] h-8">Last Run</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((rule, i) => (
                    <TableRow key={rule.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{rule.id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-xs font-medium">{rule.name ?? "—"}</TableCell>
                      <TableCell className="py-2"><TriggerBadge trigger={rule.trigger ?? rule.trigger_type ?? "unknown"} /></TableCell>
                      <TableCell className="py-2"><ActionBadge action={rule.action ?? rule.action_type ?? "unknown"} /></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{rule.last_run ?? rule.last_triggered ?? "—"}</TableCell>
                      <TableCell className="py-2 text-right"><StatusBadge status={rule.status ?? "active"} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
