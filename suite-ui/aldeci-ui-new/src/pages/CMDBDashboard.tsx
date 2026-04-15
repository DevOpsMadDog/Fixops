/**
 * CMDB Dashboard — Configuration Management Database
 *
 * IT asset inventory and relationship tracking.
 *   1. KPIs: Total CIs, Active, Changes This Week, Critical Assets
 *   2. CI inventory table (15 rows)
 *   3. Type breakdown (8 CI types, horizontal bars)
 *   4. Environment distribution (4 boxes)
 *   5. Recent changes table (12 rows)
 *   6. Relationship graph hint (static diagram)
 *
 * Route: /cmdb
 * API stubs: GET /api/v1/cmdb/cis  GET /api/v1/cmdb/changes
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Server,
  Database,
  RefreshCw,
  GitBranch,
  AlertTriangle,
  Activity,
  Eye,
  ArrowRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const CI_INVENTORY = [
  { name: "prod-db-primary",     type: "database",       env: "prod",    criticality: "Critical", owner: "DBA Team",    status: "online",  changed: "2026-04-14" },
  { name: "api-gateway-01",      type: "server",         env: "prod",    criticality: "Critical", owner: "Platform",    status: "online",  changed: "2026-04-13" },
  { name: "k8s-node-03",         type: "vm",             env: "prod",    criticality: "High",     owner: "DevOps",      status: "online",  changed: "2026-04-12" },
  { name: "auth-service",        type: "app",            env: "prod",    criticality: "Critical", owner: "AppSec",      status: "online",  changed: "2026-04-15" },
  { name: "redis-cache-01",      type: "database",       env: "prod",    criticality: "High",     owner: "Platform",    status: "online",  changed: "2026-04-10" },
  { name: "nginx-lb-01",         type: "network_device", env: "prod",    criticality: "High",     owner: "NetSec",      status: "online",  changed: "2026-04-09" },
  { name: "worker-container-07", type: "container",      env: "prod",    criticality: "Medium",   owner: "DevOps",      status: "online",  changed: "2026-04-15" },
  { name: "staging-api-02",      type: "server",         env: "staging", criticality: "Medium",   owner: "Platform",    status: "online",  changed: "2026-04-11" },
  { name: "staging-db-01",       type: "database",       env: "staging", criticality: "Medium",   owner: "DBA Team",    status: "online",  changed: "2026-04-08" },
  { name: "dev-k8s-cluster",     type: "vm",             env: "dev",     criticality: "Low",      owner: "DevOps",      status: "online",  changed: "2026-04-07" },
  { name: "data-pipeline-svc",   type: "app",            env: "prod",    criticality: "High",     owner: "Data Eng",    status: "degraded",changed: "2026-04-16" },
  { name: "vpn-concentrator",    type: "network_device", env: "prod",    criticality: "Critical", owner: "NetSec",      status: "online",  changed: "2026-04-06" },
  { name: "dr-replica-db",       type: "database",       env: "dr",      criticality: "Critical", owner: "DBA Team",    status: "standby", changed: "2026-04-05" },
  { name: "reporting-app",       type: "app",            env: "staging", criticality: "Low",      owner: "Analytics",   status: "online",  changed: "2026-04-04" },
  { name: "scan-worker-01",      type: "container",      env: "prod",    criticality: "Medium",   owner: "SecEng",      status: "online",  changed: "2026-04-16" },
];

const TYPE_BREAKDOWN = [
  { type: "server",         count: 312, color: "bg-blue-500/70" },
  { type: "vm",             count: 584, color: "bg-indigo-500/70" },
  { type: "container",      count: 891, color: "bg-violet-500/70" },
  { type: "database",       count: 203, color: "bg-amber-500/70" },
  { type: "app",            count: 447, color: "bg-green-500/70" },
  { type: "network_device", count: 128, color: "bg-cyan-500/70" },
  { type: "storage",        count:  94, color: "bg-orange-500/70" },
  { type: "endpoint",       count: 188, color: "bg-rose-500/70" },
];

const TYPE_MAX = 891;

const ENV_DIST = [
  { env: "Production", count: 1847, pct: 65, color: "border-red-500/30 bg-red-500/10", text: "text-red-400" },
  { env: "Staging",    count:  542, pct: 19, color: "border-yellow-500/30 bg-yellow-500/10", text: "text-yellow-400" },
  { env: "Dev",        count:  391, pct: 14, color: "border-blue-500/30 bg-blue-500/10", text: "text-blue-400" },
  { env: "DR",         count:   67, pct:  2, color: "border-green-500/30 bg-green-500/10", text: "text-green-400" },
];

const RECENT_CHANGES = [
  { ci: "auth-service",        change: "modify",       desc: "Updated TLS certificate to wildcard",  by: "m.chen",    date: "2026-04-16 09:12", status: "completed" },
  { ci: "scan-worker-01",      change: "add",          desc: "New container deployed for scan jobs", by: "k.devops",  date: "2026-04-16 08:45", status: "completed" },
  { ci: "data-pipeline-svc",   change: "modify",       desc: "Memory limit increased to 8GB",        by: "a.data",    date: "2026-04-16 07:30", status: "in_review" },
  { ci: "prod-db-primary",     change: "patched",      desc: "PostgreSQL 16.2 → 16.3 patch applied", by: "dba-auto",  date: "2026-04-15 22:00", status: "completed" },
  { ci: "nginx-lb-01",         change: "modify",       desc: "Added rate limiting rules (500/s)",    by: "n.netops",  date: "2026-04-15 18:14", status: "completed" },
  { ci: "worker-container-07", change: "patched",      desc: "Base image updated to node:22-slim",   by: "ci-pipeline",date: "2026-04-15 15:00", status: "completed" },
  { ci: "dev-k8s-cluster",     change: "modify",       desc: "Namespace quotas adjusted",            by: "j.devops",  date: "2026-04-15 12:33", status: "completed" },
  { ci: "reporting-app",       change: "modify",       desc: "Added SSO SAML integration",           by: "r.auth",    date: "2026-04-14 17:55", status: "completed" },
  { ci: "vpn-concentrator",    change: "patched",      desc: "Firmware 9.1.4 security patch",        by: "n.netops",  date: "2026-04-14 14:20", status: "completed" },
  { ci: "staging-api-02",      change: "add",          desc: "New replica added for load testing",   by: "platform",  date: "2026-04-14 11:00", status: "completed" },
  { ci: "redis-cache-01",      change: "modify",       desc: "maxmemory-policy set to allkeys-lru",  by: "platform",  date: "2026-04-13 16:40", status: "completed" },
  { ci: "old-batch-worker",    change: "decommission", desc: "Legacy batch worker retired",           by: "j.infra",   date: "2026-04-13 09:00", status: "completed" },
];

// ── Helpers ────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  server:         "border-blue-500/30 text-blue-400 bg-blue-500/10",
  vm:             "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  container:      "border-violet-500/30 text-violet-400 bg-violet-500/10",
  database:       "border-amber-500/30 text-amber-400 bg-amber-500/10",
  app:            "border-green-500/30 text-green-400 bg-green-500/10",
  network_device: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  storage:        "border-orange-500/30 text-orange-400 bg-orange-500/10",
  endpoint:       "border-rose-500/30 text-rose-400 bg-rose-500/10",
};

const ENV_BADGE: Record<string, string> = {
  prod:    "border-red-500/30 text-red-400 bg-red-500/10",
  staging: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  dev:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
  dr:      "border-green-500/30 text-green-400 bg-green-500/10",
};

const CRIT_BADGE: Record<string, string> = {
  Critical: "border-red-500/30 text-red-400 bg-red-500/10",
  High:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
  Medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  Low:      "border-border text-muted-foreground",
};

const CHANGE_BADGE: Record<string, string> = {
  add:          "border-green-500/30 text-green-400 bg-green-500/10",
  modify:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
  decommission: "border-red-500/30 text-red-400 bg-red-500/10",
  patched:      "border-purple-500/30 text-purple-400 bg-purple-500/10",
};

const STATUS_DOT: Record<string, string> = {
  online:   "bg-green-400",
  degraded: "bg-yellow-400",
  standby:  "bg-blue-400",
  offline:  "bg-red-400",
};

// ── Component ──────────────────────────────────────────────────

export default function CMDBDashboard() {
  const [refreshing, setRefreshing] = useState(false);

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
        title="Configuration Management Database"
        description="IT asset inventory and relationship tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total CIs"           value="2,847" icon={Database}      trend="up" />
        <KpiCard title="Active"              value="2,634" icon={Activity}      trend="up"   className="border-green-500/20" />
        <KpiCard title="Changes This Week"   value={47}    icon={GitBranch}     trend="up"   className="border-blue-500/20" />
        <KpiCard title="Critical Assets"     value={183}   icon={AlertTriangle} trend="down" className="border-red-500/20" />
      </div>

      {/* CI Inventory table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Server className="h-4 w-4 text-blue-400" />
              CI Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {CI_INVENTORY.length} shown of 2,847
            </Badge>
          </div>
          <CardDescription className="text-xs">Configuration items across all environments</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CI Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Environment</TableHead>
                  <TableHead className="text-[11px] h-8">Criticality</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Last Changed</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {CI_INVENTORY.map((ci) => (
                  <TableRow key={ci.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{ci.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", TYPE_COLORS[ci.type] ?? "border-border text-muted-foreground")}>
                        {ci.type.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", ENV_BADGE[ci.env] ?? "border-border text-muted-foreground")}>
                        {ci.env}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", CRIT_BADGE[ci.criticality])}>
                        {ci.criticality}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{ci.owner}</TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-1.5">
                        <span className={cn("h-2 w-2 rounded-full shrink-0", STATUS_DOT[ci.status] ?? "bg-muted")} />
                        <span className="text-xs text-muted-foreground capitalize">{ci.status}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{ci.changed}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                        <Eye className="h-3 w-3 mr-1" />View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Type breakdown + Environment distribution */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Type breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Database className="h-4 w-4 text-violet-400" />
              CI Type Breakdown
            </CardTitle>
            <CardDescription className="text-xs">Distribution by configuration item type</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {TYPE_BREAKDOWN.map((t) => (
              <div key={t.type} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="capitalize text-muted-foreground">{t.type.replace("_", " ")}</span>
                  <span className="font-semibold tabular-nums">{t.count}</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(t.count / TYPE_MAX) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", t.color)}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Environment distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-green-400" />
              Environment Distribution
            </CardTitle>
            <CardDescription className="text-xs">CIs grouped by deployment environment</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3">
              {ENV_DIST.map((e) => (
                <div key={e.env} className={cn("rounded-lg border p-4 flex flex-col gap-1", e.color)}>
                  <span className="text-xs font-semibold text-foreground">{e.env}</span>
                  <span className={cn("text-2xl font-bold tabular-nums", e.text)}>
                    {e.count.toLocaleString()}
                  </span>
                  <span className="text-[10px] text-muted-foreground">{e.pct}% of total</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent changes table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-blue-400" />
              Recent Changes
            </CardTitle>
            <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">
              47 this week
            </Badge>
          </div>
          <CardDescription className="text-xs">Latest CI modifications, additions, and decommissions</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CI Name</TableHead>
                  <TableHead className="text-[11px] h-8">Change</TableHead>
                  <TableHead className="text-[11px] h-8">Description</TableHead>
                  <TableHead className="text-[11px] h-8">Changed By</TableHead>
                  <TableHead className="text-[11px] h-8">Date</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {RECENT_CHANGES.map((c, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{c.ci}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", CHANGE_BADGE[c.change] ?? "border-border text-muted-foreground")}>
                        {c.change}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[220px] truncate text-muted-foreground">{c.desc}</TableCell>
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{c.by}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{c.date}</TableCell>
                    <TableCell className="py-2.5">
                      {c.status === "in_review"
                        ? <Badge className="text-[10px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10">in review</Badge>
                        : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">completed</Badge>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Relationship graph hint */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-purple-400" />
            CI Relationship Graph
          </CardTitle>
          <CardDescription className="text-xs">Example dependency chain — full interactive graph coming soon</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center gap-4 py-6">
            {/* Box 1 */}
            <div className="flex flex-col items-center gap-1">
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-center">
                <span className="text-xs font-semibold text-red-400">nginx-lb-01</span>
                <p className="text-[10px] text-muted-foreground mt-0.5">network_device</p>
              </div>
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-transparent">prod</Badge>
            </div>
            <ArrowRight className="h-5 w-5 text-muted-foreground shrink-0" />
            {/* Box 2 */}
            <div className="flex flex-col items-center gap-1">
              <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-center">
                <span className="text-xs font-semibold text-blue-400">api-gateway-01</span>
                <p className="text-[10px] text-muted-foreground mt-0.5">server</p>
              </div>
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-transparent">prod</Badge>
            </div>
            <ArrowRight className="h-5 w-5 text-muted-foreground shrink-0" />
            {/* Box 3 */}
            <div className="flex flex-col items-center gap-1">
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-center">
                <span className="text-xs font-semibold text-amber-400">prod-db-primary</span>
                <p className="text-[10px] text-muted-foreground mt-0.5">database</p>
              </div>
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-transparent">prod</Badge>
            </div>
          </div>
          <p className="text-center text-[11px] text-muted-foreground">
            Traffic flows: Load Balancer → API Gateway → Primary Database
          </p>
        </CardContent>
      </Card>
    </motion.div>
  );
}
