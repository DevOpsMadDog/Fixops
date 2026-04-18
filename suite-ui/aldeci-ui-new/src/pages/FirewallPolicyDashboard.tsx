/**
 * Firewall Policy Dashboard
 *
 * Firewall rule analysis — unused rules, conflicts, coverage.
 *   1. KPIs: Firewalls, Total Rules, Unused Rules, Conflicting Rules
 *   2. Firewalls table (name, type, rule count, last analyzed)
 *
 * Route: /firewall-policy
 * API: GET /api/v1/firewall-policy/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Flame, Shield, AlertTriangle, GitMerge, RefreshCw } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
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

const MOCK_FIREWALLS = [
  { id: "FW-001", name: "edge-fw-01",       type: "perimeter",  rule_count: 284, unused_rules: 42, conflicts: 3,  last_analyzed: "2026-04-16 08:15" },
  { id: "FW-002", name: "datacenter-fw-02", type: "internal",   rule_count: 156, unused_rules: 18, conflicts: 1,  last_analyzed: "2026-04-16 07:30" },
  { id: "FW-003", name: "cloud-fw-aws-01",  type: "cloud",      rule_count: 93,  unused_rules: 7,  conflicts: 0,  last_analyzed: "2026-04-15 22:00" },
  { id: "FW-004", name: "dmz-fw-03",        type: "dmz",        rule_count: 47,  unused_rules: 12, conflicts: 5,  last_analyzed: "2026-04-15 18:45" },
  { id: "FW-005", name: "cloud-fw-azure-01",type: "cloud",      rule_count: 68,  unused_rules: 4,  conflicts: 0,  last_analyzed: "2026-04-15 16:00" },
  { id: "FW-006", name: "branch-fw-04",     type: "branch",     rule_count: 31,  unused_rules: 8,  conflicts: 2,  last_analyzed: "2026-04-14 12:30" },
];

const MOCK_STATS = {
  firewalls: 6,
  total_rules: 679,
  unused_rules: 91,
  conflicting_rules: 11,
};

// ── Badge helpers ──────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    perimeter: "border-red-500/30 text-red-400 bg-red-500/10",
    internal:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    cloud:     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    dmz:       "border-amber-500/30 text-amber-400 bg-amber-500/10",
    branch:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border")}>
      {type}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function FirewallPolicyDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveData, setLiveData] = useState<any>(null);


  const fetchData = () => {
    setError(null);
    apiFetch(`/api/v1/firewall-policy/stats?org_id=${ORG_ID}`)
    .then((d) => setLiveData(d))
    .catch(err => setError(err.message || 'Failed to load data'));
  };

  useEffect(() => { fetchData(); }, []);

  const stats     = liveData ?? MOCK_STATS;
  const firewalls = liveData?.firewalls ?? MOCK_FIREWALLS;

  const handleRefresh = () => {
    setRefreshing(true);
    apiFetch(`/api/v1/firewall-policy/stats?org_id=${ORG_ID}`)
      .then((d) => setLiveData(d))
      .catch(err => setError(err.message || 'Failed to load data'))
      .finally(() => setRefreshing(false));
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Firewall Policy"
        description="Firewall rule analysis — unused rules, conflicts, and policy coverage"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
          <p className="font-medium">Error loading data</p>
          <p className="text-sm">{error}</p>
          <button onClick={() => { setError(null); fetchData(); }} className="mt-2 text-sm underline">Retry</button>
        </div>
      )}
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Firewalls"         value={stats.firewalls ?? 6}          icon={Flame}         trend="flat" />
        <KpiCard title="Total Rules"       value={stats.total_rules ?? 679}      icon={Shield}        trend="flat" />
        <KpiCard title="Unused Rules"      value={stats.unused_rules ?? 91}      icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Conflicting Rules" value={stats.conflicting_rules ?? 11} icon={GitMerge}      trend="up"   className="border-red-500/20" />
      </div>

      {/* Firewalls Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Flame className="h-4 w-4 text-orange-400" />
            Firewalls
          </CardTitle>
          <CardDescription className="text-xs">
            Managed firewalls with rule counts, anomalies, and last analysis timestamp
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Rules</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Unused</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Conflicts</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Last Analyzed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {firewalls.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  firewalls.map((fw: any) => (
                  <TableRow key={fw.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-xs text-foreground">{fw.name}</TableCell>
                    <TableCell className="py-2">
                      <TypeBadge type={fw.type} />
                    </TableCell>
                    <TableCell className="py-2 text-center text-xs tabular-nums">{fw.rule_count}</TableCell>
                    <TableCell className="py-2 text-center">
                      <span
                        className={cn(
                          "text-xs font-semibold tabular-nums",
                          fw.unused_rules > 20 ? "text-amber-400" : "text-muted-foreground"
                        )}
                      >
                        {fw.unused_rules}
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-center">
                      <span
                        className={cn(
                          "text-xs font-bold tabular-nums",
                          fw.conflicts > 0 ? "text-red-400" : "text-green-400"
                        )}
                      >
                        {fw.conflicts}
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">
                      {fw.last_analyzed}
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
  );
}
