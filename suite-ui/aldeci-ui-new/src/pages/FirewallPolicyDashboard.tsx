/**
 * Firewall Policy Dashboard
 *
 * Firewall rule analysis — unused rules, conflicts, coverage.
 * Route: /firewall-policy
 * API: GET /api/v1/firewall-policy/{firewalls,stats}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Flame, Shield, AlertTriangle, GitMerge, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

const ORG_ID = "juice-shop-corp";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts?.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

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

export default function FirewallPolicyDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<any>(null);
  const [firewalls, setFirewalls] = useState<any[]>([]);

  const load = () => {
    Promise.allSettled([
      apiFetch(`/api/v1/firewall-policy/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/firewall-policy/firewalls?org_id=${ORG_ID}`),
    ]).then(([statsRes, fwRes]) => {
      if (statsRes.status === "fulfilled") setStats(statsRes.value);
      if (fwRes.status === "fulfilled") {
        const v = fwRes.value;
        setFirewalls(Array.isArray(v) ? v : (v?.items ?? v?.firewalls ?? []));
      } else {
        setFirewalls([]);
      }
      setLoading(false);
      setRefreshing(false);
    });
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { setRefreshing(true); load(); };

  if (loading) return <PageSkeleton />;

  const s = stats ?? { firewalls: 0, total_rules: 0, unused_rules: 0, conflicting_rules: 0 };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Firewall Policy"
        description="Firewall rule analysis — unused rules, conflicts, and policy coverage"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Firewalls"         value={s.firewalls ?? firewalls.length}        icon={Flame}         trend="flat" />
        <KpiCard title="Total Rules"       value={s.total_rules ?? 0}                      icon={Shield}        trend="flat" />
        <KpiCard title="Unused Rules"      value={s.unused_rules ?? 0}                     icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Conflicting Rules" value={s.conflicting_rules ?? 0}                icon={GitMerge}      trend="up"   className="border-red-500/20" />
      </div>

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
          {firewalls.length === 0 ? (
            <EmptyState icon={Flame} title="No firewalls registered" description="Add a firewall integration to begin policy analysis." />
          ) : (
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
                  {firewalls.map((fw: any) => (
                    <TableRow key={fw.id} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-xs text-foreground">{fw.name}</TableCell>
                      <TableCell className="py-2"><TypeBadge type={fw.type} /></TableCell>
                      <TableCell className="py-2 text-center text-xs tabular-nums">{fw.rule_count}</TableCell>
                      <TableCell className="py-2 text-center">
                        <span className={cn("text-xs font-semibold tabular-nums", fw.unused_rules > 20 ? "text-amber-400" : "text-muted-foreground")}>
                          {fw.unused_rules}
                        </span>
                      </TableCell>
                      <TableCell className="py-2 text-center">
                        <span className={cn("text-xs font-bold tabular-nums", fw.conflicts > 0 ? "text-red-400" : "text-green-400")}>
                          {fw.conflicts}
                        </span>
                      </TableCell>
                      <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">
                        {fw.last_analyzed}
                      </TableCell>
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
