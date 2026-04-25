/**
 * Service Account Audit Dashboard
 *
 * Service account risk, rotation compliance, and unused account tracking.
 *   1. KPIs: Total Service Accounts, High Risk, Unused (90d), Overdue Rotations
 *   2. Table: service accounts with system, risk score, last rotation, action needed
 *
 * API: GET /api/v1/service-account-auditor/...
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Clock, RefreshCw, Shield, Users } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

const ORG_ID = "juice-shop-corp";

async function apiFetch(path: string) {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Helpers ──────────────────────────────────────────────────

function ActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    rotate_now:  "border-red-500/30 text-red-400 bg-red-500/10",
    rotate_soon: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    disable:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    review:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    none:        "border-green-500/30 text-green-400 bg-green-500/10",
  };
  const labels: Record<string, string> = {
    rotate_now:  "Rotate Now",
    rotate_soon: "Rotate Soon",
    disable:     "Disable",
    review:      "Review",
    none:        "OK",
  };
  return (
    <Badge className={cn("text-[10px] border", map[action] ?? "border-border text-muted-foreground")}>
      {labels[action] ?? action}
    </Badge>
  );
}

// ── Component ────────────────────────────────────────────────

export default function ServiceAccountAuditDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/service-account-auditor/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/service-account-auditor/accounts?org_id=${ORG_ID}&limit=50`),
    ]).then(([statsR, accountsR]) => {
      const stats    = statsR.status    === "fulfilled" ? statsR.value    : null;
      const accountsRaw = accountsR.status === "fulfilled" ? accountsR.value : null;
      const accounts = Array.isArray(accountsRaw) ? accountsRaw : (accountsRaw?.items ?? accountsRaw?.accounts ?? []);
      setLiveData({ stats, accounts });
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  if (dataLoading && !liveData) return <PageSkeleton />;

  const stats    = liveData?.stats ?? { total_service_accounts: 0, high_risk: 0, unused_90d: 0, overdue_rotations: 0 };
  const accounts = liveData?.accounts ?? [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Service Account Audit"
        description="Risk scoring, rotation compliance, and unused account detection"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Service Accounts" value={stats.total_service_accounts} icon={Users}         trend="up"   />
        <KpiCard title="High Risk"               value={stats.high_risk}             icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Unused (90d)"            value={stats.unused_90d}            icon={Clock}         trend="up"   className="border-amber-500/20" />
        <KpiCard title="Overdue Rotations"       value={stats.overdue_rotations}     icon={Shield}        trend="up"   className="border-orange-500/20" />
      </div>

      {/* Accounts Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Users className="h-4 w-4 text-blue-400" />
            Service Account Inventory
          </CardTitle>
          <CardDescription className="text-xs">Risk-sorted service accounts with rotation status and recommended action</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {accounts.length === 0 ? (
            <EmptyState icon={Users} title="No service accounts" description="Connect an IAM source to enumerate service accounts." />
          ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Account</TableHead>
                  <TableHead className="text-[11px] h-8">System</TableHead>
                  <TableHead className="text-[11px] h-8">Last Rotation</TableHead>
                  <TableHead className="text-[11px] h-8">Unused</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[110px]">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {accounts.map((a: any, i: number) => (
                  <TableRow key={a.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] font-medium">{a.name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{a.system}</TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{a.last_rotation}</TableCell>
                    <TableCell className="py-2">
                      {a.unused
                        ? <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">Yes</Badge>
                        : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">No</Badge>
                      }
                    </TableCell>
                    <TableCell className="py-2">
                      <div className="flex items-center gap-2">
                        <div className="relative flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden min-w-[60px]">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${a.risk_score}%` }}
                            transition={{ duration: 0.5, delay: i * 0.04 }}
                            className={cn("h-full rounded-full",
                              a.risk_score >= 80 ? "bg-red-500" :
                              a.risk_score >= 60 ? "bg-amber-500" : "bg-green-500"
                            )}
                          />
                        </div>
                        <span className={cn("text-xs font-bold tabular-nums w-6 text-right",
                          a.risk_score >= 80 ? "text-red-400" :
                          a.risk_score >= 60 ? "text-amber-400" : "text-green-400"
                        )}>{a.risk_score}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2"><ActionBadge action={a.action} /></TableCell>
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
