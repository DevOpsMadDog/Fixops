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

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ==================================================

const MOCK_ACCOUNTS = [
  { id: "SA-001", name: "svc-deploy-prod",    system: "Kubernetes",  risk_score: 92, last_rotation: "182d ago", unused: false, action: "rotate_now"  },
  { id: "SA-002", name: "svc-ci-runner",      system: "GitHub CI",   risk_score: 78, last_rotation: "96d ago",  unused: false, action: "rotate_soon" },
  { id: "SA-003", name: "svc-db-backup",      system: "PostgreSQL",  risk_score: 85, last_rotation: "211d ago", unused: true,  action: "disable"     },
  { id: "SA-004", name: "svc-monitoring",     system: "Prometheus",  risk_score: 31, last_rotation: "44d ago",  unused: false, action: "none"        },
  { id: "SA-005", name: "svc-legacy-etl",     system: "Internal",    risk_score: 74, last_rotation: "365d ago", unused: true,  action: "review"      },
  { id: "SA-006", name: "svc-s3-exporter",    system: "AWS",         risk_score: 88, last_rotation: "127d ago", unused: false, action: "rotate_now"  },
  { id: "SA-007", name: "svc-ldap-sync",      system: "AD",          risk_score: 55, last_rotation: "61d ago",  unused: false, action: "rotate_soon" },
  { id: "SA-008", name: "svc-k8s-autoscaler", system: "Kubernetes",  risk_score: 44, last_rotation: "38d ago",  unused: false, action: "none"        },
];

const MOCK_STATS = {
  total_service_accounts: 47,
  high_risk: 8,
  unused_90d: 12,
  overdue_rotations: 15,
};

// == Helpers ==================================================

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

// == Component ================================================

export default function ServiceAccountAuditDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/service-account-auditor/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/service-account-auditor/accounts?org_id=${ORG_ID}&limit=50`),
    ]).then(([statsR, accountsR]) => {
      const stats    = statsR.status    === "fulfilled" ? statsR.value    : null;
      const accounts = accountsR.status === "fulfilled" ? accountsR.value : null;
      if (stats || accounts) setLiveData({ stats, accounts });
    })
      .finally(() => setLoading(false)).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const stats    = liveData?.stats ?? MOCK_STATS;
  const accounts = liveData?.accounts?.items ?? liveData?.accounts ?? MOCK_ACCOUNTS;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

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
                {accounts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  accounts.map((a: any, i: number) => (
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
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
