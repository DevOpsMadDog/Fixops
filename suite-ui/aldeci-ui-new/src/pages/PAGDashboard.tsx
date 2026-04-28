// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * PAG (Privileged Access Governance) Dashboard - Live API
 * Route: /pag
 * API: GET /api/v1/pag/{accounts,sessions,anomalies,stats}
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { KeyRound, RefreshCw, AlertTriangle, UserCheck, Activity } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function AccountTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    admin: "border-red-500/30 text-red-400 bg-red-500/10",
    root: "border-red-600/30 text-red-300 bg-red-600/10",
    service: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    domain_admin: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    break_glass: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return <Badge variant="outline" className={cn("text-xs", map[type] ?? "border-gray-500/30 text-gray-400 bg-gray-500/10")}>{(type ?? "").replace("_", " ")}</Badge>;
}
function RiskBadge({ score }: { score: number }) {
  const cls = score >= 90 ? "bg-red-600 text-white" : score >= 70 ? "bg-orange-500 text-white" : score >= 40 ? "bg-amber-500 text-black" : "bg-emerald-500 text-white";
  return <span className={cn("inline-block px-2 py-0.5 rounded text-xs font-bold", cls)}>{score}</span>;
}

export default function PAGDashboard() {
  const [accounts, setAccounts] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [a, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/pag/accounts"),
        apiFetch<any>("/api/v1/pag/stats"),
      ]);
      if (a.status === "fulfilled") { const v = a.value as any; setAccounts(Array.isArray(v) ? v : (v.accounts ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Privileged Access Governance"
        description="Privileged account monitoring, session tracking, anomaly detection"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : accounts.length === 0 ? <EmptyState icon={KeyRound} title="No privileged accounts" description="Connect your IAM/PAM source to start governance." />
        : <>
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Total PA Accounts" value={stats?.total_pa_accounts ?? accounts.length} icon={KeyRound} />
            <KpiCard title="Active Sessions" value={stats?.active_sessions_today ?? 0} icon={Activity} />
            <KpiCard title="Open Anomalies" value={stats?.open_anomalies ?? 0} icon={AlertTriangle} />
            <KpiCard title="High Risk" value={stats?.high_risk_accounts ?? accounts.filter(a => (a.risk_score ?? 0) >= 80).length} icon={UserCheck} />
          </motion.div>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-semibold">Privileged Accounts</CardTitle>
              <CardDescription className="text-xs">Inventory with risk scoring</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow className="border-gray-700/50"><TableHead className="text-xs text-gray-400">Username</TableHead><TableHead className="text-xs text-gray-400">Type</TableHead><TableHead className="text-xs text-gray-400">System</TableHead><TableHead className="text-xs text-gray-400">Owner</TableHead><TableHead className="text-xs text-gray-400 text-right">Risk</TableHead><TableHead className="text-xs text-gray-400">Last Used</TableHead></TableRow></TableHeader>
                <TableBody>{accounts.map(a => (
                  <TableRow key={a.id ?? a.username} className="border-b border-gray-700/50 hover:bg-gray-800/30">
                    <TableCell className="text-sm font-mono text-gray-200">{a.username}</TableCell>
                    <TableCell><AccountTypeBadge type={a.account_type} /></TableCell>
                    <TableCell className="text-xs text-gray-400">{a.system}</TableCell>
                    <TableCell className="text-xs text-gray-400">{a.owner}</TableCell>
                    <TableCell className="text-right"><RiskBadge score={a.risk_score ?? 0} /></TableCell>
                    <TableCell className="text-xs text-gray-400">{a.last_used ?? "—"}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>
        </>}
    </div>
  );
}
