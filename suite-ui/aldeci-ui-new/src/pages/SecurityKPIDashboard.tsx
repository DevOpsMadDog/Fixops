/**
 * Security KPI Dashboard - Live API
 * Route: /security-kpi
 * API: GET /api/v1/kpi/{scorecard,kpis,trends}
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { TrendingUp, RefreshCw, Award } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
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

function gradeFromScore(s: number) {
  if (s >= 90) return { g: "A", color: "text-emerald-400" };
  if (s >= 80) return { g: "B", color: "text-teal-400" };
  if (s >= 70) return { g: "C", color: "text-amber-400" };
  if (s >= 60) return { g: "D", color: "text-orange-400" };
  return { g: "F", color: "text-red-400" };
}

export default function SecurityKPIDashboard() {
  const [scorecard, setScorecard] = useState<any | null>(null);
  const [kpis, setKpis] = useState<any[]>([]);
  const [trends, setTrends] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [s, k, t] = await Promise.allSettled([
        apiFetch<any>("/api/v1/kpi/scorecard"),
        apiFetch<any>("/api/v1/kpi/kpis"),
        apiFetch<any>("/api/v1/kpi/trends"),
      ]);
      if (s.status === "fulfilled") { setScorecard(s.value); }
      if (k.status === "fulfilled") { const v = k.value as any; setKpis(Array.isArray(v) ? v : (v.kpis ?? v.items ?? [])); }
      if (t.status === "fulfilled") { const v = t.value as any; setTrends(Array.isArray(v) ? v : (v.trends ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const overall = scorecard?.overall_score ?? scorecard?.score ?? 0;
  const grade = gradeFromScore(overall);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Security KPI Scorecard"
        description="CISO-level security KPIs with grade and trends"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : !scorecard && kpis.length === 0 ? <EmptyState icon={Award} title="No KPIs configured" description="Configure security KPIs to populate the scorecard." />
        : <>
          {scorecard && <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="bg-gray-800 rounded-lg p-8 flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Overall Security Grade</p>
              <p className={cn("text-7xl font-black", grade.color)}>{grade.g}</p>
              <p className="text-gray-300 text-2xl font-bold mt-1">{overall}<span className="text-base text-gray-500">/100</span></p>
            </div>
            <Award className={cn("w-24 h-24", grade.color)} />
          </motion.div>}
          {kpis.length > 0 && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">KPIs</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>KPI</TableHead><TableHead>Current</TableHead><TableHead>Target</TableHead><TableHead>Trend</TableHead></TableRow></TableHeader>
                <TableBody>{kpis.map(k => (
                  <TableRow key={k.id ?? k.name} className="border-b border-gray-700/50">
                    <TableCell className="text-sm text-gray-200">{k.name ?? k.kpi_name}</TableCell>
                    <TableCell className="text-sm text-gray-300 font-mono">{k.current ?? k.value} {k.unit}</TableCell>
                    <TableCell className="text-sm text-gray-400 font-mono">{k.target ?? "—"} {k.unit}</TableCell>
                    <TableCell><TrendingUp className={cn("w-4 h-4", k.trend === "up" ? "text-emerald-400" : k.trend === "down" ? "text-red-400 rotate-180" : "text-gray-400")} /></TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>}
          {trends.length > 0 && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Recent Trends</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2">{trends.map((t, i) => (
                <div key={t.id ?? i} className="flex items-center justify-between p-2 bg-gray-700/30 rounded text-sm">
                  <span className="text-gray-300">{t.name ?? t.metric}</span>
                  <span className={cn("font-bold", (t.change ?? 0) > 0 ? "text-emerald-400" : "text-red-400")}>{(t.change ?? 0) > 0 ? "+" : ""}{t.change ?? 0}%</span>
                </div>
              ))}</div>
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
