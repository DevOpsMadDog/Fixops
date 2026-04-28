// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Compliance Mapping Dashboard - Live API
 * Route: /compliance-mapping
 * API: GET /api/v1/compliance-mapping/{stats,controls}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, FileCheck, Link2, BarChart2, RefreshCw } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    compliant: { label: "Compliant", cls: "bg-green-500/10 text-green-400 border-green-500/20" },
    partial: { label: "Partial", cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" },
    non_compliant: { label: "Non-Compliant", cls: "bg-red-500/10 text-red-400 border-red-500/20" },
  };
  const { label, cls } = map[status] ?? { label: status ?? "—", cls: "bg-gray-500/10 text-gray-400" };
  return <Badge className={cn("border text-xs", cls)}>{label}</Badge>;
}

function ProgressBar({ value, max = 100 }: { value: number; max?: number }) {
  const pct = Math.min(100, (value / max) * 100);
  const color = pct >= 90 ? "bg-green-500" : pct >= 75 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden"><div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${pct}%` }} /></div>
      <span className="text-xs text-gray-400 w-8 text-right">{value}%</span>
    </div>
  );
}

export default function ComplianceMappingDashboard() {
  const [frameworks, setFrameworks] = useState<any[]>([]);
  const [controls, setControls] = useState<any[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [statsRes, controlsRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/compliance-mapping/stats"),
        apiFetch<any>("/api/v1/compliance-mapping/controls"),
      ]);
      if (statsRes.status === "fulfilled") {
        const v = statsRes.value;
        setFrameworks(Array.isArray(v) ? v : (v.frameworks ?? v.items ?? []));
      }
      if (controlsRes.status === "fulfilled") {
        const v = controlsRes.value;
        setControls(Array.isArray(v) ? v : (v.controls ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filtered = selectedFramework ? controls.filter(c => c.framework === selectedFramework) : controls;
  const totalFrameworks = frameworks.length;
  const totalControls = frameworks.reduce((s, f) => s + (f.total_controls ?? 0), 0);
  const mappedControls = frameworks.reduce((s, f) => s + (f.mapped_controls ?? 0), 0);
  const totalEvidence = frameworks.reduce((s, f) => s + (f.evidence_count ?? 0), 0);
  const compliantCount = frameworks.filter(f => f.status === "compliant").length;
  const isEmpty = frameworks.length === 0 && controls.length === 0;

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader title="Compliance Mapping" description="Multi-framework control mapping, implementation rates, and evidence coverage" badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />Refresh</Button>} />

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : isEmpty ? <EmptyState icon={Shield} title="No compliance data" description="No frameworks or controls mapped yet." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Frameworks" value={totalFrameworks} icon={Shield} trend="up" trendLabel={`${compliantCount} compliant`} />
            <KpiCard title="Total Controls" value={totalControls} icon={FileCheck} trend="up" trendLabel="across all frameworks" />
            <KpiCard title="Mapped Controls" value={mappedControls} icon={Link2} trend="up" trendLabel={totalControls ? `${Math.round((mappedControls / totalControls) * 100)}% coverage` : "no controls"} />
            <KpiCard title="Evidence Items" value={totalEvidence} icon={BarChart2} trend="up" trendLabel="from API" />
          </div>

          {frameworks.length > 0 && <Card>
            <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Framework Implementation Rates</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">{frameworks.map((fw, i) => (
                <motion.div key={fw.id ?? fw.name} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                  className={cn("p-4 rounded-lg border cursor-pointer transition-colors", selectedFramework === fw.name ? "bg-blue-500/10 border-blue-500/40" : "bg-gray-800/50 border-gray-700/50 hover:border-gray-600")}
                  onClick={() => setSelectedFramework(selectedFramework === fw.name ? null : fw.name)}>
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <p className="text-sm font-medium text-gray-100">{fw.name}</p>
                      <p className="text-xs text-gray-500">v{fw.version} · {fw.mapped_controls}/{fw.total_controls} controls · {fw.evidence_count} evidence</p>
                    </div>
                    <StatusBadge status={fw.status} />
                  </div>
                  <ProgressBar value={fw.implementation_rate ?? 0} />
                </motion.div>
              ))}</div>
            </CardContent>
          </Card>}

          {controls.length > 0 && <Card>
            <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
              <CardTitle className="text-sm font-semibold">Control Details {selectedFramework && <span className="ml-2 text-xs font-normal text-gray-400">— {selectedFramework}</span>}</CardTitle>
              {selectedFramework && <Button size="sm" variant="ghost" className="text-xs h-7" onClick={() => setSelectedFramework(null)}>Clear filter</Button>}
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow className="border-gray-700/50">
                  <TableHead className="text-gray-400 text-xs">Framework</TableHead><TableHead className="text-gray-400 text-xs">Control ID</TableHead><TableHead className="text-gray-400 text-xs">Title</TableHead><TableHead className="text-gray-400 text-xs">Implementation</TableHead><TableHead className="text-gray-400 text-xs text-right">Evidence</TableHead><TableHead className="text-gray-400 text-xs text-right">Mappings</TableHead>
                </TableRow></TableHeader>
                <TableBody>{filtered.map(ctrl => (
                  <TableRow key={ctrl.id} className="border-gray-700/50 hover:bg-gray-800/30">
                    <TableCell className="text-xs text-gray-400">{ctrl.framework}</TableCell>
                    <TableCell className="font-mono text-xs text-blue-400">{ctrl.control_id}</TableCell>
                    <TableCell className="text-sm text-gray-200">{ctrl.title}</TableCell>
                    <TableCell className="w-36"><ProgressBar value={ctrl.implementation_rate ?? 0} /></TableCell>
                    <TableCell className="text-right text-sm text-gray-300">{ctrl.evidence_count ?? 0}</TableCell>
                    <TableCell className="text-right text-sm text-gray-300">{ctrl.mappings ?? 0}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
