/**
 * Security Registry Dashboard - Live API
 * Route: /security-registry
 * API: GET /api/v1/security-registry/artifacts
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { BookOpen, CheckCircle2, Clock, Archive, RefreshCw, FileText, BookMarked, ClipboardList } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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

const STATUS_CONFIG: Record<string, { cls: string; label: string }> = {
  active: { cls: "bg-green-500/10 text-green-400 border-green-500/20", label: "Active" },
  review: { cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20", label: "In Review" },
  draft: { cls: "bg-gray-500/10 text-gray-400 border-gray-500/20", label: "Draft" },
  deprecated: { cls: "bg-red-500/10 text-red-400 border-red-500/20", label: "Deprecated" },
};
const TYPE_COLORS: Record<string, string> = {
  policy: "bg-blue-500/10 text-blue-400",
  procedure: "bg-purple-500/10 text-purple-400",
  standard: "bg-cyan-500/10 text-cyan-400",
  guideline: "bg-yellow-500/10 text-yellow-400",
  runbook: "bg-green-500/10 text-green-400",
  playbook: "bg-red-500/10 text-red-400",
  template: "bg-orange-500/10 text-orange-400",
  checklist: "bg-teal-500/10 text-teal-400",
};
const TYPE_ICONS: Record<string, React.ReactNode> = {
  policy: <BookOpen className="w-4 h-4" />,
  procedure: <ClipboardList className="w-4 h-4" />,
  standard: <FileText className="w-4 h-4" />,
  guideline: <BookMarked className="w-4 h-4" />,
  runbook: <FileText className="w-4 h-4" />,
  playbook: <BookOpen className="w-4 h-4" />,
  template: <FileText className="w-4 h-4" />,
  checklist: <CheckCircle2 className="w-4 h-4" />,
};

export default function SecurityRegistryDashboard() {
  const [artifacts, setArtifacts] = useState<any[]>([]);
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/security-registry/artifacts");
      setArtifacts(Array.isArray(v) ? v : (v.artifacts ?? v.items ?? []));
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filtered = filterStatus === "all" ? artifacts : artifacts.filter(a => a.status === filterStatus);
  const total = artifacts.length;
  const active = artifacts.filter(a => a.status === "active").length;
  const review = artifacts.filter(a => a.status === "review").length;
  const deprecated = artifacts.filter(a => a.status === "deprecated").length;

  const typeCounts: Record<string, number> = {};
  artifacts.forEach(a => { const t = a.artifact_type ?? "policy"; typeCounts[t] = (typeCounts[t] ?? 0) + 1; });
  const typeStats = Object.entries(typeCounts).map(([type, count]) => ({ type, count }));

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Security Registry"
        description="Centralized artifact registry"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : artifacts.length === 0 ? <EmptyState icon={BookOpen} title="No artifacts" description="Add policies, procedures, runbooks to populate the registry." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Total Artifacts" value={total} icon={BookOpen} trend="up" trendLabel="in registry" />
            <KpiCard title="Active" value={active} icon={CheckCircle2} trend="up" trendLabel="approved & live" />
            <KpiCard title="Pending Review" value={review} icon={Clock} trend="down" trendLabel="awaiting approval" />
            <KpiCard title="Deprecated" value={deprecated} icon={Archive} trend="down" trendLabel="archived" />
          </div>

          {typeStats.length > 0 && <div className="grid grid-cols-4 sm:grid-cols-8 gap-3">{typeStats.map((ts, i) => (
            <motion.div key={ts.type} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }} className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 text-center">
              <div className={cn("flex justify-center mb-1", TYPE_COLORS[ts.type]?.split(" ")[1] ?? "text-gray-400")}>{TYPE_ICONS[ts.type] ?? <FileText className="w-4 h-4" />}</div>
              <p className="text-lg font-bold text-gray-100">{ts.count}</p>
              <p className="text-xs text-gray-500 capitalize">{ts.type}s</p>
            </motion.div>
          ))}</div>}

          <div className="flex gap-2 flex-wrap">{["all", "active", "review", "draft", "deprecated"].map(s => (
            <button key={s} onClick={() => setFilterStatus(s)} className={cn("px-3 py-1.5 rounded text-xs font-medium capitalize", filterStatus === s ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-gray-200 border border-gray-700")}>
              {s === "all" ? "All Artifacts" : STATUS_CONFIG[s]?.label ?? s}
            </button>
          ))}</div>

          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Registry <span className="ml-2 text-xs font-normal text-gray-400">({filtered.length} artifacts)</span></CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow className="border-gray-700/50">
                  <TableHead className="text-gray-400 text-xs">Title</TableHead>
                  <TableHead className="text-gray-400 text-xs">Type</TableHead>
                  <TableHead className="text-gray-400 text-xs">Status</TableHead>
                  <TableHead className="text-gray-400 text-xs">Version</TableHead>
                  <TableHead className="text-gray-400 text-xs">Owner</TableHead>
                  <TableHead className="text-gray-400 text-xs">Last Reviewed</TableHead>
                  <TableHead className="text-gray-400 text-xs">Next Review</TableHead>
                  <TableHead className="text-gray-400 text-xs text-right">Reviews</TableHead>
                </TableRow></TableHeader>
                <TableBody>{filtered.map((a, i) => {
                  const sCfg = STATUS_CONFIG[a.status] ?? { cls: "bg-gray-500/10 text-gray-400 border-gray-500/20", label: a.status };
                  return (
                    <motion.tr key={a.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }} className="border-b border-gray-700/50 hover:bg-gray-800/30">
                      <TableCell className="text-sm text-gray-200 max-w-[240px]">
                        <p className="truncate">{a.title}</p>
                        {Array.isArray(a.tags) && <div className="flex gap-1 mt-1 flex-wrap">{a.tags.slice(0, 2).map((tag: string) => (
                          <span key={tag} className="px-1.5 py-0.5 bg-gray-700/50 border border-gray-600/50 rounded text-xs text-gray-400">#{tag}</span>
                        ))}</div>}
                      </TableCell>
                      <TableCell><span className={cn("inline-block px-2 py-0.5 rounded text-xs font-medium capitalize", TYPE_COLORS[a.artifact_type] ?? "bg-gray-500/10 text-gray-400")}>{a.artifact_type}</span></TableCell>
                      <TableCell><Badge className={cn("border text-xs", sCfg.cls)}>{sCfg.label}</Badge></TableCell>
                      <TableCell className="font-mono text-xs text-gray-400">v{a.version}</TableCell>
                      <TableCell className="text-xs text-gray-400">{a.owner}</TableCell>
                      <TableCell className="text-xs text-gray-400">{a.last_reviewed}</TableCell>
                      <TableCell className="text-xs text-gray-400">{a.next_review ?? "—"}</TableCell>
                      <TableCell className="text-right text-sm text-gray-300">{a.review_count ?? 0}</TableCell>
                    </motion.tr>
                  );
                })}</TableBody>
              </Table>
            </CardContent>
          </Card>
        </>}
    </div>
  );
}
