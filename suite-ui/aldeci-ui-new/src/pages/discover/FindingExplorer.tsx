import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Search, Filter, AlertTriangle, Bug, RefreshCw, Download, ChevronRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { useCases, useTriageCase, useDashboardOverview } from "@/hooks/use-api";

export default function FindingExplorer() {
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("all");
  const cases = useCases();
  const overview = useDashboardOverview();
  const triage = useTriageCase();
  const refetch = useCallback(() => { cases.refetch(); overview.refetch(); }, [cases, overview]);

  if (cases.isLoading) return <PageSkeleton />;
  if (cases.isError) return <ErrorState onRetry={refetch} />;

  const allCases = cases.data?.cases ?? [];
  const ov = overview.data ?? {};

  const filtered = allCases.filter((c: Record<string, unknown>) => {
    const matchSearch = !search || String(c.title ?? "").toLowerCase().includes(search.toLowerCase()) || String(c.case_id ?? "").toLowerCase().includes(search.toLowerCase());
    const matchSev = sevFilter === "all" || c.priority === sevFilter;
    return matchSearch && matchSev;
  });

  const critCount = allCases.filter((c: Record<string, unknown>) => c.priority === "critical").length;
  const highCount = allCases.filter((c: Record<string, unknown>) => c.priority === "high").length;
  const openCount = allCases.filter((c: Record<string, unknown>) => c.status === "open").length;

  const cols = [
    { key: "case_id", header: "ID", render: (r: Record<string, unknown>) => <span className="font-mono text-xs text-primary">{String(r.case_id)}</span> },
    { key: "title", header: "Title", render: (r: Record<string, unknown>) => (
      <div className="max-w-md">
        <p className="font-medium truncate">{String(r.title)}</p>
        <p className="text-xs text-muted-foreground truncate">{String(r.description ?? "").slice(0, 80)}</p>
      </div>
    )},
    { key: "priority", header: "Priority", render: (r: Record<string, unknown>) => <Badge variant={r.priority === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.priority)}</Badge> },
    { key: "finding_count", header: "Findings", render: (r: Record<string, unknown>) => <span className="font-mono text-sm">{Number(r.finding_count ?? 0)}</span> },
    { key: "risk_score", header: "Risk", render: (r: Record<string, unknown>) => <span className="font-mono text-sm">{Number(r.risk_score ?? 0).toFixed(1)}</span> },
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.status)}</Badge> },
    { key: "root_cve", header: "CVE", render: (r: Record<string, unknown>) => r.root_cve ? <span className="font-mono text-xs">{String(r.root_cve)}</span> : <span className="text-muted-foreground text-xs">—</span> },
    { key: "created_at", header: "Created", render: (r: Record<string, unknown>) => <span className="text-xs text-muted-foreground">{r.created_at ? new Date(String(r.created_at)).toLocaleDateString() : "—"}</span> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Finding Explorer" description="Unified exposure case management across all scanners"
        actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Total Cases" value={allCases.length} icon={Bug} />
        <KpiCard title="Critical" value={critCount} icon={AlertTriangle} trend={critCount > 0 ? "up" : "flat"} />
        <KpiCard title="High" value={highCount} icon={AlertTriangle} />
        <KpiCard title="Open" value={openCount} icon={Filter} />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search cases..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
        </div>
        <Select value={sevFilter} onValueChange={setSevFilter}>
          <SelectTrigger className="w-[140px]"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-medium">Exposure Cases ({filtered.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable columns={cols} data={filtered} emptyMessage="No cases found. Ingest scan results to generate exposure cases." />
        </CardContent>
      </Card>
    </div>
  );
}
