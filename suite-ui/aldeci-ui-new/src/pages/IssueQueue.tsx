// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Issue Queue — new findings inbox (Wave 3)
 * Route: /issue-queue
 * API:   GET /api/v1/findings?status=new
 */

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Inbox, RefreshCw, Search, ListFilter } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Finding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  source?: string;
  scanner?: string;
  asset?: string;
  asset_id?: string;
  cve?: string;
  cve_id?: string;
  created_at?: string;
}
interface ListResponse {
  items?: Finding[];
  findings?: Finding[];
  total?: number;
}

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function sevColor(s?: string) {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "border-red-500/30 text-red-400 bg-red-500/10";
    case "high": return "border-orange-500/30 text-orange-400 bg-orange-500/10";
    case "medium": return "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
    case "low": return "border-green-500/30 text-green-400 bg-green-500/10";
    default: return "border-border";
  }
}

export default function IssueQueue() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [sev, setSev] = useState<string>("all");

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<ListResponse | Finding[]>("/api/v1/findings?status=new&limit=200");
      const list: Finding[] = Array.isArray(r) ? r : (r?.items ?? r?.findings ?? []);
      setFindings(list);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return findings.filter((f) => {
      if (sev !== "all" && (f.severity ?? "").toLowerCase() !== sev) return false;
      if (!q) return true;
      const hay = [f.title, f.cve ?? f.cve_id, f.scanner ?? f.source, f.asset ?? f.asset_id]
        .filter(Boolean).join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [findings, filter, sev]);

  const sevCount = (s: string) => findings.filter((f) => (f.severity ?? "").toLowerCase() === s).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Issue Queue"
        description="New, untriaged findings from every scanner — your daily security inbox"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <KpiCard title="New Findings" value={findings.length} icon={Inbox} />
        <KpiCard title="Critical" value={sevCount("critical")} icon={Inbox} trend="down" />
        <KpiCard title="High" value={sevCount("high")} icon={Inbox} />
        <KpiCard title="Medium" value={sevCount("medium")} icon={Inbox} />
        <KpiCard title="Low" value={sevCount("low")} icon={Inbox} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <ListFilter className="h-4 w-4" /> Queue
          </CardTitle>
          <CardDescription className="text-xs">{visible.length} of {findings.length} shown</CardDescription>
          <div className="flex items-center gap-2 mt-2">
            <div className="relative flex-1 max-w-xs">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
              <Input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Search title, CVE, asset…"
                className="h-8 pl-7 text-xs"
              />
            </div>
            <Select value={sev} onValueChange={setSev}>
              <SelectTrigger className="h-8 w-[120px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : visible.length === 0 ? (
            <EmptyState
              icon={Inbox}
              title={findings.length === 0 ? "Queue is empty" : "No matches"}
              description={findings.length === 0 ? "All new findings have been triaged." : "Adjust filters to see more results."}
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">CVE</TableHead>
                    <TableHead className="text-[11px] h-8">Asset</TableHead>
                    <TableHead className="text-[11px] h-8">Scanner</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visible.map((f, i) => (
                    <TableRow key={f.id ?? f.finding_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2">
                        <Badge className={cn("text-[10px] border capitalize", sevColor(f.severity))}>{f.severity ?? "—"}</Badge>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] max-w-[320px] truncate">{f.title ?? "(untitled)"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{f.cve ?? f.cve_id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{f.asset ?? f.asset_id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{f.scanner ?? f.source ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{f.created_at?.slice(0, 10) ?? "—"}</TableCell>
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
