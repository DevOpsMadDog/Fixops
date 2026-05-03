// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Material Change Dashboard — high-impact code/config changes (Wave 3)
 * Route: /material-changes
 * API:   GET /api/v1/changes/material
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { GitPullRequest, RefreshCw, AlertTriangle, FileEdit } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface MaterialChange {
  id?: string;
  change_id?: string;
  repo?: string;
  pr_id?: string;
  title?: string;
  author?: string;
  classification?: string;
  risk_score?: number;
  files_changed?: number;
  lines_added?: number;
  lines_removed?: number;
  detected_at?: string;
  reasons?: string[];
}
interface Response {
  changes?: MaterialChange[];
  items?: MaterialChange[];
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

function classBadge(c?: string) {
  switch ((c ?? "").toLowerCase()) {
    case "security": return "border-red-500/30 text-red-400 bg-red-500/10";
    case "infra":
    case "infrastructure": return "border-orange-500/30 text-orange-400 bg-orange-500/10";
    case "auth": return "border-purple-500/30 text-purple-400 bg-purple-500/10";
    case "config": return "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
    case "data": return "border-cyan-500/30 text-cyan-400 bg-cyan-500/10";
    default: return "border-border";
  }
}

export default function MaterialChangeDashboard() {
  const [items, setItems] = useState<MaterialChange[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    setComingSoon(false);
    try {
      const r = await apiFetch<Response>("/api/v1/changes/material");
      if (!r) {
        setComingSoon(true);
        setItems([]);
      } else {
        setItems(r.changes ?? r.items ?? []);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const totalLines = items.reduce((s, m) => s + (m.lines_added ?? 0) + (m.lines_removed ?? 0), 0);
  const highRisk = items.filter((m) => (m.risk_score ?? 0) >= 7).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Material Changes"
        description="Code and config changes flagged as security-material — auth, infra, data-access, secrets"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Material Changes" value={items.length} icon={GitPullRequest} />
        <KpiCard title="High-Risk" value={highRisk} icon={AlertTriangle} trend="down" />
        <KpiCard title="Lines Changed" value={totalLines} icon={FileEdit} />
        <KpiCard title="Distinct Repos" value={new Set(items.map((m) => m.repo).filter(Boolean)).size} icon={GitPullRequest} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <GitPullRequest className="h-4 w-4" /> Detected Material Changes
          </CardTitle>
          <CardDescription className="text-xs">Sorted by detection time (newest first)</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={GitPullRequest} title="Coming soon" description="The material-change classifier endpoint is not yet enabled." />
          ) : items.length === 0 ? (
            <EmptyState icon={GitPullRequest} title="No material changes" description="When commits touch security-material areas, they'll appear here." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Repo / PR</TableHead>
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Class</TableHead>
                    <TableHead className="text-[11px] h-8">Risk</TableHead>
                    <TableHead className="text-[11px] h-8">Δ Files / LOC</TableHead>
                    <TableHead className="text-[11px] h-8">Author</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Detected</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((m, i) => (
                    <TableRow key={(m.id ?? m.change_id ?? "m") + i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">
                        <div>{m.repo ?? "—"}</div>
                        {m.pr_id && <div className="text-muted-foreground">#{m.pr_id}</div>}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] max-w-[260px]">
                        <div className="truncate">{m.title ?? "—"}</div>
                        {m.reasons && m.reasons.length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {m.reasons.slice(0, 3).map((r, ri) => (
                              <Badge key={ri} className="text-[9px] border border-border">{r}</Badge>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", classBadge(m.classification))}>{m.classification ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{m.risk_score?.toFixed(1) ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">
                        {m.files_changed ?? 0} / <span className="text-green-400">+{m.lines_added ?? 0}</span> <span className="text-red-400">−{m.lines_removed ?? 0}</span>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{m.author ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{m.detected_at?.slice(0, 10) ?? "—"}</TableCell>
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
