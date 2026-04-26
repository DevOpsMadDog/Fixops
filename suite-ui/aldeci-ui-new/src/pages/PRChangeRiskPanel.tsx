/**
 * PR Change-Risk Panel — graph diff for a specific PR (Wave 3)
 * Route: /pr-change-risk
 * API:   GET /api/v1/graph/diff?prId=...
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { GitMerge, RefreshCw, Search, FilePlus, FileMinus, FileEdit, ShieldAlert } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface NodeChange {
  id?: string;
  type?: string;
  label?: string;
  change?: "added" | "removed" | "modified";
  risk_delta?: number;
}
interface EdgeChange {
  source?: string;
  target?: string;
  change?: "added" | "removed";
  risk?: string;
}
interface DiffResponse {
  pr_id?: string;
  added_nodes?: NodeChange[];
  removed_nodes?: NodeChange[];
  modified_nodes?: NodeChange[];
  added_edges?: EdgeChange[];
  removed_edges?: EdgeChange[];
  risk_delta?: number;
  new_attack_paths?: number;
  closed_attack_paths?: number;
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

function changeIcon(c?: string) {
  if (c === "added") return <FilePlus className="h-3 w-3 text-green-400" />;
  if (c === "removed") return <FileMinus className="h-3 w-3 text-red-400" />;
  return <FileEdit className="h-3 w-3 text-yellow-400" />;
}

export default function PRChangeRiskPanel() {
  const [prId, setPrId] = useState("");
  const [data, setData] = useState<DiffResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const load = async (id: string) => {
    if (!id.trim()) return;
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const r = await apiFetch<DiffResponse>(`/api/v1/graph/diff?prId=${encodeURIComponent(id.trim())}`);
      if (!r) {
        setComingSoon(true);
        setData(null);
      } else {
        setData(r);
      }
    } catch (e) {
      setErr((e as Error).message);
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const hash = window.location.hash.match(/pr=([^&]+)/);
    if (hash) {
      setPrId(hash[1]);
      load(hash[1]);
    }
  }, []);

  const allChanges: NodeChange[] = [
    ...(data?.added_nodes ?? []).map((n) => ({ ...n, change: "added" as const })),
    ...(data?.removed_nodes ?? []).map((n) => ({ ...n, change: "removed" as const })),
    ...(data?.modified_nodes ?? []).map((n) => ({ ...n, change: "modified" as const })),
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="PR Change-Risk Analysis"
        description="Graph-diff view: how a pull request alters your security posture before merge"
        actions={
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
              <Input
                value={prId}
                onChange={(e) => setPrId(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && load(prId)}
                placeholder="PR ID (e.g. owner/repo#123)"
                className="h-8 w-[260px] pl-7 text-xs font-mono"
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => load(prId)} disabled={loading || !prId.trim()}>
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Δ Risk" value={data?.risk_delta?.toFixed(2) ?? "—"} icon={ShieldAlert} trend={(data?.risk_delta ?? 0) > 0 ? "down" : "up"} />
        <KpiCard title="Nodes Changed" value={allChanges.length} icon={FileEdit} />
        <KpiCard title="New Attack Paths" value={data?.new_attack_paths ?? 0} icon={GitMerge} trend="down" />
        <KpiCard title="Closed Attack Paths" value={data?.closed_attack_paths ?? 0} icon={GitMerge} trend="up" />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <GitMerge className="h-4 w-4" /> Graph Diff
          </CardTitle>
          <CardDescription className="text-xs">PR: <span className="font-mono">{data?.pr_id ?? prId ?? "—"}</span></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={() => load(prId)} />
          ) : comingSoon ? (
            <EmptyState icon={GitMerge} title="Coming soon" description="The graph-diff endpoint is not yet enabled in this build." />
          ) : !data ? (
            <EmptyState icon={GitMerge} title="Pick a PR" description="Enter a PR ID to compute its security graph diff." />
          ) : allChanges.length === 0 ? (
            <EmptyState icon={GitMerge} title="No graph changes" description="This PR did not alter the security graph (no asset/edge mutations)." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Δ</TableHead>
                    <TableHead className="text-[11px] h-8">Node</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Risk Δ</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {allChanges.map((n, i) => (
                    <TableRow key={(n.id ?? "n") + i} className="hover:bg-muted/30">
                      <TableCell className="py-2"><div className="flex items-center gap-1.5">{changeIcon(n.change)}<span className="text-[10px] capitalize text-muted-foreground">{n.change}</span></div></TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{n.label ?? n.id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground"><Badge className="text-[10px] border border-border">{n.type ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-right text-[11px] font-mono">
                        <span className={cn(
                          (n.risk_delta ?? 0) > 0 ? "text-red-400" : (n.risk_delta ?? 0) < 0 ? "text-green-400" : "text-muted-foreground"
                        )}>
                          {(n.risk_delta ?? 0) > 0 ? "+" : ""}{n.risk_delta?.toFixed(2) ?? "—"}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {data && (data.added_edges?.length ?? 0) + (data.removed_edges?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Edge Changes</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Δ</TableHead>
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                    <TableHead className="text-[11px] h-8">→ Target</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Risk</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {[...(data.added_edges ?? []).map((e) => ({ ...e, change: "added" as const })),
                    ...(data.removed_edges ?? []).map((e) => ({ ...e, change: "removed" as const }))].map((e, i) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-2"><span className={cn("text-[10px] capitalize", e.change === "added" ? "text-green-400" : "text-red-400")}>{e.change}</span></TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{e.source ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{e.target ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{e.risk ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}
