/**
 * Code-to-Runtime Dashboard
 *
 * Correlate build-time artifacts (git sha → image) with runtime containers
 * and cloud resources. Show the end-to-end provenance of what's actually running.
 * Route: /code-to-runtime
 * API: /api/v1/code-to-runtime/stats, /events, /matches
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { GitCommit, RefreshCw, Container, Cloud, CheckCircle2, XCircle, Link as LinkIcon } from "lucide-react";

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

interface Stats {
  total_matches?: number;
  linked_runtime?: number;
  orphan_runtime?: number;
  latest_event?: string;
}

interface MatchRow {
  id?: string;
  git_sha?: string;
  image?: string;
  container?: string;
  runtime_host?: string;
  cloud_resource?: string;
  linked?: boolean;
  signed?: boolean;
  created_at?: string;
}

interface EventRow {
  id?: string;
  kind?: string;
  source?: string;
  target?: string;
  at?: string;
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function formatTs(ts?: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return ts; }
}

export default function CodeToRuntimeDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [matches, setMatches] = useState<MatchRow[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [s, m, e] = await Promise.allSettled([
        apiFetch<Stats>("/api/v1/code-to-runtime/stats"),
        apiFetch<MatchRow[] | { matches?: MatchRow[]; items?: MatchRow[] }>("/api/v1/code-to-runtime/matches"),
        apiFetch<EventRow[] | { events?: EventRow[]; items?: EventRow[] }>("/api/v1/code-to-runtime/events"),
      ]);
      setStats(s.status === "fulfilled" ? s.value : null);
      if (m.status === "fulfilled") {
        const v = m.value;
        setMatches(Array.isArray(v) ? v : (v.matches ?? v.items ?? []));
      } else { setMatches([]); }
      if (e.status === "fulfilled") {
        const v = e.value;
        setEvents(Array.isArray(v) ? v : (v.events ?? v.items ?? []));
      } else { setEvents([]); }
    } catch (ex) { setErr((ex as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const totalMatches = stats?.total_matches ?? matches.length;
  const linked = stats?.linked_runtime ?? matches.filter(m => m.linked).length;
  const orphans = stats?.orphan_runtime ?? matches.filter(m => m.linked === false).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Code → Runtime Lineage"
        description="End-to-end provenance: git commit → container image → running workload → cloud resource"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Matches" value={totalMatches} icon={LinkIcon} />
        <KpiCard title="Linked Runtime" value={linked} icon={CheckCircle2} trend="up" />
        <KpiCard title="Orphan Runtime" value={orphans} icon={XCircle} trend="down" />
        <KpiCard title="Latest Event" value={formatTs(stats?.latest_event ?? events[0]?.at)} icon={Cloud} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><GitCommit className="h-4 w-4" /> Build → Runtime Matches</CardTitle>
          <CardDescription className="text-xs">Each row traces a git commit through its image to the running workload</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading matches…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : matches.length === 0 ? (
            <EmptyState icon={LinkIcon} title="No matches yet" description="Matches appear as builds and runtime sensors emit events." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Git SHA</TableHead>
                    <TableHead className="text-[11px] h-8">Image</TableHead>
                    <TableHead className="text-[11px] h-8">Container</TableHead>
                    <TableHead className="text-[11px] h-8">Cloud Resource</TableHead>
                    <TableHead className="text-[11px] h-8">Signed</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Linked</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {matches.map((m, i) => (
                    <TableRow key={m.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{(m.git_sha ?? "—").slice(0, 10)}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground truncate max-w-[180px]">{m.image ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono truncate max-w-[140px]">{m.container ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{m.cloud_resource ?? m.runtime_host ?? "—"}</TableCell>
                      <TableCell className="py-2">
                        {m.signed ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Signed</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-muted/60 text-muted-foreground">—</Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2 text-right">
                        {m.linked ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Linked</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">Orphan</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Container className="h-4 w-4" /> Recent Events</CardTitle>
          <CardDescription className="text-xs">Build and runtime events being correlated in real time</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {events.length === 0 ? (
            <EmptyState icon={Container} title="No events" description="Recent build/runtime events will appear here." />
          ) : (
            <div className="divide-y divide-border/30">
              {events.slice(0, 20).map((ev, i) => (
                <div key={ev.id ?? i} className="flex items-center justify-between px-4 py-2 text-[11px]">
                  <div className="flex items-center gap-2">
                    <Badge className="text-[10px] border border-border capitalize">{ev.kind ?? "event"}</Badge>
                    <span className="font-mono truncate max-w-[220px]">{ev.source ?? "—"}</span>
                    <span className="text-muted-foreground">→</span>
                    <span className="font-mono truncate max-w-[220px]">{ev.target ?? "—"}</span>
                  </div>
                  <span className="text-muted-foreground">{formatTs(ev.at)}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
