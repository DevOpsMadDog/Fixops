/**
 * Saved Investigations — list of saved RQL/graph queries
 * Route: /investigate/saved
 * API: GET /api/v1/investigate/saved
 * Multica id: eac1dd14
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Bookmark, RefreshCw, Play } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface SavedItem {
  id?: string;
  name?: string;
  rql?: string;
  owner?: string;
  category?: string;
  last_run?: string;
  result_count?: number;
}

interface Resp {
  items?: SavedItem[];
  saved?: SavedItem[];
  detail?: string;
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 501) return { detail: "Coming soon", items: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function SavedInvestigations() {
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<Resp>("/api/v1/investigate/saved");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const items = data?.items ?? data?.saved ?? [];
  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Saved Investigations"
        description="Personal and team-shared RQL queries — bookmark, schedule, share"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Bookmark className="h-4 w-4" /> Saved</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/investigate/saved</code></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={Bookmark} title="Coming soon" description="Endpoint returns 501." />
          : items.length === 0 ? <EmptyState icon={Bookmark} title="No saved investigations" />
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Name</TableHead>
                    <TableHead className="text-[11px] h-8">Owner</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Results</TableHead>
                    <TableHead className="text-[11px] h-8">Last Run</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((it, i) => (
                    <TableRow key={it.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{it.name ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{it.owner ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px]">{it.category ?? "general"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{it.result_count ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{it.last_run ?? "—"}</TableCell>
                      <TableCell className="py-2 text-right">
                        <Button variant="ghost" size="sm" className="h-7 text-[10px]"><Play className="h-3 w-3 mr-1" /> Run</Button>
                      </TableCell>
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
