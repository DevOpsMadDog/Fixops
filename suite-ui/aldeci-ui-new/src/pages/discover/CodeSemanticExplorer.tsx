/**
 * Code Semantic Explorer
 *
 * Browse semantic entities (functions, classes, modules) extracted by the DCA engine for a repo.
 * Route: /discover/code-semantic
 * API: GET /api/v1/dca/entities/{repo}
 * Multica id: ae8590d5-7186-4e90-930d-bfe895e240ea
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Boxes, FileCode2, RefreshCw, Search } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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

interface SemanticEntity {
  id?: string;
  name?: string;
  kind?: string; // function | class | module | interface
  file?: string;
  language?: string;
  loc?: number;
  complexity?: number;
  callers_count?: number;
  callees_count?: number;
  exported?: boolean;
}

interface EntityResponse {
  repo?: string;
  entities?: SemanticEntity[];
  items?: SemanticEntity[];
  total?: number;
  comingSoon?: boolean;
}

// Soft-fail statuses degrade to a "comingSoon" empty payload so the UI
// renders an EmptyState instead of throwing (which surfaces as a tab crash
// in the walkthrough console-error counter).
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  let res: Response;
  try {
    res = await fetch(url, {
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": orgId,
        "Content-Type": "application/json",
      },
    });
  } catch {
    return { data: { comingSoon: true } as T, status: 0 };
  }
  if (SOFT_FAIL_STATUSES.has(res.status)) return { data: { comingSoon: true } as T, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

const kindColor: Record<string, string> = {
  function: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  class: "border-purple-500/30 text-purple-400 bg-purple-500/10",
  module: "border-emerald-500/30 text-emerald-400 bg-emerald-500/10",
  interface: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  method: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
};

export default function CodeSemanticExplorer() {
  const [repo, setRepo] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [entities, setEntities] = useState<SemanticEntity[]>([]);
  const [comingSoon, setComingSoon] = useState(false);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async (target: string) => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data } = await apiFetch<EntityResponse>(
        `/api/v1/dca/entities/${encodeURIComponent(target)}`,
      );
      if (data.comingSoon) {
        setComingSoon(true);
        setEntities([]);
      } else {
        const list = Array.isArray(data) ? (data as SemanticEntity[]) : (data.entities ?? data.items ?? []);
        setEntities(list);
      }
    } catch (e) {
      setErr((e as Error).message);
      setEntities([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (submitted) load(submitted);
  }, [submitted]);

  const filtered = filter
    ? entities.filter(
        (e) =>
          (e.name ?? "").toLowerCase().includes(filter.toLowerCase()) ||
          (e.file ?? "").toLowerCase().includes(filter.toLowerCase()),
      )
    : entities;

  const fnCount = entities.filter((e) => (e.kind ?? "").toLowerCase() === "function").length;
  const classCount = entities.filter((e) => (e.kind ?? "").toLowerCase() === "class").length;
  const exportedCount = entities.filter((e) => e.exported).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Code Semantic Explorer"
        description="Browse functions, classes and modules extracted by the Deep Code Analysis engine"
        actions={
          <Button variant="outline" size="sm" onClick={() => submitted && load(submitted)} disabled={loading || !submitted}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Search className="h-4 w-4" /> Repository</CardTitle>
          <CardDescription className="text-xs">Enter org/repo to load semantic entities</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <Input
            value={repo}
            onChange={(e) => setRepo(e.target.value)}
            placeholder="org/repo-name"
            className="h-9 text-xs"
            onKeyDown={(e) => e.key === "Enter" && repo.trim() && setSubmitted(repo.trim())}
          />
          <Button size="sm" onClick={() => repo.trim() && setSubmitted(repo.trim())} disabled={!repo.trim()}>
            Load
          </Button>
        </CardContent>
      </Card>

      {submitted && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Total Entities" value={entities.length} icon={Boxes} />
          <KpiCard title="Functions" value={fnCount} icon={FileCode2} />
          <KpiCard title="Classes" value={classCount} icon={Boxes} />
          <KpiCard title="Exported" value={exportedCount} icon={FileCode2} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3 flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-sm font-semibold">Semantic Entities</CardTitle>
            <CardDescription className="text-xs">{submitted ? `Repo: ${submitted}` : "Pick a repository to begin"}</CardDescription>
          </div>
          {entities.length > 0 && (
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="filter by name or file…"
              className="h-8 max-w-xs text-xs"
            />
          )}
        </CardHeader>
        <CardContent className="p-0">
          {!submitted ? (
            <EmptyState icon={Search} title="No repository selected" description="Enter a repo above to load entities." />
          ) : loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading entities…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={() => submitted && load(submitted)} />
          ) : comingSoon ? (
            <EmptyState icon={Boxes} title="Coming soon" description="The /api/v1/dca/entities endpoint is not yet enabled on this deployment." />
          ) : filtered.length === 0 ? (
            <EmptyState icon={Boxes} title="No entities" description={`Repository ${submitted} returned no semantic entities.`} />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Name</TableHead>
                    <TableHead className="text-[11px] h-8">Kind</TableHead>
                    <TableHead className="text-[11px] h-8">File</TableHead>
                    <TableHead className="text-[11px] h-8">Lang</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">LOC</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Complexity</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Callers</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.slice(0, 200).map((e, i) => (
                    <TableRow key={e.id ?? `${e.name}-${i}`} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{e.name ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", kindColor[(e.kind ?? "").toLowerCase()] ?? "border-border")}>{e.kind ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground truncate max-w-xs">{e.file ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{e.language ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{e.loc ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{e.complexity ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{e.callers_count ?? 0}</TableCell>
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
