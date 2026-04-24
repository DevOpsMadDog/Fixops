/**
 * Security Query Language Dashboard
 *
 * SQL-over-security-data — run ad-hoc queries across unified finding/asset/identity tables.
 * Route: /security-query
 * API: GET /api/v1/sql/queries, /schema; POST /api/v1/sql/execute
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Database, Play, RefreshCw, Save, Terminal, Table as TableIcon } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface SavedQuery {
  id?: string;
  query_id?: string;
  name?: string;
  sql?: string;
  created_at?: string;
}

interface SchemaTable {
  name?: string;
  columns?: string[];
  row_count?: number;
}

interface ExecResult {
  columns?: string[];
  rows?: unknown[][];
  duration_ms?: number;
  row_count?: number;
  error?: string;
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

const DEFAULT_QUERY = `SELECT severity, COUNT(*) AS n
FROM findings
GROUP BY severity
ORDER BY n DESC
LIMIT 10;`;

export default function SecurityQueryLanguageDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [queries, setQueries] = useState<SavedQuery[]>([]);
  const [schema, setSchema] = useState<SchemaTable[]>([]);
  const [sql, setSql] = useState(DEFAULT_QUERY);
  const [result, setResult] = useState<ExecResult | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [q, s] = await Promise.allSettled([
        apiFetch<SavedQuery[] | { queries?: SavedQuery[] }>("/api/v1/sql/queries"),
        apiFetch<SchemaTable[] | { tables?: SchemaTable[] }>("/api/v1/sql/schema"),
      ]);
      setQueries(q.status === "fulfilled" ? (Array.isArray(q.value) ? q.value : q.value.queries ?? []) : []);
      setSchema(s.status === "fulfilled" ? (Array.isArray(s.value) ? s.value : s.value.tables ?? []) : []);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleRun = async () => {
    setRunning(true);
    setResult(null);
    try {
      const r = await apiFetch<ExecResult>("/api/v1/sql/execute", { method: "POST", body: JSON.stringify({ sql }) });
      setResult(r);
    } catch (e) {
      setResult({ error: (e as Error).message });
    } finally { setRunning(false); }
  };

  const totalQueries = queries.length;
  const tablesAvail = schema.length;
  const totalRows = schema.reduce((s, t) => s + (t.row_count ?? 0), 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Security Query Language"
        description="Ad-hoc SQL across unified findings, assets, identities, and events"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Tables Available" value={tablesAvail} icon={TableIcon} />
        <KpiCard title="Total Rows" value={totalRows} icon={Database} />
        <KpiCard title="Saved Queries" value={totalQueries} icon={Save} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        {/* Query Editor (3 cols) */}
        <Card className="xl:col-span-3">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2"><Terminal className="h-4 w-4" /> Query Editor</CardTitle>
            <CardDescription className="text-xs">Write SQL against the unified security data plane</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Textarea
              value={sql}
              onChange={e => setSql(e.target.value)}
              rows={8}
              className="font-mono text-xs leading-relaxed"
              spellCheck={false}
            />
            <div className="flex items-center gap-2">
              <Button size="sm" onClick={handleRun} disabled={running}>
                <Play className={cn("h-4 w-4 mr-2", running && "animate-pulse")} />
                Execute
              </Button>
              {result?.duration_ms !== undefined && !result.error && (
                <span className="text-xs text-muted-foreground">{result.row_count ?? result.rows?.length ?? 0} rows · {result.duration_ms} ms</span>
              )}
            </div>
            {result?.error && (
              <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs font-mono text-red-400">
                {result.error}
              </div>
            )}
            {result && !result.error && (
              <div className="overflow-x-auto rounded border border-border">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      {(result.columns ?? []).map(c => (
                        <TableHead key={c} className="text-[11px] h-8">{c}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(result.rows ?? []).map((row, i) => (
                      <TableRow key={i} className="hover:bg-muted/30">
                        {row.map((cell, j) => (
                          <TableCell key={j} className="py-2 text-[11px] font-mono">{String(cell ?? "—")}</TableCell>
                        ))}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {(result.rows?.length ?? 0) === 0 && (
                  <div className="p-6 text-center text-xs text-muted-foreground">Query returned 0 rows</div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Schema & Saved queries (1 col) */}
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><TableIcon className="h-4 w-4" /> Schema</CardTitle>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="text-xs text-muted-foreground">Loading…</div>
              ) : err ? (
                <ErrorState message={err} onRetry={load} />
              ) : schema.length === 0 ? (
                <EmptyState icon={TableIcon} title="No tables" description="Schema not yet available." />
              ) : (
                <div className="max-h-80 overflow-y-auto space-y-1.5">
                  {schema.map((t, i) => (
                    <details key={t.name ?? i} className="rounded border border-border/50 bg-muted/20 p-2">
                      <summary className="text-[11px] font-mono cursor-pointer flex items-center justify-between">
                        <span>{t.name ?? "—"}</span>
                        <Badge className="text-[10px] border border-border">{t.row_count ?? 0}</Badge>
                      </summary>
                      <div className="mt-2 flex flex-wrap gap-1">
                        {(t.columns ?? []).map(c => (
                          <span key={c} className="text-[10px] font-mono rounded bg-muted px-1.5 py-0.5">{c}</span>
                        ))}
                      </div>
                    </details>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><Save className="h-4 w-4" /> Saved Queries</CardTitle>
            </CardHeader>
            <CardContent>
              {queries.length === 0 ? (
                <EmptyState icon={Save} title="No saved queries" description="Your saved queries will appear here." />
              ) : (
                <div className="space-y-1">
                  {queries.map((q, i) => (
                    <button
                      key={q.id ?? q.query_id ?? i}
                      onClick={() => q.sql && setSql(q.sql)}
                      className="w-full text-left rounded border border-border/50 bg-muted/20 px-2 py-1.5 text-[11px] hover:bg-muted/40 transition-colors"
                    >
                      <div className="font-medium">{q.name ?? "Untitled"}</div>
                      <div className="text-muted-foreground font-mono truncate">{q.sql ?? ""}</div>
                    </button>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
