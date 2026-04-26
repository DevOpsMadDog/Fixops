/**
 * Runtime Code Trace — map runtime trace to source-code locations (Wave 3)
 * Route: /runtime-code-trace
 * API:   POST /api/v1/runtime/map-to-code
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Code2, Play, FileCode, Loader2, Layers } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface CodeMapping {
  frame_index?: number;
  function?: string;
  file?: string;
  line?: number;
  repo?: string;
  commit?: string;
  blame_author?: string;
  has_finding?: boolean;
  finding_id?: string;
  severity?: string;
}
interface MapResponse {
  trace_id?: string;
  matched?: number;
  unmatched?: number;
  frames?: CodeMapping[];
  items?: CodeMapping[];
}

async function apiPost<T>(path: string, body: unknown): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
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

const SAMPLE = `[
  { "frame": 0, "function": "exec_query", "file": "/app/db/sql.py", "line": 142 },
  { "frame": 1, "function": "handle_request", "file": "/app/api/users.py", "line": 87 }
]`;

export default function RuntimeCodeTrace() {
  const [traceText, setTraceText] = useState(SAMPLE);
  const [data, setData] = useState<MapResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const run = async () => {
    setErr(null);
    setRunning(true);
    setComingSoon(false);
    let parsed: unknown;
    try {
      parsed = JSON.parse(traceText);
    } catch {
      setErr("Trace input is not valid JSON.");
      setRunning(false);
      return;
    }
    try {
      const r = await apiPost<MapResponse>("/api/v1/runtime/map-to-code", { trace: parsed });
      if (!r) {
        setComingSoon(true);
        setData(null);
      } else {
        setData(r);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const frames = data?.frames ?? data?.items ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Runtime → Code Trace"
        description="Map runtime stack frames to repository source locations and surface adjacent findings"
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Code2 className="h-4 w-4" /> Runtime Trace Input
            </CardTitle>
            <CardDescription className="text-xs">Paste a JSON array of stack frames (function, file, line)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Label className="text-[11px] text-muted-foreground">Trace JSON</Label>
              <Textarea
                value={traceText}
                onChange={(e) => setTraceText(e.target.value)}
                className="font-mono text-xs h-[260px]"
                spellCheck={false}
              />
              <Button size="sm" onClick={run} disabled={running}>
                {running ? <Loader2 className="h-3 w-3 mr-2 animate-spin" /> : <Play className="h-3 w-3 mr-2" />}
                {running ? "Mapping…" : "Map to Code"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Layers className="h-4 w-4" /> Mapping Stats
            </CardTitle>
            <CardDescription className="text-xs">Trace ID: <span className="font-mono">{data?.trace_id ?? "—"}</span></CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3">
              <KpiCard title="Frames Matched" value={data?.matched ?? frames.filter((f) => f.file).length} icon={FileCode} trend="up" />
              <KpiCard title="Frames Unmatched" value={data?.unmatched ?? frames.filter((f) => !f.file).length} icon={Code2} trend="down" />
              <KpiCard title="With Findings" value={frames.filter((f) => f.has_finding).length} icon={FileCode} />
              <KpiCard title="Total Frames" value={frames.length} icon={Layers} />
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Resolved Frames</CardTitle>
          <CardDescription className="text-xs">Each runtime frame matched to a repository file/line</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {err ? (
            <ErrorState message={err} onRetry={run} />
          ) : comingSoon ? (
            <EmptyState icon={Code2} title="Coming soon" description="The runtime/map-to-code endpoint is not yet enabled in this build." />
          ) : !data ? (
            <EmptyState icon={Code2} title="No mapping yet" description="Paste a trace and click Map to Code to resolve frames to source." />
          ) : frames.length === 0 ? (
            <EmptyState icon={Code2} title="No frames returned" description="The mapper produced no matches for this trace." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">#</TableHead>
                    <TableHead className="text-[11px] h-8">Function</TableHead>
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                    <TableHead className="text-[11px] h-8">Repo @ Commit</TableHead>
                    <TableHead className="text-[11px] h-8">Author</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Adjacent Finding</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {frames.map((f, i) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{f.frame_index ?? i}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{f.function ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{f.file ?? "—"}{f.line ? `:${f.line}` : ""}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{f.repo ?? "—"}{f.commit ? ` @ ${f.commit.slice(0, 7)}` : ""}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{f.blame_author ?? "—"}</TableCell>
                      <TableCell className="py-2 text-right">
                        {f.has_finding ? (
                          <Badge className={cn("text-[10px] border capitalize", sevColor(f.severity))}>{f.severity ?? "linked"}</Badge>
                        ) : (
                          <span className="text-[10px] text-muted-foreground">—</span>
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
    </motion.div>
  );
}
