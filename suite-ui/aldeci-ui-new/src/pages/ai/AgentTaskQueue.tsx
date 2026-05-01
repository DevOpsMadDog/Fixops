// FOLDED into AICopilotAgentsHub hero (tasks tab) 2026-05-02 — preserve for git history
/**
 * Agent Task Queue
 *
 * Live view of queued / running / completed agent tasks.
 * Route: /ai/agent-tasks
 * API: GET /api/v1/agents/tasks
 * Multica id: 1ca85bdc-268b-409e-b039-e9a12911144b
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ListTodo, RefreshCw, Clock, CheckCircle2, XCircle } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface AgentTask {
  id?: string;
  task_id?: string;
  title?: string;
  agent?: string;
  agent_role?: string;
  priority?: string;
  status?: string;
  created_at?: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
}

interface TaskResponse {
  tasks?: AgentTask[];
  items?: AgentTask[];
  total?: number;
  comingSoon?: boolean;
}

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" } });
  if (res.status === 501 || res.status === 404) return { data: { comingSoon: true } as T, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

const statusColor: Record<string, string> = {
  queued: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  running: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  ready: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  completed: "border-green-500/30 text-green-400 bg-green-500/10",
  done: "border-green-500/30 text-green-400 bg-green-500/10",
  failed: "border-red-500/30 text-red-400 bg-red-500/10",
  error: "border-red-500/30 text-red-400 bg-red-500/10",
  cancelled: "border-gray-500/30 text-gray-400 bg-gray-500/10",
};

const priorityColor: Record<string, string> = {
  high: "border-red-500/30 text-red-400 bg-red-500/10",
  medium: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  low: "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

export default function AgentTaskQueue() {
  const [tasks, setTasks] = useState<AgentTask[]>([]);
  const [filter, setFilter] = useState<string>("all");
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data } = await apiFetch<TaskResponse>("/api/v1/agents/tasks");
      if (data.comingSoon) {
        setComingSoon(true);
        setTasks([]);
      } else {
        const list = Array.isArray(data) ? (data as AgentTask[]) : (data.tasks ?? data.items ?? []);
        setTasks(list);
      }
    } catch (e) {
      setErr((e as Error).message);
      setTasks([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const counts = {
    queued: tasks.filter((t) => ["queued", "ready"].includes((t.status ?? "").toLowerCase())).length,
    running: tasks.filter((t) => (t.status ?? "").toLowerCase() === "running").length,
    completed: tasks.filter((t) => ["completed", "done"].includes((t.status ?? "").toLowerCase())).length,
    failed: tasks.filter((t) => ["failed", "error"].includes((t.status ?? "").toLowerCase())).length,
  };

  const filtered = filter === "all" ? tasks : tasks.filter((t) => (t.status ?? "").toLowerCase() === filter || ((filter === "queued") && (t.status ?? "").toLowerCase() === "ready"));

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Agent Task Queue"
        description="Live view of queued, running, and completed agent tasks"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      {!comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Queued" value={counts.queued} icon={Clock} />
          <KpiCard title="Running" value={counts.running} icon={ListTodo} />
          <KpiCard title="Completed" value={counts.completed} icon={CheckCircle2} />
          <KpiCard title="Failed" value={counts.failed} icon={XCircle} trend={counts.failed ? "up" : "flat"} />
        </div>
      )}

      <div className="flex gap-2 flex-wrap">
        {["all", "queued", "running", "completed", "failed"].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={cn("px-3 py-1.5 rounded text-xs font-medium capitalize border border-border", filter === s ? "bg-primary text-primary-foreground" : "bg-muted/30 hover:bg-muted/50")}
          >
            {s}
          </button>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Tasks ({filtered.length})</CardTitle>
          <CardDescription className="text-xs">Includes SwarmClaw + AI agent tasks</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading queue…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={ListTodo} title="Coming soon" description="GET /api/v1/agents/tasks is not enabled on this deployment." />
          ) : filtered.length === 0 ? (
            <EmptyState icon={ListTodo} title="No tasks" description="No agent tasks match the current filter." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Agent</TableHead>
                    <TableHead className="text-[11px] h-8">Priority</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Created</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Duration (ms)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.slice(0, 200).map((t, i) => (
                    <TableRow key={t.id ?? t.task_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] truncate max-w-sm">{t.title ?? t.id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{t.agent ?? t.agent_role ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", priorityColor[(t.priority ?? "").toLowerCase()] ?? "border-border")}>{t.priority ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", statusColor[(t.status ?? "").toLowerCase()] ?? "border-border")}>{t.status ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[10px] text-muted-foreground">{t.created_at ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{t.duration_ms ?? 0}</TableCell>
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
