/**
 * AICopilotAgentsHub — AI Copilot Agents unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone AI-agent surfaces into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.18 (S18 AI Copilot —
 * Agents Console + Task Queue + Shadow AI Inventory sub-cluster).
 *
 *   tab        | source page         | endpoint
 *   -----------|---------------------|--------------------------------------
 *   console    | AIAgentsConsole     | POST /api/v1/agents/{role}/task
 *   tasks      | AgentTaskQueue      | GET  /api/v1/queue/peek + /queue/status
 *   shadow     | ShadowAIInventory   | GET  /api/v1/shadow-ai/stats + /registry
 *
 * Route: /ai/agents
 * Persona target: AI Security Engineer (#19), Sec Architect (#9), CISO (#1)
 */

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Bot,
  ListTodo,
  EyeOff,
  Send,
  RefreshCw,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Activity,
  Shield,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  agentTasksApi,
  shadowAiApi,
  type AgentTaskDispatch,
  type QueueStatus,
  type QueuePeekItem,
  type ShadowAiStats,
  type ShadowAiService,
} from "@/lib/api";

// ---------------------------------------------------------------------------
// Tab metadata
// ---------------------------------------------------------------------------

type TabKey = "console" | "tasks" | "shadow";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "console",
    label: "Agents Console",
    icon: Bot,
    description: "Dispatch a task to a named AI agent role.",
  },
  {
    key: "tasks",
    label: "Task Queue",
    icon: ListTodo,
    description: "Live view of queued and running agent tasks.",
  },
  {
    key: "shadow",
    label: "Shadow AI",
    icon: EyeOff,
    description: "Unsanctioned LLM and model usage across the org.",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

// ---------------------------------------------------------------------------
// Skeleton helper
// ---------------------------------------------------------------------------

function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={`animate-pulse rounded-md bg-muted/60 ${className ?? ""}`}
    />
  );
}

// ---------------------------------------------------------------------------
// ConsolePanel — POST /api/v1/agents/{role}/task
// ---------------------------------------------------------------------------

const AGENT_ROLES = [
  "security_analyst",
  "pentester",
  "compliance",
  "remediation",
  "general",
  "code_builder",
  "test_writer",
  "doc_generator",
  "security_reviewer",
  "code_reviewer",
] as const;

type AgentRole = (typeof AGENT_ROLES)[number];

function ConsolePanel() {
  const [role, setRole] = useState<AgentRole>("security_analyst");
  const [title, setTitle] = useState("");
  const [prompt, setPrompt] = useState("");
  const [priority, setPriority] = useState<"low" | "normal" | "high">("normal");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AgentTaskDispatch | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleDispatch() {
    if (!title.trim() || !prompt.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await agentTasksApi.dispatch(role, { title, prompt, priority });
      setResult(res.data);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Dispatch failed";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
      {/* Form */}
      <div className="rounded-xl border border-border bg-card p-5 space-y-4">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" />
          Dispatch Agent Task
        </h3>

        {/* Role selector */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Agent Role
          </label>
          <select
            value={role}
            onChange={e => setRole(e.target.value as AgentRole)}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
          >
            {AGENT_ROLES.map(r => (
              <option key={r} value={r}>
                {r.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>

        {/* Title */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Task Title
          </label>
          <input
            type="text"
            value={title}
            onChange={e => setTitle(e.target.value)}
            placeholder="e.g. Scan auth module for OWASP Top 10"
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {/* Prompt */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Prompt / Instructions
          </label>
          <textarea
            rows={4}
            value={prompt}
            onChange={e => setPrompt(e.target.value)}
            placeholder="Describe what the agent should do..."
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
          />
        </div>

        {/* Priority */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            Priority
          </label>
          <div className="flex gap-2">
            {(["low", "normal", "high"] as const).map(p => (
              <button
                key={p}
                onClick={() => setPriority(p)}
                className={`flex-1 rounded-md border px-3 py-1.5 text-xs font-medium capitalize transition-colors ${
                  priority === p
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-background text-muted-foreground hover:border-primary/50"
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>

        <Button
          onClick={handleDispatch}
          disabled={loading || !title.trim() || !prompt.trim()}
          className="w-full gap-2"
        >
          {loading ? (
            <RefreshCw className="h-4 w-4 animate-spin" />
          ) : (
            <Send className="h-4 w-4" />
          )}
          {loading ? "Dispatching…" : "Dispatch Task"}
        </Button>

        {error && (
          <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
            {error}
          </div>
        )}
      </div>

      {/* Result */}
      <div className="rounded-xl border border-border bg-card p-5 space-y-3">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 text-emerald-500" />
          Dispatch Receipt
        </h3>
        {result ? (
          <div className="space-y-2 text-sm">
            <Row label="Task ID" value={result.task_id} mono />
            <Row label="Role" value={result.role} />
            <Row label="Title" value={result.title} />
            <Row label="Priority" value={result.priority} />
            <Row
              label="Status"
              value={
                <Badge variant="secondary" className="text-xs capitalize">
                  {result.status}
                </Badge>
              }
            />
            <Row
              label="Created"
              value={new Date(result.created_at * 1000).toLocaleString()}
            />
            {result.prompt_preview && (
              <div className="rounded-md bg-muted/40 p-3 text-xs text-muted-foreground font-mono">
                {result.prompt_preview}
                {result.prompt_preview.length >= 200 && "…"}
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Dispatch a task to see the receipt here.
          </p>
        )}
      </div>
    </div>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-start gap-2">
      <span className="w-24 shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className={`flex-1 text-xs text-foreground ${mono ? "font-mono" : ""}`}>
        {value}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TasksPanel — GET /api/v1/queue/status + /queue/peek
// ---------------------------------------------------------------------------

function TasksPanel() {
  const [status, setStatus] = useState<QueueStatus | null>(null);
  const [tasks, setTasks] = useState<QueuePeekItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [statusRes, peekRes] = await Promise.all([
        agentTasksApi.queueStatus(),
        agentTasksApi.queuePeek(20),
      ]);
      setStatus(statusRes.data);
      setTasks(peekRes.data.tasks ?? []);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to load queue";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-5">
      {/* Status bar */}
      {loading ? (
        <div className="grid grid-cols-3 gap-4">
          {[0, 1, 2].map(i => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : error ? (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
          {error}
        </div>
      ) : status ? (
        <div className="grid grid-cols-3 gap-4">
          <StatCard
            icon={Activity}
            label="Backend"
            value={status.backend}
            colorClass="text-blue-400"
          />
          <StatCard
            icon={Clock}
            label="Queue Depth"
            value={String(status.depth)}
            colorClass="text-amber-400"
          />
          <StatCard
            icon={Bot}
            label="Workers"
            value={String(status.workers)}
            colorClass="text-emerald-400"
          />
        </div>
      ) : null}

      {/* Task list */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h3 className="text-sm font-semibold text-foreground">Queued Tasks</h3>
          <Button variant="ghost" size="sm" onClick={load} className="gap-1.5 text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
        {loading ? (
          <div className="p-4 space-y-2">
            {[0, 1, 2].map(i => (
              <Skeleton key={i} className="h-10" />
            ))}
          </div>
        ) : tasks.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-12 text-center">
            <CheckCircle2 className="h-8 w-8 text-muted-foreground/40" />
            <p className="text-sm text-muted-foreground">Queue is empty</p>
            <p className="text-xs text-muted-foreground/60">
              Dispatch tasks from the Agents Console tab.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {tasks.map((t, idx) => (
              <div
                key={t.task_id ?? idx}
                className="flex items-center justify-between px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <Clock className="h-4 w-4 text-muted-foreground/60 shrink-0" />
                  <div>
                    <p className="text-xs font-medium text-foreground">
                      {(t.task_type as string) ?? t.task_id ?? `Task ${idx + 1}`}
                    </p>
                    {t.task_id && (
                      <p className="text-xs text-muted-foreground font-mono">
                        {String(t.task_id)}
                      </p>
                    )}
                  </div>
                </div>
                {t.priority !== undefined && (
                  <Badge variant="outline" className="text-xs">
                    P{t.priority}
                  </Badge>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  colorClass,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  colorClass: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${colorClass}`} />
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <p className="text-xl font-bold text-foreground">{value}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ShadowPanel — GET /api/v1/shadow-ai/stats + /registry
// ---------------------------------------------------------------------------

function ShadowPanel() {
  const [stats, setStats] = useState<ShadowAiStats | null>(null);
  const [registry, setRegistry] = useState<ShadowAiService[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, regRes] = await Promise.all([
        shadowAiApi.stats(),
        shadowAiApi.registry(),
      ]);
      setStats(statsRes.data);
      setRegistry(Array.isArray(regRes.data) ? regRes.data : []);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to load shadow AI data";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-5">
      {/* Stats */}
      {loading ? (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {[0, 1, 2, 3].map(i => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
      ) : error ? (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
          {error}
        </div>
      ) : stats ? (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard
              icon={Shield}
              label="Registered"
              value={String(stats.registered_services)}
              colorClass="text-emerald-400"
            />
            <StatCard
              icon={AlertTriangle}
              label="Total Signals"
              value={String(stats.total_signals)}
              colorClass="text-amber-400"
            />
            <StatCard
              icon={EyeOff}
              label="Unregistered"
              value={String(stats.unregistered_count)}
              colorClass="text-red-400"
            />
            <StatCard
              icon={Activity}
              label="Coverage"
              value={`${Math.round(stats.coverage_pct)}%`}
              colorClass="text-blue-400"
            />
          </div>

          {/* Coverage bar */}
          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">AI Service Coverage</span>
              <span className="font-semibold text-foreground">
                {Math.round(stats.coverage_pct)}%
              </span>
            </div>
            <div className="h-2 rounded-full bg-muted/60 overflow-hidden">
              <div
                className="h-full rounded-full bg-emerald-500 transition-all duration-700"
                style={{ width: `${Math.min(100, stats.coverage_pct)}%` }}
              />
            </div>
            {stats.top_providers.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {stats.top_providers.map(p => (
                  <Badge key={p} variant="secondary" className="text-xs">
                    {p}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        </>
      ) : null}

      {/* Registry table */}
      <div className="rounded-xl border border-border bg-card overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h3 className="text-sm font-semibold text-foreground">Approved AI Registry</h3>
          <Button variant="ghost" size="sm" onClick={load} className="gap-1.5 text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
        {loading ? (
          <div className="p-4 space-y-2">
            {[0, 1, 2].map(i => (
              <Skeleton key={i} className="h-10" />
            ))}
          </div>
        ) : registry.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-12 text-center">
            <EyeOff className="h-8 w-8 text-muted-foreground/40" />
            <p className="text-sm text-muted-foreground">No approved AI services registered</p>
            <p className="text-xs text-muted-foreground/60">
              Register sanctioned AI services to track coverage.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Service</th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Provider</th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Classification</th>
                  <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground">Approved By</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {registry.map((svc, idx) => (
                  <tr key={svc.service_name ?? idx} className="hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2.5 text-xs font-medium text-foreground">
                      {svc.service_name}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">
                      {svc.provider || "—"}
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge
                        variant={svc.data_classification === "public" ? "secondary" : "outline"}
                        className="text-xs capitalize"
                      >
                        {svc.data_classification}
                      </Badge>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">
                      {svc.approved_by || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hub root
// ---------------------------------------------------------------------------

export default function AICopilotAgentsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "console";
  const [tab, setTab] = useState<TabKey>(initial);

  // Single effect: sync tab state <-> URL param without object-identity churn.
  // deps use params.toString() (primitive) — avoids infinite replaceState loop.
  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        setTab(urlTab);
      } else {
        const next = new URLSearchParams(params.toString());
        next.set("tab", tab);
        setParams(next, { replace: true });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, params.toString()]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="AI Copilot Agents"
        description="Unified AI-agent workspace — dispatch tasks to agent roles, monitor the queue, and surface shadow LLM usage."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        <TabsContent value="console">
          <ConsolePanel />
        </TabsContent>
        <TabsContent value="tasks">
          <TasksPanel />
        </TabsContent>
        <TabsContent value="shadow">
          <ShadowPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
