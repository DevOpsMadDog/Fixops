// FOLDED into AICopilotAgentsHub hero (console tab) 2026-05-02 — preserve for git history
/**
 * AI Agents Console
 *
 * Send a one-off task to a named AI agent role.
 * Route: /ai/agents-console
 * API: POST /api/v1/agents/{role}/task
 * Multica id: 8fa90b91-0400-4568-8a46-c69efd233f9f
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Bot, Send, RotateCw } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface TaskResponse {
  task_id?: string;
  status?: string;
  result?: unknown;
  output?: string;
  agent?: string;
  duration_ms?: number;
  error?: string;
  comingSoon?: boolean;
}

const ROLES = [
  "code-builder",
  "test-writer",
  "doc-generator",
  "security-reviewer",
  "code-reviewer",
  "researcher",
  "analyst",
];

async function postJson<T>(path: string, body: Record<string, unknown>): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
    body: JSON.stringify({ org_id: orgId, ...body }),
  });
  if (res.status === 501) return { data: { comingSoon: true } as T, status: 501 };
  if (res.status === 404) return { data: { comingSoon: true } as T, status: 404 };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

export default function AIAgentsConsole() {
  const [role, setRole] = useState(ROLES[0]);
  const [title, setTitle] = useState("");
  const [prompt, setPrompt] = useState("");
  const [response, setResponse] = useState<TaskResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!prompt.trim()) return;
    setErr(null);
    setLoading(true);
    setResponse(null);
    try {
      const { data } = await postJson<TaskResponse>(`/api/v1/agents/${encodeURIComponent(role)}/task`, {
        title: title.trim() || undefined,
        prompt: prompt.trim(),
      });
      setResponse(data);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setTitle("");
    setPrompt("");
    setResponse(null);
    setErr(null);
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="AI Agents Console"
        description="Send a task to a named agent role and inspect the response"
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Bot className="h-4 w-4" /> Compose Task</CardTitle>
          <CardDescription className="text-xs">Pick an agent role and describe the task</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-2 md:grid-cols-2">
            <div>
              <label className="text-[11px] text-muted-foreground">Agent role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="mt-1 w-full h-9 px-3 rounded-md border border-border bg-background text-xs"
              >
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-muted-foreground">Title (optional)</label>
              <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="short task title" className="mt-1 h-9 text-xs" />
            </div>
          </div>
          <div>
            <label className="text-[11px] text-muted-foreground">Prompt</label>
            <Textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Describe what the agent should do…" className="mt-1 min-h-32 text-xs font-mono" />
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={submit} disabled={loading || !prompt.trim()}>
              <Send className={cn("h-4 w-4 mr-1.5", loading && "animate-pulse")} /> {loading ? "Dispatching…" : "Dispatch"}
            </Button>
            <Button size="sm" variant="outline" onClick={reset}>
              <RotateCw className="h-4 w-4 mr-1.5" /> Reset
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Response</CardTitle>
          <CardDescription className="text-xs">Synchronous result, status, and timing</CardDescription>
        </CardHeader>
        <CardContent>
          {err ? (
            <ErrorState message={err} onRetry={submit} />
          ) : response?.comingSoon ? (
            <EmptyState icon={Bot} title="Coming soon" description={`POST /api/v1/agents/${role}/task is not enabled on this deployment.`} />
          ) : !response ? (
            <EmptyState icon={Send} title="No response yet" description="Submit a task to see the agent response here." />
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2 text-[11px]">
                <Badge className="text-[10px] border border-border">role: {role}</Badge>
                {response.agent && <Badge className="text-[10px] border border-border">agent: {response.agent}</Badge>}
                {response.status && <Badge className="text-[10px] border border-border capitalize">status: {response.status}</Badge>}
                {response.task_id && <Badge className="text-[10px] border border-border">task: {response.task_id}</Badge>}
                {response.duration_ms != null && <Badge className="text-[10px] border border-border">{response.duration_ms} ms</Badge>}
              </div>
              {response.output && (
                <pre className="text-[11px] font-mono bg-muted/30 rounded-md p-3 overflow-x-auto whitespace-pre-wrap">{response.output}</pre>
              )}
              {response.result != null && (
                <pre className="text-[11px] font-mono bg-muted/30 rounded-md p-3 overflow-x-auto">{JSON.stringify(response.result, null, 2)}</pre>
              )}
              {response.error && <p className="text-[11px] text-red-400">{response.error}</p>}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
