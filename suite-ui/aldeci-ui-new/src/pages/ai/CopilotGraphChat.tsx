/**
 * Copilot Graph Chat
 *
 * Multi-turn chat-style copilot with persistent history.
 * Route: /ai/copilot-chat
 * API: POST /api/v1/copilot/graph-nl-query
 * Multica id: bfe2fb45-233a-40d3-8e42-bc725b73626a
 */

import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { MessageSquare, Send, Trash2 } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ChatTurn {
  id: string;
  role: "user" | "assistant";
  text: string;
  q_id?: string;
  cypher?: string;
  duration_ms?: number;
  ts: number;
  comingSoon?: boolean;
}

async function postJson(path: string, body: Record<string, unknown>): Promise<{ data: any; status: number }> {
  const orgId = getStoredOrgId();
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
    body: JSON.stringify({ org_id: orgId, ...body }),
  });
  if (res.status === 501 || res.status === 404) return { data: { comingSoon: true }, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: await res.json(), status: res.status };
}

export default function CopilotGraphChat() {
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [turns.length]);

  const send = async () => {
    if (!input.trim()) return;
    const userTurn: ChatTurn = { id: `u-${Date.now()}`, role: "user", text: input.trim(), ts: Date.now() };
    setTurns((t) => [...t, userTurn]);
    setInput("");
    setErr(null);
    setLoading(true);
    try {
      const { data } = await postJson("/api/v1/copilot/graph-nl-query", {
        query: userTurn.text,
        history: turns.map((t) => ({ role: t.role, text: t.text })),
      });
      const assistantTurn: ChatTurn = {
        id: `a-${Date.now()}`,
        role: "assistant",
        text: data.comingSoon ? "Coming soon — copilot endpoint not enabled on this deployment." : (data.answer ?? data.text ?? JSON.stringify(data)),
        q_id: data.q_id,
        cypher: data.cypher,
        duration_ms: data.duration_ms,
        ts: Date.now(),
        comingSoon: data.comingSoon,
      };
      setTurns((t) => [...t, assistantTurn]);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Copilot Graph Chat"
        description="Multi-turn conversations against the security knowledge graph"
        actions={
          <Button variant="outline" size="sm" onClick={() => setTurns([])} disabled={turns.length === 0}>
            <Trash2 className="h-4 w-4" />
          </Button>
        }
      />

      <Card className="flex flex-col h-[640px]">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><MessageSquare className="h-4 w-4" /> Conversation</CardTitle>
          <CardDescription className="text-xs">Persisted in this session only</CardDescription>
        </CardHeader>
        <CardContent ref={scrollRef} className="flex-1 overflow-y-auto space-y-3 px-4">
          {err && <ErrorState message={err} onRetry={send} />}
          {turns.length === 0 && !err ? (
            <EmptyState icon={MessageSquare} title="Start chatting" description="Ask a security question to begin the conversation." />
          ) : (
            turns.map((t) => (
              <div key={t.id} className={cn("flex", t.role === "user" ? "justify-end" : "justify-start")}>
                <div
                  className={cn(
                    "max-w-2xl rounded-lg px-3 py-2 text-[12px]",
                    t.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted/50",
                  )}
                >
                  <p className="whitespace-pre-wrap">{t.text}</p>
                  {t.cypher && (
                    <pre className="mt-2 text-[10px] font-mono bg-background/40 rounded p-2 overflow-x-auto">{t.cypher}</pre>
                  )}
                  <div className="mt-1 flex items-center gap-1.5 opacity-70 text-[10px]">
                    {t.duration_ms != null && <span>{t.duration_ms}ms</span>}
                    {t.q_id && <span>· q:{t.q_id}</span>}
                    {t.comingSoon && <Badge className="text-[9px] border border-amber-500/30 text-amber-400 bg-amber-500/10">coming soon</Badge>}
                  </div>
                </div>
              </div>
            ))
          )}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-muted/50 rounded-lg px-3 py-2 text-[11px] text-muted-foreground animate-pulse">
                Copilot is thinking…
              </div>
            </div>
          )}
        </CardContent>
        <div className="p-3 border-t border-border flex items-center gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask the copilot…"
            className="h-9 text-xs flex-1"
            onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && send()}
          />
          <Button size="sm" onClick={send} disabled={loading || !input.trim()}>
            <Send className={cn("h-4 w-4", loading && "animate-pulse")} />
          </Button>
        </div>
      </Card>
    </motion.div>
  );
}
