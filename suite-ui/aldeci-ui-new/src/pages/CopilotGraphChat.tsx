/**
 * Copilot Graph Chat — natural-language graph queries
 * Route: /copilot/graph-chat
 * API: POST /api/v1/copilot/graph-nl-query
 * Multica id: 1c2762d4
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { MessageSquare, Send, Sparkles } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface ChatTurn {
  role: "user" | "assistant";
  text: string;
  q_id?: string;
  cypher?: string;
  rows?: Record<string, unknown>[];
  detail?: string;
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (res.status === 501) return { detail: "Coming soon" } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function CopilotGraphChat() {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const ask = async () => {
    if (!question.trim()) return;
    const userTurn: ChatTurn = { role: "user", text: question };
    setTurns(t => [...t, userTurn]);
    setLoading(true);
    setErr(null);
    try {
      const r = await apiPost<{ q_id?: string; cypher?: string; rows?: Record<string, unknown>[]; answer?: string; detail?: string }>(
        "/api/v1/copilot/graph-nl-query",
        { query: question, org_id: getStoredOrgId() }
      );
      const aiTurn: ChatTurn = {
        role: "assistant",
        text: r.answer ?? r.detail ?? "(no answer returned)",
        q_id: r.q_id,
        cypher: r.cypher,
        rows: r.rows,
        detail: r.detail,
      };
      setTurns(t => [...t, aiTurn]);
      setQuestion("");
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
        description="Ask questions about your security graph in plain English; get back Cypher + rows"
      />

      <Card className="min-h-[280px]">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><MessageSquare className="h-4 w-4" /> Conversation</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/copilot/graph-nl-query</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {turns.length === 0 ? (
            <div className="text-xs text-muted-foreground py-8 text-center">Ask anything — try "Show services that connect to RDS and have public ingress"</div>
          ) : (
            <div className="space-y-2 max-h-[400px] overflow-auto">
              {turns.map((t, i) => (
                <div key={i} className={`rounded-md border p-3 text-xs ${t.role === "user" ? "bg-primary/5 border-primary/20" : "bg-muted/30"}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <Badge className="text-[9px]">{t.role}</Badge>
                    {t.q_id && <span className="font-mono text-[10px] text-muted-foreground">{t.q_id}</span>}
                    {t.detail && <Badge variant="secondary" className="text-[9px]">501</Badge>}
                  </div>
                  <div className="whitespace-pre-wrap">{t.text}</div>
                  {t.cypher && (
                    <pre className="mt-2 rounded bg-background p-2 text-[10px] overflow-x-auto"><code>{t.cypher}</code></pre>
                  )}
                  {t.rows && t.rows.length > 0 && (
                    <div className="mt-2 text-[10px] text-muted-foreground">{t.rows.length} row(s)</div>
                  )}
                </div>
              ))}
            </div>
          )}

          {err && <ErrorState message={err} />}

          <div className="space-y-2">
            <Label className="text-xs flex items-center gap-2"><Sparkles className="h-3 w-3" /> Question</Label>
            <Textarea rows={3} value={question} onChange={e => setQuestion(e.target.value)} placeholder="What services have public S3 buckets?" className="text-sm" />
            <Button onClick={ask} disabled={loading || !question.trim()} size="sm">
              <Send className="h-4 w-4 mr-2" /> {loading ? "Thinking…" : "Ask"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
