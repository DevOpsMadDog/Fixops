/**
 * Copilot
 *
 * Plain-language graph queries against the security knowledge graph.
 * Route: /ai/copilot
 * API: POST /api/v1/copilot/graph-nl-query
 * Multica id: fac7d8eb-d39c-42d2-8a1f-e2487f7cb91e
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Sparkles, Send, RotateCw } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface CopilotResponse {
  q_id?: string;
  answer?: string;
  cypher?: string;
  rows?: Array<Record<string, unknown>>;
  duration_ms?: number;
  source?: string;
  comingSoon?: boolean;
}

const SAMPLES = [
  "Which assets have critical CVEs and are reachable from the internet?",
  "Show me all services using log4j 2.14.x",
  "Which findings touch PII and have no remediation owner?",
  "List the top 10 choke points by blast radius",
];

async function postJson<T>(path: string, body: Record<string, unknown>): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
    body: JSON.stringify({ org_id: orgId, ...body }),
  });
  if (res.status === 501 || res.status === 404) return { data: { comingSoon: true } as T, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

export default function Copilot() {
  const [query, setQuery] = useState("");
  const [response, setResponse] = useState<CopilotResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const ask = async (q?: string) => {
    const text = (q ?? query).trim();
    if (!text) return;
    setQuery(text);
    setErr(null);
    setLoading(true);
    setResponse(null);
    try {
      const { data } = await postJson<CopilotResponse>("/api/v1/copilot/graph-nl-query", { query: text });
      setResponse(data);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const rows = response?.rows ?? [];
  const cols = rows.length > 0 ? Object.keys(rows[0]) : [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Copilot"
        description="Ask questions about your security graph in plain language"
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Sparkles className="h-4 w-4" /> Ask</CardTitle>
          <CardDescription className="text-xs">Type a question or pick a sample below</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="e.g. Which assets have critical CVEs and are exposed to the internet?"
            className="min-h-24 text-xs"
          />
          <div className="flex flex-wrap gap-1.5">
            {SAMPLES.map((s) => (
              <button
                key={s}
                onClick={() => ask(s)}
                className="px-2 py-1 rounded border border-border text-[10px] text-muted-foreground hover:bg-muted/30 hover:text-foreground"
              >
                {s}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={() => ask()} disabled={loading || !query.trim()}>
              <Send className={cn("h-4 w-4 mr-1.5", loading && "animate-pulse")} /> {loading ? "Thinking…" : "Ask"}
            </Button>
            <Button size="sm" variant="outline" onClick={() => { setQuery(""); setResponse(null); setErr(null); }}>
              <RotateCw className="h-4 w-4 mr-1.5" /> Clear
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Answer</CardTitle>
          <CardDescription className="text-xs">{response?.q_id ? `q_id: ${response.q_id}` : "Result of the most recent query"}</CardDescription>
        </CardHeader>
        <CardContent>
          {err ? (
            <ErrorState message={err} onRetry={() => ask()} />
          ) : response?.comingSoon ? (
            <EmptyState icon={Sparkles} title="Coming soon" description="POST /api/v1/copilot/graph-nl-query is not enabled on this deployment." />
          ) : !response ? (
            <EmptyState icon={Sparkles} title="No question yet" description="Ask a question to see the copilot answer here." />
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2 text-[11px]">
                {response.duration_ms != null && <Badge className="text-[10px] border border-border">{response.duration_ms} ms</Badge>}
                {response.source && <Badge className="text-[10px] border border-border">source: {response.source}</Badge>}
              </div>
              {response.answer && <p className="text-sm leading-relaxed whitespace-pre-wrap">{response.answer}</p>}
              {response.cypher && (
                <div>
                  <div className="text-[11px] text-muted-foreground mb-1">Cypher</div>
                  <pre className="text-[11px] font-mono bg-muted/30 rounded-md p-3 overflow-x-auto">{response.cypher}</pre>
                </div>
              )}
              {rows.length > 0 && (
                <div>
                  <div className="text-[11px] text-muted-foreground mb-1">Rows ({rows.length})</div>
                  <div className="overflow-x-auto border border-border rounded-md">
                    <table className="w-full text-[11px]">
                      <thead className="bg-muted/30">
                        <tr>{cols.map((c) => <th key={c} className="px-3 py-1.5 text-left font-mono">{c}</th>)}</tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {rows.slice(0, 100).map((r, i) => (
                          <tr key={i} className="hover:bg-muted/30">
                            {cols.map((c) => <td key={c} className="px-3 py-1.5 font-mono text-muted-foreground">{String(r[c] ?? "—")}</td>)}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
