/**
 * LLM Pre-Flight Estimate
 * Route: /llm/estimate
 * API: POST /api/v1/llm/estimate
 * Multica id: 2ad6e909
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Calculator, Send, DollarSign, Cpu } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface Estimate {
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  estimated_cost_usd?: number;
  estimated_latency_ms?: number;
  routed_provider?: string;
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

export default function LLMPreFlightEstimateModal() {
  const [prompt, setPrompt] = useState("");
  const [model, setModel] = useState("auto");
  const [maxTokens, setMaxTokens] = useState("1024");
  const [resp, setResp] = useState<Estimate | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!prompt.trim()) return;
    setLoading(true);
    setErr(null);
    setResp(null);
    try {
      const r = await apiPost<Estimate>("/api/v1/llm/estimate", {
        prompt,
        model,
        max_output_tokens: parseInt(maxTokens, 10) || 1024,
      });
      setResp(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!resp?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="LLM Pre-Flight Estimate"
        description="Cost + latency forecast before dispatching a prompt — routed via cheapest viable provider"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Calculator className="h-4 w-4" /> Estimate</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/llm/estimate</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-xs">Prompt Preview</Label>
            <Textarea rows={5} value={prompt} onChange={e => setPrompt(e.target.value)} placeholder="Paste prompt content here…" className="text-sm" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs">Model</Label>
              <Input value={model} onChange={e => setModel(e.target.value)} className="text-sm font-mono" />
            </div>
            <div>
              <Label className="text-xs">Max Output Tokens</Label>
              <Input value={maxTokens} onChange={e => setMaxTokens(e.target.value)} type="number" className="text-sm font-mono" />
            </div>
          </div>
          <Button onClick={submit} disabled={loading || !prompt.trim()} size="sm">
            <Send className="h-4 w-4 mr-2" /> {loading ? "Estimating…" : "Estimate"}
          </Button>

          {err && <ErrorState message={err} onRetry={submit} />}
          {isComingSoon && <EmptyState icon={Calculator} title="Coming soon" description="Endpoint returns 501." />}

          {!err && !isComingSoon && resp && (
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <KpiCard title="Input Tokens" value={resp.input_tokens ?? 0} icon={Cpu} />
              <KpiCard title="Output Tokens" value={resp.output_tokens ?? 0} icon={Cpu} />
              <KpiCard title="Cost" value={`$${(resp.estimated_cost_usd ?? 0).toFixed(4)}`} icon={DollarSign} />
              <KpiCard title="Latency" value={`${resp.estimated_latency_ms ?? 0}ms`} icon={Cpu} />
              <div className="col-span-2 lg:col-span-4 text-xs text-muted-foreground flex items-center gap-2">
                Routed via <Badge className="text-[10px]">{resp.routed_provider ?? resp.model ?? "auto"}</Badge>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
