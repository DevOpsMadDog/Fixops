/**
 * LLM Context Tier Badge — preview which tier a rule belongs to
 * Route: /llm/context-tier
 * API: GET /api/v1/llm/rules/{key}/context-requirement
 * Multica id: c5fb4d22
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Layers, Search } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface CtxResp {
  key?: string;
  context_tier?: string;
  required_context?: string[];
  optional_context?: string[];
  estimated_tokens?: number;
  detail?: string;
}

const TIER_COLOR: Record<string, string> = {
  small: "border-green-500/30 text-green-400 bg-green-500/10",
  medium: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  large: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  xl: "border-red-500/30 text-red-400 bg-red-500/10",
};

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 501) return { detail: "Coming soon" } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function LLMContextTierBadge() {
  const [key, setKey] = useState("");
  const [resp, setResp] = useState<CtxResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!key.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<CtxResp>(`/api/v1/llm/rules/${encodeURIComponent(key)}/context-requirement`);
      setResp(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!resp?.detail;
  const tier = resp?.context_tier ?? "unknown";

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="LLM Context Tier"
        description="See which context tier a rule needs — small/medium/large/xl — to route to the right model"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Layers className="h-4 w-4" /> Inspect Rule</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/llm/rules/{`{key}`}/context-requirement</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Rule Key</Label>
              <Input value={key} onChange={e => setKey(e.target.value)} placeholder="iac.s3-public-bucket" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading || !key.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Inspect</Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={Layers} title="Coming soon" description="Endpoint returns 501." />}

          {!err && !isComingSoon && resp && (
            <div className="rounded-md border p-4 space-y-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">Tier:</span>
                <Badge className={`text-[11px] border ${TIER_COLOR[tier] ?? "border-muted text-muted-foreground"}`}>{tier}</Badge>
                <span className="text-muted-foreground ml-auto">~{resp.estimated_tokens ?? 0} tokens</span>
              </div>
              {(resp.required_context ?? []).length > 0 && (
                <div>
                  <div className="text-muted-foreground mb-1">Required context</div>
                  <div className="flex flex-wrap gap-1">{(resp.required_context ?? []).map(c => <Badge key={c} className="text-[10px]">{c}</Badge>)}</div>
                </div>
              )}
              {(resp.optional_context ?? []).length > 0 && (
                <div>
                  <div className="text-muted-foreground mb-1">Optional context</div>
                  <div className="flex flex-wrap gap-1">{(resp.optional_context ?? []).map(c => <Badge key={c} variant="secondary" className="text-[10px]">{c}</Badge>)}</div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
