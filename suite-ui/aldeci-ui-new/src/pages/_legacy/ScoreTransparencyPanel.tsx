/**
 * Score Transparency Panel — per-finding score breakdown (Wave 3)
 * Route: /score-transparency
 * API:   GET /api/v1/findings/{id}/score-breakdown
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Calculator, RefreshCw, Search, ChevronRight } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface BreakdownFactor {
  name?: string;
  raw_value?: number;
  weight?: number;
  contribution?: number;
  description?: string;
}
interface Breakdown {
  finding_id?: string;
  final_score?: number;
  base_score?: number;
  scoring_model?: string;
  factors?: BreakdownFactor[];
  modifiers?: Array<{ name: string; delta: number }>;
  computed_at?: string;
}

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function scoreColor(s?: number) {
  if (s === undefined) return "text-muted-foreground";
  if (s >= 9) return "text-red-400";
  if (s >= 7) return "text-orange-400";
  if (s >= 4) return "text-yellow-400";
  return "text-green-400";
}

export default function ScoreTransparencyPanel() {
  const [findingId, setFindingId] = useState("");
  const [data, setData] = useState<Breakdown | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async (id: string) => {
    if (!id.trim()) return;
    setErr(null);
    setLoading(true);
    try {
      const r = await apiFetch<Breakdown>(`/api/v1/findings/${encodeURIComponent(id.trim())}/score-breakdown`);
      setData(r);
      if (!r) setErr("Score breakdown not available for that finding (404).");
    } catch (e) {
      setErr((e as Error).message);
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Optionally seed from URL hash
    const hash = window.location.hash.match(/finding=([^&]+)/);
    if (hash) {
      setFindingId(hash[1]);
      load(hash[1]);
    }
  }, []);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Score Transparency"
        description="Inspect exactly how a finding's risk score was computed — every factor, weight, and modifier"
        actions={
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
              <Input
                value={findingId}
                onChange={(e) => setFindingId(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && load(findingId)}
                placeholder="Finding ID…"
                className="h-8 w-[260px] pl-7 text-xs font-mono"
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => load(findingId)} disabled={loading || !findingId.trim()}>
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Calculator className="h-4 w-4" /> Final Score
            </CardTitle>
            <CardDescription className="text-xs">{data?.scoring_model ?? "—"}</CardDescription>
          </CardHeader>
          <CardContent>
            {!data ? (
              <EmptyState icon={Calculator} title="Pick a finding" description="Enter a finding ID above to see its score breakdown." />
            ) : (
              <div className="space-y-3">
                <div className="flex items-baseline gap-3">
                  <span className={cn("text-5xl font-bold tabular-nums", scoreColor(data.final_score))}>
                    {data.final_score?.toFixed(1) ?? "—"}
                  </span>
                  <span className="text-sm text-muted-foreground">/ 10</span>
                </div>
                <Progress value={(data.final_score ?? 0) * 10} className="h-2" />
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Base score</span>
                  <span className="font-mono">{data.base_score?.toFixed(2) ?? "—"}</span>
                </div>
                {data.computed_at && (
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Computed at</span>
                    <span className="font-mono">{data.computed_at}</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="xl:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Factor Contributions</CardTitle>
            <CardDescription className="text-xs">Each factor's raw value × weight = contribution</CardDescription>
          </CardHeader>
          <CardContent>
            {err ? (
              <ErrorState message={err} onRetry={() => load(findingId)} />
            ) : !data ? (
              <p className="text-sm text-muted-foreground">No data.</p>
            ) : !data.factors || data.factors.length === 0 ? (
              <EmptyState icon={Calculator} title="No factor breakdown" description="The scoring engine returned no factor decomposition for this finding." />
            ) : (
              <div className="space-y-2">
                {data.factors.map((f, i) => (
                  <div key={(f.name ?? "f") + i} className="rounded-md border border-border/50 p-3 bg-muted/20">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold">{f.name ?? "(unnamed)"}</span>
                      <Badge className="text-[10px] border border-border font-mono">+{f.contribution?.toFixed(2) ?? "0"}</Badge>
                    </div>
                    {f.description && <p className="text-[11px] text-muted-foreground mt-1">{f.description}</p>}
                    <div className="mt-2 grid grid-cols-3 gap-2 text-[11px] font-mono">
                      <div className="text-muted-foreground">raw <span className="text-foreground">{f.raw_value?.toFixed(3) ?? "—"}</span></div>
                      <div className="text-muted-foreground">× weight <span className="text-foreground">{f.weight?.toFixed(2) ?? "—"}</span></div>
                      <div className="text-muted-foreground text-right">= <span className="text-foreground">{f.contribution?.toFixed(2) ?? "—"}</span></div>
                    </div>
                  </div>
                ))}
                {data.modifiers && data.modifiers.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-border/30">
                    <p className="text-[11px] uppercase tracking-wider text-muted-foreground mb-2">Modifiers</p>
                    <ul className="space-y-1">
                      {data.modifiers.map((m, i) => (
                        <li key={m.name + i} className="flex items-center justify-between text-xs">
                          <span className="flex items-center gap-2">
                            <ChevronRight className="h-3 w-3 text-muted-foreground" /> {m.name}
                          </span>
                          <span className={cn("font-mono", m.delta > 0 ? "text-red-400" : "text-green-400")}>
                            {m.delta > 0 ? "+" : ""}{m.delta.toFixed(2)}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
