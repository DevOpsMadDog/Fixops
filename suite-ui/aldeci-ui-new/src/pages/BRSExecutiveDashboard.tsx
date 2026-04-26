/**
 * BRS Executive Dashboard — Business Risk Score per Business Unit (Wave 3)
 * Route: /brs-executive
 * API:   GET /api/v1/risk/brs/bu/{bu_id}
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Building2, RefreshCw, TrendingDown, TrendingUp, DollarSign, Target } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface BRSResponse {
  bu_id?: string;
  bu_name?: string;
  brs_score?: number;
  trend?: "up" | "down" | "flat";
  trend_pct?: number;
  dollar_exposure?: number;
  open_findings?: number;
  critical_findings?: number;
  components?: Array<{ name: string; score?: number; weight?: number }>;
  history?: Array<{ ts: string; score: number }>;
}

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function fmtMoney(n?: number) {
  if (n === undefined || n === null) return "—";
  if (n >= 1e9) return `$${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(1)}K`;
  return `$${n.toFixed(0)}`;
}

function scoreColor(s?: number) {
  if (s === undefined) return "text-muted-foreground";
  if (s >= 80) return "text-red-400";
  if (s >= 60) return "text-orange-400";
  if (s >= 40) return "text-yellow-400";
  return "text-green-400";
}

export default function BRSExecutiveDashboard() {
  const [buId, setBuId] = useState("default");
  const [data, setData] = useState<BRSResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<BRSResponse>(`/api/v1/risk/brs/bu/${encodeURIComponent(buId)}`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const score = data?.brs_score;
  const trendIcon = data?.trend === "up" ? TrendingUp : data?.trend === "down" ? TrendingDown : null;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Business Risk Score (BRS) — Executive"
        description="Quantified business risk per business unit, with dollar-loss exposure and trend analysis"
        actions={
          <div className="flex items-center gap-2">
            <Input
              value={buId}
              onChange={(e) => setBuId(e.target.value)}
              placeholder="Business Unit ID"
              className="h-8 w-[180px] text-xs"
            />
            <Button variant="outline" size="sm" onClick={load} disabled={refreshing || !buId.trim()}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="BRS Score" value={score ?? "—"} icon={Target} />
        <KpiCard title="Dollar Exposure" value={fmtMoney(data?.dollar_exposure)} icon={DollarSign} />
        <KpiCard title="Open Findings" value={data?.open_findings ?? 0} icon={Building2} />
        <KpiCard title="Critical" value={data?.critical_findings ?? 0} icon={Building2} trend="down" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Target className="h-4 w-4" /> Risk Score Composition
            </CardTitle>
            <CardDescription className="text-xs">
              {data?.bu_name ? `Business Unit: ${data.bu_name}` : `BU ID: ${buId}`}
              {trendIcon && data?.trend_pct !== undefined && (
                <span className={cn("ml-2 inline-flex items-center gap-1 text-xs", data.trend === "down" ? "text-green-400" : "text-red-400")}>
                  {data.trend === "up" ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
                  {Math.abs(data.trend_pct).toFixed(1)}%
                </span>
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="p-6 text-sm text-muted-foreground">Loading…</div>
            ) : err ? (
              <ErrorState message={err} onRetry={load} />
            ) : !data ? (
              <EmptyState
                icon={Building2}
                title="No BRS data yet"
                description={`No business-risk score available for BU "${buId}". Trigger a risk recompute or pick a different BU.`}
              />
            ) : (
              <div className="flex flex-col gap-4">
                <div className="flex items-baseline gap-3">
                  <span className={cn("text-5xl font-bold tabular-nums", scoreColor(score))}>
                    {score?.toFixed(0) ?? "—"}
                  </span>
                  <span className="text-sm text-muted-foreground">/ 100</span>
                </div>
                <Progress value={score ?? 0} className="h-2" />
                <div className="space-y-2">
                  {(data.components ?? []).map((c, i) => (
                    <div key={c.name + i} className="flex items-center justify-between gap-3">
                      <span className="text-xs text-muted-foreground">{c.name}</span>
                      <div className="flex items-center gap-2">
                        <Progress value={c.score ?? 0} className="h-1 w-32" />
                        <span className="text-xs font-mono w-10 text-right">{c.score?.toFixed(0) ?? "—"}</span>
                        {c.weight !== undefined && (
                          <Badge className="text-[10px] border border-border">×{c.weight.toFixed(2)}</Badge>
                        )}
                      </div>
                    </div>
                  ))}
                  {(!data.components || data.components.length === 0) && (
                    <p className="text-xs text-muted-foreground">No component breakdown returned.</p>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Score History</CardTitle>
            <CardDescription className="text-xs">Last {data?.history?.length ?? 0} snapshots</CardDescription>
          </CardHeader>
          <CardContent>
            {!data?.history || data.history.length === 0 ? (
              <EmptyState icon={TrendingDown} title="No history" description="Score history will appear after subsequent re-evaluations." />
            ) : (
              <div className="space-y-1">
                {data.history.slice(-10).reverse().map((h, i) => (
                  <div key={h.ts + i} className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground font-mono">{h.ts.slice(0, 10)}</span>
                    <span className={cn("font-mono", scoreColor(h.score))}>{h.score.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
