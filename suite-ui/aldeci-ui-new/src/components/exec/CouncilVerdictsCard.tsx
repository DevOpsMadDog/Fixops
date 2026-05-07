/**
 * CouncilVerdictsCard — last N LLM Council verdicts table
 *
 * Calls:
 *   GET /api/v1/llm/council/recent?limit=10  (primary)
 *   GET /api/v1/llm/council/status           (fallback — shows aggregate stats only)
 *
 * Displays: timestamp/ordinal, finding_id, action badge, confidence bar,
 * escalated_to_opus flag, per-model vote chips.
 *
 * ~150 LOC. No mocks. Real EmptyState when history is empty.
 */

import { useEffect, useState, useCallback } from "react";
import { Brain, RefreshCw, AlertTriangle, ChevronRight, Zap } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

interface MemberVote {
  member: string;
  action: string;
  confidence: number;
  weight: number;
}

interface CouncilVerdict {
  timestamp: string | null;
  finding_id: string | null;
  action: string;
  confidence: number;
  escalated_to_opus: boolean;
  escalation_reason: string | null;
  member_votes: MemberVote[];
  latency_ms: number;
  cost_usd: number;
  mitre_mappings: string[];
}

interface RecentResponse {
  verdicts: CouncilVerdict[];
  total: number;
  limit: number;
  error?: string;
}

interface StatusResponse {
  member_count: number;
  consensus_enabled: boolean;
  recent_verdict?: {
    total_verdicts: number;
    average_confidence?: number;
    action_distribution?: Record<string, number>;
  };
  warning?: string;
}

// ─── API helper ───────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(buildApiUrl(path), {
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
        "Content-Type": "application/json",
      },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

// ─── Action badge styling ─────────────────────────────────────────────────────

function actionBadgeClass(action: string) {
  const a = action.toLowerCase();
  if (a.includes("critical")) return "bg-red-500/15 text-red-400 border-red-500/30";
  if (a.includes("high")) return "bg-orange-500/15 text-orange-400 border-orange-500/30";
  if (a.includes("accept")) return "bg-green-500/15 text-green-400 border-green-500/30";
  if (a.includes("false")) return "bg-blue-500/15 text-blue-400 border-blue-500/30";
  if (a.includes("defer")) return "bg-slate-500/15 text-slate-400 border-slate-500/30";
  return "bg-violet-500/15 text-violet-400 border-violet-500/30";
}

function actionLabel(action: string) {
  return action.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function confidenceColor(c: number) {
  if (c >= 0.8) return "bg-green-500";
  if (c >= 0.6) return "bg-yellow-500";
  return "bg-red-500";
}

// ─── Row component ────────────────────────────────────────────────────────────

function VerdictRow({ verdict, index }: { verdict: CouncilVerdict; index: number }) {
  const pct = Math.round(verdict.confidence * 100);
  return (
    <div className="grid grid-cols-[1.5rem_1fr_auto] gap-3 py-3 border-b border-border last:border-0 items-start">
      {/* Index */}
      <span className="text-[11px] font-mono text-muted-foreground pt-0.5">#{index + 1}</span>

      {/* Middle — action + confidence + votes */}
      <div className="min-w-0 space-y-1.5">
        <div className="flex items-center gap-2 flex-wrap">
          <Badge className={cn("text-[10px] border font-semibold", actionBadgeClass(verdict.action))}>
            {actionLabel(verdict.action)}
          </Badge>
          {verdict.escalated_to_opus && (
            <Badge className="text-[10px] border bg-amber-500/15 text-amber-400 border-amber-500/30 font-semibold gap-1">
              <Zap className="h-2.5 w-2.5" />
              Opus
            </Badge>
          )}
          {verdict.mitre_mappings.length > 0 && (
            <span className="text-[10px] text-muted-foreground font-mono">
              {verdict.mitre_mappings[0]}
              {verdict.mitre_mappings.length > 1 && ` +${verdict.mitre_mappings.length - 1}`}
            </span>
          )}
        </div>

        {/* Confidence bar */}
        <div className="flex items-center gap-2">
          <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden max-w-[120px]">
            <div
              className={cn("h-full rounded-full transition-all", confidenceColor(verdict.confidence))}
              style={{ width: `${pct}%` }}
            />
          </div>
          <span className="text-[11px] font-mono text-muted-foreground tabular-nums">{pct}%</span>
        </div>

        {/* Per-model vote chips */}
        {verdict.member_votes.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-0.5">
            {verdict.member_votes.map((mv, i) => (
              <span
                key={mv.member + i}
                className={cn(
                  "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono border",
                  actionBadgeClass(mv.action)
                )}
                title={`${mv.member}: ${actionLabel(mv.action)} (${Math.round(mv.confidence * 100)}% conf, w=${mv.weight.toFixed(2)})`}
              >
                <span className="font-semibold truncate max-w-[60px]">{mv.member.split("-")[0]}</span>
                <span className="opacity-70">{Math.round(mv.confidence * 100)}%</span>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Right — latency */}
      <span className="text-[10px] font-mono text-muted-foreground pt-0.5 tabular-nums whitespace-nowrap">
        {verdict.latency_ms > 0 ? `${(verdict.latency_ms / 1000).toFixed(1)}s` : "—"}
      </span>
    </div>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────

export function CouncilVerdictsCard() {
  const [verdicts, setVerdicts] = useState<CouncilVerdict[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);

    const [recent, st] = await Promise.all([
      apiFetch<RecentResponse>("/api/v1/llm/council/recent?limit=10"),
      apiFetch<StatusResponse>("/api/v1/llm/council/status"),
    ]);

    if (recent) {
      setVerdicts(recent.verdicts ?? []);
      setTotal(recent.total ?? 0);
    }
    setStatus(st);
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-violet-400" />
            <CardTitle className="text-sm font-semibold">LLM Council Verdicts</CardTitle>
            {status && (
              <Badge className={cn(
                "text-[10px] border font-semibold",
                status.consensus_enabled
                  ? "bg-green-500/15 text-green-400 border-green-500/30"
                  : "bg-amber-500/15 text-amber-400 border-amber-500/30"
              )}>
                {status.member_count} model{status.member_count !== 1 ? "s" : ""}
                {status.consensus_enabled ? " · consensus" : " · no consensus"}
              </Badge>
            )}
          </div>
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => load(true)} disabled={refreshing}>
            <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
          </Button>
        </div>
        <CardDescription className="text-xs">
          Last {verdicts.length > 0 ? verdicts.length : "10"} verdicts — action, confidence,
          per-model votes, Opus escalation
          {total !== null && total > 0 && (
            <span className="text-muted-foreground"> · {total} total in session</span>
          )}
        </CardDescription>
        {status?.warning && (
          <div className="flex items-start gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 mt-1">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-px" />
            <p className="text-[11px] text-amber-300 leading-relaxed">{status.warning}</p>
          </div>
        )}
      </CardHeader>

      <CardContent>
        {loading ? (
          <div className="space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="space-y-2 py-3 border-b border-border last:border-0">
                <div className="flex gap-2">
                  <Skeleton className="h-4 w-28" />
                  <Skeleton className="h-4 w-16" />
                </div>
                <Skeleton className="h-1.5 w-32" />
                <div className="flex gap-1">
                  <Skeleton className="h-4 w-16" />
                  <Skeleton className="h-4 w-16" />
                  <Skeleton className="h-4 w-16" />
                </div>
              </div>
            ))}
          </div>
        ) : verdicts.length === 0 ? (
          <EmptyState
            icon={Brain}
            title="No verdicts yet"
            description="LLM Council verdicts appear here after the first finding is processed through the Brain Pipeline."
          />
        ) : (
          <div className="space-y-0">
            {verdicts.map((v, i) => (
              <VerdictRow key={i} verdict={v} index={i} />
            ))}
          </div>
        )}

        {/* Footer link to full council view */}
        {!loading && (
          <div className="pt-3 flex justify-end">
            <Button variant="ghost" size="sm" className="h-7 text-[11px] text-muted-foreground gap-1" asChild>
              <a href="/brain/consensus">
                Full Council View <ChevronRight className="h-3 w-3" />
              </a>
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
