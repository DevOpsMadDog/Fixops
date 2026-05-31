/**
 * HealthzWidget — liveness probe badge for the executive dashboard.
 *
 * Polls GET /api/v1/health every 30 s via TanStack Query.
 * Shows: status pill (green / red), last-check time, round-trip latency, version.
 *
 * Endpoint contract (suite-api/apps/api/health.py):
 *   { status: "healthy", timestamp: string, service: string, version: string }
 *
 * No fabricated data — empty/error states render honestly.
 */

import { useQuery } from "@tanstack/react-query";
import { Activity, Clock, Zap, Tag } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// ─── Shape returned by GET /api/v1/health ────────────────────────────────────

interface HealthResponse {
  status: string;       // "healthy" | anything else = unhealthy
  timestamp: string;    // ISO-8601
  service: string;
  version: string;
}

interface HealthResult {
  data: HealthResponse;
  latencyMs: number;
}

// ─── Fetch helper — measures round-trip latency ───────────────────────────────

async function fetchHealthz(): Promise<HealthResult> {
  const t0 = performance.now();
  const res = await fetch(buildApiUrl("/api/v1/health"), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  const latencyMs = Math.round(performance.now() - t0);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  const data = (await res.json()) as HealthResponse;
  return { data, latencyMs };
}

// ─── Component ────────────────────────────────────────────────────────────────

export function HealthzWidget() {
  const { data: result, isLoading, isError, dataUpdatedAt } = useQuery<HealthResult, Error>({
    queryKey: ["healthz"],
    queryFn: fetchHealthz,
    refetchInterval: 30_000,
    retry: 1,
  });

  // ── Loading state ──
  if (isLoading) {
    return (
      <Card className="w-full">
        <CardContent className="flex items-center gap-3 py-3 px-4">
          <Activity className="h-4 w-4 text-muted-foreground shrink-0" />
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-3 w-14" />
        </CardContent>
      </Card>
    );
  }

  // ── Error / unreachable state ──
  if (isError || !result) {
    return (
      <Card className="w-full border-red-500/30">
        <CardContent className="flex items-center gap-3 py-3 px-4">
          <Activity className="h-4 w-4 text-red-400 shrink-0" />
          <Badge className="text-[10px] bg-red-500/15 text-red-400 border border-red-500/30 font-semibold">
            UNREACHABLE
          </Badge>
          <span className="text-xs text-muted-foreground">API did not respond</span>
        </CardContent>
      </Card>
    );
  }

  const isHealthy = result.data.status === "healthy";
  const lastChecked = dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString() : "—";

  return (
    <Card className={cn("w-full transition-colors", isHealthy ? "border-green-500/20" : "border-red-500/30")}>
      <CardContent className="flex items-center gap-3 py-3 px-4 flex-wrap">
        {/* Status pill */}
        <div className="flex items-center gap-1.5 shrink-0">
          <Activity className="h-4 w-4 text-muted-foreground" />
          <Badge
            className={cn(
              "text-[10px] font-semibold border",
              isHealthy
                ? "bg-green-500/15 text-green-400 border-green-500/30"
                : "bg-red-500/15 text-red-400 border-red-500/30"
            )}
          >
            {isHealthy ? "HEALTHY" : result.data.status.toUpperCase()}
          </Badge>
        </div>

        {/* Divider */}
        <span className="text-muted-foreground/30 hidden sm:inline">|</span>

        {/* Last check time */}
        <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
          <Clock className="h-3 w-3 shrink-0" />
          <span>Checked {lastChecked}</span>
        </div>

        {/* Round-trip latency */}
        <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
          <Zap className="h-3 w-3 shrink-0" />
          <span>{result.latencyMs}ms</span>
        </div>

        {/* Version */}
        {result.data.version && (
          <div className="flex items-center gap-1 text-[11px] text-muted-foreground ml-auto">
            <Tag className="h-3 w-3 shrink-0" />
            <span className="font-mono">{result.data.version}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
