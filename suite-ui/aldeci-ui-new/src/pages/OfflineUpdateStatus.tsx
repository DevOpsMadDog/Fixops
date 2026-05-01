// FOLDED into AirGapHub at /connect/mcp/air-gap?tab=update-status (2026-05-02) — preserve for git history; lazy-imported by hub
/**
 * Offline Update Status — air-gap update install status
 * Route: /air-gap/update-status
 * API: GET /api/v1/air-gap/update-status (501 ok)
 * Multica id: 8a09b108
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { RefreshCw, Download, Cpu, AlertTriangle } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface UpdateStatus {
  current_version?: string;
  latest_version?: string;
  pending_updates?: number;
  last_check?: string;
  next_check?: string;
  state?: string;
  detail?: string;
}

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

export default function OfflineUpdateStatus() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [status, setStatus] = useState<UpdateStatus | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const resp = await apiFetch<UpdateStatus>("/api/v1/air-gap/update-status");
      setStatus(resp);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const isComingSoon = !!status?.detail && !status?.current_version;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Offline Update Status"
        description="Air-gap installation version, pending updates, last sync time"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Current Version" value={status?.current_version ?? "—"} icon={Cpu} />
        <KpiCard title="Latest Version" value={status?.latest_version ?? "—"} icon={Download} />
        <KpiCard title="Pending" value={status?.pending_updates ?? 0} icon={AlertTriangle} trend={(status?.pending_updates ?? 0) > 0 ? "down" : "up"} />
        <KpiCard title="State" value={status?.state ?? "—"} icon={Cpu} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Update Detail</CardTitle>
          <CardDescription className="text-xs">
            Endpoint: <code className="text-[10px]">GET /api/v1/air-gap/update-status</code>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : isComingSoon ? (
            <EmptyState icon={Download} title="Coming soon" description="Endpoint /api/v1/air-gap/update-status returns 501 — implementation pending." />
          ) : (
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-muted-foreground">Last Check</span><span className="font-mono">{status?.last_check ?? "—"}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Next Check</span><span className="font-mono">{status?.next_check ?? "—"}</span></div>
              <div className="flex justify-between items-center"><span className="text-muted-foreground">State</span><Badge>{status?.state ?? "unknown"}</Badge></div>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
