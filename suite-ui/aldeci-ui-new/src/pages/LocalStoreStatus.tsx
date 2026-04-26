/**
 * Local Store Status
 * Route: /local-store/status
 * API: GET /api/v1/local-store/status (501 ok)
 * Multica id: 3168f49f
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { HardDrive, RefreshCw, Database } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface StoreStatus {
  initialized?: boolean;
  size_bytes?: number;
  records?: number;
  data_dir?: string;
  last_write?: string;
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

function formatBytes(n?: number) {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export default function LocalStoreStatus() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [status, setStatus] = useState<StoreStatus | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<StoreStatus>("/api/v1/local-store/status");
      setStatus(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const isComingSoon = !!status?.detail && status?.initialized === undefined;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Local Store Status"
        description="On-disk file/object store used for offline-first ingestion and storage"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Initialized" value={status?.initialized ? "Yes" : "No"} icon={HardDrive} />
        <KpiCard title="Disk Size" value={formatBytes(status?.size_bytes)} icon={Database} />
        <KpiCard title="Records" value={status?.records ?? 0} icon={Database} />
        <KpiCard title="Last Write" value={status?.last_write ? status.last_write.slice(0, 19) : "—"} icon={HardDrive} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Store Detail</CardTitle>
          <CardDescription className="text-xs">
            Endpoint: <code className="text-[10px]">GET /api/v1/local-store/status</code>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? <div className="text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={HardDrive} title="Coming soon" description="Endpoint /api/v1/local-store/status returns 501 — implementation pending." />
          : (
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-muted-foreground">Data directory</span><span className="font-mono">{status?.data_dir ?? "—"}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Initialized</span><span className="font-mono">{status?.initialized ? "Yes" : "No"}</span></div>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
