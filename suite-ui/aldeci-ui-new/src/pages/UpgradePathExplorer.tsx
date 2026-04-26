/**
 * Upgrade Path Explorer — full upgrade chain for a purl
 * Route: /components/upgrade-path
 * API: GET /api/v1/components/{purl}/safe-upgrade
 * Multica id: 1c5cb190
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { TrendingUp, Search, ChevronRight } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface UpgradeStep {
  current?: string;
  candidate?: string;
  is_breaking?: boolean;
  cves_resolved?: string[];
}

interface UpgradeResp {
  purl?: string;
  current_version?: string;
  recommended?: string;
  upgrades?: UpgradeStep[];
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
  if (res.status === 501) return { detail: "Coming soon", upgrades: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function UpgradePathExplorer() {
  const [purl, setPurl] = useState("");
  const [data, setData] = useState<UpgradeResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!purl.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<UpgradeResp>(`/api/v1/components/${encodeURIComponent(purl)}/safe-upgrade`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!data?.detail;
  const steps = data?.upgrades ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Upgrade Path Explorer"
        description="Step-by-step upgrade chain — what versions to climb to reach safe state"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><TrendingUp className="h-4 w-4" /> Path</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/components/{`{purl}`}/safe-upgrade</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Package URL (purl)</Label>
              <Input value={purl} onChange={e => setPurl(e.target.value)} placeholder="pkg:pypi/django@2.2.0" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading || !purl.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Explore</Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={TrendingUp} title="Coming soon" description="safe-upgrade endpoint returns 501." />}

          {!err && !isComingSoon && data && (
            steps.length === 0 ? (
              <EmptyState icon={TrendingUp} title="No upgrade path needed" />
            ) : (
              <div className="flex flex-wrap items-center gap-2">
                <Badge className="font-mono text-xs">{data.current_version ?? "current"}</Badge>
                {steps.map((s, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <ChevronRight className="h-3 w-3 text-muted-foreground" />
                    <Badge variant={s.is_breaking ? "destructive" : "default"} className="font-mono text-xs">
                      {s.candidate ?? "—"}
                      {(s.cves_resolved ?? []).length > 0 && <span className="ml-1 opacity-70">({(s.cves_resolved ?? []).length} CVE)</span>}
                    </Badge>
                  </div>
                ))}
              </div>
            )
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
