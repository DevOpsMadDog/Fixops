/**
 * Diff Mode Graph Canvas — visual graph diff for a PR
 * Route: /graph/diff
 * API: GET /api/v1/graph/diff?prId=
 * Multica id: 803a51e4
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { GitPullRequest, Plus, Minus, Search } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface NodeDiff {
  id?: string;
  label?: string;
  kind?: string;
  change?: "added" | "removed" | "modified";
}

interface DiffResp {
  pr_id?: string;
  added?: NodeDiff[];
  removed?: NodeDiff[];
  modified?: NodeDiff[];
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

export default function DiffModeGraphCanvas() {
  const [prId, setPrId] = useState("");
  const [data, setData] = useState<DiffResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!prId.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<DiffResp>(`/api/v1/graph/diff?prId=${encodeURIComponent(prId)}`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Diff Mode Graph"
        description="Visual diff of code/asset graph for a pull request — what nodes change"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><GitPullRequest className="h-4 w-4" /> PR Selector</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/graph/diff?prId=</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">PR ID</Label>
              <Input value={prId} onChange={e => setPrId(e.target.value)} placeholder="pr-1234" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading || !prId.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Diff</Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={GitPullRequest} title="Coming soon" description="Endpoint returns 501." />}
          {!err && !isComingSoon && data && (
            <>
              <div className="grid grid-cols-3 gap-3">
                <KpiCard title="Added" value={data.added?.length ?? 0} icon={Plus} trend="up" />
                <KpiCard title="Removed" value={data.removed?.length ?? 0} icon={Minus} trend="down" />
                <KpiCard title="Modified" value={data.modified?.length ?? 0} icon={GitPullRequest} />
              </div>
              <div className="space-y-3">
                {[
                  { label: "Added", color: "bg-green-500/10 text-green-400 border-green-500/30", items: data.added ?? [] },
                  { label: "Removed", color: "bg-red-500/10 text-red-400 border-red-500/30", items: data.removed ?? [] },
                  { label: "Modified", color: "bg-amber-500/10 text-amber-400 border-amber-500/30", items: data.modified ?? [] },
                ].map(group => (
                  <div key={group.label}>
                    <div className="text-xs font-semibold mb-2">{group.label} ({group.items.length})</div>
                    {group.items.length === 0 ? (
                      <div className="text-[11px] text-muted-foreground">— none —</div>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {group.items.map((n, i) => (
                          <Badge key={i} className={`text-[10px] border ${group.color} font-mono`}>{n.label ?? n.id ?? "node"}</Badge>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
