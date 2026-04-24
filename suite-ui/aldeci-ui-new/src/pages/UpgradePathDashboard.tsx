/**
 * Upgrade Path Dashboard
 *
 * Package version upgrade resolver — given a pURL and CVE IDs, compute
 * the minimal safe upgrade path.
 * Route: /upgrade-path
 * API: GET /api/v1/upgrade-path/stats; POST /api/v1/upgrade-path/resolve
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ArrowUpCircle, RefreshCw, Package, ShieldCheck, GitBranch, Search } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Stats {
  total_resolutions?: number;
  resolved_today?: number;
  avg_jump?: number;
  total_cves_fixed?: number;
}

interface UpgradeStep {
  from_version?: string;
  to_version?: string;
  cves_fixed?: string[];
  breaking?: boolean;
  notes?: string;
}

interface ResolveResult {
  purl?: string;
  current_version?: string;
  target_version?: string;
  path?: UpgradeStep[];
  total_hops?: number;
  breaking_changes?: number;
  fixes_cves?: string[];
  error?: string;
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function UpgradePathDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [resolving, setResolving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [purl, setPurl] = useState("pkg:npm/lodash@4.17.10");
  const [cves, setCves] = useState("CVE-2019-10744\nCVE-2020-8203");
  const [result, setResult] = useState<ResolveResult | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const s = await apiFetch<Stats>("/api/v1/upgrade-path/stats");
      setStats(s);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleResolve = async () => {
    if (!purl.trim()) return;
    setResolving(true);
    setResult(null);
    try {
      const cve_ids = cves.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
      const r = await apiFetch<ResolveResult>("/api/v1/upgrade-path/resolve", {
        method: "POST",
        body: JSON.stringify({ purl: purl.trim(), cve_ids }),
      });
      setResult(r);
    } catch (e) {
      setResult({ error: (e as Error).message });
    } finally { setResolving(false); }
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Upgrade Path Resolver"
        description="Compute the minimal safe upgrade path for vulnerable packages — fewest hops, fewest breaking changes"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Resolutions" value={stats?.total_resolutions ?? 0} icon={Package} />
        <KpiCard title="Resolved Today" value={stats?.resolved_today ?? 0} icon={ArrowUpCircle} trend="up" />
        <KpiCard title="CVEs Fixed" value={stats?.total_cves_fixed ?? 0} icon={ShieldCheck} trend="up" />
        <KpiCard title="Avg Hops" value={stats?.avg_jump?.toFixed?.(1) ?? "—"} icon={GitBranch} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Search className="h-4 w-4" /> Resolve Upgrade</CardTitle>
          <CardDescription className="text-xs">Provide a package pURL and one or more CVE IDs to compute the upgrade path</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground">Package pURL</label>
            <Input value={purl} onChange={e => setPurl(e.target.value)} placeholder="pkg:npm/lodash@4.17.10" className="h-9 text-xs font-mono" />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground">CVE IDs (one per line)</label>
            <Textarea value={cves} onChange={e => setCves(e.target.value)} rows={3} className="font-mono text-xs" spellCheck={false} />
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={handleResolve} disabled={resolving || !purl.trim()}>
              <ArrowUpCircle className={cn("h-4 w-4 mr-2", resolving && "animate-pulse")} />
              Resolve Path
            </Button>
            {result && !result.error && (
              <span className="text-xs text-muted-foreground">
                {result.total_hops ?? result.path?.length ?? 0} hops · {result.breaking_changes ?? 0} breaking
              </span>
            )}
          </div>

          {result?.error && (
            <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs font-mono text-red-400">{result.error}</div>
          )}

          {result && !result.error && (
            <div className="rounded border border-border/50 bg-muted/20 p-3">
              <div className="flex items-center justify-between text-xs mb-3">
                <span className="font-mono">{result.current_version ?? "?"} → {result.target_version ?? "?"}</span>
                <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
                  {(result.fixes_cves ?? []).length} CVEs fixed
                </Badge>
              </div>
              <div className="space-y-1.5">
                {(result.path ?? []).map((step, i) => (
                  <div key={i} className="flex items-center justify-between rounded bg-muted/30 px-2 py-1.5">
                    <div className="flex items-center gap-2 text-[11px] font-mono">
                      <span className="text-muted-foreground">{step.from_version ?? "?"}</span>
                      <ArrowUpCircle className="h-3 w-3 text-green-400" />
                      <span>{step.to_version ?? "?"}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {(step.cves_fixed ?? []).length > 0 && (
                        <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
                          {(step.cves_fixed ?? []).length} fixes
                        </Badge>
                      )}
                      {step.breaking && (
                        <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">Breaking</Badge>
                      )}
                    </div>
                  </div>
                ))}
                {(result.path ?? []).length === 0 && (
                  <EmptyState icon={Package} title="No path found" description="No upgrade path resolves the given CVEs." />
                )}
              </div>
            </div>
          )}

          {!result && !loading && (
            <div className="rounded border border-dashed border-border/50 p-4 text-xs text-muted-foreground text-center">
              Enter a pURL and CVE IDs, then click Resolve Path.
            </div>
          )}

          {err && <ErrorState message={err} onRetry={load} />}
        </CardContent>
      </Card>
    </motion.div>
  );
}
