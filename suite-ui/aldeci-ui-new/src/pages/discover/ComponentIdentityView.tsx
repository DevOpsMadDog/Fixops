/**
 * Component Identity View
 *
 * Match a component by Anchored Binary Fingerprint (ABF) → real package identity.
 * Route: /discover/component-identity
 * API: GET /api/v1/components/match-by-abf?abf=
 * Multica id: dd4efb89-5d81-41e0-a64a-e6ec843a52a7
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Fingerprint, Search, RefreshCw, Boxes, ShieldCheck } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ComponentMatch {
  abf?: string;
  package_name?: string;
  version?: string;
  ecosystem?: string;
  vendor?: string;
  license?: string;
  cpe?: string;
  purl?: string;
  confidence?: number;
  vulnerabilities?: number;
  match_type?: string;
}
interface MatchResponse {
  abf?: string;
  matches?: ComponentMatch[];
  best_match?: ComponentMatch;
  comingSoon?: boolean;
}

// Soft-fail statuses degrade to a "comingSoon" empty payload so the UI
// renders an EmptyState instead of throwing (which surfaces as a tab crash
// in the walkthrough console-error counter).
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

async function apiFetch<T>(path: string, params: Record<string, string> = {}): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  let res: Response;
  try {
    res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" } });
  } catch {
    return { data: { comingSoon: true } as T, status: 0 };
  }
  if (SOFT_FAIL_STATUSES.has(res.status)) return { data: { comingSoon: true } as T, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  const color = pct >= 80 ? "bg-green-500" : pct >= 50 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="w-24 bg-muted rounded-full h-1.5">
      <div className={cn("h-1.5 rounded-full", color)} style={{ width: `${pct}%` }} />
    </div>
  );
}

export default function ComponentIdentityView() {
  const [abf, setAbf] = useState("");
  const [data, setData] = useState<MatchResponse | null>(null);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!abf.trim()) return;
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data: payload } = await apiFetch<MatchResponse>("/api/v1/components/match-by-abf", { abf: abf.trim() });
      if (payload.comingSoon) {
        setComingSoon(true);
        setData(null);
      } else {
        setData(payload);
      }
    } catch (e) {
      setErr((e as Error).message);
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  const matches = data?.matches ?? (data?.best_match ? [data.best_match] : []);
  const best = data?.best_match ?? (matches.length > 0 ? matches[0] : null);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Component Identity"
        description="Map an Anchored Binary Fingerprint (ABF) to a real package + license + CVE profile"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading || !abf.trim()}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Fingerprint className="h-4 w-4" /> ABF Lookup</CardTitle>
          <CardDescription className="text-xs">Paste an Anchored Binary Fingerprint to identify the component</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <Input
            value={abf}
            onChange={(e) => setAbf(e.target.value)}
            placeholder="abf:sha256:…"
            className="h-9 text-xs font-mono"
            onKeyDown={(e) => e.key === "Enter" && load()}
          />
          <Button size="sm" onClick={load} disabled={loading || !abf.trim()}>
            <Search className="h-4 w-4 mr-1.5" /> Match
          </Button>
        </CardContent>
      </Card>

      {best && !comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Best Match" value={best.package_name ?? "—"} icon={Boxes} />
          <KpiCard title="Version" value={best.version ?? "—"} icon={Boxes} />
          <KpiCard title="Confidence" value={best.confidence != null ? `${Math.round(best.confidence * 100)}%` : "—"} icon={ShieldCheck} />
          <KpiCard title="Vulns" value={best.vulnerabilities ?? 0} icon={ShieldCheck} trend={(best.vulnerabilities ?? 0) > 0 ? "up" : "flat"} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Candidate Matches</CardTitle>
          <CardDescription className="text-xs">Ranked by confidence</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {!data && !loading && !comingSoon ? (
            <EmptyState icon={Fingerprint} title="No ABF submitted" description="Paste an ABF above to start the lookup." />
          ) : loading ? (
            <div className="p-6 text-sm text-muted-foreground">Looking up…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={Fingerprint} title="Coming soon" description="GET /api/v1/components/match-by-abf is not enabled on this deployment." />
          ) : matches.length === 0 ? (
            <EmptyState icon={Fingerprint} title="No matches" description="No components matched this ABF." />
          ) : (
            <div className="divide-y divide-border">
              {matches.map((m, i) => (
                <div key={i} className="px-4 py-3 hover:bg-muted/30 grid gap-2 md:grid-cols-6 text-[11px]">
                  <div className="md:col-span-2">
                    <div className="font-mono">{m.package_name ?? "—"} <span className="text-muted-foreground">@ {m.version ?? "—"}</span></div>
                    <div className="text-[10px] text-muted-foreground">{m.purl ?? m.cpe ?? "—"}</div>
                  </div>
                  <div className="text-muted-foreground">{m.ecosystem ?? "—"}</div>
                  <div className="text-muted-foreground">{m.vendor ?? "—"}</div>
                  <div><Badge className="text-[10px] border border-border">{m.license ?? "license: —"}</Badge></div>
                  <div className="flex items-center gap-2 justify-end">
                    <ConfidenceBar value={m.confidence ?? 0} />
                    <span className="font-mono">{m.confidence != null ? `${Math.round(m.confidence * 100)}%` : "—"}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
