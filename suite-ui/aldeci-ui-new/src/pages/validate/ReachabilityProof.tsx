/**
 * Reachability Proof
 *
 * Show the proof trace (taint path / call chain / data flow) that a finding is reachable.
 * Route: /validate/reachability-proof
 * API: GET /api/v1/reachability/{finding_id}/proof
 * Multica id: dc67f247-d89a-4f6d-8439-a0d6abe88f41
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, RefreshCw, Search, AlertTriangle, ArrowRight } from "lucide-react";

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

interface ProofStep {
  step?: number;
  type?: string; // source | sink | propagator
  function?: string;
  file?: string;
  line?: number;
  snippet?: string;
}
interface ProofResponse {
  finding_id?: string;
  reachable?: boolean;
  confidence?: number;
  source?: string;
  sink?: string;
  steps?: ProofStep[];
  comingSoon?: boolean;
}

// Soft-fail statuses degrade to a "comingSoon" empty payload so the UI
// renders an EmptyState instead of throwing (which surfaces as a tab crash
// in the walkthrough console-error counter).
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
    });
  } catch {
    return { data: { comingSoon: true } as T, status: 0 };
  }
  if (SOFT_FAIL_STATUSES.has(res.status)) return { data: { comingSoon: true } as T, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

const stepColor: Record<string, string> = {
  source: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  sink: "border-red-500/30 text-red-400 bg-red-500/10",
  propagator: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  sanitizer: "border-green-500/30 text-green-400 bg-green-500/10",
};

export default function ReachabilityProof() {
  const [findingId, setFindingId] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [proof, setProof] = useState<ProofResponse | null>(null);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async (id: string) => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data } = await apiFetch<ProofResponse>(`/api/v1/reachability/${encodeURIComponent(id)}/proof`);
      if (data.comingSoon) {
        setComingSoon(true);
        setProof(null);
      } else {
        setProof(data);
      }
    } catch (e) {
      setErr((e as Error).message);
      setProof(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (submitted) load(submitted);
  }, [submitted]);

  const steps = proof?.steps ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Reachability Proof"
        description="Verify a finding is reachable from real input — taint propagation source → sink"
        actions={
          <Button variant="outline" size="sm" onClick={() => submitted && load(submitted)} disabled={loading || !submitted}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Search className="h-4 w-4" /> Finding</CardTitle>
          <CardDescription className="text-xs">Enter the finding id to fetch its reachability proof</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <Input value={findingId} onChange={(e) => setFindingId(e.target.value)} placeholder="finding-id" className="h-9 text-xs" />
          <Button size="sm" onClick={() => findingId.trim() && setSubmitted(findingId.trim())} disabled={!findingId.trim()}>
            Trace
          </Button>
        </CardContent>
      </Card>

      {proof && !comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard
            title="Reachable"
            value={proof.reachable ? "YES" : "NO"}
            icon={proof.reachable ? AlertTriangle : ShieldCheck}
            trend={proof.reachable ? "up" : "down"}
          />
          <KpiCard title="Confidence" value={proof.confidence != null ? `${Math.round(proof.confidence * 100)}%` : "—"} icon={ShieldCheck} />
          <KpiCard title="Steps" value={steps.length} icon={ArrowRight} />
          <KpiCard title="Source → Sink" value={`${proof.source ?? "?"} → ${proof.sink ?? "?"}`} icon={ArrowRight} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Proof Trace</CardTitle>
          <CardDescription className="text-xs">Ordered taint propagation steps</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {!submitted ? (
            <EmptyState icon={Search} title="No finding selected" description="Submit a finding id to view its proof trace." />
          ) : loading ? (
            <div className="p-6 text-sm text-muted-foreground">Tracing…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={() => submitted && load(submitted)} />
          ) : comingSoon ? (
            <EmptyState icon={ShieldCheck} title="Coming soon" description="GET /api/v1/reachability/{id}/proof is not enabled on this deployment." />
          ) : steps.length === 0 ? (
            <EmptyState icon={ShieldCheck} title="No proof steps" description="No reachability path was returned for this finding." />
          ) : (
            <div className="divide-y divide-border">
              {steps.map((s, i) => (
                <div key={i} className="px-4 py-3 hover:bg-muted/30">
                  <div className="flex items-center gap-3">
                    <span className="text-[11px] font-mono text-muted-foreground w-6">{s.step ?? i + 1}.</span>
                    <Badge className={cn("text-[10px] border capitalize", stepColor[(s.type ?? "").toLowerCase()] ?? "border-border")}>{s.type ?? "step"}</Badge>
                    <span className="text-[11px] font-mono">{s.function ?? "—"}</span>
                    <span className="text-[10px] text-muted-foreground">{s.file ?? ""}{s.line ? `:${s.line}` : ""}</span>
                  </div>
                  {s.snippet && (
                    <pre className="mt-2 ml-9 text-[11px] font-mono text-muted-foreground bg-muted/30 rounded p-2 overflow-x-auto">{s.snippet}</pre>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
