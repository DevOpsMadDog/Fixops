/**
 * Pipeline Attestation Graph — SLSA attestation chain for an artifact
 * Route: /provenance/attestation
 * API: GET /api/v1/provenance/{artifact}/attestation
 * Multica id: be74d763
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, Search, Network } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface Step {
  predicate?: string;
  builder?: string;
  signer?: string;
  signature?: string;
  ts?: string;
}

interface Resp {
  artifact?: string;
  slsa_level?: number;
  attestations?: Step[];
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

export default function PipelineAttestationGraph() {
  const [artifact, setArtifact] = useState("");
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    if (!artifact.trim()) return;
    setLoading(true);
    setErr(null);
    try {
      const r = await apiFetch<Resp>(`/api/v1/provenance/${encodeURIComponent(artifact)}/attestation`);
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!data?.detail;
  const steps = data?.attestations ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Pipeline Attestation Graph"
        description="SLSA-style provenance chain for an artifact — predicates, signers, builders"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Network className="h-4 w-4" /> Provenance</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/provenance/{`{artifact}`}/attestation</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Artifact Reference</Label>
              <Input value={artifact} onChange={e => setArtifact(e.target.value)} placeholder="ghcr.io/acme/api:1.2.3" className="text-sm font-mono" />
            </div>
            <Button onClick={load} disabled={loading || !artifact.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Resolve</Button>
          </div>

          {err && <ErrorState message={err} onRetry={load} />}
          {isComingSoon && <EmptyState icon={ShieldCheck} title="Coming soon" description="Endpoint returns 501." />}

          {!err && !isComingSoon && data && (
            <>
              <div className="flex items-center gap-2">
                <Badge className="text-[11px]">SLSA L{data.slsa_level ?? 0}</Badge>
                <span className="text-xs text-muted-foreground">{steps.length} attestation(s)</span>
              </div>
              {steps.length === 0 ? <EmptyState icon={ShieldCheck} title="No attestations recorded" />
              : (
                <div className="space-y-2">
                  {steps.map((s, i) => (
                    <div key={i} className="rounded-md border p-3 text-xs space-y-1">
                      <div className="flex items-center gap-2">
                        <Badge className="text-[10px]">{s.predicate ?? "predicate"}</Badge>
                        <span className="text-muted-foreground ml-auto">{s.ts ?? "—"}</span>
                      </div>
                      <div><span className="text-muted-foreground">Builder:</span> <span className="font-mono">{s.builder ?? "—"}</span></div>
                      <div><span className="text-muted-foreground">Signer:</span> <span className="font-mono">{s.signer ?? "—"}</span></div>
                      <div><span className="text-muted-foreground">Sig:</span> <span className="font-mono text-[10px]">{(s.signature ?? "").slice(0, 24) || "—"}…</span></div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
