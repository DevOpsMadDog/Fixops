/**
 * SLSA Attestation Signer
 * Route: /provenance/sign
 * API: POST /api/v1/provenance/sign (501 ok)
 * Multica id: 81e332d3
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, FileSignature, Send } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface SignResp {
  attestation_id?: string;
  signature?: string;
  predicate_type?: string;
  detail?: string;
}

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (res.status === 501) return { detail: "Coming soon" } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function SLSAAttestationSigner() {
  const [artifact, setArtifact] = useState("");
  const [predicate, setPredicate] = useState("https://slsa.dev/provenance/v1");
  const [statement, setStatement] = useState("{}");
  const [resp, setResp] = useState<SignResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const sign = async () => {
    if (!artifact.trim()) return;
    setLoading(true);
    setErr(null);
    setResp(null);
    try {
      const parsed = JSON.parse(statement);
      const r = await apiPost<SignResp>("/api/v1/provenance/sign", {
        artifact,
        predicate_type: predicate,
        statement: parsed,
      });
      setResp(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!resp?.detail && !resp?.attestation_id;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="SLSA Attestation Signer"
        description="Sign an in-toto/SLSA statement and store the attestation against an artifact"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><FileSignature className="h-4 w-4" /> Sign</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/provenance/sign</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-xs">Artifact</Label>
            <Input value={artifact} onChange={e => setArtifact(e.target.value)} placeholder="ghcr.io/acme/api:1.2.3" className="text-sm font-mono" />
          </div>
          <div>
            <Label className="text-xs">Predicate Type</Label>
            <Input value={predicate} onChange={e => setPredicate(e.target.value)} className="text-sm font-mono" />
          </div>
          <div>
            <Label className="text-xs">Statement (JSON)</Label>
            <Textarea rows={8} value={statement} onChange={e => setStatement(e.target.value)} className="text-xs font-mono" />
          </div>
          <Button onClick={sign} disabled={loading || !artifact.trim()} size="sm">
            <Send className="h-4 w-4 mr-2" /> {loading ? "Signing…" : "Sign"}
          </Button>

          {err && <ErrorState message={err} onRetry={sign} />}
          {isComingSoon && <EmptyState icon={ShieldCheck} title="Coming soon" description="Endpoint returns 501." />}

          {resp && !isComingSoon && (
            <div className="rounded-md border p-3 text-xs space-y-1">
              <div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-green-400" /><Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Signed</Badge></div>
              <div><span className="text-muted-foreground">Attestation ID:</span> <span className="font-mono">{resp.attestation_id ?? "—"}</span></div>
              <div><span className="text-muted-foreground">Predicate:</span> <span className="font-mono">{resp.predicate_type ?? predicate}</span></div>
              <div><span className="text-muted-foreground">Signature:</span> <span className="font-mono">{(resp.signature ?? "").slice(0, 32) || "—"}…</span></div>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
