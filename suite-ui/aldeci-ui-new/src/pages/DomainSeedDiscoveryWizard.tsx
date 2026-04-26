/**
 * Domain Seed Discovery Wizard — start EASM with a seed domain
 * Route: /easm/seed-domain
 * API: POST /api/v1/easm/seed-domain
 * Multica id: 085ee499
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Globe, Send, ArrowRight } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface SeedResp {
  job_id?: string;
  domain?: string;
  status?: string;
  discovered_subdomains?: number;
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

export default function DomainSeedDiscoveryWizard() {
  const [domain, setDomain] = useState("");
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [resp, setResp] = useState<SeedResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    setErr(null);
    setResp(null);
    try {
      const r = await apiPost<SeedResp>("/api/v1/easm/seed-domain", {
        domain,
        include_subdomains: includeSubdomains,
        org_id: getStoredOrgId(),
      });
      setResp(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!resp?.detail && !resp?.job_id;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Domain Seed Discovery"
        description="Bootstrap external attack surface management — seed your discovery from a domain"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Globe className="h-4 w-4" /> Seed</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/easm/seed-domain</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Root Domain</Label>
              <Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" className="text-sm font-mono" />
            </div>
            <label className="flex items-center gap-2 text-xs cursor-pointer">
              <input type="checkbox" checked={includeSubdomains} onChange={e => setIncludeSubdomains(e.target.checked)} />
              Include subdomains in initial scan
            </label>
          </div>
          <Button onClick={submit} disabled={loading || !domain.trim()} size="sm">
            <Send className="h-4 w-4 mr-2" /> {loading ? "Submitting…" : "Start Discovery"}
          </Button>

          {err && <ErrorState message={err} onRetry={submit} />}
          {isComingSoon && <EmptyState icon={Globe} title="Coming soon" description="Endpoint returns 501." />}

          {resp && !isComingSoon && (
            <div className="rounded-md border p-4 space-y-2 text-xs">
              <div className="flex items-center gap-2"><ArrowRight className="h-3 w-3 text-green-400" /><span className="font-semibold">Job submitted</span></div>
              <div><span className="text-muted-foreground">Job ID:</span> <span className="font-mono">{resp.job_id ?? "—"}</span></div>
              <div><span className="text-muted-foreground">Domain:</span> <span className="font-mono">{resp.domain ?? domain}</span></div>
              <div><span className="text-muted-foreground">Status:</span> <Badge>{resp.status ?? "queued"}</Badge></div>
              {resp.discovered_subdomains !== undefined && (
                <div><span className="text-muted-foreground">Subdomains:</span> <span className="font-mono">{resp.discovered_subdomains}</span></div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
