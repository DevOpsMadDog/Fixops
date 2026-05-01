// FOLDED into WebhookIngestionHub at /connect/webhook-ingestion?tab=dry-run — preserve for git history
/**
 * Universal Ingestion Tester — dry-run a connector mapping with sample input
 * Route: /connectors/mapping/dry-run
 * API: POST /api/v1/connectors/mapping/dry-run
 * Multica id: 0875c5fc
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { FlaskConical, Play, CheckCircle, AlertTriangle } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface DryRunResp {
  ok?: boolean;
  parsed_rows?: number;
  output_sample?: Record<string, unknown>[];
  errors?: string[];
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

export default function UniversalIngestionTester() {
  const [connector, setConnector] = useState("");
  const [sample, setSample] = useState("{\n  \"finding_id\": \"abc-123\",\n  \"severity\": \"high\"\n}");
  const [resp, setResp] = useState<DryRunResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    setLoading(true);
    setErr(null);
    setResp(null);
    try {
      const parsed = JSON.parse(sample);
      const r = await apiPost<DryRunResp>("/api/v1/connectors/mapping/dry-run", {
        connector,
        sample: parsed,
      });
      setResp(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!resp?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Universal Ingestion Tester"
        description="Validate a connector mapping against a sample payload before going live"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><FlaskConical className="h-4 w-4" /> Dry Run</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/connectors/mapping/dry-run</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-xs">Connector</Label>
            <Input value={connector} onChange={e => setConnector(e.target.value)} placeholder="snyk-cli" className="text-sm font-mono" />
          </div>
          <div>
            <Label className="text-xs">Sample Payload (JSON)</Label>
            <Textarea rows={10} value={sample} onChange={e => setSample(e.target.value)} className="text-xs font-mono" />
          </div>
          <Button onClick={run} disabled={loading || !connector.trim()} size="sm">
            <Play className="h-4 w-4 mr-2" /> {loading ? "Running…" : "Run"}
          </Button>

          {err && <ErrorState message={err} onRetry={run} />}
          {isComingSoon && <EmptyState icon={FlaskConical} title="Coming soon" description="Endpoint returns 501." />}

          {!err && !isComingSoon && resp && (
            <div className="rounded-md border p-3 space-y-3 text-xs">
              <div className="flex items-center gap-2">
                {resp.ok ? <CheckCircle className="h-4 w-4 text-green-400" /> : <AlertTriangle className="h-4 w-4 text-red-400" />}
                <Badge className={resp.ok ? "text-[10px] border border-green-500/30 text-green-400 bg-green-500/10" : "text-[10px] border border-red-500/30 text-red-400 bg-red-500/10"}>
                  {resp.ok ? "OK" : "Errors"}
                </Badge>
                <span className="text-muted-foreground">{resp.parsed_rows ?? 0} row(s) parsed</span>
              </div>
              {(resp.errors ?? []).length > 0 && (
                <div className="space-y-1">
                  <div className="text-muted-foreground">Errors:</div>
                  {(resp.errors ?? []).map((e, i) => <div key={i} className="font-mono text-red-400">{e}</div>)}
                </div>
              )}
              {(resp.output_sample ?? []).length > 0 && (
                <div>
                  <div className="text-muted-foreground mb-1">Output sample (first row)</div>
                  <pre className="rounded bg-background p-2 text-[10px] overflow-x-auto"><code>{JSON.stringify(resp.output_sample?.[0], null, 2)}</code></pre>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
