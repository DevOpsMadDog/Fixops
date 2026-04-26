/**
 * Zero-Setup Onboarding — initialize local-first store for new orgs
 * Route: /local-store/init
 * API: POST /api/v1/local-store/init (501 ok)
 * Multica id: 714713e9
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Rocket, Send, CheckCircle, HardDrive } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface InitResp {
  org_id?: string;
  store_id?: string;
  data_dir?: string;
  status?: string;
  initialized_at?: string;
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

export default function ZeroSetupOnboarding() {
  const [orgName, setOrgName] = useState("");
  const [dataDir, setDataDir] = useState("./.aldeci-data");
  const [resp, setResp] = useState<InitResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const start = async () => {
    if (!orgName.trim()) return;
    setLoading(true);
    setErr(null);
    setResp(null);
    try {
      const r = await apiPost<InitResp>("/api/v1/local-store/init", {
        org_name: orgName,
        data_dir: dataDir,
      });
      setResp(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!resp?.detail && !resp?.store_id;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Zero-Setup Onboarding"
        description="Spin up a local-first ALdeci org in seconds — no DB to provision, all on disk"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Rocket className="h-4 w-4" /> Initialize</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/local-store/init</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-xs">Organization Name</Label>
            <Input value={orgName} onChange={e => setOrgName(e.target.value)} placeholder="acme-security" className="text-sm" />
          </div>
          <div>
            <Label className="text-xs flex items-center gap-1"><HardDrive className="h-3 w-3" /> Data Directory</Label>
            <Input value={dataDir} onChange={e => setDataDir(e.target.value)} className="text-sm font-mono" />
          </div>
          <Button onClick={start} disabled={loading || !orgName.trim()} size="sm">
            <Send className="h-4 w-4 mr-2" /> {loading ? "Initializing…" : "Initialize Store"}
          </Button>

          {err && <ErrorState message={err} onRetry={start} />}

          {resp && !isComingSoon && (
            <div className="rounded-md border p-3 text-xs space-y-1">
              <div className="flex items-center gap-2"><CheckCircle className="h-4 w-4 text-green-400" /><Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Initialized</Badge></div>
              <div><span className="text-muted-foreground">Org:</span> <span className="font-mono">{resp.org_id ?? orgName}</span></div>
              <div><span className="text-muted-foreground">Store:</span> <span className="font-mono">{resp.store_id ?? "—"}</span></div>
              <div><span className="text-muted-foreground">Data dir:</span> <span className="font-mono">{resp.data_dir ?? dataDir}</span></div>
              <div><span className="text-muted-foreground">At:</span> <span className="font-mono">{resp.initialized_at ?? "—"}</span></div>
            </div>
          )}
          {resp?.detail && isComingSoon && <Badge variant="secondary" className="text-[10px]">{resp.detail}</Badge>}
        </CardContent>
      </Card>
    </motion.div>
  );
}
