/**
 * Crown Jewel Configurator — tag an asset as a crown jewel
 * Route: /assets/crown-jewel
 * API: POST /api/v1/assets/{id}/crown-jewel-tag
 * Multica id: 3feb1bc9
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Crown, Send } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface TagResp {
  asset_id?: string;
  crown_jewel?: boolean;
  business_value?: string;
  reason?: string;
  detail?: string;
  status?: string;
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

export default function CrownJewelConfigurator() {
  const [assetId, setAssetId] = useState("");
  const [crownJewel, setCrownJewel] = useState(true);
  const [businessValue, setBusinessValue] = useState("high");
  const [reason, setReason] = useState("");
  const [resp, setResp] = useState<TagResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!assetId.trim()) return;
    setLoading(true);
    setErr(null);
    setResp(null);
    try {
      const r = await apiPost<TagResp>(`/api/v1/assets/${encodeURIComponent(assetId)}/crown-jewel-tag`, {
        crown_jewel: crownJewel,
        business_value: businessValue,
        reason,
      });
      setResp(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isComingSoon = !!resp?.detail && !resp?.asset_id;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Crown Jewel Configurator"
        description="Tag a critical asset as a crown jewel — boosts blast-radius scoring and SLA priorities"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Crown className="h-4 w-4 text-amber-400" /> Tag Asset</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">POST /api/v1/assets/{`{id}`}/crown-jewel-tag</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-xs">Asset ID</Label>
            <Input value={assetId} onChange={e => setAssetId(e.target.value)} placeholder="aws:rds:prod-customers" className="text-sm font-mono" />
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs cursor-pointer">
              <input type="checkbox" checked={crownJewel} onChange={e => setCrownJewel(e.target.checked)} />
              Mark as crown jewel
            </label>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs">Business Value</Label>
              <Input value={businessValue} onChange={e => setBusinessValue(e.target.value)} placeholder="critical | high | medium" className="text-sm" />
            </div>
            <div>
              <Label className="text-xs">Reason</Label>
              <Input value={reason} onChange={e => setReason(e.target.value)} placeholder="contains PII" className="text-sm" />
            </div>
          </div>
          <Button onClick={submit} disabled={loading || !assetId.trim()} size="sm">
            <Send className="h-4 w-4 mr-2" /> {loading ? "Tagging…" : "Tag"}
          </Button>

          {err && <ErrorState message={err} onRetry={submit} />}

          {resp && !isComingSoon && (
            <div className="rounded-md border p-3 text-xs space-y-1">
              <div className="flex items-center gap-2"><Crown className="h-4 w-4 text-amber-400" /><Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">Tagged</Badge></div>
              <div><span className="text-muted-foreground">Asset:</span> <span className="font-mono">{resp.asset_id ?? assetId}</span></div>
              <div><span className="text-muted-foreground">Crown Jewel:</span> <span className="font-mono">{resp.crown_jewel ? "Yes" : "No"}</span></div>
              <div><span className="text-muted-foreground">Business Value:</span> <span className="font-mono">{resp.business_value ?? businessValue}</span></div>
            </div>
          )}
          {resp?.detail && isComingSoon && (
            <Badge variant="secondary" className="text-[10px]">{resp.detail}</Badge>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
