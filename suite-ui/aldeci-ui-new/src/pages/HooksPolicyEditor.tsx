// FOLDED into PolicyAuthoringHub (hooks-policy tab) 2026-05-02 — preserve for git history
/**
 * Hooks Policy Editor
 * Route: /hooks/policy
 * API: GET/PUT /api/v1/hooks/policy (501 ok)
 * Multica id: d6bd5eea
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Webhook, Save } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface PolicyResp {
  policy?: Record<string, unknown>;
  detail?: string;
  status?: string;
}

async function apiGet<T>(path: string): Promise<T> {
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
async function apiPut<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    method: "PUT",
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

export default function HooksPolicyEditor() {
  const [policyText, setPolicyText] = useState("{\n  \"pre_finding_ingest\": [],\n  \"post_finding_ingest\": []\n}");
  const [data, setData] = useState<PolicyResp | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [savedNote, setSavedNote] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    try {
      const r = await apiGet<PolicyResp>("/api/v1/hooks/policy");
      setData(r);
      if (r.policy) setPolicyText(JSON.stringify(r.policy, null, 2));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const save = async () => {
    setSaving(true);
    setErr(null);
    setSavedNote(null);
    try {
      const parsed = JSON.parse(policyText);
      const r = await apiPut<PolicyResp>("/api/v1/hooks/policy", { policy: parsed });
      setSavedNote(r.status ?? r.detail ?? "Saved");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Hooks Policy"
        description="Define pre/post hooks at each pipeline stage — declarative JSON"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Webhook className="h-4 w-4" /> Policy</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET/PUT /api/v1/hooks/policy</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading ? <div className="text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={Webhook} title="Coming soon" description="Endpoint returns 501." />
          : (
            <>
              <div>
                <Label className="text-xs">Policy (JSON)</Label>
                <Textarea rows={14} value={policyText} onChange={e => setPolicyText(e.target.value)} className="text-xs font-mono" />
              </div>
              <div className="flex items-center gap-3">
                <Button onClick={save} disabled={saving} size="sm"><Save className="h-4 w-4 mr-2" /> {saving ? "Saving…" : "Save"}</Button>
                {savedNote && <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">{savedNote}</Badge>}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
