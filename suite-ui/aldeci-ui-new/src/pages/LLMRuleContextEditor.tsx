/**
 * LLM Rule Context Editor — view/edit context for a rule key
 * Route: /llm/rules/edit
 * API: GET/PUT /api/v1/llm/rules/{key}
 * Multica id: 33b1ed39
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { FileEdit, Search, Save } from "lucide-react";

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

interface RuleResp {
  key?: string;
  template?: string;
  variables?: string[];
  model?: string;
  context_tier?: string;
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
  if (res.status === 404) return {} as T;
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

export default function LLMRuleContextEditor() {
  const [key, setKey] = useState("");
  const [rule, setRule] = useState<RuleResp | null>(null);
  const [template, setTemplate] = useState("");
  const [model, setModel] = useState("");
  const [tier, setTier] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [savedNote, setSavedNote] = useState<string | null>(null);

  const fetchRule = async () => {
    if (!key.trim()) return;
    setLoading(true);
    setErr(null);
    setSavedNote(null);
    try {
      const r = await apiGet<RuleResp>(`/api/v1/llm/rules/${encodeURIComponent(key)}`);
      setRule(r);
      setTemplate(r.template ?? "");
      setModel(r.model ?? "");
      setTier(r.context_tier ?? "");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const save = async () => {
    if (!key.trim()) return;
    setSaving(true);
    setErr(null);
    try {
      const r = await apiPut<RuleResp>(`/api/v1/llm/rules/${encodeURIComponent(key)}`, {
        template,
        model,
        context_tier: tier,
      });
      setSavedNote(r.status ?? r.detail ?? "Saved");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const isComingSoon = !!rule?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="LLM Rule Editor"
        description="Edit prompt templates, target model, and context tier for a rule"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><FileEdit className="h-4 w-4" /> Rule</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET / PUT /api/v1/llm/rules/{`{key}`}</code></CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label className="text-xs">Rule Key</Label>
              <Input value={key} onChange={e => setKey(e.target.value)} placeholder="autofix.iac.s3-public-bucket" className="text-sm font-mono" />
            </div>
            <Button onClick={fetchRule} disabled={loading || !key.trim()} size="sm"><Search className="h-4 w-4 mr-2" /> Load</Button>
          </div>

          {err && <ErrorState message={err} onRetry={fetchRule} />}
          {isComingSoon && <EmptyState icon={FileEdit} title="Coming soon" description="Endpoint returns 501." />}

          {!err && !isComingSoon && rule && (
            <div className="space-y-3">
              <div>
                <Label className="text-xs">Prompt Template</Label>
                <Textarea rows={8} value={template} onChange={e => setTemplate(e.target.value)} className="text-sm font-mono" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-xs">Model</Label>
                  <Input value={model} onChange={e => setModel(e.target.value)} className="text-sm font-mono" />
                </div>
                <div>
                  <Label className="text-xs">Context Tier</Label>
                  <Input value={tier} onChange={e => setTier(e.target.value)} className="text-sm font-mono" />
                </div>
              </div>
              <div>
                <div className="text-[11px] text-muted-foreground mb-1">Variables</div>
                <div className="flex flex-wrap gap-1">{(rule.variables ?? []).map(v => <Badge key={v} className="text-[10px]">{v}</Badge>)}</div>
              </div>
              <div className="flex items-center gap-3">
                <Button onClick={save} disabled={saving} size="sm"><Save className="h-4 w-4 mr-2" /> {saving ? "Saving…" : "Save"}</Button>
                {savedNote && <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">{savedNote}</Badge>}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
