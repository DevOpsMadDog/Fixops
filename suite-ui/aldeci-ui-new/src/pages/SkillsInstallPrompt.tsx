/**
 * Skills Install Prompt — install a skill into the org workspace
 * Route: /skills/install
 * API: POST /api/v1/skills/install (501 ok)
 * Multica id: 59a4bfef
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Sparkles, Send } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

interface InstallResp {
  status?: string;
  skill_id?: string;
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

export default function SkillsInstallPrompt() {
  const [skillId, setSkillId] = useState("");
  const [version, setVersion] = useState("latest");
  const [loading, setLoading] = useState(false);
  const [resp, setResp] = useState<InstallResp | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const onInstall = async () => {
    if (!skillId.trim()) return;
    setLoading(true);
    setErr(null);
    setResp(null);
    try {
      const r = await apiPost<InstallResp>("/api/v1/skills/install", { skill_id: skillId, version });
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
        title="Install Claude Skill"
        description="Add a skill from the registry to your org's agent workspace"
        badge={isComingSoon ? "Coming Soon" : undefined}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Sparkles className="h-4 w-4" /> Install</CardTitle>
          <CardDescription className="text-xs">
            Endpoint: <code className="text-[10px]">POST /api/v1/skills/install</code>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <Label className="text-xs">Skill ID</Label>
              <Input value={skillId} onChange={e => setSkillId(e.target.value)} placeholder="graphify" className="text-sm" />
            </div>
            <div>
              <Label className="text-xs">Version</Label>
              <Input value={version} onChange={e => setVersion(e.target.value)} placeholder="latest" className="text-sm" />
            </div>
          </div>
          <Button onClick={onInstall} disabled={loading || !skillId.trim()} size="sm">
            <Send className="h-4 w-4 mr-2" /> Install
          </Button>
          {err && <ErrorState message={err} onRetry={onInstall} />}
          {resp && (
            <div className="rounded-md border p-3 text-xs space-y-1">
              {resp.detail && <Badge variant="secondary">{resp.detail}</Badge>}
              {resp.status && <div><span className="text-muted-foreground">Status:</span> <span className="font-mono">{resp.status}</span></div>}
              {resp.skill_id && <div><span className="text-muted-foreground">Skill:</span> <span className="font-mono">{resp.skill_id}</span></div>}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
