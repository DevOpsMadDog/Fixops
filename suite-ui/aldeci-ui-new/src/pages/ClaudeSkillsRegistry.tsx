/**
 * Claude Skills Registry
 * Route: /skills
 * API: GET /api/v1/skills (501 ok)
 * Multica id: 376639f1
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Sparkles, RefreshCw } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Skill {
  id?: string;
  name?: string;
  version?: string;
  description?: string;
  installed?: boolean;
  category?: string;
}

interface SkillResp {
  skills?: Skill[];
  items?: Skill[];
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
  if (res.status === 501) return { detail: "Coming soon", skills: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function ClaudeSkillsRegistry() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [data, setData] = useState<SkillResp | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const resp = await apiFetch<SkillResp>("/api/v1/skills");
      setData(resp);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const skills = data?.skills ?? data?.items ?? [];
  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Claude Skills Registry"
        description="Catalog of Claude skills available to ALdeci agents — searchable, installable, scoped"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Sparkles className="h-4 w-4" /> Skills</CardTitle>
          <CardDescription className="text-xs">
            Endpoint: <code className="text-[10px]">GET /api/v1/skills</code>
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading skills…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : isComingSoon ? (
            <EmptyState icon={Sparkles} title="Coming soon" description="Endpoint /api/v1/skills returns 501 — registry implementation pending." />
          ) : skills.length === 0 ? (
            <EmptyState icon={Sparkles} title="No skills registered" />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Skill</TableHead>
                    <TableHead className="text-[11px] h-8">Version</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {skills.map((s, i) => (
                    <TableRow key={s.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{s.name ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{s.version ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px]">{s.category ?? "—"}</TableCell>
                      <TableCell className="py-2">
                        {s.installed ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Installed</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-muted text-muted-foreground">Available</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
