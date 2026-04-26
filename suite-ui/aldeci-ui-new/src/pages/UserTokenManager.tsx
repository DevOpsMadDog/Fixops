/**
 * User Token Manager — manage personal API tokens for current user
 * Route: /users/me/tokens
 * API: GET /api/v1/users/me/tokens
 * Multica id: 405b2922
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Key, RefreshCw, Plus, Trash2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Token {
  id?: string;
  label?: string;
  prefix?: string;
  created_at?: string;
  expires_at?: string;
  last_used?: string;
  scopes?: string[];
  revoked?: boolean;
}

interface Resp {
  tokens?: Token[];
  items?: Token[];
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
  if (res.status === 501) return { detail: "Coming soon", tokens: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function UserTokenManager() {
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<Resp>("/api/v1/users/me/tokens");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const tokens = data?.tokens ?? data?.items ?? [];
  const isComingSoon = !!data?.detail;
  const active = tokens.filter(t => !t.revoked).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="My API Tokens"
        description="Personal access tokens for CLI/CI/SDK integrations — scoped, revocable, time-bounded"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm"><Plus className="h-4 w-4 mr-2" /> New Token</Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Active Tokens" value={active} icon={Key} />
        <KpiCard title="Revoked" value={tokens.length - active} icon={Trash2} trend={tokens.length - active > 0 ? "down" : "flat"} />
        <KpiCard title="Total" value={tokens.length} icon={Key} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Tokens</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/users/me/tokens</code></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={Key} title="Coming soon" description="Endpoint returns 501." />
          : tokens.length === 0 ? <EmptyState icon={Key} title="No tokens issued" description="Create your first personal token to integrate with CLIs and SDKs." />
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Label</TableHead>
                    <TableHead className="text-[11px] h-8">Prefix</TableHead>
                    <TableHead className="text-[11px] h-8">Scopes</TableHead>
                    <TableHead className="text-[11px] h-8">Last Used</TableHead>
                    <TableHead className="text-[11px] h-8">Expires</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tokens.map((t, i) => (
                    <TableRow key={t.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{t.label ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{t.prefix ?? "—"}…</TableCell>
                      <TableCell className="py-2">
                        <div className="flex flex-wrap gap-1">
                          {(t.scopes ?? []).slice(0, 3).map(s => <Badge key={s} className="text-[9px]">{s}</Badge>)}
                          {(t.scopes ?? []).length > 3 && <Badge className="text-[9px]">+{(t.scopes ?? []).length - 3}</Badge>}
                        </div>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{t.last_used ?? "never"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{t.expires_at ?? "never"}</TableCell>
                      <TableCell className="py-2">
                        {t.revoked ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Revoked</Badge>
                          : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Active</Badge>}
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
