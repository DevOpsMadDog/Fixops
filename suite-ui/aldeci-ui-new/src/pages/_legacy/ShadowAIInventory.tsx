// FOLDED into AICopilotAgentsHub hero (shadow tab) 2026-05-02 — preserve for git history
/**
 * Shadow AI Inventory
 *
 * Discover unsanctioned LLM / model usage across the org.
 * Route: /ai/shadow-inventory
 * API: GET /api/v1/ai-exposure/shadow
 * Multica id: f265af69-44fe-4858-8a55-e6c80f68cd56
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { EyeOff, RefreshCw, AlertTriangle, ShieldAlert } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ShadowAIItem {
  id?: string;
  service?: string;        // OpenAI, Anthropic, HuggingFace, custom
  model?: string;
  user?: string;
  team?: string;
  endpoint?: string;
  first_seen?: string;
  last_seen?: string;
  request_count?: number;
  risk?: string;           // critical|high|medium|low
  sanctioned?: boolean;
  pii_detected?: boolean;
  data_egress_kb?: number;
}
interface ShadowResponse {
  items?: ShadowAIItem[];
  shadow_models?: ShadowAIItem[];
  total?: number;
  comingSoon?: boolean;
}

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" } });
  if (res.status === 501) return { data: { comingSoon: true } as T, status: 501 };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

const riskColor: Record<string, string> = {
  critical: "border-red-500/30 text-red-400 bg-red-500/10",
  high: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  medium: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  low: "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

export default function ShadowAIInventory() {
  const [items, setItems] = useState<ShadowAIItem[]>([]);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      const { data } = await apiFetch<ShadowResponse>("/api/v1/ai-exposure/shadow");
      if (data.comingSoon) {
        setComingSoon(true);
        setItems([]);
      } else {
        const list = Array.isArray(data) ? (data as ShadowAIItem[]) : (data.items ?? data.shadow_models ?? []);
        setItems(list);
      }
    } catch (e) {
      setErr((e as Error).message);
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const total = items.length;
  const unsanctioned = items.filter((i) => i.sanctioned === false).length;
  const piiCount = items.filter((i) => i.pii_detected).length;
  const critical = items.filter((i) => (i.risk ?? "").toLowerCase() === "critical").length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Shadow AI Inventory"
        description="Discover unsanctioned LLM and model usage across the org"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      {!comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Shadow Models" value={total} icon={EyeOff} />
          <KpiCard title="Unsanctioned" value={unsanctioned} icon={ShieldAlert} trend={unsanctioned ? "up" : "flat"} />
          <KpiCard title="PII Detected" value={piiCount} icon={AlertTriangle} trend={piiCount ? "up" : "flat"} />
          <KpiCard title="Critical Risk" value={critical} icon={AlertTriangle} trend={critical ? "up" : "flat"} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Discovered Models</CardTitle>
          <CardDescription className="text-xs">Aggregated from network egress, proxies and SIEM logs</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Scanning…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={EyeOff} title="Coming soon" description="GET /api/v1/ai-exposure/shadow is not enabled on this deployment." />
          ) : items.length === 0 ? (
            <EmptyState icon={EyeOff} title="No shadow AI detected" description="The org has not surfaced any unsanctioned model usage." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Service</TableHead>
                    <TableHead className="text-[11px] h-8">Model</TableHead>
                    <TableHead className="text-[11px] h-8">User</TableHead>
                    <TableHead className="text-[11px] h-8">Team</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Requests</TableHead>
                    <TableHead className="text-[11px] h-8">Risk</TableHead>
                    <TableHead className="text-[11px] h-8">PII</TableHead>
                    <TableHead className="text-[11px] h-8">Last Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.slice(0, 200).map((it, i) => (
                    <TableRow key={it.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-medium">{it.service ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{it.model ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{it.user ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{it.team ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{it.request_count ?? 0}</TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", riskColor[(it.risk ?? "").toLowerCase()] ?? "border-border")}>{it.risk ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2">{it.pii_detected ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">YES</Badge> : <span className="text-[10px] text-muted-foreground">no</span>}</TableCell>
                      <TableCell className="py-2 text-[10px] text-muted-foreground">{it.last_seen ?? "—"}</TableCell>
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
