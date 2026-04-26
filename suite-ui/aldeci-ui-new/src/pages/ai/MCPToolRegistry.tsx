/**
 * MCP Tool Registry
 *
 * Catalog of MCP tools (and AI agents) available in this deployment.
 * Route: /ai/mcp-registry
 * API: primary GET /api/v1/mcp-protocol/tools, fallback GET /api/v1/agents
 * Multica id: 55bf9576-53a6-4a6e-94b1-05cf0842ba40
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Plug, RefreshCw, Hammer, Bot } from "lucide-react";

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

interface MCPTool {
  id?: string;
  name?: string;
  description?: string;
  server?: string;
  category?: string;
  capabilities?: string[];
  status?: string;
  invoked_count?: number;
  source?: "tool" | "agent";
}
interface MCPResponse {
  tools?: MCPTool[];
  items?: MCPTool[];
  agents?: MCPTool[];
  total?: number;
  comingSoon?: boolean;
}

async function apiFetch<T>(path: string): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" } });
  if (res.status === 501) return { data: { comingSoon: true } as T, status: 501 };
  if (res.status === 404) return { data: { comingSoon: true } as T, status: 404 };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

const statusColor: Record<string, string> = {
  active: "border-green-500/30 text-green-400 bg-green-500/10",
  registered: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  inactive: "border-gray-500/30 text-gray-400 bg-gray-500/10",
  error: "border-red-500/30 text-red-400 bg-red-500/10",
};

export default function MCPToolRegistry() {
  const [tools, setTools] = useState<MCPTool[]>([]);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      // Try primary endpoint first
      const { data, status } = await apiFetch<MCPResponse>("/api/v1/mcp-protocol/tools");
      if (status === 501 || status === 404 || data.comingSoon) {
        // Fallback to /api/v1/agents
        const { data: a } = await apiFetch<MCPResponse>("/api/v1/agents");
        if (a.comingSoon) {
          setComingSoon(true);
          setTools([]);
        } else {
          const list = Array.isArray(a) ? (a as MCPTool[]) : (a.agents ?? a.items ?? a.tools ?? []);
          setTools(list.map((t) => ({ ...t, source: "agent" })));
        }
      } else {
        const list = Array.isArray(data) ? (data as MCPTool[]) : (data.tools ?? data.items ?? []);
        setTools(list.map((t) => ({ ...t, source: "tool" })));
      }
    } catch (e) {
      setErr((e as Error).message);
      setTools([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const total = tools.length;
  const active = tools.filter((t) => (t.status ?? "").toLowerCase() === "active" || (t.status ?? "").toLowerCase() === "registered").length;
  const totalInvocations = tools.reduce((s, t) => s + (t.invoked_count ?? 0), 0);
  const categories = new Set(tools.map((t) => t.category).filter(Boolean)).size;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="MCP Tool Registry"
        description="Catalog of MCP tools and AI agents available in this deployment"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      {!comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="Registered Tools" value={total} icon={Plug} />
          <KpiCard title="Active" value={active} icon={Bot} />
          <KpiCard title="Categories" value={categories} icon={Hammer} />
          <KpiCard title="Total Invocations" value={totalInvocations} icon={Hammer} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Registry</CardTitle>
          <CardDescription className="text-xs">Tools and agents reachable via MCP</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading registry…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={Plug} title="Coming soon" description="No MCP tools or agents endpoint is available on this deployment." />
          ) : tools.length === 0 ? (
            <EmptyState icon={Plug} title="No tools registered" description="No MCP tools or agents have been registered yet." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Name</TableHead>
                    <TableHead className="text-[11px] h-8">Description</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Server</TableHead>
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Invocations</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tools.slice(0, 200).map((t, i) => (
                    <TableRow key={t.id ?? `${t.name}-${i}`} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{t.name ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground truncate max-w-sm">{t.description ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{t.category ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{t.server ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px] border border-border capitalize">{t.source ?? "tool"}</Badge></TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", statusColor[(t.status ?? "").toLowerCase()] ?? "border-border")}>{t.status ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-right">{t.invoked_count ?? 0}</TableCell>
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
