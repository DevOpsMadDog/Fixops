// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Toxic Combination Issue View (Wave 3)
 * Route: /issues/toxic
 * API:   GET /api/v1/issues/toxic
 *
 * Surfaces multi-finding "toxic combinations" (e.g. public bucket + writable IAM + sensitive data).
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { FlaskConical, RefreshCw, AlertTriangle, ChevronDown, ChevronRight, Link2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ToxicComponent {
  finding_id?: string;
  title?: string;
  severity?: string;
  asset?: string;
}
interface ToxicIssue {
  id?: string;
  title?: string;
  combo_type?: string;
  severity?: string;
  blast_radius?: number;
  components?: ToxicComponent[];
  recommendation?: string;
  created_at?: string;
}
interface Response {
  issues?: ToxicIssue[];
  items?: ToxicIssue[];
  total?: number;
}

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function sevColor(s?: string) {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "border-red-500/30 text-red-400 bg-red-500/10";
    case "high": return "border-orange-500/30 text-orange-400 bg-orange-500/10";
    case "medium": return "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
    case "low": return "border-green-500/30 text-green-400 bg-green-500/10";
    default: return "border-border";
  }
}

export default function ToxicCombinationIssueView() {
  const [issues, setIssues] = useState<ToxicIssue[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);
  const [openIds, setOpenIds] = useState<Set<string>>(new Set());

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    setComingSoon(false);
    try {
      const r = await apiFetch<Response>("/api/v1/issues/toxic");
      if (!r) {
        setComingSoon(true);
        setIssues([]);
      } else {
        setIssues(r.issues ?? r.items ?? []);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const toggle = (id: string) => {
    setOpenIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Toxic Combinations"
        description="Multi-finding security issues where individually-acceptable risks combine into a critical exposure"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Toxic Issues" value={issues.length} icon={FlaskConical} trend="down" />
        <KpiCard title="Critical" value={issues.filter((i) => (i.severity ?? "").toLowerCase() === "critical").length} icon={AlertTriangle} />
        <KpiCard title="Total Components" value={issues.reduce((s, i) => s + (i.components?.length ?? 0), 0)} icon={Link2} />
        <KpiCard title="Avg Blast" value={issues.length > 0 ? Math.round(issues.reduce((s, i) => s + (i.blast_radius ?? 0), 0) / issues.length) : 0} icon={AlertTriangle} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <FlaskConical className="h-4 w-4" /> Detected Combinations
          </CardTitle>
          <CardDescription className="text-xs">Click an issue to inspect contributing findings</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={FlaskConical} title="Coming soon" description="The toxic-combination correlator endpoint is not yet enabled." />
          ) : issues.length === 0 ? (
            <EmptyState icon={FlaskConical} title="No toxic combinations" description="Run the correlation engine to detect compound risks." />
          ) : (
            <div className="space-y-2">
              {issues.map((iss, idx) => {
                const id = iss.id ?? `i${idx}`;
                const open = openIds.has(id);
                return (
                  <Collapsible key={id} open={open} onOpenChange={() => toggle(id)}>
                    <div className="rounded-md border border-border/60 bg-muted/20">
                      <CollapsibleTrigger className="w-full flex items-start gap-2 p-3 hover:bg-muted/40 text-left">
                        {open ? <ChevronDown className="h-4 w-4 mt-0.5 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 mt-0.5 text-muted-foreground" />}
                        <div className="flex-1 space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-semibold">{iss.title ?? "Toxic combination"}</span>
                            <Badge className={cn("text-[10px] border capitalize", sevColor(iss.severity))}>{iss.severity ?? "—"}</Badge>
                            {iss.combo_type && <Badge className="text-[10px] border border-border">{iss.combo_type}</Badge>}
                            <span className="text-[11px] text-muted-foreground">{iss.components?.length ?? 0} components</span>
                          </div>
                          {iss.recommendation && (
                            <p className="text-[11px] text-muted-foreground line-clamp-2">{iss.recommendation}</p>
                          )}
                        </div>
                      </CollapsibleTrigger>
                      <CollapsibleContent className="px-3 pb-3">
                        {!iss.components || iss.components.length === 0 ? (
                          <p className="text-xs text-muted-foreground">No component findings recorded.</p>
                        ) : (
                          <ul className="space-y-1 text-[11px] mt-2 pl-6 border-l border-border/40">
                            {iss.components.map((c, i) => (
                              <li key={(c.finding_id ?? "c") + i} className="flex items-center gap-2">
                                <Badge className={cn("text-[10px] border capitalize", sevColor(c.severity))}>{c.severity ?? "—"}</Badge>
                                <span className="font-mono text-muted-foreground">{c.finding_id?.slice(0, 8) ?? "—"}</span>
                                <span className="flex-1 truncate">{c.title ?? "(untitled)"}</span>
                                {c.asset && <span className="text-muted-foreground">{c.asset}</span>}
                              </li>
                            ))}
                          </ul>
                        )}
                      </CollapsibleContent>
                    </div>
                  </Collapsible>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
