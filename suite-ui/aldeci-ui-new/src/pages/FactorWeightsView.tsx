/**
 * Factor Weights View — global scoring formula (Wave 3)
 * Route: /factor-weights
 * API:   GET /api/v1/scoring/formula
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Scale, RefreshCw, FunctionSquare } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Factor {
  name?: string;
  weight?: number;
  description?: string;
  source?: string;
  units?: string;
}
interface Formula {
  formula_id?: string;
  version?: string;
  expression?: string;
  factors?: Factor[];
  updated_at?: string;
  approver?: string;
  notes?: string;
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

export default function FactorWeightsView() {
  const [formula, setFormula] = useState<Formula | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    setComingSoon(false);
    try {
      const r = await apiFetch<Formula>("/api/v1/scoring/formula");
      if (!r) {
        setComingSoon(true);
        setFormula(null);
      } else {
        setFormula(r);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const totalWeight = (formula?.factors ?? []).reduce((s, f) => s + Math.abs(f.weight ?? 0), 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Scoring Formula & Factor Weights"
        description="The exact formula used to compute every risk score across the platform"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Factors" value={formula?.factors?.length ?? 0} icon={Scale} />
        <KpiCard title="Total Weight" value={totalWeight.toFixed(2)} icon={FunctionSquare} />
        <KpiCard title="Version" value={formula?.version ?? "—"} icon={Scale} />
        <KpiCard title="Updated" value={formula?.updated_at?.slice(0, 10) ?? "—"} icon={Scale} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <FunctionSquare className="h-4 w-4" /> Formula
          </CardTitle>
          <CardDescription className="text-xs">{formula?.formula_id ?? "(global)"}{formula?.approver ? ` · approved by ${formula.approver}` : ""}</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={FunctionSquare} title="Coming soon" description="The scoring-formula endpoint is not yet enabled in this build." />
          ) : !formula ? (
            <EmptyState icon={FunctionSquare} title="No formula configured" description="Set up a scoring formula via the policy engine." />
          ) : (
            <div className="space-y-4">
              <pre className="rounded-md bg-muted/40 p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap">
                {formula.expression ?? "(no symbolic expression provided)"}
              </pre>
              {formula.notes && <p className="text-xs text-muted-foreground">{formula.notes}</p>}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Scale className="h-4 w-4" /> Factor Weights
          </CardTitle>
          <CardDescription className="text-xs">Each factor's contribution to the final score</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {!formula?.factors || formula.factors.length === 0 ? (
            <EmptyState icon={Scale} title="No factors" description="Configure factors in the scoring engine to populate this view." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Factor</TableHead>
                    <TableHead className="text-[11px] h-8">Weight</TableHead>
                    <TableHead className="text-[11px] h-8">% of total</TableHead>
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                    <TableHead className="text-[11px] h-8">Units</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {formula.factors.map((f, i) => {
                    const pct = totalWeight > 0 ? (Math.abs(f.weight ?? 0) / totalWeight) * 100 : 0;
                    return (
                      <TableRow key={(f.name ?? "f") + i} className="hover:bg-muted/30">
                        <TableCell className="py-2 text-[11px]">
                          <div className="font-semibold">{f.name ?? "—"}</div>
                          {f.description && <div className="text-muted-foreground text-[10px]">{f.description}</div>}
                        </TableCell>
                        <TableCell className="py-2 text-[11px] font-mono">{f.weight?.toFixed(3) ?? "—"}</TableCell>
                        <TableCell className="py-2">
                          <div className="flex items-center gap-2">
                            <Progress value={pct} className="h-1 w-24" />
                            <span className="text-[11px] font-mono w-12 text-right">{pct.toFixed(1)}%</span>
                          </div>
                        </TableCell>
                        <TableCell className="py-2 text-[11px] text-muted-foreground">{f.source ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] text-muted-foreground">
                          {f.units && <Badge className="text-[10px] border border-border">{f.units}</Badge>}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
