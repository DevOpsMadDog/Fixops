/**
 * FIPS Compliance Dashboard
 *
 * FIPS 140-3 / PQC readiness — inventory of cryptographic usages,
 * readiness score, and activation of FIPS mode.
 * Route: /fips-compliance
 * API: GET /api/v1/fips/readiness, /pqc-inventory; POST /api/v1/fips/scan, /activate
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, RefreshCw, ScanLine, Lock, AlertTriangle, KeyRound } from "lucide-react";

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

interface Readiness {
  readiness_score?: number;
  fips_mode?: string;
  total_crypto_uses?: number;
  compliant_uses?: number;
  violations?: number;
  pqc_ready?: boolean;
  level?: string;
  activated_at?: string;
}

interface PqcItem {
  id?: string;
  component?: string;
  algorithm?: string;
  usage?: string;
  quantum_vulnerable?: boolean;
  migration_path?: string;
  status?: string;
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function scoreColor(s?: number) {
  const v = s ?? 0;
  if (v >= 80) return "text-green-400";
  if (v >= 60) return "text-yellow-400";
  if (v >= 40) return "text-orange-400";
  return "text-red-400";
}

function scoreBar(s?: number) {
  const v = s ?? 0;
  if (v >= 80) return "bg-green-500";
  if (v >= 60) return "bg-yellow-500";
  if (v >= 40) return "bg-orange-500";
  return "bg-red-500";
}

export default function FipsComplianceDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [activating, setActivating] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [inventory, setInventory] = useState<PqcItem[]>([]);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [r, p] = await Promise.allSettled([
        apiFetch<Readiness>("/api/v1/fips/readiness"),
        apiFetch<PqcItem[] | { items?: PqcItem[]; inventory?: PqcItem[] }>("/api/v1/fips/pqc-inventory"),
      ]);
      setReadiness(r.status === "fulfilled" ? r.value : null);
      if (p.status === "fulfilled") {
        const v = p.value;
        setInventory(Array.isArray(v) ? v : (v.inventory ?? v.items ?? []));
      } else { setInventory([]); }
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleScan = async () => {
    setScanning(true);
    try {
      await apiFetch("/api/v1/fips/scan", { method: "POST", body: JSON.stringify({}) });
      await load();
    } catch (e) { setErr((e as Error).message); }
    finally { setScanning(false); }
  };

  const handleActivate = async () => {
    setActivating(true);
    try {
      await apiFetch("/api/v1/fips/activate", { method: "POST", body: JSON.stringify({ mode: "strict" }) });
      await load();
    } catch (e) { setErr((e as Error).message); }
    finally { setActivating(false); }
  };

  const score = readiness?.readiness_score ?? 0;
  const mode = readiness?.fips_mode ?? "disabled";
  const activated = ["enabled", "strict", "active"].includes(mode.toLowerCase());

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="FIPS 140-3 / PQC Compliance"
        description="Federal cryptographic compliance and post-quantum readiness — inventory, scan, and activate FIPS mode"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button variant="outline" size="sm" onClick={handleScan} disabled={scanning}>
              <ScanLine className={cn("h-4 w-4 mr-2", scanning && "animate-pulse")} />
              Scan Now
            </Button>
            <Button size="sm" onClick={handleActivate} disabled={activating || activated}>
              <ShieldCheck className={cn("h-4 w-4 mr-2", activating && "animate-pulse")} />
              {activated ? "FIPS Active" : "Activate FIPS"}
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Readiness Score" value={`${score}/100`} icon={ShieldCheck} trend={score >= 80 ? "up" : "down"} />
        <KpiCard title="FIPS Mode" value={mode} icon={Lock} trendLabel={activated ? "Active" : "Inactive"} trend={activated ? "up" : "flat"} />
        <KpiCard title="Crypto Uses" value={readiness?.total_crypto_uses ?? 0} icon={KeyRound} />
        <KpiCard title="Violations" value={readiness?.violations ?? 0} icon={AlertTriangle} trend={(readiness?.violations ?? 0) > 0 ? "down" : "flat"} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> Compliance Gauge</CardTitle>
          <CardDescription className="text-xs">FIPS 140-3 readiness across all detected cryptographic usage</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-end justify-between">
            <div className={cn("text-4xl font-bold", scoreColor(score))}>{score}<span className="text-lg text-muted-foreground">/100</span></div>
            <div className="text-right text-xs text-muted-foreground">
              <div>Compliant: <span className="text-green-400 font-semibold">{readiness?.compliant_uses ?? 0}</span></div>
              <div>PQC-ready: <span className={cn("font-semibold", readiness?.pqc_ready ? "text-green-400" : "text-orange-400")}>{readiness?.pqc_ready ? "Yes" : "Partial"}</span></div>
            </div>
          </div>
          <div className="w-full bg-muted rounded-full h-2.5">
            <div className={cn("h-2.5 rounded-full transition-all", scoreBar(score))} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
          </div>
          {readiness?.level && (
            <div className="text-xs text-muted-foreground">Target level: <span className="font-semibold text-foreground">{readiness.level}</span></div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><KeyRound className="h-4 w-4" /> PQC Inventory</CardTitle>
          <CardDescription className="text-xs">Cryptographic components and their quantum-resistance status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading inventory…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : inventory.length === 0 ? (
            <EmptyState icon={KeyRound} title="No crypto usage indexed" description="Run a scan to inventory your cryptographic components." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Component</TableHead>
                    <TableHead className="text-[11px] h-8">Algorithm</TableHead>
                    <TableHead className="text-[11px] h-8">Usage</TableHead>
                    <TableHead className="text-[11px] h-8">Quantum</TableHead>
                    <TableHead className="text-[11px] h-8">Migration</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {inventory.map((it, i) => (
                    <TableRow key={it.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{it.component ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{it.algorithm ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{it.usage ?? "—"}</TableCell>
                      <TableCell className="py-2">
                        {it.quantum_vulnerable ? (
                          <Badge className="text-[10px] border border-red-500/30 text-red-300 bg-red-500/10">Vulnerable</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-green-500/30 text-green-300 bg-green-500/10">Safe</Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground font-mono">{it.migration_path ?? "—"}</TableCell>
                      <TableCell className="py-2 text-right text-[11px] capitalize">{it.status ?? "—"}</TableCell>
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
