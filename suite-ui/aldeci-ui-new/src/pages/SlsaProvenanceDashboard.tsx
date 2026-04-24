/**
 * SLSA Provenance Dashboard
 *
 * SLSA-compliant build provenance attestations. View existing attestations and
 * produce a new one for a given artifact.
 * Route: /slsa-provenance
 * API: GET /api/v1/slsa/attestations, /stats; POST /api/v1/slsa/attest
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, RefreshCw, FileCheck, Lock, Stamp, Layers } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Stats {
  total_attestations?: number;
  verified?: number;
  level_3_plus?: number;
  latest?: string;
}

interface Attestation {
  id?: string;
  attestation_id?: string;
  subject?: string;
  builder?: string;
  slsa_level?: number;
  verified?: boolean;
  signature?: string;
  digest?: string;
  created_at?: string;
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

function formatTs(ts?: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return ts; }
}

function levelColor(l?: number) {
  if ((l ?? 0) >= 4) return "border-emerald-500/30 text-emerald-300 bg-emerald-500/10";
  if ((l ?? 0) >= 3) return "border-green-500/30 text-green-300 bg-green-500/10";
  if ((l ?? 0) >= 2) return "border-blue-500/30 text-blue-300 bg-blue-500/10";
  if ((l ?? 0) >= 1) return "border-amber-500/30 text-amber-300 bg-amber-500/10";
  return "border-muted/60 text-muted-foreground";
}

export default function SlsaProvenanceDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [attesting, setAttesting] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [atts, setAtts] = useState<Attestation[]>([]);
  const [subject, setSubject] = useState("");
  const [builder, setBuilder] = useState("");
  const [level, setLevel] = useState("3");

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [s, a] = await Promise.allSettled([
        apiFetch<Stats>("/api/v1/slsa/stats"),
        apiFetch<Attestation[] | { attestations?: Attestation[]; items?: Attestation[] }>("/api/v1/slsa/attestations"),
      ]);
      setStats(s.status === "fulfilled" ? s.value : null);
      if (a.status === "fulfilled") {
        const v = a.value;
        setAtts(Array.isArray(v) ? v : (v.attestations ?? v.items ?? []));
      } else { setAtts([]); }
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleAttest = async () => {
    if (!subject.trim()) return;
    setAttesting(true);
    try {
      await apiFetch("/api/v1/slsa/attest", {
        method: "POST",
        body: JSON.stringify({
          subject: subject.trim(),
          builder: builder.trim() || "aldeci-ci",
          slsa_level: parseInt(level, 10) || 3,
        }),
      });
      setSubject("");
      await load();
    } catch (e) { setErr((e as Error).message); }
    finally { setAttesting(false); }
  };

  const total = stats?.total_attestations ?? atts.length;
  const verified = stats?.verified ?? atts.filter(a => a.verified).length;
  const l3plus = stats?.level_3_plus ?? atts.filter(a => (a.slsa_level ?? 0) >= 3).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="SLSA Provenance"
        description="SLSA-level build provenance attestations — cryptographically signed, verifiable chain of custody"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Attestations" value={total} icon={FileCheck} />
        <KpiCard title="Verified" value={verified} icon={ShieldCheck} trend="up" />
        <KpiCard title="SLSA ≥ L3" value={l3plus} icon={Layers} trend="up" />
        <KpiCard title="Latest" value={formatTs(stats?.latest ?? atts[0]?.created_at)} icon={Lock} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Stamp className="h-4 w-4" /> Create Attestation</CardTitle>
          <CardDescription className="text-xs">Issue a new SLSA provenance attestation for an artifact</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <Input value={subject} onChange={e => setSubject(e.target.value)} placeholder="subject (artifact digest or name)" className="h-9 text-xs font-mono sm:col-span-2" />
            <Input value={builder} onChange={e => setBuilder(e.target.value)} placeholder="builder id" className="h-9 text-xs font-mono" />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">SLSA Level:</span>
            {["1", "2", "3", "4"].map(l => (
              <button
                key={l}
                onClick={() => setLevel(l)}
                className={cn(
                  "h-7 rounded-md border px-3 text-xs font-medium transition-colors",
                  level === l ? "border-primary bg-primary/20 text-primary" : "border-border text-muted-foreground hover:bg-muted/40"
                )}
              >
                L{l}
              </button>
            ))}
            <div className="flex-1" />
            <Button size="sm" onClick={handleAttest} disabled={attesting || !subject.trim()}>
              <Stamp className={cn("h-4 w-4 mr-2", attesting && "animate-pulse")} />
              Attest
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><FileCheck className="h-4 w-4" /> Attestations</CardTitle>
          <CardDescription className="text-xs">Signed provenance records — each proves who/how/when the artifact was built</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading attestations…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : atts.length === 0 ? (
            <EmptyState icon={FileCheck} title="No attestations" description="Issue your first attestation above." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Subject</TableHead>
                    <TableHead className="text-[11px] h-8">Builder</TableHead>
                    <TableHead className="text-[11px] h-8">SLSA</TableHead>
                    <TableHead className="text-[11px] h-8">Digest</TableHead>
                    <TableHead className="text-[11px] h-8">Verified</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {atts.map((a, i) => (
                    <TableRow key={a.id ?? a.attestation_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono truncate max-w-[220px]">{a.subject ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{a.builder ?? "—"}</TableCell>
                      <TableCell className="py-2">
                        <Badge className={cn("text-[10px] border", levelColor(a.slsa_level))}>L{a.slsa_level ?? "?"}</Badge>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{(a.digest ?? "—").slice(0, 12)}</TableCell>
                      <TableCell className="py-2">
                        {a.verified ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Verified</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">Pending</Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground text-right">{formatTs(a.created_at)}</TableCell>
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
