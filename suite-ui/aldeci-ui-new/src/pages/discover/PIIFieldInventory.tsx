// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * PII Field Inventory
 *
 * List findings labelled as PII (best-effort filter on findings endpoint).
 * Route: /discover/pii-inventory
 * API: GET /api/v1/findings?label=pii (best-effort)
 * Multica id: 3ee3abd4-550e-45ad-a8bd-64ad3b9295b6
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, RefreshCw, Lock } from "lucide-react";

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

interface PIIFinding {
  id?: string;
  finding_id?: string;
  title?: string;
  field?: string;
  pii_type?: string;       // SSN, email, phone, credit_card …
  data_class?: string;
  asset?: string;
  service?: string;
  severity?: string;
  status?: string;
  detected_at?: string;
  labels?: string[];
  scanner?: string;
  source?: string;
}

interface FindingsResponse {
  findings?: PIIFinding[];
  items?: PIIFinding[];
  data?: PIIFinding[];
  total?: number;
  comingSoon?: boolean;
}

async function apiFetch<T>(path: string, params: Record<string, string> = {}): Promise<{ data: T; status: number }> {
  const orgId = getStoredOrgId();
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" } });
  if (res.status === 501 || res.status === 404) return { data: { comingSoon: true } as T, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

const sevColor: Record<string, string> = {
  critical: "border-red-500/30 text-red-400 bg-red-500/10",
  high: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  medium: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  low: "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

function isPii(f: PIIFinding): boolean {
  const labels = (f.labels ?? []).map((l) => l.toLowerCase());
  if (labels.includes("pii")) return true;
  if ((f.pii_type ?? "").length > 0) return true;
  if ((f.data_class ?? "").toLowerCase().includes("pii")) return true;
  const hay = `${f.title ?? ""} ${f.field ?? ""}`.toLowerCase();
  return /ssn|social.security|credit[\s_-]?card|email|phone|passport|dob|date.of.birth|address|pii/.test(hay);
}

export default function PIIFieldInventory() {
  const [findings, setFindings] = useState<PIIFinding[]>([]);
  const [comingSoon, setComingSoon] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setLoading(true);
    setComingSoon(false);
    try {
      // Best-effort label filter; backend may ignore unknown filter and return everything.
      let { data, status } = await apiFetch<FindingsResponse>("/api/v1/findings", { label: "pii" });
      // If endpoint doesn't exist, try analytics findings as fallback
      if (status === 404 || status === 501 || data.comingSoon) {
        const fb = await apiFetch<FindingsResponse>("/api/v1/analytics/findings");
        data = fb.data;
        if (data.comingSoon) {
          setComingSoon(true);
          setFindings([]);
          return;
        }
      }
      const list = Array.isArray(data) ? (data as PIIFinding[]) : (data.findings ?? data.items ?? data.data ?? []);
      // Client-side filter: keep only PII-labelled or PII-matching findings
      const pii = list.filter(isPii);
      setFindings(pii);
    } catch (e) {
      setErr((e as Error).message);
      setFindings([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const total = findings.length;
  const open = findings.filter((f) => (f.status ?? "").toLowerCase() === "open").length;
  const piiTypes = new Set(findings.map((f) => f.pii_type).filter(Boolean)).size;
  const services = new Set(findings.map((f) => f.service ?? f.asset).filter(Boolean)).size;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="PII Field Inventory"
        description="Findings tagged as PII or referencing protected data fields"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      {!comingSoon && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <KpiCard title="PII Findings" value={total} icon={ShieldAlert} />
          <KpiCard title="Open" value={open} icon={Lock} trend={open ? "up" : "flat"} />
          <KpiCard title="PII Types" value={piiTypes} icon={Lock} />
          <KpiCard title="Services Affected" value={services} icon={ShieldAlert} />
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Inventory</CardTitle>
          <CardDescription className="text-xs">Filtered from /api/v1/findings (best-effort, label=pii)</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Scanning findings…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={ShieldAlert} title="Coming soon" description="No findings endpoint is available on this deployment." />
          ) : findings.length === 0 ? (
            <EmptyState icon={ShieldAlert} title="No PII findings" description="No findings are currently labelled as PII." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Field</TableHead>
                    <TableHead className="text-[11px] h-8">PII Type</TableHead>
                    <TableHead className="text-[11px] h-8">Asset / Service</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Scanner</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.slice(0, 200).map((f, i) => (
                    <TableRow key={f.id ?? f.finding_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] truncate max-w-sm">{f.title ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{f.field ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px]">{f.pii_type ?? f.data_class ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{f.service ?? f.asset ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", sevColor[(f.severity ?? "").toLowerCase()] ?? "border-border")}>{f.severity ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] capitalize text-muted-foreground">{(f.status ?? "—").replace("_", " ")}</TableCell>
                      <TableCell className="py-2 text-[10px] text-muted-foreground">{f.scanner ?? f.source ?? "—"}</TableCell>
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
