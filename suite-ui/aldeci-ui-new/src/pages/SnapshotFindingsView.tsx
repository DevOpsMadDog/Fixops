// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Snapshot Findings View — kick off a CSPM snapshot scan and view findings (Wave 3)
 * Route: /snapshot-findings
 * API:   POST /api/v1/cspm/snapshot-scan
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Camera, Play, ShieldAlert, Server, Loader2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ScanFinding {
  id?: string;
  title?: string;
  severity?: string;
  resource?: string;
  resource_id?: string;
  cve?: string;
  rule_id?: string;
  category?: string;
}
interface ScanResponse {
  scan_id?: string;
  status?: string;
  resources_scanned?: number;
  findings?: ScanFinding[];
  duration_ms?: number;
}

async function apiPost<T>(path: string, body: unknown): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
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

export default function SnapshotFindingsView() {
  const [cloud, setCloud] = useState("aws");
  const [account, setAccount] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [data, setData] = useState<ScanResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const run = async () => {
    setErr(null);
    setRunning(true);
    setComingSoon(false);
    try {
      const r = await apiPost<ScanResponse>("/api/v1/cspm/snapshot-scan", {
        cloud, account_id: account.trim(), region,
      });
      if (!r) {
        setComingSoon(true);
        setData(null);
      } else {
        setData(r);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const findings = data?.findings ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Snapshot Findings"
        description="Trigger a point-in-time CSPM snapshot scan and surface posture findings"
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Camera className="h-4 w-4" /> Snapshot Scan
          </CardTitle>
          <CardDescription className="text-xs">Posture scan against cloud account in selected region</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4 items-end">
            <div className="space-y-1">
              <Label className="text-[11px] text-muted-foreground">Cloud</Label>
              <Select value={cloud} onValueChange={setCloud}>
                <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="aws">AWS</SelectItem>
                  <SelectItem value="gcp">GCP</SelectItem>
                  <SelectItem value="azure">Azure</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-[11px] text-muted-foreground">Account / Subscription ID</Label>
              <Input value={account} onChange={(e) => setAccount(e.target.value)} className="h-8 text-xs font-mono" placeholder="123456789012" />
            </div>
            <div className="space-y-1">
              <Label className="text-[11px] text-muted-foreground">Region</Label>
              <Input value={region} onChange={(e) => setRegion(e.target.value)} className="h-8 text-xs font-mono" />
            </div>
            <Button size="sm" onClick={run} disabled={running || !account.trim()} className="h-8">
              {running ? <Loader2 className="h-3 w-3 mr-2 animate-spin" /> : <Play className="h-3 w-3 mr-2" />}
              {running ? "Scanning…" : "Run Scan"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Resources Scanned" value={data?.resources_scanned ?? 0} icon={Server} />
        <KpiCard title="Findings" value={findings.length} icon={ShieldAlert} />
        <KpiCard title="Critical" value={findings.filter((f) => (f.severity ?? "").toLowerCase() === "critical").length} icon={ShieldAlert} trend="down" />
        <KpiCard title="Scan ID" value={data?.scan_id?.slice(0, 8) ?? "—"} icon={Camera} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Findings</CardTitle>
          <CardDescription className="text-xs">{data?.status ? `Status: ${data.status}` : "Run a scan to populate"}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {err ? (
            <ErrorState message={err} onRetry={run} />
          ) : comingSoon ? (
            <EmptyState icon={Camera} title="Coming soon" description="The CSPM snapshot-scan endpoint is not yet enabled in this build." />
          ) : !data ? (
            <EmptyState icon={Camera} title="No scan yet" description="Enter an account ID and click Run Scan to discover posture findings." />
          ) : findings.length === 0 ? (
            <EmptyState icon={Camera} title="No findings" description="Snapshot completed without surfacing any findings." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Resource</TableHead>
                    <TableHead className="text-[11px] h-8">Rule / CVE</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Category</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.map((f, i) => (
                    <TableRow key={(f.id ?? "f") + i} className="hover:bg-muted/30">
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", sevColor(f.severity))}>{f.severity ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] max-w-[280px] truncate">{f.title ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{f.resource ?? f.resource_id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{f.rule_id ?? f.cve ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{f.category ?? "—"}</TableCell>
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
