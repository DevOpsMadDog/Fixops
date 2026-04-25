/**
 * PKI Management Dashboard - Live API
 * Route: /pki-management
 * API: GET /api/v1/pki/{stats,certificates,cas}
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { KeyRound, RefreshCw, CheckCircle, AlertTriangle, XCircle, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const statusColor: Record<string, string> = {
  active: "bg-emerald-500/20 text-emerald-400",
  expiring: "bg-amber-500/20 text-amber-400",
  expired: "bg-red-500/20 text-red-400",
  revoked: "bg-gray-500/20 text-gray-400",
};

export default function PKIManagementDashboard() {
  const [certs, setCerts] = useState<any[]>([]);
  const [cas, setCAs] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [c, ca, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/pki/certificates"),
        apiFetch<any>("/api/v1/pki/cas"),
        apiFetch<any>("/api/v1/pki/stats"),
      ]);
      if (c.status === "fulfilled") { const v = c.value as any; setCerts(Array.isArray(v) ? v : (v.certificates ?? v.items ?? [])); }
      if (ca.status === "fulfilled") { const v = ca.value as any; setCAs(Array.isArray(v) ? v : (v.cas ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="PKI Management"
        description="Certificate lifecycle and CA hierarchy"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : certs.length === 0 && cas.length === 0 ? <EmptyState icon={KeyRound} title="No PKI data" description="Configure CAs to start tracking certificates." />
        : <>
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Total Certs" value={stats?.total_certs ?? certs.length} icon={KeyRound} />
            <KpiCard title="Active" value={stats?.active_certs ?? certs.filter(c => c.status === "active").length} icon={CheckCircle} />
            <KpiCard title="Expiring (30d)" value={stats?.expiring_30d ?? 0} icon={AlertTriangle} />
            <KpiCard title="Revoked" value={stats?.revoked_certs ?? certs.filter(c => c.status === "revoked").length} icon={XCircle} />
          </motion.div>
          <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Certificates</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow className="border-gray-700/50"><TableHead>Common Name</TableHead><TableHead>Issuer</TableHead><TableHead>Status</TableHead><TableHead>Expiry</TableHead><TableHead>Algorithm</TableHead></TableRow></TableHeader>
                <TableBody>{certs.map(c => (
                  <TableRow key={c.id ?? c.serial} className="border-b border-gray-700/50">
                    <TableCell className="text-sm font-mono text-gray-200">{c.cn ?? c.common_name ?? c.subject}</TableCell>
                    <TableCell className="text-xs text-gray-400">{c.issuer ?? "—"}</TableCell>
                    <TableCell><span className={cn("px-2 py-0.5 rounded text-xs font-medium capitalize", statusColor[c.status] ?? "bg-gray-700 text-gray-300")}>{c.status}</span></TableCell>
                    <TableCell className="text-xs text-gray-400">{c.expires_at ?? c.expiry ?? "—"}</TableCell>
                    <TableCell className="text-xs text-gray-400 font-mono">{c.algorithm ?? "—"}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>
          {cas.length > 0 && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-cyan-400" /> Certificate Authorities</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow className="border-gray-700/50"><TableHead>CA Name</TableHead><TableHead>Type</TableHead><TableHead>Issued</TableHead><TableHead>Expires</TableHead></TableRow></TableHeader>
                <TableBody>{cas.map(ca => (
                  <TableRow key={ca.id ?? ca.name} className="border-b border-gray-700/50">
                    <TableCell className="text-sm font-mono text-gray-200">{ca.name ?? ca.cn}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs">{ca.ca_type ?? ca.type ?? "—"}</Badge></TableCell>
                    <TableCell className="text-xs text-gray-400">{ca.issued_count ?? 0}</TableCell>
                    <TableCell className="text-xs text-gray-400">{ca.expires_at ?? "—"}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
