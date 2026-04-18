/**
 * PKI Management Dashboard
 *
 * Public Key Infrastructure — certificate lifecycle and CA hierarchy management.
 *   1. KPI cards: Total Certs, Active, Expiring (30d), Revoked
 *   2. Certificates table
 *   3. Certificate Authorities table
 *
 * API: GET /api/v1/pki/{stats,certificates,cas}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  KeyRound, RefreshCw, CheckCircle, AlertTriangle, XCircle, ShieldCheck,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_certs: 284,
  active_certs: 251,
  expiring_30d: 17,
  revoked_certs: 11,
};

const MOCK_CERTS = [
  { common_name: "api.aldeci.internal",     cert_type: "server",   key_algorithm: "RSA-2048",   status: "active",   expires_at: "2026-09-12" },
  { common_name: "auth.aldeci.internal",    cert_type: "server",   key_algorithm: "ECDSA-P256", status: "active",   expires_at: "2026-07-31" },
  { common_name: "vpn.corp.example.com",    cert_type: "server",   key_algorithm: "RSA-4096",   status: "expiring", expires_at: "2026-05-02" },
  { common_name: "john.doe@example.com",    cert_type: "client",   key_algorithm: "RSA-2048",   status: "active",   expires_at: "2027-01-15" },
  { common_name: "code-signing.aldeci",     cert_type: "codesign", key_algorithm: "ECDSA-P384", status: "active",   expires_at: "2026-12-01" },
  { common_name: "legacy.app.corp",         cert_type: "server",   key_algorithm: "RSA-1024",   status: "revoked",  expires_at: "2025-06-30" },
  { common_name: "*.prod.aldeci.io",        cert_type: "wildcard", key_algorithm: "RSA-2048",   status: "expiring", expires_at: "2026-04-28" },
  { common_name: "db.aldeci.internal",      cert_type: "server",   key_algorithm: "ECDSA-P256", status: "active",   expires_at: "2026-10-22" },
];

const MOCK_CAS = [
  { name: "ALDECI Root CA",        ca_type: "root",         subject: "CN=ALDECI Root CA, O=ALDECI Inc",         status: "active", cert_count: 3   },
  { name: "ALDECI Issuing CA 1",   ca_type: "intermediate", subject: "CN=ALDECI Issuing CA 1, O=ALDECI Inc",    status: "active", cert_count: 142 },
  { name: "ALDECI Issuing CA 2",   ca_type: "intermediate", subject: "CN=ALDECI Issuing CA 2, O=ALDECI Inc",    status: "active", cert_count: 98  },
  { name: "ALDECI Client Auth CA", ca_type: "intermediate", subject: "CN=ALDECI Client Auth CA, O=ALDECI Inc",  status: "active", cert_count: 41  },
  { name: "Legacy Root CA",        ca_type: "root",         subject: "CN=Legacy Root CA, O=OldCorp",            status: "deprecated", cert_count: 0 },
];

// ── Badge helpers ──────────────────────────────────────────────

function CertTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    server:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    client:   "border-green-500/30 text-green-400 bg-green-500/10",
    codesign: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    wildcard: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    root:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function CertStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:     "border-green-500/30 text-green-400 bg-green-500/10",
    expiring:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    expired:    "border-red-500/30 text-red-400 bg-red-500/10",
    revoked:    "border-red-500/30 text-red-400 bg-red-500/10",
    deprecated: "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function KeyAlgoBadge({ algo }: { algo: string }) {
  const isWeak = algo.includes("RSA-1024") || algo.includes("RSA-512");
  return (
    <Badge className={cn(
      "text-[10px] border font-mono",
      isWeak
        ? "border-red-500/30 text-red-400 bg-red-500/10"
        : "border-gray-500/30 text-gray-400 bg-gray-500/10"
    )}>
      {algo}
    </Badge>
  );
}

function CATypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    root:         "border-purple-500/30 text-purple-400 bg-purple-500/10",
    intermediate: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function daysUntil(dateStr: string): number {
  const diff = new Date(dateStr).getTime() - Date.now();
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

function expiryColor(dateStr: string, status: string): string {
  if (status === "revoked" || status === "expired") return "text-red-400";
  const days = daysUntil(dateStr);
  if (days <= 30) return "text-amber-400";
  if (days <= 90) return "text-yellow-400";
  return "text-muted-foreground";
}

// ── Component ──────────────────────────────────────────────────

export default function PKIManagementDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    certs: any[] | null;
    cas: any[] | null;
  }>({ stats: null, certs: null, cas: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/pki/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/pki/certificates?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/pki/cas?org_id=${ORG_ID}`),
    ]).then(([statsRes, certsRes, casRes]) => {
      setLiveData({
        stats: statsRes.status === "fulfilled" ? statsRes.value : null,
        certs: certsRes.status === "fulfilled" ? certsRes.value : null,
        cas:   casRes.status   === "fulfilled" ? casRes.value   : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats = liveData.stats ?? MOCK_STATS;
  const certs = liveData.certs ?? MOCK_CERTS;
  const cas   = liveData.cas   ?? MOCK_CAS;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="PKI Management"
        description="Public Key Infrastructure — certificate lifecycle, CA hierarchy, and expiry tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Certs"     value={stats.total_certs}    icon={KeyRound}     trend="flat" />
        <KpiCard title="Active"          value={stats.active_certs}   icon={CheckCircle}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Expiring (30d)"  value={stats.expiring_30d}   icon={AlertTriangle} trend="down" className="border-amber-500/20" />
        <KpiCard title="Revoked"         value={stats.revoked_certs}  icon={XCircle}      trend="flat" className="border-red-500/20" />
      </div>

      {/* Certificates Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-blue-400" />
              Certificates
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {certs.length} records
            </Badge>
          </div>
          <CardDescription className="text-xs">Certificate inventory with key algorithm, status, and expiry dates</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Common Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Algorithm</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Expires</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {certs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  certs.map((c: any, i: number) => (
                  <TableRow key={c.common_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{c.common_name}</TableCell>
                    <TableCell className="py-2"><CertTypeBadge type={c.cert_type ?? "server"} /></TableCell>
                    <TableCell className="py-2"><KeyAlgoBadge algo={c.key_algorithm ?? "RSA-2048"} /></TableCell>
                    <TableCell className="py-2"><CertStatusBadge status={c.status ?? "active"} /></TableCell>
                    <TableCell className={cn("py-2 text-[11px] font-mono", expiryColor(c.expires_at, c.status))}>
                      {c.expires_at}
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Certificate Authorities Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <ShieldCheck className="h-4 w-4" />
              Certificate Authorities
            </CardTitle>
            <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
              {cas.length} CAs
            </Badge>
          </div>
          <CardDescription className="text-xs">CA hierarchy — root and intermediate authorities with issued certificate counts</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Subject</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Certs Issued</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cas.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  cas.map((ca: any, i: number) => (
                  <TableRow key={ca.name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{ca.name}</TableCell>
                    <TableCell className="py-2"><CATypeBadge type={ca.ca_type ?? "intermediate"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground max-w-[280px] truncate">{ca.subject}</TableCell>
                    <TableCell className="py-2"><CertStatusBadge status={ca.status ?? "active"} /></TableCell>
                    <TableCell className="py-2 text-right font-mono text-[11px] text-muted-foreground">{ca.cert_count}</TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
