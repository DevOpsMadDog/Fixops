/**
 * Certificate Dashboard
 *
 * Route: /certificates
 * API: GET /api/v1/certificates/stats, /api/v1/certificates/expiring
 *
 * KPIs: Total Certs, Active, Expiring (30d), Expired
 * Table: Expiring certs = domain, type, issuer, expiry date, auto-renew badge
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, AlertTriangle, XCircle, RefreshCw, CheckCircle2, Globe } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ==================================================

const MOCK_STATS = {
  total: 89,
  active: 71,
  expiring_30d: 7,
  expired: 3,
  by_type: { ssl: 45, code_signing: 12, client: 32 },
};

const MOCK_EXPIRING = [
  { id: "CERT-001", domain: "api.prod.acme.com",       type: "ssl",          issuer: "Let's Encrypt",   expiry_date: "2026-05-04", auto_renew: true  },
  { id: "CERT-002", domain: "auth.acme.com",           type: "ssl",          issuer: "DigiCert",        expiry_date: "2026-05-08", auto_renew: false },
  { id: "CERT-003", domain: "release-signer-v3",       type: "code_signing", issuer: "Sectigo",         expiry_date: "2026-05-10", auto_renew: false },
  { id: "CERT-004", domain: "cdn.acme.com",            type: "ssl",          issuer: "Cloudflare",      expiry_date: "2026-05-14", auto_renew: true  },
  { id: "CERT-005", domain: "vpn-client-ops",          type: "client",       issuer: "Internal CA",     expiry_date: "2026-05-16", auto_renew: false },
  { id: "CERT-006", domain: "admin.internal.acme.com", type: "ssl",          issuer: "Let's Encrypt",   expiry_date: "2026-05-20", auto_renew: true  },
  { id: "CERT-007", domain: "ci-deploy-client",        type: "client",       issuer: "Internal CA",     expiry_date: "2026-05-28", auto_renew: false },
];

// == Badge helpers ==============================================

function CertTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    ssl:          "border-blue-500/30 text-blue-400 bg-blue-500/10",
    code_signing: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    client:       "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function AutoRenewBadge({ enabled }: { enabled: boolean }) {
  return enabled ? (
    <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10 flex items-center gap-1 w-fit">
      <CheckCircle2 className="h-2.5 w-2.5" /> Auto
    </Badge>
  ) : (
    <Badge className="text-[10px] border border-slate-500/30 text-slate-400 bg-slate-500/10">Manual</Badge>
  );
}

function daysUntil(dateStr: string) {
  const diff = Math.ceil((new Date(dateStr).getTime() - Date.now()) / 86_400_000);
  return diff;
}

// == Component ==================================================

export default function CertificateDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats]           = useState<typeof MOCK_STATS>(MOCK_STATS);
  const [expiring, setExpiring]     = useState<typeof MOCK_EXPIRING>(MOCK_EXPIRING);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/certificates/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/certificates/expiring?org_id=${ORG_ID}&days_ahead=30`),
    ]).then(([statsRes, expiringRes]) => {
      if (statsRes.status === "fulfilled" && statsRes.value) setStats(statsRes.value);
      if (expiringRes.status === "fulfilled" && expiringRes.value) setExpiring(expiringRes.value);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      )))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Certificate Lifecycle"
        description="Track SSL/TLS, code signing, and client certificates across all environments"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Certs"    value={stats.total}       icon={Globe}         trend="up" />
        <KpiCard title="Active"         value={stats.active}      icon={ShieldCheck}   trend="up"      className="border-green-500/20" />
        <KpiCard title="Expiring (30d)" value={stats.expiring_30d} icon={AlertTriangle} trend="up"     className="border-amber-500/20" />
        <KpiCard title="Expired"        value={stats.expired}     icon={XCircle}       trend="neutral" className="border-red-500/20" />
      </div>

      {/* Type Distribution */}
      <div className="grid grid-cols-3 gap-3">
        {Object.entries(stats.by_type ?? {}).map(([type, count]) => (
          <Card key={type} className="text-center py-4">
            <p className="text-2xl font-bold tabular-nums">{count as number}</p>
            <p className="text-[11px] text-muted-foreground mt-1 capitalize">{type.replace(/_/g, " ")}</p>
          </Card>
        )))}
      </div>

      {/* Expiring Certs Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
              Expiring in 30 Days
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {expiring.length} certs
            </Badge>
          </div>
          <CardDescription className="text-xs">Certificates requiring renewal action</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Domain / Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Issuer</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Expiry Date</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Days Left</TableHead>
                  <TableHead className="text-[11px] h-8">Renewal</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {expiring.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  expiring.map((cert: any) => {
                  const days = daysUntil(cert.expiry_date);
                  return (
                    <TableRow key={cert.id} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[11px]">{cert.domain}</TableCell>
                      <TableCell className="py-2"><CertTypeBadge type={cert.type} /></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{cert.issuer}</TableCell>
                      <TableCell className="py-2 text-right font-mono text-[11px] text-muted-foreground">{cert.expiry_date}</TableCell>
                      <TableCell className="py-2 text-right">
                        <span className={cn(
                          "text-xs tabular-nums font-semibold",
                          days <= 7 ? "text-red-400" : days <= 14 ? "text-amber-400" : "text-yellow-400"
                        )}>
                          {days}d
                        </span>
                      </TableCell>
                      <TableCell className="py-2"><AutoRenewBadge enabled={cert.auto_renew} /></TableCell>
                    </TableRow>
                  );
                })
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
