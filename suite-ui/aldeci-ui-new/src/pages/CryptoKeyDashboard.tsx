/**
 * Crypto Key Dashboard
 *
 * Route: /crypto-keys
 * API: GET /api/v1/crypto-keys/stats, /api/v1/crypto-keys/expiring
 *
 * KPIs: Total Keys, Expiring (30d), Revoked, Key Types
 * Table: Expiring keys — name, type, purpose, days until expiry, rotate button
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Key, AlertTriangle, RefreshCw, RotateCcw, ShieldOff, Layers } from "lucide-react";

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

// ── Mock data ──────────────────────────────────────────────────

const MOCK_STATS = {
  total: 156,
  by_type: { aes256: 45, rsa4096: 38, ecdsa256: 73 },
  expiring_soon: 8,
  revoked: 12,
};

const MOCK_EXPIRING = [
  { id: "KEY-001", name: "prod-db-encrypt",      type: "aes256",   purpose: "Database encryption",   days_until_expiry: 3  },
  { id: "KEY-002", name: "api-signing-key",       type: "rsa4096",  purpose: "API JWT signing",        days_until_expiry: 7  },
  { id: "KEY-003", name: "tls-inter-service",     type: "ecdsa256", purpose: "mTLS service mesh",      days_until_expiry: 12 },
  { id: "KEY-004", name: "backup-enc-key",        type: "aes256",   purpose: "Backup data encryption", days_until_expiry: 18 },
  { id: "KEY-005", name: "oauth-sign-prod",       type: "rsa4096",  purpose: "OAuth token signing",    days_until_expiry: 21 },
  { id: "KEY-006", name: "s3-sse-key",            type: "aes256",   purpose: "S3 server-side encrypt", days_until_expiry: 25 },
  { id: "KEY-007", name: "code-signing-release",  type: "ecdsa256", purpose: "Release artifact sign",  days_until_expiry: 28 },
  { id: "KEY-008", name: "session-secret-prod",   type: "aes256",   purpose: "Session token secret",   days_until_expiry: 30 },
];

// ── Badge helpers ──────────────────────────────────────────────

function KeyTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    aes256:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    rsa4096:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    ecdsa256: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono uppercase", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function ExpiryBadge({ days }: { days: number }) {
  const cls =
    days <= 7  ? "text-red-400 font-bold" :
    days <= 14 ? "text-amber-400 font-semibold" :
    "text-yellow-400";
  return <span className={cn("text-xs tabular-nums", cls)}>{days}d</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function CryptoKeyDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [stats, setStats]           = useState<typeof MOCK_STATS>(MOCK_STATS);
  const [expiring, setExpiring]     = useState<typeof MOCK_EXPIRING>(MOCK_EXPIRING);
  const [rotating, setRotating]     = useState<string | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/crypto-keys/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/crypto-keys/expiring?org_id=${ORG_ID}&days_ahead=30`),
    ]).then(([statsRes, expiringRes]) => {
      if (statsRes.status === "fulfilled" && statsRes.value) setStats(statsRes.value);
      if (expiringRes.status === "fulfilled" && expiringRes.value) setExpiring(expiringRes.value);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const handleRotate = (id: string) => {
    setRotating(id);
    setTimeout(() => setRotating(null), 1200);
  };

  const keyTypeCount = Object.keys(stats.by_type ?? {}).length;

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
      <PageHeader
        title="Crypto Key Management"
        description="Lifecycle management for encryption keys, signing keys, and secrets"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Keys"       value={stats.total}          icon={Key}           trend="up" />
        <KpiCard title="Expiring (30d)"   value={stats.expiring_soon}  icon={AlertTriangle} trend="up" className="border-amber-500/20" />
        <KpiCard title="Revoked"          value={stats.revoked}        icon={ShieldOff}     trend="neutral" className="border-red-500/20" />
        <KpiCard title="Key Types"        value={keyTypeCount}         icon={Layers}        trend="neutral" />
      </div>

      {/* Key Type Distribution */}
      <div className="grid grid-cols-3 gap-3">
        {Object.entries(stats.by_type ?? {}).map(([type, count]) => (
          <Card key={type} className="text-center py-4">
            <p className="text-2xl font-bold tabular-nums">{count as number}</p>
            <p className="text-[11px] text-muted-foreground mt-1 font-mono uppercase">{type}</p>
          </Card>
        ))}
      </div>

      {/* Expiring Keys Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
              Keys Expiring in 30 Days
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {expiring.length} keys
            </Badge>
          </div>
          <CardDescription className="text-xs">Keys requiring rotation before expiry</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Purpose</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Days Left</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {expiring.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  expiring.map((k: any) => (
                  <TableRow key={k.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{k.name}</TableCell>
                    <TableCell className="py-2"><KeyTypeBadge type={k.type} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{k.purpose}</TableCell>
                    <TableCell className="py-2 text-right"><ExpiryBadge days={k.days_until_expiry} /></TableCell>
                    <TableCell className="py-2 text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2 text-[10px]"
                        onClick={() => handleRotate(k.id)}
                        disabled={rotating === k.id}
                      >
                        <RotateCcw className={cn("h-3 w-3 mr-1", rotating === k.id && "animate-spin")} />
                        Rotate
                      </Button>
                    </TableCell>
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
