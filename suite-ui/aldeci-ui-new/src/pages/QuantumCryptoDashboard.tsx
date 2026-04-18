/**
 * Quantum Cryptography Dashboard
 *
 * Post-quantum cryptography readiness and migration tracking.
 *   1. KPI cards: Total Assets, Quantum Vulnerable, Migrated, Migration Progress
 *   2. Assets table
 *   3. Migrations table
 *
 * API: GET /api/v1/quantum-crypto/{stats,assets,migrations}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Atom, RefreshCw, AlertTriangle, CheckCircle, ArrowRightLeft, Lock,
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
  total_assets:           312,
  quantum_vulnerable:     178,
  migrated:               47,
  migration_progress_pct: 26.4,
};

const MOCK_ASSETS = [
  { asset_name: "TLS Web Gateway",       asset_type: "tls_endpoint",  current_algorithm: "RSA-2048",   quantum_vulnerable: true,  migration_status: "in_progress", risk_level: "critical" },
  { asset_name: "SSH Bastion Host",      asset_type: "ssh_endpoint",  current_algorithm: "RSA-4096",   quantum_vulnerable: true,  migration_status: "planned",     risk_level: "high"     },
  { asset_name: "Code Signing Cert",     asset_type: "certificate",   current_algorithm: "ECDSA-P256", quantum_vulnerable: false, migration_status: "not_required",risk_level: "low"      },
  { asset_name: "Database Encryption",   asset_type: "storage",       current_algorithm: "AES-256",    quantum_vulnerable: false, migration_status: "not_required",risk_level: "low"      },
  { asset_name: "JWT Auth Tokens",       asset_type: "auth",          current_algorithm: "RS256",      quantum_vulnerable: true,  migration_status: "planned",     risk_level: "high"     },
  { asset_name: "VPN Tunnel Keys",       asset_type: "network",       current_algorithm: "DH-2048",    quantum_vulnerable: true,  migration_status: "in_progress", risk_level: "critical" },
  { asset_name: "PKI Root CA",           asset_type: "pki",           current_algorithm: "RSA-4096",   quantum_vulnerable: true,  migration_status: "planned",     risk_level: "critical" },
  { asset_name: "S3 Bucket Encryption",  asset_type: "storage",       current_algorithm: "AES-256-GCM",quantum_vulnerable: false, migration_status: "migrated",    risk_level: "none"     },
];

const MOCK_MIGRATIONS = [
  { asset_id: "tls-gw-01",  from_algorithm: "RSA-2048",  to_algorithm: "CRYSTALS-Kyber",  priority: "critical", status: "in_progress", planned_date: "2026-06-01" },
  { asset_id: "vpn-tun-02", from_algorithm: "DH-2048",   to_algorithm: "CRYSTALS-Kyber",  priority: "critical", status: "in_progress", planned_date: "2026-06-15" },
  { asset_id: "pki-root",   from_algorithm: "RSA-4096",  to_algorithm: "CRYSTALS-Dilithium",priority:"critical",status: "planned",     planned_date: "2026-07-01" },
  { asset_id: "ssh-bstn",   from_algorithm: "RSA-4096",  to_algorithm: "ML-KEM-768",      priority: "high",     status: "planned",     planned_date: "2026-07-15" },
  { asset_id: "jwt-auth",   from_algorithm: "RS256",     to_algorithm: "ML-DSA-65",       priority: "high",     status: "planned",     planned_date: "2026-08-01" },
  { asset_id: "s3-bucket",  from_algorithm: "RSA-2048",  to_algorithm: "AES-256-GCM",     priority: "low",      status: "migrated",    planned_date: "2025-12-01" },
];

// ── Badge helpers ──────────────────────────────────────────────

function RiskLevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical:     "border-red-500/30 text-red-400 bg-red-500/10",
    high:         "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:       "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:          "border-blue-500/30 text-blue-400 bg-blue-500/10",
    none:         "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function MigrationStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    in_progress:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    planned:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    migrated:     "border-green-500/30 text-green-400 bg-green-500/10",
    not_required: "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>
      {status?.replace(/_/g, " ")}
    </Badge>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[priority] ?? "border-border text-muted-foreground")}>
      {priority}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function QuantumCryptoDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    assets: any[] | null;
    migrations: any[] | null;
  }>({ stats: null, assets: null, migrations: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/quantum-crypto/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/quantum-crypto/assets?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/quantum-crypto/migrations?org_id=${ORG_ID}`),
    ]).then(([statsRes, assetsRes, migrationsRes]) => {
      setLiveData({
        stats:      statsRes.status      === "fulfilled" ? statsRes.value      : null,
        assets:     assetsRes.status     === "fulfilled" ? assetsRes.value     : null,
        migrations: migrationsRes.status === "fulfilled" ? migrationsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? MOCK_STATS;
  const assets     = liveData.assets     ?? MOCK_ASSETS;
  const migrations = liveData.migrations ?? MOCK_MIGRATIONS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Quantum Cryptography Readiness"
        description="Post-quantum migration tracking and cryptographic asset risk assessment"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets"        value={stats.total_assets}                           icon={Lock}          trend="flat" />
        <KpiCard title="Quantum Vulnerable"  value={stats.quantum_vulnerable}                     icon={AlertTriangle} trend="down" className="border-red-500/20" />
        <KpiCard title="Migrated"            value={stats.migrated}                               icon={CheckCircle}   trend="up"   className="border-green-500/20" />
        <KpiCard title="Migration Progress"  value={`${stats.migration_progress_pct}%`}           icon={Atom}          trend="up"   className="border-purple-500/20" />
      </div>

      {/* Assets Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-blue-400" />
              Cryptographic Assets
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {assets.filter((a: any) => a.quantum_vulnerable).length} vulnerable
            </Badge>
          </div>
          <CardDescription className="text-xs">All cryptographic assets assessed for quantum vulnerability</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Asset Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Algorithm</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Vulnerable</TableHead>
                  <TableHead className="text-[11px] h-8">Migration Status</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((a: any, i: number) => (
                  <TableRow key={a.asset_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{a.asset_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{a.asset_type?.replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-blue-400">{a.current_algorithm}</TableCell>
                    <TableCell className="py-2 text-center text-[11px]">
                      {a.quantum_vulnerable
                        ? <AlertTriangle className="h-3.5 w-3.5 text-red-400 inline" />
                        : <CheckCircle   className="h-3.5 w-3.5 text-green-400 inline" />}
                    </TableCell>
                    <TableCell className="py-2"><MigrationStatusBadge status={a.migration_status ?? "planned"} /></TableCell>
                    <TableCell className="py-2"><RiskLevelBadge level={a.risk_level ?? "medium"} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Migrations Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <ArrowRightLeft className="h-4 w-4" />
              Migration Plan
            </CardTitle>
            <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
              {migrations.filter((m: any) => m.status === "in_progress").length} in progress
            </Badge>
          </div>
          <CardDescription className="text-xs">Post-quantum algorithm migration schedule and status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Asset ID</TableHead>
                  <TableHead className="text-[11px] h-8">From Algorithm</TableHead>
                  <TableHead className="text-[11px] h-8">To Algorithm</TableHead>
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Planned Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {migrations.map((m: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{m.asset_id}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-orange-400">{m.from_algorithm}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-green-400">{m.to_algorithm}</TableCell>
                    <TableCell className="py-2"><PriorityBadge priority={m.priority ?? "medium"} /></TableCell>
                    <TableCell className="py-2"><MigrationStatusBadge status={m.status ?? "planned"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{m.planned_date}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
