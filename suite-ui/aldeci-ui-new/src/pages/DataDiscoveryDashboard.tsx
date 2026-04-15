/**
 * Data Discovery Dashboard
 *
 * Sensitive data discovery and datastore risk assessment.
 *   1. KPIs: Total Datastores, High-Risk, Total Discoveries, PII Datastores
 *   2. Datastores table (name, datastore_type, risk_level, record_count, sensitive_record_count)
 *
 * Route: /data-discovery
 * API: GET /api/v1/data-discovery
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Database, RefreshCw, AlertTriangle, Eye, FileSearch, Lock } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_DATASTORES = [
  { id: "ds-001", name: "Customer PII Database",       datastore_type: "PostgreSQL",    risk_level: "critical", record_count: 4820000,  sensitive_record_count: 4820000 },
  { id: "ds-002", name: "Payment Records Warehouse",   datastore_type: "Snowflake",     risk_level: "critical", record_count: 1293000,  sensitive_record_count: 1293000 },
  { id: "ds-003", name: "Employee HR Data",            datastore_type: "MySQL",         risk_level: "high",     record_count: 8750,     sensitive_record_count: 8750 },
  { id: "ds-004", name: "Product Analytics S3",        datastore_type: "S3 Bucket",     risk_level: "medium",   record_count: 98300000, sensitive_record_count: 14200 },
  { id: "ds-005", name: "Audit Log Archive",           datastore_type: "Elasticsearch", risk_level: "low",      record_count: 284000000, sensitive_record_count: 0 },
  { id: "ds-006", name: "Partner Integration Cache",   datastore_type: "Redis",         risk_level: "high",     record_count: 45000,    sensitive_record_count: 12000 },
  { id: "ds-007", name: "Dev/Test Database",           datastore_type: "PostgreSQL",    risk_level: "critical", record_count: 1200000,  sensitive_record_count: 980000 },
  { id: "ds-008", name: "Marketing Email List",        datastore_type: "CSV Files",     risk_level: "medium",   record_count: 340000,   sensitive_record_count: 340000 },
  { id: "ds-009", name: "Backup Tapes",                datastore_type: "Tape Storage",  risk_level: "high",     record_count: 0,        sensitive_record_count: 0 },
  { id: "ds-010", name: "Public API Cache",            datastore_type: "MongoDB",       risk_level: "none",     record_count: 5600000,  sensitive_record_count: 0 },
];

const MOCK_STATS = { total_datastores: 214, high_risk_datastores: 38, total_discoveries: 1847, pii_datastores: 62 };

// ── Badge helpers ──────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
    none:     "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function formatRecords(n: number) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(0)}K`;
  return n.toString();
}

function exportCsv(datastores: any[]) {
  const headers = ["name", "datastore_type", "risk_level", "record_count", "sensitive_record_count"];
  const rows = datastores.map((d) => headers.map((h) => d[h] ?? "").join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "data_discovery.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function DataDiscoveryDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveDatastores, setLiveDatastores] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/data-discovery/datastores?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/data-discovery/stats?org_id=${ORG_ID}`),
    ]).then(([dsRes, statsRes]) => {
      if (dsRes.status === "fulfilled") setLiveDatastores(dsRes.value?.datastores ?? dsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const datastores = liveDatastores ?? MOCK_DATASTORES;
  const stats      = liveStats      ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Data Discovery"
        description="Sensitive data discovery across datastores — PII classification, risk profiling, and exposure quantification"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Datastores"   value={stats.total_datastores}       icon={Database}      trend="flat" className="border-indigo-500/20" />
        <KpiCard title="High-Risk"          value={stats.high_risk_datastores}   icon={AlertTriangle} trend="down" className="border-blue-500/20" />
        <KpiCard title="Total Discoveries"  value={stats.total_discoveries}      icon={FileSearch}    trend="up"   className="border-indigo-500/20" />
        <KpiCard title="PII Datastores"     value={stats.pii_datastores}         icon={Lock}          trend="down" className="border-blue-500/20" />
      </div>

      {/* Datastores Table */}
      <Card className="border-indigo-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-indigo-400">
              <Eye className="h-4 w-4" />
              Datastore Inventory
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {datastores.filter((d: any) => d.risk_level === "critical").length} critical
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(datastores)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            All discovered datastores with type, risk classification, total records, and sensitive record count
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Datastore</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8">Total Records</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Sensitive Records</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {datastores.map((ds: any, i: number) => (
                  <TableRow key={ds.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-indigo-300 max-w-[200px] truncate">
                      {ds.name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {ds.datastore_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskBadge level={ds.risk_level ?? "none"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-blue-300">
                      {formatRecords(ds.record_count ?? 0)}
                    </TableCell>
                    <TableCell className={cn(
                      "py-2 font-mono text-[11px] font-bold text-right",
                      (ds.sensitive_record_count ?? 0) > 0 ? "text-red-400" : "text-muted-foreground"
                    )}>
                      {ds.sensitive_record_count > 0 ? formatRecords(ds.sensitive_record_count) : "—"}
                    </TableCell>
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
