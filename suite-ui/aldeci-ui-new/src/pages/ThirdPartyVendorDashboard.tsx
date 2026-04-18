/**
 * Third Party Vendor Dashboard
 *
 * Third-party vendor risk management with risk rating, contract status, and data access tracking.
 *   1. KPIs: Total Vendors, High-Risk, Unassessed, Avg Risk Score
 *   2. Vendors table (name, vendor_category, risk_rating, contract_status, data_access_level, risk_score)
 *
 * Route: /third-party-vendor
 * API: GET /api/v1/third-party-vendor
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Building2, RefreshCw, AlertTriangle, HelpCircle, TrendingUp, BarChart2 } from "lucide-react";

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

const MOCK_VENDORS = [
  { id: "ven-001", name: "CloudMatrix Inc.",      vendor_category: "cloud_provider",  risk_rating: "low",      contract_status: "active",   data_access_level: "none",       risk_score: 18 },
  { id: "ven-002", name: "DataSync Partners",     vendor_category: "data_processor",  risk_rating: "critical", contract_status: "active",   data_access_level: "pii",        risk_score: 91 },
  { id: "ven-003", name: "SecureAudit LLC",       vendor_category: "auditor",         risk_rating: "medium",   contract_status: "active",   data_access_level: "audit_logs", risk_score: 47 },
  { id: "ven-004", name: "GlobalPay Systems",     vendor_category: "payment",         risk_rating: "high",     contract_status: "active",   data_access_level: "pci",        risk_score: 74 },
  { id: "ven-005", name: "TechSupport Co.",       vendor_category: "support",         risk_rating: "medium",   contract_status: "expired",  data_access_level: "limited",    risk_score: 55 },
  { id: "ven-006", name: "AI Analytics Corp.",    vendor_category: "saas",            risk_rating: "high",     contract_status: "active",   data_access_level: "analytics",  risk_score: 78 },
  { id: "ven-007", name: "NetWatch Security",     vendor_category: "security",        risk_rating: "low",      contract_status: "active",   data_access_level: "network",    risk_score: 22 },
  { id: "ven-008", name: "HR Cloud Suite",        vendor_category: "hr",              risk_rating: "critical", contract_status: "active",   data_access_level: "pii",        risk_score: 87 },
  { id: "ven-009", name: "Logistics Tracker Ltd.",vendor_category: "logistics",       risk_rating: "low",      contract_status: "inactive", data_access_level: "none",       risk_score: 14 },
  { id: "ven-010", name: "DevOps Infra Corp.",    vendor_category: "infrastructure",  risk_rating: "medium",   contract_status: "active",   data_access_level: "ci_cd",      risk_score: 51 },
];

const MOCK_STATS = { total_vendors: 143, high_risk: 22, unassessed: 17, avg_risk_score: 52.3 };

// ── Badge helpers ──────────────────────────────────────────────

function RiskRatingBadge({ rating }: { rating: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[rating] ?? "border-border")}>
      {rating}
    </Badge>
  );
}

function ContractBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:   "border-green-500/30 text-green-400 bg-green-500/10",
    expired:  "border-red-500/30 text-red-400 bg-red-500/10",
    inactive: "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
    pending:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function RiskScoreCell({ score }: { score: number }) {
  const color = score >= 75 ? "text-red-400" : score >= 50 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("font-mono text-[11px] font-semibold", color)}>{score}</span>;
}

function exportCsv(rows: any[]) {
  const headers = ["name", "vendor_category", "risk_rating", "contract_status", "data_access_level", "risk_score"];
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => `"${r[h] ?? ""}"`).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "third_party_vendors.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function ThirdPartyVendorDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveVendors, setLiveVendors] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/third-party-vendor/vendors?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/third-party-vendor/stats?org_id=${ORG_ID}`),
    ]).then(([venRes, statsRes]) => {
      if (venRes.status === "fulfilled") setLiveVendors(venRes.value?.vendors ?? venRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const vendors = liveVendors ?? MOCK_VENDORS;
  const stats   = liveStats   ?? MOCK_STATS;

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
        title="Third-Party Vendor Risk"
        description="Vendor risk management — track supplier risk ratings, contract status, data access levels, and risk scores"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Vendors"   value={stats.total_vendors}                     icon={Building2}    trend="flat" className="border-red-500/20" />
        <KpiCard title="High-Risk"       value={stats.high_risk}                         icon={AlertTriangle} trend="down" className="border-rose-500/20" />
        <KpiCard title="Unassessed"      value={stats.unassessed}                        icon={HelpCircle}   trend="down" className="border-red-500/20" />
        <KpiCard title="Avg Risk Score"  value={`${stats.avg_risk_score}`}               icon={TrendingUp}   trend="down" className="border-rose-500/20" />
      </div>

      {/* Vendors Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <BarChart2 className="h-4 w-4" />
              Vendor Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {vendors.filter((v: any) => v.risk_rating === "critical").length} critical
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(vendors)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            Third-party vendors with risk rating, contract status, data access level, and composite risk score
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Vendor Name</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Rating</TableHead>
                  <TableHead className="text-[11px] h-8">Contract</TableHead>
                  <TableHead className="text-[11px] h-8">Data Access</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Risk Score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vendors.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  vendors.map((ven: any, i: number) => (
                  <TableRow key={ven.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-red-300 max-w-[180px] truncate">
                      {ven.name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {(ven.vendor_category ?? "—").replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskRatingBadge rating={ven.risk_rating ?? "medium"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <ContractBadge status={ven.contract_status ?? "active"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-rose-300">
                      {ven.data_access_level ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <RiskScoreCell score={ven.risk_score ?? 0} />
                    </TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
