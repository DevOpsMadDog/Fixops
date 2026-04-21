/**
 * Security Budget Dashboard
 *
 * Security spend, allocations, and ROI tracking.
 *   1. KPI cards: Total Allocated, Total Spent, Remaining Budget, Utilization %
 *   2. Budget by Category table with utilization bars
 *   3. Recent Transactions table
 *
 * API: GET /api/v1/security-budget/{stats,allocations,transactions}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  DollarSign, RefreshCw, TrendingUp, PieChart, FileText, CheckCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  fiscal_year: 2026,
  total_allocated: 4200000,
  total_spent: 2730000,
  remaining: 1470000,
  utilization_pct: 65.0,
};

const MOCK_ALLOCATIONS = [
  { category: "Cloud Security",        allocated: 900000,  spent: 620000,  remaining: 280000  },
  { category: "Endpoint Protection",   allocated: 600000,  spent: 480000,  remaining: 120000  },
  { category: "Identity & Access",     allocated: 750000,  spent: 510000,  remaining: 240000  },
  { category: "Threat Intelligence",   allocated: 500000,  spent: 275000,  remaining: 225000  },
  { category: "Compliance & Audit",    allocated: 450000,  spent: 390000,  remaining: 60000   },
  { category: "Security Training",     allocated: 300000,  spent: 165000,  remaining: 135000  },
  { category: "Incident Response",     allocated: 700000,  spent: 290000,  remaining: 410000  },
];

const MOCK_TRANSACTIONS = [
  { vendor: "CrowdStrike",      description: "Falcon EDR annual renewal",      amount: 128000, date: "2026-04-10", status: "approved"  },
  { vendor: "Palo Alto",        description: "Prisma Cloud Q2 invoice",        amount: 92000,  date: "2026-04-08", status: "approved"  },
  { vendor: "KnowBe4",          description: "Security awareness platform",    amount: 18500,  date: "2026-04-05", status: "approved"  },
  { vendor: "RecordedFuture",   description: "Threat intel subscription",      amount: 45000,  date: "2026-04-02", status: "pending"   },
  { vendor: "Qualys",           description: "VMDR annual license",            amount: 67000,  date: "2026-03-28", status: "approved"  },
  { vendor: "Splunk",           description: "SIEM infrastructure expansion",  amount: 215000, date: "2026-03-20", status: "approved"  },
  { vendor: "Okta",             description: "IAM enterprise license",         amount: 110000, date: "2026-03-15", status: "approved"  },
  { vendor: "HackerOne",        description: "Bug bounty platform fee",        amount: 25000,  date: "2026-03-10", status: "rejected"  },
];

// ── Helpers ────────────────────────────────────────────────────

function fmtMoney(n: number): string {
  if (n >= 1000000) return `$${(n / 1000000).toFixed(2)}M`;
  if (n >= 1000) return `$${(n / 1000).toFixed(0)}K`;
  return `$${n.toLocaleString()}`;
}

function utilizationColor(pct: number): string {
  if (pct >= 90) return "bg-red-500";
  if (pct >= 75) return "bg-orange-500";
  if (pct >= 50) return "bg-blue-500";
  return "bg-green-500";
}

function TransactionStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    approved: "border-green-500/30 text-green-400 bg-green-500/10",
    rejected: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityBudgetDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    allocations: any[] | null;
    transactions: any[] | null;
  }>({ stats: null, allocations: null, transactions: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/security-budget/stats?org_id=${ORG_ID}&fiscal_year=2026`),
      apiFetch(`/api/v1/security-budget/allocations?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-budget/transactions?org_id=${ORG_ID}`),
    ]).then(([statsRes, allocRes, txRes]) => {
      setLiveData({
        stats:        statsRes.status  === "fulfilled" ? statsRes.value  : null,
        allocations:  allocRes.status  === "fulfilled" ? allocRes.value  : null,
        transactions: txRes.status     === "fulfilled" ? txRes.value     : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats        = liveData.stats        ?? MOCK_STATS;
  const allocations  = liveData.allocations  ?? MOCK_ALLOCATIONS;
  const transactions = liveData.transactions ?? MOCK_TRANSACTIONS;

  const utilPct = stats.utilization_pct ?? (stats.total_allocated > 0 ? (stats.total_spent / stats.total_allocated) * 100 : 0);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Security Budget Tracker"
        description={`Security spend, allocations, and ROI — FY${stats.fiscal_year ?? 2026}`}
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Allocated"  value={fmtMoney(stats.total_allocated)} icon={DollarSign}  trend="flat" />
        <KpiCard title="Total Spent"      value={fmtMoney(stats.total_spent)}     icon={TrendingUp}  trend="up"     className="border-blue-500/20" />
        <KpiCard title="Remaining Budget" value={fmtMoney(stats.remaining ?? (stats.total_allocated - stats.total_spent))} icon={PieChart} trend="flat" className="border-green-500/20" />
        <KpiCard title="Utilization"      value={`${utilPct.toFixed(1)}%`}         icon={CheckCircle} trend="flat" className="border-amber-500/20" />
      </div>

      {/* Utilization progress bar */}
      <Card>
        <CardContent className="pt-4 pb-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-muted-foreground">Budget Utilization — FY{stats.fiscal_year ?? 2026}</span>
              <span className={cn("font-bold tabular-nums",
                utilPct >= 90 ? "text-red-400" : utilPct >= 75 ? "text-orange-400" : "text-blue-400"
              )}>
                {fmtMoney(stats.total_spent)} / {fmtMoney(stats.total_allocated)} ({utilPct.toFixed(1)}%)
              </span>
            </div>
            <div className="h-3 w-full rounded-full bg-muted/30 overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${Math.min(utilPct, 100)}%` }}
                transition={{ duration: 0.8 }}
                className={cn("h-full rounded-full", utilizationColor(utilPct))}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Allocations Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <PieChart className="h-4 w-4 text-blue-400" />
              Budget by Category
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {allocations.length} categories
            </Badge>
          </div>
          <CardDescription className="text-xs">Allocated vs. spent per security domain</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Allocated</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Spent</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Remaining</TableHead>
                  <TableHead className="text-[11px] h-8">Utilization</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {allocations.map((a: any, i: number) => {
                  const pct = a.allocated > 0 ? Math.round((a.spent / a.allocated) * 100) : 0;
                  return (
                    <TableRow key={a.category ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-xs font-medium">{a.category}</TableCell>
                      <TableCell className="py-2 text-xs tabular-nums text-right text-muted-foreground">{fmtMoney(a.allocated ?? 0)}</TableCell>
                      <TableCell className="py-2 text-xs tabular-nums text-right font-medium text-blue-400">{fmtMoney(a.spent ?? 0)}</TableCell>
                      <TableCell className="py-2 text-xs tabular-nums text-right text-green-400">{fmtMoney(a.remaining ?? (a.allocated - a.spent))}</TableCell>
                      <TableCell className="py-2 min-w-[140px]">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${pct}%` }}
                              transition={{ duration: 0.6, delay: i * 0.04 }}
                              className={cn("h-full rounded-full", utilizationColor(pct))}
                            />
                          </div>
                          <span className="text-[11px] tabular-nums text-muted-foreground w-8 text-right">{pct}%</span>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Transactions Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <FileText className="h-4 w-4" />
              Recent Transactions
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {transactions.filter((t: any) => t.status === "pending").length} pending
            </Badge>
          </div>
          <CardDescription className="text-xs">Vendor payments and purchase orders</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Vendor</TableHead>
                  <TableHead className="text-[11px] h-8">Description</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Amount</TableHead>
                  <TableHead className="text-[11px] h-8">Date</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {transactions.map((t: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{t.vendor}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[260px] truncate">{t.description}</TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-right font-semibold">
                      {fmtMoney(t.amount ?? 0)}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{t.date}</TableCell>
                    <TableCell className="py-2"><TransactionStatusBadge status={t.status ?? "pending"} /></TableCell>
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
