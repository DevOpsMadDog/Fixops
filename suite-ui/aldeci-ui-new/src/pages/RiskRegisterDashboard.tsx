/**
 * Risk Register Engine Dashboard
 *
 * Enterprise risk register with likelihood/impact scoring and lifecycle tracking.
 *   1. KPIs: Total Risks, Critical Risks, High Risks, Open Risks
 *   2. Risks table (name, risk_category, likelihood, impact, risk_score, risk_level, status)
 *
 * Route: /risk-register-engine
 * API: GET /api/v1/risk-register-engine
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ClipboardList, RefreshCw, AlertTriangle, TrendingUp, CheckCircle } from "lucide-react";

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

const MOCK_RISKS = [
  { id: "risk-001", name: "Ransomware Attack",         risk_category: "Cyber",       likelihood: 4, impact: 5, risk_score: 20, risk_level: "critical", status: "open"        },
  { id: "risk-002", name: "Supply Chain Compromise",   risk_category: "Third Party",  likelihood: 3, impact: 5, risk_score: 15, risk_level: "high",     status: "open"        },
  { id: "risk-003", name: "Insider Data Theft",        risk_category: "Insider",      likelihood: 3, impact: 4, risk_score: 12, risk_level: "high",     status: "mitigating"  },
  { id: "risk-004", name: "Cloud Misconfiguration",    risk_category: "Cloud",        likelihood: 4, impact: 3, risk_score: 12, risk_level: "high",     status: "open"        },
  { id: "risk-005", name: "Credential Compromise",     risk_category: "Identity",     likelihood: 4, impact: 3, risk_score: 12, risk_level: "high",     status: "open"        },
  { id: "risk-006", name: "DDoS Attack",               risk_category: "Availability", likelihood: 3, impact: 3, risk_score: 9,  risk_level: "medium",   status: "accepted"    },
  { id: "risk-007", name: "Phishing Campaign",         risk_category: "Social Eng",   likelihood: 5, impact: 2, risk_score: 10, risk_level: "medium",   status: "open"        },
  { id: "risk-008", name: "Unpatched Vulnerabilities", risk_category: "Vulnerability",likelihood: 4, impact: 2, risk_score: 8,  risk_level: "medium",   status: "mitigating"  },
  { id: "risk-009", name: "Data Breach via API",       risk_category: "API Security", likelihood: 2, impact: 4, risk_score: 8,  risk_level: "medium",   status: "open"        },
  { id: "risk-010", name: "Physical Security Breach",  risk_category: "Physical",     likelihood: 1, impact: 3, risk_score: 3,  risk_level: "low",      status: "accepted"    },
];

const MOCK_STATS = { total_risks: 47, critical_risks: 3, high_risks: 11, open_risks: 29 };

// ── Badge helpers ──────────────────────────────────────────────

function RiskLevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:       "border-red-500/30 text-red-400 bg-red-500/10",
    mitigating: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    accepted:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    closed:     "border-green-500/30 text-green-400 bg-green-500/10",
  };
  const label: Record<string, string> = {
    open:       "Open",
    mitigating: "Mitigating",
    accepted:   "Accepted",
    closed:     "Closed",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function RiskRegisterDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveRisks, setLiveRisks] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/risk-register-engine/risks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/risk-register-engine/stats?org_id=${ORG_ID}`),
    ]).then(([risksRes, statsRes]) => {
      if (risksRes.status === "fulfilled") setLiveRisks(risksRes.value?.risks ?? risksRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); 
    setLoading(false);};

  const risks = liveRisks ?? MOCK_RISKS;
  const stats = liveStats ?? MOCK_STATS;

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
        title="Risk Register"
        description="Enterprise risk register with likelihood/impact scoring, risk lifecycle management, and treatment tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Risks"    value={stats.total_risks}    icon={ClipboardList}  trend="flat" className="border-orange-500/20" />
        <KpiCard title="Critical Risks" value={stats.critical_risks} icon={AlertTriangle}  trend="down" className="border-red-500/20" />
        <KpiCard title="High Risks"     value={stats.high_risks}     icon={TrendingUp}     trend="down" className="border-amber-500/20" />
        <KpiCard title="Open Risks"     value={stats.open_risks}     icon={CheckCircle}    trend="down" className="border-yellow-500/20" />
      </div>

      {/* Risks Table */}
      <Card className="border-orange-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <ClipboardList className="h-4 w-4" />
              Risk Register
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {risks.filter((r: any) => r.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Enterprise risks with likelihood/impact scoring, risk level classification, and treatment status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Risk Name</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Likelihood</TableHead>
                  <TableHead className="text-[11px] h-8">Impact</TableHead>
                  <TableHead className="text-[11px] h-8">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Level</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {risks.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  risks.map((risk: any, i: number) => (
                  <TableRow key={risk.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-orange-300">
                      {risk.name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {risk.risk_category ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {risk.likelihood ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {risk.impact ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] font-semibold text-amber-300">
                      {risk.risk_score ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskLevelBadge level={risk.risk_level ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <StatusBadge status={risk.status ?? "open"} />
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
