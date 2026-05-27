/**
 * Risk Register Dashboard — P08 Persona (The Assessor / Risk Manager)
 *
 * Data source: GET /api/v1/risk-register-engine/risks?org_id=default
 *   Fields: id, name, risk_category, description, likelihood (string),
 *           impact (string), risk_score (number), risk_level, owner,
 *           status, created_at, updated_at
 *
 * NO mock fallbacks. Empty state when API returns [].
 */

import { useState, useMemo, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, AlertTriangle, TrendingDown, Target, ChevronUp,
  ChevronDown, Filter, Plus, CheckCircle2, Clock, ArrowUpDown,
  ShieldCheck, Zap, Building2, Globe, Server, RefreshCw,
  ChevronRight, X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { EmptyState } from "@/components/shared/EmptyState";
import { buildApiUrl, getStoredAuthToken, getStoredAuthStrategy, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";
import axios from "axios";

// ─────────────────────────────────────────────────────────────
// Types — matching the real API shape
// ─────────────────────────────────────────────────────────────

type RiskCategory = "TECHNICAL" | "OPERATIONAL" | "COMPLIANCE" | "VENDOR" | "REPUTATIONAL";
type RiskStatus = "OPEN" | "MITIGATING" | "ACCEPTED" | "TRANSFERRED" | "CLOSED" | "IDENTIFIED";

interface ApiRisk {
  id: string;
  org_id: string;
  name: string;
  risk_category: string;
  description: string;
  likelihood: string;   // "likely" | "possible" | "unlikely" | "rare" | "almost_certain"
  impact: string;       // "major" | "minor" | "moderate" | "negligible" | "catastrophic"
  risk_score: number;
  risk_level: string;   // "critical" | "high" | "medium" | "low"
  owner: string;
  status: string;
  treatment_plan: string;
  created_at: string;
  updated_at: string;
}

interface RiskItem {
  id: string;
  category: RiskCategory;
  name: string;
  description: string;
  likelihood: string;
  impact: string;
  score: number;
  level: string;
  owner: string;
  status: RiskStatus;
  updatedAt: string;
}

// ─────────────────────────────────────────────────────────────
// Mapping helpers
// ─────────────────────────────────────────────────────────────

function normalizeCategory(cat: string): RiskCategory {
  const c = cat.toLowerCase();
  if (c === "technical") return "TECHNICAL";
  if (c === "compliance") return "COMPLIANCE";
  if (c === "vendor") return "VENDOR";
  if (c === "reputational") return "REPUTATIONAL";
  return "OPERATIONAL";
}

function normalizeStatus(s: string): RiskStatus {
  const v = s.toUpperCase();
  if (["OPEN", "MITIGATING", "ACCEPTED", "TRANSFERRED", "CLOSED", "IDENTIFIED"].includes(v)) return v as RiskStatus;
  return "OPEN";
}

function mapApiRisk(r: ApiRisk): RiskItem {
  return {
    id: r.id,
    category: normalizeCategory(r.risk_category),
    name: r.name,
    description: r.description || r.name,
    likelihood: r.likelihood,
    impact: r.impact,
    score: r.risk_score,
    level: r.risk_level,
    owner: r.owner || "Unassigned",
    status: normalizeStatus(r.status),
    updatedAt: r.updated_at.slice(0, 10),
  };
}

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const CATEGORY_META: Record<RiskCategory, { label: string; color: string; icon: React.ElementType }> = {
  TECHNICAL:    { label: "Technical",    color: "#3b82f6", icon: Server },
  OPERATIONAL:  { label: "Operational",  color: "#f97316", icon: Zap },
  COMPLIANCE:   { label: "Compliance",   color: "#a855f7", icon: ShieldCheck },
  VENDOR:       { label: "Vendor",       color: "#eab308", icon: Building2 },
  REPUTATIONAL: { label: "Reputational", color: "#ec4899", icon: Globe },
};

const STATUS_META: Record<RiskStatus, { label: string; cls: string }> = {
  OPEN:       { label: "Open",       cls: "border-red-500/40 text-red-400 bg-red-500/10" },
  MITIGATING: { label: "Mitigating", cls: "border-orange-500/40 text-orange-400 bg-orange-500/10" },
  ACCEPTED:   { label: "Accepted",   cls: "border-blue-500/40 text-blue-400 bg-blue-500/10" },
  TRANSFERRED:{ label: "Transferred",cls: "border-purple-500/40 text-purple-400 bg-purple-500/10" },
  CLOSED:     { label: "Closed",     cls: "border-green-500/40 text-green-400 bg-green-500/10" },
  IDENTIFIED: { label: "Identified", cls: "border-yellow-500/40 text-yellow-400 bg-yellow-500/10" },
};

function scoreBadgeCls(score: number): string {
  if (score >= 20) return "border-red-500/40 text-red-400 bg-red-500/10";
  if (score >= 15) return "border-orange-500/40 text-orange-400 bg-orange-500/10";
  if (score >= 9)  return "border-yellow-500/40 text-yellow-400 bg-yellow-500/10";
  return "border-green-500/40 text-green-400 bg-green-500/10";
}

function scoreLabel(score: number): string {
  if (score >= 20) return "CRITICAL";
  if (score >= 15) return "HIGH";
  if (score >= 9)  return "MEDIUM";
  return "LOW";
}

function scoreColor(score: number): string {
  if (score >= 20) return "#ef4444";
  if (score >= 15) return "#f97316";
  if (score >= 9)  return "#eab308";
  return "#22c55e";
}

function heatZoneColor(score: number): string {
  if (score >= 20) return "rgba(239,68,68,0.25)";
  if (score >= 15) return "rgba(249,115,22,0.22)";
  if (score >= 9)  return "rgba(234,179,8,0.20)";
  return "rgba(34,197,94,0.15)";
}

// ─────────────────────────────────────────────────────────────
// Auth headers helper
// ─────────────────────────────────────────────────────────────

function apiHeaders(): Record<string, string> {
  const token = getStoredAuthToken();
  const strategy = getStoredAuthStrategy();
  const orgId = getStoredOrgId();
  const h: Record<string, string> = { "Content-Type": "application/json", "X-Org-ID": orgId };
  if (token) {
    if (strategy === "jwt") {
      h.Authorization = token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
    } else {
      h["X-API-Key"] = token;
    }
  }
  return h;
}

// ─────────────────────────────────────────────────────────────
// Risk Heat Map — score-based 5×5 SVG grid
// ─────────────────────────────────────────────────────────────

function RiskHeatMap({ risks, selectedId, onSelect }: { risks: RiskItem[]; selectedId: string | null; onSelect: (id: string) => void }) {
  const CELL = 64;
  const PAD = { top: 24, left: 56, bottom: 40, right: 16 };
  const W = CELL * 5 + PAD.left + PAD.right;
  const H = CELL * 5 + PAD.top + PAD.bottom;

  // Map likelihood/impact strings to 1-5
  const likelihoodVal = (l: string) => {
    const m: Record<string, number> = { rare: 1, unlikely: 2, possible: 3, likely: 4, almost_certain: 5 };
    return m[l.toLowerCase()] ?? 3;
  };
  const impactVal = (i: string) => {
    const m: Record<string, number> = { negligible: 1, minor: 2, moderate: 3, major: 4, catastrophic: 5 };
    return m[i.toLowerCase()] ?? 3;
  };

  const cellMap = useMemo(() => {
    const m: Record<string, RiskItem[]> = {};
    risks.forEach((r) => {
      const lv = likelihoodVal(r.likelihood);
      const iv = impactVal(r.impact);
      const key = `${lv}-${iv}`;
      if (!m[key]) m[key] = [];
      m[key].push(r);
    });
    return m;
  }, [risks]);

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} className="overflow-visible">
      <text x={10} y={PAD.top + (CELL * 5) / 2} textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize={9} fontWeight="600" letterSpacing="0.08em"
        transform={`rotate(-90, 10, ${PAD.top + (CELL * 5) / 2})`}>LIKELIHOOD</text>
      <text x={PAD.left + (CELL * 5) / 2} y={H - 4} textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize={9} fontWeight="600" letterSpacing="0.08em">IMPACT</text>

      {Array.from({ length: 5 }, (_, rowIdx) => {
        const likelihood = 5 - rowIdx;
        return Array.from({ length: 5 }, (_, colIdx) => {
          const impact = colIdx + 1;
          const x = PAD.left + colIdx * CELL;
          const y = PAD.top + rowIdx * CELL;
          const key = `${likelihood}-${impact}`;
          const cellRisks = cellMap[key] ?? [];
          const score = likelihood * impact;
          const bgColor = heatZoneColor(score);
          return (
            <g key={key}>
              <rect x={x} y={y} width={CELL} height={CELL} fill={bgColor} stroke="hsl(var(--border))" strokeWidth={0.5} />
              <text x={x + CELL - 6} y={y + 13} textAnchor="end" fontSize={8} fill="hsl(var(--muted-foreground))" opacity={0.5} fontFamily="monospace">{score}</text>
              {cellRisks.slice(0, 4).map((risk, di) => {
                const dotX = x + 14 + (di % 2) * 28;
                const dotY = y + 22 + Math.floor(di / 2) * 24;
                const isSelected = risk.id === selectedId;
                const cat = CATEGORY_META[risk.category];
                return (
                  <g key={risk.id} onClick={() => onSelect(risk.id)} style={{ cursor: "pointer" }}>
                    {isSelected && (
                      <circle cx={dotX} cy={dotY} r={11} fill={cat.color} opacity={0.2}>
                        <animate attributeName="r" values="10;14;10" dur="2s" repeatCount="indefinite" />
                      </circle>
                    )}
                    <circle cx={dotX} cy={dotY} r={isSelected ? 8 : 7} fill={cat.color} opacity={isSelected ? 1 : 0.85}
                      stroke={isSelected ? "white" : "transparent"} strokeWidth={1.5} />
                    <text x={dotX} y={dotY + 3.5} textAnchor="middle" fontSize={6.5} fontWeight="700" fill="white" style={{ pointerEvents: "none" }}>
                      {String(risks.findIndex((r) => r.id === risk.id) + 1).padStart(2, "0")}
                    </text>
                  </g>
                );
              })}
              {cellRisks.length > 4 && (
                <text x={x + CELL - 4} y={y + CELL - 4} textAnchor="end" fontSize={7} fill="hsl(var(--muted-foreground))">+{cellRisks.length - 4}</text>
              )}
            </g>
          );
        });
      })}

      {[1, 2, 3, 4, 5].map((lv) => {
        const y = PAD.top + (5 - lv) * CELL + CELL / 2;
        return <text key={lv} x={PAD.left - 6} y={y + 3} textAnchor="end" fontSize={8.5} fill="hsl(var(--muted-foreground))">{lv}</text>;
      })}
      {[1, 2, 3, 4, 5].map((iv) => {
        const x = PAD.left + (iv - 1) * CELL + CELL / 2;
        return <text key={iv} x={x} y={PAD.top + 5 * CELL + 14} textAnchor="middle" fontSize={8.5} fill="hsl(var(--muted-foreground))">{iv}</text>;
      })}
    </svg>
  );
}

// ─────────────────────────────────────────────────────────────
// Risk Detail Panel
// ─────────────────────────────────────────────────────────────

function RiskDetailPanel({ risk }: { risk: RiskItem | null }) {
  if (!risk) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 py-12 text-muted-foreground">
        <ShieldCheck className="h-8 w-8 opacity-20" />
        <p className="text-xs text-center">Select a risk from the heat map or table to view details</p>
      </div>
    );
  }
  return (
    <AnimatePresence mode="wait">
      <motion.div key={risk.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.25 }} className="space-y-4">
        <div className="flex items-start justify-between gap-2">
          <div>
            <p className="text-xs font-mono text-muted-foreground">{risk.id.slice(0, 8)}…</p>
            <p className="text-sm font-semibold leading-snug line-clamp-3 mt-1">{risk.description}</p>
          </div>
          <Badge className={cn("text-[10px] border shrink-0", scoreBadgeCls(risk.score))}>{scoreLabel(risk.score)}</Badge>
        </div>
        <Separator />
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div><p className="text-muted-foreground">Category</p><p className="font-medium mt-0.5" style={{ color: CATEGORY_META[risk.category].color }}>{CATEGORY_META[risk.category].label}</p></div>
          <div><p className="text-muted-foreground">Score</p><p className="font-bold mt-0.5 tabular-nums" style={{ color: scoreColor(risk.score) }}>{risk.score}</p></div>
          <div><p className="text-muted-foreground">Likelihood</p><p className="font-medium mt-0.5 capitalize">{risk.likelihood}</p></div>
          <div><p className="text-muted-foreground">Impact</p><p className="font-medium mt-0.5 capitalize">{risk.impact}</p></div>
          <div><p className="text-muted-foreground">Owner</p><p className="font-medium mt-0.5 truncate">{risk.owner || "—"}</p></div>
          <div><p className="text-muted-foreground">Updated</p><p className="font-mono mt-0.5">{risk.updatedAt}</p></div>
        </div>
        <Separator />
        <div>
          <p className="text-xs text-muted-foreground mb-1">Risk Score</p>
          <Progress value={Math.min(100, (risk.score / 25) * 100)} className="h-2" />
          <p className="text-xs text-muted-foreground mt-1">{risk.score} / 25</p>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

// ─────────────────────────────────────────────────────────────
// Status Badge
// ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: RiskStatus }) {
  const meta = STATUS_META[status] ?? STATUS_META.OPEN;
  return (
    <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium", meta.cls)}>{meta.label}</span>
  );
}

// ─────────────────────────────────────────────────────────────
// Main Dashboard Component
// ─────────────────────────────────────────────────────────────

export default function RiskRegister() {
  const orgId = getStoredOrgId();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [sortField, setSortField] = useState<keyof RiskItem>("score");
  const [sortAsc, setSortAsc] = useState(false);

  const { data: rawRisks, isLoading, isError, refetch } = useQuery<RiskItem[]>({
    queryKey: ["risk-register", orgId],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/risk-register-engine/risks", { org_id: orgId });
      const res = await axios.get<ApiRisk[]>(url, { headers: apiHeaders() });
      const arr = Array.isArray(res.data) ? res.data : [];
      return arr.map(mapApiRisk);
    },
    refetchInterval: 120_000,
    staleTime: 60_000,
  });

  const risks = rawRisks ?? [];

  const selectedRisk = useMemo(() => risks.find((r) => r.id === selectedId) ?? null, [risks, selectedId]);

  const stats = useMemo(() => {
    const critical = risks.filter((r) => r.score >= 20).length;
    const high = risks.filter((r) => r.score >= 15 && r.score < 20).length;
    const open = risks.filter((r) => r.status === "OPEN" || r.status === "IDENTIFIED").length;
    return { total: risks.length, critical, high, open };
  }, [risks]);

  const tableRisks = useMemo(() => {
    let filtered = risks.filter((r) => {
      if (categoryFilter !== "ALL" && r.category !== categoryFilter) return false;
      if (statusFilter !== "ALL" && r.status !== statusFilter) return false;
      return true;
    });
    filtered.sort((a, b) => {
      const av = a[sortField];
      const bv = b[sortField];
      if (typeof av === "number" && typeof bv === "number") return sortAsc ? av - bv : bv - av;
      return sortAsc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });
    return filtered;
  }, [risks, categoryFilter, statusFilter, sortField, sortAsc]);

  const handleSort = useCallback((field: keyof RiskItem) => {
    if (sortField === field) setSortAsc((a) => !a);
    else { setSortField(field); setSortAsc(false); }
  }, [sortField]);

  const SortIcon = ({ field }: { field: keyof RiskItem }) => {
    if (sortField !== field) return <ArrowUpDown className="h-3 w-3 opacity-30 inline ml-1" />;
    return sortAsc ? <ChevronUp className="h-3 w-3 inline ml-1" /> : <ChevronDown className="h-3 w-3 inline ml-1" />;
  };

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load risk register" onRetry={refetch} />;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-5">
      <PageHeader title="Risk Register" description="Organizational security risk tracking — likelihood, impact, and trend analysis" badge="P08">
        <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5" onClick={() => refetch()}>
          <RefreshCw className="h-3.5 w-3.5" />Refresh
        </Button>
      </PageHeader>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <KpiCard title="Total Risks" value={stats.total} icon={Target} trend="flat" trendLabel="Tracked org-wide" />
        <KpiCard title="Critical (≥20)" value={stats.critical} icon={AlertTriangle}
          trend={stats.critical > 0 ? "down" : "up"} trendLabel={stats.critical > 0 ? "Requires immediate action" : "None active"}
          className={cn(stats.critical > 0 && "border-red-500/30 bg-red-500/5")} />
        <KpiCard title="High (15–19)" value={stats.high} icon={Shield}
          trend={stats.high > 3 ? "down" : "flat"} trendLabel="Elevated exposure"
          className={cn(stats.high > 3 && "border-orange-500/20")} />
        <KpiCard title="Open / Identified" value={stats.open} icon={Clock}
          trend={stats.open > 5 ? "down" : "flat"} trendLabel="Awaiting treatment" />
      </div>

      {/* Empty state */}
      {risks.length === 0 && (
        <EmptyState icon={Shield} title="No risks found" description="No risk register entries found for this organisation. Add your first risk via the API." />
      )}

      {risks.length > 0 && (
        <>
          {/* Heat Map + Detail */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }} className="lg:col-span-2">
              <Card className="h-full">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Target className="h-4 w-4 text-orange-400" />Risk Heat Map
                  </CardTitle>
                  <CardDescription className="text-xs">Likelihood (Y) × Impact (X) — click dot to inspect</CardDescription>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="flex items-center gap-3 mb-2 flex-wrap">
                    {[{ label: "Critical", color: "bg-red-500/40" }, { label: "High", color: "bg-orange-500/35" }, { label: "Medium", color: "bg-yellow-500/30" }, { label: "Low", color: "bg-green-500/25" }].map(({ label, color }) => (
                      <div key={label} className="flex items-center gap-1">
                        <div className={cn("h-2.5 w-2.5 rounded-sm", color)} />
                        <span className="text-[10px] text-muted-foreground">{label}</span>
                      </div>
                    ))}
                  </div>
                  <RiskHeatMap risks={risks} selectedId={selectedId} onSelect={(id) => setSelectedId((prev) => prev === id ? null : id)} />
                </CardContent>
              </Card>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.12 }} className="lg:col-span-3">
              <Card className="h-full">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-green-400" />Risk Detail
                    </CardTitle>
                    {selectedRisk && (
                      <button onClick={() => setSelectedId(null)} className="text-muted-foreground hover:text-foreground transition-colors">
                        <X className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                  {selectedRisk && (
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge className={cn("text-[9px] border", scoreBadgeCls(selectedRisk.score))}>Score {selectedRisk.score}</Badge>
                      <span className="text-[10px] text-muted-foreground">{selectedRisk.updatedAt}</span>
                    </div>
                  )}
                </CardHeader>
                <CardContent><RiskDetailPanel risk={selectedRisk} /></CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Risk Table */}
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 }}>
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div>
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Shield className="h-4 w-4 text-primary" />Risk Register
                    </CardTitle>
                    <CardDescription className="text-xs">{tableRisks.length} of {risks.length} risks</CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                    <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                      <SelectTrigger className="h-7 text-xs w-[130px]"><SelectValue placeholder="Category" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ALL" className="text-xs">All Categories</SelectItem>
                        {(Object.entries(CATEGORY_META) as [RiskCategory, typeof CATEGORY_META[RiskCategory]][]).map(([k, v]) => (
                          <SelectItem key={k} value={k} className="text-xs">{v.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Select value={statusFilter} onValueChange={setStatusFilter}>
                      <SelectTrigger className="h-7 text-xs w-[120px]"><SelectValue placeholder="Status" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ALL" className="text-xs">All Statuses</SelectItem>
                        {(Object.keys(STATUS_META) as RiskStatus[]).map((s) => (
                          <SelectItem key={s} value={s} className="text-xs">{STATUS_META[s].label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <ScrollArea className="h-[400px]">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow className="hover:bg-transparent sticky top-0 bg-card z-10 border-b">
                          <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("category")}>
                            Category <SortIcon field="category" />
                          </TableHead>
                          <TableHead className="text-[10px] h-8 font-semibold">Name / Description</TableHead>
                          <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("likelihood")}>
                            Likelihood <SortIcon field="likelihood" />
                          </TableHead>
                          <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("impact")}>
                            Impact <SortIcon field="impact" />
                          </TableHead>
                          <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground text-center" onClick={() => handleSort("score")}>
                            Score <SortIcon field="score" />
                          </TableHead>
                          <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("owner")}>
                            Owner <SortIcon field="owner" />
                          </TableHead>
                          <TableHead className="text-[10px] h-8 font-semibold">Status</TableHead>
                          <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("updatedAt")}>
                            Updated <SortIcon field="updatedAt" />
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {tableRisks.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={8} className="text-center py-8 text-sm text-muted-foreground">No risks match the current filters.</TableCell>
                          </TableRow>
                        ) : (
                          tableRisks.map((risk) => {
                            const cat = CATEGORY_META[risk.category];
                            const isSelected = risk.id === selectedId;
                            return (
                              <TableRow key={risk.id} onClick={() => setSelectedId((prev) => prev === risk.id ? null : risk.id)}
                                className={cn("cursor-pointer transition-colors text-xs", isSelected ? "bg-primary/8 border-l-2 border-l-primary" : "hover:bg-muted/30")}>
                                <TableCell className="py-2">
                                  <div className="flex items-center gap-1.5">
                                    <div className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: cat.color }} />
                                    <span className="text-[10px]" style={{ color: cat.color }}>{cat.label}</span>
                                  </div>
                                </TableCell>
                                <TableCell className="py-2 max-w-[200px]">
                                  <p className="text-xs leading-snug line-clamp-2">{risk.description}</p>
                                </TableCell>
                                <TableCell className="py-2 capitalize text-xs">{risk.likelihood}</TableCell>
                                <TableCell className="py-2 capitalize text-xs">{risk.impact}</TableCell>
                                <TableCell className="py-2 text-center">
                                  <Badge className={cn("text-[10px] border px-1.5 py-0 font-bold", scoreBadgeCls(risk.score))}>{risk.score}</Badge>
                                </TableCell>
                                <TableCell className="py-2">
                                  <span className="text-xs truncate max-w-[80px] block">{risk.owner || "—"}</span>
                                </TableCell>
                                <TableCell className="py-2"><StatusBadge status={risk.status} /></TableCell>
                                <TableCell className="py-2">
                                  <span className="text-[10px] text-muted-foreground tabular-nums">{risk.updatedAt}</span>
                                </TableCell>
                              </TableRow>
                            );
                          })
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </motion.div>
        </>
      )}
    </motion.div>
  );
}
