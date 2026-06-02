/**
 * Cyber Insurance Dashboard
 *
 * Coverage management, claims, and security assessment for cyber insurance.
 *   1. KPIs: Total Coverage, Active Policies, Open Claims, Annual Premium
 *   2. Policy cards (from API)
 *   3. Risk assessment score bars + overall gauge
 *   4. Claims table
 *   5. Coverage gap analysis
 *
 * API: GET /api/v1/cyber-insurance/policies
 *      GET /api/v1/cyber-insurance/claims
 *      GET /api/v1/cyber-insurance/stats
 */

import { useState, useEffect } from "react";
import { getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import { Shield, FileText, AlertTriangle, DollarSign, RefreshCw, BarChart3 } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "demo-key";

async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
  });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

interface Policy {
  policy_id: string;
  carrier: string;
  policy_number: string;
  coverage_type: string;
  coverage_limit: number;
  deductible: number;
  premium_annual: number;
  effective_date: string;
  expiry_date: string;
  status: string;
  covered_events: string[];
}

interface Claim {
  claim_id: string;
  policy_id: string;
  incident_type: string;
  incident_date: string;
  estimated_loss: number;
  status: string;
  adjuster: string | null;
  settlement_amount: number | null;
}

interface InsuranceStats {
  total_coverage: number;
  active_policies: number;
  open_claims: number;
  total_settled: number;
  avg_premium: number;
  coverage_gap_analysis?: {
    adequately_covered: boolean;
    gap: number;
  };
}

// ── Helpers ────────────────────────────────────────────────────

function fmt(n: number): string {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n}`;
}

function PolicyStatusBadge({ status }: { status: string }) {
  const cls =
    status === "active"   ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "pending"  ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
    status === "expired"  ? "border-red-500/30 text-red-400 bg-red-500/10" :
                            "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{status}</Badge>;
}

function IncidentBadge({ type }: { type: string }) {
  const label = type.replace(/_/g, " ");
  const cls =
    type === "ransomware"            ? "border-red-500/30 text-red-400 bg-red-500/10" :
    type === "data_breach"           ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    type === "business_interruption" ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
                                       "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{label}</Badge>;
}

function ClaimStatusBadge({ status }: { status: string }) {
  const label = status.replace(/_/g, " ");
  const cls =
    status === "filed"        ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    status === "under_review" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
    status === "approved"     ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "denied"       ? "border-red-500/30 text-red-400 bg-red-500/10" :
                                "border-slate-500/30 text-slate-400 bg-slate-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{label}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

const ORG_ID = (getStoredOrgId() ?? "default");
export default function CyberInsurance() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [stats, setStats] = useState<InsuranceStats | null>(null);

  const fetchAll = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch("/api/v1/cyber-insurance/policies?org_id=" + ORG_ID),
      apiFetch("/api/v1/cyber-insurance/claims?org_id=" + ORG_ID),
      apiFetch("/api/v1/cyber-insurance/stats?org_id=" + ORG_ID),
    ]).then(([polRes, clmRes, stsRes]) => {
      if (polRes.status === "fulfilled") {
        const d = polRes.value;
        setPolicies(Array.isArray(d) ? d : (d.items ?? d.policies ?? []));
      }
      if (clmRes.status === "fulfilled") {
        const d = clmRes.value;
        setClaims(Array.isArray(d) ? d : (d.items ?? d.claims ?? []));
      }
      if (stsRes.status === "fulfilled") setStats(stsRes.value);
      if (polRes.status === "rejected" && clmRes.status === "rejected") {
        setError("Failed to load cyber insurance data");
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { fetchAll(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAll();
    setTimeout(() => setRefreshing(false), 800);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
      </div>
    );
  }

  if (error && policies.length === 0 && claims.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <AlertTriangle className="h-10 w-10 text-amber-400 opacity-60" />
        <p className="text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" onClick={fetchAll}>Retry</Button>
      </div>
    );
  }

  const totalCoverage   = stats?.total_coverage   ?? policies.reduce((s, p) => s + (p.coverage_limit ?? 0), 0);
  const activePolicies  = stats?.active_policies  ?? policies.filter((p) => p.status === "active").length;
  const openClaims      = stats?.open_claims       ?? claims.filter((c) => c.status !== "settled" && c.status !== "denied").length;
  const avgPremium      = stats?.avg_premium       ?? (policies.length ? policies.reduce((s, p) => s + (p.premium_annual ?? 0), 0) / policies.length : 0);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Cyber Insurance"
        description="Coverage management, claims, and security assessment"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Coverage"  value={fmt(totalCoverage)}  icon={Shield}        />
        <KpiCard title="Active Policies" value={activePolicies}       icon={FileText}      />
        <KpiCard
          title="Open Claims"
          value={openClaims}
          icon={AlertTriangle}
          trend={openClaims > 0 ? "up" : "flat"}
          className={openClaims > 0 ? "border-amber-500/20" : ""}
        />
        <KpiCard title="Avg Premium" value={`${fmt(avgPremium)}/yr`} icon={DollarSign} />
      </div>

      {/* Policy Cards */}
      {policies.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-14 text-muted-foreground gap-3">
            <Shield className="h-8 w-8 opacity-30" />
            <p className="text-sm">No policies found</p>
            <p className="text-xs">Add a policy to start tracking coverage</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {policies.map((p) => (
            <Card key={p.policy_id} className="flex flex-col">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold">{p.carrier}</CardTitle>
                  <PolicyStatusBadge status={p.status} />
                </div>
                <CardDescription className="text-[11px] font-mono">{p.policy_number}</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-2 flex-1">
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  <div className="text-muted-foreground">Coverage Limit</div>
                  <div className="font-semibold text-right">{fmt(p.coverage_limit)}</div>
                  <div className="text-muted-foreground">Deductible</div>
                  <div className="font-medium text-right">{fmt(p.deductible)}</div>
                  <div className="text-muted-foreground">Premium</div>
                  <div className="font-medium text-right">{fmt(p.premium_annual)}/yr</div>
                  <div className="text-muted-foreground">Effective</div>
                  <div className="tabular-nums text-right">{p.effective_date}</div>
                  <div className="text-muted-foreground">Expires</div>
                  <div className="tabular-nums text-right">{p.expiry_date}</div>
                  <div className="text-muted-foreground">Type</div>
                  <div className="tabular-nums text-right capitalize">{p.coverage_type.replace(/_/g, " ")}</div>
                </div>
                {p.covered_events.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1">
                    {p.covered_events.map((e) => (
                      <Badge key={e} className="text-[10px] border border-border text-muted-foreground capitalize">
                        {e.replace(/_/g, " ")}
                      </Badge>
                    ))}
                  </div>
                )}
                <Button variant="outline" size="sm" className="mt-auto h-7 text-xs w-full">View Details</Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Risk Assessment (from stats gap analysis) + Coverage Gap */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Coverage summary */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Coverage Summary
            </CardTitle>
            <CardDescription className="text-xs">Aggregate coverage position across all policies</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Total Coverage", value: fmt(totalCoverage) },
                { label: "Active Policies", value: String(activePolicies) },
                { label: "Open Claims", value: String(openClaims) },
                { label: "Total Settled", value: fmt(stats?.total_settled ?? 0) },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-lg border border-border/50 bg-muted/10 p-3">
                  <p className="text-[10px] text-muted-foreground">{label}</p>
                  <p className="text-lg font-bold tabular-nums mt-0.5">{value}</p>
                </div>
              ))}
            </div>
            {stats?.coverage_gap_analysis && (
              <div className={cn(
                "rounded-lg border p-3 text-xs",
                stats.coverage_gap_analysis.adequately_covered
                  ? "border-green-500/30 bg-green-500/5 text-green-400"
                  : "border-red-500/30 bg-red-500/5 text-red-400"
              )}>
                {stats.coverage_gap_analysis.adequately_covered
                  ? "Coverage is adequate for current open claim exposure."
                  : `Coverage gap of ${fmt(stats.coverage_gap_analysis.gap)} identified.`}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Claims summary */}
        <Card className="border-orange-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <AlertTriangle className="h-4 w-4" />
              Claims Overview
            </CardTitle>
            <CardDescription className="text-xs">Open and recent claim exposure</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {claims.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground gap-2">
                <FileText className="h-6 w-6 opacity-30" />
                <p className="text-xs">No claims on record</p>
              </div>
            ) : (
              claims.slice(0, 4).map((c) => (
                <div key={c.claim_id} className="rounded-lg border border-border/50 bg-muted/10 p-3 space-y-1">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-xs font-semibold font-mono">{c.claim_id.slice(0, 8).toUpperCase()}</span>
                    <ClaimStatusBadge status={c.status} />
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                    <IncidentBadge type={c.incident_type} />
                    <span className="font-semibold text-foreground">{fmt(c.estimated_loss)}</span>
                  </div>
                  {c.adjuster && <p className="text-[10px] text-muted-foreground">{c.adjuster}</p>}
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      {/* Claims Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-purple-400" />
              Claims History
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">File New Claim</Button>
          </div>
          <CardDescription className="text-xs">All submitted insurance claims and current status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {claims.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-14 text-muted-foreground gap-2">
              <FileText className="h-8 w-8 opacity-30" />
              <p className="text-sm">No claims on record</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Claim ID</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Incident Date</TableHead>
                    <TableHead className="text-[11px] h-8">Est. Loss</TableHead>
                    <TableHead className="text-[11px] h-8">Settlement</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Adjuster</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {claims.map((row) => (
                    <TableRow key={row.claim_id} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-mono py-2.5">{row.claim_id.slice(0, 8).toUpperCase()}</TableCell>
                      <TableCell className="py-2.5"><IncidentBadge type={row.incident_type} /></TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">
                        {row.incident_date ? row.incident_date.slice(0, 10) : "—"}
                      </TableCell>
                      <TableCell className="text-xs py-2.5 font-medium tabular-nums">{fmt(row.estimated_loss)}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">
                        {row.settlement_amount != null ? fmt(row.settlement_amount) : "—"}
                      </TableCell>
                      <TableCell className="py-2.5"><ClaimStatusBadge status={row.status} /></TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">{row.adjuster ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
