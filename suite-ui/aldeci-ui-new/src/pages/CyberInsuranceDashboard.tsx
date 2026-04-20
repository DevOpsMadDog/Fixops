/**
 * Cyber Insurance Dashboard
 *
 * Coverage management, claims, and security assessment for cyber insurance.
 *   1. KPI cards: Active Policies, Total Coverage, Annual Premium, Pending Claims
 *   2. Policies table (live from /api/v1/cyber-insurance/policies)
 *   3. Claims table (live from /api/v1/cyber-insurance/claims)
 *   4. Coverage Assessment section (live from /api/v1/cyber-insurance/assessments + /stats)
 *
 * API: GET /api/v1/cyber-insurance/{policies,claims,assessments,stats}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, FileText, AlertTriangle, DollarSign,
  RefreshCw, CheckCircle, Clock, XCircle, BarChart3,
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
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_POLICIES = [
  {
    policy_id: "POL-001",
    carrier: "CyberShield Underwriters",
    policy_number: "CSU-****-8821",
    coverage_type: "both",
    coverage_limit: 2000000,
    deductible: 50000,
    premium_annual: 22400,
    effective_date: "2026-01-01",
    expiry_date: "2026-12-31",
    status: "active",
    covered_events: ["ransomware", "data_breach", "social_engineering"],
  },
  {
    policy_id: "POL-002",
    carrier: "Nexus Cyber Re",
    policy_number: "NCR-****-4410",
    coverage_type: "both",
    coverage_limit: 2000000,
    deductible: 100000,
    premium_annual: 18600,
    effective_date: "2026-01-01",
    expiry_date: "2026-12-31",
    status: "active",
    covered_events: ["network_failure", "business_interruption"],
  },
  {
    policy_id: "POL-003",
    carrier: "GlobalSec Assurance",
    policy_number: "GSA-****-0073",
    coverage_type: "third_party",
    coverage_limit: 1000000,
    deductible: 25000,
    premium_annual: 6000,
    effective_date: "2025-07-01",
    expiry_date: "2026-06-30",
    status: "pending",
    covered_events: ["data_breach"],
  },
];

const MOCK_CLAIMS = [
  { claim_id: "CLM-2024-001", policy_id: "POL-001", incident_type: "ransomware",            incident_date: "2024-09-14", estimated_loss: 420000, settlement_amount: 380000, status: "settled",      adjuster: "Marsh & McLennan", filed_at: "2024-09-15" },
  { claim_id: "CLM-2025-002", policy_id: "POL-001", incident_type: "data_breach",           incident_date: "2025-02-28", estimated_loss: 85000,  settlement_amount: 72000,  status: "settled",      adjuster: "Aon Cyber",        filed_at: "2025-03-01" },
  { claim_id: "CLM-2025-003", policy_id: "POL-002", incident_type: "business_interruption", incident_date: "2025-06-10", estimated_loss: 210000, settlement_amount: null,   status: "approved",     adjuster: "Marsh & McLennan", filed_at: "2025-06-12" },
  { claim_id: "CLM-2025-004", policy_id: "POL-001", incident_type: "data_breach",           incident_date: "2025-11-01", estimated_loss: 47000,  settlement_amount: null,   status: "under_review", adjuster: "Willis Towers",    filed_at: "2025-11-03" },
  { claim_id: "CLM-2026-005", policy_id: "POL-001", incident_type: "ransomware",            incident_date: "2026-01-18", estimated_loss: 650000, settlement_amount: null,   status: "filed",        adjuster: "Aon Cyber",        filed_at: "2026-01-19" },
  { claim_id: "CLM-2026-006", policy_id: "POL-002", incident_type: "business_interruption", incident_date: "2026-03-05", estimated_loss: 95000,  settlement_amount: null,   status: "under_review", adjuster: "Willis Towers",    filed_at: "2026-03-06" },
];

const MOCK_STATS = {
  total_policies: 3,
  active_policies: 2,
  total_coverage: 5000000,
  annual_premium: 47000,
  total_claims: 6,
  open_claims: 3,
  settled_amount: 452000,
};

const MOCK_ASSESSMENTS = [
  { assessment_id: "ASSESS-001", policy_id: "POL-001", overall_score: 66, mfa_score: 91, backup_score: 78, incident_response_score: 65, patch_score: 54, training_score: 42, recommendations: ["Improve security awareness training", "Enhance patch management cadence"], assessed_at: "2026-04-01" },
];

// ── Helpers ────────────────────────────────────────────────────

function fmtMoney(n: number): string {
  if (n >= 1000000) return `$${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `$${(n / 1000).toFixed(0)}K`;
  return `$${n.toLocaleString()}`;
}

function PolicyStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:  "border-green-500/30 text-green-400 bg-green-500/10",
    pending: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    expired: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function ClaimStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    filed:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
    under_review: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    approved:     "border-purple-500/30 text-purple-400 bg-purple-500/10",
    denied:       "border-red-500/30 text-red-400 bg-red-500/10",
    settled:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function IncidentTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    ransomware:            "border-red-500/30 text-red-400 bg-red-500/10",
    data_breach:           "border-orange-500/30 text-orange-400 bg-orange-500/10",
    business_interruption: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    social_engineering:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    network_failure:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function ScoreBar({ label, score, color }: { label: string; score: number; color: string }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className={cn("font-semibold tabular-nums", score >= 80 ? "text-green-400" : score >= 60 ? "text-yellow-400" : "text-red-400")}>
          {score}%
        </span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.7 }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function CyberInsuranceDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    policies: any[] | null;
    claims: any[] | null;
    stats: any | null;
    assessments: any[] | null;
  }>({ policies: null, claims: null, stats: null, assessments: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/cyber-insurance/policies?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cyber-insurance/claims?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cyber-insurance/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cyber-insurance/assessments?org_id=${ORG_ID}`),
    ]).then(([policiesRes, claimsRes, statsRes, assessRes]) => {
      setLiveData({
        policies:    policiesRes.status    === "fulfilled" ? policiesRes.value    : null,
        claims:      claimsRes.status      === "fulfilled" ? claimsRes.value      : null,
        stats:       statsRes.status       === "fulfilled" ? statsRes.value       : null,
        assessments: assessRes.status      === "fulfilled" ? assessRes.value      : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Resolved data — live ?? mock
  const policies    = liveData.policies    ?? MOCK_POLICIES;
  const claims      = liveData.claims      ?? MOCK_CLAIMS;
  const stats       = liveData.stats       ?? MOCK_STATS;
  const assessments = liveData.assessments ?? MOCK_ASSESSMENTS;
  const assessment  = assessments[0];

  const activePolicies  = stats?.active_policies  ?? policies.filter((p: any) => p.status === "active").length;
  const totalCoverage   = stats?.total_coverage   ?? policies.reduce((s: number, p: any) => s + (p.coverage_limit ?? 0), 0);
  const annualPremium   = stats?.annual_premium    ?? policies.reduce((s: number, p: any) => s + (p.premium_annual ?? 0), 0);
  const openClaims      = stats?.open_claims       ?? claims.filter((c: any) => c.status !== "settled" && c.status !== "denied").length;

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
        description="Policy management, claims tracking, and coverage assessment"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Policies"   value={activePolicies}               icon={Shield}        trend="stable" />
        <KpiCard title="Total Coverage"    value={fmtMoney(totalCoverage)}      icon={DollarSign}    trend="up"     className="border-green-500/20" />
        <KpiCard title="Annual Premium"    value={fmtMoney(annualPremium)}      icon={FileText}      trend="stable" className="border-blue-500/20" />
        <KpiCard title="Pending Claims"    value={openClaims}                   icon={AlertTriangle} trend="down"   className="border-amber-500/20" />
      </div>

      {/* Policies Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" />
              Insurance Policies
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {policies.length} total
            </Badge>
          </div>
          <CardDescription className="text-xs">Active and pending cyber insurance policies</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Carrier</TableHead>
                  <TableHead className="text-[11px] h-8">Policy #</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Coverage Limit</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Deductible</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Annual Premium</TableHead>
                  <TableHead className="text-[11px] h-8">Effective</TableHead>
                  <TableHead className="text-[11px] h-8">Expires</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((p: any) => (
                  <TableRow key={p.policy_id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{p.carrier}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{p.policy_number}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-border text-muted-foreground capitalize">
                        {(p.coverage_type ?? "both").replace(/_/g, " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-right font-semibold text-green-400">
                      {fmtMoney(p.coverage_limit ?? 0)}
                    </TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-right text-muted-foreground">
                      {fmtMoney(p.deductible ?? 0)}
                    </TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-right text-blue-400 font-medium">
                      {fmtMoney(p.premium_annual ?? 0)}/yr
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{p.effective_date}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{p.expiry_date}</TableCell>
                    <TableCell className="py-2"><PolicyStatusBadge status={p.status ?? "active"} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Claims Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
              Claims
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {openClaims} open
            </Badge>
          </div>
          <CardDescription className="text-xs">All filed claims and their current status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Claim ID</TableHead>
                  <TableHead className="text-[11px] h-8">Incident Type</TableHead>
                  <TableHead className="text-[11px] h-8">Incident Date</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Estimated Loss</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Settlement</TableHead>
                  <TableHead className="text-[11px] h-8">Adjuster</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {claims.map((c: any) => (
                  <TableRow key={c.claim_id} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{c.claim_id}</TableCell>
                    <TableCell className="py-2"><IncidentTypeBadge type={c.incident_type ?? ""} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{c.incident_date}</TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-right text-red-400 font-medium">
                      {fmtMoney(c.estimated_loss ?? 0)}
                    </TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-right text-green-400 font-medium">
                      {c.settlement_amount != null ? fmtMoney(c.settlement_amount) : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{c.adjuster}</TableCell>
                    <TableCell className="py-2"><ClaimStatusBadge status={c.status ?? "filed"} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Coverage Assessment */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Security Control Scores */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              Coverage Assessment
            </CardTitle>
            <CardDescription className="text-xs">Security control scores for insurability</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {assessment && (
              <>
                <ScoreBar label="Multi-Factor Authentication"  score={assessment.mfa_score ?? 91}               color={assessment.mfa_score >= 80 ? "bg-green-500" : assessment.mfa_score >= 60 ? "bg-yellow-500" : "bg-red-500"} />
                <ScoreBar label="Backup & Recovery"            score={assessment.backup_score ?? 78}             color={assessment.backup_score >= 80 ? "bg-green-500" : assessment.backup_score >= 60 ? "bg-yellow-500" : "bg-red-500"} />
                <ScoreBar label="Incident Response Plan"       score={assessment.incident_response_score ?? 65}  color={assessment.incident_response_score >= 80 ? "bg-green-500" : assessment.incident_response_score >= 60 ? "bg-yellow-500" : "bg-red-500"} />
                <ScoreBar label="Patch Management"             score={assessment.patch_score ?? 54}              color={assessment.patch_score >= 80 ? "bg-green-500" : assessment.patch_score >= 60 ? "bg-yellow-500" : "bg-red-500"} />
                <ScoreBar label="Security Awareness Training"  score={assessment.training_score ?? 42}           color={assessment.training_score >= 80 ? "bg-green-500" : assessment.training_score >= 60 ? "bg-yellow-500" : "bg-red-500"} />
              </>
            )}
          </CardContent>
        </Card>

        {/* Overall Score + Recommendations */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-400" />
              Overall Risk Score
            </CardTitle>
            <CardDescription className="text-xs">Insurability rating and recommendations</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {/* Score gauge */}
            <div className="flex items-center gap-4">
              <div className="relative flex h-24 w-24 shrink-0 items-center justify-center rounded-full border-4 border-muted/30">
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.5 }}
                  className="text-center"
                >
                  <div className={cn("text-2xl font-bold", (assessment?.overall_score ?? 66) >= 80 ? "text-green-400" : (assessment?.overall_score ?? 66) >= 60 ? "text-yellow-400" : "text-red-400")}>
                    {assessment?.overall_score ?? 66}
                  </div>
                  <div className="text-[10px] text-muted-foreground">/ 100</div>
                </motion.div>
              </div>
              <div className="space-y-1.5">
                <div className="text-sm font-semibold">
                  {(assessment?.overall_score ?? 66) >= 80 ? "Excellent" : (assessment?.overall_score ?? 66) >= 60 ? "Adequate" : "Needs Improvement"}
                </div>
                <div className="text-xs text-muted-foreground">
                  Last assessed: {assessment?.assessed_at ?? "2026-04-01"}
                </div>
                <Badge className={cn("text-[10px] border", (assessment?.overall_score ?? 66) >= 80 ? "border-green-500/30 text-green-400 bg-green-500/10" : (assessment?.overall_score ?? 66) >= 60 ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" : "border-red-500/30 text-red-400 bg-red-500/10")}>
                  {(assessment?.overall_score ?? 66) >= 80 ? "Preferred Risk" : (assessment?.overall_score ?? 66) >= 60 ? "Standard Risk" : "High Risk"}
                </Badge>
              </div>
            </div>

            {/* Recommendations */}
            {assessment?.recommendations && assessment.recommendations.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Recommendations</div>
                {assessment.recommendations.map((rec: string, i: number) => (
                  <div key={i} className="flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-2.5">
                    <Clock className="h-3 w-3 shrink-0 text-amber-400 mt-0.5" />
                    <span className="text-xs text-muted-foreground">{rec}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Portfolio stats */}
            <div className="grid grid-cols-2 gap-2 pt-1">
              <div className="rounded-lg border border-border bg-muted/20 p-2.5 text-center">
                <div className="text-lg font-bold text-green-400">{fmtMoney(stats?.settled_amount ?? 452000)}</div>
                <div className="text-[10px] text-muted-foreground">Total Settled</div>
              </div>
              <div className="rounded-lg border border-border bg-muted/20 p-2.5 text-center">
                <div className="text-lg font-bold text-red-400">{stats?.total_claims ?? claims.length}</div>
                <div className="text-[10px] text-muted-foreground">Total Claims</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
