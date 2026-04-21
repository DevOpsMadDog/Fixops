/**
 * Cyber Insurance Dashboard
 *
 * Coverage management, claims, and security assessment for cyber insurance.
 *   1. KPIs: Total Coverage, Active Policies, Open Claims, Annual Premium
 *   2. Policy cards (3)
 *   3. Risk assessment score bars + overall gauge
 *   4. Claims table (6 rows)
 *   5. Coverage gap analysis (3 recommendation cards)
 *
 * API stubs: GET /api/v1/cyber-insurance/policies, /api/v1/cyber-insurance/claims
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, FileText, AlertTriangle, DollarSign, RefreshCw, PlusCircle, BarChart3 } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
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

// ── Mock data ──────────────────────────────────────────────────

const POLICIES = [
  {
    carrier: "CyberShield Underwriters",
    policyNum: "CSU-****-8821",
    limit: "$2,000,000",
    deductible: "$50,000",
    premium: "$22,400/yr",
    events: ["Ransomware", "Data Breach", "BEC"],
    effective: "2026-01-01",
    expiry: "2026-12-31",
    status: "active",
  },
  {
    carrier: "Nexus Cyber Re",
    policyNum: "NCR-****-4410",
    limit: "$2,000,000",
    deductible: "$100,000",
    premium: "$18,600/yr",
    events: ["DDoS", "Business Interruption", "Extortion"],
    effective: "2026-01-01",
    expiry: "2026-12-31",
    status: "active",
  },
  {
    carrier: "GlobalSec Assurance",
    policyNum: "GSA-****-0073",
    limit: "$1,000,000",
    deductible: "$25,000",
    premium: "$6,000/yr",
    events: ["Privacy Liability", "Regulatory Fines"],
    effective: "2025-07-01",
    expiry: "2026-06-30",
    status: "renewing",
  },
];

const RISK_SCORES = [
  { label: "Multi-Factor Authentication",   pct: 91, color: "bg-green-500"  },
  { label: "Backup & Recovery",             pct: 78, color: "bg-green-500"  },
  { label: "Incident Response Plan",        pct: 65, color: "bg-yellow-500" },
  { label: "Patch Management",              pct: 54, color: "bg-yellow-500" },
  { label: "Security Awareness Training",   pct: 42, color: "bg-red-500"    },
];

const OVERALL_SCORE = 66;

const CLAIMS = [
  { id: "CLM-2024-001", type: "ransomware",             date: "2024-09-14", loss: "$420,000",  settlement: "$380,000", status: "settled",      adjuster: "Marsh & McLennan" },
  { id: "CLM-2025-002", type: "data_breach",            date: "2025-02-28", loss: "$85,000",   settlement: "$72,000",  status: "settled",      adjuster: "Aon Cyber" },
  { id: "CLM-2025-003", type: "business_interruption",  date: "2025-06-10", loss: "$210,000",  settlement: "—",        status: "approved",     adjuster: "Marsh & McLennan" },
  { id: "CLM-2025-004", type: "data_breach",            date: "2025-11-01", loss: "$47,000",   settlement: "—",        status: "under_review", adjuster: "Willis Towers" },
  { id: "CLM-2026-005", type: "ransomware",             date: "2026-01-18", loss: "$650,000",  settlement: "—",        status: "filed",        adjuster: "Aon Cyber" },
  { id: "CLM-2026-006", type: "business_interruption",  date: "2026-03-05", loss: "$95,000",   settlement: "—",        status: "under_review", adjuster: "Willis Towers" },
];

const GAPS = [
  {
    title: "Social Engineering / BEC",
    desc: "No coverage for business email compromise or social engineering fraud. Average BEC loss: $125K.",
    urgency: "high",
  },
  {
    title: "Physical Asset Damage",
    desc: "Hardware destruction from cyber incidents (e.g., wiper malware) is excluded from current policies.",
    urgency: "medium",
  },
  {
    title: "Insider Threat / Malicious Employee",
    desc: "Intentional data exfiltration by employees is not covered. Recommend adding crime rider.",
    urgency: "medium",
  },
];

// ── Helpers ────────────────────────────────────────────────────

function PolicyStatusBadge({ status }: { status: string }) {
  const cls =
    status === "active"   ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "renewing" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                            "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{status}</Badge>;
}

function IncidentBadge({ type }: { type: string }) {
  const label = type.replace(/_/g, " ");
  const cls =
    type === "ransomware"             ? "border-red-500/30 text-red-400 bg-red-500/10" :
    type === "data_breach"            ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    type === "business_interruption"  ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
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

function UrgencyBadge({ urgency }: { urgency: string }) {
  const cls =
    urgency === "high"   ? "border-red-500/30 text-red-400 bg-red-500/10" :
    urgency === "medium" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                           "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{urgency} priority</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function CyberInsurance() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch(`/api/v1/cyber-insurance/policies?org_id=${ORG_ID}`).catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const gaugeColor = OVERALL_SCORE >= 80 ? "text-green-400" : OVERALL_SCORE >= 60 ? "text-yellow-400" : "text-red-400";
  const gaugeBorder = OVERALL_SCORE >= 80 ? "border-green-500/40" : OVERALL_SCORE >= 60 ? "border-yellow-500/40" : "border-red-500/40";


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


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
        <KpiCard title="Total Coverage"  value="$5M"     icon={Shield}        />
        <KpiCard title="Active Policies" value={3}       icon={FileText}      />
        <KpiCard title="Open Claims"     value={2}       icon={AlertTriangle} trend="up" className="border-amber-500/20" />
        <KpiCard title="Annual Premium"  value="$47,000" icon={DollarSign}    />
      </div>

      {/* Policy Cards */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {POLICIES.map((p, i) => (
          <Card key={i} className="flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold">{p.carrier}</CardTitle>
                <PolicyStatusBadge status={p.status} />
              </div>
              <CardDescription className="text-[11px] font-mono">{p.policyNum}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 flex-1">
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <div className="text-muted-foreground">Coverage Limit</div>
                <div className="font-semibold text-right">{p.limit}</div>
                <div className="text-muted-foreground">Deductible</div>
                <div className="font-medium text-right">{p.deductible}</div>
                <div className="text-muted-foreground">Premium</div>
                <div className="font-medium text-right">{p.premium}</div>
                <div className="text-muted-foreground">Effective</div>
                <div className="tabular-nums text-right">{p.effective}</div>
                <div className="text-muted-foreground">Expires</div>
                <div className="tabular-nums text-right">{p.expiry}</div>
              </div>
              <div className="flex flex-wrap gap-1 mt-1">
                {p.events.map((e) => (
                  <Badge key={e} className="text-[10px] border border-border text-muted-foreground">{e}</Badge>
                ))}
              </div>
              <Button variant="outline" size="sm" className="mt-auto h-7 text-xs w-full">View Details</Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Risk Assessment + Claims */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Risk Assessment */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Security Risk Assessment
            </CardTitle>
            <CardDescription className="text-xs">Insurer scoring categories affecting premium</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Overall gauge */}
            <div className={cn("flex items-center gap-4 rounded-lg border p-3", gaugeBorder)}>
              <div className={cn("text-4xl font-bold tabular-nums", gaugeColor)}>{OVERALL_SCORE}</div>
              <div>
                <div className="text-xs font-semibold">Overall Security Score</div>
                <div className="text-[10px] text-muted-foreground">
                  {OVERALL_SCORE >= 80 ? "Preferred rate tier" : OVERALL_SCORE >= 60 ? "Standard rate tier" : "High-risk — premium surcharge likely"}
                </div>
              </div>
            </div>
            {RISK_SCORES.map((s) => (
              <div key={s.label} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{s.label}</span>
                  <span className="font-bold tabular-nums">{s.pct}%</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${s.pct}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", s.color)}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Coverage Gaps */}
        <Card className="border-orange-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <AlertTriangle className="h-4 w-4" />
              Coverage Gap Analysis
            </CardTitle>
            <CardDescription className="text-xs">Risks not covered by current policies</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {GAPS.map((g, i) => (
              <div key={i} className="rounded-lg border border-border/50 bg-muted/10 p-3 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs font-semibold">{g.title}</span>
                  <UrgencyBadge urgency={g.urgency} />
                </div>
                <p className="text-[11px] text-muted-foreground leading-relaxed">{g.desc}</p>
                <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] w-full">
                  <PlusCircle className="h-3 w-3 mr-1" /> Add Coverage
                </Button>
              </div>
            ))}
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
                {CLAIMS.map((row) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.id}</TableCell>
                    <TableCell className="py-2.5"><IncidentBadge type={row.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.date}</TableCell>
                    <TableCell className="text-xs py-2.5 font-medium tabular-nums">{row.loss}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.settlement}</TableCell>
                    <TableCell className="py-2.5"><ClaimStatusBadge status={row.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.adjuster}</TableCell>
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
