/**
 * GRC Dashboard
 *
 * Governance, Risk & Compliance management.
 *   1. KPIs: Frameworks, Avg Compliance Score, Open Risks, Controls Implemented
 *   2. Framework compliance bars (6 frameworks)
 *   3. Risk register table (12 rows)
 *   4. Control status breakdown (4 boxes)
 *   5. Recent assessments (5 cards)
 *
 * API stubs: GET /api/v1/grc/frameworks, /api/v1/grc/risks, /api/v1/grc/controls
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, AlertTriangle, CheckCircle, BarChart3, FileText, RefreshCw, ClipboardList } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const FRAMEWORKS = [
  { name: "SOC 2 Type II",  score: 91, color: "bg-green-500",  text: "text-green-400"  },
  { name: "ISO 27001",      score: 84, color: "bg-green-500",  text: "text-green-400"  },
  { name: "NIST CSF",       score: 78, color: "bg-yellow-500", text: "text-yellow-400" },
  { name: "PCI-DSS",        score: 73, color: "bg-yellow-500", text: "text-yellow-400" },
  { name: "HIPAA",          score: 67, color: "bg-amber-500",  text: "text-amber-400"  },
  { name: "GDPR",           score: 82, color: "bg-green-500",  text: "text-green-400"  },
];

const RISKS = [
  { title: "Unpatched Critical CVEs",            category: "Vulnerability", likelihood: 4, impact: 5, treatment: "mitigate",  owner: "AppSec",   status: "open"        },
  { title: "Third-party data breach exposure",   category: "Vendor",        likelihood: 3, impact: 5, treatment: "transfer",  owner: "Risk",     status: "open"        },
  { title: "Insider data exfiltration",          category: "Insider",       likelihood: 2, impact: 5, treatment: "mitigate",  owner: "SecOps",   status: "in-progress" },
  { title: "Cloud misconfiguration cascade",     category: "Cloud",         likelihood: 3, impact: 4, treatment: "mitigate",  owner: "CloudOps", status: "open"        },
  { title: "Ransomware infection vector",        category: "Malware",       likelihood: 3, impact: 5, treatment: "mitigate",  owner: "SOC",      status: "in-progress" },
  { title: "Regulatory non-compliance fine",     category: "Compliance",    likelihood: 2, impact: 4, treatment: "mitigate",  owner: "GRC",      status: "open"        },
  { title: "API key leakage in source code",     category: "Secrets",       likelihood: 4, impact: 3, treatment: "mitigate",  owner: "DevSec",   status: "resolved"    },
  { title: "DDoS attack on public endpoints",   category: "Availability",  likelihood: 3, impact: 3, treatment: "transfer",  owner: "NetSec",   status: "open"        },
  { title: "Supply chain compromise",            category: "Supply Chain",  likelihood: 2, impact: 5, treatment: "mitigate",  owner: "Risk",     status: "open"        },
  { title: "Weak MFA enforcement",               category: "Identity",      likelihood: 4, impact: 3, treatment: "mitigate",  owner: "IAM",      status: "in-progress" },
  { title: "Legacy system exposure",             category: "Infrastructure",likelihood: 3, impact: 2, treatment: "accept",    owner: "InfraSec", status: "accepted"    },
  { title: "Social engineering / phishing",      category: "Human",         likelihood: 4, impact: 3, treatment: "mitigate",  owner: "SecAware", status: "open"        },
];

const CONTROLS = [
  { label: "Implemented",     count: 218, color: "bg-green-500/20 border-green-500/30 text-green-400"  },
  { label: "Partial",         count: 47,  color: "bg-yellow-500/20 border-yellow-500/30 text-yellow-400" },
  { label: "Not Implemented", count: 28,  color: "bg-red-500/20 border-red-500/30 text-red-400"        },
  { label: "N/A",             count: 7,   color: "bg-muted/30 border-border text-muted-foreground"     },
];

const ASSESSMENTS = [
  { framework: "SOC 2 Type II",  assessor: "Deloitte",        date: "2026-03-15", score: 91, status: "passed"    },
  { framework: "ISO 27001",      assessor: "BSI Group",       date: "2026-02-28", score: 84, status: "passed"    },
  { framework: "PCI-DSS v4.0",   assessor: "Trustwave",       date: "2026-01-20", score: 73, status: "remediate" },
  { framework: "HIPAA Security", assessor: "Internal Audit",  date: "2026-04-02", score: 67, status: "remediate" },
  { framework: "NIST CSF 2.0",   assessor: "Internal Audit",  date: "2026-04-10", score: 78, status: "in-review" },
];

// ── Helpers ────────────────────────────────────────────────────

function CategoryBadge({ cat }: { cat: string }) {
  return (
    <Badge className="text-[10px] border border-border text-muted-foreground bg-muted/30 capitalize">
      {cat}
    </Badge>
  );
}

function TreatmentBadge({ t }: { t: string }) {
  const cls =
    t === "mitigate" ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    t === "transfer" ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
                       "border-amber-500/30 text-amber-400 bg-amber-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{t}</Badge>;
}

function StatusBadge({ s }: { s: string }) {
  const cls =
    s === "resolved" || s === "passed"   ? "border-green-500/30 text-green-400 bg-green-500/10" :
    s === "in-progress" || s === "in-review" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
    s === "remediate"                    ? "border-red-500/30 text-red-400 bg-red-500/10" :
    s === "accepted"                     ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
                                           "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{s}</Badge>;
}

function scoreColor(score: number) {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  return "text-red-400";
}

// ── Component ──────────────────────────────────────────────────

export default function GRCDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/grc/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/grc/frameworks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/grc/risks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/grc/controls?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/grc/assessments?org_id=${ORG_ID}`),
    ]).then(([statsRes, frameworksRes, risksRes, controlsRes, assessmentsRes]) => {
      const stats       = statsRes.status       === "fulfilled" ? statsRes.value       : null;
      const frameworks  = frameworksRes.status  === "fulfilled" ? frameworksRes.value  : null;
      const risks       = risksRes.status       === "fulfilled" ? risksRes.value       : null;
      const controls    = controlsRes.status    === "fulfilled" ? controlsRes.value    : null;
      const assessments = assessmentsRes.status === "fulfilled" ? assessmentsRes.value : null;
      if (stats || frameworks || risks || controls || assessments) {
        setLiveData({ stats, frameworks, risks, controls, assessments });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="GRC Dashboard"
        description="Governance, Risk & Compliance management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Frameworks"     value={liveData?.stats?.total_frameworks ?? (liveData?.frameworks?.length ?? 6)}       icon={ClipboardList} trend="up"   className="border-blue-500/20" />
        <KpiCard title="Avg Compliance" value={liveData?.stats?.avg_compliance_score != null ? `${liveData.stats.avg_compliance_score.toFixed(1)}%` : "82.4%"} icon={Shield} trend="up" className="border-green-500/20" />
        <KpiCard title="Open Risks"     value={liveData?.stats?.open_risks ?? (liveData?.risks?.filter((r: any) => r.status === "open").length ?? 47)} icon={AlertTriangle} trend="down" className="border-amber-500/20" />
        <KpiCard title="Controls Impl." value={liveData?.stats?.implemented_pct != null ? `${liveData.stats.implemented_pct.toFixed(1)}%` : "87.3%"} icon={CheckCircle} trend="up" className="border-purple-500/20" />
      </div>

      {/* Framework bars + Control status */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Framework compliance */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Framework Compliance
            </CardTitle>
            <CardDescription className="text-xs">Current compliance score per framework (green ≥80%, yellow ≥60%, red &lt;60%)</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {(liveData?.frameworks ?? FRAMEWORKS).map((f: any) => {
              const score = f.compliance_score ?? f.score ?? 0;
              const name = f.name;
              const colorCls = score >= 80 ? "bg-green-500" : score >= 60 ? "bg-yellow-500" : "bg-red-500";
              const textCls  = score >= 80 ? "text-green-400" : score >= 60 ? "text-yellow-400" : "text-red-400";
              return (
              <div key={name} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{name}</span>
                  <span className={cn("font-bold tabular-nums", f.text ?? textCls)}>{score}%</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${score}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", f.color ?? colorCls)}
                  />
                </div>
              </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Control status + Recent assessments */}
        <div className="flex flex-col gap-4">
          {/* Control status */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-400" />
                Control Status Breakdown
              </CardTitle>
              <CardDescription className="text-xs">300 total controls across all frameworks</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                {CONTROLS.map((c) => (
                  <div key={c.label} className={cn("rounded-lg border p-3 text-center", c.color)}>
                    <div className="text-2xl font-bold tabular-nums">{c.count}</div>
                    <div className="text-[10px] font-medium mt-0.5">{c.label}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Recent assessments */}
          <Card className="flex-1">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <FileText className="h-4 w-4 text-indigo-400" />
                Recent Assessments
              </CardTitle>
              <CardDescription className="text-xs">Latest compliance assessments</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {(liveData?.assessments ?? ASSESSMENTS).map((a: any, idx: number) => (
                <div key={a.id ?? a.framework ?? idx} className="flex items-center justify-between p-2 rounded-lg bg-muted/20 border border-border/50">
                  <div className="min-w-0">
                    <div className="text-xs font-medium truncate">{a.framework_id ?? a.framework}</div>
                    <div className="text-[10px] text-muted-foreground">{a.assessor} · {a.assessment_date ?? a.date}</div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    <span className={cn("text-xs font-bold tabular-nums", scoreColor(a.overall_score ?? a.score ?? 0))}>{a.overall_score ?? a.score ?? 0}%</span>
                    <StatusBadge s={a.status} />
                    <Button variant="ghost" size="sm" className="h-5 px-1.5 text-[9px]">View</Button>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Risk register */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Risk Register
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {(liveData?.risks ?? RISKS).filter((r: any) => r.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Enterprise risk inventory — score = likelihood × impact</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Risk Title</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">L</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">I</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Treatment</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.risks ?? RISKS).map((row: any) => {
                  const score = (row.likelihood ?? 1) * (row.impact ?? 1);
                  const scoreClr = score >= 16 ? "text-red-400" : score >= 9 ? "text-amber-400" : "text-yellow-400";
                  return (
                    <TableRow key={row.id ?? row.title} className="hover:bg-muted/30">
                      <TableCell className="text-xs py-2.5 max-w-[200px] truncate font-medium">{row.title}</TableCell>
                      <TableCell className="py-2.5"><CategoryBadge cat={row.category} /></TableCell>
                      <TableCell className="text-xs tabular-nums py-2.5 text-center">{row.likelihood}</TableCell>
                      <TableCell className="text-xs tabular-nums py-2.5 text-center">{row.impact}</TableCell>
                      <TableCell className={cn("text-xs tabular-nums py-2.5 font-bold text-center", scoreClr)}>{score}</TableCell>
                      <TableCell className="py-2.5"><TreatmentBadge t={row.treatment} /></TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">{row.owner}</TableCell>
                      <TableCell className="py-2.5"><StatusBadge s={row.status} /></TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
