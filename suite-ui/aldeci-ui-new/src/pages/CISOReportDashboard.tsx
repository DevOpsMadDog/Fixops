/**
 * CISO Report Dashboard
 *
 * Weekly brief, executive summary, and top risk tracking for the CISO persona.
 *
 * Data sources:
 *   GET /api/v1/ciso-report/weekly-brief?org_id=default
 *   GET /api/v1/ciso-report/executive-summary?org_id=default
 *   GET /api/v1/ciso-report/top-risks?org_id=default
 *
 * Route: /ciso-report
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  FileText,
  AlertOctagon,
  TrendingDown,
  Shield,
  BarChart3,
  Download,
  RefreshCw,
  CheckCircle2,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// == API helpers ==============================================================
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const apiKey =
  (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

const apiFetch = (path: string) =>
  fetch(`${API_BASE}/api/v1${path}`, {
    headers: { "X-API-Key": apiKey },
  }).then((r) => {
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  });

// == Types ====================================================================
interface SectionSummary {
  [key: string]: number | string;
}

interface WeeklyBrief {
  report_date: string;
  risk_posture_score: number;
  sections: {
    vulnerabilities: SectionSummary;
    threats: SectionSummary;
    compliance: SectionSummary;
    incidents: SectionSummary;
    operations: SectionSummary;
  };
  top_risks: Array<{
    title: string;
    severity: string;
    description: string;
  }>;
  exec_summary: string[];
}

interface KeyMetrics {
  risk_score: number;
  open_criticals: number;
  compliance_rate: number;
  mttr_hours: number;
}

interface ExecSummary {
  summary_bullets: string[];
  key_metrics: KeyMetrics;
}

interface TopRisk {
  title: string;
  severity: string;
  category: string;
  description: string;
  recommendation: string;
}

interface TopRisksData {
  top_risks: TopRisk[];
}

// == Mock data ================================================================
const MOCK_BRIEF: WeeklyBrief = {
  report_date: new Date().toISOString().slice(0, 10),
  risk_posture_score: 61,
  exec_summary: [
    "Critical vulnerability exposure decreased 18% this week following emergency patching of CVE-2024-3400 across 47 affected hosts.",
    "Ransomware detection coverage remains below target at 42% = recommend prioritising EDR rollout for OT network segment.",
    "SOC2 Type II audit readiness at 87%; three evidence gaps in access-review controls require remediation before June deadline.",
  ],
  sections: {
    vulnerabilities: { open: 1243, critical: 38, patched_this_week: 214 },
    threats:         { active_iocs: 87, blocked: 1203, high_severity: 12 },
    compliance:      { frameworks: 6, passing: 5, failing: 1, rate_pct: 87 },
    incidents:       { open: 9, critical: 2, resolved_this_week: 23 },
    operations:      { uptime_pct: 99.7, alerts_fired: 4821, false_positive_rate_pct: 4 },
  },
  top_risks: [],
};

const MOCK_EXEC_SUMMARY: ExecSummary = {
  summary_bullets: MOCK_BRIEF.exec_summary,
  key_metrics: {
    risk_score: 61,
    open_criticals: 38,
    compliance_rate: 87,
    mttr_hours: 14,
  },
};

const MOCK_TOP_RISKS: TopRisksData = {
  top_risks: [
    {
      title: "Unpatched Critical CVEs in Production",
      severity: "critical",
      category: "Vulnerability",
      description: "38 critical CVEs unpatched across production assets including 4 KEV-listed vulnerabilities with public exploits.",
      recommendation: "Initiate emergency change window within 48 hours for top 10 KEV vulnerabilities.",
    },
    {
      title: "Ransomware Detection Gap",
      severity: "critical",
      category: "Threat Coverage",
      description: "EDR coverage at 58% of endpoints; OT network segment has zero ransomware detection capability.",
      recommendation: "Accelerate EDR rollout to OT segment, deploy network-based ransomware detonation sensors.",
    },
    {
      title: "SOC2 Evidence Gaps",
      severity: "high",
      category: "Compliance",
      description: "Three access-review control evidence packages incomplete ahead of June SOC2 Type II audit window.",
      recommendation: "Assign compliance engineer to collect and validate missing evidence packages by May 15.",
    },
    {
      title: "Privileged Account Sprawl",
      severity: "high",
      category: "Identity",
      description: "142 stale privileged accounts identified in Active Directory; 23 have not been used in 90+ days.",
      recommendation: "Disable inactive privileged accounts and enforce quarterly access review via PAM solution.",
    },
    {
      title: "Third-Party API Key Exposure",
      severity: "medium",
      category: "Secrets",
      description: "Secret scanner identified 8 API keys committed to internal repositories within the past 30 days.",
      recommendation: "Rotate all exposed keys immediately and enforce pre-commit secret scanning hooks.",
    },
  ],
};

// == Helpers ==================================================================
function riskScoreColor(score: number): string {
  if (score >= 70) return "text-emerald-400";
  if (score >= 40) return "text-amber-400";
  return "text-red-400";
}

function severityVariant(sev: string): "destructive" | "secondary" | "outline" {
  if (sev === "critical") return "destructive";
  if (sev === "high")     return "secondary";
  return "outline";
}

function severityClass(sev: string): string {
  if (sev === "high")   return "bg-orange-500/15 text-orange-400 border-orange-500/30";
  if (sev === "medium") return "bg-amber-500/15 text-amber-400 border-amber-500/30";
  return "";
}

const SECTION_ICONS: Record<string, React.ReactNode> = {
  vulnerabilities: <AlertOctagon className="h-4 w-4 text-red-400" />,
  threats:         <Shield className="h-4 w-4 text-orange-400" />,
  compliance:      <CheckCircle2 className="h-4 w-4 text-emerald-400" />,
  incidents:       <TrendingDown className="h-4 w-4 text-amber-400" />,
  operations:      <BarChart3 className="h-4 w-4 text-blue-400" />,
};

const SECTION_LABELS: Record<string, string> = {
  vulnerabilities: "Vulnerabilities",
  threats:         "Threats",
  compliance:      "Compliance",
  incidents:       "Incidents",
  operations:      "Operations",
};

function sectionHighlight(name: string, data: SectionSummary): { label: string; value: string | number } {
  switch (name) {
    case "vulnerabilities": return { label: "Critical Open",  value: data.critical as number };
    case "threats":         return { label: "Active IOCs",    value: data.active_iocs as number };
    case "compliance":      return { label: "Pass Rate",      value: `${data.rate_pct}%` };
    case "incidents":       return { label: "Open",           value: data.open as number };
    case "operations":      return { label: "Uptime",         value: `${data.uptime_pct}%` };
    default:                return { label: "Items",          value: Object.values(data)[0] as number };
  }
}

// == Component ================================================================
export default function CISOReportDashboard() {
  const [brief, setBrief]           = useState<WeeklyBrief>(MOCK_BRIEF);
  const [execSummary, setExecSummary] = useState<ExecSummary>(MOCK_EXEC_SUMMARY);
  const [topRisks, setTopRisks]     = useState<TopRisk[]>(MOCK_TOP_RISKS.top_risks);
  const [loading, setLoading]       = useState(true);
  const [exporting, setExporting]   = useState(false);

  const load = async () => {
    setLoading(true);
    const [briefRes, execRes, risksRes] = await Promise.allSettled([
      apiFetch("/ciso-report/weekly-brief?org_id=default"),
      apiFetch("/ciso-report/executive-summary?org_id=default"),
      apiFetch("/ciso-report/top-risks?org_id=default"),
    ]);

    if (briefRes.status === "fulfilled")  setBrief(briefRes.value);
    if (execRes.status === "fulfilled")   setExecSummary(execRes.value);
    if (risksRes.status === "fulfilled")  setTopRisks(risksRes.value.top_risks ?? []);

  };

  useEffect(() => { load(); }, []);

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await fetch(
        `${API_BASE}/api/v1/ciso-report/export/markdown?org_id=default`,
        { headers: { "X-API-Key": apiKey } }
      );
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `ciso-weekly-brief-${brief.report_date}.md`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {
      // silently ignore export errors
    } finally {
      setExporting(false);
    }
  };

  const metrics = execSummary.key_metrics;
  const bullets = execSummary.summary_bullets.length
    ? execSummary.summary_bullets
    : brief.exec_summary;

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <PageHeader
        title="CISO Weekly Brief"
        description={`Report period ending ${brief.report_date}`}
        actions={
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={load}
              disabled={loading}
              className="gap-2"
            >
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
              Refresh
            </Button>
            <Button
              size="sm"
              onClick={handleExport}
              disabled={exporting}
              className="gap-2"
            >
              <Download className="h-4 w-4" />
              {exporting ? "Exporting=" : "Export MD"}
            </Button>
          </div>
        }
      />

      {/* Executive Summary */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <FileText className="h-4 w-4 text-blue-400" />
              Executive Summary
            </CardTitle>
            <CardDescription>Key findings for board-level review</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-3">
              {bullets.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                bullets.map((bullet, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  <span className="mt-1 h-2 w-2 flex-shrink-0 rounded-full bg-blue-400" />
                  <span className="text-muted-foreground leading-relaxed">{bullet}</span>
                </li>
              ))
            )}
            </ul>
          </CardContent>
        </Card>
      </motion.div>

      {/* Risk Posture Score + Key Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-5">
        {/* Risk Score */}
        <motion.div
          className="sm:col-span-1"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
        >
          <Card className="h-full flex flex-col items-center justify-center py-8">
            <span className="text-xs text-muted-foreground mb-1">Risk Posture Score</span>
            <span
              className={cn(
                "text-6xl font-bold tabular-nums",
                riskScoreColor(brief.risk_posture_score)
              )}
            >
              {brief.risk_posture_score}
            </span>
            <span className="text-xs text-muted-foreground mt-1">/ 100</span>
          </Card>
        </motion.div>

        {/* Key Metrics */}
        <div className="sm:col-span-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <KpiCard
            title="Open Criticals"
            value={metrics.open_criticals}
            icon={<AlertOctagon className="h-5 w-5 text-red-400" />}
            trend="down"
            trendLabel="Requires action"
          />
          <KpiCard
            title="Compliance Rate"
            value={`${metrics.compliance_rate}%`}
            icon={<CheckCircle2 className="h-5 w-5 text-emerald-400" />}
            trend="up"
            trendLabel="Improving"
          />
          <KpiCard
            title="MTTR (hours)"
            value={metrics.mttr_hours}
            icon={<TrendingDown className="h-5 w-5 text-amber-400" />}
          />
          <KpiCard
            title="Risk Score"
            value={metrics.risk_score}
            icon={<BarChart3 className="h-5 w-5 text-purple-400" />}
          />
        </div>
      </div>

      {/* Top Risks Table */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertOctagon className="h-4 w-4 text-red-400" />
              Top Risks
              <Badge variant="secondary" className="ml-auto">
                {topRisks.length} risks
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Risk</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Recommendation</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {topRisks.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  topRisks.map((risk, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-medium text-sm max-w-[160px]">
                      {risk.title}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={severityVariant(risk.severity)}
                        )))}
                      >
                        {risk.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {risk.category}
                      </span>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-[220px]">
                      {risk.description.length > 80
                        ? `${risk.description.slice(0, 80)}=`
                        : risk.description}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-[220px]">
                      {risk.recommendation.length > 80
                        ? `${risk.recommendation.slice(0, 80)}=`
                        : risk.recommendation}
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

      {/* Section Breakdown */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <h2 className="text-sm font-semibold text-muted-foreground mb-3 uppercase tracking-wider">
          Section Breakdown
        </h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
          {(Object.keys(brief.sections) as Array<keyof typeof brief.sections>).map(
            (sectionKey) => {
              const data = brief.sections[sectionKey];
              const { label, value } = sectionHighlight(sectionKey, data);
              return (
                <Card key={sectionKey}>
                  <CardContent className="flex flex-col gap-2 py-5 px-4">
                    <div className="flex items-center gap-2">
                      {SECTION_ICONS[sectionKey]}
                      <span className="text-xs font-semibold text-muted-foreground">
                        {SECTION_LABELS[sectionKey]}
                      </span>
                    </div>
                    <span className="text-2xl font-bold tabular-nums">{value}</span>
                    <span className="text-xs text-muted-foreground">{label}</span>
                  </CardContent>
                </Card>
              );
            }
          )}
        </div>
      </motion.div>
    </div>
  );
}
