/**
 * GRCAssessment — Control testing, gap analysis, and audit readiness
 *
 * Route: /grc-assessment
 * Note: GRCDashboard already exists at /grc — this is a detailed assessment view.
 *
 * Sections:
 *   1. KPIs: Assessments, Controls Tested, Pass Rate, Gaps Found
 *   2. Framework selector tabs: SOC2 / ISO27001 / NIST-CSF / PCI-DSS / HIPAA
 *   3. Control list for selected framework (15 rows)
 *   4. Gap analysis (3 priority levels)
 *   5. Audit readiness gauge (circular, 82%)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ClipboardCheck, BarChart3, AlertTriangle, CheckCircle, RefreshCw, FileText, Calendar } from "lucide-react";
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
  "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

type Framework = "SOC2" | "ISO27001" | "NIST-CSF" | "PCI-DSS" | "HIPAA";

const FRAMEWORKS: Framework[] = ["SOC2", "ISO27001", "NIST-CSF", "PCI-DSS", "HIPAA"];

type ControlStatus = "implemented" | "partial" | "not_implemented" | "na";

interface Control {
  ref: string;
  title: string;
  category: string;
  status: ControlStatus;
  evidence: number;
  owner: string;
  due: string;
}

const CONTROLS: Record<Framework, Control[]> = {
  SOC2: [
    { ref: "CC1.1", title: "Commitment to competence and integrity",    category: "Control Environment", status: "implemented",     evidence: 8,  owner: "CISO",      due: "2026-06-30" },
    { ref: "CC2.1", title: "Board oversight of internal controls",       category: "Control Environment", status: "implemented",     evidence: 5,  owner: "GRC Team",  due: "2026-06-30" },
    { ref: "CC3.1", title: "Risk assessment process documented",         category: "Risk Assessment",     status: "implemented",     evidence: 12, owner: "Risk Team", due: "2026-06-30" },
    { ref: "CC4.1", title: "Monitoring activities and deficiencies",     category: "Monitoring",          status: "partial",         evidence: 3,  owner: "GRC Team",  due: "2026-05-15" },
    { ref: "CC5.2", title: "Deploy control activities via policies",     category: "Control Activities",  status: "implemented",     evidence: 9,  owner: "SecOps",    due: "2026-06-30" },
    { ref: "CC6.1", title: "Logical and physical access controls",       category: "Logical Access",      status: "implemented",     evidence: 14, owner: "IAM Team",  due: "2026-06-30" },
    { ref: "CC6.3", title: "MFA for remote and privileged access",       category: "Logical Access",      status: "implemented",     evidence: 7,  owner: "IAM Team",  due: "2026-06-30" },
    { ref: "CC7.1", title: "Vulnerability management program",           category: "System Operations",   status: "partial",         evidence: 4,  owner: "VulnMgmt",  due: "2026-04-30" },
    { ref: "CC7.2", title: "System monitoring and anomaly detection",    category: "System Operations",   status: "implemented",     evidence: 11, owner: "SecOps",    due: "2026-06-30" },
    { ref: "CC8.1", title: "Change management process",                  category: "Change Management",   status: "implemented",     evidence: 6,  owner: "DevOps",    due: "2026-06-30" },
    { ref: "CC9.1", title: "Risk mitigation via vendor assessments",     category: "Risk Mitigation",     status: "partial",         evidence: 2,  owner: "Risk Team", due: "2026-05-01" },
    { ref: "A1.1",  title: "System capacity and availability planning",  category: "Availability",        status: "implemented",     evidence: 5,  owner: "Infra",     due: "2026-06-30" },
    { ref: "C1.1",  title: "Confidentiality policy and classifications", category: "Confidentiality",     status: "not_implemented", evidence: 0,  owner: "GRC Team",  due: "2026-04-20" },
    { ref: "PI1.1", title: "Processing integrity controls",              category: "Processing",          status: "partial",         evidence: 1,  owner: "AppSec",    due: "2026-05-15" },
    { ref: "P1.1",  title: "Privacy notice and consent management",      category: "Privacy",             status: "implemented",     evidence: 8,  owner: "Legal",     due: "2026-06-30" },
  ],
  ISO27001: [
    { ref: "A.5.1",  title: "Policies for information security",          category: "Org Controls",       status: "implemented",     evidence: 9,  owner: "CISO",      due: "2026-06-30" },
    { ref: "A.5.14", title: "Information transfer controls",              category: "Org Controls",       status: "partial",         evidence: 2,  owner: "SecOps",    due: "2026-05-01" },
    { ref: "A.6.1",  title: "Screening of personnel",                     category: "People Controls",    status: "implemented",     evidence: 11, owner: "HR",        due: "2026-06-30" },
    { ref: "A.6.3",  title: "Information security awareness training",    category: "People Controls",    status: "implemented",     evidence: 7,  owner: "GRC Team",  due: "2026-06-30" },
    { ref: "A.7.1",  title: "Physical security perimeters",               category: "Physical Controls",  status: "implemented",     evidence: 5,  owner: "Facilities", due: "2026-06-30" },
    { ref: "A.8.2",  title: "Privileged access rights management",        category: "Tech Controls",      status: "implemented",     evidence: 13, owner: "IAM Team",  due: "2026-06-30" },
    { ref: "A.8.5",  title: "Secure authentication controls",             category: "Tech Controls",      status: "implemented",     evidence: 8,  owner: "IAM Team",  due: "2026-06-30" },
    { ref: "A.8.7",  title: "Protection against malware",                 category: "Tech Controls",      status: "implemented",     evidence: 10, owner: "SecOps",    due: "2026-06-30" },
    { ref: "A.8.8",  title: "Management of technical vulnerabilities",    category: "Tech Controls",      status: "partial",         evidence: 4,  owner: "VulnMgmt",  due: "2026-04-30" },
    { ref: "A.8.12", title: "Data leakage prevention",                    category: "Tech Controls",      status: "not_implemented", evidence: 0,  owner: "GRC Team",  due: "2026-04-25" },
    { ref: "A.8.15", title: "Logging and monitoring",                     category: "Tech Controls",      status: "implemented",     evidence: 15, owner: "SecOps",    due: "2026-06-30" },
    { ref: "A.8.23", title: "Web filtering controls",                     category: "Tech Controls",      status: "partial",         evidence: 2,  owner: "NetSec",    due: "2026-05-15" },
    { ref: "A.8.24", title: "Use of cryptography",                        category: "Tech Controls",      status: "implemented",     evidence: 6,  owner: "AppSec",    due: "2026-06-30" },
    { ref: "A.8.28", title: "Secure coding practices",                    category: "Tech Controls",      status: "partial",         evidence: 3,  owner: "DevSec",    due: "2026-05-01" },
    { ref: "A.8.32", title: "Change management procedures",               category: "Tech Controls",      status: "implemented",     evidence: 7,  owner: "DevOps",    due: "2026-06-30" },
  ],
  "NIST-CSF": [
    { ref: "GV.OC-01", title: "Organizational mission is established",      category: "Govern",   status: "implemented",     evidence: 4,  owner: "CISO",      due: "2026-06-30" },
    { ref: "ID.AM-01", title: "Asset inventories are maintained",           category: "Identify", status: "implemented",     evidence: 12, owner: "Asset Mgmt",due: "2026-06-30" },
    { ref: "ID.AM-02", title: "Software inventories (SBOM) maintained",    category: "Identify", status: "partial",         evidence: 3,  owner: "DevSec",    due: "2026-05-15" },
    { ref: "ID.RA-01", title: "Vulnerabilities in assets are identified",   category: "Identify", status: "implemented",     evidence: 9,  owner: "VulnMgmt",  due: "2026-06-30" },
    { ref: "PR.AA-01", title: "Identities and credentials are managed",     category: "Protect",  status: "implemented",     evidence: 11, owner: "IAM Team",  due: "2026-06-30" },
    { ref: "PR.AT-01", title: "Security awareness training provided",       category: "Protect",  status: "implemented",     evidence: 8,  owner: "GRC Team",  due: "2026-06-30" },
    { ref: "PR.DS-01", title: "Data-at-rest protected via encryption",      category: "Protect",  status: "implemented",     evidence: 7,  owner: "DataSec",   due: "2026-06-30" },
    { ref: "PR.DS-02", title: "Data-in-transit protected via TLS",          category: "Protect",  status: "implemented",     evidence: 10, owner: "NetSec",    due: "2026-06-30" },
    { ref: "PR.PS-01", title: "Security configuration management",          category: "Protect",  status: "partial",         evidence: 2,  owner: "SecOps",    due: "2026-05-01" },
    { ref: "DE.AE-02", title: "Potentially adverse events are analyzed",    category: "Detect",   status: "implemented",     evidence: 14, owner: "SecOps",    due: "2026-06-30" },
    { ref: "DE.CM-01", title: "Networks are monitored for anomalies",       category: "Detect",   status: "implemented",     evidence: 9,  owner: "NetSec",    due: "2026-06-30" },
    { ref: "RS.MA-01", title: "Incident response plan in place",            category: "Respond",  status: "implemented",     evidence: 6,  owner: "IR Team",   due: "2026-06-30" },
    { ref: "RS.CO-02", title: "Incidents are reported to stakeholders",     category: "Respond",  status: "partial",         evidence: 1,  owner: "GRC Team",  due: "2026-04-30" },
    { ref: "RC.RP-01", title: "Recovery plan executed after incidents",     category: "Recover",  status: "partial",         evidence: 2,  owner: "IR Team",   due: "2026-05-15" },
    { ref: "RC.CO-03", title: "Recovery activities are communicated",       category: "Recover",  status: "not_implemented", evidence: 0,  owner: "GRC Team",  due: "2026-04-22" },
  ],
  "PCI-DSS": [
    { ref: "1.1",  title: "Network security controls documented",          category: "Network Security",     status: "implemented",     evidence: 8,  owner: "NetSec",    due: "2026-06-30" },
    { ref: "2.1",  title: "Vendor default credentials changed",            category: "Secure Configs",       status: "implemented",     evidence: 6,  owner: "SecOps",    due: "2026-06-30" },
    { ref: "3.1",  title: "CHD protection policies established",           category: "Protect Account Data", status: "implemented",     evidence: 11, owner: "DataSec",   due: "2026-06-30" },
    { ref: "3.4",  title: "Primary Account Numbers (PAN) encrypted",       category: "Protect Account Data", status: "implemented",     evidence: 9,  owner: "DataSec",   due: "2026-06-30" },
    { ref: "4.1",  title: "Strong cryptography over open networks",        category: "Encrypt Transmission", status: "implemented",     evidence: 7,  owner: "NetSec",    due: "2026-06-30" },
    { ref: "5.1",  title: "Anti-malware deployed on all systems",          category: "Anti-Malware",         status: "implemented",     evidence: 12, owner: "SecOps",    due: "2026-06-30" },
    { ref: "6.2",  title: "Bespoke software developed securely",           category: "Secure Development",   status: "partial",         evidence: 3,  owner: "DevSec",    due: "2026-05-01" },
    { ref: "6.3",  title: "Security vulnerabilities identified and fixed", category: "Secure Development",   status: "partial",         evidence: 4,  owner: "VulnMgmt",  due: "2026-04-30" },
    { ref: "7.1",  title: "Access to CHD restricted by business need",    category: "Access Control",       status: "implemented",     evidence: 8,  owner: "IAM Team",  due: "2026-06-30" },
    { ref: "8.2",  title: "User identification and authentication",        category: "Access Control",       status: "implemented",     evidence: 10, owner: "IAM Team",  due: "2026-06-30" },
    { ref: "9.1",  title: "Physical access controls to CDE",               category: "Physical Security",    status: "implemented",     evidence: 5,  owner: "Facilities", due: "2026-06-30" },
    { ref: "10.1", title: "Audit logs protect against destruction",        category: "Logging",              status: "implemented",     evidence: 14, owner: "SecOps",    due: "2026-06-30" },
    { ref: "11.3", title: "External and internal pen tests performed",     category: "Testing",              status: "partial",         evidence: 2,  owner: "RedTeam",   due: "2026-05-15" },
    { ref: "12.1", title: "Comprehensive information security policy",     category: "Policy",               status: "implemented",     evidence: 7,  owner: "GRC Team",  due: "2026-06-30" },
    { ref: "12.6", title: "Security awareness education program",          category: "Policy",               status: "not_implemented", evidence: 0,  owner: "GRC Team",  due: "2026-04-25" },
  ],
  HIPAA: [
    { ref: "164.308(a)(1)", title: "Security management process",             category: "Administrative",  status: "implemented",     evidence: 10, owner: "CISO",      due: "2026-06-30" },
    { ref: "164.308(a)(2)", title: "Assigned security responsibility",        category: "Administrative",  status: "implemented",     evidence: 5,  owner: "CISO",      due: "2026-06-30" },
    { ref: "164.308(a)(3)", title: "Workforce security procedures",           category: "Administrative",  status: "implemented",     evidence: 8,  owner: "HR",        due: "2026-06-30" },
    { ref: "164.308(a)(4)", title: "Information access management",           category: "Administrative",  status: "partial",         evidence: 4,  owner: "IAM Team",  due: "2026-05-01" },
    { ref: "164.308(a)(5)", title: "Security awareness and training",         category: "Administrative",  status: "implemented",     evidence: 7,  owner: "GRC Team",  due: "2026-06-30" },
    { ref: "164.308(a)(6)", title: "Security incident procedures",            category: "Administrative",  status: "implemented",     evidence: 9,  owner: "IR Team",   due: "2026-06-30" },
    { ref: "164.308(a)(7)", title: "Contingency plan documented",             category: "Administrative",  status: "partial",         evidence: 2,  owner: "Risk Team", due: "2026-05-15" },
    { ref: "164.310(a)(1)", title: "Facility access controls",                category: "Physical",        status: "implemented",     evidence: 6,  owner: "Facilities", due: "2026-06-30" },
    { ref: "164.312(a)(1)", title: "Access control — unique user IDs",        category: "Technical",       status: "implemented",     evidence: 12, owner: "IAM Team",  due: "2026-06-30" },
    { ref: "164.312(a)(2)", title: "Emergency access procedure",              category: "Technical",       status: "not_implemented", evidence: 0,  owner: "SecOps",    due: "2026-04-22" },
    { ref: "164.312(b)",   title: "Audit controls — hardware and software",   category: "Technical",       status: "implemented",     evidence: 11, owner: "SecOps",    due: "2026-06-30" },
    { ref: "164.312(c)(1)", title: "Integrity — PHI not improperly altered",  category: "Technical",       status: "implemented",     evidence: 8,  owner: "DataSec",   due: "2026-06-30" },
    { ref: "164.312(d)",   title: "Person or entity authentication",          category: "Technical",       status: "implemented",     evidence: 9,  owner: "IAM Team",  due: "2026-06-30" },
    { ref: "164.312(e)(1)", title: "Transmission security — encryption",      category: "Technical",       status: "implemented",     evidence: 10, owner: "NetSec",    due: "2026-06-30" },
    { ref: "164.316(b)",   title: "Documentation — policies retained 6yrs",  category: "Policies",        status: "partial",         evidence: 3,  owner: "GRC Team",  due: "2026-05-01" },
  ],
};

const GAPS = [
  {
    priority: "Critical",
    count: 12,
    timeline: "Immediate — due within 30 days",
    color: "border-red-500/30 bg-red-500/10",
    text: "text-red-400",
    desc: "Controls not yet implemented with direct audit impact. Examiner findings likely if unresolved.",
  },
  {
    priority: "High",
    count: 34,
    timeline: "Short-term — due within 60 days",
    color: "border-amber-500/30 bg-amber-500/10",
    text: "text-amber-400",
    desc: "Partially implemented controls. Evidence insufficient or processes not consistently followed.",
  },
  {
    priority: "Medium",
    count: 62,
    timeline: "Medium-term — due within 90 days",
    color: "border-yellow-500/30 bg-yellow-500/10",
    text: "text-yellow-400",
    desc: "Process improvements and documentation updates needed. No immediate audit risk.",
  },
];

const READINESS_PCT = 82;
const READINESS_COMPLETE = ["Access Controls (100%)", "Encryption (100%)", "Logging (97%)", "Incident Response (91%)", "Vulnerability Mgmt (84%)"];
const READINESS_NEEDED   = ["Data Classification (47%)", "DLP Implementation (0%)", "Pen Test Evidence (60%)", "Recovery Procedures (55%)"];

// ── Helpers ────────────────────────────────────────────────────

function ControlStatusBadge({ status }: { status: ControlStatus }) {
  const map: Record<ControlStatus, string> = {
    implemented:     "border-green-500/30 text-green-400 bg-green-500/10",
    partial:         "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    not_implemented: "border-red-500/30 text-red-400 bg-red-500/10",
    na:              "border-border text-muted-foreground",
  };
  const labels: Record<ControlStatus, string> = {
    implemented:     "Implemented",
    partial:         "Partial",
    not_implemented: "Not Implemented",
    na:              "N/A",
  };
  return <Badge className={cn("text-[10px] border", map[status])}>{labels[status]}</Badge>;
}

// Circular gauge using SVG
function AuditGauge({ pct }: { pct: number }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const progress = circ - (pct / 100) * circ;
  const color = pct >= 80 ? "#22c55e" : pct >= 60 ? "#f59e0b" : "#ef4444";

  return (
    <div className="flex flex-col items-center gap-3">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} fill="none" stroke="hsl(var(--muted)/0.3)" strokeWidth="12" />
        <circle
          cx="70" cy="70" r={r}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={progress}
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 1s ease-out" }}
        />
        <text x="70" y="65" textAnchor="middle" fontSize="22" fontWeight="bold" fill="currentColor" className="text-foreground">{pct}%</text>
        <text x="70" y="83" textAnchor="middle" fontSize="11" fill="#22c55e" fontWeight="600">Ready</text>
      </svg>
      <p className="text-xs text-muted-foreground text-center">Estimated audit readiness score based on control coverage and evidence completeness</p>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function GRCAssessment() {
  const [refreshing, setRefreshing] = useState(false);
  const [framework, setFramework] = useState<Framework>("SOC2");
  const [liveStats, setLiveStats] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/compliance/frameworks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/compliance/stats?org_id=${ORG_ID}`),
    ]).then(([frameworksResult, statsResult]) => {
      const frameworks = frameworksResult.status === "fulfilled" ? frameworksResult.value : null;
      const stats      = statsResult.status      === "fulfilled" ? statsResult.value      : null;
      if (frameworks || stats) {
        setLiveStats({ frameworks, stats });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const controls = CONTROLS[framework];
  const implemented = controls.filter((c) => c.status === "implemented").length;
  const passRate = Math.round((implemented / controls.length) * 100);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

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
      {/* Header */}
      <PageHeader
        title="GRC Assessment"
        description="Control testing, gap analysis, and audit readiness"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Assessments"     value={liveStats?.frameworks?.length ?? liveStats?.stats?.total_assessments ?? 12}                                                                                      icon={ClipboardCheck} trend="up"   />
        <KpiCard title="Controls Tested" value={liveStats?.stats?.total_controls ?? 847}                                                                                                                        icon={BarChart3}      trend="up"   className="border-blue-500/20" />
        <KpiCard title="Pass Rate"       value={liveStats?.stats?.compliance_score != null ? `${liveStats.stats.compliance_score.toFixed(1)}%` : liveStats?.stats?.pass_rate != null ? `${liveStats.stats.pass_rate.toFixed(1)}%` : "87.3%"} icon={CheckCircle} trend="up" className="border-green-500/20" />
        <KpiCard title="Gaps Found"      value={liveStats?.stats?.gaps_found ?? liveStats?.stats?.total_gaps ?? 108}                                                                                             icon={AlertTriangle}  trend="down" className="border-amber-500/20" />
      </div>

      {/* Framework selector */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <FileText className="h-4 w-4 text-blue-400" />
            Control Assessment — {framework}
          </CardTitle>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {FRAMEWORKS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              FRAMEWORKS.map((fw) => (
              <button
                key={fw}
                onClick={() => setFramework(fw)}
                className={cn(
                  "px-3 py-1 rounded-md text-xs font-medium border transition-colors",
                  framework === fw
                    ? "bg-primary text-primary-foreground border-primary"
                    : "border-border text-muted-foreground hover:bg-muted/30"
                )}
              >
                {fw}
              </button>
            ))}
          </div>
          <CardDescription className="text-xs mt-1">
            {implemented} of {controls.length} controls implemented ({passRate}% pass rate)
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Ref</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Evidence</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                  <TableHead className="text-[11px] h-8">Due</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {controls.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  controls.map((c) => (
                  <TableRow
                    key={c.ref}
                    className={cn(
                      "hover:bg-muted/30",
                      c.status === "not_implemented" && "bg-red-500/5 border-l-2 border-l-red-500"
                    )}
                  >
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{c.ref}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{c.title}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className="text-[10px] border border-border text-muted-foreground">{c.category}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5"><ControlStatusBadge status={c.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-right tabular-nums text-muted-foreground">{c.evidence}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{c.owner}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{c.due}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Update</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Gap Analysis + Audit Readiness */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Gap analysis */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Gap Analysis
            </CardTitle>
            <CardDescription className="text-xs">Remediation priorities by criticality</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {GAPS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              GAPS.map((g) => (
              <div key={g.priority} className={cn("rounded-lg border p-4 space-y-2", g.color)}>
                <div className="flex items-center justify-between">
                  <span className={cn("text-sm font-bold", g.text)}>{g.priority}</span>
                  <span className={cn("text-xl font-bold tabular-nums", g.text)}>{g.count} gaps</span>
                </div>
                <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                  <Calendar className="h-3 w-3 flex-shrink-0" />
                  {g.timeline}
                </div>
                <p className="text-[11px] text-muted-foreground leading-relaxed">{g.desc}</p>
              </div>
            ))
          )}
          </CardContent>
        </Card>

        {/* Audit readiness gauge */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-400" />
              Audit Readiness
            </CardTitle>
            <CardDescription className="text-xs">Overall readiness for next scheduled audit</CardDescription>
          </CardHeader>
          <CardContent>
            <AuditGauge pct={READINESS_PCT} />
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <p className="text-[11px] font-semibold text-green-400 flex items-center gap-1">
                  <CheckCircle className="h-3 w-3" /> Complete
                </p>
                {READINESS_COMPLETE.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  READINESS_COMPLETE.map((item) => (
                  <p key={item} className="text-[11px] text-muted-foreground flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500 flex-shrink-0" />
                    {item}
                  </p>
                ))
              )}
              </div>
              <div className="space-y-1.5">
                <p className="text-[11px] font-semibold text-amber-400 flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" /> Still Needed
                </p>
                {READINESS_NEEDED.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  READINESS_NEEDED.map((item) => (
                  <p key={item} className="text-[11px] text-muted-foreground flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-500 flex-shrink-0" />
                    {item}
                  </p>
                ))
              )}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
