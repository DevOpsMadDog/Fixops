/**
 * Cyber Threat Intelligence Dashboard
 *
 * Threat intelligence reports with IOC tracking and confidence scoring.
 *   1. KPIs: Total Reports, Published, Total IOCs, High Confidence Reports
 *   2. Reports table (title, intel_type, tlp, source_type, confidence_score, status)
 *
 * Route: /cyber-threat-intel
 * API: GET /api/v1/cyber-threat-intel
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Radio, RefreshCw, FileText, Target, ShieldCheck, BarChart2 } from "lucide-react";

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

const MOCK_REPORTS = [
  { id: "rpt-001", title: "Lazarus Group — Cloud Infrastructure Targeting",   intel_type: "threat_actor",  tlp: "red",   source_type: "ISAC",       confidence_score: 94, status: "published" },
  { id: "rpt-002", title: "Cobalt Strike Beacon Campaign — APAC Region",      intel_type: "campaign",      tlp: "amber", source_type: "OSINT",      confidence_score: 87, status: "published" },
  { id: "rpt-003", title: "RansomHub Affiliate TTPs — Q1 2026",               intel_type: "ransomware",    tlp: "amber", source_type: "Vendor",     confidence_score: 91, status: "published" },
  { id: "rpt-004", title: "Zero-Day Exploit: Citrix ADC (CVE-2026-1234)",     intel_type: "vulnerability", tlp: "red",   source_type: "Internal",   confidence_score: 98, status: "published" },
  { id: "rpt-005", title: "TA505 Phishing Kit — Financial Sector",            intel_type: "phishing",      tlp: "amber", source_type: "ISAC",       confidence_score: 82, status: "draft"     },
  { id: "rpt-006", title: "APT41 Supply Chain Compromise Indicators",          intel_type: "threat_actor",  tlp: "red",   source_type: "Government", confidence_score: 96, status: "published" },
  { id: "rpt-007", title: "Conti Successor Group — Infrastructure Reuse",     intel_type: "campaign",      tlp: "white", source_type: "OSINT",      confidence_score: 74, status: "published" },
  { id: "rpt-008", title: "Malicious PyPI Packages — SolarStorm Variant",     intel_type: "malware",       tlp: "green", source_type: "Internal",   confidence_score: 89, status: "published" },
  { id: "rpt-009", title: "DNS Tunneling Campaign — C2 Infrastructure Map",   intel_type: "infrastructure",tlp: "amber", source_type: "Vendor",     confidence_score: 83, status: "review"    },
  { id: "rpt-010", title: "BEC Campaign — Executive Impersonation via AI",    intel_type: "social_eng",    tlp: "green", source_type: "OSINT",      confidence_score: 77, status: "published" },
];

const MOCK_STATS = {
  total_reports: 312,
  published: 287,
  total_iocs: 18943,
  high_confidence_reports: 194,
};

// ── Badge helpers ──────────────────────────────────────────────

function TLPBadge({ tlp }: { tlp: string }) {
  const map: Record<string, string> = {
    red:   "border-red-500/50 text-red-300 bg-red-500/15 font-bold",
    amber: "border-orange-500/50 text-orange-300 bg-orange-500/15",
    green: "border-green-500/30 text-green-400 bg-green-500/10",
    white: "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border uppercase", map[tlp] ?? "border-border")}>
      TLP:{tlp}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    published: "border-green-500/30 text-green-400 bg-green-500/10",
    draft:     "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
    review:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    archived:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function ConfidenceBar({ score }: { score: number }) {
  const color = score >= 90 ? "text-green-400" : score >= 75 ? "text-yellow-400" : "text-orange-400";
  return <span className={cn("font-mono text-[11px]", color)}>{score}%</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function CyberThreatIntelDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveReports, setLiveReports] = useState<any[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [liveStats, setLiveStats]     = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/cyber-threat-intel/reports?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cyber-threat-intel/stats?org_id=${ORG_ID}`),
    ]).then(([reportsRes, statsRes]) => {
      if (reportsRes.status === "fulfilled") setLiveReports(reportsRes.value?.reports ?? reportsRes.value ?? null);
      if (statsRes.status === "fulfilled")   setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const reports = liveReports ?? MOCK_REPORTS;
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
        title="Cyber Threat Intelligence"
        description="Strategic threat intelligence — reports, IOC feeds, TLP classification, and confidence-scored adversary analysis"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Reports"          value={stats.total_reports}           icon={FileText}   trend="up"   className="border-orange-500/20" />
        <KpiCard title="Published"              value={stats.published}               icon={Radio}      trend="up"   className="border-amber-500/20" />
        <KpiCard title="Total IOCs"             value={stats.total_iocs.toLocaleString()} icon={Target} trend="up"   className="border-orange-500/20" />
        <KpiCard title="High Confidence"        value={stats.high_confidence_reports} icon={ShieldCheck} trend="up"  className="border-amber-500/20" />
      </div>

      {/* Reports Table */}
      <Card className="border-orange-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <BarChart2 className="h-4 w-4" />
              Intelligence Reports
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {reports.filter((r: any) => r.tlp === "red").length} TLP:RED
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Threat intelligence reports with TLP classification, source attribution, confidence scoring, and publication status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Report Title</TableHead>
                  <TableHead className="text-[11px] h-8">Intel Type</TableHead>
                  <TableHead className="text-[11px] h-8">TLP</TableHead>
                  <TableHead className="text-[11px] h-8">Source</TableHead>
                  <TableHead className="text-[11px] h-8">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  reports.map((report: any, i: number) => (
                  <TableRow key={report.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-orange-300 max-w-[240px] truncate">
                      {report.title ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {(report.intel_type ?? "—").replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="py-2">
                      <TLPBadge tlp={report.tlp ?? "white"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-amber-300 font-mono">
                      {report.source_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <ConfidenceBar score={report.confidence_score ?? 0} />
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <StatusBadge status={report.status ?? "draft"} />
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
