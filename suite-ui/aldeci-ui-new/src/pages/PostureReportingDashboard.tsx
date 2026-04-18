/**
 * Posture Reporting Dashboard
 *
 * Security posture reports with sections, metrics, trends, and publish workflow.
 * Route: /posture-reports
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  FileText, TrendingUp, TrendingDown, Minus, ChevronDown, ChevronRight,
  BarChart2, Send, PlusCircle, Lock, Globe, Users, CheckCircle2, Clock, XCircle,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// == Mock Data ==================================================

const MOCK_REPORTS = [
  {
    id: "rpt-001", report_name: "Q1 2026 Security Posture", type: "quarterly",
    audience: "board", overall_score: 84, grade: "B", status: "published",
    period_start: "2026-01-01", period_end: "2026-03-31",
    sections: [
      { section_name: "Vulnerability Management", type: "vuln", score: 78, status: "amber", content: "142 critical CVEs remediated, MTTD improved 22% QoQ." },
      { section_name: "Compliance Posture", type: "compliance", score: 91, status: "green", content: "SOC 2 Type II passed, PCI-DSS 4.0 gap assessment complete." },
      { section_name: "Threat Intelligence", type: "threat-intel", score: 82, status: "green", content: "28 threat feeds active, 4,200 IOCs ingested this quarter." },
      { section_name: "Incident Response", type: "incident", score: 86, status: "green", content: "MTTR reduced to 3.2h average, 0 P0 incidents unresolved." },
    ],
    metrics: [
      { metric_name: "MTTD (hours)", value: 2.4, unit: "h", previous_value: 3.1, trend: "improving", benchmark_value: 4.0 },
      { metric_name: "MTTR (hours)", value: 3.2, unit: "h", previous_value: 4.8, trend: "improving", benchmark_value: 6.0 },
      { metric_name: "Critical CVEs Open", value: 12, unit: "", previous_value: 34, trend: "improving", benchmark_value: 20 },
      { metric_name: "SLA Compliance %", value: 94.2, unit: "%", previous_value: 91.0, trend: "improving", benchmark_value: 90.0 },
      { metric_name: "False Positive Rate", value: 8.3, unit: "%", previous_value: 7.1, trend: "declining", benchmark_value: 10.0 },
    ],
    trend_history: {
      "MTTD (hours)":     [3.8, 3.5, 3.1, 2.9, 2.6, 2.4],
      "MTTR (hours)":     [5.2, 4.9, 4.8, 4.2, 3.6, 3.2],
      "Critical CVEs Open": [58, 45, 34, 28, 18, 12],
      "SLA Compliance %": [88, 89, 91, 92, 93, 94],
      "False Positive Rate": [6.8, 7.0, 7.1, 7.8, 8.1, 8.3],
    },
  },
  {
    id: "rpt-002", report_name: "April 2026 Executive Summary", type: "monthly",
    audience: "ciso", overall_score: 79, grade: "C", status: "draft",
    period_start: "2026-04-01", period_end: "2026-04-30",
    sections: [
      { section_name: "Attack Surface", type: "asm", score: 71, status: "amber", content: "18 new external assets discovered, 3 high-risk exposures pending." },
      { section_name: "Identity & Access", type: "iam", score: 88, status: "green", content: "MFA enrollment at 96%, 2 privileged accounts flagged for review." },
      { section_name: "Cloud Security", type: "cloud", score: 67, status: "red", content: "12 S3 buckets misconfigured, cloud drift alerts increased 40%." },
    ],
    metrics: [
      { metric_name: "Cloud Misconfigs", value: 47, unit: "", previous_value: 33, trend: "declining", benchmark_value: 25 },
      { metric_name: "MFA Enrollment %", value: 96.1, unit: "%", previous_value: 93.4, trend: "improving", benchmark_value: 95.0 },
      { metric_name: "Patch Coverage %", value: 88.7, unit: "%", previous_value: 90.2, trend: "declining", benchmark_value: 95.0 },
    ],
    trend_history: {
      "Cloud Misconfigs":  [28, 30, 33, 38, 43, 47],
      "MFA Enrollment %":  [90, 91, 93, 94, 95, 96],
      "Patch Coverage %":  [93, 92, 90, 90, 89, 89],
    },
  },
  {
    id: "rpt-003", report_name: "2026 Annual Security Review", type: "annual",
    audience: "executives", overall_score: 88, grade: "A", status: "published",
    period_start: "2025-01-01", period_end: "2025-12-31",
    sections: [
      { section_name: "Regulatory Compliance", type: "compliance", score: 94, status: "green", content: "All 7 frameworks met. Zero audit findings outstanding." },
      { section_name: "Security Culture", type: "culture", score: 81, status: "green", content: "Training completion 97%, phishing resilience score +15 pts YoY." },
    ],
    metrics: [
      { metric_name: "Incidents Resolved", value: 1247, unit: "", previous_value: 1089, trend: "stable", benchmark_value: 1200 },
      { metric_name: "Awareness Score", value: 87.3, unit: "%", previous_value: 79.1, trend: "improving", benchmark_value: 80.0 },
    ],
    trend_history: {
      "Incidents Resolved": [900, 950, 1050, 1089, 1150, 1247],
      "Awareness Score":    [72, 75, 79, 81, 84, 87],
    },
  },
];

// == Helpers ====================================================

const GRADE_COLORS: Record<string, string> = {
  A: "bg-green-500/15 text-green-400 border-green-500/30",
  B: "bg-teal-500/15 text-teal-400 border-teal-500/30",
  C: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  D: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  F: "bg-red-500/15 text-red-400 border-red-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  published: "bg-green-500/15 text-green-400 border-green-500/30",
  draft:     "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  archived:  "bg-purple-500/15 text-purple-400 border-purple-500/30",
};

const AUDIENCE_COLORS: Record<string, string> = {
  board:      "bg-purple-500/15 text-purple-400 border-purple-500/30",
  ciso:       "bg-blue-500/15 text-blue-400 border-blue-500/30",
  executives: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  technical:  "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
};

const TYPE_COLORS: Record<string, string> = {
  quarterly:     "bg-blue-500/15 text-blue-400 border-blue-500/30",
  monthly:       "bg-teal-500/15 text-teal-400 border-teal-500/30",
  annual:        "bg-purple-500/15 text-purple-400 border-purple-500/30",
  weekly:        "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  vuln:          "bg-red-500/15 text-red-400 border-red-500/30",
  compliance:    "bg-green-500/15 text-green-400 border-green-500/30",
  "threat-intel": "bg-orange-500/15 text-orange-400 border-orange-500/30",
  incident:      "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  asm:           "bg-rose-500/15 text-rose-400 border-rose-500/30",
  iam:           "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  cloud:         "bg-sky-500/15 text-sky-400 border-sky-500/30",
  culture:       "bg-teal-500/15 text-teal-400 border-teal-500/30",
};

const SECTION_DOT: Record<string, string> = {
  green: "bg-green-500",
  amber: "bg-yellow-500",
  red:   "bg-red-500",
};

function TrendIcon({ trend }: { trend: string }) {
  if (trend === "improving") return <TrendingUp className="h-4 w-4 text-green-400" />;
  if (trend === "declining") return <TrendingDown className="h-4 w-4 text-red-400" />;
  return <Minus className="h-4 w-4 text-zinc-400" />;
}

function ScoreBar({ value, max = 100, color = "bg-blue-500" }: { value: number; max?: number; color?: string }) {
  const pct = Math.min(100, (value / max) * 100);
  const barColor = pct >= 80 ? "bg-green-500" : pct >= 60 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2 w-full">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between" role="status" aria-live="polite">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
           aria-label="Refresh data">
            Retry
          </button>
        </div>
      )}
      <div className="flex-1 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full transition-all", barColor)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-zinc-400 w-8 text-right">{value}</span>
    </div>
  );
}

// == Main Component =============================================

export default function PostureReportingDashboard() {
  const [selectedReport, setSelectedReport] = useState(MOCK_REPORTS[0]);
  const [error, setError] = useState<string | null>(null);
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  const [metricFilter, setMetricFilter] = useState(selectedReport.metrics[0].metric_name);

  useEffect(() => {
    apiFetch(`/api/v1/posture-reports/reports?org_id=${ORG_ID}`).catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newReport, setNewReport] = useState({ name: "", type: "monthly", audience: "ciso", period_start: "", period_end: "" });
  const [loading, setLoading] = useState(true);

  const trendData = ((selectedReport.trend_history as unknown) as Record<string, number[]>)[metricFilter] ?? [];
  const maxTrend = Math.max(...trendData, 1);

  const totalReports = MOCK_REPORTS.length;
  const published = MOCK_REPORTS.filter(r => r.status === "published").length;
  const avgScore = Math.round(MOCK_REPORTS.reduce((a, r) => a + r.overall_score, 0) / MOCK_REPORTS.length);
  const drafts = MOCK_REPORTS.filter(r => r.status === "draft").length;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <PageHeader
        title="Posture Reporting"
        description="Security posture reports across all frameworks and audiences"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Reports" value={totalReports} icon={<FileText className="h-5 w-5" />} />
        <KpiCard title="Published" value={published} icon={<Globe className="h-5 w-5" />} />
        <KpiCard title="Avg Score" value={`${avgScore}%`} icon={<BarChart2 className="h-5 w-5" />} />
        <KpiCard title="Drafts" value={drafts} icon={<Clock className="h-5 w-5" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Report List */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wider">Reports</h2>
            <Button size="sm" variant="outline" className="text-xs border-zinc-700 text-zinc-300" onClick={() => setShowCreateForm(v => !v)}>
              <PlusCircle className="h-3 w-3 mr-1" /> New
            </Button>
          </div>

          {showCreateForm && (
            <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="bg-gray-800 rounded-lg p-4 space-y-3 border border-zinc-700">
              <p className="text-xs font-semibold text-zinc-300">Create Report</p>
              <input className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white placeholder-zinc-500" placeholder="Report name" value={newReport.name} onChange={e => setNewReport(p => ({ ...p, name: e.target.value }))} />
              <div className="grid grid-cols-2 gap-2">
                <select className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white" value={newReport.type} onChange={e => setNewReport(p => ({ ...p, type: e.target.value }))}>
                  {["monthly","quarterly","annual","weekly"].map(t => <option key={t}>{t}</option>)}
                </select>
                <select className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white" value={newReport.audience} onChange={e => setNewReport(p => ({ ...p, audience: e.target.value }))}>
                  {["ciso","board","executives","technical"].map(a => <option key={a}>{a}</option>)}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <input type="date" className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white" value={newReport.period_start} onChange={e => setNewReport(p => ({ ...p, period_start: e.target.value }))} />
                <input type="date" className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white" value={newReport.period_end} onChange={e => setNewReport(p => ({ ...p, period_end: e.target.value }))} />
              </div>
              <Button size="sm" className="w-full bg-blue-600 hover:bg-blue-700 text-xs" onClick={() => setShowCreateForm(false)}>Create Report</Button>
            </motion.div>
          )}

          {MOCK_REPORTS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            MOCK_REPORTS.map(r => (
            <motion.div key={r.id} whileHover={{ scale: 1.01 }} onClick={() => { setSelectedReport(r); setMetricFilter(r.metrics[0].metric_name); }}
              className={cn("bg-gray-800 rounded-lg p-4 cursor-pointer border transition-all", selectedReport.id === r.id ? "border-blue-500/50" : "border-zinc-700/50 hover:border-zinc-600")}>
              <div className="flex items-start justify-between mb-2">
                <p className="text-sm font-medium text-white leading-tight">{r.report_name}</p>
                <Badge className={cn("text-[10px] border capitalize ml-2 shrink-0", GRADE_COLORS[r.grade])}>{r.grade}</Badge>
              </div>
              <div className="flex flex-wrap gap-1 mb-2">
                <Badge className={cn("text-[9px] border capitalize", TYPE_COLORS[r.type])}>{r.type}</Badge>
                <Badge className={cn("text-[9px] border capitalize", AUDIENCE_COLORS[r.audience])}>{r.audience}</Badge>
                <Badge className={cn("text-[9px] border capitalize", STATUS_COLORS[r.status])}>{r.status}</Badge>
              </div>
              <ScoreBar value={r.overall_score} />
              <p className="text-[10px] text-zinc-500 mt-1">{r.period_start} = {r.period_end}</p>
            </motion.div>
          ))
        )}
        </div>

        {/* Right Panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Sections */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm text-zinc-200">Sections = {selectedReport.report_name}</CardTitle>
                {selectedReport.status === "draft" && (
                  <Button size="sm" className="bg-green-600 hover:bg-green-700 text-xs">
                    <Send className="h-3 w-3 mr-1" /> Publish
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {selectedReport.sections.map(s => (
                <div key={s.section_name} className="border border-zinc-700 rounded-lg overflow-hidden">
                  <button className="w-full flex items-center gap-3 p-3 hover:bg-zinc-700/30 transition-colors text-left"
                    onClick={() => setExpandedSection(expandedSection === s.section_name ? null : s.section_name)}>
                    <span className={cn("h-2 w-2 rounded-full shrink-0", SECTION_DOT[s.status] ?? "bg-zinc-500")} />
                    <span className="flex-1 text-sm text-zinc-200">{s.section_name}</span>
                    <Badge className={cn("text-[9px] border", TYPE_COLORS[s.type] ?? "border-zinc-600 text-zinc-400")}>{s.type}</Badge>
                    <div className="w-24"><ScoreBar value={s.score} /></div>
                    {expandedSection === s.section_name ? <ChevronDown className="h-3 w-3 text-zinc-500" /> : <ChevronRight className="h-3 w-3 text-zinc-500" />}
                  </button>
                  {expandedSection === s.section_name && (
                    <div className="px-4 pb-3 text-xs text-zinc-400 border-t border-zinc-700 pt-2">{s.content}</div>
                  )}
                </div>
              )))}
            </CardContent>
          </Card>

          {/* Metrics Table */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-200">Metrics</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table role="table" className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-zinc-700">
                      <th className="text-left py-2 text-zinc-500 font-medium">Metric</th>
                      <th className="text-right py-2 text-zinc-500 font-medium">Value</th>
                      <th className="text-right py-2 text-zinc-500 font-medium">Previous</th>
                      <th className="text-center py-2 text-zinc-500 font-medium">Trend</th>
                      <th className="text-right py-2 text-zinc-500 font-medium">Benchmark</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedReport.metrics.map(m => (
                      <tr key={m.metric_name} className="border-b border-zinc-700/50 hover:bg-zinc-700/20">
                        <td className="py-2 text-zinc-300">{m.metric_name}</td>
                        <td className="py-2 text-right text-white font-mono">{m.value}{m.unit}</td>
                        <td className="py-2 text-right text-zinc-500 font-mono">{m.previous_value}{m.unit}</td>
                        <td className="py-2 flex justify-center"><TrendIcon trend={m.trend} /></td>
                        <td className="py-2 text-right text-zinc-500 font-mono">{m.benchmark_value}{m.unit}</td>
                      </tr>
                    )))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Trend Chart */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <CardTitle className="text-sm text-zinc-200">Trend</CardTitle>
                <select className="ml-auto bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-white"
                  value={metricFilter} onChange={e => setMetricFilter(e.target.value)}>
                  {selectedReport.metrics.map(m => <option key={m.metric_name}>{m.metric_name}</option>)}
                </select>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex items-end gap-2 h-24">
                {trendData.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  trendData.map((v, i) => (
                  <div key={i} className="flex-1 flex flex-col items-center gap-1">
                    <div className="w-full bg-blue-500/20 rounded-sm relative" style={{ height: `${(v / maxTrend) * 80}px` }}>
                      <div className="absolute bottom-0 left-0 right-0 bg-blue-500 rounded-sm" style={{ height: `${(v / maxTrend) * 80}px` }} />
                    </div>
                    <span className="text-[9px] text-zinc-500">W{i + 1}</span>
                  </div>
                ))
              )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
