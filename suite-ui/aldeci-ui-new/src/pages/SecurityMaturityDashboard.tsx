/**
 * Security Maturity Dashboard
 *
 * Security Maturity Assessment — framework tabs, domain scoring, roadmap.
 *   1. KPIs: Assessments Completed, Avg Maturity Score, Domains at Target, Below Target
 *   2. Framework tabs: NIST CSF | CIS Controls | ISO 27001 | CMMI
 *   3. Domain progress bars (0-100 score)
 *   4. Domain table: level, target, score, status
 *   5. Roadmap panel: ordered by gap size
 *
 * API: GET /api/v1/security-maturity/...
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  BarChart2,
  CheckCircle,
  AlertTriangle,
  TrendingUp,
  RefreshCw,
  PlayCircle,
  Target,
  Layers,
} from "lucide-react";
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

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const FRAMEWORKS = ["NIST CSF", "CIS Controls", "ISO 27001", "CMMI"];

const DOMAINS_BY_FRAMEWORK: Record<string, Array<{
  domain: string;
  current_level: string;
  target_level: string;
  score: number;
  status: string;
  effort: string;
}>> = {
  "NIST CSF": [
    { domain: "Identify",  current_level: "L3", target_level: "L4", score: 72, status: "near_target", effort: "Medium" },
    { domain: "Protect",   current_level: "L3", target_level: "L4", score: 68, status: "near_target", effort: "Medium" },
    { domain: "Detect",    current_level: "L2", target_level: "L4", score: 55, status: "below_target", effort: "High" },
    { domain: "Respond",   current_level: "L2", target_level: "L3", score: 61, status: "near_target", effort: "Medium" },
    { domain: "Recover",   current_level: "L1", target_level: "L3", score: 48, status: "below_target", effort: "High" },
  ],
  "CIS Controls": [
    { domain: "Basic Controls",       current_level: "L3", target_level: "L4", score: 78, status: "near_target", effort: "Low" },
    { domain: "Foundational Controls",current_level: "L2", target_level: "L4", score: 62, status: "below_target", effort: "High" },
    { domain: "Organizational Controls",current_level: "L2",target_level: "L3", score: 58, status: "below_target", effort: "Medium" },
    { domain: "Asset Management",     current_level: "L3", target_level: "L4", score: 71, status: "near_target", effort: "Low" },
    { domain: "Access Control",       current_level: "L3", target_level: "L5", score: 65, status: "below_target", effort: "High" },
  ],
  "ISO 27001": [
    { domain: "Information Security Policies", current_level: "L4", target_level: "L4", score: 88, status: "at_target", effort: "Low" },
    { domain: "Organization of Info Sec",      current_level: "L3", target_level: "L4", score: 74, status: "near_target", effort: "Low" },
    { domain: "Human Resource Security",       current_level: "L2", target_level: "L3", score: 57, status: "below_target", effort: "Medium" },
    { domain: "Asset Management",              current_level: "L3", target_level: "L4", score: 69, status: "near_target", effort: "Medium" },
    { domain: "Cryptography",                  current_level: "L2", target_level: "L4", score: 44, status: "below_target", effort: "High" },
  ],
  "CMMI": [
    { domain: "Process Management",   current_level: "L3", target_level: "L4", score: 70, status: "near_target", effort: "Medium" },
    { domain: "Project Management",   current_level: "L3", target_level: "L3", score: 82, status: "at_target", effort: "Low" },
    { domain: "Engineering",          current_level: "L2", target_level: "L4", score: 52, status: "below_target", effort: "High" },
    { domain: "Support",              current_level: "L3", target_level: "L4", score: 67, status: "near_target", effort: "Medium" },
    { domain: "Service Delivery",     current_level: "L1", target_level: "L3", score: 40, status: "below_target", effort: "High" },
  ],
};

const ASSESSMENTS = [
  { id: "ASSESS-001", framework: "NIST CSF",     completed: "2026-04-10", assessor: "Jane Smith",     score: 61, status: "complete" },
  { id: "ASSESS-002", framework: "ISO 27001",    completed: "2026-04-08", assessor: "Mike Chen",      score: 66, status: "complete" },
  { id: "ASSESS-003", framework: "CIS Controls", completed: "2026-03-30", assessor: "Sarah Johnson",  score: 67, status: "complete" },
  { id: "ASSESS-004", framework: "CMMI",         completed: "2026-03-22", assessor: "Alex Rivera",    score: 62, status: "complete" },
];

// ── Helpers ────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    at_target:    "border-green-500/30 text-green-400 bg-green-500/10",
    near_target:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    below_target: "border-red-500/30 text-red-400 bg-red-500/10",
    complete:     "border-green-500/30 text-green-400 bg-green-500/10",
  };
  const label: Record<string, string> = {
    at_target: "At Target", near_target: "Near Target", below_target: "Below Target", complete: "Complete",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

function EffortBadge({ effort }: { effort: string }) {
  const map: Record<string, string> = {
    Low:    "border-green-500/30 text-green-400 bg-green-500/10",
    Medium: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    High:   "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[effort] ?? "border-border")}>{effort}</Badge>;
}

function ScoreBar({ score, idx }: { score: number; idx: number }) {
  const color = score >= 75 ? "bg-green-500" : score >= 60 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="relative flex-1 h-2 rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.6, delay: idx * 0.07 }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums w-8 text-right", score >= 75 ? "text-green-400" : score >= 60 ? "text-amber-400" : "text-red-400")}>
        {score}
      </span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityMaturityDashboard() {
  const [activeFramework, setActiveFramework] = useState("NIST CSF");
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [liveAssessments, setLiveAssessments] = useState<any[]>([]);
  const [dataLoading, setDataLoading] = useState(false);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/security-maturity/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-maturity/assessments?org_id=${ORG_ID}`),
    ]).then(([statsR, assessmentsR]) => {
      const stats = statsR.status === "fulfilled" ? statsR.value : null;
      if (stats) setLiveData({ stats });
      if (assessmentsR.status === "fulfilled") {
        const data = assessmentsR.value;
        const list = Array.isArray(data?.assessments) ? data.assessments
                   : Array.isArray(data) ? data : [];
        if (list.length > 0) setLiveAssessments(list);
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const domains = DOMAINS_BY_FRAMEWORK[activeFramework] ?? [];
  const avgScore = Math.round(domains.reduce((s, d) => s + d.score, 0) / domains.length);
  const atTarget    = domains.filter((d) => d.status === "at_target").length;
  const belowTarget = domains.filter((d) => d.status === "below_target").length;

  // Roadmap: sort by gap (score distance from 100) descending
  const roadmap = [...domains]
    .filter((d) => d.status !== "at_target")
    .sort((a, b) => (b.target_level > b.current_level ? 1 : 0) - (a.target_level > a.current_level ? 1 : 0) || a.score - b.score);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
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
        title="Security Maturity"
        description="Framework-based maturity assessment, domain scoring, and improvement roadmap"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
            <Button size="sm" className="gap-1.5">
              <PlayCircle className="h-4 w-4" />
              Start Assessment
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Assessments Completed" value={liveData?.stats?.total_assessments ?? liveData?.stats?.assessments_completed ?? ASSESSMENTS.length} icon={CheckCircle} trend="up" />
        <KpiCard title="Avg Maturity Score"    value={liveData?.stats?.avg_maturity_score != null ? `${Math.round(liveData.stats.avg_maturity_score)}/100` : `${avgScore}/100`} icon={BarChart2} trend="up" className="border-blue-500/20" />
        <KpiCard title="Domains at Target"     value={liveData?.stats?.domains_at_target ?? liveData?.stats?.at_target ?? atTarget}     icon={Target}       trend="up"   className="border-green-500/20" />
        <KpiCard title="Below Target"          value={liveData?.stats?.domains_below_target ?? liveData?.stats?.below_target ?? belowTarget} icon={AlertTriangle} trend="down" className="border-red-500/20" />
      </div>

      {/* Framework tabs */}
      <div className="flex gap-1 flex-wrap">
        {FRAMEWORKS.map((fw) => (
          <button
            key={fw}
            onClick={() => setActiveFramework(fw)}
            className={cn(
              "px-3 py-1.5 text-xs font-medium rounded-md border transition-colors",
              activeFramework === fw
                ? "bg-primary text-primary-foreground border-primary"
                : "border-border text-muted-foreground hover:text-foreground hover:bg-muted/40"
            )}
          >
            {fw}
          </button>
        ))}
      </div>

      {/* Domain progress bars + table */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Progress bars */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Layers className="h-4 w-4 text-blue-400" />
              Domain Scores — {activeFramework}
            </CardTitle>
            <CardDescription className="text-xs">Maturity score (0–100) per domain</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {domains.map((d, i) => (
              <div key={d.domain} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{d.domain}</span>
                  <span className="text-muted-foreground">{d.current_level} → {d.target_level}</span>
                </div>
                <ScoreBar score={d.score} idx={i} />
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Roadmap panel */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-amber-400" />
              Improvement Roadmap
            </CardTitle>
            <CardDescription className="text-xs">Ordered by gap size — highest priority first</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {roadmap.map((d, i) => (
              <div key={d.domain} className="flex items-center gap-3 rounded-lg border border-border bg-muted/20 p-3">
                <span className="text-[10px] font-bold text-muted-foreground w-5 shrink-0">#{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">{d.domain}</div>
                  <div className="text-[10px] text-muted-foreground">{d.current_level} → {d.target_level} &nbsp;|&nbsp; Score: {d.score}</div>
                </div>
                <EffortBadge effort={d.effort} />
              </div>
            ))}
            {roadmap.length === 0 && (
              <div className="text-xs text-center text-muted-foreground py-6">All domains at target level.</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Domain table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart2 className="h-4 w-4 text-purple-400" />
            Domain Detail — {activeFramework}
          </CardTitle>
          <CardDescription className="text-xs">Current level, target, score, and maturity status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Domain</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Current</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Target</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {domains.map((d, i) => (
                  <TableRow key={d.domain} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{d.domain}</TableCell>
                    <TableCell className="py-2 text-center">
                      <span className="font-mono text-[11px] bg-muted/40 px-1.5 py-0.5 rounded">{d.current_level}</span>
                    </TableCell>
                    <TableCell className="py-2 text-center">
                      <span className="font-mono text-[11px] bg-muted/40 px-1.5 py-0.5 rounded text-blue-400">{d.target_level}</span>
                    </TableCell>
                    <TableCell className="py-2 min-w-[120px]">
                      <ScoreBar score={d.score} idx={i} />
                    </TableCell>
                    <TableCell className="py-2"><StatusBadge status={d.status} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Recent assessments */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            Recent Assessments
          </CardTitle>
          <CardDescription className="text-xs">Completed framework assessments</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Framework</TableHead>
                  <TableHead className="text-[11px] h-8">Assessor</TableHead>
                  <TableHead className="text-[11px] h-8">Completed</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveAssessments.length > 0 ? liveAssessments : ASSESSMENTS).map((a) => (
                  <TableRow key={a.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{a.id}</TableCell>
                    <TableCell className="py-2 text-xs font-medium">{a.framework}</TableCell>
                    <TableCell className="py-2 text-xs text-muted-foreground">{a.assessor}</TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-muted-foreground">{a.completed}</TableCell>
                    <TableCell className="py-2 text-right">
                      <span className={cn("text-xs font-bold tabular-nums", a.score >= 75 ? "text-green-400" : a.score >= 60 ? "text-amber-400" : "text-red-400")}>
                        {a.score}
                      </span>
                    </TableCell>
                    <TableCell className="py-2"><StatusBadge status={a.status} /></TableCell>
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
