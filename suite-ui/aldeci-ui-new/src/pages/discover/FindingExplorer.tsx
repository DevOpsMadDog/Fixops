import { useState, useCallback, useMemo, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search, Filter, Download, CheckSquare, AlertTriangle,
  Shield, Bug, RefreshCw, ChevronUp, ChevronDown, ChevronsUpDown,
  MoreHorizontal, Eye, UserCheck, Archive, X, ExternalLink, Upload, Loader2,
  Wrench, Zap, Sparkles, GitBranch,
} from "lucide-react";
import { toast } from "sonner";
import { bulkApi, analyticsApi, threatFeedsApi, autofixApi } from "@/lib/api";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useFindings } from "@/hooks/use-api";
import { cn, severityColor, statusColor } from "@/lib/utils";

type SortDirection = "asc" | "desc" | null;
type SortField = string | null;

function SortIcon({ field, sortField, sortDir }: { field: string; sortField: SortField; sortDir: SortDirection }) {
  if (sortField !== field) return <ChevronsUpDown className="h-3 w-3 ml-1 opacity-40" />;
  if (sortDir === "asc") return <ChevronUp className="h-3 w-3 ml-1 text-primary" />;
  return <ChevronDown className="h-3 w-3 ml-1 text-primary" />;
}

function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || "").toLowerCase();
  const variants: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    info: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  return (
    <Badge className={cn("border text-xs font-semibold uppercase tracking-wide", variants[s] || variants["info"])}>
      {severity || "Unknown"}
    </Badge>
  );
}

function StatusBadge({ status }: { status?: string }) {
  const s = (status || "").toLowerCase().replace(/\s+/g, "_");
  const variants: Record<string, string> = {
    open: "bg-red-500/10 text-red-400 border-red-500/20",
    in_progress: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    resolved: "bg-green-500/10 text-green-400 border-green-500/20",
    false_positive: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    accepted: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  };
  return (
    <Badge className={cn("border text-xs", variants[s] || "bg-slate-500/10 text-slate-400 border-slate-500/20")}>
      {status || "Unknown"}
    </Badge>
  );
}

function MpteBadge({ verdict }: { verdict?: string }) {
  if (!verdict) return <span className="text-muted-foreground text-xs">—</span>;
  const v = verdict.toLowerCase();
  const variants: Record<string, string> = {
    confirmed: "bg-red-500/10 text-red-400 border-red-500/20",
    not_exploitable: "bg-green-500/10 text-green-400 border-green-500/20",
    pending: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  };
  return (
    <Badge className={cn("border text-xs", variants[v] || "bg-slate-500/10 text-slate-400 border-slate-500/20")}>
      {verdict}
    </Badge>
  );
}

function EpssBadge({ score, percentile }: { score?: number; percentile?: number }) {
  if (score == null) return <span className="text-muted-foreground text-xs">—</span>;
  const pct = Math.round(score * 100);
  const color = pct >= 50 ? "bg-red-500/15 text-red-400 border-red-500/30"
    : pct >= 10 ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
    : pct >= 1 ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30"
    : "bg-slate-500/15 text-slate-400 border-slate-500/30";
  return (
    <div className="flex flex-col items-start gap-0.5">
      <Badge className={cn("border text-xs tabular-nums", color)}>
        {pct}%
      </Badge>
      {percentile != null && (
        <span className="text-[10px] text-muted-foreground">Top {Math.round((1 - percentile) * 100)}%</span>
      )}
    </div>
  );
}

function KevBadge({ isKev, dueDate }: { isKev?: boolean; dueDate?: string }) {
  if (!isKev) return <span className="text-muted-foreground text-xs">—</span>;
  return (
    <div className="flex flex-col items-start gap-0.5">
      <Badge className="border bg-red-600/20 text-red-300 border-red-600/40 text-xs font-bold gap-1">
        <AlertTriangle className="h-3 w-3" /> KEV
      </Badge>
      {dueDate && (
        <span className="text-[10px] text-red-400">Due {new Date(dueDate).toLocaleDateString()}</span>
      )}
    </div>
  );
}

function ReachabilityBadge({ reachable }: { reachable?: boolean | string }) {
  if (reachable == null) return <span className="text-muted-foreground text-xs">—</span>;
  const isReachable = reachable === true || reachable === "reachable" || reachable === "yes";
  const isUnknown = reachable === "unknown" || reachable === "pending";
  if (isUnknown) return <Badge className="border bg-slate-500/10 text-slate-400 border-slate-500/20 text-xs">Unknown</Badge>;
  return isReachable ? (
    <Badge className="border bg-red-500/10 text-red-400 border-red-500/20 text-xs gap-1">
      <Zap className="h-3 w-3" /> Reachable
    </Badge>
  ) : (
    <Badge className="border bg-green-500/10 text-green-400 border-green-500/20 text-xs gap-1">
      <Shield className="h-3 w-3" /> Unreachable
    </Badge>
  );
}

/** Composite Risk Priority — combines FAIL, EPSS, KEV, Reachability into a single score */
function RiskPriorityBadge({ finding }: { finding: Finding }) {
  const epss = finding.epss_score ?? 0;
  const isKev = finding.kev === true;
  const isReachable = finding.reachable === true || finding.reachable === "reachable";
  const fail = finding.fail_score ?? 0;
  const sevWeight = { critical: 40, high: 30, medium: 20, low: 10, info: 0 }[(finding.severity || "").toLowerCase()] ?? 10;
  // Composite: severity base + EPSS contribution + KEV bonus + reachability bonus + FAIL score
  const score = Math.min(100, Math.round(
    sevWeight + (epss * 30) + (isKev ? 15 : 0) + (isReachable ? 10 : 0) + (fail > 0 ? Math.min(fail / 10, 5) : 0)
  ));
  const color = score >= 70 ? "text-red-400 bg-red-500/10 border-red-500/30"
    : score >= 40 ? "text-orange-400 bg-orange-500/10 border-orange-500/30"
    : score >= 20 ? "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
    : "text-green-400 bg-green-500/10 border-green-500/30";
  return (
    <Badge className={cn("border text-xs font-bold tabular-nums", color)}>
      {score}
    </Badge>
  );
}

function FailScoreBadge({ score }: { score?: number }) {
  if (score == null || score === 0) return <span className="text-muted-foreground text-xs">—</span>;
  const color = score >= 80 ? "text-red-400" : score >= 50 ? "text-orange-400" : score >= 20 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("text-xs font-bold tabular-nums", color)}>{score.toFixed(0)}</span>;
}

function getAgeDays(dateStr?: string): string {
  if (!dateStr) return "—";
  const d = new Date(dateStr);
  const now = new Date();
  const diff = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
  if (diff === 0) return "Today";
  if (diff === 1) return "1d";
  return `${diff}d`;
}

interface Finding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  scanner?: string;
  app?: string;
  application?: string;
  cve?: string;
  component?: string;
  mpte_verdict?: string;
  created_at?: string;
  description?: string;
  file?: string;
  line?: number;
  rule?: string;
  epss_score?: number;
  epss_percentile?: number;
  kev?: boolean;
  kev_due_date?: string;
  reachable?: boolean | string;
  fail_score?: number;
  attack_paths_count?: number;
  blast_radius?: number;
  risk_priority?: number;
}

export default function FindingExplorer() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [scannerFilter, setScannerFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("all");
  const [page, setPage] = useState(1);
  const [sortField, setSortField] = useState<SortField>(null);
  const [sortDir, setSortDir] = useState<SortDirection>(null);
  const [selectedRows, setSelectedRows] = useState<Set<string>>(new Set());
  const [detailFinding, setDetailFinding] = useState<Finding | null>(null);
  const [bulkLoading, setBulkLoading] = useState(false);

  // ── Deep-link support: read URL search params ──
  useEffect(() => {
    const severity = searchParams.get("severity");
    const status = searchParams.get("status");
    const scanner = searchParams.get("scanner");
    const search = searchParams.get("search") || searchParams.get("q");
    if (severity && severity !== "all") {
      setSeverityFilter(severity.toLowerCase());
      setActiveTab(severity.toLowerCase());
    }
    if (status && status !== "all") setStatusFilter(status.toLowerCase());
    if (scanner && scanner !== "all") setScannerFilter(scanner.toLowerCase());
    if (search) setSearchQuery(search);
  }, [searchParams]);

  const PAGE_SIZE = 20;

  const params = useMemo(() => {
    const p: Record<string, unknown> = { limit: 200 };
    if (severityFilter !== "all") p.severity = severityFilter;
    if (statusFilter !== "all") p.status = statusFilter;
    if (scannerFilter !== "all") p.scanner = scannerFilter;
    return p;
  }, [severityFilter, statusFilter, scannerFilter]);

  const query = useFindings(params);
  const refetch = useCallback(() => query.refetch(), [query]);

  const rawFindings: Finding[] = useMemo(() => {
    const d = query.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray(d?.findings)) return d.findings;
    if (Array.isArray(d?.cases)) return d.cases;
    if (Array.isArray(d?.items)) return d.items;
    if (Array.isArray(d?.data)) return d.data;
    return [];
  }, [query.data]);

  // ── EPSS Enrichment: fetch scores for all CVEs in batch ──
  const cveIds = useMemo(() => rawFindings.filter(f => f.cve).map(f => f.cve!).join(","), [rawFindings]);
  const epssQuery = useQuery({
    queryKey: ["epss", cveIds],
    queryFn: async () => {
      if (!cveIds) return {};
      try {
        const { data } = await threatFeedsApi.epss(cveIds);
        const scores = data?.scores || data?.data || [];
        const map: Record<string, { score: number; percentile: number }> = {};
        for (const s of scores) {
          const id = s.cve || s.cve_id;
          if (id) map[id] = { score: s.epss ?? s.score ?? 0, percentile: s.percentile ?? 0 };
        }
        return map;
      } catch { return {}; }
    },
    enabled: !!cveIds,
    staleTime: 5 * 60_000,
  });

  // ── KEV Enrichment: check which CVEs are in CISA KEV ──
  const kevQuery = useQuery({
    queryKey: ["kev"],
    queryFn: async () => {
      try {
        const { data } = await threatFeedsApi.kev();
        const entries = data?.vulnerabilities || data?.entries || data?.data || [];
        const set = new Set<string>();
        const dueDates: Record<string, string> = {};
        for (const e of entries) {
          const id = e.cve_id || e.cveID || e.id;
          if (id) { set.add(id); if (e.due_date || e.dueDate) dueDates[id] = e.due_date || e.dueDate; }
        }
        return { set, dueDates };
      } catch { return { set: new Set<string>(), dueDates: {} as Record<string, string> }; }
    },
    staleTime: 10 * 60_000,
  });

  // ── Merge enrichment data into findings ──
  const allFindings: Finding[] = useMemo(() => {
    const epss = epssQuery.data || {};
    const kev = kevQuery.data || { set: new Set<string>(), dueDates: {} };
    return rawFindings.map(f => {
      const enriched = {
        ...f,
        epss_score: f.epss_score ?? (f.cve && epss[f.cve] ? epss[f.cve].score : undefined),
        epss_percentile: f.epss_percentile ?? (f.cve && epss[f.cve] ? epss[f.cve].percentile : undefined),
        kev: f.kev ?? (f.cve ? kev.set.has(f.cve) : false),
        kev_due_date: f.kev_due_date ?? (f.cve ? kev.dueDates[f.cve] : undefined),
      };
      // Compute risk_priority for sorting
      const epssVal = enriched.epss_score ?? 0;
      const isKev = enriched.kev === true;
      const isReachable = enriched.reachable === true || enriched.reachable === "reachable";
      const fail = enriched.fail_score ?? 0;
      const sevWeight = { critical: 40, high: 30, medium: 20, low: 10, info: 0 }[(enriched.severity || "").toLowerCase()] ?? 10;
      (enriched as Record<string, unknown>).risk_priority = Math.min(100, Math.round(
        sevWeight + (epssVal * 30) + (isKev ? 15 : 0) + (isReachable ? 10 : 0) + (fail > 0 ? Math.min(fail / 10, 5) : 0)
      ));
      return enriched;
    });
  }, [rawFindings, epssQuery.data, kevQuery.data]);

  // ── AutoFix mutation ──
  const qc = useQueryClient();
  const autofixMutation = useMutation({
    mutationFn: async (findingId: string) => {
      const { data } = await autofixApi.generate(findingId);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      toast.success("AutoFix generated — check Remediation Center");
    },
    onError: () => toast.error("AutoFix generation failed"),
  });

  const stats = useMemo(() => ({
    total: allFindings.length,
    critical: allFindings.filter((f) => f.severity?.toLowerCase() === "critical").length,
    high: allFindings.filter((f) => f.severity?.toLowerCase() === "high").length,
    medium: allFindings.filter((f) => f.severity?.toLowerCase() === "medium").length,
    low: allFindings.filter((f) => f.severity?.toLowerCase() === "low").length,
    kevCount: allFindings.filter((f) => f.kev).length,
    highEpss: allFindings.filter((f) => (f.epss_score || 0) >= 0.1).length,
    reachable: allFindings.filter((f) => f.reachable === true || f.reachable === "reachable").length,
  }), [allFindings]);

  const filtered = useMemo(() => {
    let list = allFindings;
    if (activeTab !== "all") {
      list = list.filter((f) => f.severity?.toLowerCase() === activeTab);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (f) =>
          f.title?.toLowerCase().includes(q) ||
          f.cve?.toLowerCase().includes(q) ||
          f.component?.toLowerCase().includes(q) ||
          f.finding_id?.toLowerCase().includes(q) ||
          (f.id || "").toLowerCase().includes(q)
      );
    }
    if (sortField && sortDir) {
      list = [...list].sort((a, b) => {
        const av = (a as Record<string, unknown>)[sortField] ?? "";
        const bv = (b as Record<string, unknown>)[sortField] ?? "";
        const cmp = String(av).localeCompare(String(bv));
        return sortDir === "asc" ? cmp : -cmp;
      });
    }
    return list;
  }, [allFindings, activeTab, searchQuery, sortField, sortDir]);

  const paginated = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
  }, [filtered, page]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

  function toggleSort(field: string) {
    if (sortField !== field) {
      setSortField(field);
      setSortDir("asc");
    } else if (sortDir === "asc") {
      setSortDir("desc");
    } else {
      setSortField(null);
      setSortDir(null);
    }
  }

  function toggleRow(id: string) {
    setSelectedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (selectedRows.size === paginated.length) {
      setSelectedRows(new Set());
    } else {
      setSelectedRows(new Set(paginated.map((f) => f.id || f.finding_id || "")));
    }
  }

  if (query.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-5 gap-4">
          {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (query.isError) {
    return <ErrorState message="Failed to load findings. Check your API connection." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Finding Explorer"
        description="Unified browser for all security findings across your environments"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => {
              const input = document.createElement('input');
              input.type = 'file';
              input.accept = '.sarif,.json,.xml,.csv';
              input.onchange = async (e) => {
                const file = (e.target as HTMLInputElement).files?.[0];
                if (!file) return;
                const form = new FormData();
                form.append('file', file);
                form.append('scanner_type', 'auto');
                try {
                  const resp = await fetch((import.meta.env.VITE_API_URL || '') + '/api/v1/scanner-ingest/upload', {
                    method: 'POST',
                    headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || '' },
                    body: form,
                  });
                  const data = await resp.json();
                  toast.success(`Ingested ${data.findings_count || 0} findings from ${file.name}`);
                  query.refetch();
                } catch (err) {
                  toast.error(`Upload failed: ${err}`);
                }
              };
              input.click();
            }} className="gap-2">
              <Upload className="h-4 w-4" /> Upload SARIF/SBOM
            </Button>
            <Button variant="outline" size="sm" onClick={() => query.refetch()} className="gap-2">
              <RefreshCw className="h-4 w-4" /> Refresh
            </Button>
            <Button variant="outline" size="sm" className="gap-2" onClick={() => {
              const csv = ["ID,Title,Severity,Status,CVE,Scanner,Created", ...allFindings.map(f =>
                `"${f.finding_id || f.id}","${f.title}","${f.severity}","${f.status}","${f.cve || ""}","${f.scanner || ""}","${f.created_at || ""}"`
              )].join("\n");
              const blob = new Blob([csv], { type: "text/csv" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a"); a.href = url; a.download = `all-findings-${Date.now()}.csv`; a.click();
              URL.revokeObjectURL(url);
              toast.success(`Exported ${allFindings.length} findings`);
            }}>
              <Download className="h-4 w-4" /> Export
            </Button>
          </div>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-4">
        <KpiCard title="Total Findings" value={stats.total} icon={Shield} onClick={() => { setActiveTab("all"); setSeverityFilter("all"); }} />
        <KpiCard title="Critical" value={stats.critical} icon={AlertTriangle} className="border-red-500/20" onClick={() => { setActiveTab("critical"); setSeverityFilter("critical"); }} />
        <KpiCard title="High" value={stats.high} icon={Bug} className="border-orange-500/20" onClick={() => { setActiveTab("high"); setSeverityFilter("high"); }} />
        <KpiCard title="Medium" value={stats.medium} icon={AlertTriangle} className="border-yellow-500/20" onClick={() => { setActiveTab("medium"); setSeverityFilter("medium"); }} />
        <KpiCard title="Low" value={stats.low} icon={Shield} className="border-blue-500/20" onClick={() => { setActiveTab("low"); setSeverityFilter("low"); }} />
        <KpiCard title="CISA KEV" value={stats.kevCount} icon={AlertTriangle} className="border-red-600/30" />
        <KpiCard title="EPSS ≥ 10%" value={stats.highEpss} icon={Zap} className="border-orange-600/30" />
        <KpiCard title="Reachable" value={stats.reachable} icon={GitBranch} className="border-purple-500/30" />
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-4 pb-4">
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings, CVE, component..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
                className="pl-9"
              />
            </div>
            <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v); setPage(1); }}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="info">Info</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setPage(1); }}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
                <SelectItem value="accepted">Accepted</SelectItem>
              </SelectContent>
            </Select>
            <Select value={scannerFilter} onValueChange={(v) => { setScannerFilter(v); setPage(1); }}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Scanner" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Scanners</SelectItem>
                <SelectItem value="semgrep">Semgrep</SelectItem>
                <SelectItem value="sonarqube">SonarQube</SelectItem>
                <SelectItem value="bandit">Bandit</SelectItem>
                <SelectItem value="trivy">Trivy</SelectItem>
                <SelectItem value="checkov">Checkov</SelectItem>
                <SelectItem value="gitleaks">Gitleaks</SelectItem>
                <SelectItem value="wiz">Wiz</SelectItem>
              </SelectContent>
            </Select>
            {(severityFilter !== "all" || statusFilter !== "all" || scannerFilter !== "all" || searchQuery) && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => { setSeverityFilter("all"); setStatusFilter("all"); setScannerFilter("all"); setSearchQuery(""); setPage(1); }}
                className="gap-1 text-muted-foreground"
              >
                <X className="h-3 w-3" /> Clear
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Bulk Action Bar */}
      <AnimatePresence>
        {selectedRows.size > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="flex items-center gap-3 p-3 bg-primary/10 border border-primary/20 rounded-lg"
          >
            <CheckSquare className="h-4 w-4 text-primary" />
            <span className="text-sm font-medium">{selectedRows.size} selected</span>
            <Separator orientation="vertical" className="h-4" />
            <Button size="sm" variant="outline" className="gap-1" disabled={bulkLoading}
              onClick={async () => {
                setBulkLoading(true);
                try {
                  const ids = Array.from(selectedRows);
                  await bulkApi.triage(ids, "triage", "triaged");
                  toast.success(`${ids.length} findings triaged`);
                  setSelectedRows(new Set());
                  query.refetch();
                } catch (e) { toast.error(`Triage failed: ${e}`); }
                finally { setBulkLoading(false); }
              }}>
              {bulkLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <UserCheck className="h-3 w-3" />} Triage
            </Button>
            <Button size="sm" variant="outline" className="gap-1" disabled={bulkLoading}
              onClick={async () => {
                setBulkLoading(true);
                try {
                  const ids = Array.from(selectedRows);
                  await bulkApi.assignFindings(ids, "security-team");
                  toast.success(`${ids.length} findings assigned to security-team`);
                  setSelectedRows(new Set());
                  query.refetch();
                } catch (e) { toast.error(`Assign failed: ${e}`); }
                finally { setBulkLoading(false); }
              }}>
              <UserCheck className="h-3 w-3" /> Assign
            </Button>
            <Button size="sm" variant="default" className="gap-1 bg-violet-600 hover:bg-violet-700" disabled={bulkLoading}
              onClick={async () => {
                setBulkLoading(true);
                try {
                  const ids = Array.from(selectedRows);
                  const selected = allFindings.filter(f => ids.includes(f.id || f.finding_id || ""));
                  const findings = selected.map(f => ({
                    finding_id: f.finding_id || f.id,
                    title: f.title,
                    severity: f.severity,
                    cve: f.cve,
                    file: f.file,
                    line: f.line,
                    rule: f.rule,
                    scanner: f.scanner,
                  }));
                  const { data } = await autofixApi.bulkGenerate(findings);
                  toast.success(`Generated ${data?.count || findings.length} fixes`);
                  qc.invalidateQueries({ queryKey: ["findings"] });
                  setSelectedRows(new Set());
                } catch (e) { toast.error(`Bulk AutoFix failed: ${e}`); }
                finally { setBulkLoading(false); }
              }}>
              {bulkLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Sparkles className="h-3 w-3" />} Bulk AutoFix
            </Button>
            <Button size="sm" variant="outline" className="gap-1"
              onClick={() => {
                const ids = Array.from(selectedRows);
                const selected = allFindings.filter(f => ids.includes(f.id || f.finding_id || ""));
                const csv = ["ID,Title,Severity,Status,CVE,Scanner,Created", ...selected.map(f =>
                  `"${f.finding_id || f.id}","${f.title}","${f.severity}","${f.status}","${f.cve || ""}","${f.scanner || ""}","${f.created_at || ""}"`
                )].join("\n");
                const blob = new Blob([csv], { type: "text/csv" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a"); a.href = url; a.download = `findings-export-${Date.now()}.csv`; a.click();
                URL.revokeObjectURL(url);
                toast.success(`Exported ${selected.length} findings`);
              }}>
              <Download className="h-3 w-3" /> Export Selected
            </Button>
            <Button size="sm" variant="ghost" className="gap-1" disabled={bulkLoading}
              onClick={async () => {
                setBulkLoading(true);
                try {
                  const ids = Array.from(selectedRows);
                  await bulkApi.updateFindings(ids, { status: "archived" });
                  toast.success(`${ids.length} findings archived`);
                  setSelectedRows(new Set());
                  query.refetch();
                } catch (e) { toast.error(`Archive failed: ${e}`); }
                finally { setBulkLoading(false); }
              }}>
              <Archive className="h-3 w-3" /> Archive
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="ml-auto text-muted-foreground"
              onClick={() => setSelectedRows(new Set())}
            >
              <X className="h-3 w-3" />
            </Button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Tabs + Table */}
      <Tabs value={activeTab} onValueChange={(v) => { setActiveTab(v); setPage(1); setSelectedRows(new Set()); }}>
        <TabsList>
          <TabsTrigger value="all">All ({stats.total})</TabsTrigger>
          <TabsTrigger value="critical">Critical ({stats.critical})</TabsTrigger>
          <TabsTrigger value="high">High ({stats.high})</TabsTrigger>
          <TabsTrigger value="medium">Medium ({stats.medium})</TabsTrigger>
          <TabsTrigger value="low">Low ({stats.low})</TabsTrigger>
        </TabsList>

        {["all", "critical", "high", "medium", "low"].map((tab) => (
          <TabsContent key={tab} value={tab} className="mt-4">
            <Card>
              <CardHeader className="pb-2 flex flex-row items-center justify-between">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  {filtered.length} findings
                </CardTitle>
                <Button variant="ghost" size="sm" className="gap-1 text-xs">
                  <Filter className="h-3 w-3" /> Columns
                </Button>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead className="w-10">
                          <Checkbox
                            checked={selectedRows.size === paginated.length && paginated.length > 0}
                            onCheckedChange={toggleAll}
                          />
                        </TableHead>
                        <TableHead className="w-28 cursor-pointer select-none" onClick={() => toggleSort("severity")}>
                          <span className="flex items-center">Severity <SortIcon field="severity" sortField={sortField} sortDir={sortDir} /></span>
                        </TableHead>
                        <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("finding_id")}>
                          <span className="flex items-center">ID <SortIcon field="finding_id" sortField={sortField} sortDir={sortDir} /></span>
                        </TableHead>
                        <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("title")}>
                          <span className="flex items-center">Title <SortIcon field="title" sortField={sortField} sortDir={sortDir} /></span>
                        </TableHead>
                        <TableHead>CVE</TableHead>
                        <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("epss_score")}>
                          <span className="flex items-center">EPSS <SortIcon field="epss_score" sortField={sortField} sortDir={sortDir} /></span>
                        </TableHead>
                        <TableHead>KEV</TableHead>
                        <TableHead>Reachability</TableHead>
                        <TableHead>Scanner</TableHead>
                        <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("status")}>
                          <span className="flex items-center">Status <SortIcon field="status" sortField={sortField} sortDir={sortDir} /></span>
                        </TableHead>
                        <TableHead>MPTE</TableHead>
                        <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("fail_score")}>
                          <span className="flex items-center">FAIL <SortIcon field="fail_score" sortField={sortField} sortDir={sortDir} /></span>
                        </TableHead>
                        <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("risk_priority")}>
                          <span className="flex items-center">Risk <SortIcon field="risk_priority" sortField={sortField} sortDir={sortDir} /></span>
                        </TableHead>
                        <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("created_at")}>
                          <span className="flex items-center">Age <SortIcon field="created_at" sortField={sortField} sortDir={sortDir} /></span>
                        </TableHead>
                        <TableHead className="w-10" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {paginated.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={16} className="text-center py-12 text-muted-foreground">
                            <div className="flex flex-col items-center gap-2">
                              <Shield className="h-8 w-8 opacity-30" />
                              <p>No findings match the current filters</p>
                            </div>
                          </TableCell>
                        </TableRow>
                      ) : (
                        paginated.map((finding, idx) => {
                          const id = finding.id || finding.finding_id || String(idx);
                          return (
                            <TableRow
                              key={id}
                              className="cursor-pointer transition-colors hover:bg-muted/40"
                              onClick={() => setDetailFinding(finding)}
                            >
                              <TableCell onClick={(e) => e.stopPropagation()}>
                                <Checkbox
                                  checked={selectedRows.has(id)}
                                  onCheckedChange={() => toggleRow(id)}
                                />
                              </TableCell>
                              <TableCell>
                                <SeverityBadge severity={finding.severity} />
                              </TableCell>
                              <TableCell className="font-mono text-xs text-muted-foreground">
                                {finding.finding_id || finding.id || `F-${idx + 1}`}
                              </TableCell>
                              <TableCell className="max-w-[280px]">
                                <span className="truncate block font-medium text-sm">{finding.title || "Untitled"}</span>
                              </TableCell>
                              <TableCell className="font-mono text-xs">
                                {finding.cve ? (
                                  <span className="text-blue-400 hover:underline">{finding.cve}</span>
                                ) : (
                                  <span className="text-muted-foreground">—</span>
                                )}
                              </TableCell>
                              <TableCell>
                                <EpssBadge score={finding.epss_score} percentile={finding.epss_percentile} />
                              </TableCell>
                              <TableCell>
                                <KevBadge isKev={finding.kev} dueDate={finding.kev_due_date} />
                              </TableCell>
                              <TableCell>
                                <ReachabilityBadge reachable={finding.reachable} />
                              </TableCell>
                              <TableCell className="text-xs">
                                <Badge variant="outline" className="text-xs">{finding.scanner || "—"}</Badge>
                              </TableCell>
                              <TableCell>
                                <StatusBadge status={finding.status} />
                              </TableCell>
                              <TableCell>
                                <MpteBadge verdict={finding.mpte_verdict} />
                              </TableCell>
                              <TableCell>
                                <FailScoreBadge score={finding.fail_score} />
                              </TableCell>
                              <TableCell>
                                <RiskPriorityBadge finding={finding} />
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                                {getAgeDays(finding.created_at)}
                              </TableCell>
                              <TableCell onClick={(e) => e.stopPropagation()}>
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="h-7 w-7">
                                      <MoreHorizontal className="h-3.5 w-3.5" />
                                    </Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end">
                                    <DropdownMenuItem onClick={() => setDetailFinding(finding)}>
                                      <Eye className="h-3.5 w-3.5 mr-2" /> View Details
                                    </DropdownMenuItem>
                                    <DropdownMenuItem onClick={async () => {
                                      try {
                                        await bulkApi.triage([finding.id || finding.finding_id || ""], "triage", "triaged");
                                        toast.success("Finding triaged");
                                        query.refetch();
                                      } catch (e) { toast.error(`Triage failed: ${e}`); }
                                    }}>
                                      <UserCheck className="h-3.5 w-3.5 mr-2" /> Triage
                                    </DropdownMenuItem>
                                    <DropdownMenuItem onClick={() => {
                                      navigate(`/remediate?search=${encodeURIComponent(finding.cve || finding.title || finding.finding_id || "")}&severity=${finding.severity || ""}`);
                                    }}>
                                      <Wrench className="h-3.5 w-3.5 mr-2" /> Create Remediation Task
                                    </DropdownMenuItem>
                                    <DropdownMenuItem onClick={() => {
                                      autofixMutation.mutate(finding.id || finding.finding_id || "");
                                    }}>
                                      <Sparkles className="h-3.5 w-3.5 mr-2" /> AutoFix
                                    </DropdownMenuItem>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem onClick={() => {
                                      navigate(`/validate/mpte?finding=${encodeURIComponent(finding.cve || finding.finding_id || "")}`);
                                    }}>
                                      <ExternalLink className="h-3.5 w-3.5 mr-2" /> Validate with MPTE
                                    </DropdownMenuItem>
                                    <DropdownMenuItem onClick={async () => {
                                      try {
                                        await bulkApi.updateFindings([finding.id || finding.finding_id || ""], { status: "archived" });
                                        toast.success("Finding archived");
                                        query.refetch();
                                      } catch (e) { toast.error(`Archive failed: ${e}`); }
                                    }}>
                                      <Archive className="h-3.5 w-3.5 mr-2" /> Archive
                                    </DropdownMenuItem>
                                  </DropdownMenuContent>
                                </DropdownMenu>
                              </TableCell>
                            </TableRow>
                          );
                        })
                      )}
                    </TableBody>
                  </Table>
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div className="flex items-center justify-between px-4 py-3 border-t">
                    <span className="text-sm text-muted-foreground">
                      Page {page} of {totalPages} ({filtered.length} total)
                    </span>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={page === 1}
                        onClick={() => setPage((p) => p - 1)}
                      >
                        Previous
                      </Button>
                      {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                        const n = Math.max(1, Math.min(page - 2, totalPages - 4)) + i;
                        if (n > totalPages) return null;
                        return (
                          <Button
                            key={n}
                            variant={n === page ? "default" : "outline"}
                            size="sm"
                            onClick={() => setPage(n)}
                          >
                            {n}
                          </Button>
                        );
                      })}
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={page === totalPages}
                        onClick={() => setPage((p) => p + 1)}
                      >
                        Next
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        ))}
      </Tabs>

      {/* Detail Dialog */}
      <Dialog open={!!detailFinding} onOpenChange={(open) => { if (!open) setDetailFinding(null); }}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3">
              <SeverityBadge severity={detailFinding?.severity} />
              <span className="truncate">{detailFinding?.title || "Finding Detail"}</span>
            </DialogTitle>
            <DialogDescription className="font-mono text-xs">
              {detailFinding?.finding_id || detailFinding?.id}
            </DialogDescription>
          </DialogHeader>
          {detailFinding && (
            <div className="space-y-4 mt-2">
              {/* Risk Intelligence Panel */}
              {(detailFinding.epss_score != null || detailFinding.kev || detailFinding.reachable != null) && (
                <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 space-y-2">
                  <p className="text-xs font-semibold uppercase tracking-wide text-amber-400">Risk Intelligence</p>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="space-y-1">
                      <p className="text-[10px] text-muted-foreground">EPSS Probability</p>
                      <EpssBadge score={detailFinding.epss_score} percentile={detailFinding.epss_percentile} />
                    </div>
                    <div className="space-y-1">
                      <p className="text-[10px] text-muted-foreground">CISA KEV</p>
                      <KevBadge isKev={detailFinding.kev} dueDate={detailFinding.kev_due_date} />
                    </div>
                    <div className="space-y-1">
                      <p className="text-[10px] text-muted-foreground">Reachability</p>
                      <ReachabilityBadge reachable={detailFinding.reachable} />
                    </div>
                  </div>
                  {(detailFinding.attack_paths_count ?? 0) > 0 && (
                    <p className="text-xs text-muted-foreground">
                      <GitBranch className="inline h-3 w-3 mr-1" />
                      {detailFinding.attack_paths_count} attack paths · Blast radius: {detailFinding.blast_radius ?? "—"} assets
                    </p>
                  )}
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: "Status", value: <StatusBadge status={detailFinding.status} /> },
                  { label: "MPTE Verdict", value: <MpteBadge verdict={detailFinding.mpte_verdict} /> },
                  { label: "Scanner", value: detailFinding.scanner || "—" },
                  { label: "Application", value: detailFinding.app || detailFinding.application || "—" },
                  { label: "CVE", value: <span className="font-mono text-xs text-blue-400">{detailFinding.cve || "—"}</span> },
                  { label: "Component", value: detailFinding.component || "—" },
                  { label: "Age", value: getAgeDays(detailFinding.created_at) },
                ].map(({ label, value }) => (
                  <div key={label} className="space-y-1">
                    <p className="text-xs text-muted-foreground">{label}</p>
                    <div className="text-sm font-medium">{value}</div>
                  </div>
                ))}
              </div>
              {detailFinding.description && (
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wide">Description</p>
                  <p className="text-sm leading-relaxed">{detailFinding.description}</p>
                </div>
              )}
              {detailFinding.file && (
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wide">Location</p>
                  <code className="text-xs bg-muted rounded px-2 py-1 block font-mono">
                    {detailFinding.file}{detailFinding.line ? `:${detailFinding.line}` : ""}
                  </code>
                </div>
              )}
              <div className="flex flex-wrap gap-2 pt-2">
                <Button size="sm" className="gap-1" onClick={async () => {
                  try {
                    await bulkApi.triage([detailFinding.id || detailFinding.finding_id || ""], "triage", "triaged");
                    toast.success("Finding triaged successfully");
                    setDetailFinding(null);
                    query.refetch();
                  } catch (e) { toast.error(`Triage failed: ${e}`); }
                }}><UserCheck className="h-3 w-3" /> Triage</Button>
                <Button size="sm" variant="outline" className="gap-1"
                  disabled={autofixMutation.isPending}
                  onClick={() => {
                    autofixMutation.mutate(detailFinding.id || detailFinding.finding_id || "");
                  }}>
                  {autofixMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Sparkles className="h-3 w-3" />} AutoFix
                </Button>
                <Button size="sm" variant="outline" className="gap-1" onClick={() => {
                  navigate(`/remediate?search=${encodeURIComponent(detailFinding.cve || detailFinding.title || detailFinding.finding_id || "")}&severity=${detailFinding.severity || ""}`);
                  setDetailFinding(null);
                }}><Wrench className="h-3 w-3" /> Remediate</Button>
                <Button size="sm" variant="outline" className="gap-1" onClick={() => {
                  navigate(`/validate/mpte?finding=${encodeURIComponent(detailFinding.cve || detailFinding.finding_id || "")}`);
                  setDetailFinding(null);
                }}><ExternalLink className="h-3 w-3" /> MPTE Validate</Button>
                <Button size="sm" variant="outline" className="gap-1" onClick={async () => {
                  try {
                    await bulkApi.updateFindings([detailFinding.id || detailFinding.finding_id || ""], { status: "archived" });
                    toast.success("Finding archived");
                    setDetailFinding(null);
                    query.refetch();
                  } catch (e) { toast.error(`Archive failed: ${e}`); }
                }}><Archive className="h-3 w-3" /> Archive</Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
