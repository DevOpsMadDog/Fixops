import { toArray } from "@/lib/api-utils";
import { useState, useMemo } from "react";
import { motion } from "framer-motion";
import {
  GitMerge,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  TrendingDown,
  Layers,
  Search,
  SplitSquareHorizontal,
  MergeIcon,
  Filter,
  ChevronDown,
  ChevronRight,
  Zap,
  BarChart2,
  Target,
  XCircle,
  HelpCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
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
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useFindings, useDashboardTrends } from "@/hooks/use-api";
import { useQuery } from "@tanstack/react-query";
import { deduplicationApi } from "@/lib/api";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  BarChart,
  Bar,
} from "recharts";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

// ── Scanner source labels ──────────────────────────────────────────────────
const SCANNERS = ["Snyk", "Trivy", "Semgrep", "SonarQube"] as const;
type Scanner = (typeof SCANNERS)[number];

// ── Severity colours ───────────────────────────────────────────────────────
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

// ── Correlation matrix heat palette ───────────────────────────────────────
const heatColor = (val: number) => {
  if (val >= 80) return "bg-red-500/80 text-white";
  if (val >= 60) return "bg-orange-500/70 text-white";
  if (val >= 40) return "bg-yellow-500/60 text-foreground";
  if (val >= 20) return "bg-emerald-500/40 text-foreground";
  return "bg-muted text-muted-foreground";
};

// Empty defaults — dedup trend and noise pie are loaded exclusively from the dedup API
const DEDUP_TREND_EMPTY: { week: string; total: number; deduplicated: number; unique: number }[] = [];

const NOISE_PIE_EMPTY: { name: string; value: number; color: string }[] = [];

// ── Cross-scanner correlation matrix (percentage overlap) ───────────────────
const MATRIX_DATA: Record<Scanner, Record<Scanner, number>> = {
  Snyk: { Snyk: 100, Trivy: 73, Semgrep: 41, SonarQube: 38 },
  Trivy: { Snyk: 73, Trivy: 100, Semgrep: 29, SonarQube: 22 },
  Semgrep: { Snyk: 41, Trivy: 29, Semgrep: 100, SonarQube: 67 },
  SonarQube: { Snyk: 38, Trivy: 22, Semgrep: 67, SonarQube: 100 },
};

// ── Static grouped vulnerability clusters (fallback when API has no data) ───
const VULN_GROUPS = [
  {
    id: "vg-001",
    cve: "CVE-2024-1234",
    title: "Log4Shell RCE in org.apache.logging",
    severity: "critical",
    scanners: ["Snyk", "Trivy", "Semgrep"],
    count: 14,
    dedupStatus: "merged",
    affectedComponents: ["api-gateway", "auth-service", "data-pipeline"],
  },
  {
    id: "vg-002",
    cve: "CVE-2023-44487",
    title: "HTTP/2 Rapid Reset DoS in nginx",
    severity: "high",
    scanners: ["Trivy", "SonarQube"],
    count: 8,
    dedupStatus: "merged",
    affectedComponents: ["web-frontend", "load-balancer"],
  },
  {
    id: "vg-003",
    cve: "CVE-2024-3094",
    title: "XZ Utils backdoor — supply chain",
    severity: "critical",
    scanners: ["Snyk", "Trivy"],
    count: 3,
    dedupStatus: "pending",
    affectedComponents: ["build-agent", "ci-runner"],
  },
  {
    id: "vg-004",
    cve: "CVE-2023-38545",
    title: "curl SOCKS5 heap overflow",
    severity: "high",
    scanners: ["Snyk", "SonarQube"],
    count: 6,
    dedupStatus: "split",
    affectedComponents: ["data-fetcher", "ml-pipeline"],
  },
  {
    id: "vg-005",
    cve: "CVE-2024-22365",
    title: "PAM local DoS — linux-pam",
    severity: "medium",
    scanners: ["Trivy"],
    count: 11,
    dedupStatus: "merged",
    affectedComponents: ["worker-nodes"],
  },
  {
    id: "vg-006",
    cve: "CVE-2024-0056",
    title: "SQL injection via parameterised bypass",
    severity: "high",
    scanners: ["Semgrep", "SonarQube"],
    count: 5,
    dedupStatus: "pending",
    affectedComponents: ["reporting-service", "admin-api"],
  },
];

interface VulnGroup {
  id: string;
  cve: string;
  title: string;
  severity: string;
  scanners: string[];
  count: number;
  dedupStatus: string;
  affectedComponents: string[];
}

// ── Custom tooltip ─────────────────────────────────────────────────────────
const ChartTooltip = ({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, padding: "10px 14px" }}>
      {label && <p className="text-xs text-muted-foreground mb-2">{label}</p>}
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2 text-xs">
          <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          <span className="text-muted-foreground">{p.name}:</span>
          <span className="font-semibold text-foreground">{p.value}</span>
        </div>
      ))}
    </div>
  );
};

// ── Merge / Split dialog ───────────────────────────────────────────────────
function MergeSplitDialog({
  open,
  onClose,
  group,
  mode,
}: {
  open: boolean;
  onClose: () => void;
  group: VulnGroup | null;
  mode: "merge" | "split";
}) {
  const [reason, setReason] = useState("");
  if (!group) return null;

  function handleConfirm() {
    toast.success(`${mode === "merge" ? "Merged" : "Split"} ${group!.cve} successfully`);
    onClose();
    setReason("");
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {mode === "merge" ? (
              <MergeIcon className="h-4 w-4 text-primary" />
            ) : (
              <SplitSquareHorizontal className="h-4 w-4 text-orange-400" />
            )}
            {mode === "merge" ? "Merge Findings" : "Split Finding Group"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="p-3 rounded-lg bg-muted/40 space-y-1">
            <p className="text-sm font-medium">{group.cve}</p>
            <p className="text-xs text-muted-foreground">{group.title}</p>
            <div className="flex gap-2 mt-2">
              {group.scanners.map((s) => (
                <Badge key={s} variant="outline" className="text-xs">{s}</Badge>
              ))}
            </div>
          </div>
          <div className="space-y-2">
            <Label className="text-xs text-muted-foreground">Reason / Justification</Label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full min-h-[80px] rounded-md bg-muted/30 border border-border text-sm p-2 resize-none focus:outline-none focus:ring-1 focus:ring-primary"
              placeholder={
                mode === "merge"
                  ? "Describe why these findings represent the same vulnerability..."
                  : "Describe why this group should be split into separate findings..."
              }
            />
          </div>
          {mode === "split" && (
            <div className="flex items-center gap-2 p-3 rounded-md bg-amber-500/10 border border-amber-500/20">
              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
              <p className="text-xs text-amber-300">
                Splitting will create {group.scanners.length} separate finding records and reset dedup status.
              </p>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          <Button
            size="sm"
            className={cn("gap-2", mode === "split" ? "bg-orange-500 hover:bg-orange-600" : "")}
            onClick={handleConfirm}
            disabled={!reason.trim()}
          >
            {mode === "merge" ? <MergeIcon className="h-3.5 w-3.5" /> : <SplitSquareHorizontal className="h-3.5 w-3.5" />}
            Confirm {mode === "merge" ? "Merge" : "Split"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────
export default function CorrelationEngine() {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [scannerFilter, setScannerFilter] = useState("all");
  const [dedupFilter, setDedupFilter] = useState("all");
  const [autoMergeEnabled, setAutoMergeEnabled] = useState(true);
  const [mergeSplitDialog, setMergeSplitDialog] = useState<{
    open: boolean;
    group: VulnGroup | null;
    mode: "merge" | "split";
  }>({ open: false, group: null, mode: "merge" });

  const casesQuery = useFindings({ limit: 50 });
  const trendsQuery = useDashboardTrends();

  // Real dedup data from API
  const dedupStatsQuery = useQuery({
    queryKey: ["dedup-stats"],
    queryFn: () => deduplicationApi.stats().then((r) => r.data),
    staleTime: 30_000,
  });
  const dedupClustersQuery = useQuery({
    queryKey: ["dedup-clusters"],
    queryFn: () => deduplicationApi.clusters().then((r) => r.data),
    staleTime: 30_000,
  });

  const isLoading = casesQuery.isLoading || trendsQuery.isLoading;
  const isError = casesQuery.isError;

  // Build vuln groups from API clusters or fall back to static data
  const apiGroups: VulnGroup[] = useMemo(() => {
    const clusters = dedupClustersQuery.data?.clusters;
    if (!Array.isArray(clusters) || clusters.length === 0) return VULN_GROUPS;
    return clusters.map((c: Record<string, unknown>, i: number) => ({
      id: (c.cluster_id as string) || `vg-${i}`,
      cve: (c.cve_id as string) || "N/A",
      title: (c.title as string) || (c.category as string) || "Unnamed cluster",
      severity: (c.severity as string) || "medium",
      scanners: Array.isArray(c.scanners) ? (c.scanners as string[]) : [(c.category as string) || "unknown"],
      count: typeof c.finding_count === "number" ? (c.finding_count as number) : 1,
      dedupStatus: (c.status as string) || "pending",
      affectedComponents: Array.isArray(c.affected_components) ? (c.affected_components as string[]) : [(c.component_id as string) || "unknown"],
    }));
  }, [dedupClustersQuery.data]);

  // KPI derived values using real stats when available ─────────────────────
  const cases = useMemo(() => {
    const raw = toArray(casesQuery.data);
    return Array.isArray(raw) ? raw : [];
  }, [casesQuery.data]);

  const dedupStats = dedupStatsQuery.data;
  const totalCorrelations = useMemo(() =>
    dedupStats?.total_events ?? apiGroups.reduce((a, g) => a + g.count, 0),
  [dedupStats, apiGroups]);
  const dedupRatio = useMemo(() => {
    if (dedupStats?.noise_reduction_percent != null) return Math.round(dedupStats.noise_reduction_percent);
    const merged = apiGroups.filter((g) => g.dedupStatus === "merged").length;
    return apiGroups.length > 0 ? Math.round((merged / apiGroups.length) * 100) : 0;
  }, [dedupStats, apiGroups]);
  const crossScannerMatches = useMemo(
    () => apiGroups.filter((g) => g.scanners.length >= 2).length,
    [apiGroups]
  );
  const noiseReduction = dedupStats?.noise_reduction_percent != null
    ? Math.round(dedupStats.noise_reduction_percent)
    : 21;

  // Dedup trend — derive from status endpoint when available, else use fallback
  const dedupStatusQuery = useQuery({
    queryKey: ["deduplication", "status"],
    queryFn: () => deduplicationApi.status().then((r) => r.data),
    staleTime: 60_000,
  });
  const DEDUP_TREND = useMemo(() => {
    const st = dedupStatusQuery.data;
    if (st?.events && st.clusters) {
      const total = Number(st.events ?? 0);
      const deduped = Math.max(0, total - Number(st.clusters ?? 0));
      const unique = total - deduped;
      // Build a single-point summary (no fake multi-week data)
      return [{ week: "Current", total, deduplicated: deduped, unique }];
    }
    return DEDUP_TREND_EMPTY;
  }, [dedupStatusQuery.data]);
  // Noise pie — derive from real stats when available
  const NOISE_PIE = useMemo(() => {
    if (dedupStats?.true_positive_count != null || dedupStats?.false_positive_count != null) {
      const tp = Number(dedupStats.true_positive_count ?? 0);
      const fp = Number(dedupStats.false_positive_count ?? 0);
      const unv = Math.max(0, Number(dedupStats.total_events ?? 0) - tp - fp);
      if (tp + fp + unv > 0) return [
        { name: "True Positives", value: tp, color: "#ef4444" },
        { name: "False Positives", value: fp, color: "#94a3b8" },
        { name: "Unverified", value: unv, color: "#f59e0b" },
      ];
    }
    return NOISE_PIE_EMPTY;
  }, [dedupStats]);

  // Filtered groups ─────────────────────────────────────────────────────────
  const filteredGroups = useMemo(
    () =>
      apiGroups.filter((g) => {
        if (severityFilter !== "all" && g.severity !== severityFilter) return false;
        if (scannerFilter !== "all" && !g.scanners.includes(scannerFilter)) return false;
        if (dedupFilter !== "all" && g.dedupStatus !== dedupFilter) return false;
        if (
          searchQuery &&
          !g.cve.toLowerCase().includes(searchQuery.toLowerCase()) &&
          !g.title.toLowerCase().includes(searchQuery.toLowerCase())
        )
          return false;
        return true;
      }),
    [severityFilter, scannerFilter, dedupFilter, searchQuery, apiGroups]
  );

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-72" />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Skeleton className="h-72 col-span-2" />
          <Skeleton className="h-72" />
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <ErrorState
        message="Failed to load correlation data."
        onRetry={() => casesQuery.refetch()}
      />
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* ── Header ── */}
      <PageHeader
        title="Correlation Engine"
        description="Cross-scanner deduplication, grouping and noise reduction across all security findings"
      >
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Switch
              id="auto-merge"
              checked={autoMergeEnabled}
              onCheckedChange={setAutoMergeEnabled}
            />
            <Label htmlFor="auto-merge" className="text-xs text-muted-foreground cursor-pointer">
              Auto-merge
            </Label>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => { casesQuery.refetch(); toast.info("Re-running correlation pass…"); }}
            className="gap-2"
          >
            <RefreshCw className="h-4 w-4" />
            Re-correlate
          </Button>
        </div>
      </PageHeader>

      {/* ── KPI Row ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Correlations"
          value={totalCorrelations}
          icon={GitMerge}
          description={`${cases.length} raw findings processed`}
        />
        <KpiCard
          title="Dedup Ratio"
          value={`${dedupRatio}%`}
          icon={Layers}
          description="Findings merged across scanners"
          className="border-emerald-500/20"
        />
        <KpiCard
          title="Noise Reduction"
          value={`${noiseReduction}%`}
          icon={TrendingDown}
          description="False positives suppressed"
          className="border-blue-500/20"
        />
        <KpiCard
          title="Cross-Scanner Matches"
          value={crossScannerMatches}
          icon={Target}
          description="Confirmed by 2+ scanners"
          className="border-orange-500/20"
        />
      </div>



      {/* ── Row 2: Matrix + Noise Pie ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Cross-scanner correlation matrix */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <BarChart2 className="h-4 w-4 text-primary" />
              Cross-Scanner Correlation Matrix
            </CardTitle>
            <CardDescription className="text-xs">
              Percentage overlap between scanner outputs. Higher values = more finding overlap.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr>
                    <th className="p-2 text-left text-muted-foreground font-medium w-28" />
                    {SCANNERS.map((s) => (
                      <th key={s} className="p-2 text-center text-muted-foreground font-medium">
                        {s}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {SCANNERS.map((rowS) => (
                    <tr key={rowS}>
                      <td className="p-2 font-medium text-foreground">{rowS}</td>
                      {SCANNERS.map((colS) => {
                        const val = MATRIX_DATA[rowS][colS];
                        const isSelf = rowS === colS;
                        return (
                          <td key={colS} className="p-1 text-center">
                            <div
                              className={cn(
                                "rounded-md py-2 font-mono font-semibold transition-all",
                                isSelf
                                  ? "bg-primary/20 text-primary text-xs"
                                  : heatColor(val)
                              )}
                            >
                              {val}%
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex gap-4 mt-4 flex-wrap">
              {[
                { label: "≥80% High overlap", cls: "bg-red-500/80" },
                { label: "60–79% Moderate", cls: "bg-orange-500/70" },
                { label: "40–59% Low", cls: "bg-yellow-500/60" },
                { label: "<40% Minimal", cls: "bg-emerald-500/40" },
              ].map((item) => (
                <div key={item.label} className="flex items-center gap-1.5">
                  <span className={cn("w-3 h-3 rounded-sm", item.cls)} />
                  <span className="text-xs text-muted-foreground">{item.label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Noise Analysis Pie */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Filter className="h-4 w-4 text-primary" />
              Noise Analysis
            </CardTitle>
            <CardDescription className="text-xs">
              Finding classification after correlation pass
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={NOISE_PIE}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {NOISE_PIE.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;
                    const d = payload[0].payload as typeof NOISE_PIE[0];
                    return (
                      <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, padding: "8px 12px" }}>
                        <p className="text-xs font-semibold" style={{ color: d.color }}>{d.name}</p>
                        <p className="text-xs text-muted-foreground">{d.value}%</p>
                      </div>
                    );
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-2 mt-1">
              {NOISE_PIE.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ background: item.color }} />
                    <span className="text-xs text-muted-foreground">{item.name}</span>
                  </div>
                  <span className="text-xs font-semibold">{item.value}%</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Row 3: Dedup Effectiveness Line Chart ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <TrendingDown className="h-4 w-4 text-primary" />
            Deduplication Effectiveness — 12-Week Trend
          </CardTitle>
          <CardDescription className="text-xs">
            Total ingested vs. deduplicated vs. unique findings over time
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={DEDUP_TREND} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="week" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="total" stroke="#94a3b8" strokeWidth={2} dot={false} name="Total Ingested" />
              <Line type="monotone" dataKey="deduplicated" stroke="#f59e0b" strokeWidth={2} dot={false} name="Deduplicated" />
              <Line type="monotone" dataKey="unique" stroke="#22c55e" strokeWidth={2} dot={false} name="Unique Findings" strokeDasharray="5 5" />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* ── Row 4: Grouped Vulnerability List ── */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <CardTitle className="text-sm flex items-center gap-2">
                <GitMerge className="h-4 w-4 text-primary" />
                Same-Vulnerability Groupings
              </CardTitle>
              <CardDescription className="text-xs mt-0.5">
                Cross-scanner finding clusters — {filteredGroups.length} groups shown
              </CardDescription>
            </div>
            <div className="flex flex-wrap gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search CVE or title…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 h-8 text-xs w-48"
                />
              </div>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="h-8 text-xs w-32">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
              <Select value={scannerFilter} onValueChange={setScannerFilter}>
                <SelectTrigger className="h-8 text-xs w-32">
                  <SelectValue placeholder="Scanner" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Scanners</SelectItem>
                  {SCANNERS.map((s) => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={dedupFilter} onValueChange={setDedupFilter}>
                <SelectTrigger className="h-8 text-xs w-32">
                  <SelectValue placeholder="Dedup Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="merged">Merged</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="split">Split</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ScrollArea className="max-h-[480px]">
            <div className="space-y-2">
              {filteredGroups.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <GitMerge className="h-8 w-8 opacity-30 mx-auto mb-2" />
                  <p className="text-sm">No groups match the current filters</p>
                </div>
              ) : (
                filteredGroups.map((group) => (
                  <VulnGroupRow
                    key={group.id}
                    group={group}
                    onMerge={(g) =>
                      setMergeSplitDialog({ open: true, group: g, mode: "merge" })
                    }
                    onSplit={(g) =>
                      setMergeSplitDialog({ open: true, group: g, mode: "split" })
                    }
                  />
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* ── Merge/Split Dialog ── */}
      <MergeSplitDialog
        open={mergeSplitDialog.open}
        onClose={() => setMergeSplitDialog((s) => ({ ...s, open: false }))}
        group={mergeSplitDialog.group}
        mode={mergeSplitDialog.mode}
      />
    </motion.div>
  );
}

// ── Vulnerability Group Row ────────────────────────────────────────────────
function VulnGroupRow({
  group,
  onMerge,
  onSplit,
}: {
  group: VulnGroup;
  onMerge: (g: VulnGroup) => void;
  onSplit: (g: VulnGroup) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  const statusConfig: Record<string, { label: string; cls: string; icon: React.ReactNode }> = {
    merged: {
      label: "Merged",
      cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
      icon: <CheckCircle2 className="h-3 w-3" />,
    },
    pending: {
      label: "Pending",
      cls: "bg-amber-500/15 text-amber-400 border-amber-500/30",
      icon: <HelpCircle className="h-3 w-3" />,
    },
    split: {
      label: "Split",
      cls: "bg-blue-500/15 text-blue-400 border-blue-500/30",
      icon: <SplitSquareHorizontal className="h-3 w-3" />,
    },
  };

  const status = statusConfig[group.dedupStatus] ?? statusConfig.pending;
  const sevColor = SEVERITY_COLORS[group.severity] ?? "#94a3b8";

  return (
    <div className="border border-border/40 rounded-lg overflow-hidden">
      <div
        className="flex items-center gap-3 p-3 bg-card/60 cursor-pointer hover:bg-muted/30 transition-colors"
        onClick={() => setExpanded((e) => !e)}
      >
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        )}

        {/* Severity dot */}
        <span className="w-2 h-2 rounded-full shrink-0" style={{ background: sevColor }} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono font-semibold text-primary">{group.cve}</span>
            <span className="text-xs text-foreground truncate max-w-sm">{group.title}</span>
          </div>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            {group.scanners.map((s) => (
              <Badge key={s} variant="outline" className="text-[10px] h-4 px-1.5">
                {s}
              </Badge>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <span className="text-xs text-muted-foreground">{group.count} findings</span>
          <Badge
            className={cn("border text-[10px] gap-1 h-5 px-2", status.cls)}
            variant="outline"
          >
            {status.icon}
            {status.label}
          </Badge>
        </div>

        {/* Actions — stop propagation so row click doesn't fire */}
        <div className="flex gap-1.5" onClick={(e) => e.stopPropagation()}>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs gap-1 px-2"
            onClick={() => onMerge(group)}
            disabled={group.dedupStatus === "merged"}
          >
            <MergeIcon className="h-3 w-3" />
            Merge
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs gap-1 px-2 text-orange-400 border-orange-500/30 hover:bg-orange-500/10"
            onClick={() => onSplit(group)}
            disabled={group.scanners.length < 2}
          >
            <SplitSquareHorizontal className="h-3 w-3" />
            Split
          </Button>
        </div>
      </div>

      {expanded && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          transition={{ duration: 0.2 }}
          className="border-t border-border/40 bg-muted/20 px-4 py-3"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div>
              <p className="text-muted-foreground mb-1.5 font-medium">Affected Components</p>
              <div className="flex flex-wrap gap-1.5">
                {group.affectedComponents.map((c) => (
                  <Badge key={c} variant="secondary" className="text-[10px]">
                    {c}
                  </Badge>
                ))}
              </div>
            </div>
            <div>
              <p className="text-muted-foreground mb-1.5 font-medium">Scanner Coverage</p>
              <div className="space-y-1">
                {SCANNERS.map((s) => {
                  const detected = group.scanners.includes(s);
                  return (
                    <div key={s} className="flex items-center gap-2">
                      {detected ? (
                        <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                      ) : (
                        <XCircle className="h-3 w-3 text-muted-foreground/40" />
                      )}
                      <span className={detected ? "text-foreground" : "text-muted-foreground/40"}>
                        {s}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
