import { toArray } from "@/lib/api-utils";
import { useState, useMemo } from "react";
import { motion } from "framer-motion";
import {
  Database,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Activity,
  GitBranch,
  Layers,
  ChevronRight,
  ChevronDown,
  Search,
  Download,
  Clock,
  Zap,
  BarChart2,
  ArrowLeftRight,
  FileJson,
  Shield,
  Cloud,
  Code,
  Package,
  Server,
  Filter,
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
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useFindings, useDashboardOverview, useIntegrations } from "@/hooks/use-api";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from "recharts";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

// ── Data source definitions ────────────────────────────────────────────────
interface DataSource {
  id: string;
  name: string;
  type: "scanner" | "cloud" | "siem" | "ticketing" | "registry";
  status: "healthy" | "degraded" | "offline";
  eventsIngested: number;
  lastSync: string;
  schemaVersion: string;
  icon: React.ElementType;
  latencyMs: number;
  qualityScore: number;
  recordsTotal: number;
}

const DATA_SOURCES: DataSource[] = [
  {
    id: "ds-001",
    name: "Snyk",
    type: "scanner",
    status: "healthy",
    eventsIngested: 48320,
    lastSync: "2 min ago",
    schemaVersion: "v2.4",
    icon: Shield,
    latencyMs: 142,
    qualityScore: 96,
    recordsTotal: 124800,
  },
  {
    id: "ds-002",
    name: "Trivy",
    type: "scanner",
    status: "healthy",
    eventsIngested: 31740,
    lastSync: "5 min ago",
    schemaVersion: "v1.9",
    icon: Package,
    latencyMs: 88,
    qualityScore: 94,
    recordsTotal: 87400,
  },
  {
    id: "ds-003",
    name: "AWS Security Hub",
    type: "cloud",
    status: "degraded",
    eventsIngested: 19200,
    lastSync: "18 min ago",
    schemaVersion: "v3.1",
    icon: Cloud,
    latencyMs: 640,
    qualityScore: 71,
    recordsTotal: 55300,
  },
  {
    id: "ds-004",
    name: "Semgrep",
    type: "scanner",
    status: "healthy",
    eventsIngested: 27560,
    lastSync: "3 min ago",
    schemaVersion: "v2.0",
    icon: Code,
    latencyMs: 210,
    qualityScore: 92,
    recordsTotal: 63200,
  },
  {
    id: "ds-005",
    name: "Splunk SIEM",
    type: "siem",
    status: "healthy",
    eventsIngested: 142000,
    lastSync: "1 min ago",
    schemaVersion: "v4.2",
    icon: Activity,
    latencyMs: 55,
    qualityScore: 98,
    recordsTotal: 1240000,
  },
  {
    id: "ds-006",
    name: "SonarQube",
    type: "scanner",
    status: "offline",
    eventsIngested: 0,
    lastSync: "3 h ago",
    schemaVersion: "v2.2",
    icon: Server,
    latencyMs: 0,
    qualityScore: 0,
    recordsTotal: 44100,
  },
  {
    id: "ds-007",
    name: "GitHub Advanced Security",
    type: "scanner",
    status: "healthy",
    eventsIngested: 18900,
    lastSync: "4 min ago",
    schemaVersion: "v1.6",
    icon: GitBranch,
    latencyMs: 175,
    qualityScore: 89,
    recordsTotal: 39800,
  },
  {
    id: "ds-008",
    name: "GCP Security Command",
    type: "cloud",
    status: "healthy",
    eventsIngested: 9400,
    lastSync: "7 min ago",
    schemaVersion: "v2.8",
    icon: Cloud,
    latencyMs: 320,
    qualityScore: 85,
    recordsTotal: 28600,
  },
];

// ── Finding correlation timeline (24h, hourly) ─────────────────────────────
const CORRELATION_TIMELINE = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2, "0")}:00`,
  ingested: 1200 + Math.round(Math.random() * 3000),
  correlated: 800 + Math.round(Math.random() * 2000),
  deduplicated: 400 + Math.round(Math.random() * 900),
}));

// ── Source comparison radar data ───────────────────────────────────────────
const SOURCE_RADAR = [
  { metric: "Coverage", Snyk: 88, Trivy: 79, Semgrep: 91, SonarQube: 74 },
  { metric: "Accuracy", Snyk: 94, Trivy: 82, Semgrep: 87, SonarQube: 90 },
  { metric: "Latency", Snyk: 78, Trivy: 95, Semgrep: 72, SonarQube: 65 },
  { metric: "Freshness", Snyk: 91, Trivy: 88, Semgrep: 84, SonarQube: 42 },
  { metric: "Schema Fit", Snyk: 96, Trivy: 93, Semgrep: 89, SonarQube: 88 },
];

// ── Unified data model tree nodes ─────────────────────────────────────────
interface ModelNode {
  id: string;
  label: string;
  type: "root" | "entity" | "field";
  children?: ModelNode[];
  dataType?: string;
  sources?: string[];
}

const DATA_MODEL_TREE: ModelNode[] = [
  {
    id: "finding",
    label: "Finding",
    type: "root",
    children: [
      {
        id: "finding.id",
        label: "id",
        type: "field",
        dataType: "UUID",
        sources: ["Snyk", "Trivy", "Semgrep", "SonarQube"],
      },
      {
        id: "finding.cve",
        label: "cve_id",
        type: "field",
        dataType: "String",
        sources: ["Snyk", "Trivy"],
      },
      {
        id: "finding.severity",
        label: "severity",
        type: "field",
        dataType: "Enum",
        sources: ["Snyk", "Trivy", "Semgrep", "SonarQube"],
      },
      {
        id: "finding.component",
        label: "component",
        type: "entity",
        sources: ["Snyk", "Trivy", "Semgrep"],
        children: [
          { id: "finding.component.name", label: "name", type: "field", dataType: "String", sources: ["Snyk"] },
          { id: "finding.component.version", label: "version", type: "field", dataType: "String", sources: ["Snyk", "Trivy"] },
          { id: "finding.component.purl", label: "purl", type: "field", dataType: "URI", sources: ["Snyk", "Trivy"] },
        ],
      },
      {
        id: "finding.evidence",
        label: "evidence",
        type: "entity",
        sources: ["Semgrep", "SonarQube"],
        children: [
          { id: "finding.evidence.file", label: "file_path", type: "field", dataType: "String", sources: ["Semgrep", "SonarQube"] },
          { id: "finding.evidence.line", label: "line_number", type: "field", dataType: "Int", sources: ["Semgrep", "SonarQube"] },
          { id: "finding.evidence.snippet", label: "code_snippet", type: "field", dataType: "Text", sources: ["Semgrep"] },
        ],
      },
    ],
  },
  {
    id: "asset",
    label: "Asset",
    type: "root",
    children: [
      { id: "asset.id", label: "id", type: "field", dataType: "UUID", sources: ["All"] },
      { id: "asset.type", label: "asset_type", type: "field", dataType: "Enum", sources: ["All"] },
      { id: "asset.owner", label: "owner_team", type: "field", dataType: "String", sources: ["Snyk", "Splunk SIEM"] },
      { id: "asset.risk_score", label: "risk_score", type: "field", dataType: "Float", sources: ["Snyk", "AWS Security Hub"] },
    ],
  },
];

// ── Data quality metrics bar data ─────────────────────────────────────────
const QUALITY_METRICS = DATA_SOURCES.filter((s) => s.qualityScore > 0).map((s) => ({
  name: s.name.split(" ")[0],
  score: s.qualityScore,
  latency: s.latencyMs,
}));

// ── Status colour helpers ──────────────────────────────────────────────────
const statusConfig = {
  healthy: {
    label: "Healthy",
    cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    dot: "bg-emerald-400",
    icon: CheckCircle2,
  },
  degraded: {
    label: "Degraded",
    cls: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    dot: "bg-amber-400",
    icon: AlertTriangle,
  },
  offline: {
    label: "Offline",
    cls: "bg-red-500/15 text-red-400 border-red-500/30",
    dot: "bg-red-400",
    icon: XCircle,
  },
} as const;

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
          <span className="font-semibold text-foreground">{p.value.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
};

// ── Tree node renderer ─────────────────────────────────────────────────────
function ModelTreeNode({ node, depth = 0 }: { node: ModelNode; depth?: number }) {
  const [expanded, setExpanded] = useState(depth === 0);
  const hasChildren = node.children && node.children.length > 0;

  const typeColor: Record<string, string> = {
    root: "text-primary",
    entity: "text-blue-400",
    field: "text-slate-400",
  };

  return (
    <div>
      <div
        className={cn(
          "flex items-center gap-2 py-1 px-2 rounded-md transition-colors text-xs",
          hasChildren ? "cursor-pointer hover:bg-muted/40" : "",
          depth === 0 ? "font-semibold" : ""
        )}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onClick={() => hasChildren && setExpanded((e) => !e)}
      >
        {hasChildren ? (
          expanded ? (
            <ChevronDown className="h-3 w-3 text-muted-foreground shrink-0" />
          ) : (
            <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
          )
        ) : (
          <span className="w-3 h-3 shrink-0" />
        )}

        {node.type === "root" && <Database className="h-3.5 w-3.5 text-primary shrink-0" />}
        {node.type === "entity" && <Layers className="h-3.5 w-3.5 text-blue-400 shrink-0" />}
        {node.type === "field" && <FileJson className="h-3 w-3 text-slate-400 shrink-0" />}

        <span className={cn("flex-1", typeColor[node.type])}>{node.label}</span>

        {node.dataType && (
          <span className="text-[10px] text-muted-foreground font-mono bg-muted/40 px-1.5 py-0.5 rounded">
            {node.dataType}
          </span>
        )}

        {node.sources && (
          <div className="flex gap-1">
            {node.sources.slice(0, 3).map((s) => (
              <span
                key={s}
                className="text-[9px] bg-primary/10 text-primary px-1 py-0.5 rounded-sm"
              >
                {s === "All" ? "All" : s.split(" ")[0]}
              </span>
            ))}
            {node.sources.length > 3 && (
              <span className="text-[9px] text-muted-foreground">+{node.sources.length - 3}</span>
            )}
          </div>
        )}
      </div>

      {expanded && hasChildren && (
        <div>
          {node.children!.map((child) => (
            <ModelTreeNode key={child.id} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────
export default function DataFabric() {
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const casesQuery = useFindings({ limit: 10 });
  const overviewQuery = useDashboardOverview();
  const integrationsQuery = useIntegrations();

  const isLoading = casesQuery.isLoading || overviewQuery.isLoading;
  const isError = casesQuery.isError;

  // Derived KPIs ─────────────────────────────────────────────────────────────
  const totalSources = DATA_SOURCES.length;
  const healthySources = DATA_SOURCES.filter((s) => s.status === "healthy").length;
  const totalEventsIngested = useMemo(
    () => DATA_SOURCES.reduce((a, s) => a + s.eventsIngested, 0),
    []
  );
  const avgQualityScore = useMemo(() => {
    const active = DATA_SOURCES.filter((s) => s.qualityScore > 0);
    return Math.round(active.reduce((a, s) => a + s.qualityScore, 0) / active.length);
  }, []);

  const correlationMatches = useMemo(() => {
    const raw = toArray(casesQuery.data);
    const arr = Array.isArray(raw) ? raw : [];
    return arr.length;
  }, [casesQuery.data]);

  // Filtered sources ─────────────────────────────────────────────────────────
  const filteredSources = useMemo(
    () =>
      DATA_SOURCES.filter((s) => {
        if (typeFilter !== "all" && s.type !== typeFilter) return false;
        if (statusFilter !== "all" && s.status !== statusFilter) return false;
        if (searchQuery && !s.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
        return true;
      }),
    [typeFilter, statusFilter, searchQuery]
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
          <Skeleton className="h-64 lg:col-span-2" />
          <Skeleton className="h-64" />
        </div>
        <Skeleton className="h-48" />
      </div>
    );
  }

  if (isError) {
    return (
      <ErrorState
        message="Failed to load data fabric status."
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
        title="Data Fabric"
        description="Unified ingestion layer — normalise, correlate and quality-score all security data sources"
      >
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={() => toast.info("Exporting data fabric report…")}
          >
            <Download className="h-4 w-4" />
            Export Report
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              casesQuery.refetch();
              overviewQuery.refetch();
              integrationsQuery.refetch();
              toast.info("Refreshing all data sources…");
            }}
            className="gap-2"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </PageHeader>

      {/* ── KPI Row ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Data Sources"
          value={`${healthySources}/${totalSources}`}
          icon={Database}
          description={`${totalSources - healthySources} degraded or offline`}
        />
        <KpiCard
          title="Events Ingested (24h)"
          value={totalEventsIngested.toLocaleString()}
          icon={Activity}
          description="Across all active connectors"
          className="border-blue-500/20"
        />
        <KpiCard
          title="Correlation Matches"
          value={correlationMatches.toLocaleString()}
          icon={ArrowLeftRight}
          description="Cross-source entity links"
          className="border-purple-500/20"
        />
        <KpiCard
          title="Data Quality Score"
          value={`${avgQualityScore}%`}
          icon={Zap}
          description="Weighted average across sources"
          className={cn(
            avgQualityScore >= 90
              ? "border-emerald-500/20"
              : avgQualityScore >= 70
              ? "border-amber-500/20"
              : "border-red-500/20"
          )}
        />
      </div>

      {/* ── Row 2: Timeline + Radar ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Finding correlation timeline */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              Finding Correlation Timeline — 24h
            </CardTitle>
            <CardDescription className="text-xs">
              Ingested vs correlated vs deduplicated events per hour
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={CORRELATION_TIMELINE} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradIngested" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradCorrelated" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradDeduped" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="hour"
                  tick={{ fontSize: 10, fill: "#94a3b8" }}
                  axisLine={false}
                  tickLine={false}
                  interval={3}
                />
                <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <Tooltip content={<ChartTooltip />} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area
                  type="monotone"
                  dataKey="ingested"
                  stroke="#6366f1"
                  strokeWidth={2}
                  fill="url(#gradIngested)"
                  name="Ingested"
                />
                <Area
                  type="monotone"
                  dataKey="correlated"
                  stroke="#22c55e"
                  strokeWidth={2}
                  fill="url(#gradCorrelated)"
                  name="Correlated"
                />
                <Area
                  type="monotone"
                  dataKey="deduplicated"
                  stroke="#f59e0b"
                  strokeWidth={2}
                  fill="url(#gradDeduped)"
                  name="Deduplicated"
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Source comparison radar */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <BarChart2 className="h-4 w-4 text-primary" />
              Source Comparison
            </CardTitle>
            <CardDescription className="text-xs">
              Multi-dimensional quality assessment
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={230}>
              <RadarChart data={SOURCE_RADAR}>
                <PolarGrid stroke="#1e293b" />
                <PolarAngleAxis dataKey="metric" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                <PolarRadiusAxis angle={90} domain={[0, 100]} tick={false} axisLine={false} />
                <Radar name="Snyk" dataKey="Snyk" stroke="#ef4444" fill="#ef4444" fillOpacity={0.15} />
                <Radar name="Trivy" dataKey="Trivy" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.15} />
                <Radar name="Semgrep" dataKey="Semgrep" stroke="#22c55e" fill="#22c55e" fillOpacity={0.15} />
                <Legend wrapperStyle={{ fontSize: 10 }} />
              </RadarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* ── Row 3: Data Quality Bar ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Zap className="h-4 w-4 text-primary" />
            Data Quality Metrics by Source
          </CardTitle>
          <CardDescription className="text-xs">
            Quality score (0–100) and ingestion latency (ms) per active data source
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={QUALITY_METRICS} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis yAxisId="score" domain={[0, 100]} tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis yAxisId="latency" orientation="right" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar yAxisId="score" dataKey="score" fill="#6366f1" name="Quality Score" radius={[4, 4, 0, 0]} />
              <Bar yAxisId="latency" dataKey="latency" fill="#f59e0b" name="Latency (ms)" radius={[4, 4, 0, 0]} opacity={0.7} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* ── Row 4: Data Source Status Grid + Unified Model Tree ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Data Source Status Grid */}
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Database className="h-4 w-4 text-primary" />
                    Data Source Status
                  </CardTitle>
                  <CardDescription className="text-xs mt-0.5">
                    {filteredSources.length} of {DATA_SOURCES.length} sources shown
                  </CardDescription>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input
                      placeholder="Search source…"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-8 h-8 text-xs w-40"
                    />
                  </div>
                  <Select value={typeFilter} onValueChange={setTypeFilter}>
                    <SelectTrigger className="h-8 text-xs w-32">
                      <SelectValue placeholder="Type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Types</SelectItem>
                      <SelectItem value="scanner">Scanner</SelectItem>
                      <SelectItem value="cloud">Cloud</SelectItem>
                      <SelectItem value="siem">SIEM</SelectItem>
                      <SelectItem value="ticketing">Ticketing</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={statusFilter} onValueChange={setStatusFilter}>
                    <SelectTrigger className="h-8 text-xs w-32">
                      <SelectValue placeholder="Status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Statuses</SelectItem>
                      <SelectItem value="healthy">Healthy</SelectItem>
                      <SelectItem value="degraded">Degraded</SelectItem>
                      <SelectItem value="offline">Offline</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <ScrollArea className="max-h-[420px]">
                <div className="space-y-2">
                  {filteredSources.length === 0 ? (
                    <div className="text-center py-10 text-muted-foreground">
                      <Database className="h-8 w-8 opacity-30 mx-auto mb-2" />
                      <p className="text-sm">No sources match filters</p>
                    </div>
                  ) : (
                    filteredSources.map((source) => {
                      const cfg = statusConfig[source.status];
                      const Icon = source.icon;
                      return (
                        <div
                          key={source.id}
                          className="flex items-center gap-3 p-3 rounded-lg border border-border/40 bg-card/60 hover:bg-muted/20 transition-colors"
                        >
                          {/* Icon */}
                          <div className="w-8 h-8 rounded-md bg-muted/40 flex items-center justify-center shrink-0">
                            <Icon className="h-4 w-4 text-muted-foreground" />
                          </div>

                          {/* Info */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{source.name}</span>
                              <Badge variant="outline" className="text-[10px] h-4 px-1.5 capitalize">
                                {source.type}
                              </Badge>
                              <Badge
                                className={cn("border text-[10px] h-4 px-1.5 gap-1", cfg.cls)}
                                variant="outline"
                              >
                                <span className={cn("w-1.5 h-1.5 rounded-full", cfg.dot)} />
                                {cfg.label}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-4 mt-1.5">
                              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                <Clock className="h-3 w-3" />
                                {source.lastSync}
                              </div>
                              <div className="text-xs text-muted-foreground font-mono">
                                {source.schemaVersion}
                              </div>
                              {source.status !== "offline" && (
                                <div className="text-xs text-muted-foreground">
                                  {source.latencyMs}ms
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Quality score */}
                          <div className="shrink-0 w-28 space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-muted-foreground">Quality</span>
                              <span
                                className={cn(
                                  "text-xs font-semibold",
                                  source.qualityScore >= 90
                                    ? "text-emerald-400"
                                    : source.qualityScore >= 70
                                    ? "text-amber-400"
                                    : "text-red-400"
                                )}
                              >
                                {source.qualityScore > 0 ? `${source.qualityScore}%` : "—"}
                              </span>
                            </div>
                            <Progress
                              value={source.qualityScore}
                              className="h-1"
                            />
                          </div>

                          {/* Events */}
                          <div className="shrink-0 text-right">
                            <p className="text-xs font-semibold font-mono">
                              {source.eventsIngested > 0
                                ? source.eventsIngested.toLocaleString()
                                : "—"}
                            </p>
                            <p className="text-[10px] text-muted-foreground">events/24h</p>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>

        {/* Unified Data Model Tree */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-primary" />
              Unified Data Model
            </CardTitle>
            <CardDescription className="text-xs">
              Canonical schema — field sources and types
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[420px]">
              <div className="space-y-1">
                {DATA_MODEL_TREE.map((node) => (
                  <ModelTreeNode key={node.id} node={node} depth={0} />
                ))}
              </div>
            </ScrollArea>
            <Separator className="my-3" />
            <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
              <div className="flex items-center gap-1.5">
                <Database className="h-3 w-3 text-primary" />
                Root entity
              </div>
              <div className="flex items-center gap-1.5">
                <Layers className="h-3 w-3 text-blue-400" />
                Sub-entity
              </div>
              <div className="flex items-center gap-1.5">
                <FileJson className="h-3 w-3 text-slate-400" />
                Field
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Row 5: Source Comparison Table ── */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <ArrowLeftRight className="h-4 w-4 text-primary" />
            Source Comparison Table
          </CardTitle>
          <CardDescription className="text-xs">
            Side-by-side key metrics across all data sources
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/40">
                  {["Source", "Type", "Status", "Events (24h)", "Records Total", "Latency", "Schema", "Quality"].map(
                    (h) => (
                      <th
                        key={h}
                        className="text-left text-muted-foreground font-medium px-3 py-2 whitespace-nowrap"
                      >
                        {h}
                      </th>
                    )
                  )}
                </tr>
              </thead>
              <tbody>
                {DATA_SOURCES.map((source, i) => {
                  const cfg = statusConfig[source.status];
                  const Icon = source.icon;
                  return (
                    <tr
                      key={source.id}
                      className={cn(
                        "border-b border-border/20 hover:bg-muted/20 transition-colors",
                        i % 2 === 0 ? "bg-transparent" : "bg-muted/5"
                      )}
                    >
                      <td className="px-3 py-2.5">
                        <div className="flex items-center gap-2">
                          <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                          <span className="font-medium whitespace-nowrap">{source.name}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5">
                        <Badge variant="outline" className="text-[10px] h-4 px-1.5 capitalize whitespace-nowrap">
                          {source.type}
                        </Badge>
                      </td>
                      <td className="px-3 py-2.5">
                        <Badge
                          className={cn("border text-[10px] h-4 px-1.5 gap-1 whitespace-nowrap", cfg.cls)}
                          variant="outline"
                        >
                          <span className={cn("w-1.5 h-1.5 rounded-full", cfg.dot)} />
                          {cfg.label}
                        </Badge>
                      </td>
                      <td className="px-3 py-2.5 font-mono">
                        {source.eventsIngested > 0 ? source.eventsIngested.toLocaleString() : "—"}
                      </td>
                      <td className="px-3 py-2.5 font-mono">
                        {source.recordsTotal.toLocaleString()}
                      </td>
                      <td className="px-3 py-2.5 font-mono">
                        {source.latencyMs > 0 ? `${source.latencyMs}ms` : "—"}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-muted-foreground">
                        {source.schemaVersion}
                      </td>
                      <td className="px-3 py-2.5">
                        <div className="flex items-center gap-2">
                          <Progress value={source.qualityScore} className="w-16 h-1.5" />
                          <span
                            className={cn(
                              "font-semibold whitespace-nowrap",
                              source.qualityScore >= 90
                                ? "text-emerald-400"
                                : source.qualityScore >= 70
                                ? "text-amber-400"
                                : source.qualityScore > 0
                                ? "text-red-400"
                                : "text-muted-foreground"
                            )}
                          >
                            {source.qualityScore > 0 ? `${source.qualityScore}%` : "—"}
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
