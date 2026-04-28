/**
 * Attack Surface Management Page
 *
 * Designed for security engineers mapping exposure breadth and blast radius.
 * Information-dense, dark-first, terminal-noir aesthetic.
 * Asset inventory + exposure path chains + recent change feed.
 *
 * Route: /attack-surface
 */

import { useState, useMemo, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Globe,
  Server,
  Cloud,
  Container,
  Code,
  Database,
  Shield,
  ShieldAlert,
  AlertTriangle,
  ChevronRight,
  ArrowRight,
  Search,
  Filter,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Minus,
  Clock,
  GitCommit,
  Zap,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Network,
  Loader2,
  type LucideIcon,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type AssetType = "host" | "cloud" | "container" | "api" | "repo" | "database";
type ExposureLevel = "internet" | "internal" | "isolated";
type RiskTier = "critical" | "high" | "medium" | "low";

interface Asset {
  id: string;
  name: string;
  type: AssetType;
  exposure: ExposureLevel;
  riskScore: number;
  riskTier: RiskTier;
  openPorts?: number[];
  cveCount: number;
  lastSeen: Date;
  owner: string;
  tags: string[];
  cloudProvider?: string;
}

interface ExposurePath {
  id: string;
  title: string;
  severity: RiskTier;
  chain: string[];
  technique: string;
  likelihood: number;
  impact: number;
  discovered: Date;
}

interface RecentChange {
  id: string;
  asset: string;
  changeType: "added" | "removed" | "modified" | "risk-change";
  detail: string;
  timestamp: Date;
  riskDelta?: number;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const now = new Date();
const minsAgo = (m: number) => new Date(now.getTime() - m * 60_000);
const hoursAgo = (h: number) => new Date(now.getTime() - h * 3_600_000);
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000);

const MOCK_ASSETS: Asset[] = [
  {
    id: "AST-001",
    name: "api-gateway-prod.aldeci.io",
    type: "host",
    exposure: "internet",
    riskScore: 94,
    riskTier: "critical",
    openPorts: [443, 80, 8443],
    cveCount: 7,
    lastSeen: minsAgo(3),
    owner: "platform-team",
    tags: ["production", "ingress", "tls-termination"],
  },
  {
    id: "AST-002",
    name: "s3://aldeci-prod-exports",
    type: "cloud",
    exposure: "internet",
    riskScore: 88,
    riskTier: "critical",
    cveCount: 0,
    lastSeen: minsAgo(12),
    owner: "data-team",
    cloudProvider: "AWS",
    tags: ["s3", "public-acl", "pii"],
  },
  {
    id: "AST-003",
    name: "aldeci-api:v2.3.1",
    type: "container",
    exposure: "internal",
    riskScore: 91,
    riskTier: "critical",
    openPorts: [8000],
    cveCount: 3,
    lastSeen: minsAgo(5),
    owner: "platform-team",
    tags: ["docker", "xz-backdoor", "supply-chain"],
  },
  {
    id: "AST-004",
    name: "suite-api/routers/findings_router.py",
    type: "repo",
    exposure: "internal",
    riskScore: 82,
    riskTier: "high",
    cveCount: 2,
    lastSeen: minsAgo(47),
    owner: "backend-team",
    tags: ["sqli", "injection", "api"],
  },
  {
    id: "AST-005",
    name: "postgres-prod-01.internal",
    type: "database",
    exposure: "internal",
    riskScore: 76,
    riskTier: "high",
    openPorts: [5432],
    cveCount: 1,
    lastSeen: hoursAgo(1),
    owner: "dba-team",
    tags: ["postgresql", "sensitive-data"],
  },
  {
    id: "AST-006",
    name: "k8s-worker-node-07",
    type: "host",
    exposure: "internal",
    riskScore: 71,
    riskTier: "high",
    openPorts: [9100, 10250, 6443],
    cveCount: 4,
    lastSeen: minsAgo(20),
    owner: "infra-team",
    tags: ["kubernetes", "node-exporter", "kubelet"],
  },
  {
    id: "AST-007",
    name: "auth-service-staging.internal",
    type: "api",
    exposure: "internal",
    riskScore: 58,
    riskTier: "medium",
    openPorts: [8001],
    cveCount: 1,
    lastSeen: hoursAgo(2),
    owner: "auth-team",
    tags: ["oauth2", "jwt", "staging"],
  },
  {
    id: "AST-008",
    name: "redis-cache-01.internal",
    type: "database",
    exposure: "internal",
    riskScore: 44,
    riskTier: "medium",
    openPorts: [6379],
    cveCount: 0,
    lastSeen: hoursAgo(3),
    owner: "platform-team",
    tags: ["redis", "session-store"],
  },
  {
    id: "AST-009",
    name: "ecr.aws/aldeci/scanner:latest",
    type: "container",
    exposure: "isolated",
    riskScore: 38,
    riskTier: "medium",
    cveCount: 2,
    lastSeen: daysAgo(1),
    owner: "security-team",
    cloudProvider: "AWS",
    tags: ["ecr", "scanner", "batch"],
  },
  {
    id: "AST-010",
    name: "cdn-edge-cache.cloudfront.net",
    type: "cloud",
    exposure: "internet",
    riskScore: 22,
    riskTier: "low",
    cveCount: 0,
    lastSeen: minsAgo(8),
    owner: "platform-team",
    cloudProvider: "AWS",
    tags: ["cloudfront", "cdn", "static"],
  },
  {
    id: "AST-011",
    name: "suite-ui/aldeci-ui-new",
    type: "repo",
    exposure: "isolated",
    riskScore: 18,
    riskTier: "low",
    cveCount: 0,
    lastSeen: minsAgo(2),
    owner: "frontend-team",
    tags: ["react", "vite", "spa"],
  },
  {
    id: "AST-012",
    name: "vault.internal:8200",
    type: "api",
    exposure: "isolated",
    riskScore: 12,
    riskTier: "low",
    cveCount: 0,
    lastSeen: minsAgo(15),
    owner: "security-team",
    tags: ["vault", "secrets-manager", "hardened"],
  },
];

const MOCK_PATHS: ExposurePath[] = [
  {
    id: "PATH-001",
    title: "Internet → API Gateway → XZ Backdoor → RCE",
    severity: "critical",
    chain: ["Internet", "api-gateway-prod.aldeci.io:443", "aldeci-api:v2.3.1", "liblzma.so RCE"],
    technique: "T1190 — Exploit Public-Facing Application",
    likelihood: 92,
    impact: 98,
    discovered: minsAgo(8),
  },
  {
    id: "PATH-002",
    title: "SQLi → Findings API → Postgres Lateral Move",
    severity: "critical",
    chain: ["Auth'd HTTP Request", "findings_router.py (SQLi)", "postgres-prod-01.internal", "Full DB Dump"],
    technique: "T1190 + T1078 — Initial Access + Valid Accounts",
    likelihood: 85,
    impact: 94,
    discovered: minsAgo(47),
  },
  {
    id: "PATH-003",
    title: "Public S3 Exfil → PII Extraction",
    severity: "critical",
    chain: ["Anonymous HTTP", "s3://aldeci-prod-exports (AllUsers READ)", "CSV exports", "PII exfiltration"],
    technique: "T1530 — Data from Cloud Storage Object",
    likelihood: 99,
    impact: 82,
    discovered: hoursAgo(5),
  },
  {
    id: "PATH-004",
    title: "Kubelet API → Node Exec → Cluster Takeover",
    severity: "high",
    chain: ["k8s-worker-node-07:10250", "Unauthenticated Kubelet", "Pod exec", "Cluster admin escalation"],
    technique: "T1613 — Container and Resource Discovery",
    likelihood: 67,
    impact: 88,
    discovered: hoursAgo(2),
  },
  {
    id: "PATH-005",
    title: "Prometheus Metrics → Internal Topology Leak",
    severity: "high",
    chain: ["k8s-worker-node-07:9100", "Node Exporter (no auth)", "Internal hostnames + ports", "Recon mapping"],
    technique: "T1046 — Network Service Discovery",
    likelihood: 95,
    impact: 55,
    discovered: hoursAgo(2),
  },
  {
    id: "PATH-006",
    title: "Staging Auth → Token Forge → Prod Access",
    severity: "medium",
    chain: ["auth-service-staging.internal", "Weak JWT secret (staging)", "Token forging", "Production API access"],
    technique: "T1550.001 — Application Access Token",
    likelihood: 42,
    impact: 79,
    discovered: daysAgo(1),
  },
];

const MOCK_CHANGES: RecentChange[] = [
  {
    id: "CHG-001",
    asset: "aldeci-api:v2.3.1",
    changeType: "risk-change",
    detail: "XZ backdoor CVE-2024-3094 detected — risk score +41",
    timestamp: minsAgo(8),
    riskDelta: 41,
  },
  {
    id: "CHG-002",
    asset: "s3://aldeci-prod-exports",
    changeType: "modified",
    detail: "Bucket ACL changed to AllUsers READ",
    timestamp: hoursAgo(5),
    riskDelta: 28,
  },
  {
    id: "CHG-003",
    asset: "api-gateway-prod.aldeci.io",
    changeType: "added",
    detail: "Port 8443 opened — TLS offload endpoint exposed",
    timestamp: hoursAgo(6),
    riskDelta: 12,
  },
  {
    id: "CHG-004",
    asset: "k8s-worker-node-07",
    changeType: "added",
    detail: "Node exporter deployed without NetworkPolicy",
    timestamp: hoursAgo(8),
    riskDelta: 18,
  },
  {
    id: "CHG-005",
    asset: "vault.internal:8200",
    changeType: "modified",
    detail: "TLS certificate renewed — mTLS enforced",
    timestamp: daysAgo(1),
    riskDelta: -8,
  },
  {
    id: "CHG-006",
    asset: "cdn-edge-cache.cloudfront.net",
    changeType: "added",
    detail: "New distribution created for static assets",
    timestamp: daysAgo(1),
    riskDelta: 4,
  },
  {
    id: "CHG-007",
    asset: "redis-cache-01.internal",
    changeType: "modified",
    detail: "AUTH command enabled — anonymous access removed",
    timestamp: daysAgo(2),
    riskDelta: -15,
  },
];

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

const ASSET_TYPE_META: Record<AssetType, { icon: LucideIcon; label: string; color: string }> = {
  host:      { icon: Server,    label: "Host",      color: "text-sky-400" },
  cloud:     { icon: Cloud,     label: "Cloud",     color: "text-violet-400" },
  container: { icon: Container, label: "Container", color: "text-cyan-400" },
  api:       { icon: Network,   label: "API",       color: "text-amber-400" },
  repo:      { icon: Code,      label: "Repo",      color: "text-emerald-400" },
  database:  { icon: Database,  label: "Database",  color: "text-orange-400" },
};

const EXPOSURE_META: Record<ExposureLevel, { label: string; color: string; dot: string }> = {
  internet: { label: "Internet",  color: "text-rose-400",    dot: "bg-rose-400" },
  internal: { label: "Internal",  color: "text-amber-400",   dot: "bg-amber-400" },
  isolated: { label: "Isolated",  color: "text-emerald-400", dot: "bg-emerald-400" },
};

const RISK_META: Record<RiskTier, { color: string; bg: string; border: string }> = {
  critical: { color: "text-rose-400",    bg: "bg-rose-400/10",    border: "border-rose-400/30" },
  high:     { color: "text-orange-400",  bg: "bg-orange-400/10",  border: "border-orange-400/30" },
  medium:   { color: "text-amber-400",   bg: "bg-amber-400/10",   border: "border-amber-400/30" },
  low:      { color: "text-emerald-400", bg: "bg-emerald-400/10", border: "border-emerald-400/30" },
};

// ═══════════════════════════════════════════════════════════
// Utility helpers
// ═══════════════════════════════════════════════════════════

function timeAgo(date: Date): string {
  const diff = Math.floor((now.getTime() - date.getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function surfaceScore(assets: Asset[]): number {
  if (assets.length === 0) return 0;
  const weighted = assets.reduce((sum, a) => sum + a.riskScore, 0);
  return Math.round(weighted / assets.length);
}

// ═══════════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════════

function RiskBadge({ tier, score }: { tier: RiskTier; score?: number }) {
  const m = RISK_META[tier];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wider",
        m.bg, m.color, "border", m.border
      )}
    >
      {tier}
      {score !== undefined && <span className="font-mono opacity-75">/{score}</span>}
    </span>
  );
}

function ExposureDot({ level }: { level: ExposureLevel }) {
  const m = EXPOSURE_META[level];
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn("h-1.5 w-1.5 rounded-full", m.dot)} />
      <span className={cn("text-xs font-medium", m.color)}>{m.label}</span>
    </span>
  );
}

function AssetTypeChip({ type }: { type: AssetType }) {
  const m = ASSET_TYPE_META[type];
  const Icon = m.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs font-medium", m.color)}>
      <Icon className="h-3.5 w-3.5 shrink-0" />
      {m.label}
    </span>
  );
}

// Exposure path visualization — directed chain
function PathChain({ chain }: { chain: string[] }) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      {chain.map((node, i) => (
        <span key={i} className="inline-flex items-center gap-1">
          <span className="font-mono text-xs bg-zinc-800 border border-zinc-700 rounded px-1.5 py-0.5 text-zinc-200 whitespace-nowrap">
            {node}
          </span>
          {i < chain.length - 1 && (
            <ArrowRight className="h-3 w-3 text-zinc-600 shrink-0" />
          )}
        </span>
      ))}
    </div>
  );
}

// Score gauge ring
function ScoreRing({ score }: { score: number }) {
  const tier: RiskTier =
    score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : "low";
  const m = RISK_META[tier];
  const circumference = 2 * Math.PI * 20;
  const offset = circumference * (1 - score / 100);

  return (
    <div className="relative flex items-center justify-center h-16 w-16">
      <svg className="absolute -rotate-90" width="64" height="64" viewBox="0 0 48 48">
        <circle cx="24" cy="24" r="20" fill="none" stroke="currentColor" strokeWidth="3" className="text-zinc-800" />
        <circle
          cx="24" cy="24" r="20" fill="none" strokeWidth="3"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className={cn(
            tier === "critical" ? "stroke-rose-400" :
            tier === "high"     ? "stroke-orange-400" :
            tier === "medium"   ? "stroke-amber-400" :
                                  "stroke-emerald-400",
            "transition-all duration-700"
          )}
        />
      </svg>
      <span className={cn("text-sm font-bold font-mono tabular-nums", m.color)}>
        {score}
      </span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main page component
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// API → frontend mapping
// ═══════════════════════════════════════════════════════════

const ASSET_TYPE_MAP: Record<string, AssetType> = {
  host: "host", server: "host", vm: "host",
  cloud: "cloud", s3: "cloud", bucket: "cloud", lambda: "cloud",
  container: "container", docker: "container", pod: "container",
  api: "api", endpoint: "api", service: "api",
  repo: "repo", repository: "repo", code: "repo",
  database: "database", db: "database", rds: "database",
  domain: "host", ip_address: "host", subdomain: "host",
};

function mapApiAsset(raw: Record<string, unknown>, idx: number): Asset {
  const rawType = String(raw.asset_type ?? raw.type ?? "host").toLowerCase();
  const type: AssetType = ASSET_TYPE_MAP[rawType] ?? "host";
  const riskScore = Math.min(100, Math.max(0, Number(raw.risk_score ?? 0)));
  const riskTier: RiskTier =
    riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 40 ? "medium" : "low";

  const status = String(raw.status ?? "active").toLowerCase();
  const exposure: ExposureLevel =
    status === "internet" || rawType === "domain" || rawType === "subdomain"
      ? "internet"
      : status === "isolated" ? "isolated" : "internal";

  const tagsRaw = raw.tags;
  const tags: string[] = Array.isArray(tagsRaw)
    ? tagsRaw.map(String)
    : typeof tagsRaw === "string" && tagsRaw
      ? tagsRaw.split(",").map((t: string) => t.trim())
      : [rawType];

  return {
    id: String(raw.id ?? raw.asset_id ?? `AST-API-${idx}`),
    name: String(raw.value ?? raw.name ?? "Unknown Asset"),
    type,
    exposure,
    riskScore,
    riskTier,
    openPorts: Array.isArray(raw.open_ports) ? raw.open_ports.map(Number) : undefined,
    cveCount: Number(raw.cve_count ?? raw.exposure_count ?? 0),
    lastSeen: raw.last_seen ? new Date(String(raw.last_seen)) : new Date(),
    owner: String(raw.owner ?? raw.notes ?? "unassigned"),
    tags,
    cloudProvider: raw.cloud_provider ? String(raw.cloud_provider) : undefined,
  };
}

export default function AttackSurface() {
  const [assets, setAssets] = useState<Asset[]>(MOCK_ASSETS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<AssetType | "all">("all");
  const [exposureFilter, setExposureFilter] = useState<ExposureLevel | "all">("all");
  const [riskFilter, setRiskFilter] = useState<RiskTier | "all">("all");
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [expandedPath, setExpandedPath] = useState<string | null>(null);
  const [showAllChanges, setShowAllChanges] = useState(false);

  // Fetch assets from real API, fall back to MOCK_ASSETS
  useEffect(() => {
    let cancelled = false;
    async function fetchAssets() {
      try {
        setLoading(true);
        setError(null);
        const resp = await fetch("/api/v1/asm/assets?org_id=default");
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        const rawList: Record<string, unknown>[] = Array.isArray(data) ? data : (data.assets ?? []);
        if (!cancelled && rawList.length > 0) {
          const mapped = rawList.map(mapApiAsset);
          setAssets(mapped);
          setLastRefresh(new Date());
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load assets");
          // Keep MOCK_ASSETS as fallback — already set as initial state
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchAssets();
    return () => { cancelled = true; };
  }, []);

  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      if (typeFilter !== "all" && a.type !== typeFilter) return false;
      if (exposureFilter !== "all" && a.exposure !== exposureFilter) return false;
      if (riskFilter !== "all" && a.riskTier !== riskFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          a.name.toLowerCase().includes(q) ||
          a.id.toLowerCase().includes(q) ||
          a.owner.toLowerCase().includes(q) ||
          a.tags.some((t) => t.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [searchQuery, typeFilter, exposureFilter, riskFilter, assets]);

  // KPI derivations
  const totalAssets = assets.length;
  const externalAssets = assets.filter((a) => a.exposure === "internet").length;
  const highRiskPaths = MOCK_PATHS.filter((p) => p.severity === "critical" || p.severity === "high").length;
  const overallScore = surfaceScore(assets);

  const criticalCount = assets.filter((a) => a.riskTier === "critical").length;
  const highCount     = assets.filter((a) => a.riskTier === "high").length;

  const visibleChanges = showAllChanges ? MOCK_CHANGES : MOCK_CHANGES.slice(0, 5);

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* ── Header ── */}
        <PageHeader
          title="Attack Surface"
          description="External exposure inventory, risk-ranked asset table, and active exposure path chains."
          badge="CTEM"
          actions={
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <RefreshCw className="h-3 w-3" />
              <span>Refreshed {timeAgo(lastRefresh)}</span>
            </div>
          }
        />

        {/* ── KPI Row ── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title="Total Assets"
            value={totalAssets}
            icon={Shield}         trend="up"
            trendLabel={`${criticalCount} critical · ${highCount} high`}
          />
          <KpiCard
            title="Internet-Exposed"
            value={externalAssets}
            icon={Globe}         trend="down"
            trendLabel="Direct external reach"
          />
          <KpiCard
            title="High-Risk Paths"
            value={highRiskPaths}
            icon={ShieldAlert}         trend="down"
            trendLabel={`${MOCK_PATHS.filter((p) => p.severity === "critical").length} critical paths`}
          />
          <div>
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: 0.15 }}
            >
              <Card className="p-5">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Surface Score
                    </p>
                    <RiskBadge
                      tier={
                        overallScore >= 80 ? "critical" :
                        overallScore >= 60 ? "high" :
                        overallScore >= 40 ? "medium" : "low"
                      }
                    />
                    <p className="text-xs text-muted-foreground">aggregate weighted risk</p>
                  </div>
                  <ScoreRing score={overallScore} />
                </div>
              </Card>
            </motion.div>
          </div>
        </div>

        {/* Loading / Error banners */}
        {loading && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground animate-pulse">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading assets from API...
          </div>
        )}
        {error && !loading && (
          <div className="flex items-center gap-2 text-xs text-amber-400 bg-amber-400/10 border border-amber-400/30 rounded-lg px-3 py-2">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            <span>API unavailable ({error}) — showing cached demo data</span>
          </div>
        )}

        {/* ── Main grid: Asset Table + Side panels ── */}
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-6">

          {/* Left column: filters + asset table */}
          <div className="space-y-4">
            {/* Filter bar */}
            <Card className="p-4">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[180px]">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Search assets, tags, owners…"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-8 h-8 text-xs font-mono bg-zinc-900/50"
                  />
                </div>
                <Select
                  value={typeFilter}
                  onValueChange={(v) => setTypeFilter(v as AssetType | "all")}
                >
                  <SelectTrigger className="h-8 w-[130px] text-xs">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="host">Host</SelectItem>
                    <SelectItem value="cloud">Cloud</SelectItem>
                    <SelectItem value="container">Container</SelectItem>
                    <SelectItem value="api">API</SelectItem>
                    <SelectItem value="repo">Repo</SelectItem>
                    <SelectItem value="database">Database</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={exposureFilter}
                  onValueChange={(v) => setExposureFilter(v as ExposureLevel | "all")}
                >
                  <SelectTrigger className="h-8 w-[130px] text-xs">
                    <SelectValue placeholder="Exposure" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Exposure</SelectItem>
                    <SelectItem value="internet">Internet</SelectItem>
                    <SelectItem value="internal">Internal</SelectItem>
                    <SelectItem value="isolated">Isolated</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={riskFilter}
                  onValueChange={(v) => setRiskFilter(v as RiskTier | "all")}
                >
                  <SelectTrigger className="h-8 w-[120px] text-xs">
                    <SelectValue placeholder="Risk" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Risk</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
                <span className="text-xs text-muted-foreground ml-auto">
                  {filteredAssets.length} of {totalAssets} assets
                </span>
              </div>
            </Card>

            {/* Asset table */}
            <Card className="overflow-hidden">
              <CardHeader className="px-5 py-3 border-b border-border">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Network className="h-4 w-4 text-primary" />
                  Asset Inventory
                </CardTitle>
              </CardHeader>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-zinc-900/40">
                      <th className="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground w-[280px]">
                        Asset
                      </th>
                      <th className="px-4 py-2.5 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                        Type
                      </th>
                      <th className="px-4 py-2.5 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                        Exposure
                      </th>
                      <th className="px-4 py-2.5 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                        Risk
                      </th>
                      <th className="px-4 py-2.5 text-right text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                        CVEs
                      </th>
                      <th className="px-5 py-2.5 text-right text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                        Last Seen
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <AnimatePresence initial={false}>
                      {filteredAssets.map((asset, idx) => {
                        const TypeIcon = ASSET_TYPE_META[asset.type].icon;
                        return (
                          <motion.tr
                            key={asset.id}
                            initial={{ opacity: 0, x: -6 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: 6 }}
                            transition={{ duration: 0.18, delay: idx * 0.03 }}
                            className={cn(
                              "border-b border-border/50 transition-colors hover:bg-zinc-900/50 group",
                              asset.riskTier === "critical" && "hover:bg-rose-950/20"
                            )}
                          >
                            <td className="px-5 py-3">
                              <div className="flex items-center gap-2 min-w-0">
                                <TypeIcon className={cn("h-3.5 w-3.5 shrink-0", ASSET_TYPE_META[asset.type].color)} />
                                <div className="min-w-0">
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <span className="font-mono text-xs text-foreground truncate block max-w-[220px] cursor-default">
                                        {asset.name}
                                      </span>
                                    </TooltipTrigger>
                                    <TooltipContent side="bottom" className="font-mono text-xs max-w-xs break-all">
                                      {asset.name}
                                    </TooltipContent>
                                  </Tooltip>
                                  <span className="text-[10px] text-muted-foreground font-mono">{asset.id}</span>
                                </div>
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <AssetTypeChip type={asset.type} />
                            </td>
                            <td className="px-4 py-3">
                              <ExposureDot level={asset.exposure} />
                            </td>
                            <td className="px-4 py-3">
                              <RiskBadge tier={asset.riskTier} score={asset.riskScore} />
                            </td>
                            <td className="px-4 py-3 text-right">
                              {asset.cveCount > 0 ? (
                                <span className="font-mono text-xs font-semibold text-rose-400">
                                  {asset.cveCount}
                                </span>
                              ) : (
                                <span className="font-mono text-xs text-muted-foreground">—</span>
                              )}
                            </td>
                            <td className="px-5 py-3 text-right">
                              <span className="text-[11px] text-muted-foreground font-mono tabular-nums">
                                {timeAgo(asset.lastSeen)}
                              </span>
                            </td>
                          </motion.tr>
                        );
                      })}
                    </AnimatePresence>
                    {filteredAssets.length === 0 && (
                      <tr>
                        <td colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                          No assets match the current filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>

          {/* Right column: paths + changes */}
          <div className="space-y-4">

            {/* Recent changes panel */}
            <Card>
              <CardHeader className="px-5 py-3 border-b border-border">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <GitCommit className="h-4 w-4 text-primary" />
                  Recent Changes
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="divide-y divide-border/50">
                  {visibleChanges.map((chg) => (
                    <div key={chg.id} className="px-5 py-3 hover:bg-zinc-900/40 transition-colors">
                      <div className="flex items-start justify-between gap-2 mb-1">
                        <span className="font-mono text-[11px] text-muted-foreground truncate max-w-[160px]">
                          {chg.asset}
                        </span>
                        <div className="flex items-center gap-1 shrink-0">
                          {chg.riskDelta !== undefined && chg.riskDelta !== 0 && (
                            <span
                              className={cn(
                                "text-[10px] font-semibold font-mono",
                                chg.riskDelta > 0 ? "text-rose-400" : "text-emerald-400"
                              )}
                            >
                              {chg.riskDelta > 0 ? "+" : ""}{chg.riskDelta}
                            </span>
                          )}
                          <ChangeTypeBadge type={chg.changeType} />
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground leading-snug">{chg.detail}</p>
                      <p className="text-[10px] text-zinc-600 font-mono mt-1">{timeAgo(chg.timestamp)}</p>
                    </div>
                  ))}
                </div>
                {MOCK_CHANGES.length > 5 && (
                  <div className="px-5 py-2 border-t border-border/50">
                    <button
                      onClick={() => setShowAllChanges(!showAllChanges)}
                      className="text-xs text-primary hover:underline"
                    >
                      {showAllChanges ? "Show less" : `Show ${MOCK_CHANGES.length - 5} more`}
                    </button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Surface score breakdown */}
            <Card>
              <CardHeader className="px-5 py-3 border-b border-border">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Zap className="h-4 w-4 text-amber-400" />
                  Risk Distribution
                </CardTitle>
              </CardHeader>
              <CardContent className="p-5 space-y-3">
                {(["critical", "high", "medium", "low"] as RiskTier[]).map((tier) => {
                  const count = assets.filter((a) => a.riskTier === tier).length;
                  const pct = Math.round((count / totalAssets) * 100);
                  const m = RISK_META[tier];
                  return (
                    <div key={tier} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className={cn("font-medium capitalize", m.color)}>{tier}</span>
                        <span className="font-mono text-muted-foreground">{count} assets · {pct}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                        <motion.div
                          className={cn("h-full rounded-full", {
                            "bg-rose-400":    tier === "critical",
                            "bg-orange-400":  tier === "high",
                            "bg-amber-400":   tier === "medium",
                            "bg-emerald-400": tier === "low",
                          })}
                          initial={{ width: 0 }}
                          animate={{ width: `${pct}%` }}
                          transition={{ duration: 0.6, delay: 0.1 }}
                        />
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* ── Exposure Paths Section ── */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-semibold">Exposure Path Visualization</h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                Active source-to-target attack chains ranked by combined likelihood × impact
              </p>
            </div>
            <Badge variant="destructive" className="font-mono text-xs">
              {MOCK_PATHS.filter((p) => p.severity === "critical").length} CRITICAL
            </Badge>
          </div>
          <div className="space-y-3">
            {MOCK_PATHS.map((path, idx) => {
              const isExpanded = expandedPath === path.id;
              const rm = RISK_META[path.severity];
              const score = Math.round((path.likelihood * path.impact) / 100);
              return (
                <motion.div
                  key={path.id}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2, delay: idx * 0.04 }}
                >
                  <Card
                    className={cn(
                      "transition-colors cursor-pointer",
                      isExpanded && cn("border", rm.border),
                      "hover:bg-zinc-900/50"
                    )}
                    onClick={() => setExpandedPath(isExpanded ? null : path.id)}
                  >
                    <div className="px-5 py-3.5">
                      <div className="flex items-start gap-3">
                        {/* Severity indicator */}
                        <div className={cn("mt-0.5 h-2 w-2 rounded-full shrink-0", {
                          "bg-rose-400":    path.severity === "critical",
                          "bg-orange-400":  path.severity === "high",
                          "bg-amber-400":   path.severity === "medium",
                          "bg-emerald-400": path.severity === "low",
                        })} />

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-3 flex-wrap">
                            <span className="text-sm font-medium text-foreground">{path.title}</span>
                            <div className="flex items-center gap-2 shrink-0">
                              <Tooltip>
                                <TooltipTrigger>
                                  <span className="font-mono text-xs text-muted-foreground">
                                    score {score}
                                  </span>
                                </TooltipTrigger>
                                <TooltipContent>
                                  Likelihood {path.likelihood}% × Impact {path.impact}% / 100
                                </TooltipContent>
                              </Tooltip>
                              <RiskBadge tier={path.severity} />
                              <ChevronRight
                                className={cn(
                                  "h-3.5 w-3.5 text-muted-foreground transition-transform duration-200",
                                  isExpanded && "rotate-90"
                                )}
                              />
                            </div>
                          </div>

                          {/* Chain preview (always visible, condensed) */}
                          <div className="mt-2">
                            <PathChain chain={path.chain} />
                          </div>

                          {/* Expanded detail */}
                          <AnimatePresence initial={false}>
                            {isExpanded && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: "auto", opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                transition={{ duration: 0.2 }}
                                className="overflow-hidden"
                              >
                                <Separator className="my-3" />
                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                                  <div>
                                    <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Technique</span>
                                    <p className="font-mono mt-0.5 text-foreground">{path.technique}</p>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Likelihood</span>
                                    <p className={cn("font-mono font-semibold mt-0.5", path.likelihood >= 80 ? "text-rose-400" : path.likelihood >= 50 ? "text-amber-400" : "text-emerald-400")}>
                                      {path.likelihood}%
                                    </p>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Impact</span>
                                    <p className={cn("font-mono font-semibold mt-0.5", path.impact >= 80 ? "text-rose-400" : path.impact >= 50 ? "text-amber-400" : "text-emerald-400")}>
                                      {path.impact}%
                                    </p>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Discovered</span>
                                    <p className="font-mono mt-0.5 text-muted-foreground">{timeAgo(path.discovered)}</p>
                                  </div>
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </div>
                      </div>
                    </div>
                  </Card>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}

// ── Change type badge ──
function ChangeTypeBadge({ type }: { type: RecentChange["changeType"] }) {
  const config: Record<RecentChange["changeType"], { label: string; className: string }> = {
    added:         { label: "added",     className: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20" },
    removed:       { label: "removed",   className: "text-zinc-400   bg-zinc-400/10   border-zinc-400/20" },
    modified:      { label: "modified",  className: "text-sky-400    bg-sky-400/10    border-sky-400/20" },
    "risk-change": { label: "risk",      className: "text-amber-400  bg-amber-400/10  border-amber-400/20" },
  };
  const c = config[type];
  return (
    <span className={cn("text-[10px] font-medium border rounded px-1.5 py-0.5 uppercase tracking-wider", c.className)}>
      {c.label}
    </span>
  );
}
