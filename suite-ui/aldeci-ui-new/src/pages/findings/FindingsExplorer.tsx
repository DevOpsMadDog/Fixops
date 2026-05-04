/**
 * Findings Explorer — Universal Finding Triage Page
 *
 * The core page every persona lands on. Engineered for SOC T1, AppSec,
 * CloudSec, DevSec, CISO, and Compliance personas simultaneously.
 *
 * Features:
 *   - Paginated findings table (severity, title, source scanner, CVE, CVSS,
 *     status, age, risk score)
 *   - Advanced filter bar (severity, scanner, status, date range, search)
 *   - Finding detail slide-out panel (full details, LLM Council verdict,
 *     remediation steps, related findings, timeline)
 *   - Bulk actions (acknowledge, assign, export)
 *
 * Design: information-dense, dark-first, surgical precision over decoration.
 * One memorable thing: the Council verdict section with model-level breakdown
 * is shown directly in the slide-out — no modal-within-modal.
 *
 * Route: /findings
 */

import { useState, useMemo, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  SlidersHorizontal,
  Download,
  RefreshCw,
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  X,
  CheckCircle2,
  UserCheck,
  Archive,
  AlertTriangle,
  Shield,
  Bug,
  Code,
  KeyRound,
  Server,
  Cloud,
  Container,
  Package,
  Flame,
  Clock,
  CalendarDays,
  Zap,
  Brain,
  GitBranch,
  Terminal,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Activity,
  FileText,
  TriangleAlert,
  Layers,
  Users,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { API_BASE_URL, API_KEY, DEFAULT_ORG_ID } from "@/lib/api-config";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low" | "info";
type FindingStatus =
  | "open"
  | "in_progress"
  | "acknowledged"
  | "resolved"
  | "false_positive"
  | "accepted_risk";
type Verdict = "BLOCK" | "REVIEW" | "ALLOW" | "PENDING";
type AssetType =
  | "container"
  | "code"
  | "cloud"
  | "secrets"
  | "iac"
  | "package"
  | "dependency"
  | "api";

interface CouncilModel {
  name: string;
  verdict: Verdict;
  confidence: number;
  reasoning: string;
}

interface TimelineEvent {
  at: Date;
  actor: string;
  action: string;
  detail?: string;
}

interface RelatedFinding {
  id: string;
  title: string;
  severity: Severity;
}

// TrustGraph cross-domain correlation (FEATURE-2 / DoD #8)
// Surfaced via GET /api/v1/graph/related/{entity_id}
// Backend: suite-core/core/trustgraph_backbone.py::query_related
interface TrustGraphRelatedNode {
  id: string;
  type?: string;
  source_engine?: string;
  entity_type?: string;
  severity?: Severity | string;
  title?: string;
  name?: string;
  properties?: Record<string, unknown>;
}

interface TrustGraphRelatedEdge {
  source: string;
  target: string;
  relationship?: string;
  type?: string;
  weight?: number;
}

interface TrustGraphRelatedResponse {
  entity_id?: string;
  depth?: number;
  neighbors?: TrustGraphRelatedNode[];
  edges?: TrustGraphRelatedEdge[];
  // Some backends group nodes by type — accept both shapes
  nodes_by_type?: Record<string, TrustGraphRelatedNode[]>;
}

type RelatedFetchState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; nodes: TrustGraphRelatedNode[] }
  | { status: "error"; message: string };

interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  source: string;
  asset: string;
  asset_type: AssetType;
  cve?: string;
  cvss?: number;
  epss?: number;
  status: FindingStatus;
  discovered_at: Date;
  updated_at: Date;
  assignee?: string;
  risk_score: number;
  verdict: Verdict;
  verdict_confidence: number;
  council_models: CouncilModel[];
  remediation: string[];
  related: RelatedFinding[];
  timeline: TimelineEvent[];
  tags: string[];
  kev?: boolean;
  reachable?: boolean;
  file_path?: string;
  line?: number;
  component?: string;
  fix_version?: string;
}

// ═══════════════════════════════════════════════════════════
// Helper components
// ═══════════════════════════════════════════════════════════

const SCANNERS = ["All", "Trivy", "Semgrep", "Grype", "Prowler", "Checkov", "ZAP", "kube-bench", "TruffleHog", "npm audit"];
const STATUSES: FindingStatus[] = ["open", "in_progress", "acknowledged", "resolved", "false_positive", "accepted_risk"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SOURCE_ICON: Record<string, React.ReactNode> = {
  container: <Container className="h-3.5 w-3.5" />,
  code: <Code className="h-3.5 w-3.5" />,
  cloud: <Cloud className="h-3.5 w-3.5" />,
  secrets: <KeyRound className="h-3.5 w-3.5" />,
  iac: <Server className="h-3.5 w-3.5" />,
  package: <Package className="h-3.5 w-3.5" />,
  dependency: <GitBranch className="h-3.5 w-3.5" />,
  api: <Terminal className="h-3.5 w-3.5" />,
};

function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    info: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  return (
    <Badge className={cn("border text-[10px] font-bold uppercase tracking-widest px-1.5 py-0", styles[severity])}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: FindingStatus }) {
  const styles: Record<FindingStatus, string> = {
    open: "bg-red-500/10 text-red-400 border-red-500/20",
    in_progress: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    acknowledged: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    resolved: "bg-green-500/10 text-green-400 border-green-500/20",
    false_positive: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    accepted_risk: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  };
  const labels: Record<FindingStatus, string> = {
    open: "Open",
    in_progress: "In Progress",
    acknowledged: "Acknowledged",
    resolved: "Resolved",
    false_positive: "False +",
    accepted_risk: "Risk Accepted",
  };
  return (
    <Badge className={cn("border text-[10px]", styles[status])}>
      {labels[status]}
    </Badge>
  );
}

function VerdictBadge({ verdict, confidence }: { verdict: Verdict; confidence: number }) {
  const styles: Record<Verdict, string> = {
    BLOCK: "bg-red-600/20 text-red-300 border-red-600/40",
    REVIEW: "bg-yellow-600/20 text-yellow-300 border-yellow-600/40",
    ALLOW: "bg-green-600/20 text-green-300 border-green-600/40",
    PENDING: "bg-slate-600/20 text-slate-300 border-slate-600/40",
  };
  return (
    <Badge className={cn("border text-[10px] font-bold gap-1", styles[verdict])}>
      <Brain className="h-2.5 w-2.5" />
      {verdict}
      <span className="opacity-70">{confidence}%</span>
    </Badge>
  );
}

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 80 ? "text-red-400"
    : score >= 60 ? "text-orange-400"
    : score >= 35 ? "text-yellow-400"
    : "text-green-400";
  return <span className={cn("text-xs font-bold tabular-nums", color)}>{score}</span>;
}

function AgeBadge({ date }: { date: Date }) {
  const diffMs = Date.now() - date.getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  const diffHours = Math.floor(diffMs / 3_600_000);
  const diffDays = Math.floor(diffMs / 86_400_000);
  let label: string;
  if (diffMins < 60) label = `${diffMins}m`;
  else if (diffHours < 24) label = `${diffHours}h`;
  else label = `${diffDays}d`;
  return (
    <span className="text-xs text-muted-foreground tabular-nums">{label}</span>
  );
}

function SortIcon({ field, sortField, sortDir }: { field: string; sortField: string | null; sortDir: "asc" | "desc" | null }) {
  if (sortField !== field) return <ChevronsUpDown className="h-3 w-3 ml-1 opacity-30" />;
  if (sortDir === "asc") return <ChevronUp className="h-3 w-3 ml-1 text-primary" />;
  return <ChevronDown className="h-3 w-3 ml-1 text-primary" />;
}

// ═══════════════════════════════════════════════════════════
// TrustGraph Related Findings Panel (DoD #8)
// ═══════════════════════════════════════════════════════════
//
// Surfaces cross-domain correlations from FEATURE-2 (cb25906d):
//   RASP / CTEM / SAST / CloudConnectors emit canonical events with
//   `source_engine` + `entity_type`, KnowledgeBrainAdapter routes them
//   into TrustGraph cores. This panel exposes those neighborhood links
//   per-finding via GET /api/v1/graph/related/{entity_id}.

function normalizeSeverity(raw: unknown): Severity {
  const s = String(raw ?? "").toLowerCase().trim();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") {
    return s;
  }
  return "info";
}

function TrustGraphRelatedPanel({
  findingId,
  onSelect,
}: {
  findingId: string;
  onSelect?: (relatedId: string) => void;
}) {
  const [state, setState] = useState<RelatedFetchState>({ status: "idle" });

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });

    const url = `${API_BASE_URL.replace(/\/$/, "")}/api/v1/graph/related/${encodeURIComponent(
      findingId
    )}?depth=2&org_id=${encodeURIComponent(DEFAULT_ORG_ID)}`;

    const headers: Record<string, string> = { Accept: "application/json" };
    if (API_KEY) headers["X-API-Key"] = API_KEY;
    if (DEFAULT_ORG_ID) headers["X-Org-ID"] = DEFAULT_ORG_ID;

    fetch(url, { headers })
      .then(async (res) => {
        if (!res.ok) {
          // 404 = entity not yet in TrustGraph (no correlations) — render empty
          if (res.status === 404) {
            return { neighbors: [] } satisfies TrustGraphRelatedResponse;
          }
          throw new Error(`HTTP ${res.status}`);
        }
        return (await res.json()) as TrustGraphRelatedResponse;
      })
      .then((data) => {
        if (cancelled) return;
        // Normalize: backend may return `neighbors` flat OR `nodes_by_type` dict
        let nodes: TrustGraphRelatedNode[] = [];
        if (Array.isArray(data?.neighbors)) {
          nodes = data.neighbors;
        } else if (data?.nodes_by_type && typeof data.nodes_by_type === "object") {
          nodes = Object.values(data.nodes_by_type).flat();
        }
        // Filter out self-references
        nodes = nodes.filter((n) => n && n.id && n.id !== findingId);
        setState({ status: "ready", nodes });
      })
      .catch((err: Error) => {
        if (cancelled) return;
        setState({ status: "error", message: err.message || "Failed to fetch correlations" });
      });

    return () => {
      cancelled = true;
    };
  }, [findingId]);

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <Layers className="h-3.5 w-3.5 text-primary" />
        <p className="text-xs uppercase tracking-wider text-muted-foreground">
          Related findings (TrustGraph)
        </p>
      </div>

      {state.status === "loading" && (
        <div className="space-y-1.5">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="h-9 rounded-md border border-border bg-muted/20 animate-pulse"
            />
          ))}
        </div>
      )}

      {state.status === "error" && (
        <div className="rounded-md border border-yellow-600/40 bg-yellow-600/10 px-3 py-2">
          <p className="text-[11px] text-yellow-300">
            Could not load correlations: {state.message}
          </p>
          <p className="text-[10px] text-muted-foreground mt-0.5">
            TrustGraph correlation service unavailable — findings still triageable.
          </p>
        </div>
      )}

      {state.status === "ready" && state.nodes.length === 0 && (
        <div className="rounded-md border border-dashed border-border px-3 py-3">
          <p className="text-[11px] text-muted-foreground">
            No correlated findings yet — TrustGraph builds links as more data arrives.
          </p>
        </div>
      )}

      {state.status === "ready" && state.nodes.length > 0 && (
        <div className="space-y-1.5">
          {state.nodes.slice(0, 12).map((node) => {
            const sev = normalizeSeverity(node.severity ?? node.properties?.["severity"]);
            const engine = String(
              node.source_engine ??
                node.properties?.["source_engine"] ??
                node.entity_type ??
                node.type ??
                "trustgraph"
            );
            const title = String(
              node.title ??
                node.name ??
                node.properties?.["title"] ??
                node.properties?.["name"] ??
                node.id
            );
            return (
              <button
                key={node.id}
                type="button"
                onClick={() => onSelect?.(node.id)}
                className="flex w-full items-center gap-2 rounded-md border border-border px-3 py-2 text-left hover:border-primary/60 hover:bg-primary/5 transition-colors"
              >
                <SeverityBadge severity={sev} />
                <Badge
                  variant="outline"
                  className="text-[10px] font-mono uppercase tracking-wider border-border text-muted-foreground"
                >
                  {engine}
                </Badge>
                <span className="text-xs text-foreground truncate flex-1">{title}</span>
                <ExternalLink className="h-3 w-3 text-muted-foreground shrink-0" />
              </button>
            );
          })}
          {state.nodes.length > 12 && (
            <p className="text-[10px] text-muted-foreground pl-1">
              +{state.nodes.length - 12} more correlations
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Detail Slide-out Panel
// ═══════════════════════════════════════════════════════════

function DetailPanel({ finding, onClose, onStatusChange, onSelectRelated }: {
  finding: Finding;
  onClose: () => void;
  onStatusChange: (id: string, status: FindingStatus) => void;
  onSelectRelated?: (relatedId: string) => void;
}) {
  return (
    <motion.div
      initial={{ x: "100%", opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: "100%", opacity: 0 }}
      transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
      className="fixed inset-y-0 right-0 z-50 flex w-[520px] flex-col border-l border-border bg-card shadow-xl"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-mono text-muted-foreground">{finding.id}</span>
            <SeverityBadge severity={finding.severity} />
            {finding.kev && (
              <Badge className="border bg-red-700/25 text-red-300 border-red-700/50 text-[10px] font-bold gap-1">
                <TriangleAlert className="h-2.5 w-2.5" /> KEV
              </Badge>
            )}
          </div>
          <h2 className="text-sm font-semibold leading-snug line-clamp-2">{finding.title}</h2>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 rounded-md p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-5 space-y-5">
          {/* Meta row */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="space-y-0.5">
              <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Status</span>
              <div><StatusBadge status={finding.status} /></div>
            </div>
            <div className="space-y-0.5">
              <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Risk Score</span>
              <div className="text-lg font-bold"><RiskScore score={finding.risk_score} /></div>
            </div>
            <div className="space-y-0.5">
              <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Scanner</span>
              <div className="font-medium">{finding.source}</div>
            </div>
            <div className="space-y-0.5">
              <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Asset</span>
              <div className="font-medium font-mono text-xs truncate" title={finding.asset}>{finding.asset}</div>
            </div>
            {finding.cve && (
              <div className="space-y-0.5">
                <span className="text-muted-foreground uppercase tracking-wider text-[10px]">CVE</span>
                <div className="flex items-center gap-1">
                  <span className="font-mono text-xs">{finding.cve}</span>
                  <ExternalLink className="h-3 w-3 text-muted-foreground" />
                </div>
              </div>
            )}
            {finding.cvss != null && (
              <div className="space-y-0.5">
                <span className="text-muted-foreground uppercase tracking-wider text-[10px]">CVSS</span>
                <div className={cn(
                  "font-bold tabular-nums text-sm",
                  finding.cvss >= 9 ? "text-red-400" : finding.cvss >= 7 ? "text-orange-400" : finding.cvss >= 4 ? "text-yellow-400" : "text-green-400"
                )}>{finding.cvss.toFixed(1)}</div>
              </div>
            )}
            {finding.epss != null && (
              <div className="space-y-0.5">
                <span className="text-muted-foreground uppercase tracking-wider text-[10px]">EPSS</span>
                <div className="font-medium">{Math.round(finding.epss * 100)}%</div>
              </div>
            )}
            {finding.assignee && (
              <div className="space-y-0.5">
                <span className="text-muted-foreground uppercase tracking-wider text-[10px]">Assignee</span>
                <div className="flex items-center gap-1.5">
                  <div className="h-4 w-4 rounded-full bg-primary/20 flex items-center justify-center text-[8px] font-bold text-primary">
                    {finding.assignee[0].toUpperCase()}
                  </div>
                  <span className="font-medium">{finding.assignee}</span>
                </div>
              </div>
            )}
          </div>

          {/* Description */}
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Description</p>
            <p className="text-sm text-muted-foreground leading-relaxed">{finding.description}</p>
          </div>

          {finding.file_path && (
            <div className="rounded-lg bg-muted/40 px-3 py-2.5 font-mono text-xs text-muted-foreground flex items-center gap-2">
              <FileText className="h-3.5 w-3.5 shrink-0" />
              <span className="truncate">{finding.file_path}</span>
              {finding.line && <span className="shrink-0 text-primary">:{finding.line}</span>}
            </div>
          )}

          <Separator />

          {/* LLM Council Verdict */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                <Brain className="h-3.5 w-3.5 text-primary" />
                LLM Council Verdict
              </p>
              <VerdictBadge verdict={finding.verdict} confidence={finding.verdict_confidence} />
            </div>
            <div className="space-y-2">
              {finding.council_models.map((model) => (
                <div key={model.name} className="rounded-lg border border-border bg-muted/20 p-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-semibold">{model.name}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-muted-foreground tabular-nums">{model.confidence}%</span>
                      <VerdictBadge verdict={model.verdict} confidence={model.confidence} />
                    </div>
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">{model.reasoning}</p>
                </div>
              ))}
            </div>
          </div>

          <Separator />

          {/* Remediation steps */}
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-3">Remediation Steps</p>
            <ol className="space-y-2">
              {finding.remediation.map((step, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  <span className="shrink-0 h-5 w-5 rounded-full bg-primary/10 text-primary text-[10px] font-bold flex items-center justify-center mt-0.5">
                    {i + 1}
                  </span>
                  <span className="text-muted-foreground leading-relaxed">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* Tags */}
          {finding.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {finding.tags.map((tag) => (
                <span key={tag} className="rounded-md bg-muted/50 px-2 py-0.5 text-[10px] text-muted-foreground font-mono">
                  #{tag}
                </span>
              ))}
            </div>
          )}

          {/* Related findings — TrustGraph cross-domain correlation (DoD #8) */}
          <TrustGraphRelatedPanel
            findingId={finding.id}
            onSelect={onSelectRelated}
          />

          <Separator />

          {/* Timeline */}
          <div>
            <p className="text-xs uppercase tracking-wider text-muted-foreground mb-3">Timeline</p>
            <div className="relative pl-4">
              <div className="absolute left-1.5 top-0 bottom-0 w-px bg-border" />
              <div className="space-y-4">
                {finding.timeline.map((event, i) => (
                  <div key={i} className="relative">
                    <div className="absolute -left-[11px] top-1 h-2 w-2 rounded-full bg-primary ring-2 ring-background" />
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-xs font-medium">{event.action}</span>
                        <span className="text-[10px] text-muted-foreground">by {event.actor}</span>
                      </div>
                      {event.detail && (
                        <p className="text-[11px] text-muted-foreground">{event.detail}</p>
                      )}
                      <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                        {event.at.toLocaleString()}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </ScrollArea>

      {/* Footer actions */}
      <div className="border-t border-border p-4">
        <div className="flex items-center gap-2">
          <Select
            value={finding.status}
            onValueChange={(v) => onStatusChange(finding.id, v as FindingStatus)}
          >
            <SelectTrigger className="h-8 text-xs flex-1">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map((s) => (
                <SelectItem key={s} value={s} className="text-xs">
                  {s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button size="sm" variant="outline" className="h-8 text-xs gap-1.5">
            <UserCheck className="h-3.5 w-3.5" />
            Assign
          </Button>
          <Button size="sm" className="h-8 text-xs gap-1.5">
            <ExternalLink className="h-3.5 w-3.5" />
            Open Ticket
          </Button>
        </div>
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

const PAGE_SIZE = 10;

export default function FindingsExplorer() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [scannerFilter, setScannerFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "all">("all");
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "all">("all");
  const [sortField, setSortField] = useState<string | null>("risk_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc" | null>("desc");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [activeDetail, setActiveDetail] = useState<Finding | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (API_KEY) headers["X-API-Key"] = API_KEY;
    if (DEFAULT_ORG_ID) headers["X-Org-ID"] = DEFAULT_ORG_ID;
    const url = `${API_BASE_URL.replace(/\/$/, "")}/api/v1/findings?org_id=${encodeURIComponent(DEFAULT_ORG_ID)}&limit=100`;
    fetch(url, { headers })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`${r.status}`)))
      .then(d => {
        const items = Array.isArray(d) ? d : (d?.findings ?? d?.items ?? []);
        if (items.length > 0) setFindings(items);
      })
      .catch(() => { /* leave empty — real empty state */ });
  }, []);

  // Derived KPIs
  const kpis = useMemo(() => {
    const critical = findings.filter((f) => f.severity === "critical").length;
    const high = findings.filter((f) => f.severity === "high").length;
    const open = findings.filter((f) => f.status === "open").length;
    const kev = findings.filter((f) => f.kev).length;
    const blocked = findings.filter((f) => f.verdict === "BLOCK").length;
    const avgRisk = findings.length
      ? Math.round(findings.reduce((acc, f) => acc + f.risk_score, 0) / findings.length)
      : 0;
    return { critical, high, open, kev, blocked, avgRisk };
  }, [findings]);

  // Filter + sort
  const filtered = useMemo(() => {
    let result = findings.filter((f) => {
      if (search) {
        const q = search.toLowerCase();
        if (
          !f.title.toLowerCase().includes(q) &&
          !f.id.toLowerCase().includes(q) &&
          !(f.cve?.toLowerCase().includes(q)) &&
          !f.asset.toLowerCase().includes(q) &&
          !f.source.toLowerCase().includes(q)
        ) return false;
      }
      if (severityFilter !== "all" && f.severity !== severityFilter) return false;
      if (scannerFilter !== "All" && f.source !== scannerFilter) return false;
      if (statusFilter !== "all" && f.status !== statusFilter) return false;
      if (verdictFilter !== "all" && f.verdict !== verdictFilter) return false;
      return true;
    });

    if (sortField) {
      result = [...result].sort((a, b) => {
        let av: number | string, bv: number | string;
        if (sortField === "risk_score") { av = a.risk_score; bv = b.risk_score; }
        else if (sortField === "cvss") { av = a.cvss ?? -1; bv = b.cvss ?? -1; }
        else if (sortField === "discovered_at") { av = a.discovered_at.getTime(); bv = b.discovered_at.getTime(); }
        else if (sortField === "severity") {
          const order: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          av = order[a.severity] ?? 0; bv = order[b.severity] ?? 0;
        }
        else { av = a.id; bv = b.id; }
        const cmp = typeof av === "number" ? av - (bv as number) : (av as string).localeCompare(bv as string);
        return sortDir === "asc" ? cmp : -cmp;
      });
    }

    return result;
  }, [findings, search, severityFilter, scannerFilter, statusFilter, verdictFilter, sortField, sortDir]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const allOnPageSelected = paginated.length > 0 && paginated.every((f) => selected.has(f.id));

  const toggleSort = useCallback((field: string) => {
    if (sortField !== field) { setSortField(field); setSortDir("desc"); }
    else if (sortDir === "desc") setSortDir("asc");
    else { setSortField(null); setSortDir(null); }
    setPage(1);
  }, [sortField, sortDir]);

  const toggleSelectAll = useCallback(() => {
    if (allOnPageSelected) {
      setSelected((prev) => { const next = new Set(prev); paginated.forEach((f) => next.delete(f.id)); return next; });
    } else {
      setSelected((prev) => { const next = new Set(prev); paginated.forEach((f) => next.add(f.id)); return next; });
    }
  }, [allOnPageSelected, paginated]);

  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => { const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next; });
  }, []);

  const handleStatusChange = useCallback((id: string, status: FindingStatus) => {
    setFindings((prev) => prev.map((f) => f.id === id ? { ...f, status } : f));
    if (activeDetail?.id === id) setActiveDetail((prev) => prev ? { ...prev, status } : prev);
  }, [activeDetail]);

  const bulkAcknowledge = useCallback(() => {
    setFindings((prev) => prev.map((f) => selected.has(f.id) ? { ...f, status: "acknowledged" } : f));
    setSelected(new Set());
  }, [selected]);

  const bulkResolve = useCallback(() => {
    setFindings((prev) => prev.map((f) => selected.has(f.id) ? { ...f, status: "resolved" } : f));
    setSelected(new Set());
  }, [selected]);

  // Close detail when clicking outside
  useEffect(() => {
    if (!activeDetail) return;
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") setActiveDetail(null); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [activeDetail]);

  return (
    <TooltipProvider>
      <div className="space-y-6 pb-16">
        {/* Header */}
        <PageHeader
          title="Findings Explorer"
          description="Unified view of all security findings across scanners, clouds, and code. Every persona's ground truth."
          badge="CORE"
          actions={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5">
                <RefreshCw className="h-3.5 w-3.5" />
                Refresh
              </Button>
              <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5">
                <Download className="h-3.5 w-3.5" />
                Export
              </Button>
            </div>
          }
        />

        {/* KPI Strip */}
        <motion.div
          className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, staggerChildren: 0.05 }}
        >
          <KpiCard
            title="Critical"
            value={kpis.critical}
            icon={Flame}
            trendLabel="Requires immediate action"
            trend="down"
            className="border-red-500/20"
            onClick={() => { setSeverityFilter("critical"); setPage(1); }}
          />
          <KpiCard
            title="High"
            value={kpis.high}
            icon={TriangleAlert}
            trendLabel="High severity findings"
            trend="down"
            className="border-orange-500/20"
            onClick={() => { setSeverityFilter("high"); setPage(1); }}
          />
          <KpiCard
            title="Open"
            value={kpis.open}
            icon={CircleDot}
            trendLabel="Awaiting triage"
            className="border-border"
            onClick={() => { setStatusFilter("open"); setPage(1); }}
          />
          <KpiCard
            title="KEV Listed"
            value={kpis.kev}
            icon={Zap}
            trendLabel="CISA Known Exploited"
            trend="down"
            className="border-red-500/20"
          />
          <KpiCard
            title="BLOCK Verdict"
            value={kpis.blocked}
            icon={Shield}
            trendLabel="LLM Council: stop deployment"
            trend="down"
            className="border-border"
            onClick={() => { setVerdictFilter("BLOCK"); setPage(1); }}
          />
          <KpiCard
            title="Avg Risk Score"
            value={kpis.avgRisk}
            icon={Activity}
            trendLabel="Composite across all findings"
            className="border-border"
          />
        </motion.div>

        {/* Filter Bar */}
        <Card className="p-0 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
              <Input
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search findings, CVE, asset, scanner..."
                className="pl-9 h-8 text-xs"
              />
              {search && (
                <button
                  onClick={() => { setSearch(""); setPage(1); }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>

            <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v as Severity | "all"); setPage(1); }}>
              <SelectTrigger className="h-8 w-[120px] text-xs">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All Severities</SelectItem>
                {SEVERITIES.map((s) => <SelectItem key={s} value={s} className="text-xs capitalize">{s}</SelectItem>)}
              </SelectContent>
            </Select>

            <Select value={scannerFilter} onValueChange={(v) => { setScannerFilter(v); setPage(1); }}>
              <SelectTrigger className="h-8 w-[130px] text-xs">
                <SelectValue placeholder="Scanner" />
              </SelectTrigger>
              <SelectContent>
                {SCANNERS.map((s) => <SelectItem key={s} value={s} className="text-xs">{s}</SelectItem>)}
              </SelectContent>
            </Select>

            <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v as FindingStatus | "all"); setPage(1); }}>
              <SelectTrigger className="h-8 w-[140px] text-xs">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All Statuses</SelectItem>
                {STATUSES.map((s) => (
                  <SelectItem key={s} value={s} className="text-xs">
                    {s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={verdictFilter} onValueChange={(v) => { setVerdictFilter(v as Verdict | "all"); setPage(1); }}>
              <SelectTrigger className="h-8 w-[120px] text-xs">
                <SelectValue placeholder="Verdict" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All Verdicts</SelectItem>
                {(["BLOCK", "REVIEW", "ALLOW", "PENDING"] as Verdict[]).map((v) => (
                  <SelectItem key={v} value={v} className="text-xs">{v}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
              <span>{filtered.length} findings</span>
              {(severityFilter !== "all" || scannerFilter !== "All" || statusFilter !== "all" || verdictFilter !== "all" || search) && (
                <button
                  onClick={() => { setSeverityFilter("all"); setScannerFilter("All"); setStatusFilter("all"); setVerdictFilter("all"); setSearch(""); setPage(1); }}
                  className="flex items-center gap-1 text-primary hover:text-primary/80 transition-colors"
                >
                  <X className="h-3 w-3" /> Clear
                </button>
              )}
            </div>
          </div>

          {/* Bulk action bar */}
          <AnimatePresence>
            {selected.size > 0 && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="flex items-center gap-3 px-4 py-2.5 bg-primary/5 border-b border-primary/20">
                  <span className="text-xs font-medium text-primary">
                    {selected.size} selected
                  </span>
                  <Separator orientation="vertical" className="h-4" />
                  <button
                    onClick={bulkAcknowledge}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Acknowledge
                  </button>
                  <button
                    onClick={bulkResolve}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <Archive className="h-3.5 w-3.5" />
                    Mark Resolved
                  </button>
                  <button className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
                    <UserCheck className="h-3.5 w-3.5" />
                    Assign
                  </button>
                  <button className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
                    <Download className="h-3.5 w-3.5" />
                    Export
                  </button>
                  <button
                    onClick={() => setSelected(new Set())}
                    className="ml-auto text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/20">
                  <th className="px-4 py-2.5 w-10">
                    <Checkbox
                      checked={allOnPageSelected}
                      onCheckedChange={toggleSelectAll}
                      className="h-3.5 w-3.5"
                    />
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    ID
                  </th>
                  <th
                    className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px] cursor-pointer hover:text-foreground"
                    onClick={() => toggleSort("severity")}
                  >
                    <span className="flex items-center">
                      Severity <SortIcon field="severity" sortField={sortField} sortDir={sortDir} />
                    </span>
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    Title
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    Scanner
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    CVE
                  </th>
                  <th
                    className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px] cursor-pointer hover:text-foreground"
                    onClick={() => toggleSort("cvss")}
                  >
                    <span className="flex items-center">
                      CVSS <SortIcon field="cvss" sortField={sortField} sortDir={sortDir} />
                    </span>
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    Status
                  </th>
                  <th
                    className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px] cursor-pointer hover:text-foreground"
                    onClick={() => toggleSort("discovered_at")}
                  >
                    <span className="flex items-center">
                      Age <SortIcon field="discovered_at" sortField={sortField} sortDir={sortDir} />
                    </span>
                  </th>
                  <th
                    className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px] cursor-pointer hover:text-foreground"
                    onClick={() => toggleSort("risk_score")}
                  >
                    <span className="flex items-center">
                      Risk <SortIcon field="risk_score" sortField={sortField} sortDir={sortDir} />
                    </span>
                  </th>
                  <th className="px-3 py-2.5 text-left font-medium text-muted-foreground uppercase tracking-wider text-[10px]">
                    Verdict
                  </th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {paginated.map((finding, i) => (
                    <motion.tr
                      key={finding.id}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15, delay: i * 0.02 }}
                      onClick={() => setActiveDetail(finding)}
                      className={cn(
                        "border-b border-border/50 cursor-pointer transition-colors",
                        selected.has(finding.id) ? "bg-primary/5" : "hover:bg-muted/30",
                        activeDetail?.id === finding.id && "bg-primary/8 border-l-2 border-l-primary"
                      )}
                    >
                      <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={selected.has(finding.id)}
                          onCheckedChange={() => toggleSelect(finding.id)}
                          className="h-3.5 w-3.5"
                        />
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="font-mono text-muted-foreground">{finding.id}</span>
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="px-3 py-2.5 max-w-[280px]">
                        <div className="flex items-start gap-2">
                          <span className="shrink-0 text-muted-foreground mt-0.5">
                            {SOURCE_ICON[finding.asset_type]}
                          </span>
                          <div className="min-w-0">
                            <div className="truncate font-medium text-foreground">{finding.title}</div>
                            <div className="truncate text-muted-foreground text-[10px] mt-0.5">{finding.asset}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="text-muted-foreground">{finding.source}</span>
                      </td>
                      <td className="px-3 py-2.5">
                        {finding.cve ? (
                          <span className="font-mono text-[10px] text-cyan-400">{finding.cve}</span>
                        ) : (
                          <span className="text-muted-foreground/40">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        {finding.cvss != null ? (
                          <span className={cn(
                            "font-bold tabular-nums",
                            finding.cvss >= 9 ? "text-red-400" : finding.cvss >= 7 ? "text-orange-400" : finding.cvss >= 4 ? "text-yellow-400" : "text-green-400"
                          )}>
                            {finding.cvss.toFixed(1)}
                          </span>
                        ) : (
                          <span className="text-muted-foreground/40">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <StatusBadge status={finding.status} />
                      </td>
                      <td className="px-3 py-2.5">
                        <AgeBadge date={finding.discovered_at} />
                      </td>
                      <td className="px-3 py-2.5">
                        <RiskScore score={finding.risk_score} />
                      </td>
                      <td className="px-3 py-2.5">
                        <VerdictBadge verdict={finding.verdict} confidence={finding.verdict_confidence} />
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>

                {paginated.length === 0 && (
                  <tr>
                    <td colSpan={11} className="px-4 py-16 text-center text-muted-foreground">
                      <div className="flex flex-col items-center gap-3">
                        <Shield className="h-10 w-10 opacity-20" />
                        <span className="text-sm">No findings match the current filters.</span>
                        <button
                          onClick={() => { setSeverityFilter("all"); setScannerFilter("All"); setStatusFilter("all"); setVerdictFilter("all"); setSearch(""); }}
                          className="text-xs text-primary hover:text-primary/80 transition-colors"
                        >
                          Clear all filters
                        </button>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-border">
              <span className="text-xs text-muted-foreground">
                Showing {Math.min((page - 1) * PAGE_SIZE + 1, filtered.length)}–{Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length}
              </span>
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </Button>
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let pageNum: number;
                  if (totalPages <= 5) pageNum = i + 1;
                  else if (page <= 3) pageNum = i + 1;
                  else if (page >= totalPages - 2) pageNum = totalPages - 4 + i;
                  else pageNum = page - 2 + i;
                  return (
                    <Button
                      key={pageNum}
                      variant={page === pageNum ? "default" : "ghost"}
                      size="icon"
                      className="h-7 w-7 text-xs"
                      onClick={() => setPage(pageNum)}
                    >
                      {pageNum}
                    </Button>
                  );
                })}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* Detail Slide-out */}
      <AnimatePresence>
        {activeDetail && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
              onClick={() => setActiveDetail(null)}
            />
            <DetailPanel
              finding={activeDetail}
              onClose={() => setActiveDetail(null)}
              onStatusChange={handleStatusChange}
              onSelectRelated={(relId) => {
                const next = findings.find((f) => f.id === relId);
                if (next) setActiveDetail(next);
              }}
            />
          </>
        )}
      </AnimatePresence>
    </TooltipProvider>
  );
}
