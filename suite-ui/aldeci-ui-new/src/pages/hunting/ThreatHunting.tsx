/**
 * Threat Hunting — P04 Persona (SOC T2 Analyst)
 *
 * Designed for advanced analysts running structured hunt campaigns.
 * Hunt session management, MITRE ATT&CK query builder, predefined hunt
 * libraries, results with IOC highlighting, and a chronological session
 * timeline. Dark-first, information-dense, operator aesthetic.
 *
 * Route: /hunting
 */

import { useState, useMemo, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search, Crosshair, Play, Square, Plus, ChevronDown, ChevronRight,
  Clock, CheckCircle2, XCircle, AlertTriangle, Activity, Shield,
  Eye, Terminal, Server, Network, Package, Database, Cpu, Globe,
  Filter, Download, RefreshCw, Layers, GitBranch, Zap, Target,
  Lock, FileText, TriangleAlert, Flame, Radio, Radar,
  Bug, Code, BookOpen, ChevronUp, Hash, List, BarChart3,
  CircleDot, ArrowRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type MitreTactic =
  | "initial-access"
  | "execution"
  | "persistence"
  | "privilege-escalation"
  | "defense-evasion"
  | "credential-access"
  | "discovery"
  | "lateral-movement";

type SessionStatus = "active" | "completed" | "paused";
type Severity = "critical" | "high" | "medium" | "low";
type ConditionOperator = "equals" | "contains" | "regex" | "gt" | "lt" | "exists";

interface HuntSession {
  id: string;
  name: string;
  status: SessionStatus;
  tactic: MitreTactic;
  startedAt: Date;
  endedAt?: Date;
  analyst: string;
  findingsCount: number;
  queriesRun: number;
  assetsScanned: number;
}

interface QueryCondition {
  id: string;
  field: string;
  operator: ConditionOperator;
  value: string;
}

interface PredefinedQuery {
  id: string;
  name: string;
  description: string;
  tactic: MitreTactic;
  technique: string;
  techniqueId: string;
  severity: Severity;
  queriesCount: number;
  lastRun?: Date;
  tags: string[];
}

interface HuntFinding {
  id: string;
  severity: Severity;
  title: string;
  asset: string;
  assetType: "container" | "host" | "network" | "cloud" | "identity" | "endpoint";
  tactic: MitreTactic;
  technique: string;
  techniqueId: string;
  confidence: number;
  iocs: string[];
  evidence: string;
  detectedAt: Date;
  status: "new" | "investigating" | "confirmed" | "false_positive";
}

interface TimelineEvent {
  id: string;
  timestamp: Date;
  type: "session_start" | "query_run" | "finding" | "session_pause" | "session_end" | "note";
  title: string;
  detail?: string;
  severity?: Severity;
}

// ═══════════════════════════════════════════════════════════
// MITRE ATT&CK Tactic metadata
// ═══════════════════════════════════════════════════════════

const MITRE_TACTICS: Record<MitreTactic, { label: string; color: string; bgColor: string; icon: React.FC<{ className?: string }> }> = {
  "initial-access": {
    label: "Initial Access",
    color: "text-red-400",
    bgColor: "bg-red-500/15 border-red-500/30",
    icon: ({ className }) => <Globe className={className} />,
  },
  "execution": {
    label: "Execution",
    color: "text-orange-400",
    bgColor: "bg-orange-500/15 border-orange-500/30",
    icon: ({ className }) => <Terminal className={className} />,
  },
  "persistence": {
    label: "Persistence",
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/15 border-yellow-500/30",
    icon: ({ className }) => <Lock className={className} />,
  },
  "privilege-escalation": {
    label: "Privilege Escalation",
    color: "text-amber-400",
    bgColor: "bg-amber-500/15 border-amber-500/30",
    icon: ({ className }) => <Zap className={className} />,
  },
  "defense-evasion": {
    label: "Defense Evasion",
    color: "text-purple-400",
    bgColor: "bg-purple-500/15 border-purple-500/30",
    icon: ({ className }) => <Shield className={className} />,
  },
  "credential-access": {
    label: "Credential Access",
    color: "text-pink-400",
    bgColor: "bg-pink-500/15 border-pink-500/30",
    icon: ({ className }) => <Database className={className} />,
  },
  "discovery": {
    label: "Discovery",
    color: "text-cyan-400",
    bgColor: "bg-cyan-500/15 border-cyan-500/30",
    icon: ({ className }) => <Radar className={className} />,
  },
  "lateral-movement": {
    label: "Lateral Movement",
    color: "text-blue-400",
    bgColor: "bg-blue-500/15 border-blue-500/30",
    icon: ({ className }) => <Network className={className} />,
  },
};

const SEVERITY_CONFIG: Record<Severity, { label: string; color: string; bg: string; dot: string }> = {
  critical: { label: "Critical", color: "text-red-400", bg: "bg-red-500/10 border-red-500/30", dot: "bg-red-500" },
  high:     { label: "High",     color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30", dot: "bg-orange-500" },
  medium:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30", dot: "bg-yellow-500" },
  low:      { label: "Low",      color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/30", dot: "bg-cyan-500" },
};

// ═══════════════════════════════════════════════════════════
// API config
// ═══════════════════════════════════════════════════════════

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

// ═══════════════════════════════════════════════════════════
// Helper components
// ═══════════════════════════════════════════════════════════

function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-medium", cfg.bg, cfg.color, className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", cfg.dot)} />
      {cfg.label}
    </span>
  );
}

function TacticBadge({ tactic, className }: { tactic: MitreTactic; className?: string }) {
  const cfg = MITRE_TACTICS[tactic];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-medium", cfg.bgColor, cfg.color, className)}>
      <cfg.icon className="h-2.5 w-2.5" />
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }: { status: SessionStatus }) {
  const map: Record<SessionStatus, { label: string; className: string; dot: string }> = {
    active:    { label: "Active",     className: "text-green-400 bg-green-500/10 border-green-500/30",    dot: "bg-green-500 animate-pulse" },
    completed: { label: "Completed",  className: "text-muted-foreground bg-muted/30 border-border",       dot: "bg-muted-foreground" },
    paused:    { label: "Paused",     className: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30", dot: "bg-yellow-500" },
  };
  const cfg = map[status];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-medium", cfg.className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", cfg.dot)} />
      {cfg.label}
    </span>
  );
}

function FindingStatusBadge({ status }: { status: HuntFinding["status"] }) {
  const map: Record<HuntFinding["status"], { label: string; className: string }> = {
    new:            { label: "New",           className: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30" },
    investigating:  { label: "Investigating", className: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" },
    confirmed:      { label: "Confirmed",     className: "text-red-400 bg-red-500/10 border-red-500/30" },
    false_positive: { label: "False Positive", className: "text-muted-foreground bg-muted/30 border-border" },
  };
  const cfg = map[status];
  return (
    <span className={cn("inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-medium", cfg.className)}>
      {cfg.label}
    </span>
  );
}

function IocHighlight({ value }: { value: string }) {
  return (
    <code className="rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[11px] text-primary border border-primary/20">
      {value}
    </code>
  );
}

function formatDuration(start: Date, end?: Date): string {
  const ms = (end ?? new Date()).getTime() - start.getTime();
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatRelative(date: Date): string {
  const ms = Date.now() - date.getTime();
  const m = Math.floor(ms / 60_000);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (d > 0) return `${d}d ago`;
  if (h > 0) return `${h}h ago`;
  return `${m}m ago`;
}

// ═══════════════════════════════════════════════════════════
// Section: Session Manager
// ═══════════════════════════════════════════════════════════

function SessionCard({ session, isSelected, onClick }: { session: HuntSession; isSelected: boolean; onClick: () => void }) {
  const tactic = MITRE_TACTICS[session.tactic];
  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.2 }}
    >
      <button
        onClick={onClick}
        className={cn(
          "w-full rounded-lg border p-3 text-left transition-all duration-200",
          isSelected
            ? "border-primary/40 bg-primary/8"
            : "border-border bg-card hover:border-border/80 hover:bg-muted/20"
        )}
      >
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-1.5 min-w-0">
            <span className="shrink-0 text-[10px] font-mono text-muted-foreground">{session.id}</span>
            <StatusBadge status={session.status} />
          </div>
          <TacticBadge tactic={session.tactic} />
        </div>
        <p className="text-sm font-medium text-foreground truncate mb-1">{session.name}</p>
        <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
          <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{formatDuration(session.startedAt, session.endedAt)}</span>
          <span className="flex items-center gap-1"><Target className="h-3 w-3" />{session.findingsCount} findings</span>
          <span className="flex items-center gap-1"><Activity className="h-3 w-3" />{session.queriesRun} queries</span>
        </div>
      </button>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Section: New Session Modal
// ═══════════════════════════════════════════════════════════

function NewSessionModal({ onClose, onStart }: { onClose: () => void; onStart: (name: string, tactic: MitreTactic) => void }) {
  const [name, setName] = useState("");
  const [tactic, setTactic] = useState<MitreTactic>("persistence");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-xl"
      >
        <h2 className="text-lg font-semibold mb-4">New Hunt Session</h2>
        <div className="space-y-4">
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5 block">Session Name</label>
            <Input
              placeholder="e.g. APT29 Persistence Hunt — Prod Infra"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="font-mono text-sm"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5 block">Primary MITRE Tactic</label>
            <Select value={tactic} onValueChange={(v) => setTactic(v as MitreTactic)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(MITRE_TACTICS).map(([key, cfg]) => (
                  <SelectItem key={key} value={key}>
                    <span className="flex items-center gap-2">
                      <cfg.icon className={cn("h-3.5 w-3.5", cfg.color)} />
                      {cfg.label}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="flex gap-2 mt-6">
          <Button variant="outline" onClick={onClose} className="flex-1">Cancel</Button>
          <Button
            onClick={() => { if (name.trim()) { onStart(name.trim(), tactic); onClose(); } }}
            disabled={!name.trim()}
            className="flex-1 gap-2"
          >
            <Play className="h-3.5 w-3.5" />
            Start Hunt
          </Button>
        </div>
      </motion.div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Section: Query Builder
// ═══════════════════════════════════════════════════════════

const QUERY_FIELDS = [
  "process.name", "process.parent.name", "process.args", "process.pid",
  "file.path", "file.hash.sha256", "file.extension",
  "network.destination.ip", "network.destination.port", "network.protocol",
  "registry.key", "registry.value",
  "user.name", "user.domain", "event.type", "host.name",
];

const QUERY_OPERATORS: { value: ConditionOperator; label: string }[] = [
  { value: "equals", label: "=" },
  { value: "contains", label: "contains" },
  { value: "regex", label: "regex" },
  { value: "gt", label: ">" },
  { value: "lt", label: "<" },
  { value: "exists", label: "exists" },
];

let _conditionIdCounter = 0;
function newConditionId() { return `cond-${++_conditionIdCounter}`; }

function QueryBuilder({ tactic, onRun }: { tactic: MitreTactic; onRun: () => void }) {
  const [conditions, setConditions] = useState<QueryCondition[]>([
    { id: newConditionId(), field: "process.name", operator: "equals", value: "" },
  ]);
  const [selectedTactic, setSelectedTactic] = useState<MitreTactic>(tactic);
  const [isRunning, setIsRunning] = useState(false);

  const addCondition = () => {
    setConditions((prev) => [...prev, { id: newConditionId(), field: "process.name", operator: "contains", value: "" }]);
  };

  const removeCondition = (id: string) => {
    setConditions((prev) => prev.filter((c) => c.id !== id));
  };

  const updateCondition = (id: string, patch: Partial<QueryCondition>) => {
    setConditions((prev) => prev.map((c) => (c.id === id ? { ...c, ...patch } : c)));
  };

  const handleRun = () => {
    setIsRunning(true);
    setTimeout(() => { setIsRunning(false); onRun(); }, 1800);
  };

  const activeTactic = MITRE_TACTICS[selectedTactic];

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Terminal className="h-4 w-4 text-primary" />
            Custom Query Builder
          </CardTitle>
          <TacticBadge tactic={selectedTactic} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Tactic selector */}
        <div>
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">MITRE ATT&CK Tactic</label>
          <div className="flex flex-wrap gap-2">
            {(Object.entries(MITRE_TACTICS) as [MitreTactic, typeof MITRE_TACTICS[MitreTactic]][]).map(([key, cfg]) => (
              <button
                key={key}
                onClick={() => setSelectedTactic(key)}
                className={cn(
                  "flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-all",
                  selectedTactic === key
                    ? cn(cfg.bgColor, cfg.color)
                    : "border-border text-muted-foreground hover:border-border/80 hover:text-foreground"
                )}
              >
                <cfg.icon className="h-3 w-3" />
                {cfg.label}
              </button>
            ))}
          </div>
        </div>

        <Separator />

        {/* Conditions */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Conditions (AND)</label>
            <Button variant="ghost" size="sm" onClick={addCondition} className="h-7 gap-1 text-xs">
              <Plus className="h-3 w-3" />
              Add
            </Button>
          </div>
          <div className="space-y-2">
            {conditions.map((cond, idx) => (
              <motion.div
                key={cond.id}
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex items-center gap-2"
              >
                <span className="text-[10px] text-muted-foreground font-mono w-6 text-center">{idx === 0 ? "IF" : "AND"}</span>
                <Select value={cond.field} onValueChange={(v) => updateCondition(cond.id, { field: v })}>
                  <SelectTrigger className="h-8 flex-1 text-xs font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {QUERY_FIELDS.map((f) => (
                      <SelectItem key={f} value={f} className="font-mono text-xs">{f}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={cond.operator} onValueChange={(v) => updateCondition(cond.id, { operator: v as ConditionOperator })}>
                  <SelectTrigger className="h-8 w-24 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {QUERY_OPERATORS.map((op) => (
                      <SelectItem key={op.value} value={op.value} className="text-xs">{op.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {cond.operator !== "exists" && (
                  <Input
                    className="h-8 flex-1 text-xs font-mono"
                    placeholder="value..."
                    value={cond.value}
                    onChange={(e) => updateCondition(cond.id, { value: e.target.value })}
                  />
                )}
                {conditions.length > 1 && (
                  <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => removeCondition(cond.id)}>
                    <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                  </Button>
                )}
              </motion.div>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-between pt-1">
          <span className="text-xs text-muted-foreground">{conditions.length} condition{conditions.length !== 1 ? "s" : ""} · AND logic</span>
          <Button onClick={handleRun} disabled={isRunning} className="gap-2 h-8 text-xs">
            {isRunning ? (
              <><RefreshCw className="h-3.5 w-3.5 animate-spin" />Running…</>
            ) : (
              <><Play className="h-3.5 w-3.5" />Execute Hunt</>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Section: Predefined Queries
// ═══════════════════════════════════════════════════════════

function PredefinedQueryCard({ query, onRun }: { query: PredefinedQuery; onRun: (id: string) => void }) {
  const tactic = MITRE_TACTICS[query.tactic];
  const sev = SEVERITY_CONFIG[query.severity];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      <Card className="h-full flex flex-col hover:border-primary/30 transition-colors">
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between gap-2 mb-1">
            <SeverityBadge severity={query.severity} />
            <span className="text-[10px] font-mono text-muted-foreground bg-muted/40 rounded px-1.5 py-0.5 border border-border shrink-0">{query.techniqueId}</span>
          </div>
          <h3 className="text-sm font-semibold text-foreground leading-snug">{query.name}</h3>
        </CardHeader>
        <CardContent className="flex-1 flex flex-col gap-3">
          <p className="text-xs text-muted-foreground leading-relaxed">{query.description}</p>
          <TacticBadge tactic={query.tactic} />
          <div className="flex flex-wrap gap-1 mt-auto">
            {query.tags.map((tag) => (
              <span key={tag} className="rounded bg-muted/40 border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground font-mono">
                {tag}
              </span>
            ))}
          </div>
          <div className="flex items-center justify-between pt-1 border-t border-border mt-1">
            <span className="text-[11px] text-muted-foreground flex items-center gap-1">
              <List className="h-3 w-3" />{query.queriesCount} queries
              {query.lastRun && <span className="ml-2 text-[10px]">· {formatRelative(query.lastRun)}</span>}
            </span>
            <Button size="sm" variant="ghost" className="h-7 gap-1 text-xs" onClick={() => onRun(query.id)}>
              <Play className="h-3 w-3" />Run
            </Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Section: Results Table
// ═══════════════════════════════════════════════════════════

function FindingRow({ finding }: { finding: HuntFinding }) {
  const [expanded, setExpanded] = useState(false);
  const tactic = MITRE_TACTICS[finding.tactic];

  const assetIcon: Record<HuntFinding["assetType"], React.FC<{ className?: string }>> = {
    container: ({ className }) => <Package className={className} />,
    host:      ({ className }) => <Server className={className} />,
    network:   ({ className }) => <Network className={className} />,
    cloud:     ({ className }) => <Globe className={className} />,
    identity:  ({ className }) => <Database className={className} />,
    endpoint:  ({ className }) => <Cpu className={className} />,
  };
  const AssetIcon = assetIcon[finding.assetType];

  return (
    <>
      <tr
        className={cn(
          "border-b border-border/50 transition-colors cursor-pointer",
          expanded ? "bg-muted/10" : "hover:bg-muted/10"
        )}
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="py-2.5 px-3">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="py-2.5 px-3">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-muted-foreground">{finding.id}</span>
            <span className="text-sm text-foreground font-medium">{finding.title}</span>
          </div>
        </td>
        <td className="py-2.5 px-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <AssetIcon className="h-3.5 w-3.5" />
            <span className="font-mono">{finding.asset}</span>
          </div>
        </td>
        <td className="py-2.5 px-3">
          <TacticBadge tactic={finding.tactic} />
        </td>
        <td className="py-2.5 px-3">
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden">
              <div
                className={cn("h-full rounded-full transition-all", finding.confidence >= 90 ? "bg-red-500" : finding.confidence >= 75 ? "bg-orange-500" : "bg-yellow-500")}
                style={{ width: `${finding.confidence}%` }}
              />
            </div>
            <span className="text-xs font-mono text-muted-foreground">{finding.confidence}%</span>
          </div>
        </td>
        <td className="py-2.5 px-3">
          <FindingStatusBadge status={finding.status} />
        </td>
        <td className="py-2.5 px-3 text-xs text-muted-foreground">{formatRelative(finding.detectedAt)}</td>
        <td className="py-2.5 px-3">
          <ChevronDown className={cn("h-4 w-4 text-muted-foreground transition-transform", expanded && "rotate-180")} />
        </td>
      </tr>
      <AnimatePresence initial={false}>
        {expanded && (
          <tr>
            <td colSpan={8} className="bg-muted/5 px-4 pb-4 pt-2">
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
              >
                <div className="grid grid-cols-2 gap-4 py-2">
                  <div>
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Indicators of Compromise</p>
                    <div className="flex flex-wrap gap-1.5">
                      {finding.iocs.map((ioc) => (
                        <IocHighlight key={ioc} value={ioc} />
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Technique</p>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs bg-muted/40 border border-border rounded px-2 py-1">{finding.techniqueId}</span>
                      <span className="text-sm text-foreground">{finding.technique}</span>
                    </div>
                  </div>
                  <div className="col-span-2">
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Evidence</p>
                    <p className="text-xs text-muted-foreground leading-relaxed bg-muted/20 rounded-lg border border-border p-3 font-mono">
                      {finding.evidence}
                    </p>
                  </div>
                </div>
              </motion.div>
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  );
}

// ═══════════════════════════════════════════════════════════
// Section: Session Timeline
// ═══════════════════════════════════════════════════════════

function TimelineEventItem({ event }: { event: TimelineEvent }) {
  const typeConfig: Record<TimelineEvent["type"], { icon: React.FC<{ className?: string }>; color: string }> = {
    session_start:  { icon: ({ className }) => <Play className={className} />,         color: "text-green-400 bg-green-500/10 border-green-500/30" },
    session_end:    { icon: ({ className }) => <Square className={className} />,        color: "text-muted-foreground bg-muted/30 border-border" },
    session_pause:  { icon: ({ className }) => <Clock className={className} />,         color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" },
    query_run:      { icon: ({ className }) => <Terminal className={className} />,      color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30" },
    finding:        { icon: ({ className }) => <TriangleAlert className={className} />, color: "text-orange-400 bg-orange-500/10 border-orange-500/30" },
    note:           { icon: ({ className }) => <FileText className={className} />,      color: "text-muted-foreground bg-muted/30 border-border" },
  };
  const cfg = typeConfig[event.type];
  const isFind = event.type === "finding";

  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <div className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-full border", cfg.color)}>
          <cfg.icon className="h-3.5 w-3.5" />
        </div>
        <div className="mt-1 flex-1 w-px bg-border min-h-4" />
      </div>
      <div className="pb-4 min-w-0 flex-1">
        <div className="flex items-center gap-2 mb-0.5">
          <span className={cn("text-sm font-medium", isFind && event.severity ? SEVERITY_CONFIG[event.severity].color : "text-foreground")}>
            {event.title}
          </span>
          <span className="text-[11px] text-muted-foreground ml-auto shrink-0">{formatRelative(event.timestamp)}</span>
        </div>
        {event.detail && (
          <p className="text-xs text-muted-foreground">{event.detail}</p>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function ThreatHunting() {
  const [sessions, setSessions] = useState<HuntSession[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>("");
  const [showNewSession, setShowNewSession] = useState(false);
  const [findings, setFindings] = useState<HuntFinding[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [predefinedQueries, setPredefinedQueries] = useState<PredefinedQuery[]>([]);
  const [tacticFilter, setTacticFilter] = useState<MitreTactic | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [querySearch, setQuerySearch] = useState("");
  const [activeTab, setActiveTab] = useState<"queries" | "results" | "timeline">("queries");
  const [runningQueryId, setRunningQueryId] = useState<string | null>(null);

  const selectedSession = sessions.find((s) => s.id === selectedSessionId);

  const filteredQueries = useMemo(() => {
    return predefinedQueries.filter((q) => {
      if (tacticFilter !== "all" && q.tactic !== tacticFilter) return false;
      if (severityFilter !== "all" && q.severity !== severityFilter) return false;
      if (querySearch && !q.name.toLowerCase().includes(querySearch.toLowerCase()) && !q.techniqueId.toLowerCase().includes(querySearch.toLowerCase())) return false;
      return true;
    });
  }, [tacticFilter, severityFilter, querySearch, predefinedQueries]);

  useEffect(() => {
    const headers = { "X-API-Key": API_KEY };
    Promise.allSettled([
      fetch(`${API_BASE}/api/v1/threat-hunting/sessions?org_id=${ORG_ID}`, { headers })
        .then(r => r.ok ? r.json() : Promise.reject()),
      fetch(`${API_BASE}/api/v1/threat-hunting/findings?org_id=${ORG_ID}`, { headers })
        .then(r => r.ok ? r.json() : Promise.reject()),
      fetch(`${API_BASE}/api/v1/threat-hunting/timeline?org_id=${ORG_ID}`, { headers })
        .then(r => r.ok ? r.json() : Promise.reject()),
      fetch(`${API_BASE}/api/v1/threat-hunting/queries?org_id=${ORG_ID}`, { headers })
        .then(r => r.ok ? r.json() : Promise.reject()),
    ]).then(([sessRes, findRes, timeRes, querRes]) => {
      if (sessRes.status === "fulfilled") {
        const d = sessRes.value;
        const list = Array.isArray(d) ? d : (d?.sessions ?? []);
        setSessions(list);
        if (list.length > 0) setSelectedSessionId(list[0].id);
      }
      if (findRes.status === "fulfilled") {
        const d = findRes.value;
        setFindings(Array.isArray(d) ? d : (d?.findings ?? []));
      }
      if (timeRes.status === "fulfilled") {
        const d = timeRes.value;
        setTimeline(Array.isArray(d) ? d : (d?.timeline ?? []));
      }
      if (querRes.status === "fulfilled") {
        const d = querRes.value;
        setPredefinedQueries(Array.isArray(d) ? d : (d?.queries ?? []));
      }
    });
  }, []);

  const handleStartSession = useCallback((name: string, tactic: MitreTactic) => {
    const newSession: HuntSession = {
      id: `HS-${String(sessions.length + 10).padStart(4, "0")}`,
      name,
      status: "active",
      tactic,
      startedAt: new Date(),
      analyst: "Current User",
      findingsCount: 0,
      queriesRun: 0,
      assetsScanned: 0,
    };
    setSessions((prev) => [newSession, ...prev]);
    setSelectedSessionId(newSession.id);
  }, [sessions.length]);

  const handleRunQuery = useCallback((queryId: string) => {
    setRunningQueryId(queryId);
    setTimeout(() => setRunningQueryId(null), 2000);
    setSessions((prev) =>
      prev.map((s) =>
        s.id === selectedSessionId ? { ...s, queriesRun: s.queriesRun + 1, assetsScanned: s.assetsScanned + Math.floor(Math.random() * 200 + 50) } : s
      )
    );
    setActiveTab("results");
  }, [selectedSessionId]);

  const handleEndSession = useCallback(() => {
    setSessions((prev) =>
      prev.map((s) => s.id === selectedSessionId ? { ...s, status: "completed" as const, endedAt: new Date() } : s)
    );
  }, [selectedSessionId]);

  // KPIs
  const kpiValues = useMemo(() => {
    const active = sessions.filter((s) => s.status === "active").length;
    const totalFindings = sessions.reduce((acc, s) => acc + s.findingsCount, 0);
    const criticalFindings = findings.filter((f) => f.severity === "critical").length;
    const avgConf = findings.length > 0 ? Math.round(findings.reduce((acc, f) => acc + f.confidence, 0) / findings.length) : 0;
    return { active, totalFindings, criticalFindings, avgConf };
  }, [sessions, findings]);

  return (
    <TooltipProvider delayDuration={200}>
      <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title="Threat Hunting"
          description="Structured hunt campaigns for SOC Tier 2 — MITRE ATT&CK framework, custom query builder, IOC correlation."
          badge="P04"
          actions={
            <div className="flex items-center gap-2">
              {selectedSession?.status === "active" && (
                <Button variant="outline" size="sm" onClick={handleEndSession} className="gap-1.5 text-xs h-8 border-red-500/30 text-red-400 hover:bg-red-500/10">
                  <Square className="h-3.5 w-3.5" />
                  End Session
                </Button>
              )}
              <Button size="sm" onClick={() => setShowNewSession(true)} className="gap-1.5 text-xs h-8">
                <Plus className="h-3.5 w-3.5" />
                New Hunt Session
              </Button>
            </div>
          }
        />

        {/* KPI Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard title="Active Sessions" value={kpiValues.active} icon={Radio} trendLabel="running now" trend="flat" />
          <KpiCard title="Total Findings" value={kpiValues.totalFindings} icon={Target} trendLabel="across all sessions" trend="flat" />
          <KpiCard title="Critical Findings" value={kpiValues.criticalFindings} icon={Flame} trendLabel="require action" trend={kpiValues.criticalFindings > 0 ? "down" : "flat"} />
          <KpiCard title="Avg. Confidence" value={`${kpiValues.avgConf}%`} icon={BarChart3} trendLabel="detection accuracy" trend="up" />
        </div>

        {/* Main grid: Sessions left + Content right */}
        <div className="grid grid-cols-[300px_1fr] gap-6 items-start">
          {/* Sessions Panel */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Hunt Sessions</h2>
              <span className="text-[11px] text-muted-foreground">{sessions.length} total</span>
            </div>
            <div className="space-y-2">
              {sessions.map((session) => (
                <SessionCard
                  key={session.id}
                  session={session}
                  isSelected={session.id === selectedSessionId}
                  onClick={() => setSelectedSessionId(session.id)}
                />
              ))}
            </div>
          </div>

          {/* Right Content */}
          <div className="space-y-4 min-w-0">
            {/* Session context bar */}
            {selectedSession && (
              <div className={cn("rounded-lg border p-3 flex items-center gap-4", selectedSession.status === "active" ? "border-green-500/20 bg-green-500/5" : "border-border bg-card")}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <StatusBadge status={selectedSession.status} />
                    <span className="text-sm font-semibold text-foreground truncate">{selectedSession.name}</span>
                  </div>
                  <div className="flex items-center gap-4 text-[11px] text-muted-foreground">
                    <span>{selectedSession.id}</span>
                    <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{formatDuration(selectedSession.startedAt, selectedSession.endedAt)}</span>
                    <span className="flex items-center gap-1"><Target className="h-3 w-3" />{selectedSession.findingsCount} findings</span>
                    <span className="flex items-center gap-1"><Activity className="h-3 w-3" />{selectedSession.queriesRun} queries</span>
                    <span className="flex items-center gap-1"><Server className="h-3 w-3" />{selectedSession.assetsScanned.toLocaleString()} assets</span>
                    <span>Analyst: {selectedSession.analyst}</span>
                  </div>
                </div>
                <TacticBadge tactic={selectedSession.tactic} />
              </div>
            )}

            {/* Tab navigation */}
            <div className="flex items-center gap-1 border-b border-border">
              {(["queries", "results", "timeline"] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={cn(
                    "px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px",
                    activeTab === tab
                      ? "border-primary text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                >
                  {tab === "queries" && "Query Library"}
                  {tab === "results" && `Results (${findings.length})`}
                  {tab === "timeline" && "Session Timeline"}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <AnimatePresence mode="wait">
              {activeTab === "queries" && (
                <motion.div
                  key="queries"
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  transition={{ duration: 0.2 }}
                  className="space-y-4"
                >
                  {/* Query Builder */}
                  <QueryBuilder tactic={selectedSession?.tactic ?? "persistence"} onRun={() => setActiveTab("results")} />

                  {/* Predefined Query Library */}
                  <Card>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between flex-wrap gap-3">
                        <CardTitle className="text-sm font-semibold flex items-center gap-2">
                          <BookOpen className="h-4 w-4 text-primary" />
                          Hunt Query Library
                          <span className="ml-1 rounded bg-primary/10 px-1.5 py-0.5 text-[11px] font-medium text-primary">{filteredQueries.length}</span>
                        </CardTitle>
                        <div className="flex items-center gap-2">
                          <div className="relative">
                            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                            <Input
                              className="pl-8 h-8 w-48 text-xs"
                              placeholder="Search queries…"
                              value={querySearch}
                              onChange={(e) => setQuerySearch(e.target.value)}
                            />
                          </div>
                          <Select value={tacticFilter} onValueChange={(v) => setTacticFilter(v as MitreTactic | "all")}>
                            <SelectTrigger className="h-8 w-40 text-xs">
                              <SelectValue placeholder="All Tactics" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All Tactics</SelectItem>
                              {Object.entries(MITRE_TACTICS).map(([key, cfg]) => (
                                <SelectItem key={key} value={key} className="text-xs">{cfg.label}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as Severity | "all")}>
                            <SelectTrigger className="h-8 w-32 text-xs">
                              <SelectValue placeholder="All Severity" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All Severity</SelectItem>
                              {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
                                <SelectItem key={s} value={s} className="text-xs capitalize">{s}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {filteredQueries.length === 0 ? (
                        <div className="py-12 text-center text-muted-foreground text-sm">No queries match the current filters.</div>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                          {filteredQueries.map((query) => (
                            <PredefinedQueryCard
                              key={query.id}
                              query={query}
                              onRun={handleRunQuery}
                            />
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </motion.div>
              )}

              {activeTab === "results" && (
                <motion.div
                  key="results"
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  transition={{ duration: 0.2 }}
                >
                  <Card>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm font-semibold flex items-center gap-2">
                          <Target className="h-4 w-4 text-primary" />
                          Hunt Findings
                          <span className="ml-1 rounded bg-primary/10 px-1.5 py-0.5 text-[11px] font-medium text-primary">{findings.length}</span>
                        </CardTitle>
                        <div className="flex items-center gap-2">
                          <Button variant="outline" size="sm" className="h-8 gap-1.5 text-xs">
                            <Download className="h-3.5 w-3.5" />
                            Export
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent className="p-0">
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-border bg-muted/20">
                              <th className="py-2.5 px-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Severity</th>
                              <th className="py-2.5 px-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Finding</th>
                              <th className="py-2.5 px-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Asset</th>
                              <th className="py-2.5 px-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Tactic</th>
                              <th className="py-2.5 px-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Confidence</th>
                              <th className="py-2.5 px-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Status</th>
                              <th className="py-2.5 px-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Detected</th>
                              <th className="py-2.5 px-3" />
                            </tr>
                          </thead>
                          <tbody>
                            {findings.map((finding) => (
                              <FindingRow key={finding.id} finding={finding} />
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}

              {activeTab === "timeline" && (
                <motion.div
                  key="timeline"
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  transition={{ duration: 0.2 }}
                >
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <Clock className="h-4 w-4 text-primary" />
                        Session Timeline
                        <span className="ml-1 text-[11px] font-normal text-muted-foreground">— {selectedSession?.name}</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[560px] pr-4">
                        <div className="space-y-0">
                          {timeline.map((event) => (
                            <TimelineEventItem key={event.id} event={event} />
                          ))}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* New Session Modal */}
      <AnimatePresence>
        {showNewSession && (
          <NewSessionModal onClose={() => setShowNewSession(false)} onStart={handleStartSession} />
        )}
      </AnimatePresence>
    </TooltipProvider>
  );
}
