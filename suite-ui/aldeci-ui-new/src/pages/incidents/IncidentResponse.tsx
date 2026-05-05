/**
 * Incident Response — IR Command Center
 *
 * Designed for SOC T2/T3 and IR leads managing active security incidents.
 * State machine lifecycle, step checklists, assignees, timeline, linked findings.
 * Dark-first, information-dense, high-signal visual hierarchy.
 *
 * Route: /incidents
 */

import { useState, useMemo, useEffect } from "react";
import { incidentsApi } from "@/lib/api";
import { motion, AnimatePresence } from "framer-motion";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  Siren,
  ShieldAlert,
  Bug,
  Cloud,
  KeyRound,
  Container,
  Server,
  Network,
  Lock,
  Globe,
  ChevronRight,
  Clock,
  User,
  CheckSquare,
  Square,
  AlertTriangle,
  Activity,
  FileText,
  Link2,
  Calendar,
  ArrowRight,
  Search,
  Filter,
  Plus,
  ExternalLink,
  Circle,
  CheckCircle2,
  Loader2,
  XCircle,
  Crosshair,
  Zap,
  Database,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low";
type IRState =
  | "DETECTED"
  | "TRIAGING"
  | "CONTAINING"
  | "ERADICATING"
  | "RECOVERING"
  | "CLOSED";

type IncidentType =
  | "ransomware"
  | "data_breach"
  | "supply_chain"
  | "insider_threat"
  | "ddos"
  | "credential_compromise"
  | "lateral_movement"
  | "zero_day";

interface ChecklistItem {
  id: string;
  label: string;
  assignee?: string;
  done: boolean;
  phase: IRState;
}

interface TimelineEvent {
  id: string;
  ts: Date;
  actor: string;
  action: string;
  detail?: string;
  type: "detection" | "action" | "escalation" | "update" | "resolution";
}

interface LinkedFinding {
  id: string;
  title: string;
  severity: Severity;
  source: string;
  cve?: string;
}

interface Incident {
  id: string;
  title: string;
  type: IncidentType;
  severity: Severity;
  state: IRState;
  summary: string;
  affectedAssets: string[];
  owner: string;
  team: string[];
  detectedAt: Date;
  updatedAt: Date;
  sla_breach_at: Date;
  checklist: ChecklistItem[];
  timeline: TimelineEvent[];
  findings: LinkedFinding[];
  mttr_est_hours: number;
  tags: string[];
}

// ═══════════════════════════════════════════════════════════
// State machine config
// ═══════════════════════════════════════════════════════════

const IR_STATES: IRState[] = [
  "DETECTED",
  "TRIAGING",
  "CONTAINING",
  "ERADICATING",
  "RECOVERING",
  "CLOSED",
];

const STATE_META: Record<
  IRState,
  { label: string; color: string; bg: string; description: string }
> = {
  DETECTED: {
    label: "Detected",
    color: "text-red-400",
    bg: "bg-red-400/10 border-red-400/30",
    description: "Incident identified, initial assessment underway",
  },
  TRIAGING: {
    label: "Triaging",
    color: "text-orange-400",
    bg: "bg-orange-400/10 border-orange-400/30",
    description: "Scope, impact, and severity being assessed",
  },
  CONTAINING: {
    label: "Containing",
    color: "text-yellow-400",
    bg: "bg-yellow-400/10 border-yellow-400/30",
    description: "Active threat being isolated to prevent spread",
  },
  ERADICATING: {
    label: "Eradicating",
    color: "text-blue-400",
    bg: "bg-blue-400/10 border-blue-400/30",
    description: "Root cause and malicious artifacts being removed",
  },
  RECOVERING: {
    label: "Recovering",
    color: "text-emerald-400",
    bg: "bg-emerald-400/10 border-emerald-400/30",
    description: "Systems being restored and validated",
  },
  CLOSED: {
    label: "Closed",
    color: "text-muted-foreground",
    bg: "bg-muted/20 border-border",
    description: "Incident resolved, post-mortem complete",
  },
};

// ═══════════════════════════════════════════════════════════
// Incident type config
// ═══════════════════════════════════════════════════════════

const TYPE_META: Record<
  IncidentType,
  { label: string; icon: React.ComponentType<{ className?: string }> }
> = {
  ransomware: { label: "Ransomware", icon: Lock },
  data_breach: { label: "Data Breach", icon: Database },
  supply_chain: { label: "Supply Chain", icon: Link2 },
  insider_threat: { label: "Insider Threat", icon: User },
  ddos: { label: "DDoS", icon: Network },
  credential_compromise: { label: "Credential Compromise", icon: KeyRound },
  lateral_movement: { label: "Lateral Movement", icon: Crosshair },
  zero_day: { label: "Zero Day", icon: Zap },
};

// ═══════════════════════════════════════════════════════════
// Time helpers
// ═══════════════════════════════════════════════════════════

const now = new Date();


// ═══════════════════════════════════════════════════════════
// Helper components
// ═══════════════════════════════════════════════════════════

function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  }[severity];
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border", cfg)}>
      {severity}
    </span>
  );
}

function StateBadge({ state }: { state: IRState }) {
  const meta = STATE_META[state];
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border", meta.bg, meta.color)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
      {meta.label}
    </span>
  );
}

function TimeAgo({ date }: { date: Date }) {
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays > 0) return <span>{diffDays}d ago</span>;
  if (diffHours > 0) return <span>{diffHours}h {diffMins % 60}m ago</span>;
  return <span>{diffMins}m ago</span>;
}

function SLABadge({ sla_breach_at }: { sla_breach_at: Date }) {
  const diffMs = sla_breach_at.getTime() - now.getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  const diffHours = Math.floor(diffMins / 60);
  const breached = diffMs < 0;
  const urgent = !breached && diffHours < 2;

  if (breached) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/40">
        <XCircle className="h-3 w-3" /> SLA BREACHED
      </span>
    );
  }
  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border",
      urgent
        ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
        : "bg-muted/30 text-muted-foreground border-border"
    )}>
      <Clock className="h-3 w-3" />
      {urgent ? `${diffHours}h ${diffMins % 60}m` : `${diffHours}h`} left
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// State Machine Progress
// ═══════════════════════════════════════════════════════════

function IRStateMachine({ state }: { state: IRState }) {
  const currentIdx = IR_STATES.indexOf(state);

  return (
    <div className="flex items-center gap-0 w-full">
      {IR_STATES.map((s, idx) => {
        const meta = STATE_META[s];
        const isActive = idx === currentIdx;
        const isPast = idx < currentIdx;
        const isFuture = idx > currentIdx;

        return (
          <div key={s} className="flex items-center flex-1">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="flex flex-col items-center gap-1.5 flex-1">
                    <div
                      className={cn(
                        "h-7 w-7 rounded-full flex items-center justify-center border-2 transition-all duration-300",
                        isActive && cn("border-current ring-2 ring-offset-1 ring-offset-background", meta.color),
                        isPast && "border-emerald-500/50 bg-emerald-500/15",
                        isFuture && "border-muted-foreground/20 bg-muted/10"
                      )}
                    >
                      {isPast ? (
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                      ) : isActive ? (
                        <div className={cn("h-2 w-2 rounded-full bg-current animate-pulse", meta.color)} />
                      ) : (
                        <Circle className="h-3 w-3 text-muted-foreground/30" />
                      )}
                    </div>
                    <span
                      className={cn(
                        "text-[9px] font-bold uppercase tracking-wider text-center leading-tight",
                        isActive && meta.color,
                        isPast && "text-emerald-400/70",
                        isFuture && "text-muted-foreground/30"
                      )}
                    >
                      {meta.label}
                    </span>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="text-xs">{meta.description}</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            {idx < IR_STATES.length - 1 && (
              <div
                className={cn(
                  "h-px flex-1 mx-1 transition-colors duration-300",
                  idx < currentIdx ? "bg-emerald-500/40" : "bg-muted/30"
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Timeline panel
// ═══════════════════════════════════════════════════════════

const TIMELINE_TYPE_STYLE: Record<TimelineEvent["type"], { dot: string; icon: React.ComponentType<{ className?: string }> }> = {
  detection: { dot: "bg-red-400", icon: AlertTriangle },
  action: { dot: "bg-blue-400", icon: Activity },
  escalation: { dot: "bg-orange-400", icon: Siren },
  update: { dot: "bg-muted-foreground", icon: FileText },
  resolution: { dot: "bg-emerald-400", icon: CheckCircle2 },
};

function TimelinePanel({ events }: { events: TimelineEvent[] }) {
  const sorted = [...events].sort((a, b) => b.ts.getTime() - a.ts.getTime());
  return (
    <div className="relative pl-5">
      <div className="absolute left-2 top-0 bottom-0 w-px bg-border" />
      {sorted.map((ev, idx) => {
        const style = TIMELINE_TYPE_STYLE[ev.type];
        const Icon = style.icon;
        return (
          <motion.div
            key={ev.id}
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.04 }}
            className="relative mb-4 last:mb-0"
          >
            <div className={cn("absolute -left-5 mt-1 h-3 w-3 rounded-full border-2 border-background", style.dot)} />
            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <Icon className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-xs font-medium text-foreground">{ev.action}</span>
              </div>
              {ev.detail && (
                <p className="text-[11px] text-muted-foreground leading-relaxed pl-5">{ev.detail}</p>
              )}
              <div className="flex items-center gap-2 pl-5">
                <span className="text-[10px] font-medium text-muted-foreground/70">{ev.actor}</span>
                <span className="text-[10px] text-muted-foreground/40">·</span>
                <span className="text-[10px] text-muted-foreground/60 tabular-nums">
                  <TimeAgo date={ev.ts} />
                </span>
              </div>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Checklist panel
// ═══════════════════════════════════════════════════════════

function ChecklistPanel({ items, currentState }: { items: ChecklistItem[]; currentState: IRState }) {
  const [checked, setChecked] = useState<Record<string, boolean>>(
    Object.fromEntries(items.map((i) => [i.id, i.done]))
  );

  const byPhase = useMemo(() => {
    const phases: Partial<Record<IRState, ChecklistItem[]>> = {};
    for (const item of items) {
      if (!phases[item.phase]) phases[item.phase] = [];
      phases[item.phase]!.push(item);
    }
    return phases;
  }, [items]);

  const currentPhaseIdx = IR_STATES.indexOf(currentState);

  return (
    <div className="space-y-4">
      {IR_STATES.filter((s) => byPhase[s]).map((phase) => {
        const phaseIdx = IR_STATES.indexOf(phase);
        const isPast = phaseIdx < currentPhaseIdx;
        const isCurrent = phaseIdx === currentPhaseIdx;
        const meta = STATE_META[phase];
        const phaseItems = byPhase[phase]!;
        const doneCount = phaseItems.filter((i) => checked[i.id]).length;

        return (
          <div key={phase} className={cn("rounded-lg border p-3", isCurrent ? meta.bg : "border-border/50")}>
            <div className="flex items-center justify-between mb-2.5">
              <div className="flex items-center gap-2">
                <span className={cn("text-[10px] font-bold uppercase tracking-wider", isCurrent ? meta.color : isPast ? "text-emerald-400/70" : "text-muted-foreground/40")}>
                  {meta.label}
                </span>
                {isPast && <CheckCircle2 className="h-3 w-3 text-emerald-400" />}
              </div>
              <span className="text-[10px] text-muted-foreground tabular-nums">{doneCount}/{phaseItems.length}</span>
            </div>
            <div className="space-y-1.5">
              {phaseItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setChecked((prev) => ({ ...prev, [item.id]: !prev[item.id] }))}
                  className="flex items-start gap-2.5 w-full text-left group"
                >
                  <div className="mt-0.5 shrink-0">
                    {checked[item.id] ? (
                      <CheckSquare className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <Square className="h-3.5 w-3.5 text-muted-foreground/40 group-hover:text-muted-foreground/70 transition-colors" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <span className={cn("text-xs leading-relaxed", checked[item.id] && "line-through text-muted-foreground/50")}>
                      {item.label}
                    </span>
                    {item.assignee && (
                      <div className="flex items-center gap-1 mt-0.5">
                        <User className="h-2.5 w-2.5 text-muted-foreground/40" />
                        <span className="text-[10px] text-muted-foreground/50">{item.assignee}</span>
                      </div>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Linked findings panel
// ═══════════════════════════════════════════════════════════

function FindingsPanel({ findings }: { findings: LinkedFinding[] }) {
  return (
    <div className="space-y-2">
      {findings.map((f) => (
        <div key={f.id} className="flex items-center gap-3 p-2.5 rounded-lg bg-muted/20 border border-border/50 hover:border-border transition-colors group">
          <SeverityBadge severity={f.severity} />
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium truncate">{f.title}</p>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-[10px] text-muted-foreground">{f.id}</span>
              <span className="text-[10px] text-muted-foreground/40">·</span>
              <span className="text-[10px] text-muted-foreground">{f.source}</span>
              {f.cve && (
                <>
                  <span className="text-[10px] text-muted-foreground/40">·</span>
                  <span className="text-[10px] font-mono text-blue-400">{f.cve}</span>
                </>
              )}
            </div>
          </div>
          <ExternalLink className="h-3 w-3 text-muted-foreground/30 group-hover:text-muted-foreground/70 shrink-0 transition-colors" />
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Incident detail panel
// ═══════════════════════════════════════════════════════════

function IncidentDetail({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const TypeIcon = TYPE_META[incident.type].icon;

  return (
    <motion.div
      initial={{ opacity: 0, x: 24 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 24 }}
      transition={{ duration: 0.2 }}
      className="flex flex-col h-full"
    >
      {/* Detail header */}
      <div className="p-5 border-b border-border space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <div className="h-9 w-9 rounded-lg bg-muted/30 border border-border flex items-center justify-center shrink-0 mt-0.5">
              <TypeIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono text-muted-foreground">{incident.id}</span>
                <SeverityBadge severity={incident.severity} />
                <StateBadge state={incident.state} />
              </div>
              <h2 className="text-sm font-semibold mt-1 leading-snug">{incident.title}</h2>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} className="shrink-0 h-7 w-7">
            <XCircle className="h-4 w-4" />
          </Button>
        </div>

        {/* State machine */}
        <IRStateMachine state={incident.state} />

        {/* Meta row */}
        <div className="flex items-center gap-4 flex-wrap text-[11px] text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <User className="h-3 w-3" />
            <span>{incident.owner}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Clock className="h-3 w-3" />
            <TimeAgo date={incident.detectedAt} />
          </div>
          <div className="flex items-center gap-1.5">
            <Activity className="h-3 w-3" />
            <span>~{incident.mttr_est_hours}h MTTR</span>
          </div>
          <SLABadge sla_breach_at={incident.sla_breach_at} />
        </div>

        {/* Summary */}
        <p className="text-xs text-muted-foreground leading-relaxed">{incident.summary}</p>

        {/* Affected assets */}
        <div className="space-y-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Affected Assets</span>
          <div className="flex flex-wrap gap-1.5">
            {incident.affectedAssets.map((a) => (
              <span key={a} className="px-2 py-0.5 rounded bg-muted/30 border border-border text-[10px] font-mono">{a}</span>
            ))}
          </div>
        </div>

        {/* Team */}
        <div className="space-y-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Response Team</span>
          <div className="flex flex-wrap gap-1.5">
            {incident.team.map((m) => (
              <span key={m} className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-muted/20 border border-border text-[11px]">
                <div className="h-3.5 w-3.5 rounded-full bg-primary/20 flex items-center justify-center text-[8px] font-bold text-primary">
                  {m[0]?.toUpperCase()}
                </div>
                {m}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex-1 overflow-hidden">
        <Tabs defaultValue="checklist" className="flex flex-col h-full">
          <TabsList className="mx-5 mt-3 w-auto justify-start shrink-0">
            <TabsTrigger value="checklist" className="text-xs gap-1.5">
              <CheckSquare className="h-3 w-3" />
              Steps
            </TabsTrigger>
            <TabsTrigger value="timeline" className="text-xs gap-1.5">
              <Clock className="h-3 w-3" />
              Timeline
            </TabsTrigger>
            <TabsTrigger value="findings" className="text-xs gap-1.5">
              <Link2 className="h-3 w-3" />
              Findings
            </TabsTrigger>
          </TabsList>

          <ScrollArea className="flex-1 mt-3">
            <div className="px-5 pb-6">
              <TabsContent value="checklist" className="mt-0">
                <ChecklistPanel items={incident.checklist} currentState={incident.state} />
              </TabsContent>
              <TabsContent value="timeline" className="mt-0">
                <TimelinePanel events={incident.timeline} />
              </TabsContent>
              <TabsContent value="findings" className="mt-0">
                <FindingsPanel findings={incident.findings} />
              </TabsContent>
            </div>
          </ScrollArea>
        </Tabs>
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Incident list row
// ═══════════════════════════════════════════════════════════

function IncidentRow({
  incident,
  isSelected,
  onClick,
}: {
  incident: Incident;
  isSelected: boolean;
  onClick: () => void;
}) {
  const TypeIcon = TYPE_META[incident.type].icon;
  const progress = incident.checklist.filter((c) => c.done).length / Math.max(incident.checklist.length, 1);

  return (
    <motion.button
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={onClick}
      className={cn(
        "w-full text-left p-4 rounded-lg border transition-all duration-150 group",
        isSelected
          ? "border-primary/40 bg-primary/5"
          : "border-border/60 bg-card hover:border-border hover:bg-muted/10"
      )}
    >
      <div className="flex items-start gap-3">
        <div className={cn(
          "h-8 w-8 rounded-md flex items-center justify-center shrink-0 mt-0.5 border",
          isSelected ? "bg-primary/10 border-primary/30" : "bg-muted/20 border-border"
        )}>
          <TypeIcon className="h-3.5 w-3.5 text-muted-foreground" />
        </div>

        <div className="flex-1 min-w-0 space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-mono text-muted-foreground/60">{incident.id}</span>
            <SeverityBadge severity={incident.severity} />
            <StateBadge state={incident.state} />
          </div>
          <p className="text-sm font-medium leading-snug group-hover:text-primary transition-colors line-clamp-2">
            {incident.title}
          </p>
          <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
            <div className="flex items-center gap-1">
              <User className="h-2.5 w-2.5" />
              {incident.owner}
            </div>
            <div className="flex items-center gap-1">
              <Clock className="h-2.5 w-2.5" />
              <TimeAgo date={incident.detectedAt} />
            </div>
            <SLABadge sla_breach_at={incident.sla_breach_at} />
          </div>

          {/* Progress bar */}
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1 rounded-full bg-muted/30 overflow-hidden">
              <motion.div
                className="h-full bg-emerald-500/60 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${progress * 100}%` }}
                transition={{ duration: 0.6, ease: "easeOut" }}
              />
            </div>
            <span className="text-[10px] text-muted-foreground/60 tabular-nums shrink-0">
              {incident.checklist.filter((c) => c.done).length}/{incident.checklist.length}
            </span>
          </div>
        </div>

        <ChevronRight className={cn(
          "h-4 w-4 shrink-0 mt-1 transition-all duration-150",
          isSelected ? "text-primary rotate-90" : "text-muted-foreground/30 group-hover:text-muted-foreground"
        )} />
      </div>
    </motion.button>
  );
}

// ═══════════════════════════════════════════════════════════
// Main page
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// API → frontend mapping
// ═══════════════════════════════════════════════════════════

const STATUS_TO_STATE: Record<string, IRState> = {
  detected: "DETECTED",
  triaging: "TRIAGING",
  investigating: "TRIAGING",
  containing: "CONTAINING",
  contained: "CONTAINING",
  eradicating: "ERADICATING",
  eradicated: "ERADICATING",
  recovering: "RECOVERING",
  recovered: "RECOVERING",
  closed: "CLOSED",
  resolved: "CLOSED",
};

function mapApiIncident(raw: Record<string, unknown>): Incident | null {
  try {
    const state = STATUS_TO_STATE[(String(raw.status ?? "detected")).toLowerCase()] ?? "DETECTED";
    const severity = (["critical", "high", "medium", "low"].includes(String(raw.severity ?? "").toLowerCase())
      ? String(raw.severity).toLowerCase()
      : "medium") as Severity;
    const type = (Object.keys(TYPE_META).includes(String(raw.type ?? ""))
      ? String(raw.type)
      : "zero_day") as IncidentType;
    const detectedAt = raw.created_at ? new Date(String(raw.created_at)) : new Date();
    const updatedAt = raw.updated_at ? new Date(String(raw.updated_at)) : detectedAt;
    const slaHours = severity === "critical" ? 4 : severity === "high" ? 12 : severity === "medium" ? 48 : 168;
    const sla_breach_at = new Date(detectedAt.getTime() + slaHours * 3_600_000);

    const steps = Array.isArray(raw.steps) ? raw.steps : [];
    const checklist: ChecklistItem[] = steps.map((s: Record<string, unknown>, idx: number) => ({
      id: String(s.id ?? `step-${idx}`),
      label: String(s.description ?? s.title ?? `Step ${idx + 1}`),
      assignee: s.assignee ? String(s.assignee) : undefined,
      done: s.status === "completed" || s.completed === true,
      phase: STATUS_TO_STATE[String(s.phase ?? "detected").toLowerCase()] ?? state,
    }));

    const timelineRaw = Array.isArray(raw.timeline) ? raw.timeline : [];
    const timeline: TimelineEvent[] = timelineRaw.map((t: Record<string, unknown>, idx: number) => ({
      id: String(t.id ?? `tl-${idx}`),
      ts: t.timestamp ? new Date(String(t.timestamp)) : detectedAt,
      actor: String(t.author ?? t.actor ?? "System"),
      action: String(t.event_description ?? t.action ?? ""),
      detail: t.detail ? String(t.detail) : undefined,
      type: (["detection", "action", "escalation", "update", "resolution"].includes(String(t.type ?? ""))
        ? String(t.type)
        : "update") as TimelineEvent["type"],
    }));

    const findingsRaw = Array.isArray(raw.findings) ? raw.findings : [];
    const findings: LinkedFinding[] = findingsRaw.map((f: Record<string, unknown>, idx: number) => ({
      id: String(f.id ?? f.finding_id ?? `f-${idx}`),
      title: String(f.title ?? f.description ?? "Finding"),
      severity: (["critical", "high", "medium", "low"].includes(String(f.severity ?? "").toLowerCase())
        ? String(f.severity).toLowerCase()
        : "medium") as Severity,
      source: String(f.source ?? "API"),
      cve: f.cve ? String(f.cve) : undefined,
    }));

    return {
      id: String(raw.id ?? raw.incident_id ?? `INC-${Date.now()}`),
      title: String(raw.title ?? "Untitled Incident"),
      type,
      severity,
      state,
      summary: String(raw.description ?? raw.summary ?? ""),
      affectedAssets: Array.isArray(raw.affected_assets) ? raw.affected_assets.map(String) : [],
      owner: String(raw.reported_by ?? raw.owner ?? "unassigned"),
      team: Array.isArray(raw.team) ? raw.team.map(String) : [String(raw.reported_by ?? "unassigned")],
      detectedAt,
      updatedAt,
      sla_breach_at,
      checklist,
      timeline,
      findings,
      mttr_est_hours: Number(raw.mttr_est_hours ?? slaHours),
      tags: Array.isArray(raw.tags) ? raw.tags.map(String) : [type],
    };
  } catch {
    return null;
  }
}

export default function IncidentResponse() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [filterState, setFilterState] = useState<IRState | "ALL">("ALL");
  const [filterSeverity, setFilterSeverity] = useState<Severity | "ALL">("ALL");

  // Fetch incidents from real API via incidentsApi; empty state renders when none
  useEffect(() => {
    let cancelled = false;
    async function fetchIncidents() {
      try {
        setLoading(true);
        setError(null);
        const res = await incidentsApi.list({ limit: 100 });
        const data = res.data as Record<string, unknown>;
        // Index route: { items, total, stats } | list route: { incidents, count }
        const rawList: Record<string, unknown>[] = Array.isArray(data)
          ? (data as Record<string, unknown>[])
          : ((data.items ?? data.incidents ?? []) as Record<string, unknown>[]);
        if (!cancelled && rawList.length > 0) {
          const mapped = rawList.map(mapApiIncident).filter(Boolean) as Incident[];
          if (mapped.length > 0) {
            setIncidents(mapped);
            setSelectedId(mapped[0].id);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load incidents");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchIncidents();
    return () => { cancelled = true; };
  }, []);

  const selectedIncident = useMemo(
    () => incidents.find((i) => i.id === selectedId) ?? null,
    [selectedId, incidents]
  );

  const filtered = useMemo(() => {
    return incidents.filter((inc) => {
      if (filterState !== "ALL" && inc.state !== filterState) return false;
      if (filterSeverity !== "ALL" && inc.severity !== filterSeverity) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          inc.title.toLowerCase().includes(q) ||
          inc.id.toLowerCase().includes(q) ||
          inc.summary.toLowerCase().includes(q) ||
          inc.tags.some((t) => t.includes(q))
        );
      }
      return true;
    });
  }, [search, filterState, filterSeverity, incidents]);

  // KPI counts
  const kpis = useMemo(() => ({
    active: incidents.filter((i) => i.state !== "CLOSED").length,
    critical: incidents.filter((i) => i.severity === "critical" && i.state !== "CLOSED").length,
    slaBreached: incidents.filter((i) => i.sla_breach_at.getTime() < now.getTime() && i.state !== "CLOSED").length,
    avgMttr: Math.round(
      incidents.filter((i) => i.state === "CLOSED").reduce((acc, i) => acc + i.mttr_est_hours, 0) /
        Math.max(incidents.filter((i) => i.state === "CLOSED").length, 1)
    ),
  }), [incidents]);

  return (
    <TooltipProvider>
      <div className="flex flex-col h-full min-h-0 p-6 gap-6">
        {/* Page header */}
        <PageHeader
          title="Incident Response"
          description="Active security incidents — detection to closure. State machine lifecycle, evidence chain, and team coordination."
          badge="IR"
          actions={
            <Button size="sm" className="gap-1.5">
              <Plus className="h-3.5 w-3.5" />
              Declare Incident
            </Button>
          }
        />

        {/* KPIs */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 shrink-0">
          <KpiCard
            title="Active Incidents"
            value={kpis.active}
            icon={Siren}         trend="down"
            trendLabel="vs last week"
            description="Open across all phases"
          />
          <KpiCard
            title="Critical Open"
            value={kpis.critical}
            icon={ShieldAlert}         trend={kpis.critical > 2 ? "down" : "flat"}
            description="Requiring immediate action"
          />
          <KpiCard
            title="SLA Breached"
            value={kpis.slaBreached}
            icon={AlertTriangle}         trend="flat"
            description="Resolution time exceeded"
          />
          <KpiCard
            title="Avg MTTR"
            value={`${kpis.avgMttr}h`}
            icon={Clock}         trend="up"
            trendLabel="vs baseline"
            description="Mean time to resolve (closed)"
          />
        </div>

        {/* Loading / Error banners */}
        {loading && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground animate-pulse shrink-0">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading incidents from API...
          </div>
        )}
        {error && !loading && (
          <div className="flex items-center gap-2 text-xs text-amber-400 bg-amber-400/10 border border-amber-400/30 rounded-lg px-3 py-2 shrink-0">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            <span>API unavailable ({error}) — showing cached demo data</span>
          </div>
        )}

        {/* Main split layout */}
        <div className="flex gap-4 flex-1 min-h-0">
          {/* Left: incident list */}
          <div className={cn(
            "flex flex-col gap-3 transition-all duration-300",
            selectedIncident ? "w-[42%] shrink-0" : "flex-1"
          )}>
            {/* Filters */}
            <div className="flex items-center gap-2 shrink-0">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search incidents..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8 h-8 text-xs"
                />
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                {(["ALL", "DETECTED", "TRIAGING", "CONTAINING", "ERADICATING", "RECOVERING"] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setFilterState(s)}
                    className={cn(
                      "px-2 py-1 rounded text-[10px] font-semibold uppercase tracking-wider border transition-colors",
                      filterState === s
                        ? "bg-primary/15 border-primary/40 text-primary"
                        : "border-border/50 text-muted-foreground/60 hover:border-border hover:text-muted-foreground"
                    )}
                  >
                    {s === "ALL" ? "All" : STATE_META[s].label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-1.5 shrink-0">
              <Filter className="h-3 w-3 text-muted-foreground" />
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Severity:</span>
              {(["ALL", "critical", "high", "medium", "low"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setFilterSeverity(s)}
                  className={cn(
                    "px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border transition-colors",
                    filterSeverity === s
                      ? "bg-primary/15 border-primary/40 text-primary"
                      : "border-border/50 text-muted-foreground/50 hover:border-border"
                  )}
                >
                  {s}
                </button>
              ))}
              <span className="ml-auto text-[10px] text-muted-foreground/50">
                {filtered.length} of {incidents.length}
              </span>
            </div>

            {/* List */}
            <ScrollArea className="flex-1">
              <div className="space-y-2 pr-2">
                <AnimatePresence mode="popLayout">
                  {filtered.length === 0 ? (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="flex flex-col items-center justify-center py-16 text-muted-foreground/40"
                    >
                      <ShieldAlert className="h-10 w-10 mb-3" />
                      <p className="text-sm">No incidents match filters</p>
                    </motion.div>
                  ) : (
                    filtered.map((inc) => (
                      <IncidentRow
                        key={inc.id}
                        incident={inc}
                        isSelected={selectedId === inc.id}
                        onClick={() => setSelectedId(selectedId === inc.id ? null : inc.id)}
                      />
                    ))
                  )}
                </AnimatePresence>
              </div>
            </ScrollArea>
          </div>

          {/* Right: detail panel */}
          <AnimatePresence>
            {selectedIncident && (
              <motion.div
                key={selectedIncident.id}
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: "auto" }}
                exit={{ opacity: 0, width: 0 }}
                className="flex-1 min-w-0 overflow-hidden"
              >
                <Card className="h-full overflow-hidden flex flex-col">
                  <IncidentDetail
                    incident={selectedIncident}
                    onClose={() => setSelectedId(null)}
                  />
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </TooltipProvider>
  );
}
