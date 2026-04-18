/**
 * Vulnerability Lifecycle — Kanban board
 *
 * 6-column Kanban: discovered → triaging → confirmed → in_remediation → fixed → closed
 * Metrics bar, severity filter, card state transitions.
 * Route: /vuln-lifecycle
 *
 * API: GET /api/v1/vuln-lifecycle/state/{state}
 *      POST /api/v1/vuln-lifecycle/{id}/transition
 * Falls back to mock data on failure.
 */

import { useState, useMemo, useCallback, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  ChevronRight,
  Clock,
  Filter,
  FlaskConical,
  Shield,
  ShieldCheck,
  XCircle,
  User,
  TrendingUp,
  Percent,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low";
type VulnState = "discovered" | "triaging" | "confirmed" | "in_remediation" | "fixed" | "closed";

interface Vuln {
  id: string;
  finding_id: string;
  severity: Severity;
  title: string;
  state: VulnState;
  age: string;
  assigned: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_VULNS: Vuln[] = [
  { id: "LC-001", finding_id: "FIND-847", severity: "critical", title: "RCE in log4j",                   state: "confirmed",      age: "3d",  assigned: "alice"      },
  { id: "LC-002", finding_id: "FIND-901", severity: "high",     title: "SQL injection in /api/users",     state: "in_remediation", age: "5d",  assigned: "bob"        },
  { id: "LC-003", finding_id: "FIND-412", severity: "medium",   title: "SSRF via redirect",               state: "triaging",       age: "1d",  assigned: "unassigned" },
  { id: "LC-004", finding_id: "FIND-233", severity: "low",      title: "Outdated TLS 1.0",               state: "fixed",          age: "10d", assigned: "carol"      },
  { id: "LC-005", finding_id: "FIND-512", severity: "critical", title: "Unauthenticated RCE in Redis",    state: "discovered",     age: "4h",  assigned: "unassigned" },
  { id: "LC-006", finding_id: "FIND-630", severity: "high",     title: "Path traversal in file upload",   state: "triaging",       age: "2d",  assigned: "alice"      },
  { id: "LC-007", finding_id: "FIND-711", severity: "medium",   title: "Broken access control /admin",    state: "confirmed",      age: "6d",  assigned: "dave"       },
  { id: "LC-008", finding_id: "FIND-820", severity: "high",     title: "XXE via XML parser",              state: "discovered",     age: "12h", assigned: "unassigned" },
  { id: "LC-009", finding_id: "FIND-155", severity: "low",      title: "Insecure cookie flags",           state: "closed",         age: "14d", assigned: "carol"      },
  { id: "LC-010", finding_id: "FIND-392", severity: "medium",   title: "Open redirect in OAuth flow",     state: "in_remediation", age: "3d",  assigned: "bob"        },
  { id: "LC-011", finding_id: "FIND-058", severity: "critical", title: "Hardcoded AWS credentials",       state: "confirmed",      age: "1d",  assigned: "alice"      },
  { id: "LC-012", finding_id: "FIND-244", severity: "low",      title: "Missing security headers",        state: "fixed",          age: "7d",  assigned: "dave"       },
];

// ═══════════════════════════════════════════════════════════
// Column config
// ═══════════════════════════════════════════════════════════

interface ColumnDef {
  state: VulnState;
  label: string;
  icon: typeof Bug;
  accent: string;
  next?: VulnState;
}

const COLUMNS: ColumnDef[] = [
  { state: "discovered",     label: "Discovered",     icon: Bug,          accent: "text-red-400    border-red-400/30",    next: "triaging"       },
  { state: "triaging",       label: "Triaging",       icon: FlaskConical, accent: "text-orange-400 border-orange-400/30", next: "confirmed"      },
  { state: "confirmed",      label: "Confirmed",      icon: AlertTriangle,accent: "text-yellow-400 border-yellow-400/30", next: "in_remediation" },
  { state: "in_remediation", label: "In Remediation", icon: Shield,       accent: "text-blue-400   border-blue-400/30",   next: "fixed"          },
  { state: "fixed",          label: "Fixed",          icon: CheckCircle2, accent: "text-green-400  border-green-400/30",  next: "closed"         },
  { state: "closed",         label: "Closed",         icon: ShieldCheck,  accent: "text-slate-400  border-slate-400/30"                          },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

const SEV_BADGE: Record<Severity, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high:     "high",
  medium:   "medium",
  low:      "low",
};

const SEV_BORDER: Record<Severity, string> = {
  critical: "border-l-red-400",
  high:     "border-l-orange-400",
  medium:   "border-l-yellow-400",
  low:      "border-l-blue-400",
};

// ═══════════════════════════════════════════════════════════
// Vuln Card
// ═══════════════════════════════════════════════════════════

function VulnCard({
  vuln,
  nextState,
  onTransition,
  index,
}: {
  vuln: Vuln;
  nextState?: VulnState;
  onTransition: (id: string, next: VulnState) => void;
  index: number;
}) {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      transition={{ delay: index * 0.04, duration: 0.25 }}
    >
      <Card className={cn(
        "border-l-2 hover:border-primary/30 transition-colors duration-200",
        SEV_BORDER[vuln.severity],
      )}>
        <CardContent className="p-3 space-y-2.5">
          {/* Top: finding ID + severity */}
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-[10px] text-muted-foreground">{vuln.finding_id}</span>
            <Badge variant={SEV_BADGE[vuln.severity]} className="text-[10px] uppercase tracking-wide">
              {vuln.severity}
            </Badge>
          </div>

          {/* Title */}
          <p className="text-xs font-medium leading-snug">{vuln.title}</p>

          {/* Meta row */}
          <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1">
              <Clock className="w-2.5 h-2.5" />
              {vuln.age}
            </span>
            <span className="flex items-center gap-1">
              <User className="w-2.5 h-2.5" />
              {vuln.assigned}
            </span>
          </div>

          {/* Transition button */}
          {nextState && (
            <Button
              size="sm"
              variant="ghost"
              className="w-full h-6 text-[10px] font-medium gap-1 border border-border/50 hover:bg-primary/10 hover:border-primary/30 hover:text-primary transition-colors"
              onClick={() => onTransition(vuln.id, nextState)}
              aria-label={`Advance ${vuln.id} to ${nextState}`}
            >
              Next: {nextState.replace("_", " ")}
              <ChevronRight className="w-2.5 h-2.5" />
            </Button>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Column
// ═══════════════════════════════════════════════════════════

function KanbanColumn({
  col,
  vulns,
  onTransition,
}: {
  col: ColumnDef;
  vulns: Vuln[];
  onTransition: (id: string, next: VulnState) => void;
}) {
  const Icon = col.icon;
  const [accentText, accentBorder] = col.accent.split(" ");

  return (
    <div className="flex flex-col min-w-[220px] w-[220px] shrink-0">
      {/* Column header */}
      <div className={cn("flex items-center justify-between px-3 py-2.5 mb-2 rounded-t border-b", accentBorder)}>
        <div className="flex items-center gap-2">
          <Icon className={cn("w-3.5 h-3.5", accentText)} />
          <span className="text-xs font-semibold">{col.label}</span>
        </div>
        <span className={cn("text-xs font-bold tabular-nums px-1.5 py-0.5 rounded bg-muted", accentText)}>
          {vulns.length}
        </span>
      </div>

      {/* Cards */}
      <ScrollArea className="flex-1 max-h-[calc(100vh-340px)] pr-1">
        <div className="space-y-2 pb-4">
          <AnimatePresence mode="popLayout">
            {vulns.length === 0 ? (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex items-center justify-center py-8"
              >
                <p className="text-xs text-muted-foreground">Empty</p>
              </motion.div>
            ) : (
              vulns.map((v, i) => (
                <VulnCard
                  key={v.id}
                  vuln={v}
                  nextState={col.next}
                  onTransition={onTransition}
                  index={i}
                />
              ))
            )}
          </AnimatePresence>
        </div>
      </ScrollArea>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function VulnLifecycle() {
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const [liveStats, setLiveStats] = useState<Record<string, any> | null>(null);
  const [loading, setLoading] = useState(true);
  const queryClient = useQueryClient();

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/vuln-lifecycle/stats?org_id=${ORG_ID}`),
    ]).then(([statsResult]) => {
      if (statsResult.status === "fulfilled") {
        setLiveStats(statsResult.value);
      }
    });
  }, []);

  const { data: vulns } = useQuery<Vuln[]>({
    queryKey: ["vuln-lifecycle"],
    queryFn: async () => {
      // Fetch all 6 columns in parallel
      const states: VulnState[] = ["discovered", "triaging", "confirmed", "in_remediation", "fixed", "closed"];
      const results = await Promise.all(
        states.map(async (s) => {
          const res = await fetch(`${API}/api/v1/vuln-lifecycle/state/${s}`);
          if (!res.ok) throw new Error(`state ${s} unavailable`);
          const data: Vuln[] = await res.json();
          return data;
        }),
      );
      return results.flat();
    },
    retry: 1,
    staleTime: 30_000,
    initialData: MOCK_VULNS,
  });

  const transition = useMutation({
    mutationFn: async ({ id, next }: { id: string; next: VulnState }) => {
      const res = await fetch(`${API}/api/v1/vuln-lifecycle/${id}/transition`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ state: next }),
      });
      if (!res.ok) throw new Error("transition failed");
      return res.json();
    },
    onMutate: async ({ id, next }) => {
      // Optimistic update — move card locally immediately
      queryClient.setQueryData<Vuln[]>(["vuln-lifecycle"], (old) =>
        old?.map((v) => (v.id === id ? { ...v, state: next } : v)) ?? [],
      );
    },
    onError: () => {
      queryClient.invalidateQueries({ queryKey: ["vuln-lifecycle"] });
    },
  });

  const handleTransition = useCallback(
    (id: string, next: VulnState) => {
      transition.mutate({ id, next });
    },
    [transition],
  );

  const filtered = useMemo(() => {
    if (!vulns) return [];
    if (sevFilter === "all") return vulns;
    return vulns.filter((v) => v.severity === sevFilter);
  }, [vulns, sevFilter]);

  // Metrics — prefer live stats from API, fall back to local computation
  const openCount  = liveStats?.open_count  ?? liveStats?.total_open  ?? vulns?.filter((v) => !["fixed", "closed"].includes(v.state)).length ?? 0;
  const inRemCount = liveStats?.in_remediation_count ?? vulns?.filter((v) => v.state === "in_remediation").length ?? 0;
  const fixedCount = liveStats?.fixed_count ?? vulns?.filter((v) => v.state === "fixed").length ?? 0;
  const closedCount = vulns?.filter((v) => v.state === "closed").length ?? 0;
  const mttr       = liveStats?.mttr_days   ?? liveStats?.avg_remediation_days ?? null;
  const mttd       = liveStats?.mttd_hours  ?? liveStats?.avg_detection_hours  ?? null;
  const fpRate     = closedCount > 0 ? Math.round((1 / closedCount) * 100) : 0;

  const SEV_FILTERS: Array<{ label: string; value: Severity | "all" }> = [
    { label: "All",      value: "all"      },
    { label: "Critical", value: "critical" },
    { label: "High",     value: "high"     },
    { label: "Medium",   value: "medium"   },
    { label: "Low",      value: "low"      },
  ];

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <TooltipProvider>
      <div className="flex flex-col gap-6 p-6 h-full overflow-hidden">
        {/* Header */}
        <PageHeader
          title="Vulnerability Lifecycle"
          description="End-to-end vulnerability tracking from discovery through remediation and closure"
          badge="CTEM"
          actions={
            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-xs text-muted-foreground mr-1">Severity:</span>
              {SEV_FILTERS.map(({ label, value }) => (
                <Button
                  key={value}
                  size="sm"
                  variant={sevFilter === value ? "default" : "outline"}
                  className={cn(
                    "h-7 px-2.5 text-xs",
                    sevFilter !== value && "text-muted-foreground"
                  )}
                  onClick={() => setSevFilter(value)}
                >
                  {label}
                </Button>
              ))}
            </div>
          }
        />

        {/* Metrics bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KpiCard
            title="Open"
            value={openCount}
            icon={Bug}
            trend="down"
            trendLabel="Active exposure"
          />
          <KpiCard
            title="In Remediation"
            value={inRemCount}
            icon={Shield}
            trend="up"
            trendLabel="Being worked"
          />
          <KpiCard
            title={mttr != null ? "MTTR (days)" : "Fixed This Week"}
            value={mttr != null ? `${mttr}d` : fixedCount}
            icon={CheckCircle2}
            trend="up"
            trendLabel={mttr != null ? "Mean time to remediate" : "Good velocity"}
          />
          <KpiCard
            title={mttd != null ? "MTTD (hours)" : "False Positive Rate"}
            value={mttd != null ? `${mttd}h` : `${fpRate}%`}
            icon={Percent}
            trend="flat"
            trendLabel={mttd != null ? "Mean time to detect" : "Across closed"}
          />
        </div>

        {/* Kanban board */}
        <div className="flex-1 overflow-hidden">
          <ScrollArea className="h-full w-full">
            <div className="flex gap-4 pb-4 min-w-max">
              {COLUMNS.map((col) => {
                const colVulns = filtered.filter((v) => v.state === col.state);
                return (
                  <KanbanColumn
                    key={col.state}
                    col={col}
                    vulns={colVulns}
                    onTransition={handleTransition}
                  />
                );
              })}
            </div>
          </ScrollArea>
        </div>
      </div>
    </TooltipProvider>
  );
}
