import { useState, useEffect, useRef, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  Zap,
  Lock,
  Server,
  Bot,
  Globe,
  Shield,
  Activity,
  Pause,
  Play,
  ChevronRight,
  X,
  Filter,
  Radio,
  FileText,
  GitBranch,
  Settings,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { nerveCenterApi } from "@/lib/api";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type EventType = "finding" | "decision" | "mpte" | "deployment" | "policy" | "scan" | "threat_intel" | "compliance" | "all";
type Severity = "critical" | "high" | "medium" | "low" | "info";

interface FeedEvent {
  id: string;
  type: Exclude<EventType, "all">;
  severity: Severity;
  title: string;
  detail: string;
  app?: string;
  cve?: string;
  actor?: string;
  timestamp: string;
  tsMs: number;
  meta?: Record<string, string>;
}

// ─── Mock Event Pool ──────────────────────────────────────────────────────────

const BASE_TS = Date.now();

const MOCK_EVENTS: FeedEvent[] = [
  { id: "EVT-11241", type: "finding", severity: "critical", title: "Critical RCE detected — CVE-2024-50379", detail: "Apache Tomcat 9.0.85 remote code execution vulnerability ingested from Tenable.io scan on payments-gateway-prod. CVSS 9.8. Exploit code published on GitHub.", app: "payments-gateway-prod", cve: "CVE-2024-50379", actor: "Tenable.io", timestamp: "Just now", tsMs: BASE_TS - 60_000, meta: { CVSS: "9.8", EPSS: "0.94", Exploitability: "Active" } },
  { id: "EVT-11240", type: "decision", severity: "info", title: "AI triage: 47 findings marked as noise", detail: "MPTE consensus + LLM analysis identified 47 low-confidence findings as false positives. Engineering hours saved: ~2.3h. Model confidence: 94.1%.", actor: "ALdeci AI", timestamp: "8m ago", tsMs: BASE_TS - 480_000, meta: { "False Positives": "47", "Confidence": "94.1%", "Hours Saved": "2.3h" } },
  { id: "EVT-11239", type: "deployment", severity: "info", title: "Autofix merged: CVE-2024-44082 patch applied", detail: "ALdeci autofix PR #2842 merged and deployed to payments-gateway-prod via ArgoCD. Pod restart complete. Post-deploy scan: no regression.", app: "payments-gateway-prod", cve: "CVE-2024-44082", actor: "autofix-bot", timestamp: "15m ago", tsMs: BASE_TS - 900_000, meta: { PR: "#2842", Branch: "fix/cve-2024-44082", Pipeline: "argocd-prod" } },
  { id: "EVT-11238", type: "policy", severity: "medium", title: "Policy updated: S3-encryption-at-rest v2.1", detail: "Policy 'S3-encryption-at-rest' updated by admin@aldeci.io to enforce SSE-KMS on all new buckets. Change applies to 14 active policies. Effective immediately.", actor: "admin@aldeci.io", timestamp: "32m ago", tsMs: BASE_TS - 1920_000, meta: { Version: "2.1", Scope: "All S3 buckets", "Change Type": "Enforcement" } },
  { id: "EVT-11237", type: "scan", severity: "info", title: "Scheduled scan completed — 3,412 assets", detail: "Full surface scan on prod environment: 3,412 assets scanned in 4m 12s. 18 new findings (3 high, 15 medium). 6 findings auto-resolved post-patch.", app: "prod-environment", actor: "ALdeci Scanner", timestamp: "1h ago", tsMs: BASE_TS - 3600_000, meta: { Assets: "3,412", "New Findings": "18", "Auto-Resolved": "6", Duration: "4m 12s" } },
  { id: "EVT-11236", type: "mpte", severity: "high", title: "MPTE verdict: CVE-2024-48990 downgraded to Medium", detail: "Multi-perspective threat evaluation on CVE-2024-48990 (sudo privilege escalation). Exploitation requires local access — MPTE consensus: Medium. Adjusted CVSS: 5.9 (from 7.8).", cve: "CVE-2024-48990", actor: "MPTE Engine", timestamp: "1h 20m ago", tsMs: BASE_TS - 4800_000, meta: { "Original CVSS": "7.8", "Adjusted CVSS": "5.9", Verdict: "Downgraded", Consensus: "4/5 models" } },
  { id: "EVT-11235", type: "threat_intel", severity: "high", title: "Threat intel: TA558 targeting Apache Tomcat", detail: "CISA advisory + ALdeci threat feeds: TA558 ransomware group actively exploiting CVE-2024-50379 in financial services sector. 12 known victims past 48h. Patch immediately.", actor: "Threat Feeds", timestamp: "2h ago", tsMs: BASE_TS - 7200_000, meta: { Actor: "TA558", Sector: "Financial Services", IOCs: "47 IPs", Source: "CISA + ALdeci Feeds" } },
  { id: "EVT-11234", type: "compliance", severity: "info", title: "SOC2 CC6.1 evidence auto-collected", detail: "ALdeci evidence engine auto-collected and cryptographically verified SOC2 CC6.1 (Logical Access Controls) evidence for March 2025 audit cycle. 12 artifacts captured.", actor: "Evidence Engine", timestamp: "3h ago", tsMs: BASE_TS - 10800_000, meta: { Framework: "SOC2 Type II", Control: "CC6.1", Artifacts: "12", Verified: "Yes" } },
  { id: "EVT-11233", type: "finding", severity: "high", title: "SQL injection vulnerability — identity-service", detail: "Authenticated SQL injection in /api/v2/users endpoint discovered by DAST scan. Parameterized queries missing in 3 query builders. Ticket auto-assigned to AppSec.", app: "identity-service", cve: "CVE-2024-49138", actor: "ALdeci DAST", timestamp: "3h 45m ago", tsMs: BASE_TS - 13500_000, meta: { CVSS: "9.1", Endpoint: "/api/v2/users", Method: "POST", Auth: "Required" } },
  { id: "EVT-11232", type: "deployment", severity: "info", title: "Infrastructure deployed: k8s node security patch", detail: "Kubernetes node security patch v1.28.7 applied across 12 worker nodes in prod cluster. Nodes: k8s-worker-01 through k8s-worker-12. Zero downtime rolling update.", app: "k8s-prod-cluster", actor: "GitOps Pipeline", timestamp: "4h ago", tsMs: BASE_TS - 14400_000, meta: { Nodes: "12", Version: "v1.28.7", Downtime: "Zero", Strategy: "Rolling" } },
  { id: "EVT-11231", type: "policy", severity: "low", title: "New policy created: Container-image-signing", detail: "Policy 'Container-image-signing' created by sec@aldeci.io to enforce Cosign signatures on all container images in prod. 14 pipelines updated.", actor: "sec@aldeci.io", timestamp: "5h ago", tsMs: BASE_TS - 18000_000, meta: { Scope: "All containers", Tool: "Cosign v2", Pipelines: "14" } },
  { id: "EVT-11230", type: "scan", severity: "medium", title: "Dependency audit: 8 transitive vulns in npm", detail: "ALdeci SCA scan identified 8 transitive dependencies with known CVEs in customer-portal npm packages. 3 medium, 5 low. Auto-PR raised for npm audit fix.", app: "customer-portal", actor: "ALdeci SCA", timestamp: "6h ago", tsMs: BASE_TS - 21600_000, meta: { Deps: "8 affected", Severity: "3 Medium, 5 Low", Action: "PR raised" } },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

const EVENT_TYPE_CONFIG: Record<Exclude<EventType, "all">, { label: string; icon: React.ElementType; color: string; bg: string }> = {
  finding: { label: "New Finding", icon: AlertTriangle, color: "text-red-400", bg: "bg-red-500/10" },
  decision: { label: "Decision", icon: CheckCircle2, color: "text-green-400", bg: "bg-green-500/10" },
  mpte: { label: "MPTE Result", icon: Bot, color: "text-purple-400", bg: "bg-purple-500/10" },
  deployment: { label: "Deployment", icon: Zap, color: "text-primary", bg: "bg-primary/10" },
  policy: { label: "Policy Change", icon: Lock, color: "text-yellow-400", bg: "bg-yellow-500/10" },
  scan: { label: "Scan", icon: Server, color: "text-blue-400", bg: "bg-blue-500/10" },
  threat_intel: { label: "Threat Intel", icon: Globe, color: "text-orange-400", bg: "bg-orange-500/10" },
  compliance: { label: "Compliance", icon: Shield, color: "text-teal-400", bg: "bg-teal-500/10" },
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-muted-foreground",
};

function generateNewEvent(index: number): FeedEvent {
  const pool: Omit<FeedEvent, "id" | "timestamp" | "tsMs">[] = [
    { type: "scan", severity: "info", title: "Incremental scan: data-pipeline-service", detail: "6 assets rescanned. 0 new findings. 2 findings verified remediated.", app: "data-pipeline-service", actor: "ALdeci Scanner" },
    { type: "finding", severity: "medium", title: "Missing HTTP security headers — customer-portal", detail: "X-Frame-Options and Content-Security-Policy headers absent on 4 endpoints.", app: "customer-portal", actor: "ALdeci DAST" },
    { type: "decision", severity: "info", title: "AI marked 12 medium findings as accepted risk", detail: "Risk owner approval captured. 12 findings accepted risk per risk appetite policy.", actor: "Risk Engine" },
  ];
  const template = pool[index % pool.length];
  return {
    ...template,
    id: `EVT-${11242 + index}`,
    timestamp: "Just now",
    tsMs: Date.now(),
  };
}

// ─── Event Detail Panel ───────────────────────────────────────────────────────

function EventDetail({ event, onClose }: { event: FeedEvent; onClose: () => void }) {
  const cfg = EVENT_TYPE_CONFIG[event.type];
  return (
    <motion.div
      initial={{ opacity: 0, x: 16 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 16 }}
      className="lg:col-span-1"
    >
      <Card className="p-5 sticky top-4">
        <CardHeader className="p-0 pb-3">
          <div className="flex items-start justify-between gap-2">
            <CardTitle className="text-sm font-semibold leading-snug">{event.title}</CardTitle>
            <Button variant="ghost" size="sm" className="h-6 w-6 p-0 shrink-0" onClick={onClose}>
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0 space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className={cn("text-xs", cfg.color)}>{cfg.label}</Badge>
            <Badge variant={event.severity === "critical" ? "critical" : event.severity === "high" ? "high" : event.severity === "medium" ? "warning" : "secondary"} className="text-xs">
              {event.severity}
            </Badge>
            {event.cve && <Badge variant="outline" className="text-xs font-mono">{event.cve}</Badge>}
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">{event.detail}</p>
          {event.app && (
            <div className="text-xs">
              <span className="text-muted-foreground">Application: </span>
              <span className="font-medium">{event.app}</span>
            </div>
          )}
          {event.actor && (
            <div className="text-xs">
              <span className="text-muted-foreground">Actor: </span>
              <span className="font-medium">{event.actor}</span>
            </div>
          )}
          {event.meta && Object.keys(event.meta).length > 0 && (
            <div className="space-y-1.5 rounded-md bg-muted/30 p-3">
              {Object.entries(event.meta).map(([k, v]) => (
                <div key={k} className="flex justify-between text-xs">
                  <span className="text-muted-foreground">{k}</span>
                  <span className="font-medium tabular-nums">{v}</span>
                </div>
              ))}
            </div>
          )}
          <p className="text-xs text-muted-foreground">{event.timestamp}</p>
          <div className="flex gap-2">
            <Button size="sm" className="flex-1 text-xs" onClick={() => toast.success(`Opened investigation for ${event.id}`)}>
              Investigate
            </Button>
            <Button variant="outline" size="sm" className="text-xs" onClick={() => toast.info("Copied event ID")}>
              Copy ID
            </Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function LiveFeed() {
  const [events, setEvents] = useState<FeedEvent[]>(MOCK_EVENTS);
  const [typeFilter, setTypeFilter] = useState<EventType>("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<FeedEvent | null>(null);
  const [injectCount, setInjectCount] = useState(0);
  const feedRef = useRef<HTMLDivElement>(null);

  useQuery({
    queryKey: ["nerve-center-activity"],
    queryFn: () => nerveCenterApi.activity({ limit: "50" }),
    retry: false,
  });

  // Simulate live events
  useEffect(() => {
    if (!autoScroll) return;
    const id = setInterval(() => {
      const newEvt = generateNewEvent(injectCount);
      setEvents((prev) => [newEvt, ...prev.slice(0, 49)]);
      setInjectCount((n) => n + 1);
    }, 8_000);
    return () => clearInterval(id);
  }, [autoScroll, injectCount]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [events, autoScroll]);

  const filteredEvents = typeFilter === "all" ? events : events.filter((e) => e.type === typeFilter);

  const counts = {
    critical: events.filter((e) => e.severity === "critical").length,
    high: events.filter((e) => e.severity === "high").length,
    total: events.length,
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="space-y-6"
    >
      {/* Header */}
      <PageHeader
        title="Live Feed"
        description="Real-time security event stream — findings, AI decisions, deployments, and policy changes"
        badge="LIVE"
        actions={
          <div className="flex items-center gap-2">
            <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as EventType)}>
              <SelectTrigger className="w-[160px]">
                <Filter className="h-3.5 w-3.5 mr-1" />
                <SelectValue placeholder="All Events" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Events</SelectItem>
                <SelectItem value="finding">New Finding</SelectItem>
                <SelectItem value="decision">Decision</SelectItem>
                <SelectItem value="mpte">MPTE Result</SelectItem>
                <SelectItem value="deployment">Deployment</SelectItem>
                <SelectItem value="policy">Policy Change</SelectItem>
                <SelectItem value="scan">Scan</SelectItem>
                <SelectItem value="threat_intel">Threat Intel</SelectItem>
                <SelectItem value="compliance">Compliance</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant={autoScroll ? "default" : "outline"}
              size="sm"
              onClick={() => {
                setAutoScroll((v) => !v);
                toast.info(autoScroll ? "Auto-scroll paused" : "Auto-scroll resumed");
              }}
              className="gap-1.5"
            >
              {autoScroll ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
              {autoScroll ? "Pause" : "Resume"}
            </Button>
          </div>
        }
      />

      {/* Status Bar */}
      <div className="flex items-center gap-4 rounded-lg border border-border/50 bg-card px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Radio className={cn("h-3.5 w-3.5", autoScroll ? "text-green-400 animate-pulse" : "text-muted-foreground")} />
          <span className="text-xs font-medium">{autoScroll ? "Live" : "Paused"}</span>
        </div>
        <div className="h-4 w-px bg-border/50" />
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="tabular-nums"><span className="font-semibold text-foreground">{counts.total}</span> events</span>
          <span className="text-red-400 tabular-nums"><span className="font-semibold">{counts.critical}</span> critical</span>
          <span className="text-orange-400 tabular-nums"><span className="font-semibold">{counts.high}</span> high</span>
        </div>
        <div className="ml-auto flex items-center gap-3 text-xs">
          {(Object.keys(EVENT_TYPE_CONFIG) as Exclude<EventType, "all">[]).slice(0, 4).map((type) => {
            const cfg = EVENT_TYPE_CONFIG[type];
            const count = events.filter((e) => e.type === type).length;
            return (
              <button
                key={type}
                onClick={() => setTypeFilter(typeFilter === type ? "all" : type)}
                className={cn("flex items-center gap-1 transition-opacity", typeFilter !== "all" && typeFilter !== type && "opacity-40")}
              >
                <cfg.icon className={cn("h-3 w-3", cfg.color)} />
                <span className="text-muted-foreground">{count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Feed + Detail Panel */}
      <div className={cn("grid gap-4", selectedEvent ? "lg:grid-cols-3" : "grid-cols-1")}>
        {/* Event Stream */}
        <div className={cn(selectedEvent ? "lg:col-span-2" : "col-span-1")}>
          <Card className="p-0 overflow-hidden">
            <div
              ref={feedRef}
              className="h-[600px] overflow-y-auto"
              style={{ scrollbarWidth: "thin" }}
            >
              <AnimatePresence initial={false}>
                {filteredEvents.map((event, i) => {
                  const cfg = EVENT_TYPE_CONFIG[event.type];
                  const isSelected = selectedEvent?.id === event.id;
                  return (
                    <motion.div
                      key={event.id}
                      initial={{ opacity: 0, y: -12 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.25 }}
                      onClick={() => setSelectedEvent(isSelected ? null : event)}
                      className={cn(
                        "flex items-start gap-3 px-4 py-3.5 border-b border-border/30 cursor-pointer transition-colors group",
                        isSelected ? "bg-primary/5 border-l-2 border-l-primary" : "hover:bg-muted/20",
                        i === 0 && event.tsMs > BASE_TS && "bg-green-500/5"
                      )}
                    >
                      {/* Type icon */}
                      <div className={cn("shrink-0 rounded-lg p-2 mt-0.5", cfg.bg)}>
                        <cfg.icon className={cn("h-3.5 w-3.5", cfg.color)} />
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0 space-y-0.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-semibold">{event.title}</span>
                          {event.severity !== "info" && (
                            <Badge
                              variant={event.severity === "critical" ? "critical" : event.severity === "high" ? "high" : event.severity === "medium" ? "warning" : "secondary"}
                              className="text-xs"
                            >
                              {event.severity}
                            </Badge>
                          )}
                          {event.cve && (
                            <span className="text-xs font-mono text-muted-foreground">{event.cve}</span>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground line-clamp-1">{event.detail}</p>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground/70">
                          <span className={cn("font-medium", cfg.color)}>{cfg.label}</span>
                          {event.app && <><span>·</span><span>{event.app}</span></>}
                          {event.actor && <><span>·</span><span>{event.actor}</span></>}
                        </div>
                      </div>

                      {/* Timestamp */}
                      <div className="flex items-center gap-1 shrink-0">
                        <span className="text-xs text-muted-foreground tabular-nums">{event.timestamp}</span>
                        <ChevronRight className={cn("h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity", isSelected && "opacity-100 rotate-90")} />
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>

              {filteredEvents.length === 0 && (
                <div className="flex flex-col items-center justify-center h-40 text-muted-foreground text-sm">
                  <Activity className="h-8 w-8 mb-2 opacity-30" />
                  No events match the current filter
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Detail Panel */}
        <AnimatePresence>
          {selectedEvent && (
            <EventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
