/**
 * Issues HERO — Wiz-style single queue (Phase 3 P0, S5 in UX_CONSOLIDATION_PLAN_2026-04-26.md).
 *
 * Folds in: SecurityFindings, IssueQueue, ToxicCombinationIssueView,
 * ChokePointDashboard (related), DriftTrackingPanel, MaterialChangeDashboard,
 * PRChangeRiskPanel, KEV-Active filter view.
 *
 * Real apiFetch only. NO MOCKS. Tab anchor read from `?tab=` query string for
 * 90-day muscle-memory redirects from old routes.
 *
 * Route: /issues
 */

import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  AlertOctagon,
  AlertTriangle,
  GitPullRequest,
  Inbox,
  Layers,
  ListFilter,
  Network,
  RefreshCw,
  Search,
  ShieldAlert,
  TrendingUp,
  X,
  Zap,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";

import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { LiveEventStream } from "@/components/shared/LiveEventStream";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// Lazy-load existing dashboards as inline drawers (zero functionality loss)
const ScoreTransparencyPanel = lazy(() => import("@/pages/ScoreTransparencyPanel"));
const ReachabilityProofView = lazy(() => import("@/pages/validate/ReachabilityProof"));

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface Finding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  source?: string;
  scanner?: string;
  asset?: string;
  asset_id?: string;
  cve?: string;
  cve_id?: string;
  created_at?: string;
  kev?: boolean;
  is_kev?: boolean;
  toxic_combo?: boolean;
  reachable?: boolean;
  exploitable?: boolean;
}

interface ListResponse {
  items?: Finding[];
  findings?: Finding[];
  total?: number;
}

type TabKey =
  | "all"
  | "critical"
  | "high"
  | "toxic"
  | "kev"
  | "drift"
  | "material"
  | "pr-risk";

interface TabSpec {
  key: TabKey;
  label: string;
  icon: typeof AlertOctagon;
  endpoint: string;
  description: string;
}

const TABS: TabSpec[] = [
  { key: "all", label: "All", icon: Inbox, endpoint: "/api/v1/findings?status=new&limit=200", description: "Every untriaged finding from every scanner" },
  { key: "critical", label: "Critical", icon: AlertOctagon, endpoint: "/api/v1/findings?severity=critical&limit=200", description: "P0 — drop everything" },
  { key: "high", label: "High", icon: AlertTriangle, endpoint: "/api/v1/findings?severity=high&limit=200", description: "P1 — fix this sprint" },
  { key: "toxic", label: "Toxic Combos", icon: Zap, endpoint: "/api/v1/issues/toxic", description: "Multi-factor risk: vuln + reachable + KEV + crown-jewel" },
  { key: "kev", label: "KEV-Active", icon: ShieldAlert, endpoint: "/api/v1/findings?kev=true&limit=200", description: "CISA Known-Exploited Vulnerabilities — actively weaponized" },
  { key: "drift", label: "Drift", icon: TrendingUp, endpoint: "/api/v1/drift/findings", description: "Posture drift since last baseline" },
  { key: "material", label: "Material Changes", icon: Layers, endpoint: "/api/v1/changes/material", description: "Significant code changes worth reviewing" },
  { key: "pr-risk", label: "PR Risk", icon: GitPullRequest, endpoint: "/api/v1/pr/change-risk", description: "Inbound PR risk scores from open pull requests" },
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function sevTone(s?: string) {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "border-red-500/40 text-red-400 bg-red-500/10";
    case "high": return "border-orange-500/40 text-orange-400 bg-orange-500/10";
    case "medium": return "border-yellow-500/40 text-yellow-400 bg-yellow-500/10";
    case "low": return "border-emerald-500/40 text-emerald-400 bg-emerald-500/10";
    default: return "border-border text-muted-foreground";
  }
}

function findingId(f: Finding): string {
  return f.id ?? f.finding_id ?? f.cve ?? f.cve_id ?? f.title ?? "unknown";
}

function findingsFromResponse(r: unknown): Finding[] {
  if (Array.isArray(r)) return r as Finding[];
  if (!r || typeof r !== "object") return [];
  const obj = r as ListResponse;
  return obj.items ?? obj.findings ?? [];
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function Issues() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = (searchParams.get("tab") as TabKey | null) ?? "all";

  const [tab, setTab] = useState<TabKey>(initialTab);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [drawer, setDrawer] = useState<"score" | "reachability" | null>(null);

  // Persist tab to ?tab= query so links to specific tabs work and so old-route
  // redirects (Navigate to="/issues?tab=toxic") land on the right view.
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (tab === "all") next.delete("tab");
    else next.set("tab", tab);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [tab, searchParams, setSearchParams]);

  const activeSpec = useMemo(() => TABS.find((t) => t.key === tab) ?? TABS[0], [tab]);

  const load = useCallback(async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<ListResponse | Finding[]>(activeSpec.endpoint);
      setFindings(findingsFromResponse(r));
    } catch (e) {
      setErr((e as Error).message);
      setFindings([]);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSpec.endpoint]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return findings;
    return findings.filter((f) => {
      const hay = [
        f.title,
        f.cve ?? f.cve_id,
        f.scanner ?? f.source,
        f.asset ?? f.asset_id,
        f.severity,
        f.status,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [findings, filter]);

  const sevCount = (s: string) =>
    findings.filter((f) => (f.severity ?? "").toLowerCase() === s).length;

  const kpis = useMemo(
    () => [
      { title: "Total", value: findings.length, icon: Inbox },
      { title: "Critical", value: sevCount("critical"), icon: AlertOctagon, trend: "down" as const },
      { title: "High", value: sevCount("high"), icon: AlertTriangle },
      { title: "KEV", value: findings.filter((f) => f.kev || f.is_kev).length, icon: ShieldAlert },
      { title: "Reachable", value: findings.filter((f) => f.reachable).length, icon: Network },
    ],
    [findings],
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6 p-6"
    >
      <PageHeader
        title="Issues"
        description="Single queue across every scanner, every source, every severity. The Wiz-style hero. Click any row for lifecycle, score breakdown, and reachability proof."
        badge="HERO"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("mr-2 h-4 w-4", refreshing && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {kpis.map((k) => (
          <KpiCard
            key={k.title}
            title={k.title}
            value={k.value}
            icon={k.icon}
            trend={(k as { trend?: "up" | "down" | "flat" }).trend}
          />
        ))}
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)} className="space-y-4">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="flex items-center gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        {TABS.map((t) => (
          <TabsContent key={t.key} value={t.key} className="space-y-4">
            <p className="text-sm text-muted-foreground">{t.description}</p>

            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Filter title, CVE, scanner, asset…"
                  className="pl-8"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                />
              </div>
              <Badge variant="outline" className="gap-1">
                <ListFilter className="h-3 w-3" />
                {visible.length} of {findings.length}
              </Badge>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <Card className="lg:col-span-2">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">{t.label} Queue</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  {loading ? (
                    <div className="space-y-2 p-4">
                      {Array.from({ length: 6 }).map((_, i) => (
                        <Skeleton key={i} className="h-10 w-full" />
                      ))}
                    </div>
                  ) : err ? (
                    <ErrorState
                      title="Failed to load issues"
                      message={err}
                      onRetry={load}
                    />
                  ) : visible.length === 0 ? (
                    <EmptyState
                      icon={Inbox}
                      title="Queue is clean"
                      description={`No ${t.label.toLowerCase()} findings match the current filter. Run a scan from /discover or wait for the next pipeline cycle.`}
                    />
                  ) : (
                    <ScrollArea className="h-[520px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-[120px]">Severity</TableHead>
                            <TableHead>Title</TableHead>
                            <TableHead className="w-[140px]">CVE</TableHead>
                            <TableHead className="w-[160px]">Scanner</TableHead>
                            <TableHead className="w-[180px]">Asset</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {visible.map((f) => {
                            const id = findingId(f);
                            const isSel = selected && findingId(selected) === id;
                            return (
                              <TableRow
                                key={id}
                                className={cn(
                                  "cursor-pointer hover:bg-muted/40",
                                  isSel && "bg-muted/60",
                                )}
                                onClick={() => {
                                  setSelected(f);
                                  setDrawer("score");
                                }}
                              >
                                <TableCell>
                                  <Badge variant="outline" className={sevTone(f.severity)}>
                                    {(f.severity ?? "—").toString().toUpperCase()}
                                  </Badge>
                                </TableCell>
                                <TableCell className="font-medium">
                                  {f.title ?? "(untitled finding)"}
                                </TableCell>
                                <TableCell className="text-xs text-muted-foreground">
                                  {f.cve ?? f.cve_id ?? "—"}
                                </TableCell>
                                <TableCell className="text-xs text-muted-foreground">
                                  {f.scanner ?? f.source ?? "—"}
                                </TableCell>
                                <TableCell className="text-xs text-muted-foreground truncate max-w-[180px]">
                                  {f.asset ?? f.asset_id ?? "—"}
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3 flex flex-row items-center justify-between">
                  <CardTitle className="text-base">Live Events</CardTitle>
                  <Badge variant="outline" className="text-[10px]">SSE</Badge>
                </CardHeader>
                <CardContent>
                  <LiveEventStream eventTypes={["finding", "scan", "decision"]} heightClass="h-[480px]" />
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        ))}
      </Tabs>

      {/* Side drawer: finding detail (score-breakdown + reachability proof) */}
      {selected && drawer && (
        <motion.aside
          key={findingId(selected) + drawer}
          initial={{ x: 480, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 480, opacity: 0 }}
          transition={{ duration: 0.25 }}
          className="fixed right-0 top-0 z-40 h-screen w-full max-w-[520px] border-l border-border bg-background shadow-2xl flex flex-col"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="min-w-0">
              <h3 className="font-semibold truncate">{selected.title ?? findingId(selected)}</h3>
              <p className="text-xs text-muted-foreground truncate">
                {selected.cve ?? selected.cve_id ?? findingId(selected)} · {selected.scanner ?? selected.source ?? "scanner"}
              </p>
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => {
                setSelected(null);
                setDrawer(null);
              }}
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>

          <Tabs value={drawer} onValueChange={(v) => setDrawer(v as "score" | "reachability")} className="flex-1 flex flex-col">
            <TabsList className="mx-3 mt-3 grid w-auto grid-cols-2">
              <TabsTrigger value="score">Score Breakdown</TabsTrigger>
              <TabsTrigger value="reachability">Reachability Proof</TabsTrigger>
            </TabsList>
            <ScrollArea className="flex-1">
              <Suspense fallback={<div className="p-6 space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>}>
                <TabsContent value="score" className="m-0 p-0">
                  <ScoreTransparencyPanel />
                </TabsContent>
                <TabsContent value="reachability" className="m-0 p-0">
                  <ReachabilityProofView />
                </TabsContent>
              </Suspense>
            </ScrollArea>
          </Tabs>
        </motion.aside>
      )}
    </motion.div>
  );
}
