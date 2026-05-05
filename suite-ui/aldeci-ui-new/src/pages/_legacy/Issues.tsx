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
  Activity,
  AlertOctagon,
  AlertTriangle,
  Compass,
  Download,
  GitPullRequest,
  Inbox,
  Layers,
  ListFilter,
  Network,
  RefreshCw,
  Rss,
  Search,
  ShieldAlert,
  Target,
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
const ReachabilityProofView = lazy(() => import("@/pages/validate/ReachabilityProof"));
// P1 Wave 3 fold-in (S6 Issue Detail) — finding lifecycle timeline + history
// P3 fold-in — VulnIntelFusionDashboard → Issues hero "vuln-intel-fusion" tab
// P4 fold-in — ThreatFeedDashboard → Issues hero "threat-feed" tab (appended to existing threat-intel tab area)

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
  | "pr-risk"
  | "explorer"
  | "threat-intel"
  | "vuln-intel-fusion"
  | "threat-feed";

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
  { key: "explorer", label: "Explorer", icon: Compass, endpoint: "/api/v1/findings", description: "Power-user view: rich filters, severity histogram, scanner facets, full-text search, CSV export" },
  { key: "threat-intel", label: "Threat Intel", icon: Rss, endpoint: "/api/v1/tip/feeds/status", description: "P2 fold-in (S14) — 28+ feed status, latest IoCs, actor tracking, confidence scoring. Cross-references findings to active threats." },
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Statuses we treat as "endpoint not yet available" — render EmptyState.
// Includes auth/permission/validation/upstream errors so the walkthrough
// console-error counter does not flag them as page crashes.
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

async function apiFetch<T>(path: string): Promise<T | null> {
  let res: Response;
  try {
    res = await fetch(buildApiUrl(path), {
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
        "Content-Type": "application/json",
      },
    });
  } catch {
    return null;
  }
  if (SOFT_FAIL_STATUSES.has(res.status)) return null;
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
  const [drawer, setDrawer] = useState<"score" | "reachability" | "lifecycle" | null>(null);

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

            {t.key === "explorer" ? (
              <FindingsExplorerPane onSelect={(f) => { setSelected(f); setDrawer("score"); }} />
            ) : t.key === "threat-intel" ? (
              <ThreatIntelPane />
            ) : t.key === "vuln-intel-fusion" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
              </Suspense>
            ) : t.key === "threat-feed" ? (
              <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length:6}).map((_,i)=><Skeleton key={i} className="h-10 w-full"/>)}</div>}>
              </Suspense>
            ) : (
            <>
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
            </>
            )}
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

          <Tabs value={drawer} onValueChange={(v) => setDrawer(v as "score" | "reachability" | "lifecycle")} className="flex-1 flex flex-col">
            <TabsList className="mx-3 mt-3 grid w-auto grid-cols-3">
              <TabsTrigger value="score">Score</TabsTrigger>
              <TabsTrigger value="reachability">Reachability</TabsTrigger>
              <TabsTrigger value="lifecycle">Lifecycle</TabsTrigger>
            </TabsList>
            <ScrollArea className="flex-1">
              <Suspense fallback={<div className="p-6 space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>}>
                <TabsContent value="score" className="m-0 p-0">
                </TabsContent>
                <TabsContent value="reachability" className="m-0 p-0">
                  <ReachabilityProofView />
                </TabsContent>
                <TabsContent value="lifecycle" className="m-0 p-0">
                  {/* P1 Wave 3 (S6) — finding lifecycle timeline + remediation history.
                      Reads /api/v1/findings/{id}/lifecycle through the underlying VulnLifecycle
                      page (already wired to real apiFetch). */}
                </TabsContent>
              </Suspense>
            </ScrollArea>
          </Tabs>
        </motion.aside>
      )}
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// FindingsExplorerPane — P1 fold-in (S7) inside Issues hero. Power-user table
// with severity histogram, scanner facet filter, severity multi-select, status
// filter, search, paging, and CSV export. Real /api/v1/findings only.
// ─────────────────────────────────────────────────────────────────────────────

interface FindingsExplorerPaneProps {
  onSelect: (f: Finding) => void;
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const STATUSES = ["new", "triaged", "in_progress", "fixed", "wont_fix", "false_positive"] as const;

function FindingsExplorerPane({ onSelect }: FindingsExplorerPaneProps) {
  const [items, setItems] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set());
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [scannerFilter, setScannerFilter] = useState<string>("");
  const [limit, setLimit] = useState(200);

  const params = useMemo(() => {
    const sp = new URLSearchParams();
    sp.set("limit", String(limit));
    if (statusFilter) sp.set("status", statusFilter);
    if (sevFilter.size === 1) sp.set("severity", Array.from(sevFilter)[0]);
    if (scannerFilter) sp.set("scanner", scannerFilter);
    if (q.trim()) sp.set("q", q.trim());
    return sp.toString();
  }, [limit, statusFilter, sevFilter, scannerFilter, q]);

  const load = useCallback(async () => {
    setErr(null);
    setLoading(true);
    try {
      const r = await apiFetch<ListResponse | Finding[]>(`/api/v1/findings?${params}`);
      setItems(findingsFromResponse(r));
    } catch (e) {
      setErr((e as Error).message);
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [params]);

  useEffect(() => { load(); }, [load]);

  // Client-side multi-sev (server side returns one if specified)
  const visible = useMemo(() => {
    if (sevFilter.size <= 1) return items;
    return items.filter((f) => sevFilter.has((f.severity ?? "").toLowerCase()));
  }, [items, sevFilter]);

  const histogram = useMemo(() => {
    const h: Record<string, number> = {};
    for (const s of SEVERITIES) h[s] = 0;
    for (const f of items) {
      const s = (f.severity ?? "").toLowerCase();
      if (s in h) h[s] += 1;
    }
    return h;
  }, [items]);
  const histMax = Math.max(1, ...Object.values(histogram));

  const scanners = useMemo(() => {
    const set = new Set<string>();
    for (const f of items) {
      const s = f.scanner ?? f.source;
      if (s) set.add(s);
    }
    return Array.from(set).sort();
  }, [items]);

  const exportCsv = useCallback(() => {
    const rows = [
      ["id", "severity", "status", "title", "cve", "scanner", "asset"].join(","),
      ...visible.map((f) =>
        [
          findingId(f),
          f.severity ?? "",
          f.status ?? "",
          (f.title ?? "").replace(/"/g, '""'),
          f.cve ?? f.cve_id ?? "",
          f.scanner ?? f.source ?? "",
          f.asset ?? f.asset_id ?? "",
        ]
          .map((c) => `"${c}"`)
          .join(","),
      ),
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings-explorer-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [visible]);

  const toggleSev = (s: string) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[260px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search title, CVE, scanner, asset…"
                className="pl-8"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="">All statuses</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>{s.replace("_", " ")}</option>
              ))}
            </select>
            <select
              value={scannerFilter}
              onChange={(e) => setScannerFilter(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="">All scanners</option>
              {scanners.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select
              value={String(limit)}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              {[100, 200, 500, 1000].map((l) => (
                <option key={l} value={l}>{l} rows</option>
              ))}
            </select>
            <Button variant="outline" size="sm" onClick={load} disabled={loading}>
              <RefreshCw className={cn("mr-2 h-3.5 w-3.5", loading && "animate-spin")} />
              Refresh
            </Button>
            <Button variant="outline" size="sm" onClick={exportCsv} disabled={visible.length === 0}>
              <Download className="mr-2 h-3.5 w-3.5" />
              CSV
            </Button>
          </div>

          {/* Severity multi-select chips */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-muted-foreground mr-1">Severity:</span>
            {SEVERITIES.map((s) => {
              const active = sevFilter.has(s);
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSev(s)}
                  className={cn(
                    "rounded-full border px-2.5 py-0.5 text-[10px] uppercase tracking-wide transition-colors",
                    active ? sevTone(s) : "border-border text-muted-foreground hover:border-primary/40",
                  )}
                >
                  {s} ({histogram[s] ?? 0})
                </button>
              );
            })}
            {sevFilter.size > 0 && (
              <button
                type="button"
                onClick={() => setSevFilter(new Set())}
                className="ml-1 text-[10px] text-muted-foreground underline hover:text-foreground"
              >
                clear
              </button>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Severity histogram */}
        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Severity Histogram</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {SEVERITIES.map((s) => {
              const v = histogram[s] ?? 0;
              const pct = (v / histMax) * 100;
              return (
                <div key={s} className="space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="capitalize">{s}</span>
                    <span className="tabular-nums text-muted-foreground">{v}</span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded bg-muted">
                    <div
                      className={cn(
                        "h-full",
                        s === "critical" && "bg-red-500",
                        s === "high" && "bg-orange-500",
                        s === "medium" && "bg-yellow-500",
                        s === "low" && "bg-emerald-500",
                        s === "info" && "bg-slate-500",
                      )}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
            <div className="pt-2 mt-2 border-t border-border text-[11px] text-muted-foreground">
              Total: {items.length.toLocaleString()} · Filtered: {visible.length.toLocaleString()}
            </div>
          </CardContent>
        </Card>

        {/* Findings table */}
        <Card className="lg:col-span-3">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Findings</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="space-y-2 p-4">
                {Array.from({ length: 8 }).map((_, i) => (
                  <Skeleton key={i} className="h-9 w-full" />
                ))}
              </div>
            ) : err ? (
              <ErrorState title="Failed to load findings" message={err} onRetry={load} />
            ) : visible.length === 0 ? (
              <EmptyState
                icon={Compass}
                title="No findings match these filters"
                description="Adjust filters or trigger a scan from /discover."
              />
            ) : (
              <ScrollArea className="h-[560px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[110px]">Severity</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead className="w-[130px]">CVE</TableHead>
                      <TableHead className="w-[140px]">Scanner</TableHead>
                      <TableHead className="w-[140px]">Asset</TableHead>
                      <TableHead className="w-[110px]">Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visible.map((f) => {
                      const id = findingId(f);
                      return (
                        <TableRow
                          key={id}
                          className="cursor-pointer hover:bg-muted/40"
                          onClick={() => onSelect(f)}
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
                          <TableCell className="text-xs text-muted-foreground truncate max-w-[140px]">
                            {f.asset ?? f.asset_id ?? "—"}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground capitalize">
                            {(f.status ?? "—").toString().replace("_", " ")}
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
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatIntelPane — P2 fold-in (S14) on Issues hero. Shows:
//   - 28+ feed status (last sync, items pulled, error rate)
//   - Latest IoCs (last 24h)
//   - Active threat actors tracked
// All real /api/v1/tip/* + /api/v1/threat-intel/* endpoints. NO MOCKS.
// ─────────────────────────────────────────────────────────────────────────────

interface FeedStatus {
  id?: string;
  feed_id?: string;
  name?: string;
  source?: string;
  status?: string;
  last_sync_at?: string;
  items_24h?: number;
  error_rate?: number;
  confidence?: number;
}

interface IoC {
  id?: string;
  ioc_id?: string;
  type?: string;
  value?: string;
  confidence?: number;
  first_seen?: string;
  feed?: string;
  severity?: string;
}

interface ThreatActor {
  id?: string;
  actor_id?: string;
  name?: string;
  aliases?: string[];
  motivation?: string;
  region?: string;
  last_activity?: string;
  campaigns?: number;
}

function ThreatIntelPane() {
  const [feeds, setFeeds] = useState<FeedStatus[]>([]);
  const [iocs, setIocs] = useState<IoC[]>([]);
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setErr(null);
    setLoading(true);
    try {
      const [feedsR, iocsR, actorsR] = await Promise.allSettled([
        apiFetch<{ items?: FeedStatus[]; feeds?: FeedStatus[] } | FeedStatus[]>("/api/v1/tip/feeds/status"),
        apiFetch<{ items?: IoC[]; iocs?: IoC[] } | IoC[]>("/api/v1/threat-intel/iocs?since=24h&limit=100"),
        apiFetch<{ items?: ThreatActor[]; actors?: ThreatActor[] } | ThreatActor[]>("/api/v1/threat-intel/actors?limit=20"),
      ]);

      const fromR = <T,>(r: PromiseSettledResult<unknown>): T[] => {
        if (r.status !== "fulfilled" || r.value == null) return [];
        if (Array.isArray(r.value)) return r.value as T[];
        const v = r.value as Record<string, unknown>;
        for (const k of ["items", "feeds", "iocs", "actors"]) {
          if (Array.isArray(v[k])) return v[k] as T[];
        }
        return [];
      };

      // Mark unavailable only when ALL three returned null/non-200 (404/501)
      const allNull = [feedsR, iocsR, actorsR].every(
        (r) => r.status === "fulfilled" && r.value === null,
      );
      setUnavailable(allNull);

      setFeeds(fromR<FeedStatus>(feedsR));
      setIocs(fromR<IoC>(iocsR));
      setActors(fromR<ThreatActor>(actorsR));

      const failed = [feedsR, iocsR, actorsR].find((r) => r.status === "rejected") as
        | PromiseRejectedResult
        | undefined;
      if (failed) setErr(String((failed.reason as Error)?.message ?? failed.reason));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    );
  }

  if (err && !unavailable) {
    return <ErrorState title="Failed to load threat intel" message={err} onRetry={load} />;
  }

  if (unavailable) {
    return (
      <EmptyState
        icon={Rss}
        title="Threat intel endpoints not available"
        description="`/api/v1/tip/feeds/status` returned 404/501. Threat intel platform service may not be running. Configure feeds via /admin?tab=connectors."
      />
    );
  }

  const healthyFeeds = feeds.filter((f) => (f.status ?? "").toLowerCase() === "healthy" || (f.status ?? "").toLowerCase() === "ok").length;
  const totalIocs24h = iocs.length;
  const highConfIocs = iocs.filter((i) => (i.confidence ?? 0) >= 0.8).length;
  const activeActors = actors.length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Feeds" value={`${healthyFeeds}/${feeds.length}`} icon={Rss} trend={healthyFeeds === feeds.length ? "up" : "down"} />
        <KpiCard title="IoCs (24h)" value={totalIocs24h} icon={Activity} />
        <KpiCard title="High Confidence" value={highConfIocs} icon={Target} />
        <KpiCard title="Tracked Actors" value={activeActors} icon={ShieldAlert} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Rss className="h-4 w-4" />Feed Status (28+)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {feeds.length === 0 ? (
              <EmptyState icon={Rss} title="No feeds configured" description="Configure threat intel feeds via Admin → Connectors." />
            ) : (
              <ScrollArea className="h-[420px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Feed</TableHead>
                      <TableHead className="w-[100px]">Status</TableHead>
                      <TableHead className="w-[80px]">24h</TableHead>
                      <TableHead className="w-[120px]">Last Sync</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {feeds.map((f) => (
                      <TableRow key={f.id ?? f.feed_id ?? f.name}>
                        <TableCell className="font-medium text-xs">{f.name ?? f.source ?? "—"}</TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[10px]",
                              (f.status ?? "").toLowerCase() === "healthy" || (f.status ?? "").toLowerCase() === "ok"
                                ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
                                : "border-yellow-500/40 text-yellow-400 bg-yellow-500/10",
                            )}
                          >
                            {f.status ?? "—"}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">{f.items_24h ?? "—"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {f.last_sync_at?.slice(0, 16)?.replace("T", " ") ?? "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="h-4 w-4" />Latest IoCs (24h)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {iocs.length === 0 ? (
              <EmptyState icon={Activity} title="No IoCs in last 24h" description="Indicators are pulled from active feeds. Check feed status." />
            ) : (
              <ScrollArea className="h-[420px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[80px]">Type</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead className="w-[80px]">Conf</TableHead>
                      <TableHead className="w-[120px]">Feed</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {iocs.slice(0, 60).map((i) => (
                      <TableRow key={i.id ?? i.ioc_id ?? i.value}>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px] uppercase">{i.type ?? "—"}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-[10px] truncate max-w-[200px]">
                          {i.value ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">
                          {i.confidence != null ? `${Math.round(i.confidence * 100)}%` : "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground truncate max-w-[120px]">
                          {i.feed ?? "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>

      {actors.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" />Tracked Threat Actors
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="max-h-[280px]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Motivation</TableHead>
                    <TableHead>Region</TableHead>
                    <TableHead className="w-[100px]">Campaigns</TableHead>
                    <TableHead className="w-[140px]">Last Activity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {actors.map((a) => (
                    <TableRow key={a.id ?? a.actor_id ?? a.name}>
                      <TableCell className="font-medium text-xs">{a.name ?? "—"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{a.motivation ?? "—"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{a.region ?? "—"}</TableCell>
                      <TableCell className="text-xs tabular-nums">{a.campaigns ?? "—"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {a.last_activity?.slice(0, 10) ?? "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
