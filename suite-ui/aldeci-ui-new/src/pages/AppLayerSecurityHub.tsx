/**
 * AppLayerSecurityHub — Application-Layer Security unified hub
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone application-layer security pages into a single tabbed
 * surface per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10.
 *
 *   tab     | backend prefix                    | key endpoints used
 *   --------|-----------------------------------|--------------------------------------
 *   web     | /api/v1/app-security              | /stats, /apps, /findings
 *   mobile  | /api/v1/mobile-app-security       | /stats, /apps, /findings
 *   browser | /api/v1/browser-security          | /stats, /extensions, /events
 *
 * Route: /discover/app-security
 * NO MOCKS — all panels call real backend routes. EmptyState when 0 records.
 */

import { useEffect, useMemo, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Code2,
  Smartphone,
  Globe,
  RefreshCw,
  Shield,
  AlertTriangle,
  Activity,
  Layers,
  Bug,
  Eye,
  Puzzle,
} from "lucide-react";

import { Button } from "@/components/ui/button";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────────────────

function getApiKey(): string {
  return (
    (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) ||
    (import.meta.env.VITE_API_KEY as string) ||
    "dev-key"
  );
}

async function apiFetch<T = unknown>(path: string): Promise<T> {
  const res = await fetch(path, {
    headers: { "X-API-Key": getApiKey() },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Shared UI atoms ────────────────────────────────────────────────────────

function Spinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  );
}

function SevBadge({ sev }: { sev: string }) {
  const cls =
    sev === "critical"
      ? "border-red-500/30 text-red-400 bg-red-500/10"
      : sev === "high"
        ? "border-amber-500/30 text-amber-400 bg-amber-500/10"
        : sev === "medium"
          ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10"
          : "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{sev}</Badge>;
}

function RiskBadge({ level }: { level: string }) {
  const cls =
    level === "high" || level === "critical"
      ? "border-red-500/30 text-red-400 bg-red-500/10"
      : level === "medium"
        ? "border-amber-500/30 text-amber-400 bg-amber-500/10"
        : "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{level}</Badge>;
}

function KpiCard({
  title,
  value,
  icon: Icon,
  accent,
}: {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  accent?: string;
}) {
  return (
    <Card className="bg-muted/30 border-border/50">
      <CardContent className="p-4 flex items-center gap-3">
        <div className={cn("p-2 rounded-lg", accent ?? "bg-primary/10")}>
          <Icon className={cn("h-4 w-4", accent ? "text-white" : "text-primary")} />
        </div>
        <div>
          <p className="text-[11px] text-muted-foreground">{title}</p>
          <p className="text-lg font-semibold tabular-nums">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Types ──────────────────────────────────────────────────────────────────

interface AppSecStats {
  total_apps?: number;
  total_scans?: number;
  open_findings?: number;
  critical_findings?: number;
  high_findings?: number;
  [key: string]: unknown;
}

interface AppSecApp {
  app_id?: string;
  id?: string;
  name?: string;
  risk_level?: string;
  status?: string;
  last_scan?: string;
  [key: string]: unknown;
}

interface AppSecFinding {
  finding_id?: string;
  id?: string;
  title?: string;
  severity?: string;
  status?: string;
  app_id?: string;
  [key: string]: unknown;
}

interface MobileStats {
  total_apps?: number;
  total_findings?: number;
  critical_count?: number;
  high_count?: number;
  [key: string]: unknown;
}

interface MobileApp {
  app_id?: string;
  id?: string;
  name?: string;
  platform?: string;
  risk_level?: string;
  status?: string;
  [key: string]: unknown;
}

interface MobileFinding {
  finding_id?: string;
  id?: string;
  title?: string;
  severity?: string;
  status?: string;
  app_id?: string;
  [key: string]: unknown;
}

interface BrowserStats {
  total_extensions?: number;
  blocked_extensions?: number;
  total_events?: number;
  high_risk_extensions?: number;
  [key: string]: unknown;
}

interface BrowserExtension {
  ext_id?: string;
  id?: string;
  name?: string;
  risk_level?: string;
  status?: string;
  browser_type?: string;
  [key: string]: unknown;
}

interface BrowserEvent {
  event_id?: string;
  id?: string;
  event_type?: string;
  severity?: string;
  blocked?: boolean;
  source?: string;
  [key: string]: unknown;
}

// ── Tab panels ─────────────────────────────────────────────────────────────

function WebAppsPanel() {
  const [stats, setStats] = useState<AppSecStats | null>(null);
  const [apps, setApps] = useState<AppSecApp[]>([]);
  const [findings, setFindings] = useState<AppSecFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, a, f] = await Promise.all([
        apiFetch<AppSecStats>("/api/v1/app-security/stats"),
        apiFetch<{ apps?: AppSecApp[]; items?: AppSecApp[] } | AppSecApp[]>(
          "/api/v1/app-security/apps"
        ),
        apiFetch<{ findings?: AppSecFinding[]; items?: AppSecFinding[] } | AppSecFinding[]>(
          "/api/v1/app-security/findings"
        ),
      ]);
      setStats(s);
      setApps(Array.isArray(a) ? a : ((a as { apps?: AppSecApp[]; items?: AppSecApp[] }).apps ?? (a as { apps?: AppSecApp[]; items?: AppSecApp[] }).items ?? []));
      setFindings(Array.isArray(f) ? f : ((f as { findings?: AppSecFinding[]; items?: AppSecFinding[] }).findings ?? (f as { findings?: AppSecFinding[]; items?: AppSecFinding[] }).items ?? []));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <Spinner />;
  if (error) return (
    <EmptyState
      icon={AlertTriangle}
      title="Failed to load web app security"
      description={error}
      action={<Button size="sm" variant="outline" onClick={load}>Retry</Button>}
    />
  );

  return (
    <div className="flex flex-col gap-6">
      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <KpiCard title="Total Apps" value={stats?.total_apps ?? 0} icon={Layers} />
        <KpiCard title="Total Scans" value={stats?.total_scans ?? 0} icon={Activity} />
        <KpiCard title="Open Findings" value={stats?.open_findings ?? 0} icon={Bug} accent="bg-amber-500" />
        <KpiCard title="Critical" value={stats?.critical_findings ?? 0} icon={AlertTriangle} accent="bg-red-600" />
      </div>

      {/* Apps table */}
      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" /> Registered Applications
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {apps.length === 0 ? (
            <EmptyState
              icon={Layers}
              title="No applications registered"
              description="Register an application to begin SAST/DAST scanning."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Scan</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.slice(0, 20).map((a, i) => (
                  <TableRow key={a.app_id ?? a.id ?? i}>
                    <TableCell className="font-mono text-xs">{String(a.name ?? "—")}</TableCell>
                    <TableCell><RiskBadge level={String(a.risk_level ?? "unknown")} /></TableCell>
                    <TableCell className="text-xs text-muted-foreground capitalize">{String(a.status ?? "—")}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {a.last_scan ? new Date(String(a.last_scan)).toLocaleDateString() : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Findings table */}
      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Bug className="h-4 w-4 text-amber-400" /> Findings
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {findings.length === 0 ? (
            <EmptyState
              icon={Bug}
              title="No findings"
              description="No SAST/DAST findings recorded yet."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>App</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.slice(0, 20).map((f, i) => (
                  <TableRow key={f.finding_id ?? f.id ?? i}>
                    <TableCell className="text-xs max-w-[200px] truncate">{String(f.title ?? "—")}</TableCell>
                    <TableCell><SevBadge sev={String(f.severity ?? "info")} /></TableCell>
                    <TableCell className="text-xs text-muted-foreground capitalize">{String(f.status ?? "—")}</TableCell>
                    <TableCell className="text-xs text-muted-foreground font-mono">{String(f.app_id ?? "—")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function MobileAppsPanel() {
  const [stats, setStats] = useState<MobileStats | null>(null);
  const [apps, setApps] = useState<MobileApp[]>([]);
  const [findings, setFindings] = useState<MobileFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, a, f] = await Promise.all([
        apiFetch<MobileStats>("/api/v1/mobile-app-security/stats"),
        apiFetch<{ apps?: MobileApp[]; items?: MobileApp[] } | MobileApp[]>(
          "/api/v1/mobile-app-security/apps"
        ),
        apiFetch<{ findings?: MobileFinding[]; items?: MobileFinding[] } | MobileFinding[]>(
          "/api/v1/mobile-app-security/findings"
        ),
      ]);
      setStats(s);
      setApps(Array.isArray(a) ? a : ((a as { apps?: MobileApp[]; items?: MobileApp[] }).apps ?? (a as { apps?: MobileApp[]; items?: MobileApp[] }).items ?? []));
      setFindings(Array.isArray(f) ? f : ((f as { findings?: MobileFinding[]; items?: MobileFinding[] }).findings ?? (f as { findings?: MobileFinding[]; items?: MobileFinding[] }).items ?? []));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <Spinner />;
  if (error) return (
    <EmptyState
      icon={AlertTriangle}
      title="Failed to load mobile security"
      description={error}
      action={<Button size="sm" variant="outline" onClick={load}>Retry</Button>}
    />
  );

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <KpiCard title="Mobile Apps" value={stats?.total_apps ?? 0} icon={Smartphone} />
        <KpiCard title="Total Findings" value={stats?.total_findings ?? 0} icon={Bug} accent="bg-amber-500" />
        <KpiCard title="Critical" value={stats?.critical_count ?? 0} icon={AlertTriangle} accent="bg-red-600" />
        <KpiCard title="High" value={stats?.high_count ?? 0} icon={Shield} accent="bg-orange-600" />
      </div>

      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Smartphone className="h-4 w-4 text-primary" /> Mobile Applications
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {apps.length === 0 ? (
            <EmptyState
              icon={Smartphone}
              title="No mobile apps registered"
              description="Register a mobile application to begin security scanning."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Platform</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.slice(0, 20).map((a, i) => (
                  <TableRow key={a.app_id ?? a.id ?? i}>
                    <TableCell className="font-mono text-xs">{String(a.name ?? "—")}</TableCell>
                    <TableCell className="text-xs text-muted-foreground capitalize">{String(a.platform ?? "—")}</TableCell>
                    <TableCell><RiskBadge level={String(a.risk_level ?? "unknown")} /></TableCell>
                    <TableCell className="text-xs text-muted-foreground capitalize">{String(a.status ?? "—")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Bug className="h-4 w-4 text-amber-400" /> Mobile Findings
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {findings.length === 0 ? (
            <EmptyState
              icon={Bug}
              title="No mobile findings"
              description="No mobile security findings recorded yet."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>App</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.slice(0, 20).map((f, i) => (
                  <TableRow key={f.finding_id ?? f.id ?? i}>
                    <TableCell className="text-xs max-w-[200px] truncate">{String(f.title ?? "—")}</TableCell>
                    <TableCell><SevBadge sev={String(f.severity ?? "info")} /></TableCell>
                    <TableCell className="text-xs text-muted-foreground capitalize">{String(f.status ?? "—")}</TableCell>
                    <TableCell className="text-xs text-muted-foreground font-mono">{String(f.app_id ?? "—")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function BrowserPolicyPanel() {
  const [stats, setStats] = useState<BrowserStats | null>(null);
  const [extensions, setExtensions] = useState<BrowserExtension[]>([]);
  const [events, setEvents] = useState<BrowserEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, ex, ev] = await Promise.all([
        apiFetch<BrowserStats>("/api/v1/browser-security/stats"),
        apiFetch<{ extensions?: BrowserExtension[]; items?: BrowserExtension[] } | BrowserExtension[]>(
          "/api/v1/browser-security/extensions"
        ),
        apiFetch<{ events?: BrowserEvent[]; items?: BrowserEvent[] } | BrowserEvent[]>(
          "/api/v1/browser-security/events"
        ),
      ]);
      setStats(s);
      setExtensions(Array.isArray(ex) ? ex : ((ex as { extensions?: BrowserExtension[]; items?: BrowserExtension[] }).extensions ?? (ex as { extensions?: BrowserExtension[]; items?: BrowserExtension[] }).items ?? []));
      setEvents(Array.isArray(ev) ? ev : ((ev as { events?: BrowserEvent[]; items?: BrowserEvent[] }).events ?? (ev as { events?: BrowserEvent[]; items?: BrowserEvent[] }).items ?? []));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <Spinner />;
  if (error) return (
    <EmptyState
      icon={AlertTriangle}
      title="Failed to load browser security"
      description={error}
      action={<Button size="sm" variant="outline" onClick={load}>Retry</Button>}
    />
  );

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <KpiCard title="Extensions" value={stats?.total_extensions ?? 0} icon={Puzzle} />
        <KpiCard title="Blocked" value={stats?.blocked_extensions ?? 0} icon={Shield} accent="bg-red-600" />
        <KpiCard title="Events" value={stats?.total_events ?? 0} icon={Activity} />
        <KpiCard title="High Risk Ext." value={stats?.high_risk_extensions ?? 0} icon={AlertTriangle} accent="bg-amber-500" />
      </div>

      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Puzzle className="h-4 w-4 text-primary" /> Browser Extensions
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {extensions.length === 0 ? (
            <EmptyState
              icon={Puzzle}
              title="No extensions tracked"
              description="No browser extensions are registered for policy enforcement."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Browser</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {extensions.slice(0, 20).map((e, i) => (
                  <TableRow key={e.ext_id ?? e.id ?? i}>
                    <TableCell className="text-xs font-mono">{String(e.name ?? "—")}</TableCell>
                    <TableCell className="text-xs text-muted-foreground capitalize">{String(e.browser_type ?? "—")}</TableCell>
                    <TableCell><RiskBadge level={String(e.risk_level ?? "unknown")} /></TableCell>
                    <TableCell className="text-xs text-muted-foreground capitalize">{String(e.status ?? "—")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Eye className="h-4 w-4 text-amber-400" /> Security Events
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {events.length === 0 ? (
            <EmptyState
              icon={Eye}
              title="No browser events"
              description="No browser security events recorded yet."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Blocked</TableHead>
                  <TableHead>Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.slice(0, 20).map((e, i) => (
                  <TableRow key={e.event_id ?? e.id ?? i}>
                    <TableCell className="text-xs capitalize">{String(e.event_type ?? "—")}</TableCell>
                    <TableCell><SevBadge sev={String(e.severity ?? "info")} /></TableCell>
                    <TableCell>
                      <Badge className={cn("text-[10px] border", e.blocked ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-green-500/30 text-green-400 bg-green-500/10")}>
                        {e.blocked ? "Blocked" : "Allowed"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground font-mono">{String(e.source ?? "—")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Hub shell ──────────────────────────────────────────────────────────────

type TabKey = "web" | "mobile" | "browser";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "web",
    label: "Web Apps (SAST/DAST)",
    icon: Code2,
    description: "Application security posture, SAST/DAST scans, and findings — /api/v1/app-security.",
  },
  {
    key: "mobile",
    label: "Mobile Apps",
    icon: Smartphone,
    description: "Mobile application security scanning, app inventory, and findings — /api/v1/mobile-app-security.",
  },
  {
    key: "browser",
    label: "Browser Policy",
    icon: Globe,
    description: "Browser extension risk management and security events — /api/v1/browser-security.",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map((t) => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function AppLayerSecurityHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab")) ? (params.get("tab") as TabKey) : "web";
  const [tab, setTab] = useState<TabKey>(initial);

  // Single effect: sync tab state <-> URL param without object-identity churn.
  // deps use params.toString() (primitive) — avoids infinite replaceState loop.
  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        setTab(urlTab);
      } else {
        const next = new URLSearchParams(params.toString());
        next.set("tab", tab);
        setParams(next, { replace: true });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, params.toString()]);

  const activeMeta = useMemo(() => TABS.find((t) => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Application Security"
        description="Unified application-layer security workspace — web SAST/DAST, mobile scanning, and browser policy enforcement."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        <TabsContent value="web">
          <WebAppsPanel />
        </TabsContent>
        <TabsContent value="mobile">
          <MobileAppsPanel />
        </TabsContent>
        <TabsContent value="browser">
          <BrowserPolicyPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
