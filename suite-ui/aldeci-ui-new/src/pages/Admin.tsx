/**
 * Admin Console HERO — Multi-tenant administration (Phase 3 P0 Wave 3).
 *
 * One page for everything an admin needs: organizations, users, tokens,
 * connector mappings, webhook events, billing, and system health.
 *
 * Folds in: UserTokenManager.tsx, ConnectorMappingUI.tsx,
 * WebhookEventCatalogExplorer.tsx, OrgHierarchyExplorer.tsx,
 * OrgHierarchyDashboard.tsx, ScopeManager.tsx, settings/SystemHealth.tsx,
 * settings/Users.tsx, settings/Teams.tsx.
 *
 * Real apiFetch only. NO MOCKS. Tab anchor read from `?tab=` query string.
 *
 * Route: /admin (admin-RBAC-gated) + redirects from existing admin paths.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Boxes,
  Building2,
  CheckCircle2,
  Cloud,
  CreditCard,
  Database,
  GitBranch,
  Key,
  Network,
  Package,
  Plug,
  RefreshCw,
  Rss,
  Server,
  Shield,
  ShieldCheck,
  Ticket,
  Users,
  Webhook,
  XCircle,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";

import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface Organization {
  id?: string;
  org_id?: string;
  name?: string;
  slug?: string;
  tier?: string;
  user_count?: number;
  created_at?: string;
  status?: string;
}

interface UserToken {
  id?: string;
  token_id?: string;
  name?: string;
  prefix?: string;
  /** Backend may return scopes as `string[]` (modern) OR `string` (legacy comma-separated rows). */
  scopes?: string[] | string;
  created_at?: string;
  last_used_at?: string;
  expires_at?: string;
}

interface ConnectorMapping {
  id?: string;
  connector_id?: string;
  type?: string;
  name?: string;
  status?: string;
  field_mappings?: Record<string, string>;
}

interface WebhookEvent {
  event?: string;
  description?: string;
  category?: string;
  payload_schema?: string;
}

interface BillingInfo {
  tier?: string;
  monthly_cost?: number;
  seats?: number;
  seats_used?: number;
  status?: string;
  next_invoice_date?: string;
}

interface HAStatus {
  status?: string;
  uptime?: string;
  uptime_pct?: number;
  nodes?: number;
  active_nodes?: number;
  message?: string;
  components?: Array<{ name: string; status: string }>;
}

interface ConnectorHealth {
  id?: string;
  name?: string;
  type?: string;        // scanner / git / cloud / siem / ticketing / notification / feed / secrets
  category?: string;    // OSS | commercial
  vendor?: string;
  status?: string;      // healthy / degraded / down / unknown
  last_sync_at?: string;
  latency_ms?: number;
  error_rate?: number;
  events_last_hour?: number;
}

interface ListResponse<T> {
  items?: T[];
  data?: T[];
  total?: number;
}

type TabKey =
  | "orgs"
  | "users"
  | "tokens"
  | "connectors"
  | "integrations"
  | "webhooks"
  | "billing"
  | "system";

interface TabSpec {
  key: TabKey;
  label: string;
  icon: typeof Building2;
  description: string;
}

const TABS: TabSpec[] = [
  { key: "orgs", label: "Organizations", icon: Building2, description: "Tenant orgs, hierarchy, slugs, tiers" },
  { key: "users", label: "Users", icon: Users, description: "Users, teams, scopes, role assignments" },
  { key: "tokens", label: "Tokens", icon: Key, description: "API keys & PATs — your own + tenant-wide" },
  { key: "connectors", label: "Connectors", icon: Plug, description: "Field mappings & data-source bindings" },
  { key: "integrations", label: "Integrations Hub", icon: Boxes, description: "Visual catalog of OSS + commercial connectors with live health badges" },
  { key: "webhooks", label: "Webhooks", icon: Webhook, description: "Event catalogue, subscriptions, retries" },
  { key: "billing", label: "Billing", icon: CreditCard, description: "Plan, seats, monthly cost, invoices" },
  { key: "system", label: "System", icon: Server, description: "HA status, uptime, component health" },
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

function listFromResponse<T>(r: unknown): T[] {
  if (Array.isArray(r)) return r as T[];
  if (!r || typeof r !== "object") return [];
  const obj = r as ListResponse<T> & Record<string, unknown>;
  if (Array.isArray(obj.items)) return obj.items;
  if (Array.isArray(obj.data)) return obj.data;
  // Some endpoints return { events: [], catalogue: [], mappings: [] }
  for (const key of ["events", "catalogue", "mappings", "tokens", "users", "organizations"]) {
    if (Array.isArray(obj[key])) return obj[key] as T[];
  }
  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function Admin() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = (searchParams.get("tab") as TabKey | null) ?? "orgs";

  const [tab, setTab] = useState<TabKey>(initialTab);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [tokens, setTokens] = useState<UserToken[]>([]);
  const [adminTokens, setAdminTokens] = useState<UserToken[]>([]);
  const [connectors, setConnectors] = useState<ConnectorMapping[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookEvent[]>([]);
  const [billing, setBilling] = useState<BillingInfo | null>(null);
  const [ha, setHa] = useState<HAStatus | null>(null);
  const [connectorHealth, setConnectorHealth] = useState<ConnectorHealth[]>([]);

  // Persist tab to ?tab= query
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (tab === "orgs") next.delete("tab");
    else next.set("tab", tab);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [tab, searchParams, setSearchParams]);

  const load = useCallback(async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [orgsR, tokR, admTokR, connR, hookR, billR, haR, healthR] = await Promise.all([
        apiFetch<ListResponse<Organization> | Organization[]>("/api/v1/organizations").catch(() => null),
        apiFetch<ListResponse<UserToken> | UserToken[]>("/api/v1/users/me/tokens").catch(() => null),
        apiFetch<ListResponse<UserToken> | UserToken[]>("/api/v1/admin/tokens").catch(() => null),
        apiFetch<ListResponse<ConnectorMapping> | ConnectorMapping[]>("/api/v1/connectors/mapping").catch(() => null),
        apiFetch<ListResponse<WebhookEvent> | WebhookEvent[]>("/api/v1/webhooks/event-catalogue").catch(() => null),
        apiFetch<BillingInfo>("/api/v1/billing/current").catch(() => null),
        apiFetch<HAStatus>("/api/v1/system/ha-status").catch(() => null),
        apiFetch<ListResponse<ConnectorHealth> | ConnectorHealth[]>("/api/v1/connectors/health").catch(() => null),
      ]);
      setOrgs(listFromResponse<Organization>(orgsR));
      setTokens(listFromResponse<UserToken>(tokR));
      setAdminTokens(listFromResponse<UserToken>(admTokR));
      setConnectors(listFromResponse<ConnectorMapping>(connR));
      setWebhooks(listFromResponse<WebhookEvent>(hookR));
      setBilling(billR);
      setHa(haR);
      setConnectorHealth(listFromResponse<ConnectorHealth>(healthR));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  const kpis = useMemo(
    () => [
      { title: "Orgs", value: orgs.length, icon: Building2 },
      { title: "API Tokens", value: tokens.length + adminTokens.length, icon: Key },
      { title: "Connectors", value: connectors.length, icon: Plug },
      { title: "Webhook Events", value: webhooks.length, icon: Webhook },
    ],
    [orgs.length, tokens.length, adminTokens.length, connectors.length, webhooks.length],
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6 p-6"
    >
      <PageHeader
        title="Admin Console"
        description="Multi-tenant administration. Organizations, users, tokens, connectors, webhooks, billing, and system health — one page."
        badge="HERO"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("mr-2 h-4 w-4", refreshing && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {kpis.map((k) => (
          <KpiCard key={k.title} title={k.title} value={k.value} icon={k.icon} />
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

        {/* Organizations */}
        <TabsContent value="orgs" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS[0].description}</p>
          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-base">Organizations</CardTitle></CardHeader>
            <CardContent className="p-0">
              {loading ? (
                <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : err ? (
                <ErrorState title="Failed to load organizations" message={err} onRetry={load} />
              ) : orgs.length === 0 ? (
                <EmptyState icon={Building2} title="No organizations" description="Create the first tenant via /api/v1/organizations or onboarding." />
              ) : (
                <ScrollArea className="h-[420px]">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Slug / ID</TableHead>
                        <TableHead className="w-[100px]">Tier</TableHead>
                        <TableHead className="w-[100px]">Users</TableHead>
                        <TableHead className="w-[120px]">Created</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {orgs.map((o) => (
                        <TableRow key={o.id ?? o.org_id ?? o.slug}>
                          <TableCell className="font-medium">{o.name ?? "—"}</TableCell>
                          <TableCell className="text-xs font-mono text-muted-foreground">{o.slug ?? o.id ?? o.org_id ?? "—"}</TableCell>
                          <TableCell><Badge variant="outline" className="uppercase text-[10px]">{o.tier ?? "—"}</Badge></TableCell>
                          <TableCell className="text-xs">{o.user_count ?? "—"}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">{o.created_at?.slice(0, 10) ?? "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Users (lazy-load existing settings/Users page) */}
        <TabsContent value="users" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS[1].description}</p>
          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-base">User Directory</CardTitle></CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                User CRUD lives in <a className="underline hover:text-primary" href="/settings/users">/settings/users</a>.
                Team scopes in <a className="underline hover:text-primary" href="/settings/teams">/settings/teams</a>.
              </p>
              <p className="text-xs text-muted-foreground mt-2">
                This section will inline the user table once the org-scoped users endpoint is consolidated.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tokens */}
        <TabsContent value="tokens" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS[2].description}</p>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3"><CardTitle className="text-base">My Tokens</CardTitle></CardHeader>
              <CardContent className="p-0">
                {loading ? (
                  <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
                ) : tokens.length === 0 ? (
                  <EmptyState icon={Key} title="No personal tokens" description="Create one via POST /api/v1/users/me/tokens." />
                ) : (
                  <ScrollArea className="h-[360px]">
                    <Table>
                      <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Prefix</TableHead><TableHead>Last Used</TableHead></TableRow></TableHeader>
                      <TableBody>
                        {tokens.map((t) => (
                          <TableRow key={t.id ?? t.token_id ?? t.prefix}>
                            <TableCell className="font-medium">{t.name ?? "—"}</TableCell>
                            <TableCell className="text-xs font-mono">{t.prefix ?? "—"}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">{t.last_used_at?.slice(0, 10) ?? "never"}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3"><CardTitle className="text-base">Tenant-Wide Tokens (Admin)</CardTitle></CardHeader>
              <CardContent className="p-0">
                {loading ? (
                  <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
                ) : adminTokens.length === 0 ? (
                  <EmptyState icon={Key} title="No tenant tokens" description="Service-account tokens visible only to admins." />
                ) : (
                  <ScrollArea className="h-[360px]">
                    <Table>
                      <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Scopes</TableHead><TableHead>Expires</TableHead></TableRow></TableHeader>
                      <TableBody>
                        {adminTokens.map((t) => (
                          <TableRow key={t.id ?? t.token_id ?? t.prefix}>
                            <TableCell className="font-medium">{t.name ?? "—"}</TableCell>
                            <TableCell className="text-xs">{Array.isArray(t.scopes) ? (t.scopes.length ? t.scopes.join(", ") : "—") : (typeof t.scopes === "string" && t.scopes ? t.scopes : "—")}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">{t.expires_at?.slice(0, 10) ?? "no expiry"}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Connectors */}
        <TabsContent value="connectors" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS[3].description}</p>
          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-base">Connector Field Mappings</CardTitle></CardHeader>
            <CardContent className="p-0">
              {loading ? (
                <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : connectors.length === 0 ? (
                <EmptyState icon={Plug} title="No connector mappings" description="Configure connectors via /settings/integrations or POST /api/v1/connectors." />
              ) : (
                <ScrollArea className="h-[420px]">
                  <Table>
                    <TableHeader><TableRow><TableHead>Connector</TableHead><TableHead>Type</TableHead><TableHead>Status</TableHead><TableHead>Field Mappings</TableHead></TableRow></TableHeader>
                    <TableBody>
                      {connectors.map((c) => (
                        <TableRow key={c.id ?? c.connector_id ?? c.name}>
                          <TableCell className="font-medium">{c.name ?? c.connector_id ?? "—"}</TableCell>
                          <TableCell><Badge variant="outline" className="uppercase text-[10px]">{c.type ?? "—"}</Badge></TableCell>
                          <TableCell className="text-xs">{c.status ?? "—"}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">{c.field_mappings ? Object.keys(c.field_mappings).length + " fields" : "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Integrations Hub (P1 Wave 2 — visual catalog of OSS + commercial connectors) */}
        <TabsContent value="integrations" className="space-y-4">
          <IntegrationsHubPane
            health={connectorHealth}
            mappings={connectors}
            webhooks={webhooks}
            loading={loading}
          />
        </TabsContent>

        {/* Webhooks */}
        <TabsContent value="webhooks" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS.find((t) => t.key === "webhooks")?.description}</p>
          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-base">Webhook Event Catalogue</CardTitle></CardHeader>
            <CardContent className="p-0">
              {loading ? (
                <div className="space-y-2 p-4">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
              ) : webhooks.length === 0 ? (
                <EmptyState icon={Webhook} title="No webhook events" description="The catalogue endpoint returned empty. Check /api/v1/webhooks/event-catalogue." />
              ) : (
                <ScrollArea className="h-[420px]">
                  <Table>
                    <TableHeader><TableRow><TableHead>Event</TableHead><TableHead className="w-[140px]">Category</TableHead><TableHead>Description</TableHead></TableRow></TableHeader>
                    <TableBody>
                      {webhooks.map((w, i) => (
                        <TableRow key={w.event ?? i}>
                          <TableCell className="font-mono text-xs">{w.event ?? "—"}</TableCell>
                          <TableCell><Badge variant="outline" className="text-[10px]">{w.category ?? "—"}</Badge></TableCell>
                          <TableCell className="text-xs text-muted-foreground">{w.description ?? "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Billing */}
        <TabsContent value="billing" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS.find((t) => t.key === "billing")?.description}</p>
          <Card>
            <CardHeader className="pb-3"><CardTitle className="text-base">Subscription</CardTitle></CardHeader>
            <CardContent>
              {loading ? (
                <Skeleton className="h-32 w-full" />
              ) : !billing ? (
                <EmptyState icon={CreditCard} title="No billing info" description="Billing API not configured. POST to /api/v1/billing/setup to enable." />
              ) : (
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="space-y-1"><p className="text-xs uppercase tracking-wider text-muted-foreground">Tier</p><p className="text-2xl font-bold">{billing.tier ?? "—"}</p></div>
                  <div className="space-y-1"><p className="text-xs uppercase tracking-wider text-muted-foreground">Monthly</p><p className="text-2xl font-bold tabular-nums">${billing.monthly_cost?.toFixed(0) ?? "—"}</p></div>
                  <div className="space-y-1"><p className="text-xs uppercase tracking-wider text-muted-foreground">Seats</p><p className="text-2xl font-bold tabular-nums">{billing.seats_used ?? "—"} / {billing.seats ?? "—"}</p></div>
                  <div className="space-y-1"><p className="text-xs uppercase tracking-wider text-muted-foreground">Status</p><Badge variant="outline" className="text-sm">{billing.status ?? "—"}</Badge></div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* System */}
        <TabsContent value="system" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS.find((t) => t.key === "system")?.description}</p>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3"><CardTitle className="text-base">HA Status</CardTitle></CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-24 w-full" />
                ) : !ha ? (
                  <EmptyState icon={Server} title="No HA data" description="HA endpoint not reachable." />
                ) : (
                  <div className="space-y-2">
                    <div className="flex justify-between"><span className="text-sm text-muted-foreground">Status</span><Badge variant="outline" className={cn(
                      ha.status === "healthy" || ha.status === "ok" || ha.status === "OK"
                        ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
                        : "border-yellow-500/40 text-yellow-400 bg-yellow-500/10",
                    )}>{ha.status ?? "—"}</Badge></div>
                    <div className="flex justify-between"><span className="text-sm text-muted-foreground">Uptime</span><span className="text-sm font-mono">{ha.uptime ?? (ha.uptime_pct ? `${ha.uptime_pct.toFixed(1)}%` : "—")}</span></div>
                    <div className="flex justify-between"><span className="text-sm text-muted-foreground">Active Nodes</span><span className="text-sm font-mono">{ha.active_nodes ?? "—"} / {ha.nodes ?? "—"}</span></div>
                  </div>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3"><CardTitle className="text-base">Components</CardTitle></CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-24 w-full" />
                ) : !ha?.components?.length ? (
                  <p className="text-sm text-muted-foreground">No component breakdown reported.</p>
                ) : (
                  <ul className="space-y-1">
                    {ha.components.map((c) => (
                      <li key={c.name} className="flex items-center justify-between">
                        <span className="text-sm">{c.name}</span>
                        <Badge variant="outline" className={cn(
                          "text-[10px]",
                          c.status === "healthy" || c.status === "ok"
                            ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
                            : "border-yellow-500/40 text-yellow-400 bg-yellow-500/10",
                        )}>{c.status}</Badge>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Integrations Hub pane — visual catalog of OSS + commercial connectors with
// live health badges (P1 Wave 2).
// API: /api/v1/connectors/health, /api/v1/webhooks/event-catalogue
// ─────────────────────────────────────────────────────────────────────────────

const OSS_CATALOGUE: Array<Omit<ConnectorHealth, "status"> & { description: string }> = [
  { id: "trivy", name: "Trivy", type: "scanner", category: "OSS", vendor: "Aqua", description: "Container + IaC + SBOM SCA" },
  { id: "grype", name: "Grype", type: "scanner", category: "OSS", vendor: "Anchore", description: "Container vulnerability scanner" },
  { id: "syft", name: "Syft", type: "scanner", category: "OSS", vendor: "Anchore", description: "SBOM generator" },
  { id: "semgrep", name: "Semgrep", type: "scanner", category: "OSS", vendor: "r2c", description: "Static code analysis (SAST)" },
  { id: "checkov", name: "Checkov", type: "scanner", category: "OSS", vendor: "Bridgecrew", description: "IaC misconfigurations" },
  { id: "trufflehog", name: "TruffleHog", type: "secrets", category: "OSS", vendor: "Truffle Security", description: "Secrets in git history" },
  { id: "gitleaks", name: "Gitleaks", type: "secrets", category: "OSS", vendor: "Zricethezav", description: "Secret detection in repos" },
];

const COMMERCIAL_CATALOGUE: Array<Omit<ConnectorHealth, "status"> & { description: string }> = [
  { id: "snyk", name: "Snyk", type: "scanner", category: "commercial", vendor: "Snyk", description: "Vuln, IaC, container, code" },
  { id: "wiz", name: "Wiz", type: "cloud", category: "commercial", vendor: "Wiz", description: "Agentless CNAPP" },
  { id: "github", name: "GitHub", type: "git", category: "commercial", vendor: "GitHub", description: "Repos, code scanning, dependabot" },
  { id: "gitlab", name: "GitLab", type: "git", category: "commercial", vendor: "GitLab", description: "Repos, container scanning, SAST" },
  { id: "jira", name: "Jira", type: "ticketing", category: "commercial", vendor: "Atlassian", description: "Ticket lifecycle automation" },
  { id: "servicenow", name: "ServiceNow", type: "ticketing", category: "commercial", vendor: "ServiceNow", description: "ITSM / VR pipeline" },
  { id: "splunk", name: "Splunk", type: "siem", category: "commercial", vendor: "Splunk", description: "SIEM event ingestion" },
  { id: "sentinel", name: "Sentinel", type: "siem", category: "commercial", vendor: "Microsoft", description: "Cloud-native SIEM" },
  { id: "datadog", name: "Datadog", type: "siem", category: "commercial", vendor: "Datadog", description: "Observability + security" },
  { id: "aws", name: "AWS", type: "cloud", category: "commercial", vendor: "Amazon", description: "Multi-account org scan" },
  { id: "azure", name: "Azure", type: "cloud", category: "commercial", vendor: "Microsoft", description: "Subscription posture" },
  { id: "gcp", name: "GCP", type: "cloud", category: "commercial", vendor: "Google", description: "Project + folder posture" },
];

function statusTone(status?: string) {
  switch ((status ?? "unknown").toLowerCase()) {
    case "healthy":
    case "ok":
    case "online":
      return { cn: "border-emerald-500/40 text-emerald-400 bg-emerald-500/10", icon: CheckCircle2, label: "HEALTHY" };
    case "degraded":
    case "partial":
    case "warning":
      return { cn: "border-amber-500/40 text-amber-400 bg-amber-500/10", icon: AlertTriangle, label: "DEGRADED" };
    case "down":
    case "error":
    case "failed":
    case "offline":
      return { cn: "border-red-500/40 text-red-400 bg-red-500/10", icon: XCircle, label: "DOWN" };
    default:
      return { cn: "border-border text-muted-foreground", icon: Activity, label: "UNKNOWN" };
  }
}

function typeIcon(t?: string): typeof Plug {
  switch ((t ?? "").toLowerCase()) {
    case "scanner": return Shield;
    case "git": return GitBranch;
    case "cloud": return Cloud;
    case "siem": return Database;
    case "ticketing": return Ticket;
    case "feed": return Rss;
    case "secrets": return ShieldCheck;
    case "registry": return Package;
    case "notification": return Network;
    default: return Plug;
  }
}

function ConnectorCard({
  spec,
  health,
}: {
  spec: Omit<ConnectorHealth, "status"> & { description: string };
  health?: ConnectorHealth;
}) {
  const tone = statusTone(health?.status);
  const Icon = typeIcon(spec.type);
  const StatusIcon = tone.icon;
  return (
    <div className="rounded-md border border-border bg-muted/20 p-3 hover:border-primary/60 transition-colors space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className="h-4 w-4 text-primary shrink-0" />
          <div className="min-w-0">
            <p className="text-sm font-semibold truncate">{spec.name}</p>
            <p className="text-[10px] text-muted-foreground truncate">{spec.vendor}</p>
          </div>
        </div>
        <Badge variant="outline" className={cn("text-[9px] shrink-0", tone.cn)}>
          <StatusIcon className="h-2.5 w-2.5 mr-1" />
          {tone.label}
        </Badge>
      </div>
      <p className="text-[11px] text-muted-foreground line-clamp-2">{spec.description}</p>
      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
        <Badge variant="outline" className="text-[9px] uppercase">
          {spec.type ?? "—"}
        </Badge>
        {health?.latency_ms != null && (
          <span className="font-mono tabular-nums">{health.latency_ms}ms</span>
        )}
      </div>
      {health?.last_sync_at && (
        <p className="text-[10px] text-muted-foreground">
          last sync {new Date(health.last_sync_at).toLocaleTimeString()}
        </p>
      )}
    </div>
  );
}

function IntegrationsHubPane({
  health,
  mappings,
  webhooks,
  loading,
}: {
  health: ConnectorHealth[];
  mappings: ConnectorMapping[];
  webhooks: WebhookEvent[];
  loading: boolean;
}) {
  const healthMap = useMemo(() => {
    const m = new Map<string, ConnectorHealth>();
    for (const h of health) {
      const key = (h.id ?? h.name ?? "").toLowerCase();
      if (key) m.set(key, h);
    }
    return m;
  }, [health]);

  const healthyCount = health.filter((h) => statusTone(h.status).label === "HEALTHY").length;
  const degradedCount = health.filter((h) => statusTone(h.status).label === "DEGRADED").length;
  const downCount = health.filter((h) => statusTone(h.status).label === "DOWN").length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <KpiCard title="Total Integrations" value={OSS_CATALOGUE.length + COMMERCIAL_CATALOGUE.length} icon={Boxes} />
        <KpiCard title="OSS Connectors" value={OSS_CATALOGUE.length} icon={GitBranch} />
        <KpiCard title="Commercial" value={COMMERCIAL_CATALOGUE.length} icon={Cloud} />
        <KpiCard title="Healthy" value={healthyCount} icon={CheckCircle2} trend={healthyCount > 0 ? "up" : "flat"} />
        <KpiCard title="Down / Degraded" value={downCount + degradedCount} icon={AlertTriangle} trend={(downCount + degradedCount) > 0 ? "down" : "flat"} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-primary" />
            OSS Connectors
            <Badge variant="outline" className="text-[9px]">{OSS_CATALOGUE.length}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {Array.from({ length: 7 }).map((_, i) => (
                <Skeleton key={i} className="h-24 w-full" />
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {OSS_CATALOGUE.map((c) => (
                <ConnectorCard key={c.id} spec={c} health={healthMap.get((c.id ?? "").toLowerCase())} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Cloud className="h-4 w-4 text-primary" />
            Commercial Connectors
            <Badge variant="outline" className="text-[9px]">{COMMERCIAL_CATALOGUE.length}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {Array.from({ length: 12 }).map((_, i) => (
                <Skeleton key={i} className="h-24 w-full" />
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {COMMERCIAL_CATALOGUE.map((c) => (
                <ConnectorCard key={c.id} spec={c} health={healthMap.get((c.id ?? "").toLowerCase())} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Plug className="h-4 w-4" />
              Active Field Mappings
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
              </div>
            ) : mappings.length === 0 ? (
              <EmptyState
                icon={Plug}
                title="No field mappings"
                description="Configure connector mappings via the Connectors tab."
              />
            ) : (
              <div className="space-y-2 text-xs">
                {mappings.slice(0, 5).map((m) => (
                  <div key={m.id ?? m.name} className="flex items-center justify-between gap-2 rounded-md border border-border bg-muted/30 p-2.5">
                    <span className="font-medium truncate">{m.name ?? m.connector_id ?? "—"}</span>
                    <Badge variant="outline" className="text-[9px]">
                      {Object.keys(m.field_mappings ?? {}).length} fields
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Webhook className="h-4 w-4" />
              Webhook Events
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-2">
                {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
              </div>
            ) : webhooks.length === 0 ? (
              <EmptyState
                icon={Webhook}
                title="No webhook events"
                description="Catalogue is empty — see the Webhooks tab."
              />
            ) : (
              <div className="space-y-1 text-xs">
                {webhooks.slice(0, 6).map((w, i) => (
                  <div key={w.event ?? i} className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded border border-border bg-muted/30">
                    <span className="font-mono truncate">{w.event ?? "—"}</span>
                    <Badge variant="outline" className="text-[9px] shrink-0">{w.category ?? "—"}</Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
