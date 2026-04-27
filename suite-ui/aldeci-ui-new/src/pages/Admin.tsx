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
  Building2,
  CreditCard,
  Key,
  Plug,
  RefreshCw,
  Server,
  Users,
  Webhook,
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
  scopes?: string[];
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

interface ListResponse<T> {
  items?: T[];
  data?: T[];
  total?: number;
}

type TabKey = "orgs" | "users" | "tokens" | "connectors" | "webhooks" | "billing" | "system";

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
      const [orgsR, tokR, admTokR, connR, hookR, billR, haR] = await Promise.all([
        apiFetch<ListResponse<Organization> | Organization[]>("/api/v1/organizations").catch(() => null),
        apiFetch<ListResponse<UserToken> | UserToken[]>("/api/v1/users/me/tokens").catch(() => null),
        apiFetch<ListResponse<UserToken> | UserToken[]>("/api/v1/admin/tokens").catch(() => null),
        apiFetch<ListResponse<ConnectorMapping> | ConnectorMapping[]>("/api/v1/connectors/mapping").catch(() => null),
        apiFetch<ListResponse<WebhookEvent> | WebhookEvent[]>("/api/v1/webhooks/event-catalogue").catch(() => null),
        apiFetch<BillingInfo>("/api/v1/billing/current").catch(() => null),
        apiFetch<HAStatus>("/api/v1/system/ha-status").catch(() => null),
      ]);
      setOrgs(listFromResponse<Organization>(orgsR));
      setTokens(listFromResponse<UserToken>(tokR));
      setAdminTokens(listFromResponse<UserToken>(admTokR));
      setConnectors(listFromResponse<ConnectorMapping>(connR));
      setWebhooks(listFromResponse<WebhookEvent>(hookR));
      setBilling(billR);
      setHa(haR);
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
                            <TableCell className="text-xs">{t.scopes?.length ? t.scopes.join(", ") : "—"}</TableCell>
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

        {/* Webhooks */}
        <TabsContent value="webhooks" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS[4].description}</p>
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
          <p className="text-sm text-muted-foreground">{TABS[5].description}</p>
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
          <p className="text-sm text-muted-foreground">{TABS[6].description}</p>
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
