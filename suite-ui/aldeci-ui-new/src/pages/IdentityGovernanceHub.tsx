/**
 * IdentityGovernanceHub — Identity Governance & Analytics unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone identity governance / analytics pages into a single
 * tabbed hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 * (S11 Cloud Posture — IAM Deep / Identity Governance sub-cluster).
 *
 *   tab        | source page                  | endpoint
 *   -----------|------------------------------|----------------------------------------------
 *   governance | IdentityGovernance           | /api/v1/identity-governance/{reviews,entitlements,stats}
 *   analytics  | IdentityAnalyticsDashboard   | /api/v1/identity-analytics/{stats,risks,profiles}
 *   digital    | DigitalIdentityDashboard     | /api/v1/digital-identity/{identities,stats}
 *
 * Route: /discover/identity-governance
 * Persona target: GRC Analyst (#12), Security Architect (#11), IAM Admin
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (IAM Deep)
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import type { ComponentType } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, BarChart3, Fingerprint, Grid3x3, AlertCircle, Users, TrendingUp } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { AccessMatrixPanel } from "@/components/access-matrix/AccessMatrixPanel";
import { GovernanceReviewsPanel } from "@/components/identity/GovernanceReviewsPanel";
import { identityAnalyticsApi, digitalIdentityApi } from "@/lib/api";

// ── Identity Analytics Panel ────────────────────────────────────────────────

interface IdentityProfile {
  user_id?: string;
  id?: string;
  display_name?: string;
  email?: string;
  risk_score?: number;
  status?: string;
  verified?: boolean;
  [key: string]: unknown;
}

interface AnalyticsProfilesResponse {
  profiles?: IdentityProfile[];
  items?: IdentityProfile[];
  total?: number;
  count?: number;
}

function IdentityAnalyticsPanel() {
  const { data, isLoading, isError, error } = useQuery<AnalyticsProfilesResponse>({
    queryKey: ["identity-analytics", "profiles"],
    queryFn: async () => {
      const res = await identityAnalyticsApi.profiles("default", 50);
      return res.data as AnalyticsProfilesResponse;
    },
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle className="text-sm">Identity Risk Profiles</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 py-10 text-destructive">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p className="text-sm">Failed to load identity analytics: {error instanceof Error ? error.message : "Unknown error"}</p>
        </CardContent>
      </Card>
    );
  }

  const profiles = data?.profiles ?? data?.items ?? [];
  const total = data?.total ?? data?.count ?? profiles.length;

  if (profiles.length === 0) {
    return (
      <EmptyState
        icon={TrendingUp}
        title="No identity profiles yet"
        description="Ingest identity events or connect an IdP to populate risk analytics and behavioral profiles."
      />
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center justify-between">
          <span>Identity Risk Profiles</span>
          <Badge variant="secondary">{total} profiles</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground uppercase tracking-wide">
                <th className="px-4 py-2 font-medium">User</th>
                <th className="px-4 py-2 font-medium">Email</th>
                <th className="px-4 py-2 font-medium">Risk Score</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Verified</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {profiles.map((p, idx) => {
                const uid = p.user_id ?? p.id ?? `profile-${idx}`;
                const risk = typeof p.risk_score === "number" ? p.risk_score : null;
                const riskClass = risk === null ? "bg-muted text-muted-foreground"
                  : risk >= 70 ? "bg-red-600 text-white"
                  : risk >= 40 ? "bg-amber-500 text-black"
                  : "bg-green-600 text-white";
                return (
                  <tr key={uid} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-2 font-mono text-xs text-indigo-400 whitespace-nowrap">{p.display_name ?? uid.slice(0, 12)}</td>
                    <td className="px-4 py-2 text-muted-foreground">{p.email ?? "—"}</td>
                    <td className="px-4 py-2">
                      {risk !== null ? (
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${riskClass}`}>{risk}</span>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-2 text-muted-foreground">{p.status ?? "—"}</td>
                    <td className="px-4 py-2 text-muted-foreground">{p.verified === true ? "Yes" : p.verified === false ? "No" : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Digital Identity Panel ───────────────────────────────────────────────────

interface DigitalIdentityStats {
  total?: number;
  verified?: number;
  suspended?: number;
  at_risk?: number;
  [key: string]: unknown;
}

interface DigitalIdentity {
  identity_id?: string;
  id?: string;
  user_id?: string;
  status?: string;
  created_at?: string;
  [key: string]: unknown;
}

interface DigitalIdentityListResponse {
  identities?: DigitalIdentity[];
  items?: DigitalIdentity[];
  total?: number;
}

function DigitalIdentityPanel() {
  const { data: statsData } = useQuery<DigitalIdentityStats>({
    queryKey: ["digital-identity", "stats"],
    queryFn: async () => {
      const res = await digitalIdentityApi.stats("default");
      return res.data as DigitalIdentityStats;
    },
    staleTime: 60_000,
  });

  const { data, isLoading, isError, error } = useQuery<DigitalIdentityListResponse>({
    queryKey: ["digital-identity", "identities"],
    queryFn: async () => {
      const res = await digitalIdentityApi.identities("default", 50, 0);
      return res.data as DigitalIdentityListResponse;
    },
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle className="text-sm">Digital Identity Inventory</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 py-10 text-destructive">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p className="text-sm">Failed to load digital identities: {error instanceof Error ? error.message : "Unknown error"}</p>
        </CardContent>
      </Card>
    );
  }

  const identities = data?.identities ?? data?.items ?? [];
  const total = data?.total ?? identities.length;

  return (
    <div className="space-y-4">
      {statsData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {([
            { label: "Total", value: statsData.total ?? 0, cls: "text-muted-foreground" },
            { label: "Verified", value: statsData.verified ?? 0, cls: "text-green-500" },
            { label: "Suspended", value: statsData.suspended ?? 0, cls: "text-red-500" },
            { label: "At Risk", value: statsData.at_risk ?? 0, cls: "text-amber-500" },
          ] as const).map(({ label, value, cls }) => (
            <Card key={label} className="py-3 px-4">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-xl font-bold ${cls}`}>{value}</p>
            </Card>
          ))}
        </div>
      )}
      {identities.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No digital identities registered"
          description="Register digital identities via the API or connect an identity provider to populate this inventory."
        />
      ) : (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center justify-between">
              <span>Digital Identity Inventory</span>
              <Badge variant="secondary">{total} identities</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground uppercase tracking-wide">
                    <th className="px-4 py-2 font-medium">Identity ID</th>
                    <th className="px-4 py-2 font-medium">User ID</th>
                    <th className="px-4 py-2 font-medium">Status</th>
                    <th className="px-4 py-2 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {identities.map((id, idx) => {
                    const iid = id.identity_id ?? id.id ?? `id-${idx}`;
                    const status = (id.status ?? "unknown").toLowerCase();
                    const statusClass = status === "verified" ? "bg-green-600 text-white"
                      : status === "suspended" ? "bg-red-600 text-white"
                      : "bg-muted text-muted-foreground";
                    const created = id.created_at ? new Date(id.created_at).toLocaleDateString() : "—";
                    return (
                      <tr key={iid} className="hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-2 font-mono text-xs text-indigo-400 whitespace-nowrap">{iid.slice(0, 12)}…</td>
                        <td className="px-4 py-2 text-muted-foreground">{id.user_id ?? "—"}</td>
                        <td className="px-4 py-2">
                          <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${statusClass}`}>{status}</span>
                        </td>
                        <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">{created}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

type TabKey = "governance" | "analytics" | "digital" | "access-matrix";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "governance",
    label: "Governance",
    icon: ShieldCheck,
    description:
      "Access reviews, entitlements, and orphaned-account governance (Folded from IdentityGovernance).",
  },
  {
    key: "analytics",
    label: "Analytics",
    icon: BarChart3,
    description:
      "Identity risk analytics, behavioral profiles, and risk scoring (Folded from IdentityAnalyticsDashboard).",
  },
  {
    key: "digital",
    label: "Digital Identity",
    icon: Fingerprint,
    description:
      "Digital identity inventory and lifecycle stats (Folded from DigitalIdentityDashboard).",
  },
  {
    key: "access-matrix",
    label: "Access Matrix",
    icon: Grid3x3,
    description:
      "Roles × resource-types permission grid — effective access levels per ALDECI RBAC role. Live from /api/v1/access-matrix/.",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function IdentityGovernanceHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "governance";
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

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Identity Governance & Analytics"
        description="Unified IAM workspace — access governance, risk analytics, and digital identity inventory."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
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

        <TabsContent value="governance">
          <Suspense fallback={<PageSkeleton />}>
            <GovernanceReviewsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="analytics">
          <Suspense fallback={<PageSkeleton />}>
            <IdentityAnalyticsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="digital">
          <Suspense fallback={<PageSkeleton />}>
            <DigitalIdentityPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="access-matrix">
          <Suspense fallback={<PageSkeleton />}>
            <AccessMatrixPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
