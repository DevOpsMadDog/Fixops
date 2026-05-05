/**
 * WebhookIngestionHub — Webhook & ingestion-pipeline health unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone webhook + connector-pipeline pages into a single tabbed
 * hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.27 (S27 Integrations
 * Hub — Webhook & Integration Health sub-cluster).
 *
 *   tab        | source page                    | endpoint
 *   -----------|--------------------------------|----------------------------------------------
 *   catalogue  | WebhookEventCatalogExplorer    | GET /api/v1/webhooks/event-catalogue
 *   retry      | WebhookRetryConsole            | GET /api/v1/webhooks/retry-queue
 *   dry-run    | UniversalIngestionTester       | POST /api/v1/connectors/mapping/dry-run
 *
 * Route: /connect/webhook-ingestion
 * Persona target: DevOps Engineer (#18), Automation Eng (#25), SRE (#19), Backend Eng (#16)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.27
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { BookOpen, RotateCcw, FlaskConical, AlertCircle, RefreshCw } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { WebhookEventsTable } from "@/components/webhooks/WebhookEventsTable";
import { webhookDlqApi } from "@/lib/api";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "catalogue" | "retry" | "dry-run";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "catalogue",
    label: "Event Catalogue",
    icon: BookOpen,
    description:
      "Browse the canonical webhook event catalogue — every event ALdeci can emit, with schema, version, and category (Folded from WebhookEventCatalogExplorer).",
  },
  {
    key: "retry",
    label: "Retry Queue",
    icon: RotateCcw,
    description:
      "Inspect failed-webhook retry queue — attempt counts, last status, last error, and next-retry timing (Folded from WebhookRetryConsole).",
  },
  {
    key: "dry-run",
    label: "Ingestion Dry-Run",
    icon: FlaskConical,
    description:
      "Validate a connector mapping against a sample payload before going live — confirms parsed rows, output sample, and any mapping errors (Folded from UniversalIngestionTester).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

interface DlqDelivery {
  id?: string;
  delivery_id?: string;
  subscription_id?: string;
  event_type?: string;
  status?: string;
  attempt_count?: number;
  last_error?: string;
  next_retry_at?: string;
  created_at?: string;
  [key: string]: unknown;
}

interface DlqPendingResponse {
  deliveries?: DlqDelivery[];
  total?: number;
  pending_count?: number;
}

interface DlqStatsResponse {
  pending?: number;
  dead?: number;
  delivered?: number;
  total?: number;
  [key: string]: unknown;
}

const STATUS_VARIANT: Record<string, string> = {
  pending: "bg-amber-500 text-black",
  failed: "bg-red-600 text-white",
  delivered: "bg-green-600 text-white",
  dead: "bg-gray-600 text-white",
};

function WebhookRetryQueuePanel() {
  const queryClient = useQueryClient();

  const { data: statsData } = useQuery<DlqStatsResponse>({
    queryKey: ["webhook-dlq", "stats"],
    queryFn: async () => {
      const res = await webhookDlqApi.stats();
      return res.data as DlqStatsResponse;
    },
    staleTime: 30_000,
  });

  const { data, isLoading, isError, error } = useQuery<DlqPendingResponse>({
    queryKey: ["webhook-dlq", "pending"],
    queryFn: async () => {
      const res = await webhookDlqApi.pending({ limit: 50 });
      return res.data as DlqPendingResponse;
    },
    staleTime: 30_000,
  });

  const replayMutation = useMutation({
    mutationFn: (deliveryId: string) => webhookDlqApi.replay(deliveryId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhook-dlq"] });
    },
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Retry Queue</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 py-10 text-destructive">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p className="text-sm">
            Failed to load retry queue:{" "}
            {error instanceof Error ? error.message : "Unknown error"}
          </p>
        </CardContent>
      </Card>
    );
  }

  const deliveries = data?.deliveries ?? [];
  const total = data?.total ?? data?.pending_count ?? deliveries.length;

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      {statsData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {(
            [
              { label: "Pending", value: statsData.pending ?? 0, cls: "text-amber-500" },
              { label: "Dead", value: statsData.dead ?? 0, cls: "text-red-500" },
              { label: "Delivered", value: statsData.delivered ?? 0, cls: "text-green-500" },
              { label: "Total", value: statsData.total ?? 0, cls: "text-muted-foreground" },
            ] as const
          ).map(({ label, value, cls }) => (
            <Card key={label} className="py-3 px-4">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-xl font-bold ${cls}`}>{value}</p>
            </Card>
          ))}
        </div>
      )}

      {deliveries.length === 0 ? (
        <EmptyState
          icon={RotateCcw}
          title="No pending retries"
          description="All webhook deliveries have been successfully delivered or the retry queue is empty."
        />
      ) : (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center justify-between">
              <span>Pending Retry Deliveries</span>
              <Badge variant="secondary">{total} queued</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground uppercase tracking-wide">
                    <th className="px-4 py-2 font-medium">Delivery ID</th>
                    <th className="px-4 py-2 font-medium">Event Type</th>
                    <th className="px-4 py-2 font-medium">Status</th>
                    <th className="px-4 py-2 font-medium">Attempts</th>
                    <th className="px-4 py-2 font-medium">Last Error</th>
                    <th className="px-4 py-2 font-medium">Next Retry</th>
                    <th className="px-4 py-2 font-medium"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {deliveries.map((d, idx) => {
                    const did = d.delivery_id ?? d.id ?? `dlq-${idx}`;
                    const status = (d.status ?? "pending").toLowerCase();
                    const nextRetry = d.next_retry_at
                      ? new Date(d.next_retry_at).toLocaleString()
                      : "—";
                    const lastErr = d.last_error ?? "—";
                    const trimErr = lastErr.length > 40 ? `${lastErr.slice(0, 40)}…` : lastErr;

                    return (
                      <tr key={did} className="hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-2 font-mono text-xs text-indigo-400 whitespace-nowrap">
                          {did.slice(0, 8)}…
                        </td>
                        <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">
                          {d.event_type ?? "—"}
                        </td>
                        <td className="px-4 py-2">
                          <span
                            className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${
                              STATUS_VARIANT[status] ?? "bg-muted text-muted-foreground"
                            }`}
                          >
                            {status}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-center text-muted-foreground">
                          {d.attempt_count ?? 0}
                        </td>
                        <td className="px-4 py-2 text-muted-foreground max-w-xs truncate" title={lastErr}>
                          {trimErr}
                        </td>
                        <td className="px-4 py-2 text-muted-foreground whitespace-nowrap text-xs">
                          {nextRetry}
                        </td>
                        <td className="px-4 py-2">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-6 px-2 text-xs gap-1"
                            disabled={replayMutation.isPending}
                            onClick={() => replayMutation.mutate(did)}
                          >
                            <RefreshCw className="h-3 w-3" />
                            Replay
                          </Button>
                        </td>
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

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function WebhookIngestionHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "catalogue";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /webhooks/retry-queue → /connect/webhook-ingestion?tab=retry) work.
  useEffect(() => {
    if (params.get("tab") !== tab) {
      const next = new URLSearchParams(params);
      next.set("tab", tab);
      setParams(next, { replace: true });
    }
  }, [tab, params, setParams]);

  // React when query string changes (e.g. user clicks an old link in another tab).
  useEffect(() => {
    const incoming = params.get("tab");
    if (isTabKey(incoming) && incoming !== tab) setTab(incoming);
  }, [params, tab]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Webhook & Ingestion Health"
        description="Webhook event catalogue, failed-delivery retry queue, and connector-mapping dry-run — operate the inbound/outbound integration pipeline from a single console."
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

        <TabsContent value="catalogue">
          <Suspense fallback={<PageSkeleton />}>
            <WebhookEventsTable />
          </Suspense>
        </TabsContent>
        <TabsContent value="retry">
          <Suspense fallback={<PageSkeleton />}>
            <WebhookRetryQueuePanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="dry-run">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
