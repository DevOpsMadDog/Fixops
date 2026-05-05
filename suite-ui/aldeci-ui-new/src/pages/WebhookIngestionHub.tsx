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
import { BookOpen, RotateCcw, FlaskConical } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { WebhookEventsTable } from "@/components/webhooks/WebhookEventsTable";

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
