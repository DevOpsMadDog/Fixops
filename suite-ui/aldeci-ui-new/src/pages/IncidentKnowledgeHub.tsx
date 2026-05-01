/**
 * IncidentKnowledgeHub — Post-Incident Analytics & Knowledge unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone post-incident analytics pages into a single tabbed hero
 * per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22 (S22 Incident Response —
 * Post-Incident Knowledge sub-cluster).
 *
 *   tab        | source page                  | endpoint
 *   -----------|------------------------------|----------------------------------------------
 *   metrics    | IncidentMetricsDashboard     | /api/v1/incident-metrics/{stats,incidents}
 *   knowledge  | IncidentKBDashboard          | /api/v1/incident-kb/{articles,stats}
 *   lessons    | IncidentLessonsDashboard     | /api/v1/incident-lessons/{lessons,stats}
 *
 * Route: /remediate/incidents/knowledge
 * Persona target: Incident Responder (#7), SOC T2 (#6), Engineering Manager (#14),
 *                 QA Engineer (#21 — IR Lessons)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Activity, BookOpen, Lightbulb } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const IncidentMetricsDashboard = lazy(() => import("@/pages/IncidentMetricsDashboard"));
const IncidentKBDashboard = lazy(() => import("@/pages/IncidentKBDashboard"));
const IncidentLessonsDashboard = lazy(() => import("@/pages/IncidentLessonsDashboard"));

type TabKey = "metrics" | "knowledge" | "lessons";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "metrics",
    label: "Metrics",
    icon: Activity,
    description:
      "Operational incident KPIs: total/open volume, MTTR, SLA breach counts (Folded from IncidentMetricsDashboard).",
  },
  {
    key: "knowledge",
    label: "Knowledge Base",
    icon: BookOpen,
    description:
      "Searchable incident KB articles built from past investigations and runbooks (Folded from IncidentKBDashboard).",
  },
  {
    key: "lessons",
    label: "Lessons Learned",
    icon: Lightbulb,
    description:
      "Post-mortem lessons-learned register with action items and ownership (Folded from IncidentLessonsDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function IncidentKnowledgeHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "metrics";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /incident-metrics → /remediate/incidents/knowledge?tab=metrics) work.
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
        title="Incident Knowledge"
        description="Unified post-incident workspace — operational metrics, searchable knowledge base, and lessons-learned register."
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

        <TabsContent value="metrics">
          <Suspense fallback={<PageSkeleton />}>
            <IncidentMetricsDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="knowledge">
          <Suspense fallback={<PageSkeleton />}>
            <IncidentKBDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="lessons">
          <Suspense fallback={<PageSkeleton />}>
            <IncidentLessonsDashboard />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
