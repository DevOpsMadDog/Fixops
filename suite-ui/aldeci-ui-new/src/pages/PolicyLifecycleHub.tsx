/**
 * PolicyLifecycleHub — Policy lifecycle unified hero
 * (Phase 3 UX consolidation, 2026-05-02 — combined 3-page hub)
 *
 * Folds 3 standalone policy-lifecycle pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.27 (Policy Lifecycle sub-cluster).
 * Sibling to the existing PolicyAuthoringHub at /comply/policies/authoring;
 * authoring covers create/edit/hooks, lifecycle covers browse/inherit/stage-edit.
 *
 *   tab          | source page              | endpoint
 *   -------------|--------------------------|------------------------------------------
 *   library      | PolicyLibraryBrowser     | GET /api/v1/policies + /api/v1/policies/stats
 *   inheritance  | PolicyInheritanceView    | GET /api/v1/organizations + /api/v1/policies
 *   stage-edit   | PolicyStageEditor        | GET/PATCH /api/v1/policies/{id}
 *
 * Route: /comply/policies/lifecycle
 * Persona target: Policy Author (#15), Compliance Lead (#13), Security Architect (#3)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.27
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { BookOpen, Network, Pencil } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "library" | "inheritance" | "stage-edit";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "library",
    label: "Library",
    icon: BookOpen,
    description:
      "Browseable catalogue of policy definitions with name search and tag filter chips derived from live data (Folded from PolicyLibraryBrowser).",
  },
  {
    key: "inheritance",
    label: "Inheritance",
    icon: Network,
    description:
      "Parent → child organisation tree showing which policies apply at each level, using the Wave-C parent_id field (Folded from PolicyInheritanceView).",
  },
  {
    key: "stage-edit",
    label: "Stage Editor",
    icon: Pencil,
    description:
      "Pick a policy, edit per-stage thresholds for each severity, validate the JSON and PATCH the policy back to the live store (Folded from PolicyStageEditor).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function PolicyLifecycleHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "library";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with active tab so deep-links and old-route
  // redirects (e.g. /policies/library → /comply/policies/lifecycle?tab=library) work.
  useEffect(() => {
    if (params.get("tab") !== tab) {
      const next = new URLSearchParams(params);
      next.set("tab", tab);
      setParams(next, { replace: true });
    }
  }, [tab, params, setParams]);

  // React when query string changes externally.
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
        title="Policy Lifecycle"
        description="Unified policy-lifecycle hero — browseable catalogue, org inheritance tree, and per-stage threshold editor."
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

        <TabsContent value="library">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="inheritance">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="stage-edit">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
