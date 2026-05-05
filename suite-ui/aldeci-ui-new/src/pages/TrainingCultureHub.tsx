/**
 * TrainingCultureHub — Security Training & Culture unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone training/culture dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (S29 Admin Console — Training &
 * Culture sub-cluster). All three sources hit real backend routers — zero mocks.
 *
 *   tab            | source page                       | endpoint
 *   ---------------|-----------------------------------|---------------------------------------
 *   training       | SecurityTrainingDashboard         | /api/v1/security-training/{stats,courses,enrollments,campaigns}
 *   effectiveness  | TrainingEffectivenessDashboard    | /api/v1/training-effectiveness/programs
 *   culture        | SecurityCultureDashboard          | /api/v1/security-culture
 *
 * Route: /admin/training-culture
 * Persona target: Security Awareness Lead (#21), CISO (#1), GRC Analyst (#12)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (S29 Training & Culture sub-cluster)
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { GraduationCap, TrendingUp, Heart } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "training" | "effectiveness" | "culture";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "training",
    label: "Training",
    icon: GraduationCap,
    description:
      "Course catalog, enrollment, and active training campaigns (Folded from SecurityTrainingDashboard).",
  },
  {
    key: "effectiveness",
    label: "Effectiveness",
    icon: TrendingUp,
    description:
      "Program effectiveness metrics — completion rates, knowledge retention, behavior change (Folded from TrainingEffectivenessDashboard).",
  },
  {
    key: "culture",
    label: "Culture",
    icon: Heart,
    description:
      "Org-wide security culture posture, sentiment, and maturity (Folded from SecurityCultureDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function TrainingCultureHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "training";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /security-training → /admin/training-culture?tab=training) work.
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
        title="Training & Culture"
        description="Unified workspace — security training delivery, program effectiveness, and org-wide culture posture."
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

        <TabsContent value="training">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="effectiveness">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="culture">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
