/**
 * HuntingHub — Threat Hunting unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone hunting pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.3 (S3 SOC Operations —
 * Hunt sub-cluster).
 *
 *   tab          | source page                    | endpoint
 *   -------------|--------------------------------|----------------------------------------------
 *   sessions     | ThreatHuntingPage              | /api/v1/hunting/sessions
 *   playbooks    | HuntingPlaybookDashboard       | /api/v1/hunting-playbooks
 *   automation   | HuntingAutomationDashboard     | /api/v1/hunting-automation/hypotheses
 *
 * Route: /mission-control/hunt
 * Persona target: SOC T2 (#6), Threat Hunter (#8), Incident Responder (#7)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.3
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Crosshair, BookOpen, Bot } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const ThreatHuntingPage = lazy(() => import("@/pages/ThreatHunting"));
const HuntingPlaybooksPanel = lazy(() =>
  import("@/pages/hunting/HuntingPlaybooksPanel").then(m => ({ default: m.HuntingPlaybooksPanel }))
);
const HuntingAutomationPanel = lazy(() =>
  import("@/pages/hunting/HuntingAutomationPanel").then(m => ({ default: m.HuntingAutomationPanel }))
);

type TabKey = "sessions" | "playbooks" | "automation";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "sessions",
    label: "Sessions",
    icon: Crosshair,
    description:
      "Active and historical threat-hunting sessions with status, scope, and findings (Folded from ThreatHunting).",
  },
  {
    key: "playbooks",
    label: "Playbooks",
    icon: BookOpen,
    description:
      "Reusable hunting playbooks library with steps, queries, and run history (Folded from HuntingPlaybookDashboard).",
  },
  {
    key: "automation",
    label: "Automation",
    icon: Bot,
    description:
      "Automated hunting hypotheses, scheduled queries, and execution telemetry (Folded from HuntingAutomationDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function HuntingHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "sessions";
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
        title="Threat Hunting"
        description="Unified hunting workspace — live sessions, playbook library, and automated hypothesis-driven hunts."
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

        <TabsContent value="sessions">
          <Suspense fallback={<PageSkeleton />}>
            <ThreatHuntingPage />
          </Suspense>
        </TabsContent>
        <TabsContent value="playbooks">
          <Suspense fallback={<PageSkeleton />}>
            <HuntingPlaybooksPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="automation">
          <Suspense fallback={<PageSkeleton />}>
            <HuntingAutomationPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
