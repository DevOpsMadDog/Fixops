/**
 * OffensiveValidationHub — Pentest / Red Team / Social Engineering unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds the offensive-validation surfaces from the S13 MPTE Console cluster
 * into a single tabbed hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md
 * §2.13 (Pentest / Red Team / Social Engineering sub-cluster).
 *
 *   tab          | source page             | endpoint
 *   -------------|-------------------------|-------------------------------------
 *   pentest      | PentestManagement       | /api/v1/pentest-mgmt/{stats,engagements,findings}
 *   red-team     | RedTeamStatus           | /api/v1/red-team/{stats,engagements,findings}
 *   social-eng   | SocialEngineering       | /api/v1/phishing/{stats,campaigns,templates}
 *
 * Route: /validate/offensive
 * Persona target: Red Team Lead, Pentest Manager, Sec Awareness Lead
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.13
 *
 * Notes:
 *   - PentestManagementDashboard at /pentest-mgmt redirects to ?tab=pentest
 *     (PentestManagement is the canonical view; both call /pentest-mgmt/*).
 *   - BugBounty is intentionally NOT folded here — already a tab inside Brain.tsx.
 *   - AttackSimulation is intentionally NOT folded here — it lives RoleGuarded
 *     at /validate/simulation as the dedicated BAS surface (S13 'Simulate' tab).
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ClipboardList, Swords, MailWarning } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const PentestManagement = lazy(() => import("@/pages/PentestManagement"));
const RedTeamStatus = lazy(() => import("@/pages/RedTeamStatus"));
const SocialEngineering = lazy(() => import("@/pages/SocialEngineering"));

type TabKey = "pentest" | "red-team" | "social-eng";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "pentest",
    label: "Pentest",
    icon: ClipboardList,
    description:
      "Pentest engagements, findings, and remediation tracking (Folded from PentestManagement / PentestManagementDashboard).",
  },
  {
    key: "red-team",
    label: "Red Team",
    icon: Swords,
    description:
      "Red team engagements, live attack feed, and critical findings (Folded from RedTeamStatus).",
  },
  {
    key: "social-eng",
    label: "Social Engineering",
    icon: MailWarning,
    description:
      "Phishing campaigns, templates, and click-through awareness data (Folded from SocialEngineering).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function OffensiveValidationHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "pentest";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (/pentest, /red-team, /social-engineering, /pentest-mgmt) work.
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
        title="Offensive Validation"
        description="Unified offensive-validation workspace — pentest engagements, red team operations, and social engineering campaigns."
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

        <TabsContent value="pentest">
          <Suspense fallback={<PageSkeleton />}>
            <PentestManagement />
          </Suspense>
        </TabsContent>
        <TabsContent value="red-team">
          <Suspense fallback={<PageSkeleton />}>
            <RedTeamStatus />
          </Suspense>
        </TabsContent>
        <TabsContent value="social-eng">
          <Suspense fallback={<PageSkeleton />}>
            <SocialEngineering />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
