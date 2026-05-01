/**
 * EmailThreatProtectionHub — Unified email/phishing/ransomware defense hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone edge-protection pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture —
 * Email/Phish + Ransomware sub-cluster).
 *
 *   tab          | source page                   | endpoint
 *   -------------|-------------------------------|--------------------------------------------
 *   email        | EmailSecurity                 | /api/v1/email-filtering/{threats,stats}
 *   phishing     | PhishingSimulation            | /api/v1/phishing/{stats,campaigns,templates}
 *   ransomware   | RansomwareProtectionDashboard | /api/v1/ransomware-protection/{patterns,backup-status}
 *
 * Route: /discover/threat-protection
 * Persona target: SOC T1 (#5), SOC T2 (#6), Vuln Mgr (#9), GRC Analyst (#12)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import type { ComponentType } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Mail, Fish, ShieldAlert } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const EmailSecurity = lazy(() => import("@/pages/EmailSecurity"));
const PhishingSimulation = lazy(() => import("@/pages/PhishingSimulation"));
const RansomwareProtectionDashboard = lazy(
  () => import("@/pages/RansomwareProtectionDashboard"),
);

type TabKey = "email" | "phishing" | "ransomware";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "email",
    label: "Email Security",
    icon: Mail,
    description:
      "Inbound email threat filtering — live threats and detection stats (Folded from EmailSecurity).",
  },
  {
    key: "phishing",
    label: "Phishing Simulation",
    icon: Fish,
    description:
      "Phishing campaign management, template library, and employee training metrics (Folded from PhishingSimulation).",
  },
  {
    key: "ransomware",
    label: "Ransomware Protection",
    icon: ShieldAlert,
    description:
      "Ransomware behavior patterns and backup-readiness posture (Folded from RansomwareProtectionDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map((t) => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function EmailThreatProtectionHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "email";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /email-security → /discover/threat-protection?tab=email) work.
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

  const activeMeta = useMemo(
    () => TABS.find((t) => t.key === tab) ?? TABS[0],
    [tab],
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Email & Threat Protection"
        description="Unified edge-protection workspace — inbound email filtering, phishing simulation campaigns, and ransomware defense posture."
        badge={activeMeta.label}
      />

      <Tabs
        value={tab}
        onValueChange={(v) => setTab(v as TabKey)}
        className="w-full"
      >
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <TabsTrigger
                key={t.key}
                value={t.key}
                className="text-xs gap-1.5"
              >
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">
          {activeMeta.description}
        </p>

        <TabsContent value="email">
          <Suspense fallback={<PageSkeleton />}>
            <EmailSecurity />
          </Suspense>
        </TabsContent>
        <TabsContent value="phishing">
          <Suspense fallback={<PageSkeleton />}>
            <PhishingSimulation />
          </Suspense>
        </TabsContent>
        <TabsContent value="ransomware">
          <Suspense fallback={<PageSkeleton />}>
            <RansomwareProtectionDashboard />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
