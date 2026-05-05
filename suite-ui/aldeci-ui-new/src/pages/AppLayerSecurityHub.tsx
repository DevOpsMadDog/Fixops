/**
 * AppLayerSecurityHub — Application-Layer Security unified hub
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone application-layer security pages into a single tabbed
 * surface per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10 (S10 Code
 * Intelligence — Application Security sub-cluster).
 *
 *   tab     | source page                  | endpoints
 *   --------|------------------------------|----------------------------------------------------
 *   web     | AppSecurity                  | /api/v1/appsec/{stats,apps,scans,findings}
 *   mobile  | MobileAppSecurityDashboard   | /api/v1/mobile-app-security/{stats,apps,findings}
 *   browser | BrowserSecurityDashboard     | /api/v1/browser-security/{stats,events,extensions}
 *
 * Route: /discover/app-security
 * Old routes redirect with ?tab=:
 *   /app-security        → /discover/app-security?tab=web
 *   /mobile-app-security → /discover/app-security?tab=mobile
 *   /browser-security    → /discover/app-security?tab=browser
 *
 * Persona target: AppSec Engineer (#10), Security Architect (#11),
 * Mobile/Frontend Engineer (#17), Platform Engineer (#20).
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Code2, Smartphone, Globe } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.


type TabKey = "web" | "mobile" | "browser";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "web",
    label: "Web Apps (SAST/DAST)",
    icon: Code2,
    description:
      "Application security posture, SAST/DAST scans, and OWASP Top 10 findings (Folded from AppSecurity).",
  },
  {
    key: "mobile",
    label: "Mobile Apps",
    icon: Smartphone,
    description:
      "Mobile application security scanning, app inventory, and findings management (Folded from MobileAppSecurityDashboard).",
  },
  {
    key: "browser",
    label: "Browser Policy",
    icon: Globe,
    description:
      "Browser policy enforcement, event monitoring, and extension risk management (Folded from BrowserSecurityDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map((t) => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function AppLayerSecurityHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "web";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /app-security → /discover/app-security?tab=web) work.
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
        title="Application Security"
        description="Unified application-layer security workspace — web app SAST/DAST, mobile app scanning, and browser policy enforcement."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">
          {activeMeta.description}
        </p>

        <TabsContent value="web">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="mobile">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="browser">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
