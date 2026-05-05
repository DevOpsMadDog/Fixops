/**
 * PrivilegedAccessHub — Privileged Access / IAM Deep unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone privileged-access pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture —
 * IAM Deep / Privileged Access sub-cluster).
 *
 *   tab       | source page                          | endpoint
 *   ----------|--------------------------------------|-------------------------------------------
 *   mfa       | MFAManagementDashboard               | /api/v1/mfa/{stats,enrollments,events}
 *   pam       | PAMDashboard                         | /api/v1/pam/{stats,accounts,sessions,requests}
 *   sessions  | PrivilegedSessionRecordingDashboard  | /api/v1/session-recording/{sessions,stats}
 *
 * Route: /discover/privileged-access
 * Persona target: SOC T2 (#6), Security Architect (#11), GRC Analyst (#12)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { KeyRound, ShieldCheck, Video } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "mfa" | "pam" | "sessions";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "mfa",
    label: "MFA",
    icon: ShieldCheck,
    description:
      "Multi-factor authentication enrollment status, factor mix, and event audit (Folded from MFAManagementDashboard).",
  },
  {
    key: "pam",
    label: "PAM",
    icon: KeyRound,
    description:
      "Privileged Access Management — accounts, active sessions, and access requests (Folded from PAMDashboard).",
  },
  {
    key: "sessions",
    label: "Session Recording",
    icon: Video,
    description:
      "Recorded privileged sessions with playback metadata for forensic review (Folded from PrivilegedSessionRecordingDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function PrivilegedAccessHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "mfa";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /mfa-management → /discover/privileged-access?tab=mfa) work.
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
        title="Privileged Access"
        description="Unified IAM-deep workspace — MFA enrollment, PAM accounts and sessions, and recorded privileged sessions."
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

        <TabsContent value="mfa">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="pam">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="sessions">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
