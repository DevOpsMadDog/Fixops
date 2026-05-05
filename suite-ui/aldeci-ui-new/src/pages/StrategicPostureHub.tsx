/**
 * StrategicPostureHub — Executive / GRC strategic posture unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone strategic-posture / GRC / roadmap pages into a single
 * tabbed hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.23 (Comply space —
 * Strategic Posture sub-cluster).
 *
 *   tab       | source page                | endpoint
 *   ----------|----------------------------|----------------------------------------
 *   posture   | SecurityPostureDashboard   | /api/v1/security-posture/{stats,scores}
 *   roadmap   | SecurityRoadmap            | /api/v1/security-roadmap/{initiatives,milestones,gaps}
 *   grc       | GRCAssessment              | /api/v1/grc/{controls,gaps,audits}
 *
 * Route: /comply/strategic-posture
 * Persona target: CISO (#1), Sec Architect (#11), GRC Analyst (#12), Compliance Mgr (#13)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.23
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Map, ClipboardCheck } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { PostureScorePanel } from "@/components/strategic-posture/PostureScorePanel";
import { SecurityRoadmapPanel } from "@/components/strategic-posture/SecurityRoadmapPanel";
import { GRCAssessmentPanel } from "@/components/strategic-posture/GRCAssessmentPanel";

type TabKey = "posture" | "roadmap" | "grc";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "posture",
    label: "Security Posture",
    icon: Shield,
    description:
      "Overall security posture scoring across domains and frameworks (Folded from SecurityPostureDashboard).",
  },
  {
    key: "roadmap",
    label: "Security Roadmap",
    icon: Map,
    description:
      "Strategic initiatives, milestones, and gap remediation tracked over time (Folded from SecurityRoadmap).",
  },
  {
    key: "grc",
    label: "GRC Assessment",
    icon: ClipboardCheck,
    description:
      "Control testing, gap analysis, and audit readiness for governance and regulatory frameworks (Folded from GRCAssessment).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function StrategicPostureHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "posture";
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
        title="Strategic Posture"
        description="Executive-level security posture, strategic roadmap, and GRC control assessment."
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

        <TabsContent value="posture">
          <Suspense fallback={<PageSkeleton />}>
            <PostureScorePanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="roadmap">
          <Suspense fallback={<PageSkeleton />}>
            <SecurityRoadmapPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="grc">
          <Suspense fallback={<PageSkeleton />}>
            <GRCAssessmentPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
