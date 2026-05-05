/**
 * DetectAndRespondHub — XDR/EDR/ITDR unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone detect-and-respond dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.3 (S3 SOC Operations — Detect & Respond
 * sub-cluster, cross-listed with §2.11 S11 Cloud Posture).
 *
 *   tab      | source page              | endpoint
 *   ---------|--------------------------|---------------------------------------------
 *   xdr      | XDRDashboard             | /api/v1/xdr/{incidents,signals,rules}
 *   edr      | EDRDashboard             | /api/v1/edr/{endpoints,detections,processes}
 *   itdr     | ITDRDashboard            | /api/v1/itdr/{stats,threats,response-actions}
 *
 * Route: /discover/detect-respond
 * Persona target: SOC T2 (#6), Incident Responder (#7), Identity Engineer
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.3
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Layers, Monitor, ShieldAlert } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported panel components — each wired to a real backend endpoint.
const XDRPanel  = lazy(() => import("@/components/detect-respond/XDRPanel"));
const EDRPanel  = lazy(() => import("@/components/detect-respond/EDRPanel"));
const ITDRPanel = lazy(() => import("@/components/detect-respond/ITDRPanel"));

type TabKey = "xdr" | "edr" | "itdr";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "xdr",
    label: "XDR — Cross-Domain",
    icon: Layers,
    description:
      "Cross-domain signal correlation, kill-chain coverage, and unified incident command (Folded from XDRDashboard).",
  },
  {
    key: "edr",
    label: "EDR — Endpoints",
    icon: Monitor,
    description:
      "Endpoint telemetry, malware detection, process events, and isolation log (Folded from EDRDashboard).",
  },
  {
    key: "itdr",
    label: "ITDR — Identity",
    icon: ShieldAlert,
    description:
      "Identity threat detection, account-takeover alerts, and automated response actions (Folded from ITDRDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function DetectAndRespondHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "xdr";
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
        title="Detect & Respond"
        description="Unified detect-and-respond workspace — cross-domain XDR correlation, endpoint EDR telemetry, and identity ITDR threat response."
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

        <TabsContent value="xdr">
          <Suspense fallback={<PageSkeleton />}>
            <XDRPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="edr">
          <Suspense fallback={<PageSkeleton />}>
            <EDRPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="itdr">
          <Suspense fallback={<PageSkeleton />}>
            <ITDRPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
