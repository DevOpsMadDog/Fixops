/**
 * ForensicsHub — Incident Response / Forensics unified hero (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone forensics pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22 (S22 Incident Response —
 * Forensics sub-cluster).
 *
 *   tab        | source page/view                | endpoint
 *   -----------|---------------------------------|---------------------------------------------
 *   digital    | DigitalForensicsDashboard       | /api/v1/digital-forensics/{stats,cases}
 *   network    | NetworkForensics (FindingsView) | /api/v1/network-forensics/{captures,stats}
 *   malware    | MalwareAnalysis (FindingsView)  | /api/v1/malware-analysis/{samples,stats}
 *
 * Route: /remediate/forensics
 * Persona target: Incident Responder (#7), Threat Hunter (#8), SOC T2 (#6)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ScanSearch, Network, Bug } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { FindingsExplorerView } from "@/components/FindingsExplorerView";
import { FINDINGS_EXPLORER_ROUTES } from "@/config/findingsExplorerRoutes";
import { DigitalForensicsPanel } from "@/components/forensics/DigitalForensicsPanel";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

// Resolve FindingsExplorerView props from the existing route config so we
// reuse the same data-shape contract as the standalone /network-forensics
// and /malware-analysis pages — zero-drift fold.
const NETWORK_FORENSICS_PROPS =
  FINDINGS_EXPLORER_ROUTES.find(r => r.path === "/network-forensics")?.props;
const MALWARE_ANALYSIS_PROPS =
  FINDINGS_EXPLORER_ROUTES.find(r => r.path === "/malware-analysis")?.props;

type TabKey = "digital" | "network" | "malware";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "digital",
    label: "Digital Forensics",
    icon: ScanSearch,
    description:
      "Endpoint forensic case ledger — disk, memory, and triage artefacts (Folded from DigitalForensicsDashboard).",
  },
  {
    key: "network",
    label: "Network Forensics",
    icon: Network,
    description:
      "Network capture analysis and forensic artifact correlation (Folded from /network-forensics).",
  },
  {
    key: "malware",
    label: "Malware Analysis",
    icon: Bug,
    description:
      "Malware sample analysis results and threat classification (Folded from /malware-analysis).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function ForensicsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "digital";
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
        title="Forensics"
        description="Unified IR forensics workspace — disk/memory cases, network captures, and malware sample triage."
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

        <TabsContent value="digital">
          <Suspense fallback={<PageSkeleton />}>
            <DigitalForensicsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="network">
          {NETWORK_FORENSICS_PROPS ? (
            <FindingsExplorerView {...NETWORK_FORENSICS_PROPS} />
          ) : (
            <div className="text-sm text-muted-foreground p-4">
              Network forensics route config missing — check findingsExplorerRoutes.ts.
            </div>
          )}
        </TabsContent>
        <TabsContent value="malware">
          {MALWARE_ANALYSIS_PROPS ? (
            <FindingsExplorerView {...MALWARE_ANALYSIS_PROPS} />
          ) : (
            <div className="text-sm text-muted-foreground p-4">
              Malware analysis route config missing — check findingsExplorerRoutes.ts.
            </div>
          )}
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
