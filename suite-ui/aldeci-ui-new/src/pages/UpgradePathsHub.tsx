/**
 * UpgradePathsHub — S21 unified hero (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 5 standalone pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.21:
 *
 *   tab            | source page                       | endpoint
 *   ---------------|-----------------------------------|--------------------------------------------------------
 *   resolver       | UpgradePathDashboard              | /api/v1/upgrade-path/recent + /resolve
 *   explorer       | UpgradePathExplorer               | /api/v1/components/{purl}/safe-upgrade
 *   version-graph  | ComponentVersionGraph             | /api/v1/components/{purl}/safe-upgrade
 *   dep-map        | DependencyMappingDashboard        | /api/v1/dependency-mapping/services + /critical-paths
 *   binary-fp      | BinaryFingerprintDashboard        | /api/v1/binary-fp/stats + /fingerprint
 *   dep-risk       | SecurityDependencyRiskDashboard   | /api/v1/dependency-risk/summary
 *
 * Route: /remediate/upgrade
 * Persona target: Vulnerability Manager (#9), Tech Lead (#15)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.21
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  GitBranch,
  TrendingUp,
  Network,
  Fingerprint,
  AlertOctagon,
  Search,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const UpgradePathDashboard = lazy(() => import("@/pages/UpgradePathDashboard"));
const UpgradePathExplorer = lazy(() => import("@/pages/UpgradePathExplorer"));
const ComponentVersionGraph = lazy(() => import("@/pages/ComponentVersionGraph"));
const DependencyMappingDashboard = lazy(() => import("@/pages/DependencyMappingDashboard"));
const BinaryFingerprintDashboard = lazy(() => import("@/pages/BinaryFingerprintDashboard"));
const SecurityDependencyRiskDashboard = lazy(() => import("@/pages/SecurityDependencyRiskDashboard"));

type TabKey =
  | "resolver"
  | "explorer"
  | "version-graph"
  | "dep-map"
  | "binary-fp"
  | "dep-risk";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "resolver",
    label: "Resolver",
    icon: GitBranch,
    description: "Compute the minimal safe upgrade for a vulnerable package (Folded from UpgradePathDashboard).",
  },
  {
    key: "explorer",
    label: "Explorer",
    icon: Search,
    description: "Step-by-step upgrade chain to climb to a safe version (Folded from UpgradePathExplorer).",
  },
  {
    key: "version-graph",
    label: "Version Graph",
    icon: TrendingUp,
    description: "Tabular safe upgrade paths with breaking-change + effort signals (Folded from ComponentVersionGraph).",
  },
  {
    key: "dep-map",
    label: "Dependency Map",
    icon: Network,
    description: "Service dependency graph + blast radius + critical paths (Folded from DependencyMappingDashboard).",
  },
  {
    key: "binary-fp",
    label: "Binary Fingerprint",
    icon: Fingerprint,
    description: "Identify binaries by content hash; correlate with known vulnerable libraries (Folded from BinaryFingerprintDashboard).",
  },
  {
    key: "dep-risk",
    label: "Dependency Risk",
    icon: AlertOctagon,
    description: "SCA risk summary across npm, pypi, maven, nuget, cargo, go (Folded from SecurityDependencyRiskDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function UpgradePathsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab")) ? (params.get("tab") as TabKey) : "resolver";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /upgrade-path → /remediate/upgrade?tab=resolver) work.
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
        title="Upgrade Paths"
        description="Plan and execute safe component upgrades — resolve, explore, blast-radius, fingerprint, score risk."
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

        <TabsContent value="resolver">
          <Suspense fallback={<PageSkeleton />}>
            <UpgradePathDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="explorer">
          <Suspense fallback={<PageSkeleton />}>
            <UpgradePathExplorer />
          </Suspense>
        </TabsContent>
        <TabsContent value="version-graph">
          <Suspense fallback={<PageSkeleton />}>
            <ComponentVersionGraph />
          </Suspense>
        </TabsContent>
        <TabsContent value="dep-map">
          <Suspense fallback={<PageSkeleton />}>
            <DependencyMappingDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="binary-fp">
          <Suspense fallback={<PageSkeleton />}>
            <BinaryFingerprintDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="dep-risk">
          <Suspense fallback={<PageSkeleton />}>
            <SecurityDependencyRiskDashboard />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
