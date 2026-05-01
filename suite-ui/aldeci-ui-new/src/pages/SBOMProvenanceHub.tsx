/**
 * SBOMProvenanceHub — S25 SBOM & Provenance unified hero (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 6 standalone SBOM/provenance/attestation pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.25:
 *
 *   tab          | source page                  | endpoint
 *   -------------|------------------------------|--------------------------------------------------------
 *   export       | SBOMExportDashboard          | /api/v1/sbom-export/{projects,components,history}
 *   pipeline-bom | PipelineBomDashboard         | /api/v1/pbom/stats + /run/{id}/export
 *   pbom-prop    | PBOMViewer                   | /api/v1/pbom/artifact/{digest}/propagation
 *   slsa         | SlsaProvenanceDashboard      | /api/v1/slsa/{stats,attestations,attest}
 *   attestation  | PipelineAttestationGraph     | /api/v1/provenance/{artifact}/attestation
 *   sign         | SLSAAttestationSigner        | /api/v1/provenance/sign
 *
 * Route: /comply/provenance
 * Persona target: GRC Analyst (#12), Compliance Manager (#13)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.25
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  FileDown,
  GitMerge,
  Workflow,
  ShieldCheck,
  Network,
  PenSquare,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const SBOMExportDashboard = lazy(() => import("@/pages/SBOMExportDashboard"));
const PipelineBomDashboard = lazy(() => import("@/pages/PipelineBomDashboard"));
const PBOMViewer = lazy(() => import("@/pages/PBOMViewer"));
const SlsaProvenanceDashboard = lazy(() => import("@/pages/SlsaProvenanceDashboard"));
const PipelineAttestationGraph = lazy(() => import("@/pages/PipelineAttestationGraph"));
const SLSAAttestationSigner = lazy(() => import("@/pages/SLSAAttestationSigner"));

type TabKey =
  | "export"
  | "pipeline-bom"
  | "pbom-prop"
  | "slsa"
  | "attestation"
  | "sign";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "export",
    label: "SBOM Export",
    icon: FileDown,
    description: "Export project SBOMs in CycloneDX/SPDX formats with full component history (Folded from SBOMExportDashboard).",
  },
  {
    key: "pipeline-bom",
    label: "Pipeline BOM",
    icon: Workflow,
    description: "Per-build pipeline BOM with stats and per-run export to CycloneDX (Folded from PipelineBomDashboard).",
  },
  {
    key: "pbom-prop",
    label: "PBOM Propagation",
    icon: GitMerge,
    description: "Trace where a single artifact digest has propagated across pipelines (Folded from PBOMViewer).",
  },
  {
    key: "slsa",
    label: "SLSA Provenance",
    icon: ShieldCheck,
    description: "SLSA attestation registry with build provenance + verifier chain (Folded from SlsaProvenanceDashboard).",
  },
  {
    key: "attestation",
    label: "Attestation Graph",
    icon: Network,
    description: "Visualize the attestation chain for a built artifact end-to-end (Folded from PipelineAttestationGraph).",
  },
  {
    key: "sign",
    label: "Sign Attestation",
    icon: PenSquare,
    description: "Generate and sign a new SLSA attestation for an artifact (Folded from SLSAAttestationSigner).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function SBOMProvenanceHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab")) ? (params.get("tab") as TabKey) : "export";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /sbom-export → /comply/provenance?tab=export) work.
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
        title="SBOM & Provenance"
        description="Export SBOMs, view per-pipeline BOM propagation, register and sign SLSA attestations — full software supply-chain evidence for SOC2 / FedRAMP / EU CRA."
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

        <TabsContent value="export">
          <Suspense fallback={<PageSkeleton />}>
            <SBOMExportDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="pipeline-bom">
          <Suspense fallback={<PageSkeleton />}>
            <PipelineBomDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="pbom-prop">
          <Suspense fallback={<PageSkeleton />}>
            <PBOMViewer />
          </Suspense>
        </TabsContent>
        <TabsContent value="slsa">
          <Suspense fallback={<PageSkeleton />}>
            <SlsaProvenanceDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="attestation">
          <Suspense fallback={<PageSkeleton />}>
            <PipelineAttestationGraph />
          </Suspense>
        </TabsContent>
        <TabsContent value="sign">
          <Suspense fallback={<PageSkeleton />}>
            <SLSAAttestationSigner />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
