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

import { useEffect, useMemo, useState } from "react";
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
import { SBOMExportPanel } from "@/components/sbom/SBOMExportPanel";
import { PipelineBOMPanel } from "@/components/sbom/PipelineBOMPanel";
import { PBOMPropagationPanel } from "@/components/sbom/PBOMPropagationPanel";
import { SLSAProvenancePanel } from "@/components/sbom/SLSAProvenancePanel";
import { AttestationGraphPanel } from "@/components/sbom/AttestationGraphPanel";
import { AttestationSignPanel } from "@/components/sbom/AttestationSignPanel";

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
          <SBOMExportPanel />
        </TabsContent>
        <TabsContent value="pipeline-bom">
          <PipelineBOMPanel />
        </TabsContent>
        <TabsContent value="pbom-prop">
          <PBOMPropagationPanel />
        </TabsContent>
        <TabsContent value="slsa">
          <SLSAProvenancePanel />
        </TabsContent>
        <TabsContent value="attestation">
          <AttestationGraphPanel />
        </TabsContent>
        <TabsContent value="sign">
          <AttestationSignPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
