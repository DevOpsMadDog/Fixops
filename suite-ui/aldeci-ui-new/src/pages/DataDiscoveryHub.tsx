/**
 * DataDiscoveryHub — Data Security Posture Management (DSPM) unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone DSPM / data-security pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (Data Discovery / DSPM cluster).
 *
 *   tab            | source page                  | endpoint
 *   ---------------|------------------------------|----------------------------------------------
 *   discovery      | DataDiscoveryDashboard       | /api/v1/data-discovery/datastores
 *   classification | DataClassificationDashboard  | /api/v1/data-classification/{stats,items,violations}
 *   exfiltration   | DataExfiltrationDashboard    | /api/v1/data-exfiltration/{stats,incidents}
 *
 * Route: /discover/dspm
 * Persona target: GRC Analyst (#12), Compliance Manager (#13), DPO, Security Architect (#11)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (Data Discovery / DSPM sub-cluster)
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import type { ComponentType } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Database, Tags, AlertOctagon } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { DataDiscoveryPanel } from "@/components/data-discovery/DataDiscoveryPanel";
import { GenericDashboard } from "@/components/GenericDashboard";
import type { ColumnDef, KpiDef } from "@/components/GenericDashboard";

// ── Classification panel ─────────────────────────────────────────────────────

const CLASS_COLUMNS: ColumnDef[] = [
  { key: "item_id",          label: "Item ID" },
  { key: "name",             label: "Name" },
  { key: "sensitivity_level", label: "Sensitivity" },
  { key: "classification",   label: "Classification" },
  { key: "data_store",       label: "Datastore" },
  { key: "last_scanned",     label: "Last Scanned" },
];

const CLASS_KPIS: KpiDef[] = [
  { key: "total_items",       label: "Total Items",   colorClass: "text-indigo-400" },
  { key: "pii_items",         label: "PII Items",     colorClass: "text-red-400" },
  { key: "violations",        label: "Violations",    colorClass: "text-amber-400" },
  { key: "classified_pct",   label: "Classified %",  colorClass: "text-green-400" },
];

function DataClassificationPanel() {
  return (
    <GenericDashboard
      title="Data Classification"
      description="Sensitivity classification, PII detection, and policy violation tracking across all discovered datastores."
      apiPath="/api/v1/data-classification/items"
      itemsKey="items"
      statsPath="/api/v1/data-classification/stats"
      columns={CLASS_COLUMNS}
      kpis={CLASS_KPIS}
      emptyMessage="No classified data items yet. Run a classification scan to detect PII, secrets, and sensitive data across your datastores."
    />
  );
}

// ── Exfiltration panel ────────────────────────────────────────────────────────

const EXFIL_COLUMNS: ColumnDef[] = [
  { key: "incident_id",  label: "Incident ID" },
  { key: "source",       label: "Source" },
  { key: "destination",  label: "Destination" },
  { key: "data_type",    label: "Data Type" },
  { key: "severity",     label: "Severity" },
  { key: "detected_at",  label: "Detected" },
];

const EXFIL_KPIS: KpiDef[] = [
  { key: "total_incidents",  label: "Incidents",    colorClass: "text-indigo-400" },
  { key: "active_incidents", label: "Active",       colorClass: "text-red-400" },
  { key: "blocked_count",    label: "Blocked",      colorClass: "text-amber-400" },
  { key: "data_volume_gb",   label: "Volume (GB)",  colorClass: "text-sky-400" },
];

function DataExfiltrationPanel() {
  return (
    <GenericDashboard
      title="Data Exfiltration"
      description="Exfiltration incidents and DLP detections across all egress vectors — network, cloud storage, and endpoint."
      apiPath="/api/v1/data-exfiltration/incidents"
      itemsKey="incidents"
      statsPath="/api/v1/data-exfiltration/stats"
      columns={EXFIL_COLUMNS}
      kpis={EXFIL_KPIS}
      emptyMessage="No exfiltration incidents detected. The DLP engine monitors egress channels continuously and raises incidents on suspicious data movement."
    />
  );
}

// ── Tab definitions ───────────────────────────────────────────────────────────

type TabKey = "discovery" | "classification" | "exfiltration";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "discovery",
    label: "Discovery",
    icon: Database,
    description:
      "Discovered datastores across cloud + on-prem with sensitivity context (Folded from DataDiscoveryDashboard).",
  },
  {
    key: "classification",
    label: "Classification",
    icon: Tags,
    description:
      "Sensitivity classification, PII detection, and policy violation tracking (Folded from DataClassificationDashboard).",
  },
  {
    key: "exfiltration",
    label: "Exfiltration",
    icon: AlertOctagon,
    description:
      "Exfiltration incidents and DLP detections across all egress vectors (Folded from DataExfiltrationDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function DataDiscoveryHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "discovery";
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
        title="Data Security Posture (DSPM)"
        description="Unified data security workspace — datastore discovery, sensitivity classification, and exfiltration monitoring."
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

        <TabsContent value="discovery">
          <Suspense fallback={<PageSkeleton />}>
            <DataDiscoveryPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="classification">
          <Suspense fallback={<PageSkeleton />}>
            <DataClassificationPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="exfiltration">
          <Suspense fallback={<PageSkeleton />}>
            <DataExfiltrationPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
