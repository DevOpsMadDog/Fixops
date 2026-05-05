/**
 * IncidentExtensionsHub — Incident Response extensions unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone IR-extension dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22 (S22 Incident Response —
 * Extensions sub-cluster). Sits alongside the main S22 IR Console and
 * complements ForensicsHub (already folded at /remediate/forensics).
 *
 *   tab          | source page              | endpoint
 *   -------------|--------------------------|----------------------------------------------
 *   cloud        | CloudIRDashboard         | /api/v1/cloud-ir/incidents + /metrics
 *   breach       | BreachResponse           | /api/v1/breach-response/cases + /stats
 *   comms        | IncidentCommsDashboard   | /api/v1/incident-comms/comms + /stats
 *
 * Route: /remediate/incidents/extensions
 * Persona target: IR Lead (#7), SOC T2 (#6), Crisis Comms (#13)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22
 */

import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Cloud, ShieldAlert, MessageCircle } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { GenericDashboard } from "@/components/GenericDashboard";
import type { ColumnDef, KpiDef } from "@/components/GenericDashboard";

// ── Cloud IR tab ─────────────────────────────────────────────────────────────

const CLOUD_IR_COLUMNS: ColumnDef[] = [
  { key: "incident_id", label: "Incident ID" },
  { key: "title",       label: "Title" },
  { key: "severity",    label: "Severity" },
  { key: "status",      label: "Status" },
  { key: "cloud_provider", label: "Provider" },
  { key: "region",      label: "Region" },
];

const CLOUD_IR_KPIS: KpiDef[] = [
  { key: "total_incidents",    label: "Total Incidents",    colorClass: "text-indigo-400" },
  { key: "active_incidents",   label: "Active",             colorClass: "text-red-400" },
  { key: "contained_incidents", label: "Contained",         colorClass: "text-amber-400" },
  { key: "resolved_incidents", label: "Resolved",           colorClass: "text-green-400" },
];

function CloudIRPanel() {
  return (
    <GenericDashboard
      title="Cloud IR"
      description="Cloud-native incident response — multi-cloud incident triage, runbook execution and snapshot evidence."
      apiPath="/api/v1/cloud-ir/incidents"
      itemsKey="incidents"
      statsPath="/api/v1/cloud-ir/metrics"
      columns={CLOUD_IR_COLUMNS}
      kpis={CLOUD_IR_KPIS}
      emptyMessage="No cloud incidents recorded. Cloud IR incidents are raised automatically when the Brain Pipeline detects anomalous activity in connected cloud accounts."
    />
  );
}

// ── Breach Response tab ──────────────────────────────────────────────────────

const BREACH_COLUMNS: ColumnDef[] = [
  { key: "case_id",       label: "Case ID" },
  { key: "title",         label: "Title" },
  { key: "breach_type",   label: "Breach Type" },
  { key: "severity",      label: "Severity" },
  { key: "status",        label: "Status" },
  { key: "detected_at",   label: "Detected" },
];

const BREACH_KPIS: KpiDef[] = [
  { key: "total_cases",      label: "Total Cases",       colorClass: "text-indigo-400" },
  { key: "open_cases",       label: "Open",              colorClass: "text-red-400" },
  { key: "notified_cases",   label: "Notified",          colorClass: "text-amber-400" },
  { key: "closed_cases",     label: "Closed",            colorClass: "text-green-400" },
];

function BreachResponsePanel() {
  return (
    <GenericDashboard
      title="Breach Response"
      description="Active breach cases, response timeline, regulator notifications and disclosure status."
      apiPath="/api/v1/breach-response/cases"
      itemsKey="cases"
      statsPath="/api/v1/breach-response/stats"
      columns={BREACH_COLUMNS}
      kpis={BREACH_KPIS}
      emptyMessage="No breach cases open. Cases are opened automatically when a confirmed data breach is detected or reported."
    />
  );
}

// ── Incident Comms tab ───────────────────────────────────────────────────────

const COMMS_COLUMNS: ColumnDef[] = [
  { key: "comm_id",       label: "ID" },
  { key: "title",         label: "Subject" },
  { key: "comm_type",     label: "Type" },
  { key: "channel",       label: "Channel" },
  { key: "status",        label: "Status" },
  { key: "created_at",    label: "Created" },
];

const COMMS_KPIS: KpiDef[] = [
  { key: "total_comms",       label: "Total Comms",        colorClass: "text-indigo-400" },
  { key: "pending_comms",     label: "Pending",            colorClass: "text-amber-400" },
  { key: "sent_comms",        label: "Sent",               colorClass: "text-green-400" },
  { key: "acknowledgment_rate", label: "Ack Rate (%)",     colorClass: "text-sky-400" },
];

function IncidentCommsPanel() {
  return (
    <GenericDashboard
      title="Incident Comms"
      description="Stakeholder communications log — internal channels, external disclosures and acknowledgment tracking."
      apiPath="/api/v1/incident-comms/comms"
      itemsKey="comms"
      statsPath="/api/v1/incident-comms/stats"
      columns={COMMS_COLUMNS}
      kpis={COMMS_KPIS}
      emptyMessage="No communications logged yet. Comms are created when incident stakeholder notifications are dispatched."
    />
  );
}

// ── Hub shell ────────────────────────────────────────────────────────────────

type TabKey = "cloud" | "breach" | "comms";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "cloud",
    label: "Cloud IR",
    icon: Cloud,
    description:
      "Cloud-native incident response — multi-cloud incident triage, runbook execution and snapshot evidence (Folded from CloudIRDashboard).",
  },
  {
    key: "breach",
    label: "Breach Response",
    icon: ShieldAlert,
    description:
      "Active breach cases, response timeline, regulator notifications and disclosure status (Folded from BreachResponse).",
  },
  {
    key: "comms",
    label: "Comms",
    icon: MessageCircle,
    description:
      "Incident communications log — stakeholder updates, internal channels and external disclosures (Folded from IncidentCommsDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function IncidentExtensionsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "cloud";
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
        title="Incident Extensions"
        description="Cloud IR, breach response and stakeholder comms — unified IR extensions complementing the core IR Console."
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

        <TabsContent value="cloud">
          <CloudIRPanel />
        </TabsContent>
        <TabsContent value="breach">
          <BreachResponsePanel />
        </TabsContent>
        <TabsContent value="comms">
          <IncidentCommsPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
