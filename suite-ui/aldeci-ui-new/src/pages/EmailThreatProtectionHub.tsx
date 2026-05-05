/**
 * EmailThreatProtectionHub — Unified email/phishing/ransomware defense hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone edge-protection pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture —
 * Email/Phish + Ransomware sub-cluster).
 *
 *   tab          | source page                   | endpoint
 *   -------------|-------------------------------|--------------------------------------------
 *   email        | EmailSecurity / EmailFiltering | /api/v1/email-filtering/events + /stats
 *   phishing     | PhishingSimulation             | /api/v1/phishing/campaigns + /stats
 *   ransomware   | RansomwareProtectionDashboard  | /api/v1/ransomware-protection/detections + /
 *
 * Route: /discover/threat-protection
 * Persona target: SOC T1 (#5), SOC T2 (#6), Vuln Mgr (#9), GRC Analyst (#12)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { useEffect, useMemo, useState } from "react";
import type { ComponentType } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Mail, Fish, ShieldAlert } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { GenericDashboard } from "@/components/GenericDashboard";
import type { ColumnDef, KpiDef } from "@/components/GenericDashboard";

// ── Email Security tab ───────────────────────────────────────────────────────

const EMAIL_COLUMNS: ColumnDef[] = [
  { key: "event_id",    label: "Event ID" },
  { key: "sender",      label: "Sender" },
  { key: "subject",     label: "Subject" },
  { key: "threat_type", label: "Threat Type" },
  { key: "action",      label: "Action Taken" },
  { key: "received_at", label: "Received" },
];

const EMAIL_KPIS: KpiDef[] = [
  { key: "total_events",    label: "Total Events",    colorClass: "text-indigo-400" },
  { key: "blocked_count",   label: "Blocked",         colorClass: "text-red-400" },
  { key: "quarantined_count", label: "Quarantined",   colorClass: "text-amber-400" },
  { key: "allowed_count",   label: "Allowed",         colorClass: "text-green-400" },
];

function EmailSecurityPanel() {
  return (
    <GenericDashboard
      title="Email Security"
      description="Inbound email threat filtering — live threat events, blocking actions and detection statistics."
      apiPath="/api/v1/email-filtering/events"
      itemsKey="events"
      statsPath="/api/v1/email-filtering/stats"
      columns={EMAIL_COLUMNS}
      kpis={EMAIL_KPIS}
      emptyMessage="No email threat events recorded yet. Events are logged automatically when the email filtering engine processes inbound mail."
    />
  );
}

// ── Phishing Simulation tab ──────────────────────────────────────────────────

const PHISHING_COLUMNS: ColumnDef[] = [
  { key: "campaign_id",   label: "Campaign ID" },
  { key: "name",          label: "Name" },
  { key: "status",        label: "Status" },
  { key: "target_count",  label: "Targets" },
  { key: "click_rate",    label: "Click Rate (%)" },
  { key: "created_at",    label: "Created" },
];

const PHISHING_KPIS: KpiDef[] = [
  { key: "total_campaigns",   label: "Campaigns",        colorClass: "text-indigo-400" },
  { key: "active_campaigns",  label: "Active",           colorClass: "text-amber-400" },
  { key: "avg_click_rate",    label: "Avg Click Rate",   colorClass: "text-red-400" },
  { key: "avg_report_rate",   label: "Avg Report Rate",  colorClass: "text-green-400" },
];

function PhishingSimulationPanel() {
  return (
    <GenericDashboard
      title="Phishing Simulation"
      description="Phishing campaign management, template library and employee security awareness metrics."
      apiPath="/api/v1/phishing/campaigns"
      itemsKey="campaigns"
      statsPath="/api/v1/phishing/stats"
      columns={PHISHING_COLUMNS}
      kpis={PHISHING_KPIS}
      emptyMessage="No phishing simulation campaigns yet. Create a campaign to test and measure employee security awareness across your organisation."
    />
  );
}

// ── Ransomware Protection tab ────────────────────────────────────────────────

const RANSOMWARE_COLUMNS: ColumnDef[] = [
  { key: "detection_id",  label: "Detection ID" },
  { key: "host",          label: "Host" },
  { key: "family",        label: "Family" },
  { key: "severity",      label: "Severity" },
  { key: "containment_status", label: "Containment" },
  { key: "detected_at",   label: "Detected" },
];

const RANSOMWARE_KPIS: KpiDef[] = [
  { key: "total_detections",     label: "Detections",        colorClass: "text-indigo-400" },
  { key: "active_detections",    label: "Active",            colorClass: "text-red-400" },
  { key: "contained_detections", label: "Contained",         colorClass: "text-amber-400" },
  { key: "total_backups",        label: "Backups Registered", colorClass: "text-green-400" },
];

function RansomwareProtectionPanel() {
  return (
    <GenericDashboard
      title="Ransomware Protection"
      description="Ransomware behavior detections, containment status and backup-readiness posture across all endpoints."
      apiPath="/api/v1/ransomware-protection/detections"
      itemsKey="detections"
      statsPath="/api/v1/ransomware-protection/"
      columns={RANSOMWARE_COLUMNS}
      kpis={RANSOMWARE_KPIS}
      emptyMessage="No ransomware detections recorded. The protection engine monitors endpoints continuously and raises detections on suspicious encryption or lateral-movement activity."
    />
  );
}

// ── Hub shell ────────────────────────────────────────────────────────────────

type TabKey = "email" | "phishing" | "ransomware";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "email",
    label: "Email Security",
    icon: Mail,
    description:
      "Inbound email threat filtering — live threats and detection stats (Folded from EmailSecurity).",
  },
  {
    key: "phishing",
    label: "Phishing Simulation",
    icon: Fish,
    description:
      "Phishing campaign management, template library, and employee training metrics (Folded from PhishingSimulation).",
  },
  {
    key: "ransomware",
    label: "Ransomware Protection",
    icon: ShieldAlert,
    description:
      "Ransomware behavior detections and backup-readiness posture (Folded from RansomwareProtectionDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map((t) => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function EmailThreatProtectionHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "email";
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
        title="Email & Threat Protection"
        description="Unified edge-protection workspace — inbound email filtering, phishing simulation campaigns, and ransomware defense posture."
        badge={activeMeta.label}
      />

      <Tabs
        value={tab}
        onValueChange={(v) => setTab(v as TabKey)}
        className="w-full"
      >
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <TabsTrigger
                key={t.key}
                value={t.key}
                className="text-xs gap-1.5"
              >
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">
          {activeMeta.description}
        </p>

        <TabsContent value="email">
          <EmailSecurityPanel />
        </TabsContent>
        <TabsContent value="phishing">
          <PhishingSimulationPanel />
        </TabsContent>
        <TabsContent value="ransomware">
          <RansomwareProtectionPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
