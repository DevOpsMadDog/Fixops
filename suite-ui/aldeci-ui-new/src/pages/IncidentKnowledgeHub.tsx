/**
 * IncidentKnowledgeHub — Post-Incident Analytics & Knowledge unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone post-incident analytics pages into a single tabbed hero
 * per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22 (S22 Incident Response —
 * Post-Incident Knowledge sub-cluster).
 *
 *   tab        | source page                  | endpoint
 *   -----------|------------------------------|----------------------------------------------
 *   metrics    | IncidentMetricsDashboard     | /api/v1/incident-metrics/{stats,incidents}
 *   knowledge  | IncidentKBDashboard          | /api/v1/incident-kb/{articles,stats}
 *   lessons    | IncidentLessonsDashboard     | /api/v1/incident-lessons/{lessons,stats}
 *
 * Route: /remediate/incidents/knowledge
 * Persona target: Incident Responder (#7), SOC T2 (#6), Engineering Manager (#14),
 *                 QA Engineer (#21 — IR Lessons)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22
 */

import { useEffect, useMemo, useState } from "react";
// Note: Suspense/PageSkeleton removed — GenericDashboard handles its own loading state
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Activity, BookOpen, Lightbulb } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { GenericDashboard } from "@/components/GenericDashboard";
import type { ColumnDef, KpiDef } from "@/components/GenericDashboard";

// ── Metrics tab ──────────────────────────────────────────────────────────────

const METRICS_COLUMNS: ColumnDef[] = [
  { key: "incident_id", label: "Incident ID" },
  { key: "title",       label: "Title" },
  { key: "severity",    label: "Severity" },
  { key: "category",    label: "Category" },
  { key: "status",      label: "Status" },
  { key: "team",        label: "Team" },
];

const METRICS_KPIS: KpiDef[] = [
  { key: "total_incidents",   label: "Total Incidents",   colorClass: "text-indigo-400" },
  { key: "open_incidents",    label: "Open",              colorClass: "text-amber-400" },
  { key: "avg_mttr_minutes",  label: "Avg MTTR (min)",    colorClass: "text-sky-400" },
  { key: "sla_breach_count",  label: "SLA Breaches",      colorClass: "text-red-400" },
];

function IncidentMetricsPanel() {
  return (
    <GenericDashboard
      title="Incident Metrics"
      description="Operational KPIs: volume, MTTR and SLA breach tracking across all security incidents."
      apiPath="/api/v1/incident-metrics/incidents"
      itemsKey="incidents"
      statsPath="/api/v1/incident-metrics/stats"
      columns={METRICS_COLUMNS}
      kpis={METRICS_KPIS}
      emptyMessage="No incidents recorded yet. Incidents are created automatically when the Brain Pipeline detects a security event."
    />
  );
}

// ── Knowledge Base tab ───────────────────────────────────────────────────────

const KB_COLUMNS: ColumnDef[] = [
  { key: "article_id",    label: "ID" },
  { key: "title",         label: "Title" },
  { key: "article_type",  label: "Type" },
  { key: "incident_type", label: "Incident Type" },
  { key: "severity",      label: "Severity" },
  { key: "helpful_count", label: "Helpful" },
];

const KB_KPIS: KpiDef[] = [
  { key: "total_articles",   label: "Articles",         colorClass: "text-indigo-400" },
  { key: "total_runbooks",   label: "Runbooks",         colorClass: "text-sky-400" },
  { key: "total_views",      label: "Total Views",      colorClass: "text-green-400" },
  { key: "helpful_rate",     label: "Helpful Rate",     colorClass: "text-amber-400" },
];

function IncidentKBPanel() {
  return (
    <GenericDashboard
      title="Knowledge Base"
      description="Searchable incident KB articles, runbooks and playbooks built from past investigations."
      apiPath="/api/v1/incident-kb/search?query="
      itemsKey="articles"
      statsPath="/api/v1/incident-kb/stats"
      columns={KB_COLUMNS}
      kpis={KB_KPIS}
      emptyMessage="No KB articles yet. Articles are auto-generated from closed incidents and post-mortems."
    />
  );
}

// ── Lessons Learned tab ──────────────────────────────────────────────────────

const LESSONS_COLUMNS: ColumnDef[] = [
  { key: "lesson_id",    label: "ID" },
  { key: "title",        label: "Title" },
  { key: "lesson_type",  label: "Type" },
  { key: "severity",     label: "Severity" },
  { key: "status",       label: "Status" },
  { key: "identified_by", label: "Identified By" },
];

const LESSONS_KPIS: KpiDef[] = [
  { key: "total",             label: "Total Lessons",       colorClass: "text-indigo-400" },
  { key: "implemented",       label: "Implemented",         colorClass: "text-green-400" },
  { key: "pending",           label: "Pending",             colorClass: "text-amber-400" },
  { key: "implementation_rate", label: "Impl. Rate (%)",    colorClass: "text-sky-400" },
];

function IncidentLessonsPanel() {
  return (
    <GenericDashboard
      title="Lessons Learned"
      description="Post-mortem lessons register with action items, ownership, and implementation tracking."
      apiPath="/api/v1/incident-lessons/lessons"
      itemsKey="lessons"
      statsPath="/api/v1/incident-lessons/summary"
      columns={LESSONS_COLUMNS}
      kpis={LESSONS_KPIS}
      emptyMessage="No lessons-learned entries yet. Create one after closing an incident post-mortem."
    />
  );
}

// ── Hub shell ────────────────────────────────────────────────────────────────

type TabKey = "metrics" | "knowledge" | "lessons";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "metrics",
    label: "Metrics",
    icon: Activity,
    description:
      "Operational incident KPIs: total/open volume, MTTR, SLA breach counts (Folded from IncidentMetricsDashboard).",
  },
  {
    key: "knowledge",
    label: "Knowledge Base",
    icon: BookOpen,
    description:
      "Searchable incident KB articles built from past investigations and runbooks (Folded from IncidentKBDashboard).",
  },
  {
    key: "lessons",
    label: "Lessons Learned",
    icon: Lightbulb,
    description:
      "Post-mortem lessons-learned register with action items and ownership (Folded from IncidentLessonsDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function IncidentKnowledgeHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "metrics";
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
        title="Incident Knowledge"
        description="Unified post-incident workspace — operational metrics, searchable knowledge base, and lessons-learned register."
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

        <TabsContent value="metrics">
          <IncidentMetricsPanel />
        </TabsContent>
        <TabsContent value="knowledge">
          <IncidentKBPanel />
        </TabsContent>
        <TabsContent value="lessons">
          <IncidentLessonsPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
