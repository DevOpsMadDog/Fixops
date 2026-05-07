/**
 * VulnLifecyclePipelineHub — Vulnerability Lifecycle Pipeline unified hero
 * (Phase 3 UX consolidation, 2026-05-02 — combined 4-page pair)
 *
 * Folds 4 standalone vulnerability-pipeline dashboards into a single tabbed
 * hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10 (Vuln Lifecycle
 * Pipeline combined sub-cluster — backlog 53 / item 53 follow-up to
 * ThreatIntelOpsHub: pair-merge of two adjacent 2-page candidates into one
 * 4-page hero covering intake → triage → workflow → close-out).
 *
 *   tab           | source page                       | endpoint
 *   --------------|-----------------------------------|----------------------------------------------
 *   age           | VulnerabilityAgeDashboard         | /api/v1/vuln-age/{distribution,sla-compliance,oldest,history}
 *   lifecycle     | VulnLifecycle                     | /api/v1/vuln-lifecycle/{distribution,bottlenecks,avg-time,flow}
 *   prioritize    | VulnPrioritizationDashboard       | /api/v1/vuln-prioritization/{scored,stats}
 *   workflow      | VulnWorkflowDashboard             | /api/v1/vuln-workflow/{tickets,stats}
 *
 * Route: /discover/vuln-pipeline
 * Persona target: Vuln Manager (#5), AppSec Engineer (#10), SOC Analyst (#7), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10
 *
 * Sprint 2 wiring — all 4 tabs wired to real backend APIs (zero mocks).
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Hourglass, GitBranch, ListOrdered, Workflow, Download } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import GenericDashboard from "@/components/GenericDashboard";

// ── Tab types ────────────────────────────────────────────────────────────────

type TabKey = "age" | "lifecycle" | "prioritize" | "workflow";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "age",
    label: "Age & SLA",
    icon: Hourglass,
    description:
      "Vulnerability age distribution, SLA breach tracking, oldest open finds and historical snapshots (Folded from VulnerabilityAgeDashboard).",
  },
  {
    key: "lifecycle",
    label: "Lifecycle",
    icon: GitBranch,
    description:
      "Per-state vulnerability lifecycle counts, state transitions and audit trail across new → triage → fix → verify → close (Folded from VulnLifecycle).",
  },
  {
    key: "prioritize",
    label: "Prioritization",
    icon: ListOrdered,
    description:
      "Risk-scored prioritization queue, exploitation signals and recommended next-actions for each open vuln (Folded from VulnPrioritizationDashboard).",
  },
  {
    key: "workflow",
    label: "Workflow",
    icon: Workflow,
    description:
      "Active remediation workflows, owners, due-dates and closed-today rollups across the open backlog (Folded from VulnWorkflowDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

// ── Tab panel components — each wired to real backend APIs ───────────────────

/**
 * AgePanel — wires to /api/v1/vuln-age
 *
 * Primary list: GET /api/v1/vuln-age/oldest   → array of oldest open vulns
 * Stats:        GET /api/v1/vuln-age/sla-compliance → per-severity SLA compliance
 */
function AgePanel() {
  return (
    <GenericDashboard
      title="Vulnerability Age & SLA"
      description="Oldest open vulnerabilities by age, SLA breach rates and cohort distribution."
      apiPath="/api/v1/vuln-age/oldest"
      statsPath="/api/v1/vuln-age/sla-compliance"
      itemsKey="items"
      columns={[
        { key: "vuln_id",      label: "Vuln ID" },
        { key: "cve_id",       label: "CVE" },
        { key: "severity",     label: "Severity" },
        { key: "cvss_score",   label: "CVSS",    format: (v) => typeof v === "number" ? v.toFixed(1) : String(v ?? "—") },
        { key: "age_days",     label: "Age (days)" },
        { key: "sla_breached", label: "SLA Breach", format: (v) => v ? "Yes" : "No" },
      ]}
      kpis={[
        { key: "total",       label: "Total" },
        { key: "breached",    label: "Breached",    colorClass: "text-red-400" },
        { key: "compliant",   label: "Compliant",   colorClass: "text-green-400" },
        { key: "breach_rate", label: "Breach Rate %", colorClass: "text-amber-400" },
      ]}
      emptyMessage="No open vulnerabilities tracked yet."
    />
  );
}

/**
 * LifecyclePanel — wires to /api/v1/vuln-lifecycle
 *
 * Primary list: GET /api/v1/vuln-lifecycle/bottlenecks → stuck-stage analysis
 * Stats:        GET /api/v1/vuln-lifecycle/flow         → throughput & cycle time
 */
function LifecyclePanel() {
  return (
    <GenericDashboard
      title="Vulnerability Lifecycle"
      description="Stage distribution, bottleneck analysis and flow metrics across the full lifecycle pipeline."
      apiPath="/api/v1/vuln-lifecycle/bottlenecks"
      statsPath="/api/v1/vuln-lifecycle/flow"
      itemsKey="items"
      columns={[
        { key: "stage",        label: "Stage" },
        { key: "count",        label: "Count" },
        { key: "avg_hours",    label: "Avg Hours",  format: (v) => typeof v === "number" ? v.toFixed(1) : String(v ?? "—") },
        { key: "max_hours",    label: "Max Hours",  format: (v) => typeof v === "number" ? v.toFixed(1) : String(v ?? "—") },
      ]}
      kpis={[
        { key: "throughput",        label: "Throughput",    colorClass: "text-green-400" },
        { key: "cycle_time_hours",  label: "Cycle Time (h)", colorClass: "text-amber-400" },
        { key: "lead_time_hours",   label: "Lead Time (h)",  colorClass: "text-blue-400" },
        { key: "wip",               label: "WIP",            colorClass: "text-indigo-400" },
      ]}
      emptyMessage="No lifecycle data available yet."
    />
  );
}

/**
 * PrioritizePanel — wires to /api/v1/vuln-prioritization
 *
 * Primary list: GET /api/v1/vuln-prioritization/scored → risk-scored vuln queue
 * Stats:        GET /api/v1/vuln-prioritization/stats  → totals / by_tier / KEV count
 */
function PrioritizePanel() {
  return (
    <GenericDashboard
      title="Vulnerability Prioritization"
      description="Risk-scored vulnerability queue with exploitation signals, KEV coverage and SLA assignments."
      apiPath="/api/v1/vuln-prioritization/scored"
      statsPath="/api/v1/vuln-prioritization/stats"
      itemsKey="items"
      columns={[
        { key: "cve_id",            label: "CVE" },
        { key: "asset_id",          label: "Asset" },
        { key: "priority_tier",     label: "Priority" },
        { key: "composite_score",   label: "Score",   format: (v) => typeof v === "number" ? v.toFixed(2) : String(v ?? "—") },
        { key: "kev_listed",        label: "KEV",     format: (v) => v ? "Yes" : "No" },
        { key: "exploitability",    label: "Exploit" },
      ]}
      kpis={[
        { key: "total",        label: "Total",      colorClass: "text-slate-300" },
        { key: "critical",     label: "Critical",   colorClass: "text-red-400" },
        { key: "kev_count",    label: "KEV Listed", colorClass: "text-orange-400" },
        { key: "sla_breaches", label: "SLA Breach", colorClass: "text-amber-400" },
      ]}
      emptyMessage="No scored vulnerabilities found."
    />
  );
}

/**
 * WorkflowPanel — wires to /api/v1/vuln-workflow
 *
 * Primary list: GET /api/v1/vuln-workflow/tickets → open workflow tickets
 * Stats:        GET /api/v1/vuln-workflow/stats   → aggregated workflow stats
 */
function WorkflowPanel() {
  return (
    <GenericDashboard
      title="Vulnerability Workflows"
      description="Active remediation tickets, assignees, due-dates, overdue counts and closed-today rollups."
      apiPath="/api/v1/vuln-workflow/tickets"
      statsPath="/api/v1/vuln-workflow/stats"
      itemsKey="items"
      columns={[
        { key: "id",             label: "Ticket ID" },
        { key: "title",          label: "Title" },
        { key: "severity",       label: "Severity" },
        { key: "status",         label: "Status" },
        { key: "assignee_id",    label: "Assignee" },
        { key: "due_date",       label: "Due Date" },
      ]}
      kpis={[
        { key: "total",         label: "Total",       colorClass: "text-slate-300" },
        { key: "open",          label: "Open",        colorClass: "text-blue-400" },
        { key: "overdue",       label: "Overdue",     colorClass: "text-red-400" },
        { key: "closed_today",  label: "Closed Today", colorClass: "text-green-400" },
      ]}
      emptyMessage="No workflow tickets found."
    />
  );
}

// ── Hub component ────────────────────────────────────────────────────────────

export default function VulnLifecyclePipelineHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "age";
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

  const handleExportCsv = () => {
    const orgId = localStorage.getItem("org_id") || "default";
    window.location.href = `/api/v1/security-findings/export?format=csv&org_id=${orgId}`;
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Vulnerability Lifecycle Pipeline"
        description="Unified vulnerability pipeline hero — age & SLA, lifecycle states, prioritization queue, and active remediation workflows."
        badge={activeMeta.label}
        actions={
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
        }
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

        {/* WIRED — age: /api/v1/vuln-age/oldest + /api/v1/vuln-age/sla-compliance */}
        <TabsContent value="age">
          <Suspense fallback={<PageSkeleton />}>
            <AgePanel />
          </Suspense>
        </TabsContent>

        {/* WIRED — lifecycle: /api/v1/vuln-lifecycle/bottlenecks + /api/v1/vuln-lifecycle/flow */}
        <TabsContent value="lifecycle">
          <Suspense fallback={<PageSkeleton />}>
            <LifecyclePanel />
          </Suspense>
        </TabsContent>

        {/* WIRED — prioritize: /api/v1/vuln-prioritization/scored + /api/v1/vuln-prioritization/stats */}
        <TabsContent value="prioritize">
          <Suspense fallback={<PageSkeleton />}>
            <PrioritizePanel />
          </Suspense>
        </TabsContent>

        {/* WIRED — workflow: /api/v1/vuln-workflow/tickets + /api/v1/vuln-workflow/stats */}
        <TabsContent value="workflow">
          <Suspense fallback={<PageSkeleton />}>
            <WorkflowPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
