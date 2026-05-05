/**
 * NetworkMonitoringHub — Network monitoring/anomaly/threat unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone network-observability dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (S11 Cloud Posture — Network Observability
 * sub-cluster).
 *
 *   tab        | source page                  | endpoint
 *   -----------|------------------------------|---------------------------------------------
 *   monitoring | NetworkMonitoringDashboard   | /api/v1/network-monitoring/{interfaces,alert-rules,...}
 *   anomaly    | NetworkAnomalyDashboard      | /api/v1/network-anomaly/{summary,baselines,traffic-trend}
 *   threats    | NetworkThreatsDashboard      | /api/v1/network-threats/{threats/active,rules,baselines}
 *
 * Route: /discover/network
 * Persona target: SOC T2 (#6), Network Engineer (#15), Incident Responder (#7)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Activity, ShieldAlert, Waves } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported panels wired to real backend endpoints.
import { GenericDashboard } from "@/components/GenericDashboard";

type TabKey = "monitoring" | "anomaly" | "threats";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "monitoring",
    label: "Monitoring — Interfaces",
    icon: Activity,
    description:
      "Live network interfaces, alert rules, and observability inventory (Folded from NetworkMonitoringDashboard).",
  },
  {
    key: "anomaly",
    label: "Anomaly — Baselines",
    icon: Waves,
    description:
      "Traffic baselines, anomaly summary, and per-segment trend analysis (Folded from NetworkAnomalyDashboard).",
  },
  {
    key: "threats",
    label: "Threats — Active",
    icon: ShieldAlert,
    description:
      "Active network threats, detection rules, and threat baselines (Folded from NetworkThreatsDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function NetworkMonitoringHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "monitoring";
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
        title="Network Monitoring"
        description="Unified network observability workspace — live interfaces, anomaly baselines, and active threat detection."
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

        {/* WIRED: monitoring → /api/v1/network-monitoring */}
        <TabsContent value="monitoring">
          <Suspense fallback={<PageSkeleton />}>
            <GenericDashboard
              title="Network Interfaces & Alert Rules"
              description="Live network interfaces, traffic samples, and active alert rules from /api/v1/network-monitoring."
              apiPath="/api/v1/network-monitoring/interfaces"
              itemsKey="interfaces"
              statsPath="/api/v1/network-monitoring/stats"
              columns={[
                { key: "id", label: "Interface ID", className: "font-mono text-xs" },
                { key: "name", label: "Name" },
                { key: "ip", label: "IP Address", className: "font-mono text-xs" },
                { key: "if_type", label: "Type" },
                { key: "description", label: "Description" },
              ]}
              kpis={[
                { key: "total_interfaces", label: "Interfaces" },
                { key: "active_alerts", label: "Active Alerts", colorClass: "text-amber-400" },
                { key: "critical_alerts", label: "Critical", colorClass: "text-red-400" },
                { key: "total_samples", label: "Samples" },
              ]}
              emptyMessage="No interfaces registered. Add network interfaces via the API to begin monitoring."
            />
          </Suspense>
        </TabsContent>

        {/* WIRED: anomaly → /api/v1/network-traffic (anomalies + flows) */}
        <TabsContent value="anomaly">
          <Suspense fallback={<PageSkeleton />}>
            <GenericDashboard
              title="Traffic Anomalies & Baselines"
              description="Detected traffic anomalies, flow analysis, and per-segment trend data from /api/v1/network-traffic."
              apiPath="/api/v1/network-traffic/anomalies"
              itemsKey="anomalies"
              statsPath="/api/v1/network-traffic/stats"
              columns={[
                { key: "id", label: "Anomaly ID", className: "font-mono text-xs" },
                { key: "anomaly_type", label: "Type" },
                { key: "severity", label: "Severity" },
                { key: "src_ip", label: "Source IP", className: "font-mono text-xs" },
                { key: "status", label: "Status" },
                { key: "detected_at", label: "Detected", format: (v) => v ? new Date(v as string).toLocaleString() : "—" },
              ]}
              kpis={[
                { key: "total_flows", label: "Total Flows" },
                { key: "flagged_flows", label: "Flagged Flows", colorClass: "text-amber-400" },
                { key: "total_anomalies", label: "Anomalies", colorClass: "text-red-400" },
                { key: "open_anomalies", label: "Open", colorClass: "text-red-400" },
              ]}
              emptyMessage="No anomalies detected. Traffic flows are being recorded — anomalies appear when baselines are exceeded."
            />
          </Suspense>
        </TabsContent>

        {/* WIRED: threats → /api/v1/threat-vectors */}
        <TabsContent value="threats">
          <Suspense fallback={<PageSkeleton />}>
            <GenericDashboard
              title="Active Network Threats"
              description="Threat vectors, MITRE ATT&CK mappings, and mitigation plans from /api/v1/threat-vectors."
              apiPath="/api/v1/threat-vectors/vectors"
              itemsKey="items"
              statsPath="/api/v1/threat-vectors/stats"
              columns={[
                { key: "id", label: "Vector ID", className: "font-mono text-xs" },
                { key: "name", label: "Name" },
                { key: "vector_type", label: "Type" },
                { key: "severity", label: "Severity" },
                { key: "frequency_score", label: "Freq Score", format: (v) => v != null ? `${Number(v).toFixed(0)}` : "—" },
                { key: "impact_score", label: "Impact Score", format: (v) => v != null ? `${Number(v).toFixed(0)}` : "—" },
              ]}
              kpis={[
                { key: "total_vectors", label: "Vectors" },
                { key: "critical_vectors", label: "Critical", colorClass: "text-red-400" },
                { key: "high_vectors", label: "High", colorClass: "text-amber-400" },
                { key: "total_indicators", label: "Indicators" },
              ]}
              emptyMessage="No threat vectors recorded. Import MITRE ATT&CK via POST /api/v1/threat-vectors/import-mitre or record custom vectors."
            />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
