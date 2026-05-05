/**
 * PrivilegedAccessHub — Privileged Access / IAM Deep unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone privileged-access pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture —
 * IAM Deep / Privileged Access sub-cluster).
 *
 *   tab       | source page                          | endpoint
 *   ----------|--------------------------------------|-------------------------------------------
 *   mfa       | MFAManagementDashboard               | /api/v1/mfa/{stats,enrollments,events}
 *   pam       | PAMDashboard                         | /api/v1/privileged-identity/{summary,accounts,sessions}
 *   sessions  | PrivilegedSessionRecordingDashboard  | /api/v1/session-recording/{sessions,stats}
 *
 * Route: /discover/privileged-access
 * Persona target: SOC T2 (#6), Security Architect (#11), GRC Analyst (#12)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 *
 * Wired 2026-05-05 — all 3 tabs hitting real backend endpoints (no mocks).
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { KeyRound, ShieldCheck, Video } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { FindingsExplorerView } from "@/components/FindingsExplorerView";
import type { FindingsExplorerViewProps } from "@/components/FindingsExplorerView";

// ── Tab content configs wired to real backends ─────────────────────────────────

const MFA_PROPS: FindingsExplorerViewProps = {
  title: "MFA Enrollments",
  description: "Multi-factor authentication enrollment status, factor mix, and event audit",
  apiPath: "/api/v1/mfa/enrollments",
  itemsKey: "enrollments",
  statsPath: "/api/v1/mfa/stats",
  severityKey: "status",
  columns: [
    { key: "user_id",     label: "User",        className: "max-w-[180px]" },
    { key: "factor_type", label: "Factor Type" },
    { key: "status",      label: "Status",      isStatus: true },
    { key: "enrolled_at", label: "Enrolled" },
    { key: "last_used",   label: "Last Used" },
  ],
  kpis: [
    { key: "total",    label: "Total",    colorClass: "text-slate-300" },
    { key: "active",   label: "Active",   colorClass: "text-green-400" },
    { key: "disabled", label: "Disabled", colorClass: "text-amber-400" },
    { key: "pending",  label: "Pending",  colorClass: "text-blue-400" },
  ],
};

const PAM_PROPS: FindingsExplorerViewProps = {
  title: "Privileged Accounts",
  description: "PAM account inventory — risk scores, active sessions, and access requests",
  apiPath: "/api/v1/privileged-identity/high-risk",
  itemsKey: "accounts",
  statsPath: "/api/v1/privileged-identity/summary",
  severityKey: "risk_level",
  columns: [
    { key: "account_name", label: "Account",    className: "max-w-[200px]" },
    { key: "system",       label: "System" },
    { key: "risk_level",   label: "Risk",       isSeverity: true },
    { key: "risk_score",   label: "Score" },
    { key: "status",       label: "Status",     isStatus: true },
    { key: "last_used",    label: "Last Used" },
  ],
  kpis: [
    { key: "total_accounts",  label: "Accounts",     colorClass: "text-slate-300" },
    { key: "high_risk",       label: "High Risk",    colorClass: "text-red-400" },
    { key: "active_sessions", label: "Active Sess.", colorClass: "text-amber-400" },
    { key: "pending_requests",label: "Pending Req.", colorClass: "text-blue-400" },
  ],
};

const SESSIONS_PROPS: FindingsExplorerViewProps = {
  title: "Recorded Sessions",
  description: "Privileged session recordings with playback metadata for forensic review",
  apiPath: "/api/v1/session-recording/sessions",
  itemsKey: "sessions",
  statsPath: "/api/v1/session-recording/stats",
  severityKey: "risk_level",
  columns: [
    { key: "session_id",  label: "Session ID",  className: "max-w-[160px]" },
    { key: "user_id",     label: "User" },
    { key: "target",      label: "Target" },
    { key: "risk_level",  label: "Risk",        isSeverity: true },
    { key: "duration",    label: "Duration" },
    { key: "started_at",  label: "Started" },
    { key: "status",      label: "Status",      isStatus: true },
  ],
  kpis: [
    { key: "total_sessions",    label: "Total",        colorClass: "text-slate-300" },
    { key: "active_sessions",   label: "Active",       colorClass: "text-green-400" },
    { key: "flagged_sessions",  label: "Flagged",      colorClass: "text-red-400" },
    { key: "alerts_triggered",  label: "Alerts",       colorClass: "text-amber-400" },
  ],
};

// ── Hub shell ──────────────────────────────────────────────────────────────────

type TabKey = "mfa" | "pam" | "sessions";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  props: FindingsExplorerViewProps;
}> = [
  {
    key: "mfa",
    label: "MFA",
    icon: ShieldCheck,
    description:
      "Multi-factor authentication enrollment status, factor mix, and event audit (wired: /api/v1/mfa/*).",
    props: MFA_PROPS,
  },
  {
    key: "pam",
    label: "PAM",
    icon: KeyRound,
    description:
      "Privileged Access Management — accounts, risk scores, and access requests (wired: /api/v1/privileged-identity/*).",
    props: PAM_PROPS,
  },
  {
    key: "sessions",
    label: "Session Recording",
    icon: Video,
    description:
      "Recorded privileged sessions with playback metadata for forensic review (wired: /api/v1/session-recording/*).",
    props: SESSIONS_PROPS,
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function PrivilegedAccessHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "mfa";
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
        title="Privileged Access"
        description="Unified IAM-deep workspace — MFA enrollment, PAM accounts and sessions, and recorded privileged sessions."
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

        {TABS.map(t => (
          <TabsContent key={t.key} value={t.key}>
            <Suspense fallback={<PageSkeleton />}>
              <FindingsExplorerView {...t.props} />
            </Suspense>
          </TabsContent>
        ))}
      </Tabs>
    </motion.div>
  );
}
