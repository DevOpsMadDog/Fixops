/**
 * AutomationOrchestrationHub — Remediation Automation & Orchestration unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone patch/SOAR automation pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.19 (S19 Remediation Center —
 * Automation/Orchestration sub-cluster).
 *
 *   tab          | source page                | endpoint
 *   -------------|----------------------------|----------------------------------------------
 *   patch        | PatchManagementDashboard   | /api/v1/patch-management/patches + /stats
 *   prioritize   | PatchPrioritizer           | /api/v1/patch-priority/ + /plans + /stats
 *   soar         | SOARDashboard              | /api/v1/soar/stats + /playbooks + /mttr
 *
 * Route: /remediate/automation
 * Persona target: Remediation Engineer (#15), SOC T2 (#6), Platform Eng (#16)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.19
 */

import { useEffect, useMemo, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Wrench,
  ListOrdered,
  Workflow,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Clock,
  Package,
  Zap,
  BarChart3,
  PlayCircle,
  ShieldCheck,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { API_BASE_URL, API_KEY, DEFAULT_ORG_ID } from "@/lib/api-config";

// ─────────────────────────────────────────────────────────────────────────────
// Shared fetch helper
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const res = await fetch(`${API_BASE_URL}${path}`, { headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain types
// ─────────────────────────────────────────────────────────────────────────────

interface PatchRecord {
  id: string;
  cve_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  asset_id?: string;
  created_at?: string;
}

interface PatchStats {
  total_patches?: number;
  pending?: number;
  applied?: number;
  failed?: number;
  by_severity?: Record<string, number>;
}

interface PatchPlan {
  plan_id: string;
  org_id: string;
  created_at?: string;
  cves?: Array<{ cve_id: string; priority_score?: number; patched?: boolean }>;
}

interface PriorityStats {
  total_plans?: number;
  total_cves_scored?: number;
  kev_count?: number;
}

interface PrioritySummary {
  org_id?: string;
  total_plans?: number;
  stats?: PriorityStats;
}

interface SOARPlaybook {
  id: string;
  name: string;
  description?: string;
  enabled?: boolean;
  trigger_type?: string;
  action_count?: number;
  created_at?: string;
}

interface PlaybookStats {
  total_playbooks?: number;
  enabled_playbooks?: number;
  total_executions?: number;
  completed_executions?: number;
  failed_executions?: number;
  by_trigger?: Record<string, number>;
}

interface MTTRResponse {
  org_id?: string;
  mttr_seconds?: number;
  mttr_minutes?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared UI primitives
// ─────────────────────────────────────────────────────────────────────────────

function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-10 rounded bg-muted/40 animate-pulse" />
      ))}
    </div>
  );
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 py-12 text-destructive">
      <AlertCircle className="h-8 w-8" />
      <p className="text-sm">{message}</p>
      <button
        onClick={onRetry}
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
      >
        <RefreshCw className="h-3.5 w-3.5" /> Retry
      </button>
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
      <Package className="h-8 w-8 opacity-40" />
      <p className="text-sm">{label}</p>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  color = "text-foreground",
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  color?: string;
}) {
  return (
    <div className="rounded-lg border bg-card p-4 flex items-center gap-3">
      <Icon className={`h-5 w-5 shrink-0 ${color}`} />
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className={`text-lg font-semibold ${color}`}>{value}</p>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity ?? "").toLowerCase();
  const cls =
    s === "critical"
      ? "bg-red-900/40 text-red-400"
      : s === "high"
        ? "bg-orange-900/40 text-orange-400"
        : s === "medium"
          ? "bg-yellow-900/40 text-yellow-400"
          : "bg-slate-700 text-slate-300";
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {severity ?? "—"}
    </span>
  );
}

function StatusBadge({ status }: { status?: string }) {
  const s = (status ?? "").toLowerCase();
  const cls =
    s === "applied"
      ? "bg-green-900/40 text-green-400"
      : s === "failed"
        ? "bg-red-900/40 text-red-400"
        : s === "pending"
          ? "bg-yellow-900/40 text-yellow-400"
          : "bg-slate-700 text-slate-300";
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {status ?? "—"}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab: Patch Management  → /api/v1/patch-management/patches + /stats
// ─────────────────────────────────────────────────────────────────────────────

function PatchManagementPanel() {
  const [patches, setPatches] = useState<PatchRecord[]>([]);
  const [stats, setStats] = useState<PatchStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const org = DEFAULT_ORG_ID;
    Promise.all([
      apiFetch<{ patches?: PatchRecord[]; items?: PatchRecord[] } | PatchRecord[]>(
        `/api/v1/patch-management/patches?org_id=${org}&limit=50`
      ),
      apiFetch<PatchStats>(`/api/v1/patch-management/stats?org_id=${org}`),
    ])
      .then(([patchRes, statsRes]) => {
        const list = Array.isArray(patchRes)
          ? patchRes
          : (patchRes as { patches?: PatchRecord[]; items?: PatchRecord[] }).patches ??
            (patchRes as { patches?: PatchRecord[]; items?: PatchRecord[] }).items ??
            [];
        setPatches(list);
        setStats(statsRes);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <SkeletonRows rows={6} />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div className="space-y-4">
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Total Patches" value={stats.total_patches ?? 0} icon={Package} />
          <StatCard label="Pending" value={stats.pending ?? 0} icon={Clock} color="text-yellow-400" />
          <StatCard label="Applied" value={stats.applied ?? 0} icon={CheckCircle2} color="text-green-400" />
          <StatCard label="Failed" value={stats.failed ?? 0} icon={AlertCircle} color="text-red-400" />
        </div>
      )}

      {patches.length === 0 ? (
        <EmptyState label="No patches registered for this org." />
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">CVE / ID</th>
                <th className="px-3 py-2 text-left">Title</th>
                <th className="px-3 py-2 text-left">Severity</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Asset</th>
              </tr>
            </thead>
            <tbody>
              {patches.map((p, i) => (
                <tr
                  key={p.id}
                  className={`border-t ${i % 2 === 0 ? "bg-background" : "bg-muted/10"} hover:bg-muted/20 transition-colors`}
                >
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                    {p.cve_id ?? p.id.slice(0, 12)}
                  </td>
                  <td className="px-3 py-2 max-w-[220px] truncate">{p.title ?? "—"}</td>
                  <td className="px-3 py-2"><SeverityBadge severity={p.severity} /></td>
                  <td className="px-3 py-2"><StatusBadge status={p.status} /></td>
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                    {p.asset_id ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab: Patch Prioritizer  → /api/v1/patch-priority/ + /plans + /stats
// ─────────────────────────────────────────────────────────────────────────────

function PatchPrioritizerPanel() {
  const [summary, setSummary] = useState<PrioritySummary | null>(null);
  const [plans, setPlans] = useState<PatchPlan[]>([]);
  const [stats, setStats] = useState<PriorityStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const org = DEFAULT_ORG_ID;
    Promise.all([
      apiFetch<PrioritySummary>(`/api/v1/patch-priority/?org_id=${org}`),
      apiFetch<PatchPlan[]>(`/api/v1/patch-priority/plans?org_id=${org}`),
      apiFetch<PriorityStats>(`/api/v1/patch-priority/stats?org_id=${org}`),
    ])
      .then(([sumRes, plansRes, statsRes]) => {
        setSummary(sumRes);
        setPlans(Array.isArray(plansRes) ? plansRes : []);
        setStats(statsRes);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <SkeletonRows rows={6} />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div className="space-y-4">
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <StatCard label="Plans" value={stats.total_plans ?? summary?.total_plans ?? 0} icon={ListOrdered} />
          <StatCard label="CVEs Scored" value={stats.total_cves_scored ?? 0} icon={BarChart3} color="text-indigo-400" />
          <StatCard label="CISA KEV" value={stats.kev_count ?? 0} icon={ShieldCheck} color="text-red-400" />
        </div>
      )}

      {plans.length === 0 ? (
        <EmptyState label="No patch plans created yet. Score CVEs to generate a plan." />
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Plan ID</th>
                <th className="px-3 py-2 text-left">Org</th>
                <th className="px-3 py-2 text-left">CVEs</th>
                <th className="px-3 py-2 text-left">Created</th>
              </tr>
            </thead>
            <tbody>
              {plans.map((plan, i) => (
                <tr
                  key={plan.plan_id}
                  className={`border-t ${i % 2 === 0 ? "bg-background" : "bg-muted/10"} hover:bg-muted/20 transition-colors`}
                >
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                    {plan.plan_id.slice(0, 12)}
                  </td>
                  <td className="px-3 py-2 text-xs">{plan.org_id}</td>
                  <td className="px-3 py-2">
                    <span className="inline-block rounded bg-indigo-900/40 text-indigo-300 px-1.5 py-0.5 text-xs">
                      {plan.cves?.length ?? 0} CVEs
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {plan.created_at ? new Date(plan.created_at).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab: SOAR  → /api/v1/soar/stats + /playbooks + /mttr
// ─────────────────────────────────────────────────────────────────────────────

function SOARPanel() {
  const [playbooks, setPlaybooks] = useState<SOARPlaybook[]>([]);
  const [soarStats, setSoarStats] = useState<PlaybookStats | null>(null);
  const [mttr, setMttr] = useState<MTTRResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const org = DEFAULT_ORG_ID;
    Promise.all([
      apiFetch<{ playbooks?: SOARPlaybook[]; items?: SOARPlaybook[] } | SOARPlaybook[]>(
        `/api/v1/soar/playbooks?org_id=${org}`
      ),
      apiFetch<PlaybookStats>(`/api/v1/soar/stats?org_id=${org}`),
      apiFetch<MTTRResponse>(`/api/v1/soar/mttr?org_id=${org}`),
    ])
      .then(([pbRes, statsRes, mttrRes]) => {
        const list = Array.isArray(pbRes)
          ? pbRes
          : (pbRes as { playbooks?: SOARPlaybook[]; items?: SOARPlaybook[] }).playbooks ??
            (pbRes as { playbooks?: SOARPlaybook[]; items?: SOARPlaybook[] }).items ??
            [];
        setPlaybooks(list);
        setSoarStats(statsRes);
        setMttr(mttrRes);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <SkeletonRows rows={6} />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const mttrMin = mttr?.mttr_minutes ?? 0;

  return (
    <div className="space-y-4">
      {soarStats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Playbooks" value={soarStats.total_playbooks ?? 0} icon={Workflow} />
          <StatCard label="Enabled" value={soarStats.enabled_playbooks ?? 0} icon={CheckCircle2} color="text-green-400" />
          <StatCard label="Executions" value={soarStats.total_executions ?? 0} icon={PlayCircle} color="text-indigo-400" />
          <StatCard
            label="MTTR"
            value={mttrMin > 0 ? `${mttrMin.toFixed(1)} min` : "—"}
            icon={Zap}
            color="text-yellow-400"
          />
        </div>
      )}

      {playbooks.length === 0 ? (
        <EmptyState label="No SOAR playbooks configured for this org." />
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Name</th>
                <th className="px-3 py-2 text-left">Trigger</th>
                <th className="px-3 py-2 text-left">Actions</th>
                <th className="px-3 py-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {playbooks.map((pb, i) => (
                <tr
                  key={pb.id}
                  className={`border-t ${i % 2 === 0 ? "bg-background" : "bg-muted/10"} hover:bg-muted/20 transition-colors`}
                >
                  <td className="px-3 py-2 font-medium">{pb.name}</td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {pb.trigger_type ?? "—"}
                  </td>
                  <td className="px-3 py-2 text-xs">{pb.action_count ?? "—"}</td>
                  <td className="px-3 py-2">
                    <span
                      className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${
                        pb.enabled
                          ? "bg-green-900/40 text-green-400"
                          : "bg-slate-700 text-slate-400"
                      }`}
                    >
                      {pb.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hub shell
// ─────────────────────────────────────────────────────────────────────────────

type TabKey = "patch" | "prioritize" | "soar";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "patch",
    label: "Patch Management",
    icon: Wrench,
    description:
      "Patch lifecycle, deployment status and SLA tracking across managed assets.",
  },
  {
    key: "prioritize",
    label: "Patch Prioritizer",
    icon: ListOrdered,
    description:
      "Risk-weighted patch queue with CVE scoring, CISA KEV integration and blast-radius analysis.",
  },
  {
    key: "soar",
    label: "SOAR",
    icon: Workflow,
    description:
      "SOAR playbooks, executions, integrations and MTTR analytics for automated remediation.",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function AutomationOrchestrationHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "patch";
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
        title="Automation & Orchestration"
        description="Unified remediation-automation workspace — patch management, risk-weighted patch queue, and SOAR playbook orchestration."
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

        <TabsContent value="patch">
          <PatchManagementPanel />
        </TabsContent>
        <TabsContent value="prioritize">
          <PatchPrioritizerPanel />
        </TabsContent>
        <TabsContent value="soar">
          <SOARPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
