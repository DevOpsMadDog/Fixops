/**
 * OffensiveValidationHub — Pentest / Red Team / Social Engineering unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds the offensive-validation surfaces from the S13 MPTE Console cluster
 * into a single tabbed hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md
 * §2.13 (Pentest / Red Team / Social Engineering sub-cluster).
 *
 *   tab          | source page             | endpoint
 *   -------------|-------------------------|-------------------------------------
 *   pentest      | PentestManagement       | /api/v1/pentest-mgmt/{stats,engagements,findings}
 *   red-team     | RedTeamStatus           | /api/v1/red-team/{simulations,attack-surface-score,mitre-coverage}
 *   social-eng   | SocialEngineering       | /api/v1/phishing/{stats,campaigns}
 *
 * Route: /validate/offensive
 * Persona target: Red Team Lead, Pentest Manager, Sec Awareness Lead
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.13
 */

import { useEffect, useMemo, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ClipboardList,
  Swords,
  MailWarning,
  RefreshCw,
  ShieldAlert,
  Target,
  Bug,
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = buildApiUrl(path, { org_id: getStoredOrgId(), ...params });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken() },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

type LoadState<T> = { status: "idle" | "loading" | "error" | "ok"; data: T | null; error: string };

function initLoad<T>(): LoadState<T> {
  return { status: "idle", data: null, error: "" };
}

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
  info: "bg-slate-600/60 text-slate-200",
};

function SevBadge({ value }: { value: string }) {
  const cls = SEV_CLASS[value?.toLowerCase()] ?? "bg-slate-600/60 text-slate-200";
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${cls}`}>
      {value || "—"}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Status badge
// ---------------------------------------------------------------------------

function StatusBadge({ value }: { value: string }) {
  const v = value?.toLowerCase() ?? "";
  const cls =
    v === "open" || v === "active" || v === "running"
      ? "bg-red-700/70 text-red-100"
      : v === "planned" || v === "pending"
      ? "bg-amber-600/70 text-amber-100"
      : v === "completed" || v === "done" || v === "remediated"
      ? "bg-green-700/70 text-green-100"
      : "bg-slate-600/60 text-slate-200";
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${cls}`}>
      {value || "—"}
    </span>
  );
}

// ---------------------------------------------------------------------------
// KPI card (stat tile)
// ---------------------------------------------------------------------------

function KpiCard({
  label,
  value,
  colorClass = "text-slate-200",
  icon: Icon,
}: {
  label: string;
  value: string | number;
  colorClass?: string;
  icon?: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 flex flex-col gap-1">
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        {Icon && <Icon className="h-3.5 w-3.5" />}
        {label}
      </div>
      <span className={`text-2xl font-bold ${colorClass}`}>{value ?? "—"}</span>
    </div>
  );
}

// ===========================================================================
// TAB 1: PENTEST
// ===========================================================================

interface PentestStats {
  total_engagements?: number;
  active_engagements?: number;
  total_findings?: number;
  critical_findings?: number;
  high_findings?: number;
  open_findings?: number;
  remediated_findings?: number;
}

interface PentestEngagement {
  id: string;
  name: string;
  engagement_type?: string;
  status?: string;
  start_date?: string;
  end_date?: string;
  lead_tester?: string;
}

interface PentestFinding {
  id: string;
  title: string;
  severity?: string;
  status?: string;
  category?: string;
  affected_component?: string;
  cvss_score?: number;
}

function PentestPanel() {
  const [stats, setStats] = useState<LoadState<PentestStats>>(initLoad());
  const [engagements, setEngagements] = useState<LoadState<PentestEngagement[]>>(initLoad());
  const [findings, setFindings] = useState<LoadState<PentestFinding[]>>(initLoad());
  const [sevFilter, setSevFilter] = useState<string>("all");

  const load = useCallback(async () => {
    setStats(s => ({ ...s, status: "loading" }));
    setEngagements(e => ({ ...e, status: "loading" }));
    setFindings(f => ({ ...f, status: "loading" }));

    const [sRes, eRes, fRes] = await Promise.allSettled([
      apiFetch<PentestStats>("/api/v1/pentest-mgmt/stats"),
      apiFetch<PentestEngagement[]>("/api/v1/pentest-mgmt/engagements"),
      apiFetch<PentestFinding[]>("/api/v1/pentest-mgmt/findings"),
    ]);

    setStats(
      sRes.status === "fulfilled"
        ? { status: "ok", data: sRes.value, error: "" }
        : { status: "error", data: null, error: (sRes.reason as Error).message }
    );
    setEngagements(
      eRes.status === "fulfilled"
        ? { status: "ok", data: Array.isArray(eRes.value) ? eRes.value : [], error: "" }
        : { status: "error", data: null, error: (eRes.reason as Error).message }
    );
    setFindings(
      fRes.status === "fulfilled"
        ? { status: "ok", data: Array.isArray(fRes.value) ? fRes.value : [], error: "" }
        : { status: "error", data: null, error: (fRes.reason as Error).message }
    );
  }, []);

  useEffect(() => { void load(); }, [load]);

  const filteredFindings = useMemo(() => {
    if (!findings.data) return [];
    if (sevFilter === "all") return findings.data;
    return findings.data.filter(f => f.severity?.toLowerCase() === sevFilter);
  }, [findings.data, sevFilter]);

  if (stats.status === "loading" && engagements.status === "loading") return <PageSkeleton />;

  const s = stats.data;

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <KpiCard label="Engagements" value={s?.total_engagements ?? "—"} icon={ClipboardList} />
        <KpiCard label="Active" value={s?.active_engagements ?? "—"} colorClass="text-amber-400" icon={Activity} />
        <KpiCard label="Total Findings" value={s?.total_findings ?? "—"} icon={Bug} />
        <KpiCard label="Critical" value={s?.critical_findings ?? "—"} colorClass="text-red-400" icon={ShieldAlert} />
        <KpiCard label="High" value={s?.high_findings ?? "—"} colorClass="text-orange-400" icon={ShieldAlert} />
        <KpiCard label="Open" value={s?.open_findings ?? "—"} colorClass="text-amber-400" icon={XCircle} />
        <KpiCard label="Remediated" value={s?.remediated_findings ?? "—"} colorClass="text-green-400" icon={CheckCircle2} />
      </div>

      {/* Engagements table */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-foreground">Engagements</h3>
          <button onClick={load} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
            <RefreshCw className="h-3 w-3" /> Refresh
          </button>
        </div>
        {engagements.status === "error" ? (
          <ErrorState message={engagements.error} onRetry={load} />
        ) : (engagements.data?.length ?? 0) === 0 ? (
          <EmptyState message="No pentest engagements found." />
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-muted/40">
                <tr>
                  {["Name", "Type", "Status", "Start", "End", "Lead"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(engagements.data ?? []).map(eng => (
                  <tr key={eng.id} className="border-t border-border hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium text-foreground">{eng.name}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{eng.engagement_type ?? "—"}</td>
                    <td className="px-3 py-2"><StatusBadge value={eng.status ?? ""} /></td>
                    <td className="px-3 py-2 text-muted-foreground">{eng.start_date || "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{eng.end_date || "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{eng.lead_tester || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Findings table with severity filter */}
      <div>
        <div className="flex items-center gap-2 mb-2 flex-wrap">
          <h3 className="text-sm font-semibold text-foreground">Findings</h3>
          <div className="flex gap-1 ml-auto flex-wrap">
            {["all", "critical", "high", "medium", "low"].map(sev => (
              <button
                key={sev}
                onClick={() => setSevFilter(sev)}
                className={`rounded px-2 py-0.5 text-[10px] font-semibold uppercase transition-colors ${
                  sevFilter === sev
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted/40 text-muted-foreground hover:bg-muted/70"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
        {findings.status === "error" ? (
          <ErrorState message={findings.error} onRetry={load} />
        ) : filteredFindings.length === 0 ? (
          <EmptyState message="No findings match the selected filter." />
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-muted/40">
                <tr>
                  {["Title", "Category", "Severity", "CVSS", "Component", "Status"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map(f => (
                  <tr key={f.id} className="border-t border-border hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium text-foreground">{f.title}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{f.category ?? "—"}</td>
                    <td className="px-3 py-2"><SevBadge value={f.severity ?? ""} /></td>
                    <td className="px-3 py-2 text-muted-foreground">{f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{f.affected_component || "—"}</td>
                    <td className="px-3 py-2"><StatusBadge value={f.status ?? ""} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ===========================================================================
// TAB 2: RED TEAM
// ===========================================================================

interface RedTeamSimulation {
  simulation_id?: string;
  id?: string;
  name: string;
  status?: string;
  intensity?: string;
  tactics?: string[];
  created_at?: string;
}

interface AttackSurfaceScore {
  overall_score?: number;
  risk_level?: string;
  total_simulations?: number;
  successful_attacks?: number;
  failed_attacks?: number;
  coverage_percentage?: number;
}

interface MitreCoverage {
  [tactic: string]: {
    detected?: number;
    total?: number;
    coverage_pct?: number;
  };
}

function RedTeamPanel() {
  const [simulations, setSimulations] = useState<LoadState<RedTeamSimulation[]>>(initLoad());
  const [score, setScore] = useState<LoadState<AttackSurfaceScore>>(initLoad());
  const [mitre, setMitre] = useState<LoadState<MitreCoverage>>(initLoad());

  const load = useCallback(async () => {
    setSimulations(s => ({ ...s, status: "loading" }));
    setScore(s => ({ ...s, status: "loading" }));
    setMitre(m => ({ ...m, status: "loading" }));

    const [simRes, scoreRes, mitreRes] = await Promise.allSettled([
      apiFetch<RedTeamSimulation[]>("/api/v1/red-team/simulations"),
      apiFetch<AttackSurfaceScore>("/api/v1/red-team/attack-surface-score"),
      apiFetch<MitreCoverage>("/api/v1/red-team/mitre-coverage"),
    ]);

    setSimulations(
      simRes.status === "fulfilled"
        ? { status: "ok", data: Array.isArray(simRes.value) ? simRes.value : [], error: "" }
        : { status: "error", data: null, error: (simRes.reason as Error).message }
    );
    setScore(
      scoreRes.status === "fulfilled"
        ? { status: "ok", data: scoreRes.value, error: "" }
        : { status: "error", data: null, error: (scoreRes.reason as Error).message }
    );
    setMitre(
      mitreRes.status === "fulfilled"
        ? { status: "ok", data: mitreRes.value, error: "" }
        : { status: "error", data: null, error: (mitreRes.reason as Error).message }
    );
  }, []);

  useEffect(() => { void load(); }, [load]);

  if (simulations.status === "loading" && score.status === "loading") return <PageSkeleton />;

  const asc = score.data;
  const mitreEntries = mitre.data ? Object.entries(mitre.data) : [];

  return (
    <div className="space-y-6">
      {/* Attack surface KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard label="Surface Score" value={asc?.overall_score != null ? `${asc.overall_score.toFixed(0)}` : "—"} colorClass="text-red-400" icon={Target} />
        <KpiCard label="Risk Level" value={asc?.risk_level ?? "—"} icon={ShieldAlert} />
        <KpiCard label="Simulations" value={asc?.total_simulations ?? "—"} icon={Swords} />
        <KpiCard label="Attacks Landed" value={asc?.successful_attacks ?? "—"} colorClass="text-red-400" icon={XCircle} />
        <KpiCard label="Blocked" value={asc?.failed_attacks ?? "—"} colorClass="text-green-400" icon={CheckCircle2} />
        <KpiCard label="Coverage" value={asc?.coverage_percentage != null ? `${asc.coverage_percentage.toFixed(0)}%` : "—"} colorClass="text-blue-400" icon={Activity} />
      </div>

      {/* MITRE ATT&CK coverage */}
      {mitre.status === "error" ? (
        <ErrorState message={mitre.error} onRetry={load} />
      ) : mitreEntries.length > 0 ? (
        <div>
          <h3 className="text-sm font-semibold text-foreground mb-2">MITRE ATT&amp;CK Coverage</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {mitreEntries.map(([tactic, cov]) => {
              const pct = cov?.coverage_pct ?? (cov?.total ? Math.round(((cov.detected ?? 0) / cov.total) * 100) : 0);
              return (
                <div key={tactic} className="rounded-lg border border-border bg-card p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-foreground capitalize">{tactic.replace(/_/g, " ")}</span>
                    <span className="text-xs text-muted-foreground">{cov?.detected ?? 0}/{cov?.total ?? 0}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-muted/50 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-blue-500 transition-all duration-500"
                      style={{ width: `${Math.min(pct, 100)}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-muted-foreground">{pct}% detected</span>
                </div>
              );
            })}
          </div>
        </div>
      ) : null}

      {/* Simulations table */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-foreground">Simulations</h3>
          <button onClick={load} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
            <RefreshCw className="h-3 w-3" /> Refresh
          </button>
        </div>
        {simulations.status === "error" ? (
          <ErrorState message={simulations.error} onRetry={load} />
        ) : (simulations.data?.length ?? 0) === 0 ? (
          <EmptyState message="No red team simulations found." />
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-muted/40">
                <tr>
                  {["Name", "Status", "Intensity", "Tactics", "Created"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(simulations.data ?? []).map((sim, idx) => (
                  <tr key={sim.simulation_id ?? sim.id ?? idx} className="border-t border-border hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium text-foreground">{sim.name}</td>
                    <td className="px-3 py-2"><StatusBadge value={sim.status ?? ""} /></td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{sim.intensity ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{(sim.tactics ?? []).join(", ") || "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{sim.created_at ? new Date(sim.created_at).toLocaleDateString() : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ===========================================================================
// TAB 3: SOCIAL ENGINEERING (PHISHING)
// ===========================================================================

interface PhishingStats {
  total_campaigns?: number;
  active_campaigns?: number;
  total_targets?: number;
  total_sent?: number;
  total_opened?: number;
  total_clicked?: number;
  total_reported?: number;
  click_rate?: number;
  org_risk_score?: number;
}

interface PhishingCampaign {
  id: string;
  name: string;
  status?: string;
  sent_count?: number;
  opened_count?: number;
  clicked_count?: number;
  reported_count?: number;
  template_id?: string;
  created_at?: string;
}

function SocialEngPanel() {
  const [phishStats, setPhishStats] = useState<LoadState<PhishingStats>>(initLoad());
  const [campaigns, setCampaigns] = useState<LoadState<PhishingCampaign[]>>(initLoad());

  const load = useCallback(async () => {
    setPhishStats(s => ({ ...s, status: "loading" }));
    setCampaigns(c => ({ ...c, status: "loading" }));

    const [statsRes, campRes] = await Promise.allSettled([
      apiFetch<PhishingStats>("/api/v1/phishing/stats"),
      apiFetch<{ campaigns?: PhishingCampaign[] } | PhishingCampaign[]>("/api/v1/phishing/campaigns"),
    ]);

    setPhishStats(
      statsRes.status === "fulfilled"
        ? { status: "ok", data: statsRes.value, error: "" }
        : { status: "error", data: null, error: (statsRes.reason as Error).message }
    );

    if (campRes.status === "fulfilled") {
      const raw = campRes.value;
      const list: PhishingCampaign[] = Array.isArray(raw)
        ? raw
        : (raw as { campaigns?: PhishingCampaign[] }).campaigns ?? [];
      setCampaigns({ status: "ok", data: list, error: "" });
    } else {
      setCampaigns({ status: "error", data: null, error: (campRes.reason as Error).message });
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  if (phishStats.status === "loading" && campaigns.status === "loading") return <PageSkeleton />;

  const ps = phishStats.data;
  const clickRate = ps?.click_rate != null ? `${(ps.click_rate * 100).toFixed(1)}%` : "—";
  const riskScore = ps?.org_risk_score != null ? ps.org_risk_score.toFixed(0) : "—";

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <KpiCard label="Campaigns" value={ps?.total_campaigns ?? "—"} icon={MailWarning} />
        <KpiCard label="Active" value={ps?.active_campaigns ?? "—"} colorClass="text-amber-400" icon={Clock} />
        <KpiCard label="Sent" value={ps?.total_sent ?? "—"} icon={Activity} />
        <KpiCard label="Opened" value={ps?.total_opened ?? "—"} colorClass="text-amber-400" />
        <KpiCard label="Clicked" value={ps?.total_clicked ?? "—"} colorClass="text-red-400" icon={XCircle} />
        <KpiCard label="Click Rate" value={clickRate} colorClass="text-red-400" />
        <KpiCard label="Risk Score" value={riskScore} colorClass="text-orange-400" icon={ShieldAlert} />
      </div>

      {/* Campaigns table */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-foreground">Campaigns</h3>
          <button onClick={load} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
            <RefreshCw className="h-3 w-3" /> Refresh
          </button>
        </div>
        {campaigns.status === "error" ? (
          <ErrorState message={campaigns.error} onRetry={load} />
        ) : (campaigns.data?.length ?? 0) === 0 ? (
          <EmptyState message="No phishing campaigns found." />
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-muted/40">
                <tr>
                  {["Name", "Status", "Sent", "Opened", "Clicked", "Reported", "Template"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(campaigns.data ?? []).map(c => (
                  <tr key={c.id} className="border-t border-border hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium text-foreground">{c.name}</td>
                    <td className="px-3 py-2"><StatusBadge value={c.status ?? ""} /></td>
                    <td className="px-3 py-2 text-muted-foreground">{c.sent_count ?? 0}</td>
                    <td className="px-3 py-2 text-muted-foreground">{c.opened_count ?? 0}</td>
                    <td className="px-3 py-2 text-amber-400 font-semibold">{c.clicked_count ?? 0}</td>
                    <td className="px-3 py-2 text-green-400">{c.reported_count ?? 0}</td>
                    <td className="px-3 py-2 text-muted-foreground font-mono text-[10px]">{c.template_id || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ===========================================================================
// HUB SHELL
// ===========================================================================

type TabKey = "pentest" | "red-team" | "social-eng";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "pentest",
    label: "Pentest",
    icon: ClipboardList,
    description:
      "Pentest engagements, findings, and remediation tracking — /api/v1/pentest-mgmt.",
  },
  {
    key: "red-team",
    label: "Red Team",
    icon: Swords,
    description:
      "Red team simulations, MITRE ATT&CK coverage, and attack-surface scoring — /api/v1/red-team.",
  },
  {
    key: "social-eng",
    label: "Social Engineering",
    icon: MailWarning,
    description:
      "Phishing campaigns, click-through rates, and org risk score — /api/v1/phishing.",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function OffensiveValidationHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "pentest";
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
        title="Offensive Validation"
        description="Unified offensive-validation workspace — pentest engagements, red team operations, and social engineering campaigns."
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

        <TabsContent value="pentest">
          <PentestPanel />
        </TabsContent>
        <TabsContent value="red-team">
          <RedTeamPanel />
        </TabsContent>
        <TabsContent value="social-eng">
          <SocialEngPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
