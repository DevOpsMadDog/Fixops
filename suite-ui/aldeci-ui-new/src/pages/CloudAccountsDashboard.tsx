/**
 * Cloud Accounts Dashboard
 *
 * Displays cloud account inventory grouped by provider, risk score gauges,
 * event feed, and provider risk summary.
 *
 * Route: /cloud-accounts
 * API: GET /api/v1/cloud-accounts
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/cloud-accounts";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });


// ── Types ──────────────────────────────────────────────────────

type Provider = "AWS" | "Azure" | "GCP" | "OCI" | "Alibaba";
type AccountStatus = "healthy" | "warning" | "critical";
type EventSeverity = "info" | "low" | "medium" | "high" | "critical";

interface CloudAccount {
  id: string;
  account_name: string;
  account_id: string;
  provider: Provider;
  status: AccountStatus;
  risk_score: number;
  region: string;
  environment: string;
  unresolved_events: number;
  last_scanned: string;
}

interface AccountEvent {
  id: string;
  account_id: string;
  title: string;
  severity: EventSeverity;
  event_time: string;
  resolved: boolean;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ACCOUNTS: CloudAccount[] = [
  { id: "acc-001", account_name: "Production AWS",         account_id: "123456789012", provider: "AWS",     status: "warning",  risk_score: 64, region: "us-east-1",      environment: "Production",  unresolved_events: 8,  last_scanned: "2026-04-16 09:00" },
  { id: "acc-002", account_name: "Dev AWS",                account_id: "234567890123", provider: "AWS",     status: "healthy",  risk_score: 28, region: "us-west-2",      environment: "Development", unresolved_events: 2,  last_scanned: "2026-04-16 09:05" },
  { id: "acc-003", account_name: "Azure Corp Prod",        account_id: "sub-aaa-bbb",  provider: "Azure",   status: "critical", risk_score: 82, region: "eastus",         environment: "Production",  unresolved_events: 14, last_scanned: "2026-04-16 08:45" },
  { id: "acc-004", account_name: "Azure Dev/Test",         account_id: "sub-ccc-ddd",  provider: "Azure",   status: "healthy",  risk_score: 32, region: "westeurope",     environment: "Dev/Test",    unresolved_events: 1,  last_scanned: "2026-04-16 09:10" },
  { id: "acc-005", account_name: "GCP Analytics Project",  account_id: "proj-analytics", provider: "GCP",   status: "warning",  risk_score: 58, region: "us-central1",    environment: "Production",  unresolved_events: 5,  last_scanned: "2026-04-16 09:15" },
  { id: "acc-006", account_name: "GCP ML Platform",        account_id: "proj-ml-prod", provider: "GCP",     status: "healthy",  risk_score: 41, region: "us-east1",       environment: "Production",  unresolved_events: 3,  last_scanned: "2026-04-16 09:20" },
  { id: "acc-007", account_name: "OCI Finance Tenant",     account_id: "ocid1.tenancy", provider: "OCI",    status: "healthy",  risk_score: 35, region: "us-ashburn-1",   environment: "Production",  unresolved_events: 0,  last_scanned: "2026-04-16 08:50" },
  { id: "acc-008", account_name: "AWS Security Tooling",   account_id: "345678901234", provider: "AWS",     status: "healthy",  risk_score: 19, region: "us-east-1",      environment: "Security",    unresolved_events: 0,  last_scanned: "2026-04-16 09:00" },
];

const MOCK_EVENTS: AccountEvent[] = [
  { id: "evt-001", account_id: "acc-003", title: "Public S3 bucket detected",          severity: "critical", event_time: "2026-04-16 08:30", resolved: false },
  { id: "evt-002", account_id: "acc-001", title: "Root account login detected",        severity: "high",     event_time: "2026-04-16 07:55", resolved: false },
  { id: "evt-003", account_id: "acc-003", title: "Overly permissive IAM policy added", severity: "high",     event_time: "2026-04-16 06:10", resolved: false },
  { id: "evt-004", account_id: "acc-005", title: "GCS bucket ACL set to public",       severity: "critical", event_time: "2026-04-16 05:45", resolved: false },
  { id: "evt-005", account_id: "acc-001", title: "Security group allows 0.0.0.0/0",   severity: "medium",   event_time: "2026-04-15 23:20", resolved: false },
  { id: "evt-006", account_id: "acc-002", title: "MFA disabled on IAM user",           severity: "medium",   event_time: "2026-04-15 21:00", resolved: true  },
  { id: "evt-007", account_id: "acc-004", title: "VM snapshot exported externally",    severity: "high",     event_time: "2026-04-15 19:30", resolved: false },
  { id: "evt-008", account_id: "acc-006", title: "Service account key created",        severity: "low",      event_time: "2026-04-15 18:15", resolved: false },
];

// ── Helpers ────────────────────────────────────────────────────

const providerBadge: Record<Provider, string> = {
  AWS:     "bg-orange-700 text-orange-100",
  Azure:   "bg-blue-700 text-blue-100",
  GCP:     "bg-green-700 text-green-100",
  OCI:     "bg-red-700 text-red-100",
  Alibaba: "bg-amber-700 text-amber-100",
};

const statusConfig: Record<AccountStatus, { color: string; dot: string; label: string }> = {
  healthy:  { color: "bg-green-700 text-green-100",  dot: "bg-green-400",  label: "Healthy"  },
  warning:  { color: "bg-amber-700 text-amber-100",  dot: "bg-amber-400",  label: "Warning"  },
  critical: { color: "bg-red-700 text-red-100",      dot: "bg-red-400",    label: "Critical" },
};

const severityColors: Record<EventSeverity, string> = {
  info:     "text-blue-400 bg-blue-900/20",
  low:      "text-green-400 bg-green-900/20",
  medium:   "text-amber-400 bg-amber-900/20",
  high:     "text-orange-400 bg-orange-900/20",
  critical: "text-red-400 bg-red-900/20",
};

function riskBarColor(score: number) {
  if (score >= 70) return "bg-red-500";
  if (score >= 50) return "bg-amber-500";
  return "bg-green-500";
}

// ── Component ──────────────────────────────────────────────────

const ALL_PROVIDERS: Provider[] = ["AWS", "Azure", "GCP", "OCI", "Alibaba"];

export default function CloudAccountsDashboard() {
  const [providerFilter, setProviderFilter] = useState<Provider | "All">("All");
  const [accounts, setAccounts] = useState([]);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    fetch(`${_API_BASE}/accounts?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setAccounts(d); })
      .catch(() => {});
    fetch(`${_API_BASE}/events?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setEvents(d); })
      .catch(() => {});
  }, []);

  const filtered = providerFilter === "All"
    ? accounts
    : accounts.filter(a => a.provider === providerFilter);

  const totalUnresolved = events.filter(e => !e.resolved).length;
  const criticalAccounts = accounts.filter(a => a.status === "critical").length;
  const avgRisk = accounts.length > 0 ? Math.round(accounts.reduce((s, a) => s + a.risk_score, 0) / accounts.length) : 0;

  // Provider risk summary
  const providerSummary = ALL_PROVIDERS.map(p => {
    const provAccounts = accounts.filter(a => a.provider === p);
    if (provAccounts.length === 0) return null;
    const avgScore = Math.round(provAccounts.reduce((s, a) => s + a.risk_score, 0) / provAccounts.length);
    const maxStatus = provAccounts.some(a => a.status === "critical") ? "critical"
      : provAccounts.some(a => a.status === "warning") ? "warning" : "healthy";
    return { provider: p, accounts: provAccounts.length, avgScore, maxStatus: maxStatus as AccountStatus };
  }).filter(Boolean) as { provider: Provider; accounts: number; avgScore: number; maxStatus: AccountStatus }[];

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Cloud Accounts</h1>
          <p className="text-gray-400 mt-1">Multi-cloud account inventory, risk scoring, and event monitoring</p>
        </div>
        <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          + Add Account
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Accounts", value: accounts.length, color: "text-blue-400" },
          { label: "Critical Risk",  value: criticalAccounts,     color: "text-red-400" },
          { label: "Avg Risk Score", value: avgRisk,              color: avgRisk >= 60 ? "text-red-400" : avgRisk >= 40 ? "text-amber-400" : "text-green-400" },
          { label: "Unresolved Events", value: totalUnresolved,   color: "text-orange-400" },
        ].map(kpi => (
          <div key={kpi.label} className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">{kpi.label}</p>
            <p className={`text-3xl font-bold mt-1 ${kpi.color}`}>{kpi.value}</p>
          </div>
        ))}
      </div>

      {/* Provider filter */}
      <div className="flex gap-2 flex-wrap">
        {(["All", ...ALL_PROVIDERS] as (Provider | "All")[]).map(p => (
          <button
            key={p}
            onClick={() => setProviderFilter(p)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              providerFilter === p ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"
            }`}
          >
            {p}
          </button>
        ))}
      </div>

      {/* Accounts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {filtered.map(account => (
          <div key={account.id} className="bg-gray-800 rounded-lg p-5 space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-white font-semibold">{account.account_name}</p>
                <p className="text-gray-500 text-xs font-mono mt-0.5">{account.account_id}</p>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${providerBadge[account.provider]}`}>{account.provider}</span>
                <span className={`px-2 py-0.5 rounded text-xs font-medium flex items-center gap-1 ${statusConfig[account.status].color}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${statusConfig[account.status].dot}`} />
                  {statusConfig[account.status].label}
                </span>
              </div>
            </div>
            {/* Risk gauge */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-gray-400 text-xs">Risk Score</span>
                <span className={`text-sm font-bold ${account.risk_score >= 70 ? "text-red-400" : account.risk_score >= 50 ? "text-amber-400" : "text-green-400"}`}>
                  {account.risk_score}/100
                </span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div className={`h-2 rounded-full ${riskBarColor(account.risk_score)}`} style={{ width: `${account.risk_score}%` }} />
              </div>
            </div>
            <div className="flex items-center justify-between text-xs text-gray-400">
              <span>{account.region} · {account.environment}</span>
              <span className={account.unresolved_events > 0 ? "text-orange-400 font-medium" : "text-gray-500"}>
                {account.unresolved_events} events
              </span>
            </div>
            <p className="text-gray-500 text-xs">Scanned: {account.last_scanned}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Events Feed */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Events Feed <span className="text-orange-400 text-sm font-normal ml-2">{totalUnresolved} unresolved</span>
          </h2>
          <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {events.map(evt => {
              const account = accounts.find(a => a.id === evt.account_id);
              return (
                <div key={evt.id} className={`p-3 rounded-lg border border-transparent ${severityColors[evt.severity]} ${evt.resolved ? "opacity-50" : ""}`}>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className="text-sm font-medium">{evt.title}</p>
                      <p className="text-xs opacity-70 mt-0.5">
                        {account?.account_name} · {evt.event_time}
                      </p>
                    </div>
                    <div className="flex flex-col items-end gap-1 shrink-0">
                      <span className="text-xs font-semibold uppercase">{evt.severity}</span>
                      {evt.resolved && <span className="text-xs bg-green-800 text-green-200 px-1.5 py-0.5 rounded">resolved</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Provider Risk Summary */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Provider Risk Summary</h2>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-left">
                <th className="pb-3 pr-4">Provider</th>
                <th className="pb-3 pr-4">Accounts</th>
                <th className="pb-3 pr-4">Avg Risk</th>
                <th className="pb-3">Worst Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {providerSummary.map(ps => (
                <tr key={ps.provider} className="hover:bg-gray-700/50">
                  <td className="py-3 pr-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${providerBadge[ps.provider]}`}>{ps.provider}</span>
                  </td>
                  <td className="py-3 pr-4 text-gray-300">{ps.accounts}</td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-gray-700 rounded-full h-1.5">
                        <div className={`h-1.5 rounded-full ${riskBarColor(ps.avgScore)}`} style={{ width: `${ps.avgScore}%` }} />
                      </div>
                      <span className={`text-xs font-medium ${ps.avgScore >= 70 ? "text-red-400" : ps.avgScore >= 50 ? "text-amber-400" : "text-green-400"}`}>{ps.avgScore}</span>
                    </div>
                  </td>
                  <td className="py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusConfig[ps.maxStatus].color}`}>{statusConfig[ps.maxStatus].label}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
