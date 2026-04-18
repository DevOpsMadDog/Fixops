/**
 * Access Governance Dashboard
 *
 * Shows entitlements table with expiry warnings, SoD violations list,
 * role definitions grid, revoke entitlement action, and access summary stats.
 *
 * Route: /access-governance
 * API: GET /api/v1/access-governance
 */

import { useState, useEffect } from "react";

const API_BASE = "/api/v1/access-governance";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

// ── Types ──────────────────────────────────────────────────────

type AccessLevel = "read" | "write" | "admin" | "owner" | "execute";
type SoDSeverity = "critical" | "high" | "medium" | "low";
type RoleType = "functional" | "technical" | "privileged" | "service";
type RiskLevel = "critical" | "high" | "medium" | "low";

interface Entitlement {
  id: string;
  user_id: string;
  resource: string;
  access_level: AccessLevel;
  granted_by: string;
  granted_at: string;
  expires_at: string | null;
  active: boolean;
  revoked: boolean;
}

interface SoDViolation {
  id: string;
  rule_name: string;
  severity: SoDSeverity;
  user_id: string;
  description: string;
  detected_at: string;
  acknowledged: boolean;
}

interface RoleDefinition {
  id: string;
  role_name: string;
  role_type: RoleType;
  user_count: number;
  risk_level: RiskLevel;
  description: string;
  permissions_count: number;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ENTITLEMENTS: Entitlement[] = [
  { id: "ent-001", user_id: "alice@corp.io",  resource: "prod-db-main",         access_level: "admin",   granted_by: "IAM Admin",    granted_at: "2025-10-01", expires_at: "2026-04-30", active: true,  revoked: false },
  { id: "ent-002", user_id: "bob@corp.io",    resource: "s3://data-lake-raw",   access_level: "write",   granted_by: "DataEng Lead", granted_at: "2025-12-15", expires_at: "2026-05-15", active: true,  revoked: false },
  { id: "ent-003", user_id: "carol@corp.io",  resource: "k8s-cluster-prod",     access_level: "owner",   granted_by: "CTO",          granted_at: "2024-06-01", expires_at: "2026-04-20", active: true,  revoked: false },
  { id: "ent-004", user_id: "dave@corp.io",   resource: "github-org/core",      access_level: "write",   granted_by: "DevOps Mgr",   granted_at: "2026-01-10", expires_at: null,          active: true,  revoked: false },
  { id: "ent-005", user_id: "eve@corp.io",    resource: "vault-secrets-prod",   access_level: "read",    granted_by: "SecAdmin",     granted_at: "2025-11-20", expires_at: "2026-04-19", active: true,  revoked: false },
  { id: "ent-006", user_id: "frank@corp.io",  resource: "billing-api",          access_level: "execute", granted_by: "Finance Mgr",  granted_at: "2025-09-01", expires_at: "2026-04-25", active: true,  revoked: false },
  { id: "ent-007", user_id: "grace@corp.io",  resource: "analytics-dashboard",  access_level: "read",    granted_by: "BI Lead",      granted_at: "2026-02-01", expires_at: "2027-02-01", active: true,  revoked: false },
  { id: "ent-008", user_id: "henry@corp.io",  resource: "prod-db-main",         access_level: "write",   granted_by: "DBA",          granted_at: "2025-08-15", expires_at: "2026-08-15", active: false, revoked: true  },
];

const MOCK_VIOLATIONS: SoDViolation[] = [
  { id: "sod-001", rule_name: "Approve + Initiate Payments", severity: "critical", user_id: "alice@corp.io",  description: "User has both payment initiation and approval rights — bypasses 4-eyes control.", detected_at: "2026-04-14", acknowledged: false },
  { id: "sod-002", rule_name: "Code Deploy + Code Review",   severity: "high",     user_id: "dave@corp.io",   description: "User can merge their own PRs and trigger production deploys.",                  detected_at: "2026-04-12", acknowledged: false },
  { id: "sod-003", rule_name: "Create + Approve Vendors",    severity: "high",     user_id: "frank@corp.io",  description: "User can create vendor records and approve purchase orders.",                   detected_at: "2026-04-10", acknowledged: true  },
  { id: "sod-004", rule_name: "Admin + Audit Log Access",    severity: "medium",   user_id: "carol@corp.io",  description: "Administrator also has rights to modify audit logs.",                          detected_at: "2026-04-08", acknowledged: false },
];

const MOCK_ROLES: RoleDefinition[] = [
  { id: "role-001", role_name: "Platform Admin",       role_type: "privileged",  user_count: 4,  risk_level: "critical", description: "Full platform access including prod DB and infra.", permissions_count: 142 },
  { id: "role-002", role_name: "Security Analyst",     role_type: "functional",  user_count: 12, risk_level: "high",     description: "Read access to all security events and alerts.", permissions_count: 67 },
  { id: "role-003", role_name: "Developer",            role_type: "technical",   user_count: 48, risk_level: "medium",   description: "Code access, staging deploy, read-only prod.", permissions_count: 38 },
  { id: "role-004", role_name: "Read Only",            role_type: "functional",  user_count: 95, risk_level: "low",      description: "Dashboard and report viewing only.", permissions_count: 12 },
  { id: "role-005", role_name: "CI/CD Service Account",role_type: "service",     user_count: 8,  risk_level: "high",     description: "Deploy pipelines to staging and production.", permissions_count: 29 },
  { id: "role-006", role_name: "DBA",                  role_type: "privileged",  user_count: 3,  risk_level: "critical", description: "Database administration and schema changes.", permissions_count: 88 },
];

// ── Helpers ────────────────────────────────────────────────────

const accessLevelConfig: Record<AccessLevel, { label: string; color: string }> = {
  read:    { label: "Read",    color: "bg-blue-900 text-blue-200" },
  write:   { label: "Write",   color: "bg-amber-900 text-amber-200" },
  admin:   { label: "Admin",   color: "bg-red-900 text-red-200" },
  owner:   { label: "Owner",   color: "bg-purple-900 text-purple-200" },
  execute: { label: "Execute", color: "bg-cyan-900 text-cyan-200" },
};

const sodSeverityConfig: Record<SoDSeverity, { label: string; color: string }> = {
  critical: { label: "Critical", color: "bg-red-700 text-red-100" },
  high:     { label: "High",     color: "bg-orange-700 text-orange-100" },
  medium:   { label: "Medium",   color: "bg-amber-700 text-amber-100" },
  low:      { label: "Low",      color: "bg-green-700 text-green-100" },
};

const roleTypeConfig: Record<RoleType, { label: string; color: string }> = {
  functional: { label: "Functional", color: "bg-blue-700 text-blue-100" },
  technical:  { label: "Technical",  color: "bg-cyan-700 text-cyan-100" },
  privileged: { label: "Privileged", color: "bg-red-700 text-red-100" },
  service:    { label: "Service",    color: "bg-purple-700 text-purple-100" },
};

const riskLevelConfig: Record<RiskLevel, { label: string; color: string; text: string }> = {
  critical: { label: "Critical", color: "bg-red-900/40 border border-red-700", text: "text-red-400" },
  high:     { label: "High",     color: "bg-orange-900/40 border border-orange-700", text: "text-orange-400" },
  medium:   { label: "Medium",   color: "bg-amber-900/40 border border-amber-700", text: "text-amber-400" },
  low:      { label: "Low",      color: "bg-green-900/40 border border-green-600", text: "text-green-400" },
};

const TODAY = "2026-04-16";

function daysUntil(dateStr: string): number {
  const diff = new Date(dateStr).getTime() - new Date(TODAY).getTime();
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

function expiryWarning(expires_at: string | null): { warn: boolean; label: string } {
  if (!expires_at) return { warn: false, label: "No expiry" };
  const days = daysUntil(expires_at);
  if (days < 0)  return { warn: true,  label: "Expired" };
  if (days <= 30) return { warn: true,  label: `${days}d left` };
  return { warn: false, label: expires_at };
}

// ── Component ──────────────────────────────────────────────────

export default function AccessGovernanceDashboard() {
  const [entitlements, setEntitlements] = useState<Entitlement[]>(MOCK_ENTITLEMENTS);
  const [error, setError] = useState<string | null>(null);
  const [violations, setViolations] = useState<SoDViolation[]>(MOCK_VIOLATIONS);
  const [revokeMsg, setRevokeMsg] = useState<string | null>(null);
  const [ackMsg, setAckMsg] = useState<string | null>(null);


  const fetchData = () => {
    setError(null);
    fetch(`${API_BASE}/entitlements`, { headers: getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => { if (Array.isArray(d)) setEntitlements(d); })
    .catch(err => setError(err.message || 'Failed to load data'));
    fetch(`${API_BASE}/violations`, { headers: getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => { if (Array.isArray(d)) setViolations(d); })
    .catch(err => setError(err.message || 'Failed to load data'));
  };

  useEffect(() => { fetchData(); }, []);

  function handleRevoke(id: string) {
    setEntitlements(prev => prev.map(e => e.id === id ? { ...e, active: false, revoked: true } : e));
    setRevokeMsg("Entitlement revoked successfully.");
    setTimeout(() => setRevokeMsg(null), 3000);
  }

  function handleAcknowledge(id: string) {
    setViolations(prev => prev.map(v => v.id === id ? { ...v, acknowledged: true } : v));
    setAckMsg("Violation acknowledged.");
    setTimeout(() => setAckMsg(null), 3000);
  }

  const activeEntitlements = entitlements.filter(e => e.active && !e.revoked).length;
  const revokedEntitlements = entitlements.filter(e => e.revoked).length;
  const openViolations = violations.filter(v => !v.acknowledged).length;
  const highRiskRoles = MOCK_ROLES.filter(r => r.risk_level === "critical" || r.risk_level === "high").length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
          <p className="font-medium">Error loading data</p>
          <p className="text-sm">{error}</p>
          <button onClick={() => { setError(null); fetchData(); }} className="mt-2 text-sm underline">Retry</button>
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Access Governance</h1>
          <p className="text-gray-400 mt-1">Entitlements, SoD violations, role definitions, and access lifecycle</p>
        </div>
        <div className="flex gap-3">
          {revokeMsg && <div className="bg-green-800/40 border border-green-600 text-green-300 px-4 py-2 rounded text-sm">{revokeMsg}</div>}
          {ackMsg && <div className="bg-blue-800/40 border border-blue-600 text-blue-300 px-4 py-2 rounded text-sm">{ackMsg}</div>}
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Entitlements", value: entitlements.length,  color: "text-blue-400" },
          { label: "Active",             value: activeEntitlements,   color: "text-green-400" },
          { label: "Revoked",            value: revokedEntitlements,  color: "text-gray-400" },
          { label: "Open Violations",    value: openViolations,       color: "text-red-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Entitlements Table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Entitlements</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-3">User</th>
                <th className="text-left pb-2 pr-3">Resource</th>
                <th className="text-left pb-2 pr-3">Level</th>
                <th className="text-left pb-2 pr-3">Granted By</th>
                <th className="text-left pb-2 pr-3">Expires</th>
                <th className="text-left pb-2">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {entitlements.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                entitlements.map(ent => {
                const expiry = expiryWarning(ent.expires_at);
                return (
                  <tr key={ent.id} className={`hover:bg-gray-700/30 transition-colors ${ent.revoked ? "opacity-50" : ""}`}>
                    <td className="py-2.5 pr-3 text-gray-200 font-medium">{ent.user_id}</td>
                    <td className="py-2.5 pr-3 text-gray-400 font-mono text-xs">{ent.resource}</td>
                    <td className="py-2.5 pr-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${accessLevelConfig[ent.access_level].color}`}>
                        {accessLevelConfig[ent.access_level].label}
                      </span>
                    </td>
                    <td className="py-2.5 pr-3 text-gray-400">{ent.granted_by}</td>
                    <td className="py-2.5 pr-3">
                      <span className={`text-xs font-medium ${expiry.warn ? "text-red-400" : "text-gray-400"}`}>
                        {expiry.label}
                        {expiry.warn && !ent.revoked && " ⚠"}
                      </span>
                    </td>
                    <td className="py-2.5">
                      {ent.revoked ? (
                        <span className="text-gray-500 text-xs">Revoked</span>
                      ) : (
                        <button
                          onClick={() => handleRevoke(ent.id)}
                          className="px-2 py-1 bg-red-800/50 hover:bg-red-700 text-red-300 hover:text-white rounded text-xs font-medium transition-colors"
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* SoD Violations */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Segregation of Duties Violations</h2>
          <span className="bg-red-800/50 text-red-300 px-2 py-1 rounded text-xs font-medium">{openViolations} open</span>
        </div>
        <div className="space-y-3">
          {violations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            violations.map(v => (
            <div key={v.id} className={`p-4 rounded-lg border transition-opacity ${v.acknowledged ? "opacity-50 border-gray-700 bg-gray-700/20" : "border-gray-600 bg-gray-700/30"}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${sodSeverityConfig[v.severity].color}`}>
                      {sodSeverityConfig[v.severity].label}
                    </span>
                    <span className="text-gray-300 text-sm font-medium">{v.rule_name}</span>
                    {v.acknowledged && <span className="bg-gray-600 text-gray-300 px-2 py-0.5 rounded text-xs">Acknowledged</span>}
                  </div>
                  <p className="text-gray-400 text-xs">{v.description}</p>
                  <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                    <span>User: <span className="text-gray-300">{v.user_id}</span></span>
                    <span>Detected: {v.detected_at}</span>
                  </div>
                </div>
                {!v.acknowledged && (
                  <button
                    onClick={() => handleAcknowledge(v.id)}
                    className="shrink-0 px-3 py-1.5 bg-blue-800/50 hover:bg-blue-700 text-blue-300 hover:text-white rounded text-xs font-medium transition-colors"
                  >
                    Acknowledge
                  </button>
                )}
              </div>
            </div>
          ))
          )}
        </div>
      </div>

      {/* Role Definitions Grid */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Role Definitions</h2>
          <span className="text-gray-400 text-sm">{highRiskRoles} high-risk role{highRiskRoles !== 1 ? "s" : ""}</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {MOCK_ROLES.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            MOCK_ROLES.map(role => (
            <div key={role.id} className={`rounded-lg p-4 space-y-2 ${riskLevelConfig[role.risk_level].color}`}>
              <div className="flex items-start justify-between gap-2">
                <p className="text-white font-semibold">{role.role_name}</p>
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${roleTypeConfig[role.role_type].color}`}>
                  {roleTypeConfig[role.role_type].label}
                </span>
              </div>
              <p className="text-gray-400 text-xs">{role.description}</p>
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-400">{role.user_count} user{role.user_count !== 1 ? "s" : ""}</span>
                <span className="text-gray-400">{role.permissions_count} permissions</span>
                <span className={`font-semibold ${riskLevelConfig[role.risk_level].text}`}>
                  {riskLevelConfig[role.risk_level].label}
                </span>
              </div>
            </div>
          ))
          )}
        </div>
      </div>
    </div>
  );
}
