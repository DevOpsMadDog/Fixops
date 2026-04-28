// FOLDED into AssetGraph hero 2026-04-27 — access via /asset-graph?tab=access-governance
// Wave 3 Phase 3 UX consolidation fold (target: 30 screens)
/**
 * Access Governance Dashboard
 *
 * Shows entitlements table with expiry warnings, SoD violations list,
 * role definitions grid, revoke entitlement action, and access summary stats.
 *
 * Route: /access-governance
 * API: GET /api/v1/access-governance/{expiring,summary}
 */

import { useState, useEffect } from "react";
import { ShieldOff, AlertTriangle, Users } from "lucide-react";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

const API_BASE = "/api/v1/access-governance";
const ORG_ID = "juice-shop-corp";

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json() as Promise<T>;
}

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

function daysUntil(dateStr: string): number {
  const diff = new Date(dateStr).getTime() - Date.now();
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
  const [entitlements, setEntitlements] = useState<Entitlement[]>([]);
  const [violations, setViolations] = useState<SoDViolation[]>([]);
  const [roles, setRoles] = useState<RoleDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [revokeMsg, setRevokeMsg] = useState<string | null>(null);
  const [ackMsg, setAckMsg] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    Promise.allSettled([
      apiFetch<Entitlement[] | { items?: Entitlement[]; entitlements?: Entitlement[] }>(`${API_BASE}/expiring?org_id=${ORG_ID}`),
      apiFetch<{ violations?: SoDViolation[]; roles?: RoleDefinition[] }>(`${API_BASE}/summary?org_id=${ORG_ID}`),
    ]).then(([entRes, sumRes]) => {
      if (!mounted) return;
      if (entRes.status === "fulfilled") {
        const v = entRes.value;
        const arr = Array.isArray(v) ? v : (v.entitlements ?? v.items ?? []);
        setEntitlements(arr);
      }
      if (sumRes.status === "fulfilled") {
        const d = sumRes.value;
        if (Array.isArray(d?.violations)) setViolations(d.violations);
        if (Array.isArray(d?.roles)) setRoles(d.roles);
      }
      setLoading(false);
    });
    return () => { mounted = false; };
  }, []);

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

  if (loading) return <PageSkeleton />;

  const activeEntitlements = entitlements.filter(e => e.active && !e.revoked).length;
  const revokedEntitlements = entitlements.filter(e => e.revoked).length;
  const openViolations = violations.filter(v => !v.acknowledged).length;
  const highRiskRoles = roles.filter(r => r.risk_level === "critical" || r.risk_level === "high").length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
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

      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Entitlements</h2>
        {entitlements.length === 0 ? (
          <EmptyState icon={ShieldOff} title="No entitlements found" description="Connect an IAM source to start tracking access entitlements." />
        ) : (
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
                {entitlements.map(ent => {
                  const expiry = expiryWarning(ent.expires_at);
                  return (
                    <tr key={ent.id} className={`hover:bg-gray-700/30 transition-colors ${ent.revoked ? "opacity-50" : ""}`}>
                      <td className="py-2.5 pr-3 text-gray-200 font-medium">{ent.user_id}</td>
                      <td className="py-2.5 pr-3 text-gray-400 font-mono text-xs">{ent.resource}</td>
                      <td className="py-2.5 pr-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${accessLevelConfig[ent.access_level]?.color ?? "bg-gray-700 text-gray-200"}`}>
                          {accessLevelConfig[ent.access_level]?.label ?? ent.access_level}
                        </span>
                      </td>
                      <td className="py-2.5 pr-3 text-gray-400">{ent.granted_by}</td>
                      <td className="py-2.5 pr-3">
                        <span className={`text-xs font-medium ${expiry.warn ? "text-red-400" : "text-gray-400"}`}>
                          {expiry.label}{expiry.warn && !ent.revoked && " ⚠"}
                        </span>
                      </td>
                      <td className="py-2.5">
                        {ent.revoked ? (
                          <span className="text-gray-500 text-xs">Revoked</span>
                        ) : (
                          <button onClick={() => handleRevoke(ent.id)} className="px-2 py-1 bg-red-800/50 hover:bg-red-700 text-red-300 hover:text-white rounded text-xs font-medium transition-colors">
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Segregation of Duties Violations</h2>
          <span className="bg-red-800/50 text-red-300 px-2 py-1 rounded text-xs font-medium">{openViolations} open</span>
        </div>
        {violations.length === 0 ? (
          <EmptyState icon={AlertTriangle} title="No SoD violations" description="No segregation-of-duties violations detected." />
        ) : (
          <div className="space-y-3">
            {violations.map(v => (
              <div key={v.id} className={`p-4 rounded-lg border transition-opacity ${v.acknowledged ? "opacity-50 border-gray-700 bg-gray-700/20" : "border-gray-600 bg-gray-700/30"}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${sodSeverityConfig[v.severity]?.color ?? "bg-gray-700 text-gray-200"}`}>
                        {sodSeverityConfig[v.severity]?.label ?? v.severity}
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
                    <button onClick={() => handleAcknowledge(v.id)} className="shrink-0 px-3 py-1.5 bg-blue-800/50 hover:bg-blue-700 text-blue-300 hover:text-white rounded text-xs font-medium transition-colors">
                      Acknowledge
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Role Definitions</h2>
          <span className="text-gray-400 text-sm">{highRiskRoles} high-risk role{highRiskRoles !== 1 ? "s" : ""}</span>
        </div>
        {roles.length === 0 ? (
          <EmptyState icon={Users} title="No roles defined" description="No role definitions returned by the access governance API." />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {roles.map(role => (
              <div key={role.id} className={`rounded-lg p-4 space-y-2 ${riskLevelConfig[role.risk_level]?.color ?? ""}`}>
                <div className="flex items-start justify-between gap-2">
                  <p className="text-white font-semibold">{role.role_name}</p>
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${roleTypeConfig[role.role_type]?.color ?? ""}`}>
                    {roleTypeConfig[role.role_type]?.label ?? role.role_type}
                  </span>
                </div>
                <p className="text-gray-400 text-xs">{role.description}</p>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-400">{role.user_count} user{role.user_count !== 1 ? "s" : ""}</span>
                  <span className="text-gray-400">{role.permissions_count} permissions</span>
                  <span className={`font-semibold ${riskLevelConfig[role.risk_level]?.text ?? ""}`}>
                    {riskLevelConfig[role.risk_level]?.label ?? role.risk_level}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
