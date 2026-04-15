/**
 * Exception Workflow Dashboard
 *
 * Manage security exception requests: review, approve/reject, renewals,
 * expiry alerts, and summary counts.
 *
 * Route: /exception-workflow
 */

import { useState } from "react";
import { AlertTriangle, CheckCircle2, XCircle, Clock, RefreshCw, ShieldAlert, Bell } from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

type ExceptionStatus = "pending" | "approved" | "rejected" | "needs-info" | "expired";
type ExceptionType = "policy-waiver" | "risk-acceptance" | "compensating-control" | "temporary-bypass" | "architectural-exception";
type Priority = "critical" | "high" | "medium" | "low";
type Decision = "approved" | "rejected" | "needs-info";

interface ExceptionRequest {
  id: string;
  policy_name: string;
  exception_type: ExceptionType;
  requestor: string;
  department: string;
  priority: Priority;
  status: ExceptionStatus;
  submitted_at: string;
  expires_at: string;
  risk_rating: number;
  reviewer: string;
  decision: Decision | null;
  decision_date: string | null;
  justification: string;
}

interface RenewalHistory {
  id: string;
  exception_id: string;
  policy_name: string;
  renewed_by: string;
  renewed_at: string;
  previous_expiry: string;
  new_expiry: string;
}

// ── Mock data ─────────────────────────────────────────────────────────────────

const MOCK_EXCEPTIONS: ExceptionRequest[] = [
  { id: "exc-001", policy_name: "Multi-Factor Authentication Policy",      exception_type: "policy-waiver",           requestor: "Alice Chen",     department: "Engineering",   priority: "critical", status: "pending",   submitted_at: "2026-04-10", expires_at: "2026-04-30", risk_rating: 82, reviewer: "Bob Smith",   decision: null,        decision_date: null,          justification: "Legacy system cannot support MFA integration currently." },
  { id: "exc-002", policy_name: "Privileged Access Management Standard",   exception_type: "compensating-control",    requestor: "Dan Lee",        department: "IT Ops",        priority: "high",     status: "approved",  submitted_at: "2026-03-15", expires_at: "2026-05-10", risk_rating: 65, reviewer: "Carol Wu",    decision: "approved",  decision_date: "2026-03-18",  justification: "Compensating control deployed — network segmentation active." },
  { id: "exc-003", policy_name: "Data Encryption at Rest Policy",          exception_type: "risk-acceptance",         requestor: "Eve Martinez",   department: "Finance",       priority: "high",     status: "rejected",  submitted_at: "2026-04-01", expires_at: "2026-06-01", risk_rating: 91, reviewer: "Frank Ng",    decision: "rejected",  decision_date: "2026-04-03",  justification: "Encryption overhead claimed too high — rejected, remediation required." },
  { id: "exc-004", policy_name: "Vulnerability Remediation SLA",           exception_type: "temporary-bypass",        requestor: "Grace Kim",      department: "Product",       priority: "medium",   status: "needs-info", submitted_at: "2026-04-08", expires_at: "2026-05-20", risk_rating: 58, reviewer: "Henry Park",  decision: "needs-info", decision_date: "2026-04-09",  justification: "Additional context required on affected asset scope." },
  { id: "exc-005", policy_name: "Network Segmentation Requirement",        exception_type: "architectural-exception", requestor: "Ivan Torres",    department: "Cloud Infra",   priority: "critical", status: "approved",  submitted_at: "2026-02-20", expires_at: "2026-04-25", risk_rating: 74, reviewer: "Jana Wells",  decision: "approved",  decision_date: "2026-02-23",  justification: "Migration to new VPC architecture in progress — 90-day grace period approved." },
  { id: "exc-006", policy_name: "Software Composition Analysis Gate",      exception_type: "policy-waiver",           requestor: "Karl Stone",     department: "DevOps",        priority: "medium",   status: "approved",  submitted_at: "2026-03-28", expires_at: "2026-05-28", risk_rating: 44, reviewer: "Lisa Ray",    decision: "approved",  decision_date: "2026-04-01",  justification: "SCA tooling upgrade in progress; manual review process active." },
  { id: "exc-007", policy_name: "Endpoint Detection & Response Coverage",  exception_type: "compensating-control",    requestor: "Mike Adams",     department: "HR",            priority: "low",      status: "expired",   submitted_at: "2026-01-01", expires_at: "2026-04-01", risk_rating: 37, reviewer: "Nina Patel",  decision: "approved",  decision_date: "2026-01-05",  justification: "HR kiosks exempt; physical security compensates." },
  { id: "exc-008", policy_name: "Password Complexity Policy",              exception_type: "risk-acceptance",         requestor: "Olivia Brown",   department: "Customer Svc",  priority: "high",     status: "pending",   submitted_at: "2026-04-12", expires_at: "2026-06-12", risk_rating: 69, reviewer: "Paul Davis",  decision: null,        decision_date: null,          justification: "Legacy CRM vendor constrains password length to 8 chars." },
];

const MOCK_RENEWALS: RenewalHistory[] = [
  { id: "ren-001", exception_id: "exc-002", policy_name: "Privileged Access Management Standard", renewed_by: "Dan Lee",     renewed_at: "2026-03-14", previous_expiry: "2026-03-15", new_expiry: "2026-05-10" },
  { id: "ren-002", exception_id: "exc-006", policy_name: "Software Composition Analysis Gate",     renewed_by: "Karl Stone",  renewed_at: "2026-03-27", previous_expiry: "2026-03-28", new_expiry: "2026-05-28" },
  { id: "ren-003", exception_id: "exc-005", policy_name: "Network Segmentation Requirement",       renewed_by: "Ivan Torres", renewed_at: "2026-02-19", previous_expiry: "2026-02-20", new_expiry: "2026-04-25" },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

const TODAY = new Date("2026-04-16");

function daysUntil(dateStr: string): number {
  return Math.ceil((new Date(dateStr).getTime() - TODAY.getTime()) / 86400000);
}

function isOverdue(dateStr: string): boolean {
  return daysUntil(dateStr) < 0;
}

function isExpiringSoon(dateStr: string): boolean {
  const d = daysUntil(dateStr);
  return d >= 0 && d <= 30;
}

function priorityColor(p: Priority): string {
  return p === "critical" ? "text-red-400" : p === "high" ? "text-orange-400" : p === "medium" ? "text-yellow-400" : "text-gray-400";
}

function priorityBg(p: Priority): string {
  return p === "critical" ? "bg-red-500/20 text-red-300" : p === "high" ? "bg-orange-500/20 text-orange-300" : p === "medium" ? "bg-yellow-500/20 text-yellow-300" : "bg-gray-500/20 text-gray-300";
}

function statusBadge(s: ExceptionStatus) {
  const map: Record<ExceptionStatus, string> = {
    pending: "bg-blue-500/20 text-blue-300",
    approved: "bg-green-500/20 text-green-300",
    rejected: "bg-red-500/20 text-red-300",
    "needs-info": "bg-amber-500/20 text-amber-300",
    expired: "bg-gray-500/20 text-gray-400",
  };
  return map[s];
}

function decisionBadge(d: Decision): string {
  return d === "approved" ? "bg-green-500/20 text-green-300" : d === "rejected" ? "bg-red-500/20 text-red-300" : "bg-amber-500/20 text-amber-300";
}

function typeBadge(t: ExceptionType): string {
  const map: Record<ExceptionType, string> = {
    "policy-waiver": "bg-purple-500/20 text-purple-300",
    "risk-acceptance": "bg-orange-500/20 text-orange-300",
    "compensating-control": "bg-cyan-500/20 text-cyan-300",
    "temporary-bypass": "bg-pink-500/20 text-pink-300",
    "architectural-exception": "bg-indigo-500/20 text-indigo-300",
  };
  return map[t];
}

function typeLabel(t: ExceptionType): string {
  return t.split("-").map(w => w[0].toUpperCase() + w.slice(1)).join(" ");
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ExceptionWorkflowDashboard() {
  const [selectedId, setSelectedId] = useState<string | null>("exc-001");
  const [filterStatus, setFilterStatus] = useState<string>("all");

  const selected = MOCK_EXCEPTIONS.find(e => e.id === selectedId) ?? null;

  const expiringSoon = MOCK_EXCEPTIONS.filter(e => e.status !== "expired" && isExpiringSoon(e.expires_at));
  const expired      = MOCK_EXCEPTIONS.filter(e => e.status === "expired" || isOverdue(e.expires_at));

  const counts = {
    total:     MOCK_EXCEPTIONS.length,
    pending:   MOCK_EXCEPTIONS.filter(e => e.status === "pending").length,
    approved:  MOCK_EXCEPTIONS.filter(e => e.status === "approved").length,
    rejected:  MOCK_EXCEPTIONS.filter(e => e.status === "rejected").length,
    expired:   MOCK_EXCEPTIONS.filter(e => e.status === "expired").length,
  };

  const filtered = filterStatus === "all" ? MOCK_EXCEPTIONS : MOCK_EXCEPTIONS.filter(e => e.status === filterStatus);

  const STATUSES = ["all", "pending", "approved", "rejected", "needs-info", "expired"];

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-amber-400" />
            Exception Workflow
          </h1>
          <p className="text-gray-400 text-sm mt-1">Security exception requests — review, approve, and track renewals</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Expiring-soon banner */}
      {expiringSoon.length > 0 && (
        <div className="flex items-center gap-3 bg-amber-500/10 border border-amber-500/30 rounded-lg p-4">
          <Bell className="w-5 h-5 text-amber-400 flex-shrink-0" />
          <span className="text-amber-300 text-sm font-medium">
            {expiringSoon.length} exception{expiringSoon.length > 1 ? "s" : ""} expiring within 30 days:&nbsp;
            {expiringSoon.map(e => e.policy_name).join(", ")}
          </span>
        </div>
      )}

      {/* Expired alert */}
      {expired.length > 0 && (
        <div className="flex items-center gap-3 bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <span className="text-red-300 text-sm font-medium">
            {expired.length} expired exception{expired.length > 1 ? "s" : ""} require immediate action.
          </span>
        </div>
      )}

      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        {[
          { label: "Total",    value: counts.total,    color: "text-white" },
          { label: "Pending",  value: counts.pending,  color: "text-blue-400" },
          { label: "Approved", value: counts.approved, color: "text-green-400" },
          { label: "Rejected", value: counts.rejected, color: "text-red-400" },
          { label: "Expired",  value: counts.expired,  color: "text-gray-400" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
            <div className={`text-3xl font-bold ${k.color}`}>{k.value}</div>
            <div className="text-gray-400 text-xs mt-1">{k.label}</div>
          </div>
        ))}
      </div>

      {/* Status filter tabs */}
      <div className="flex gap-2 flex-wrap">
        {STATUSES.map(s => (
          <button
            key={s}
            onClick={() => setFilterStatus(s)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${filterStatus === s ? "bg-indigo-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}
          >
            {s === "all" ? "All" : s}
          </button>
        ))}
      </div>

      {/* Main layout: table + detail panel */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Exceptions table */}
        <div className="xl:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white">Exception Requests</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                  <th className="text-left p-3">Policy</th>
                  <th className="text-left p-3">Type</th>
                  <th className="text-left p-3">Requestor</th>
                  <th className="text-left p-3">Priority</th>
                  <th className="text-left p-3">Status</th>
                  <th className="text-left p-3">Expires</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(exc => {
                  const days = daysUntil(exc.expires_at);
                  const overdue = days < 0;
                  const soon = !overdue && days <= 30;
                  return (
                    <tr
                      key={exc.id}
                      onClick={() => setSelectedId(exc.id)}
                      className={`border-b border-gray-700/50 cursor-pointer hover:bg-gray-700/40 transition-colors ${selectedId === exc.id ? "bg-gray-700/60" : ""}`}
                    >
                      <td className="p-3 text-gray-200 max-w-[200px] truncate">{exc.policy_name}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${typeBadge(exc.exception_type)}`}>
                          {typeLabel(exc.exception_type)}
                        </span>
                      </td>
                      <td className="p-3 text-gray-300">{exc.requestor}</td>
                      <td className="p-3">
                        <span className={`font-semibold text-xs uppercase ${priorityColor(exc.priority)}`}>{exc.priority}</span>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded-full text-xs font-medium capitalize ${statusBadge(exc.status)}`}>{exc.status}</span>
                      </td>
                      <td className={`p-3 text-xs font-medium ${overdue ? "text-red-400" : soon ? "text-amber-400" : "text-gray-300"}`}>
                        {overdue ? `${Math.abs(days)}d overdue` : soon ? `${days}d left` : exc.expires_at}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail / review panel */}
        <div className="space-y-4">
          {selected ? (
            <>
              <div className="bg-gray-800 rounded-lg p-5 space-y-4">
                <h2 className="font-semibold text-white text-sm">Review Panel</h2>
                <div>
                  <div className="text-xs text-gray-400 mb-1">Policy</div>
                  <div className="text-gray-200 text-sm font-medium">{selected.policy_name}</div>
                </div>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Requestor</div>
                    <div className="text-gray-200">{selected.requestor}</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Department</div>
                    <div className="text-gray-200">{selected.department}</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Reviewer</div>
                    <div className="text-gray-200">{selected.reviewer}</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Risk Rating</div>
                    <div className={`font-bold ${selected.risk_rating >= 75 ? "text-red-400" : selected.risk_rating >= 50 ? "text-orange-400" : "text-green-400"}`}>
                      {selected.risk_rating}/100
                    </div>
                  </div>
                </div>
                {selected.decision && (
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Decision</div>
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium capitalize ${decisionBadge(selected.decision)}`}>
                      {selected.decision}
                    </span>
                    {selected.decision_date && (
                      <span className="text-gray-400 text-xs ml-2">on {selected.decision_date}</span>
                    )}
                  </div>
                )}
                <div>
                  <div className="text-xs text-gray-400 mb-1">Justification</div>
                  <p className="text-gray-300 text-xs leading-relaxed">{selected.justification}</p>
                </div>
                {/* Risk bar */}
                <div>
                  <div className="text-xs text-gray-400 mb-1">Risk Level</div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${selected.risk_rating >= 75 ? "bg-red-500" : selected.risk_rating >= 50 ? "bg-orange-400" : "bg-green-500"}`}
                      style={{ width: `${selected.risk_rating}%` }}
                    />
                  </div>
                  <div className="text-xs text-gray-400 mt-1">{selected.risk_rating}% risk score</div>
                </div>
              </div>

              {/* Priority badge */}
              <div className={`rounded-lg p-3 text-sm font-medium flex items-center gap-2 ${priorityBg(selected.priority)}`}>
                <AlertTriangle className="w-4 h-4" />
                Priority: {selected.priority.toUpperCase()}
              </div>
            </>
          ) : (
            <div className="bg-gray-800 rounded-lg p-6 text-center text-gray-400 text-sm">
              Select an exception to view details
            </div>
          )}

          {/* Renewal history */}
          <div className="bg-gray-800 rounded-lg p-5">
            <h2 className="font-semibold text-white text-sm mb-3">Renewal History</h2>
            <div className="space-y-3">
              {MOCK_RENEWALS.map(r => (
                <div key={r.id} className="border-l-2 border-indigo-500/50 pl-3">
                  <div className="text-gray-300 text-xs font-medium">{r.policy_name}</div>
                  <div className="text-gray-400 text-xs mt-0.5">
                    Renewed by {r.renewed_by} on {r.renewed_at}
                  </div>
                  <div className="text-gray-500 text-xs mt-0.5">
                    {r.previous_expiry} → <span className="text-green-400">{r.new_expiry}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Summary by type */}
      <div className="bg-gray-800 rounded-lg p-5">
        <h2 className="font-semibold text-white text-sm mb-4">Summary by Exception Type</h2>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {(["policy-waiver", "risk-acceptance", "compensating-control", "temporary-bypass", "architectural-exception"] as ExceptionType[]).map(t => {
            const c = MOCK_EXCEPTIONS.filter(e => e.exception_type === t).length;
            return (
              <div key={t} className="text-center">
                <div className={`text-xl font-bold text-white mb-1`}>{c}</div>
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${typeBadge(t)}`}>
                  {typeLabel(t)}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
