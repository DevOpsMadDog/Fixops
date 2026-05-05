/**
 * ExceptionWorkflowPanel — approval workflow from /api/v1/exception-workflow/requests
 * Shows request queue with status, priority, requestor, and workflow summary.
 */

import { useEffect, useState } from "react";
import { GitPullRequest, RefreshCw, Clock } from "lucide-react";
import { exceptionWorkflowApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface WorkflowRequest {
  request_id: string;
  policy_name: string;
  exception_type: string;
  requestor: string;
  status: string;
  priority: string;
  business_justification?: string;
  expires_at?: string;
  created_at?: string;
  org_id?: string;
}

interface WorkflowSummary {
  total: number;
  pending: number;
  approved: number;
  rejected: number;
  needs_info: number;
  expiring_soon: number;
}

const PRIORITY_COLORS: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-slate-600 text-slate-200",
};

const STATUS_COLORS: Record<string, string> = {
  approved: "bg-green-800 text-green-200",
  pending: "bg-amber-800 text-amber-200",
  rejected: "bg-red-800 text-red-200",
  "needs-info": "bg-blue-800 text-blue-200",
  revoked: "bg-purple-800 text-purple-200",
};

function priClass(p: string) {
  return PRIORITY_COLORS[p?.toLowerCase()] ?? PRIORITY_COLORS.medium;
}
function statusClass(s: string) {
  return STATUS_COLORS[s?.toLowerCase()] ?? STATUS_COLORS.pending;
}

export function ExceptionWorkflowPanel() {
  const [requests, setRequests] = useState<WorkflowRequest[]>([]);
  const [summary, setSummary] = useState<WorkflowSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      exceptionWorkflowApi.list("default"),
      exceptionWorkflowApi.summary("default"),
    ])
      .then(([listRes, summaryRes]) => {
        const raw = listRes.data;
        setRequests(Array.isArray(raw) ? raw : raw?.requests ?? raw?.items ?? []);
        setSummary(summaryRes.data as WorkflowSummary);
      })
      .catch((e: Error) => setError(e.message ?? "Failed to load workflow requests"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 mt-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-16 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  const filtered = filter === "all" ? requests : requests.filter(r => r.status === filter);

  return (
    <div className="space-y-4 mt-2">
      {/* Summary bar */}
      {summary && (
        <div className="grid grid-cols-5 gap-3">
          {[
            { label: "Total", value: summary.total, color: "text-slate-300" },
            { label: "Pending", value: summary.pending, color: "text-amber-400" },
            { label: "Approved", value: summary.approved, color: "text-green-400" },
            { label: "Rejected", value: summary.rejected, color: "text-red-400" },
            { label: "Needs Info", value: summary.needs_info, color: "text-blue-400" },
          ].map(s => (
            <div key={s.label} className="rounded-lg bg-muted/30 border border-border p-3 text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value ?? 0}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter + refresh */}
      <div className="flex items-center gap-2">
        {["all", "pending", "approved", "rejected", "needs-info"].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              filter === f
                ? "bg-primary text-primary-foreground"
                : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
            }`}
          >
            {f === "needs-info" ? "Needs Info" : f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
        <button
          onClick={load}
          className="ml-auto p-1.5 rounded-md hover:bg-muted/40 text-muted-foreground"
          aria-label="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Requests list */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={GitPullRequest}
          title="No workflow requests"
          description={filter === "all" ? "No exception workflow requests found." : `No ${filter} requests.`}
        />
      ) : (
        <div className="space-y-2">
          {filtered.map(req => (
            <div
              key={req.request_id}
              className="rounded-lg border border-border bg-muted/10 p-4 flex items-start justify-between gap-4"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-medium text-sm truncate">{req.policy_name}</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${priClass(req.priority)}`}>
                    {req.priority}
                  </span>
                </div>
                <div className="text-xs text-muted-foreground space-y-0.5">
                  <div>Type: {req.exception_type} · Requestor: {req.requestor || "—"}</div>
                  {req.business_justification && (
                    <div className="truncate">Justification: {req.business_justification}</div>
                  )}
                  {req.expires_at && (
                    <div className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      Expires: {new Date(req.expires_at).toLocaleDateString()}
                    </div>
                  )}
                </div>
              </div>
              <div className="flex-shrink-0">
                <span className={`px-2 py-1 rounded text-xs font-medium ${statusClass(req.status)}`}>
                  {req.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {requests.length > 0 && (
        <p className="text-xs text-muted-foreground text-right">
          {filtered.length} of {requests.length} requests
        </p>
      )}
    </div>
  );
}
