// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Compliance Workflow Dashboard - Live API
 * Route: /compliance-workflows
 * API: GET /api/v1/compliance-workflows/{workflows,overdue-tasks}
 */

import { useState, useEffect } from "react";
import { ClipboardCheck, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const frameworkColor = (f: string) => ({ SOC2: "bg-blue-700 text-blue-100", ISO27001: "bg-purple-700 text-purple-100", "PCI-DSS": "bg-yellow-700 text-yellow-100", HIPAA: "bg-green-700 text-green-100", NIST: "bg-cyan-700 text-cyan-100", GDPR: "bg-orange-700 text-orange-100", CIS: "bg-indigo-700 text-indigo-100", FedRAMP: "bg-red-700 text-red-100" }[f] ?? "bg-gray-700 text-gray-200");
const statusColor = (s: string) => ({ not_started: "bg-gray-700 text-gray-200", in_progress: "bg-blue-700 text-blue-100", review: "bg-amber-700 text-amber-100", approved: "bg-green-700 text-green-100", closed: "bg-gray-600 text-gray-300" }[s] ?? "bg-gray-700 text-gray-200");

export default function ComplianceWorkflowDashboard() {
  const [workflows, setWorkflows] = useState<any[]>([]);
  const [overdueTasks, setOverdueTasks] = useState<any[]>([]);
  const [selectedWorkflow, setSelectedWorkflow] = useState<string>("");
  const [filterFramework, setFilterFramework] = useState<string>("All");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [wf, ov] = await Promise.allSettled([
        apiFetch<any>("/api/v1/compliance-workflows/workflows"),
        apiFetch<any>("/api/v1/compliance-workflows/overdue-tasks"),
      ]);
      if (wf.status === "fulfilled") {
        const v = wf.value as any;
        const arr = Array.isArray(v) ? v : (v.workflows ?? v.items ?? []);
        setWorkflows(arr);
        if (arr.length && !selectedWorkflow) setSelectedWorkflow(arr[0].id);
      }
      if (ov.status === "fulfilled") {
        const v = ov.value as any;
        setOverdueTasks(Array.isArray(v) ? v : (v.tasks ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const frameworks = Array.from(new Set(workflows.map(w => w.framework)));
  const filtered = filterFramework === "All" ? workflows : workflows.filter(w => w.framework === filterFramework);
  const totalWorkflows = workflows.length;
  const activeWorkflows = workflows.filter(w => w.status === "in_progress" || w.status === "review").length;
  const approvedWorkflows = workflows.filter(w => w.status === "approved").length;
  const overdueWorkflows = workflows.filter(w => w.overdue).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><ClipboardCheck className="w-6 h-6 text-cyan-400" /> Compliance Workflows</h1>
          <p className="text-gray-400 mt-1">Manage audit workflows, tasks, approvals</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : workflows.length === 0 ? <EmptyState icon={ClipboardCheck} title="No compliance workflows" description="Create a workflow to start tracking audit tasks." />
        : <>
          {frameworks.length > 0 && <div className="flex gap-2 flex-wrap">{["All", ...frameworks].map(f => (
            <button key={f} onClick={() => setFilterFramework(f)} className={`px-3 py-1.5 rounded text-xs font-medium ${filterFramework === f ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>{f}</button>
          ))}</div>}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[{label:"Total",value:totalWorkflows,color:"text-blue-400"},{label:"Active",value:activeWorkflows,color:"text-amber-400"},{label:"Approved",value:approvedWorkflows,color:"text-green-400"},{label:"Overdue",value:overdueWorkflows,color:"text-red-400"}].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>
          {overdueTasks.length > 0 && (
            <div className="bg-red-900/30 border border-red-700 rounded-lg p-4">
              <p className="text-red-400 font-semibold text-sm mb-2">Overdue Tasks ({overdueTasks.length})</p>
              <div className="flex flex-wrap gap-2">{overdueTasks.map(t => <span key={t.id} className="bg-red-800/50 text-red-200 px-2 py-1 rounded text-xs">{t.task_name} — {t.assignee}</span>)}</div>
            </div>
          )}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filtered.map(wf => (
              <div key={wf.id} onClick={() => setSelectedWorkflow(wf.id)} className={`bg-gray-800 rounded-lg p-4 cursor-pointer border-2 ${selectedWorkflow === wf.id ? "border-blue-500" : "border-transparent hover:border-gray-600"}`}>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${frameworkColor(wf.framework)}`}>{wf.framework}</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor(wf.status)}`}>{wf.status?.replace("_", " ")}</span>
                </div>
                <p className="text-white text-sm font-medium">{wf.name}</p>
                <p className="text-gray-500 text-xs mt-1">{wf.workflow_type} · {wf.owner}</p>
                <div className="mt-3 flex items-center gap-2">
                  <div className="flex-1 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${(wf.completion_rate ?? 0) >= 80 ? "bg-green-500" : (wf.completion_rate ?? 0) >= 40 ? "bg-amber-500" : "bg-red-500"}`} style={{ width: `${wf.completion_rate ?? 0}%` }} /></div>
                  <span className="text-xs text-gray-400 font-medium">{wf.completion_rate ?? 0}%</span>
                </div>
                {wf.overdue && <p className="text-red-400 text-xs mt-1 font-medium">OVERDUE</p>}
              </div>
            ))}
          </div>
        </>}
    </div>
  );
}
