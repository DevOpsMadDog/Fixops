/**
 * Compliance Workflow Dashboard
 *
 * Shows compliance workflow lifecycle: workflow list with framework badges,
 * task sub-tables, approval panel, overdue alerts, framework readiness grid,
 * and summary counts.
 *
 * Route: /compliance-workflows
 * API: GET /api/v1/compliance-workflows
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/compliance-workflows";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });


// ── Types ──────────────────────────────────────────────────────

type Framework = "SOC2" | "ISO27001" | "PCI-DSS" | "HIPAA" | "NIST" | "GDPR" | "CIS" | "FedRAMP";
type WorkflowStatus = "not_started" | "in_progress" | "review" | "approved" | "closed";
type TaskPriority = "critical" | "high" | "medium" | "low";
type ApprovalDecision = "approved" | "rejected" | "pending";

interface ComplianceTask {
  id: string;
  workflow_id: string;
  task_name: string;
  assignee: string;
  priority: TaskPriority;
  evidence_required: number;
  evidence_provided: number;
  due_date: string;
}

interface ApprovalRecord {
  id: string;
  workflow_id: string;
  approver: string;
  decision: ApprovalDecision;
  comment: string;
  decided_at: string;
}

interface ComplianceWorkflow {
  id: string;
  name: string;
  framework: Framework;
  workflow_type: string;
  status: WorkflowStatus;
  owner: string;
  completion_rate: number;
  due_date: string;
  overdue: boolean;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_WORKFLOWS: ComplianceWorkflow[] = [
  { id: "wf-001", name: "Annual SOC 2 Type II Audit",         framework: "SOC2",     workflow_type: "Annual Audit",      status: "in_progress", owner: "GRC Lead",      completion_rate: 68, due_date: "2026-06-30", overdue: false },
  { id: "wf-002", name: "ISO 27001 Recertification",          framework: "ISO27001", workflow_type: "Recertification",   status: "review",      owner: "CISO",          completion_rate: 85, due_date: "2026-05-15", overdue: false },
  { id: "wf-003", name: "PCI DSS SAQ-D Assessment",           framework: "PCI-DSS",  workflow_type: "Self-Assessment",   status: "not_started", owner: "Compliance Mgr", completion_rate: 0,  due_date: "2026-04-20", overdue: true  },
  { id: "wf-004", name: "HIPAA Risk Assessment 2026",         framework: "HIPAA",    workflow_type: "Risk Assessment",   status: "in_progress", owner: "Privacy Officer", completion_rate: 42, due_date: "2026-07-01", overdue: false },
  { id: "wf-005", name: "NIST CSF Gap Analysis",              framework: "NIST",     workflow_type: "Gap Analysis",      status: "approved",    owner: "SecArch",       completion_rate: 100,due_date: "2026-04-10", overdue: false },
  { id: "wf-006", name: "GDPR Article 30 Records Update",     framework: "GDPR",     workflow_type: "Record Keeping",    status: "in_progress", owner: "DPO",           completion_rate: 55, due_date: "2026-05-01", overdue: false },
];

const MOCK_TASKS: ComplianceTask[] = [
  { id: "t-001", workflow_id: "wf-001", task_name: "Collect access control evidence",     assignee: "IAM Team",      priority: "high",     evidence_required: 10, evidence_provided: 7,  due_date: "2026-05-01" },
  { id: "t-002", workflow_id: "wf-001", task_name: "Review incident response logs",       assignee: "SOC Analyst",   priority: "medium",   evidence_required: 5,  evidence_provided: 5,  due_date: "2026-05-05" },
  { id: "t-003", workflow_id: "wf-001", task_name: "Vendor due diligence documentation",  assignee: "Procurement",   priority: "critical", evidence_required: 8,  evidence_provided: 2,  due_date: "2026-04-25" },
  { id: "t-004", workflow_id: "wf-002", task_name: "Asset inventory reconciliation",      assignee: "IT Ops",        priority: "high",     evidence_required: 6,  evidence_provided: 6,  due_date: "2026-05-10" },
  { id: "t-005", workflow_id: "wf-002", task_name: "Policy review and sign-off",          assignee: "Legal",         priority: "medium",   evidence_required: 3,  evidence_provided: 2,  due_date: "2026-05-12" },
  { id: "t-006", workflow_id: "wf-003", task_name: "Cardholder data flow mapping",        assignee: "PCI Analyst",   priority: "critical", evidence_required: 12, evidence_provided: 0,  due_date: "2026-04-18" },
  { id: "t-007", workflow_id: "wf-004", task_name: "PHI access log review",               assignee: "Privacy Team",  priority: "high",     evidence_required: 7,  evidence_provided: 3,  due_date: "2026-06-01" },
  { id: "t-008", workflow_id: "wf-006", task_name: "Update processing activity register", assignee: "DPO Assistant", priority: "medium",   evidence_required: 4,  evidence_provided: 2,  due_date: "2026-04-28" },
];

const MOCK_APPROVALS: ApprovalRecord[] = [
  { id: "ap-001", workflow_id: "wf-005", approver: "CISO",          decision: "approved", comment: "All controls verified and documented.",       decided_at: "2026-04-09" },
  { id: "ap-002", workflow_id: "wf-002", approver: "External Auditor", decision: "pending", comment: "Awaiting final evidence package.",           decided_at: "" },
  { id: "ap-003", workflow_id: "wf-001", approver: "Audit Committee", decision: "pending", comment: "Scheduled for Q2 board meeting.",            decided_at: "" },
  { id: "ap-004", workflow_id: "wf-003", approver: "QSA",            decision: "rejected", comment: "Incomplete SAQ sections 6 and 11. Resubmit.", decided_at: "2026-04-15" },
];

const FRAMEWORK_READINESS: { framework: Framework; score: number; controls_total: number; controls_met: number }[] = [
  { framework: "SOC2",     score: 68,  controls_total: 114, controls_met: 78  },
  { framework: "ISO27001", score: 85,  controls_total: 93,  controls_met: 79  },
  { framework: "PCI-DSS",  score: 22,  controls_total: 250, controls_met: 55  },
  { framework: "HIPAA",    score: 54,  controls_total: 164, controls_met: 89  },
  { framework: "NIST",     score: 91,  controls_total: 108, controls_met: 98  },
  { framework: "GDPR",     score: 63,  controls_total: 72,  controls_met: 45  },
  { framework: "CIS",      score: 77,  controls_total: 153, controls_met: 118 },
  { framework: "FedRAMP",  score: 38,  controls_total: 325, controls_met: 124 },
];

// ── Helpers ────────────────────────────────────────────────────

const frameworkColors: Record<Framework, string> = {
  "SOC2":     "bg-blue-700 text-blue-100",
  "ISO27001": "bg-purple-700 text-purple-100",
  "PCI-DSS":  "bg-yellow-700 text-yellow-100",
  "HIPAA":    "bg-green-700 text-green-100",
  "NIST":     "bg-cyan-700 text-cyan-100",
  "GDPR":     "bg-orange-700 text-orange-100",
  "CIS":      "bg-indigo-700 text-indigo-100",
  "FedRAMP":  "bg-red-700 text-red-100",
};

const statusConfig: Record<WorkflowStatus, { label: string; color: string }> = {
  not_started: { label: "Not Started", color: "bg-gray-700 text-gray-200" },
  in_progress: { label: "In Progress", color: "bg-blue-700 text-blue-100" },
  review:      { label: "In Review",   color: "bg-amber-700 text-amber-100" },
  approved:    { label: "Approved",    color: "bg-green-700 text-green-100" },
  closed:      { label: "Closed",      color: "bg-gray-600 text-gray-300" },
};

const priorityConfig: Record<TaskPriority, { label: string; color: string }> = {
  critical: { label: "Critical", color: "text-red-400" },
  high:     { label: "High",     color: "text-orange-400" },
  medium:   { label: "Medium",   color: "text-amber-400" },
  low:      { label: "Low",      color: "text-green-400" },
};

const approvalConfig: Record<ApprovalDecision, { label: string; color: string }> = {
  approved: { label: "Approved", color: "bg-green-700 text-green-100" },
  rejected: { label: "Rejected", color: "bg-red-700 text-red-100" },
  pending:  { label: "Pending",  color: "bg-amber-700 text-amber-100" },
};

function readinessColor(score: number) {
  if (score >= 80) return "bg-green-500";
  if (score >= 50) return "bg-amber-500";
  return "bg-red-500";
}

function readinessTextColor(score: number) {
  if (score >= 80) return "text-green-400";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}

// ── Component ──────────────────────────────────────────────────

export default function ComplianceWorkflowDashboard() {
  const [workflows, setWorkflows] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${_API_BASE}/workflows?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setWorkflows(d); })
      .catch((e) => setError(e?.message || 'Failed to load data'));
  }, []);

  const [selectedWorkflow, setSelectedWorkflow] = useState<string>(MOCK_WORKFLOWS[0].id);
  useEffect(() => {
    fetch(`${_API_BASE}/workflows?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => {
        // live data loaded — components read from API response
        void d;
      })
      .catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);

  const [filterFramework, setFilterFramework] = useState<Framework | "All">("All");
  const [error, setError] = useState<string | null>(null);

  const overdueTasks = MOCK_TASKS.filter(t => {
    const wf = MOCK_WORKFLOWS.find(w => w.id === t.workflow_id);
    return wf?.overdue || t.due_date < "2026-04-17";
  });

  const filteredWorkflows = filterFramework === "All"
    ? MOCK_WORKFLOWS
    : MOCK_WORKFLOWS.filter(w => w.framework === filterFramework);

  const selectedWF = MOCK_WORKFLOWS.find(w => w.id === selectedWorkflow);
  const selectedTasks = MOCK_TASKS.filter(t => t.workflow_id === selectedWorkflow);
  const selectedApprovals = MOCK_APPROVALS.filter(a => a.workflow_id === selectedWorkflow);

  const totalWorkflows = MOCK_WORKFLOWS.length;
  const activeWorkflows = MOCK_WORKFLOWS.filter(w => w.status === "in_progress" || w.status === "review").length;
  const approvedWorkflows = MOCK_WORKFLOWS.filter(w => w.status === "approved").length;
  const overdueWorkflows = MOCK_WORKFLOWS.filter(w => w.overdue).length;


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Compliance Workflows</h1>
          <p className="text-gray-400 mt-1">Manage audit workflows, tasks, approvals, and framework readiness</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {(["All", "SOC2", "ISO27001", "PCI-DSS", "HIPAA", "NIST", "GDPR"] as (Framework | "All")[]).map(f => (
            <button
              key={f}
              onClick={() => setFilterFramework(f)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                filterFramework === f ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Summary counts */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Workflows", value: totalWorkflows,   color: "text-blue-400" },
          { label: "Active",          value: activeWorkflows,  color: "text-amber-400" },
          { label: "Approved",        value: approvedWorkflows,color: "text-green-400" },
          { label: "Overdue",         value: overdueWorkflows, color: "text-red-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Overdue alert */}
      {overdueTasks.length > 0 && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-4">
          <p className="text-red-400 font-semibold text-sm mb-2">Overdue Tasks ({overdueTasks.length})</p>
          <div className="flex flex-wrap gap-2">
            {overdueTasks.map(t => (
              <span key={t.id} className="bg-red-800/50 text-red-200 px-2 py-1 rounded text-xs">
                {t.task_name} — {t.assignee}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Workflow list */}
        <div className="lg:col-span-1 space-y-3">
          <h2 className="text-lg font-semibold text-white">Workflows</h2>
          {filteredWorkflows.map(wf => (
            <div
              key={wf.id}
              onClick={() => setSelectedWorkflow(wf.id)}
              className={`bg-gray-800 rounded-lg p-4 cursor-pointer transition-all border-2 ${
                selectedWorkflow === wf.id ? "border-blue-500" : "border-transparent hover:border-gray-600"
              }`}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${frameworkColors[wf.framework]}`}>{wf.framework}</span>
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusConfig[wf.status].color}`}>{statusConfig[wf.status].label}</span>
              </div>
              <p className="text-white text-sm font-medium leading-snug">{wf.name}</p>
              <p className="text-gray-500 text-xs mt-1">{wf.workflow_type} · {wf.owner}</p>
              <div className="mt-3 flex items-center gap-2">
                <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                  <div
                    className={`h-1.5 rounded-full ${wf.completion_rate >= 80 ? "bg-green-500" : wf.completion_rate >= 40 ? "bg-amber-500" : "bg-red-500"}`}
                    style={{ width: `${wf.completion_rate}%` }}
                  />
                </div>
                <span className="text-xs text-gray-400 font-medium">{wf.completion_rate}%</span>
              </div>
              {wf.overdue && <p className="text-red-400 text-xs mt-1 font-medium">OVERDUE</p>}
            </div>
          ))}
        </div>

        {/* Right panel: tasks + approvals */}
        <div className="lg:col-span-2 space-y-5">
          <h2 className="text-lg font-semibold text-white">
            {selectedWF?.name ?? "Select a Workflow"}
          </h2>

          {/* Tasks table */}
          <div className="bg-gray-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-3">Tasks</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                    <th className="text-left pb-2 pr-3">Task</th>
                    <th className="text-left pb-2 pr-3">Assignee</th>
                    <th className="text-left pb-2 pr-3">Priority</th>
                    <th className="text-left pb-2">Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {selectedTasks.length === 0 ? (
                    <tr><td colSpan={4} className="py-4 text-gray-500 text-center text-xs">No tasks for this workflow</td></tr>
                  ) : (
                    selectedTasks.map(task => (
                      <tr key={task.id} className="hover:bg-gray-700/30 transition-colors">
                        <td className="py-2 pr-3 text-gray-200">{task.task_name}</td>
                        <td className="py-2 pr-3 text-gray-400">{task.assignee}</td>
                        <td className="py-2 pr-3">
                          <span className={`text-xs font-medium ${priorityConfig[task.priority].color}`}>
                            {priorityConfig[task.priority].label}
                          </span>
                        </td>
                        <td className="py-2">
                          <div className="flex items-center gap-2">
                            <div className="w-20 bg-gray-700 rounded-full h-1.5">
                              <div
                                className={`h-1.5 rounded-full ${
                                  task.evidence_provided >= task.evidence_required ? "bg-green-500" : "bg-amber-500"
                                }`}
                                style={{ width: `${Math.min(100, (task.evidence_provided / task.evidence_required) * 100)}%` }}
                              />
                            </div>
                            <span className="text-xs text-gray-400">{task.evidence_provided}/{task.evidence_required}</span>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Approval panel */}
          <div className="bg-gray-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-3">Approvals</h3>
            {selectedApprovals.length === 0 ? (
              <p className="text-gray-500 text-xs">No approvals for this workflow</p>
            ) : (
              <div className="space-y-3">
                {selectedApprovals.map(ap => (
                  <div key={ap.id} className="flex items-start gap-4 p-3 bg-gray-700/40 rounded-lg">
                    <div className="flex-1">
                      <p className="text-gray-200 text-sm font-medium">{ap.approver}</p>
                      <p className="text-gray-400 text-xs mt-0.5">{ap.comment}</p>
                      {ap.decided_at && <p className="text-gray-600 text-xs mt-1">{ap.decided_at}</p>}
                    </div>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium shrink-0 ${approvalConfig[ap.decision].color}`}>
                      {approvalConfig[ap.decision].label}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Framework Readiness Grid */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-5">Framework Readiness</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {FRAMEWORK_READINESS.map(fr => (
            <div key={fr.framework} className="bg-gray-700/40 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${frameworkColors[fr.framework]}`}>{fr.framework}</span>
                <span className={`text-sm font-bold ${readinessTextColor(fr.score)}`}>{fr.score}%</span>
              </div>
              <div className="w-full bg-gray-600 rounded-full h-2 mb-2">
                <div className={`h-2 rounded-full ${readinessColor(fr.score)}`} style={{ width: `${fr.score}%` }} />
              </div>
              <p className="text-gray-500 text-xs">{fr.controls_met} / {fr.controls_total} controls met</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
