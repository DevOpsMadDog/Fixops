/**
 * Incident Lessons Learned Dashboard
 *
 * Tracks post-incident lessons, action items, implementation progress, and
 * review outcomes.
 *
 * Route: /incident-lessons
 * API: GET /api/v1/incident-lessons
 */

import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// ── Types ──────────────────────────────────────────────────────

type LessonType = "process" | "technical" | "communication" | "training" | "tooling" | "policy";
type LessonSeverity = "critical" | "high" | "medium" | "low";
type LessonStatus = "identified" | "under_review" | "actioned" | "closed";
type ActionStatus = "open" | "in_progress" | "completed" | "overdue";

interface Lesson {
  id: string;
  title: string;
  incident_ref: string;
  lesson_type: LessonType;
  severity: LessonSeverity;
  status: LessonStatus;
  identified_by: string;
  identified_date: string;
  implementation_rate: number;
}

interface ActionItem {
  id: string;
  lesson_id: string;
  action: string;
  owner: string;
  due_date: string;
  status: ActionStatus;
}

interface ReviewOutcome {
  id: string;
  lesson_id: string;
  outcome: string;
  reviewed_by: string;
  reviewed_date: string;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_LESSONS: Lesson[] = [
  { id: "les-001", title: "Insufficient MFA enforcement on admin accounts", incident_ref: "INC-2026-0312", lesson_type: "policy",        severity: "critical", status: "actioned",      identified_by: "CISO",        identified_date: "2026-03-15", implementation_rate: 90 },
  { id: "les-002", title: "Alert fatigue delayed ransomware detection",      incident_ref: "INC-2026-0298", lesson_type: "process",       severity: "high",     status: "under_review",  identified_by: "SOC Lead",    identified_date: "2026-03-20", implementation_rate: 40 },
  { id: "les-003", title: "No runbook for cloud region failover",            incident_ref: "INC-2026-0301", lesson_type: "technical",     severity: "high",     status: "actioned",      identified_by: "SRE Lead",    identified_date: "2026-03-22", implementation_rate: 75 },
  { id: "les-004", title: "Communication gaps during P1 incident",          incident_ref: "INC-2026-0312", lesson_type: "communication", severity: "medium",   status: "identified",    identified_by: "Incident Cmd", identified_date: "2026-03-25", implementation_rate: 10 },
  { id: "les-005", title: "Security training lacked phishing scenarios",    incident_ref: "INC-2026-0280", lesson_type: "training",      severity: "medium",   status: "closed",        identified_by: "HR Security", identified_date: "2026-02-10", implementation_rate: 100 },
  { id: "les-006", title: "SIEM rules missed lateral movement pattern",     incident_ref: "INC-2026-0298", lesson_type: "tooling",       severity: "critical", status: "under_review",  identified_by: "Threat Hunter", identified_date: "2026-03-18", implementation_rate: 25 },
];

const MOCK_ACTIONS: ActionItem[] = [
  { id: "act-001", lesson_id: "les-001", action: "Enforce MFA on all admin accounts via IdP policy", owner: "IAM Team",    due_date: "2026-04-01", status: "completed" },
  { id: "act-002", lesson_id: "les-001", action: "Audit all service accounts for MFA exemptions",    owner: "Security Ops", due_date: "2026-04-15", status: "in_progress" },
  { id: "act-003", lesson_id: "les-002", action: "Implement alert correlation to reduce noise",      owner: "SOC Team",    due_date: "2026-04-20", status: "in_progress" },
  { id: "act-004", lesson_id: "les-002", action: "Review and tune 50 noisy SIEM rules",              owner: "SOC Analyst", due_date: "2026-04-10", status: "overdue" },
  { id: "act-005", lesson_id: "les-003", action: "Document cloud failover runbook for us-east-1",   owner: "SRE Team",    due_date: "2026-04-25", status: "in_progress" },
  { id: "act-006", lesson_id: "les-006", action: "Add lateral movement detection rules to SIEM",    owner: "Threat Hunt", due_date: "2026-04-30", status: "open" },
];

const MOCK_OUTCOMES: ReviewOutcome[] = [
  { id: "out-001", lesson_id: "les-001", outcome: "MFA policy applied to 100% of admin roles. Exemptions reduced from 14 to 0.", reviewed_by: "CISO", reviewed_date: "2026-04-05" },
  { id: "out-002", lesson_id: "les-005", outcome: "Phishing simulation added to annual training. Pass rate improved 23%.",        reviewed_by: "HR Security", reviewed_date: "2026-03-01" },
  { id: "out-003", lesson_id: "les-003", outcome: "Failover runbook drafted. Pending SRE sign-off and tabletop exercise.",        reviewed_by: "SRE Lead", reviewed_date: "2026-04-10" },
];

// ── Helpers ────────────────────────────────────────────────────

const typeColors: Record<LessonType, string> = {
  process:       "bg-blue-700 text-blue-100",
  technical:     "bg-purple-700 text-purple-100",
  communication: "bg-cyan-700 text-cyan-100",
  training:      "bg-yellow-700 text-yellow-100",
  tooling:       "bg-indigo-700 text-indigo-100",
  policy:        "bg-orange-700 text-orange-100",
};

const severityColors: Record<LessonSeverity, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-amber-400",
  low:      "text-green-400",
};

const actionStatusColors: Record<ActionStatus, string> = {
  open:        "bg-gray-600 text-gray-200",
  in_progress: "bg-blue-700 text-blue-100",
  completed:   "bg-green-700 text-green-100",
  overdue:     "bg-red-700 text-red-100",
};

const lessonStatusColors: Record<LessonStatus, string> = {
  identified:   "bg-gray-600 text-gray-200",
  under_review: "bg-amber-700 text-amber-100",
  actioned:     "bg-blue-700 text-blue-100",
  closed:       "bg-green-700 text-green-100",
};

const typeBarCounts = Object.fromEntries(
  (["process", "technical", "communication", "training", "tooling", "policy"] as LessonType[]).map(t => [
    t,
    MOCK_LESSONS.filter(l => l.lesson_type === t).length,
  ])
) as Record<LessonType, number>;
const maxTypeCount = Math.max(...Object.values(typeBarCounts));

// ── Component ──────────────────────────────────────────────────

export default function IncidentLessonsDashboard() {
  const [selectedLesson, setSelectedLesson] = useState<string>(MOCK_LESSONS[0].id);
  const [loading, setLoading] = useState(true);

  const [fetchError, setFetchError] = useState<string | null>(null);

  const loadData = () => {
    setFetchError(null);
    apiFetch(`/api/v1/incident-lessons/lessons?org_id=${ORG_ID}`).catch((err) => {
      setFetchError(err instanceof Error ? err.message : "Failed to load incident lessons data");
    });
  };

  useEffect(() => {
    loadData();
  }, []);

  const overdueActions = MOCK_ACTIONS.filter(a => a.status === "overdue");
  const selectedLesson_obj = MOCK_LESSONS.find(l => l.id === selectedLesson);
  const lessonActions = MOCK_ACTIONS.filter(a => a.lesson_id === selectedLesson);
  const lessonOutcomes = MOCK_OUTCOMES.filter(o => o.lesson_id === selectedLesson);


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Incident Lessons Learned</h1>
        <p className="text-gray-400 mt-1">Post-incident analysis, action items, and implementation tracking</p>
      </div>

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors">Retry</button>
        </div>
      )}

      {/* Overdue Actions Banner */}
      {overdueActions.length > 0 && (
        <div className="bg-red-900/40 border border-red-700 rounded-lg p-4 flex items-center gap-3">
          <span className="text-red-400 text-xl">⚠</span>
          <div>
            <p className="text-red-300 font-semibold">{overdueActions.length} action item{overdueActions.length > 1 ? "s" : ""} overdue</p>
            <p className="text-red-400 text-sm mt-0.5">
              {overdueActions.map(a => a.action.slice(0, 50) + "…").join(" · ")}
            </p>
          </div>
        </div>
      )}

      {/* Summary KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Lessons", value: MOCK_LESSONS.length, color: "text-blue-400" },
          { label: "Under Review", value: MOCK_LESSONS.filter(l => l.status === "under_review").length, color: "text-amber-400" },
          { label: "Closed", value: MOCK_LESSONS.filter(l => l.status === "closed").length, color: "text-green-400" },
          { label: "Overdue Actions", value: overdueActions.length, color: "text-red-400" },
        ].map(kpi => (
          <div key={kpi.label} className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">{kpi.label}</p>
            <p className={`text-3xl font-bold mt-1 ${kpi.color}`}>{kpi.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Lessons Table */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Lessons</h2>
          <div className="space-y-2">
            {MOCK_LESSONS.map(lesson => (
              <div
                key={lesson.id}
                onClick={() => setSelectedLesson(lesson.id)}
                className={`p-4 rounded-lg cursor-pointer transition-all border ${
                  selectedLesson === lesson.id ? "border-blue-500 bg-blue-900/20" : "border-gray-700 hover:border-gray-600 bg-gray-700/30"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className={`text-xs font-bold uppercase ${severityColors[lesson.severity]}`}>{lesson.severity}</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${typeColors[lesson.lesson_type]}`}>{lesson.lesson_type}</span>
                      <span className="text-gray-500 text-xs">{lesson.incident_ref}</span>
                    </div>
                    <p className="text-white text-sm font-medium">{lesson.title}</p>
                    <p className="text-gray-400 text-xs mt-1">By {lesson.identified_by} on {lesson.identified_date}</p>
                  </div>
                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${lessonStatusColors[lesson.status]}`}>
                      {lesson.status.replace("_", " ")}
                    </span>
                    <div className="flex items-center gap-1">
                      <div className="w-16 bg-gray-700 rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${lesson.implementation_rate >= 80 ? "bg-green-500" : lesson.implementation_rate >= 40 ? "bg-amber-500" : "bg-red-500"}`}
                          style={{ width: `${lesson.implementation_rate}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-400">{lesson.implementation_rate}%</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right panel — by type chart + implementation rate circle */}
        <div className="space-y-6">
          {/* Implementation rate */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-4">Selected Lesson</h2>
            {selectedLesson_obj && (
              <>
                <p className="text-white text-sm font-medium mb-3">{selectedLesson_obj.title}</p>
                {/* CSS progress circle approximation */}
                <div className="flex items-center gap-4">
                  <div className="relative w-20 h-20 shrink-0">
                    <svg viewBox="0 0 36 36" className="w-20 h-20 -rotate-90">
                      <circle cx="18" cy="18" r="15.9" fill="none" stroke="#374151" strokeWidth="3" />
                      <circle
                        cx="18" cy="18" r="15.9" fill="none"
                        stroke={selectedLesson_obj.implementation_rate >= 80 ? "#22c55e" : selectedLesson_obj.implementation_rate >= 40 ? "#f59e0b" : "#ef4444"}
                        strokeWidth="3"
                        strokeDasharray={`${selectedLesson_obj.implementation_rate} 100`}
                        strokeLinecap="round"
                      />
                    </svg>
                    <span className="absolute inset-0 flex items-center justify-center text-white text-sm font-bold">
                      {selectedLesson_obj.implementation_rate}%
                    </span>
                  </div>
                  <div>
                    <p className="text-gray-400 text-xs">Implementation Rate</p>
                    <p className="text-gray-300 text-xs mt-1">Status: <span className="text-white capitalize">{selectedLesson_obj.status.replace("_", " ")}</span></p>
                  </div>
                </div>
              </>
            )}
          </div>

          {/* By type bar chart */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-4">Lessons by Type</h2>
            <div className="space-y-2">
              {(Object.entries(typeBarCounts) as [LessonType, number][]).map(([type, count]) => (
                <div key={type} className="flex items-center gap-2">
                  <span className="text-gray-400 text-xs w-24 capitalize">{type}</span>
                  <div className="flex-1 bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${typeColors[type].split(" ")[0]}`}
                      style={{ width: maxTypeCount > 0 ? `${(count / maxTypeCount) * 100}%` : "0%" }}
                    />
                  </div>
                  <span className="text-gray-300 text-xs w-4 text-right">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Action Items for selected lesson */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">
          Action Items — {selectedLesson_obj?.title.slice(0, 60)}
        </h2>
        {lessonActions.length === 0 ? (
          <p className="text-gray-400 text-sm">No action items for this lesson.</p>
        ) : (
          <div className="space-y-2">
            {lessonActions.map(action => (
              <div key={action.id} className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg">
                <div className="flex-1">
                  <p className="text-white text-sm">{action.action}</p>
                  <p className="text-gray-400 text-xs mt-0.5">Owner: {action.owner} · Due: {action.due_date}</p>
                </div>
                <span className={`ml-4 px-2 py-0.5 rounded text-xs font-medium ${actionStatusColors[action.status]}`}>
                  {action.status.replace("_", " ")}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Review Outcomes */}
      {lessonOutcomes.length > 0 && (
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Review Outcomes</h2>
          <div className="space-y-3">
            {lessonOutcomes.map(outcome => (
              <div key={outcome.id} className="p-4 bg-green-900/20 border border-green-800 rounded-lg">
                <p className="text-green-200 text-sm">{outcome.outcome}</p>
                <p className="text-green-400 text-xs mt-1">Reviewed by {outcome.reviewed_by} on {outcome.reviewed_date}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
