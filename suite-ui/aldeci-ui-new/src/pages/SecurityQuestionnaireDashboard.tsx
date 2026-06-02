/**
 * Security Questionnaire Dashboard
 *
 * Vendor security questionnaire management and assessment tracking.
 *   1. KPIs: Total questionnaires, active assessments, overdue, avg score
 *   2. Questionnaire list (name, framework badge, question_count, type)
 *   3. Assessment table (vendor, status, score bar, risk_level, sent_at, due_date)
 *   4. Response submission form (question text, radio 0-4)
 *   5. Overdue assessments banner
 *   6. Vendor risk summary cards
 *
 * Route: /security-questionnaires
 * API: GET /api/v1/security-questionnaires
 */

import { useState, useEffect } from "react";
import {
  ClipboardList, AlertTriangle, CheckCircle2, Clock, ChevronRight,
  RefreshCw, Send, Users, BarChart2
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

interface Questionnaire {
  id: string;
  name: string;
  framework: string;
  question_count: number;
  type: "standard" | "custom" | "lite";
  created_at: string;
}

interface Assessment {
  id: string;
  vendor_name: string;
  questionnaire: string;
  questionnaire_id?: string;
  status: "draft" | "sent" | "in_progress" | "completed" | "overdue";
  score: number;
  risk_level: "critical" | "high" | "medium" | "low";
  sent_at: string;
  due_date: string;
}

interface Question {
  id: string;
  text: string;
  category: string;
  required: boolean;
}

const RESPONSE_LABELS = ["No", "Partial", "Yes", "Yes + Evidence", "N/A"];

// ── API (real backend, no mocks) ───────────────────────────────

function getApiKey(): string {
  return (
    (typeof window !== "undefined" && localStorage.getItem("aldeci.authToken")) ||
    import.meta.env.VITE_API_KEY ||
    ""
  );
}

async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`/api/v1/security-questionnaires${path}`, {
    headers: { "X-API-Key": getApiKey() },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const QUESTIONNAIRE_TYPES = new Set(["standard", "custom", "lite"]);

function mapQuestionnaire(r: Record<string, any>): Questionnaire {
  const t = String(r.questionnaire_type ?? r.type ?? "custom").toLowerCase();
  return {
    id: String(r.id),
    name: String(r.questionnaire_name ?? r.name ?? r.id),
    framework: String(r.framework ?? "custom"),
    question_count: Number(r.question_count ?? 0),
    type: (QUESTIONNAIRE_TYPES.has(t) ? t : "custom") as Questionnaire["type"],
    created_at: String(r.created_at ?? "").slice(0, 10),
  };
}

function mapAssessment(
  r: Record<string, any>,
  qnameById: Record<string, string>,
): Assessment {
  const status = String(r.status ?? "draft").toLowerCase() as Assessment["status"];
  const risk = String(r.risk_level ?? "medium").toLowerCase() as Assessment["risk_level"];
  return {
    id: String(r.id),
    vendor_name: String(r.vendor_name || r.vendor_id || "Unknown vendor"),
    questionnaire: qnameById[String(r.questionnaire_id)] ?? String(r.questionnaire_id ?? "—"),
    status,
    score: Number(r.score ?? 0),
    risk_level: risk,
    sent_at: String(r.sent_at ?? "—").slice(0, 10) || "—",
    due_date: String(r.due_date ?? "—").slice(0, 10) || "—",
    // keep questionnaire_id around so the response form can fetch questions
    ...(r.questionnaire_id ? { questionnaire_id: String(r.questionnaire_id) } : {}),
  } as Assessment;
}

function mapQuestion(r: Record<string, any>): Question {
  return {
    id: String(r.id),
    text: String(r.question_text ?? r.text ?? ""),
    category: String(r.question_category ?? r.category ?? "general"),
    required: Boolean(r.required ?? true),
  };
}

// ── Helpers ────────────────────────────────────────────────────

const statusColor: Record<Assessment["status"], string> = {
  draft: "bg-gray-600 text-gray-100",
  sent: "bg-blue-600 text-white",
  in_progress: "bg-yellow-600 text-white",
  completed: "bg-green-600 text-white",
  overdue: "bg-red-600 text-white",
};

const riskColor: Record<Assessment["risk_level"], string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

const typeColor: Record<Questionnaire["type"], string> = {
  standard: "bg-blue-900 text-blue-300",
  custom: "bg-purple-900 text-purple-300",
  lite: "bg-teal-900 text-teal-300",
};

function isOverdue(a: Assessment): boolean {
  return a.status === "overdue" || (a.status !== "completed" && new Date(a.due_date) < new Date());
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityQuestionnaireDashboard() {
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [questionnaires, setQuestionnaires] = useState<Questionnaire[]>([]);
  const [questions, setQuestions] = useState<Question[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAssessment, setSelectedAssessment] = useState<Assessment | null>(null);
  const [responses, setResponses] = useState<Record<string, number>>({});
  const [activeTab, setActiveTab] = useState<"assessments" | "questionnaires">("assessments");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const [qRaw, aRaw] = await Promise.all([
          apiGet<Record<string, any>[]>("/questionnaires"),
          apiGet<Record<string, any>[]>("/assessments"),
        ]);
        if (cancelled) return;
        const qs = (Array.isArray(qRaw) ? qRaw : []).map(mapQuestionnaire);
        const qnameById: Record<string, string> = {};
        qs.forEach(q => { qnameById[q.id] = q.name; });
        setQuestionnaires(qs);
        setAssessments((Array.isArray(aRaw) ? aRaw : []).map(r => mapAssessment(r, qnameById)));
      } catch (e: any) {
        if (!cancelled) setError(e?.message || "Failed to load questionnaires");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // Load the selected assessment's questionnaire questions for the response form.
  useEffect(() => {
    const qid = selectedAssessment?.questionnaire_id;
    if (!qid) { setQuestions([]); return; }
    let cancelled = false;
    apiGet<Record<string, any>[]>(`/questionnaires/${encodeURIComponent(qid)}/questions`)
      .then(rows => { if (!cancelled) setQuestions((Array.isArray(rows) ? rows : []).map(mapQuestion)); })
      .catch(() => { if (!cancelled) setQuestions([]); });
    return () => { cancelled = true; };
  }, [selectedAssessment?.questionnaire_id]);

  const overdue = assessments.filter(isOverdue);
  const completed = assessments.filter(a => a.status === "completed");
  const avgScore = completed.length
    ? Math.round(completed.reduce((s, a) => s + a.score, 0) / completed.length)
    : 0;

  const vendorRisk = {
    critical: assessments.filter(a => a.risk_level === "critical").length,
    high: assessments.filter(a => a.risk_level === "high").length,
    medium: assessments.filter(a => a.risk_level === "medium").length,
    low: assessments.filter(a => a.risk_level === "low").length,
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0f172a] text-white p-6 flex items-center justify-center">
        <div className="flex items-center gap-3 text-gray-400">
          <RefreshCw className="w-5 h-5 animate-spin" /> Loading security questionnaires…
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-[#0f172a] text-white p-6 flex items-center justify-center">
        <div className="bg-red-900/40 border border-red-700 rounded-lg p-6 flex items-center gap-3 max-w-md">
          <AlertTriangle className="w-6 h-6 text-red-400 shrink-0" />
          <div>
            <div className="font-semibold text-red-300">Couldn’t load questionnaires</div>
            <div className="text-red-400/80 text-sm mt-1">{error}</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ClipboardList className="w-6 h-6 text-blue-400" />
            Security Questionnaires
          </h1>
          <p className="text-gray-400 text-sm mt-1">Vendor security assessments and questionnaire management</p>
        </div>
        <button className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <Send className="w-4 h-4" /> Send Assessment
        </button>
      </div>

      {/* Overdue banner */}
      {overdue.length > 0 && (
        <div className="bg-red-900/40 border border-red-700 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <span className="text-red-300 font-medium">
            {overdue.length} assessment{overdue.length > 1 ? "s are" : " is"} overdue —{" "}
            {overdue.map(a => a.vendor_name).join(", ")}
          </span>
        </div>
      )}

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Questionnaires", value: questionnaires.length, icon: <ClipboardList className="w-5 h-5 text-blue-400" />, sub: "templates available" },
          { label: "Active Assessments", value: assessments.filter(a => ["sent","in_progress"].includes(a.status)).length, icon: <Clock className="w-5 h-5 text-yellow-400" />, sub: "awaiting response" },
          { label: "Overdue", value: overdue.length, icon: <AlertTriangle className="w-5 h-5 text-red-400" />, sub: "require follow-up" },
          { label: "Avg Score", value: `${avgScore}%`, icon: <BarChart2 className="w-5 h-5 text-green-400" />, sub: "completed assessments" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-400 text-xs uppercase tracking-wide">{k.label}</span>
              {k.icon}
            </div>
            <div className="text-3xl font-bold">{k.value}</div>
            <div className="text-gray-500 text-xs mt-1">{k.sub}</div>
          </div>
        ))}
      </div>

      {/* Vendor risk summary */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {(["critical","high","medium","low"] as const).map(level => (
          <div key={level} className="bg-gray-800 rounded-lg p-4 flex items-center gap-4">
            <div className={`text-2xl font-bold ${riskColor[level]}`}>{vendorRisk[level]}</div>
            <div>
              <div className={`capitalize font-medium ${riskColor[level]}`}>{level}</div>
              <div className="text-gray-500 text-xs">risk vendors</div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-800 rounded-lg p-1 w-fit">
        {(["assessments","questionnaires"] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-md text-sm font-medium capitalize transition-colors ${
              activeTab === tab ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === "assessments" ? (
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Assessment table */}
          <div className="lg:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700 font-semibold flex items-center gap-2">
              <Users className="w-4 h-4 text-blue-400" /> Vendor Assessments
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-700/50">
                  <tr>
                    {["Vendor","Questionnaire","Status","Score","Risk","Due Date"].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {assessments.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-10 text-center text-gray-500 text-sm">
                        No vendor assessments yet. Click “Send Assessment” to send a
                        questionnaire to a vendor.
                      </td>
                    </tr>
                  )}
                  {assessments.map(a => (
                    <tr
                      key={a.id}
                      onClick={() => setSelectedAssessment(a)}
                      className={`border-t border-gray-700 hover:bg-gray-700/40 cursor-pointer transition-colors ${
                        selectedAssessment?.id === a.id ? "bg-blue-900/20" : ""
                      }`}
                    >
                      <td className="px-4 py-3 font-medium">{a.vendor_name}</td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{a.questionnaire}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[a.status]}`}>
                          {a.status.replace("_"," ")}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {a.score > 0 ? (
                          <div className="flex items-center gap-2">
                            <div className="w-20 bg-gray-700 rounded-full h-1.5">
                              <div
                                className={`h-1.5 rounded-full ${a.score >= 80 ? "bg-green-500" : a.score >= 60 ? "bg-yellow-500" : "bg-red-500"}`}
                                style={{ width: `${a.score}%` }}
                              />
                            </div>
                            <span className="text-xs text-gray-300">{a.score}%</span>
                          </div>
                        ) : (
                          <span className="text-gray-500 text-xs">—</span>
                        )}
                      </td>
                      <td className={`px-4 py-3 font-semibold capitalize text-xs ${riskColor[a.risk_level]}`}>
                        {a.risk_level}
                      </td>
                      <td className={`px-4 py-3 text-xs ${isOverdue(a) ? "text-red-400 font-medium" : "text-gray-400"}`}>
                        {a.due_date}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Response form */}
          <div className="bg-gray-800 rounded-lg p-4 space-y-4">
            <div className="font-semibold flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-400" />
              {selectedAssessment ? `Respond: ${selectedAssessment.vendor_name}` : "Select an assessment"}
            </div>
            {selectedAssessment ? (
              <>
                {questions.length === 0 && (
                  <p className="text-gray-500 text-sm">
                    This questionnaire has no questions defined yet.
                  </p>
                )}
                <div className="space-y-4">
                  {questions.map((q, i) => (
                    <div key={q.id} className="bg-gray-700/50 rounded-lg p-3 space-y-2">
                      <div className="text-xs text-gray-400 flex justify-between">
                        <span className="bg-gray-600 px-2 py-0.5 rounded">{q.category}</span>
                        {q.required && <span className="text-red-400">Required</span>}
                      </div>
                      <p className="text-sm leading-snug">{i+1}. {q.text}</p>
                      <div className="flex flex-wrap gap-2 mt-2">
                        {RESPONSE_LABELS.map((label, val) => (
                          <label key={val} className="flex items-center gap-1 cursor-pointer">
                            <input
                              type="radio"
                              name={q.id}
                              value={val}
                              checked={responses[q.id] === val}
                              onChange={() => setResponses(r => ({ ...r, [q.id]: val }))}
                              className="accent-blue-500"
                            />
                            <span className="text-xs text-gray-300">{label}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
                <button className="w-full bg-blue-600 hover:bg-blue-700 py-2 rounded-lg text-sm font-medium transition-colors">
                  Submit Responses
                </button>
              </>
            ) : (
              <p className="text-gray-500 text-sm">Click on an assessment row to begin submitting responses.</p>
            )}
          </div>
        </div>
      ) : (
        /* Questionnaire list */
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700 font-semibold flex items-center gap-2">
            <ClipboardList className="w-4 h-4 text-blue-400" /> Questionnaire Templates
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-700/50">
                <tr>
                  {["Name","Framework","Questions","Type","Created"].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>
                  ))}
                  <th className="px-4 py-3 text-left text-gray-400 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {questionnaires.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-10 text-center text-gray-500 text-sm">
                      No questionnaire templates yet. Create one to start sending vendor
                      assessments.
                    </td>
                  </tr>
                )}
                {questionnaires.map(q => (
                  <tr key={q.id} className="border-t border-gray-700 hover:bg-gray-700/30 transition-colors">
                    <td className="px-4 py-3 font-medium">{q.name}</td>
                    <td className="px-4 py-3">
                      <span className="bg-indigo-900 text-indigo-300 px-2 py-0.5 rounded text-xs font-medium">{q.framework}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-300">{q.question_count}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${typeColor[q.type]}`}>{q.type}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">{q.created_at}</td>
                    <td className="px-4 py-3">
                      <button className="text-blue-400 hover:text-blue-300 text-xs flex items-center gap-1 transition-colors">
                        Use <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
