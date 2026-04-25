/**
 * Security Questionnaire Dashboard - Live API
 * Route: /security-questionnaires
 * API: GET /api/v1/security-questionnaires/{questionnaires,assessments,questions}
 */
import { useState, useEffect } from "react";
import { ClipboardList, AlertTriangle, CheckCircle2, ChevronRight, Send, Users, BarChart2, Clock, RefreshCw } from "lucide-react";
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

const statusColor: Record<string, string> = {
  draft: "bg-gray-600 text-gray-100",
  sent: "bg-blue-600 text-white",
  in_progress: "bg-yellow-600 text-white",
  completed: "bg-green-600 text-white",
  overdue: "bg-red-600 text-white",
};
const riskColor: Record<string, string> = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-green-400" };
const typeColor: Record<string, string> = {
  standard: "bg-blue-900 text-blue-300",
  custom: "bg-purple-900 text-purple-300",
  lite: "bg-teal-900 text-teal-300",
};
const RESPONSE_LABELS = ["No", "Partial", "Yes", "Yes + Evidence", "N/A"];

function isOverdue(a: any) {
  return a.status === "overdue" || (a.status !== "completed" && a.due_date && new Date(a.due_date) < new Date());
}

export default function SecurityQuestionnaireDashboard() {
  const [questionnaires, setQuestionnaires] = useState<any[]>([]);
  const [assessments, setAssessments] = useState<any[]>([]);
  const [questions, setQuestions] = useState<any[]>([]);
  const [selectedAssessment, setSelectedAssessment] = useState<any | null>(null);
  const [responses, setResponses] = useState<Record<string, number>>({});
  const [activeTab, setActiveTab] = useState<"assessments" | "questionnaires">("assessments");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [q, a, qs] = await Promise.allSettled([
        apiFetch<any>("/api/v1/security-questionnaires/questionnaires"),
        apiFetch<any>("/api/v1/security-questionnaires/assessments"),
        apiFetch<any>("/api/v1/security-questionnaires/questions"),
      ]);
      if (q.status === "fulfilled") { const v = q.value as any; setQuestionnaires(Array.isArray(v) ? v : (v.questionnaires ?? v.items ?? [])); }
      if (a.status === "fulfilled") { const v = a.value as any; setAssessments(Array.isArray(v) ? v : (v.assessments ?? v.items ?? [])); }
      if (qs.status === "fulfilled") { const v = qs.value as any; setQuestions(Array.isArray(v) ? v : (v.questions ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const overdue = assessments.filter(isOverdue);
  const completed = assessments.filter(a => a.status === "completed");
  const avgScore = completed.length ? Math.round(completed.reduce((s, a) => s + (a.score ?? 0), 0) / completed.length) : 0;
  const vendorRisk = (lvl: string) => assessments.filter(a => a.risk_level === lvl).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><ClipboardList className="w-6 h-6 text-blue-400" /> Security Questionnaires</h1>
          <p className="text-gray-400 text-sm mt-1">Vendor security assessments and questionnaire management</p>
        </div>
        <div className="flex gap-2">
          <button className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm font-medium"><Send className="w-4 h-4" /> Send Assessment</button>
          <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
        </div>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : questionnaires.length === 0 && assessments.length === 0 ? <EmptyState icon={ClipboardList} title="No questionnaires" description="Create questionnaires to start vendor assessments." />
        : <>
          {overdue.length > 0 && (
            <div className="bg-red-900/40 border border-red-700 rounded-lg p-4 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              <span className="text-red-300 font-medium">{overdue.length} assessment{overdue.length > 1 ? "s are" : " is"} overdue — {overdue.map(a => a.vendor_name).join(", ")}</span>
            </div>
          )}

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: "Questionnaires", value: questionnaires.length, icon: <ClipboardList className="w-5 h-5 text-blue-400" /> },
              { label: "Active", value: assessments.filter(a => ["sent", "in_progress"].includes(a.status)).length, icon: <Clock className="w-5 h-5 text-yellow-400" /> },
              { label: "Overdue", value: overdue.length, icon: <AlertTriangle className="w-5 h-5 text-red-400" /> },
              { label: "Avg Score", value: `${avgScore}%`, icon: <BarChart2 className="w-5 h-5 text-green-400" /> },
            ].map(k => (
              <div key={k.label} className="bg-gray-800 rounded-lg p-5">
                <div className="flex items-center justify-between mb-2"><span className="text-gray-400 text-xs uppercase">{k.label}</span>{k.icon}</div>
                <div className="text-3xl font-bold">{k.value}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">{(["critical", "high", "medium", "low"] as const).map(lvl => (
            <div key={lvl} className="bg-gray-800 rounded-lg p-4 flex items-center gap-4">
              <div className={`text-2xl font-bold ${riskColor[lvl]}`}>{vendorRisk(lvl)}</div>
              <div><div className={`capitalize font-medium ${riskColor[lvl]}`}>{lvl}</div><div className="text-gray-500 text-xs">risk vendors</div></div>
            </div>
          ))}</div>

          <div className="flex gap-1 bg-gray-800 rounded-lg p-1 w-fit">
            {(["assessments", "questionnaires"] as const).map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} className={`px-4 py-2 rounded-md text-sm font-medium capitalize ${activeTab === tab ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}>{tab}</button>
            ))}
          </div>

          {activeTab === "assessments" ? (
            <div className="grid lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
                <div className="p-4 border-b border-gray-700 font-semibold flex items-center gap-2"><Users className="w-4 h-4 text-blue-400" /> Vendor Assessments</div>
                {assessments.length === 0 ? <p className="p-6 text-gray-500 text-sm">No assessments yet.</p>
                  : <div className="overflow-x-auto"><table className="w-full text-sm">
                    <thead className="bg-gray-700/50"><tr>{["Vendor","Questionnaire","Status","Score","Risk","Due Date"].map(h => <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>)}</tr></thead>
                    <tbody>{assessments.map(a => (
                      <tr key={a.id} onClick={() => setSelectedAssessment(a)} className={`border-t border-gray-700 hover:bg-gray-700/40 cursor-pointer ${selectedAssessment?.id === a.id ? "bg-blue-900/20" : ""}`}>
                        <td className="px-4 py-3 font-medium">{a.vendor_name}</td>
                        <td className="px-4 py-3 text-gray-400 text-xs">{a.questionnaire}</td>
                        <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[a.status] ?? "bg-gray-600 text-white"}`}>{(a.status ?? "").replace("_", " ")}</span></td>
                        <td className="px-4 py-3">{(a.score ?? 0) > 0 ? <div className="flex items-center gap-2"><div className="w-20 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${a.score >= 80 ? "bg-green-500" : a.score >= 60 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${a.score}%` }} /></div><span className="text-xs text-gray-300">{a.score}%</span></div> : <span className="text-gray-500 text-xs">—</span>}</td>
                        <td className={`px-4 py-3 font-semibold capitalize text-xs ${riskColor[a.risk_level] ?? "text-gray-400"}`}>{a.risk_level}</td>
                        <td className={`px-4 py-3 text-xs ${isOverdue(a) ? "text-red-400 font-medium" : "text-gray-400"}`}>{a.due_date}</td>
                      </tr>
                    ))}</tbody>
                  </table></div>}
              </div>
              <div className="bg-gray-800 rounded-lg p-4 space-y-4">
                <div className="font-semibold flex items-center gap-2"><CheckCircle2 className="w-4 h-4 text-green-400" /> {selectedAssessment ? `Respond: ${selectedAssessment.vendor_name}` : "Select assessment"}</div>
                {selectedAssessment ? questions.length === 0 ? <p className="text-gray-500 text-sm">No questions defined.</p>
                  : <div className="space-y-4">{questions.map((q, i) => (
                    <div key={q.id} className="bg-gray-700/50 rounded-lg p-3 space-y-2">
                      <div className="text-xs text-gray-400 flex justify-between"><span className="bg-gray-600 px-2 py-0.5 rounded">{q.category}</span>{q.required && <span className="text-red-400">Required</span>}</div>
                      <p className="text-sm">{i + 1}. {q.text}</p>
                      <div className="flex flex-wrap gap-2">{RESPONSE_LABELS.map((label, val) => (
                        <label key={val} className="flex items-center gap-1 cursor-pointer">
                          <input type="radio" name={q.id} value={val} checked={responses[q.id] === val} onChange={() => setResponses(r => ({ ...r, [q.id]: val }))} className="accent-blue-500" />
                          <span className="text-xs text-gray-300">{label}</span>
                        </label>
                      ))}</div>
                    </div>
                  ))}</div>
                  : <p className="text-gray-500 text-sm">Click an assessment to begin.</p>}
              </div>
            </div>
          ) : (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700 font-semibold flex items-center gap-2"><ClipboardList className="w-4 h-4 text-blue-400" /> Questionnaire Templates</div>
              {questionnaires.length === 0 ? <p className="p-6 text-gray-500 text-sm">No templates.</p>
                : <div className="overflow-x-auto"><table className="w-full text-sm">
                  <thead className="bg-gray-700/50"><tr>{["Name","Framework","Questions","Type","Created","Action"].map(h => <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>)}</tr></thead>
                  <tbody>{questionnaires.map(q => (
                    <tr key={q.id} className="border-t border-gray-700 hover:bg-gray-700/30">
                      <td className="px-4 py-3 font-medium">{q.name}</td>
                      <td className="px-4 py-3"><span className="bg-indigo-900 text-indigo-300 px-2 py-0.5 rounded text-xs font-medium">{q.framework}</span></td>
                      <td className="px-4 py-3 text-gray-300">{q.question_count}</td>
                      <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${typeColor[q.type] ?? "bg-gray-700 text-gray-300"}`}>{q.type}</span></td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{q.created_at}</td>
                      <td className="px-4 py-3"><button className="text-blue-400 hover:text-blue-300 text-xs flex items-center gap-1">Use <ChevronRight className="w-3 h-3" /></button></td>
                    </tr>
                  ))}</tbody>
                </table></div>}
            </div>
          )}
        </>}
    </div>
  );
}
