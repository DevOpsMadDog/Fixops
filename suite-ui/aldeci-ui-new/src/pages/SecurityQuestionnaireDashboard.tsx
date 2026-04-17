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

// ── Mock data ──────────────────────────────────────────────────

const QUESTIONNAIRES: Questionnaire[] = [
  { id: "q1", name: "SIG Core",            framework: "SIG",      question_count: 218, type: "standard", created_at: "2026-01-10" },
  { id: "q2", name: "CAIQ 4.0",            framework: "CSA",      question_count: 261, type: "standard", created_at: "2026-01-15" },
  { id: "q3", name: "VSA Lite",            framework: "VSAQ",     question_count: 62,  type: "lite",     created_at: "2026-02-01" },
  { id: "q4", name: "GDPR Vendor Check",   framework: "GDPR",     question_count: 48,  type: "custom",   created_at: "2026-02-10" },
  { id: "q5", name: "ISO 27001 Supplier",  framework: "ISO 27001",question_count: 114, type: "standard", created_at: "2026-02-20" },
  { id: "q6", name: "PCI DSS Vendor",      framework: "PCI-DSS",  question_count: 87,  type: "custom",   created_at: "2026-03-05" },
];

const ASSESSMENTS: Assessment[] = [
  { id: "a1", vendor_name: "Acme Cloud",       questionnaire: "SIG Core",           status: "completed",   score: 88,  risk_level: "low",      sent_at: "2026-03-01", due_date: "2026-03-31" },
  { id: "a2", vendor_name: "DataSafe Inc",      questionnaire: "CAIQ 4.0",           status: "in_progress", score: 62,  risk_level: "medium",   sent_at: "2026-03-10", due_date: "2026-04-10" },
  { id: "a3", vendor_name: "SecureNet Corp",    questionnaire: "GDPR Vendor Check",  status: "overdue",     score: 0,   risk_level: "high",     sent_at: "2026-02-15", due_date: "2026-03-15" },
  { id: "a4", vendor_name: "PayFlow Systems",   questionnaire: "PCI DSS Vendor",     status: "sent",        score: 0,   risk_level: "critical", sent_at: "2026-03-20", due_date: "2026-04-20" },
  { id: "a5", vendor_name: "LogiTech Partners", questionnaire: "VSA Lite",           status: "completed",   score: 74,  risk_level: "medium",   sent_at: "2026-02-28", due_date: "2026-03-28" },
  { id: "a6", vendor_name: "CloudStore Ltd",    questionnaire: "ISO 27001 Supplier", status: "overdue",     score: 0,   risk_level: "high",     sent_at: "2026-02-10", due_date: "2026-03-10" },
  { id: "a7", vendor_name: "Apex Analytics",    questionnaire: "SIG Core",           status: "in_progress", score: 55,  risk_level: "high",     sent_at: "2026-03-25", due_date: "2026-04-25" },
  { id: "a8", vendor_name: "NovaTech AI",       questionnaire: "CAIQ 4.0",           status: "draft",       score: 0,   risk_level: "medium",   sent_at: "—",          due_date: "2026-05-01" },
];

const SAMPLE_QUESTIONS: Question[] = [
  { id: "sq1", text: "Does your organization have a documented Information Security Policy reviewed annually?", category: "Governance", required: true },
  { id: "sq2", text: "Are all production systems covered by a vulnerability management program?", category: "Vulnerability Mgmt", required: true },
  { id: "sq3", text: "Is multi-factor authentication enforced for all privileged accounts?", category: "Access Control", required: true },
  { id: "sq4", text: "Does your organization maintain an inventory of all third-party sub-processors?", category: "Supply Chain", required: false },
  { id: "sq5", text: "Are encryption standards documented and enforced for data at rest and in transit?", category: "Cryptography", required: true },
];

const RESPONSE_LABELS = ["No", "Partial", "Yes", "Yes + Evidence", "N/A"];

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
  const [selectedAssessment, setSelectedAssessment] = useState<Assessment | null>(null);
  useEffect(() => {
    fetch("/api/v1/security-questionnaires", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => {});
  }, []);
  const [responses, setResponses] = useState<Record<string, number>>({});
  const [activeTab, setActiveTab] = useState<"assessments" | "questionnaires">("assessments");

  const overdue = ASSESSMENTS.filter(isOverdue);
  const completed = ASSESSMENTS.filter(a => a.status === "completed");
  const avgScore = completed.length
    ? Math.round(completed.reduce((s, a) => s + a.score, 0) / completed.length)
    : 0;

  const vendorRisk = {
    critical: ASSESSMENTS.filter(a => a.risk_level === "critical").length,
    high: ASSESSMENTS.filter(a => a.risk_level === "high").length,
    medium: ASSESSMENTS.filter(a => a.risk_level === "medium").length,
    low: ASSESSMENTS.filter(a => a.risk_level === "low").length,
  };

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
          { label: "Questionnaires", value: QUESTIONNAIRES.length, icon: <ClipboardList className="w-5 h-5 text-blue-400" />, sub: "templates available" },
          { label: "Active Assessments", value: ASSESSMENTS.filter(a => ["sent","in_progress"].includes(a.status)).length, icon: <Clock className="w-5 h-5 text-yellow-400" />, sub: "awaiting response" },
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
                  {ASSESSMENTS.map(a => (
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
                <div className="space-y-4">
                  {SAMPLE_QUESTIONS.map((q, i) => (
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
                {QUESTIONNAIRES.map(q => (
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
