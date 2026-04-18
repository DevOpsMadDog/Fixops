/**
 * Security Training Effectiveness Dashboard
 * Route: /training-effectiveness
 * API: /api/v1/training-effectiveness
 */
import { useState, useEffect } from "react";
import { BookOpen, TrendingUp, Users, RefreshCw, Award } from "lucide-react";

const API_BASE = "/api/v1/training-effectiveness";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

interface TrainingProgram {
  id: string;
  program_name: string;
  training_type: string;
  completion_rate: number;
  avg_score: number;
  score_improvement: number;
  enrolled_count: number;
  completed_count: number;
}

const MOCK_PROGRAMS: TrainingProgram[] = [
  { id: "prog-001", program_name: "Phishing Awareness Q2", training_type: "phishing", completion_rate: 87.3, avg_score: 82.1, score_improvement: 14.2, enrolled_count: 240, completed_count: 209 },
  { id: "prog-002", program_name: "Password Security Essentials", training_type: "password_security", completion_rate: 93.5, avg_score: 91.0, score_improvement: 8.7, enrolled_count: 240, completed_count: 224 },
  { id: "prog-003", program_name: "Data Handling & GDPR", training_type: "compliance", completion_rate: 71.2, avg_score: 76.4, score_improvement: 11.3, enrolled_count: 180, completed_count: 128 },
  { id: "prog-004", program_name: "Secure Code Review", training_type: "secure_coding", completion_rate: 64.8, avg_score: 69.8, score_improvement: 18.5, enrolled_count: 85, completed_count: 55 },
  { id: "prog-005", program_name: "Incident Response Drills", training_type: "incident_response", completion_rate: 100.0, avg_score: 88.3, score_improvement: 6.1, enrolled_count: 32, completed_count: 32 },
];

const typeColor: Record<string, string> = {
  phishing: "bg-red-800 text-red-200",
  password_security: "bg-blue-800 text-blue-200",
  compliance: "bg-purple-800 text-purple-200",
  secure_coding: "bg-cyan-800 text-cyan-200",
  incident_response: "bg-orange-800 text-orange-200",
};

export default function TrainingEffectivenessDashboard() {
  const [programs, setPrograms] = useState<TrainingProgram[]>(MOCK_PROGRAMS);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(`${API_BASE}/programs`, { headers: getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setPrograms(d); })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const avgCompletion = programs.length > 0
    ? (programs.reduce((s, p) => s + p.completion_rate, 0) / programs.length).toFixed(1)
    : "0";
  const avgScore = programs.length > 0
    ? (programs.reduce((s, p) => s + p.avg_score, 0) / programs.length).toFixed(1)
    : "0";
  const totalEnrolled = programs.reduce((s, p) => s + p.enrolled_count, 0);
  const totalCompleted = programs.reduce((s, p) => s + p.completed_count, 0);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <BookOpen className="w-6 h-6 text-green-400" /> Training Effectiveness
          </h1>
          <p className="text-gray-400 text-sm mt-1">Completion rates, score improvements, and retention trends</p>
        </div>
        <button onClick={() => window.location.reload()} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Avg Completion", value: `${avgCompletion}%`, color: "text-green-400" },
          { label: "Avg Score", value: `${avgScore}%`, color: "text-blue-400" },
          { label: "Total Enrolled", value: totalEnrolled, color: "text-purple-400" },
          { label: "Total Completed", value: totalCompleted, color: "text-cyan-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Award className="w-4 h-4 text-green-400" /> Training Programs
          {loading && <span className="text-xs text-gray-400 ml-2">Loading...</span>}
        </h2>
        <div className="space-y-4">
          {programs.map(prog => (
            <div key={prog.id} className="bg-gray-700/30 rounded-lg p-4 border border-gray-700">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${typeColor[prog.training_type] || "bg-gray-700 text-gray-200"}`}>
                      {prog.training_type.replace("_", " ")}
                    </span>
                    <span className="text-white font-medium">{prog.program_name}</span>
                  </div>
                  <p className="text-gray-400 text-xs">{prog.completed_count} / {prog.enrolled_count} completed</p>
                </div>
                <div className="text-right">
                  <div className="text-green-400 font-bold text-sm">+{prog.score_improvement.toFixed(1)}%</div>
                  <div className="text-gray-500 text-xs">improvement</div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-400">Completion</span>
                    <span className="text-gray-300">{prog.completion_rate.toFixed(1)}%</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className="h-2 rounded-full bg-green-500" style={{ width: `${prog.completion_rate}%` }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-400">Avg Score</span>
                    <span className="text-gray-300">{prog.avg_score.toFixed(1)}%</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div className="h-2 rounded-full bg-blue-500" style={{ width: `${prog.avg_score}%` }} />
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
