import { useState, useEffect } from "react";
import { GraduationCap, Users, CheckCircle, Star, Clock, ChevronRight, TrendingUp } from "lucide-react";

// == API helpers ================================================
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY  = import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID   = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

const COURSES = [
  { id: 1, title: "Phishing Awareness Fundamentals", category: "phishing", difficulty: "Beginner", duration: "45 min", passingScore: 80, enrolled: 1240, completion: 92 },
  { id: 2, title: "Security Compliance Essentials", category: "compliance", difficulty: "Intermediate", duration: "90 min", passingScore: 85, enrolled: 980, completion: 78 },
  { id: 3, title: "Secure Coding Practices", category: "secure_coding", difficulty: "Advanced", duration: "120 min", passingScore: 75, enrolled: 340, completion: 61 },
  { id: 4, title: "Data Privacy & GDPR", category: "privacy", difficulty: "Intermediate", duration: "60 min", passingScore: 80, enrolled: 720, completion: 84 },
  { id: 5, title: "Social Engineering Defense", category: "phishing", difficulty: "Intermediate", duration: "50 min", passingScore: 80, enrolled: 890, completion: 71 },
  { id: 6, title: "HIPAA Compliance Training", category: "compliance", difficulty: "Intermediate", duration: "75 min", passingScore: 85, enrolled: 415, completion: 88 },
  { id: 7, title: "OWASP Top 10 for Developers", category: "secure_coding", difficulty: "Advanced", duration: "150 min", passingScore: 70, enrolled: 210, completion: 53 },
  { id: 8, title: "AI Security & Responsible Use", category: "privacy", difficulty: "Beginner", duration: "30 min", passingScore: 75, enrolled: 1052, completion: 44 },
];

const ENROLLMENTS = [
  { user: "u-****4821", course: "Phishing Awareness Fundamentals", enrolled: "2026-03-01", due: "2026-04-01", progress: 100, score: 91, status: "passed" },
  { user: "u-****2934", course: "Secure Coding Practices", enrolled: "2026-03-10", due: "2026-04-10", progress: 68, score: null, status: "enrolled" },
  { user: "u-****7761", course: "Data Privacy & GDPR", enrolled: "2026-02-15", due: "2026-03-15", progress: 100, score: 73, status: "failed" },
  { user: "u-****0032", course: "Security Compliance Essentials", enrolled: "2026-03-20", due: "2026-04-20", progress: 45, score: null, status: "enrolled" },
  { user: "u-****5589", course: "HIPAA Compliance Training", enrolled: "2026-03-05", due: "2026-04-05", progress: 100, score: 88, status: "passed" },
  { user: "u-****8810", course: "Social Engineering Defense", enrolled: "2026-03-18", due: "2026-04-18", progress: 100, score: 82, status: "passed" },
  { user: "u-****3341", course: "AI Security & Responsible Use", enrolled: "2026-04-01", due: "2026-05-01", progress: 20, score: null, status: "enrolled" },
  { user: "u-****6692", course: "OWASP Top 10 for Developers", enrolled: "2026-02-01", due: "2026-03-01", progress: 100, score: 69, status: "failed" },
  { user: "u-****1123", course: "Phishing Awareness Fundamentals", enrolled: "2026-03-28", due: "2026-04-28", progress: 55, score: null, status: "enrolled" },
  { user: "u-****9977", course: "Security Compliance Essentials", enrolled: "2026-03-12", due: "2026-04-12", progress: 100, score: 94, status: "passed" },
  { user: "u-****4450", course: "Data Privacy & GDPR", enrolled: "2026-04-05", due: "2026-05-05", progress: 12, score: null, status: "enrolled" },
  { user: "u-****8831", course: "HIPAA Compliance Training", enrolled: "2026-02-20", due: "2026-03-20", progress: 80, score: null, status: "enrolled" },
];

const CAMPAIGNS = [
  { name: "Q2 Compliance Refresh", group: "All Staff", courses: 3, due: "2026-05-31", completion: 62, status: "active" },
  { name: "Developer Security Bootcamp", group: "Engineering", courses: 4, due: "2026-04-30", completion: 48, status: "active" },
  { name: "New Hire Onboarding Security", group: "HR Onboarding", courses: 5, due: "2026-06-15", completion: 91, status: "active" },
  { name: "GDPR Annual Refresh", group: "EU Region", courses: 2, due: "2026-03-31", completion: 100, status: "completed" },
  { name: "Executive Cyber Awareness", group: "Leadership", courses: 2, due: "2026-05-15", completion: 35, status: "at_risk" },
];

const CATEGORIES = [
  { name: "Compliance", completion: 87 },
  { name: "Phishing Defense", completion: 82 },
  { name: "Data Privacy", completion: 76 },
  { name: "Secure Coding", completion: 58 },
  { name: "Identity & Access", completion: 54 },
  { name: "Incident Response", completion: 49 },
  { name: "AI Safety", completion: 41 },
];

const categoryColor: Record<string, string> = {
  phishing: "bg-orange-500/20 text-orange-400",
  compliance: "bg-blue-500/20 text-blue-400",
  secure_coding: "bg-purple-500/20 text-purple-400",
  privacy: "bg-teal-500/20 text-teal-400",
};

const difficultyColor: Record<string, string> = {
  Beginner: "bg-green-500/20 text-green-400",
  Intermediate: "bg-yellow-500/20 text-yellow-400",
  Advanced: "bg-red-500/20 text-red-400",
};

const statusColor: Record<string, string> = {
  passed: "bg-green-500/20 text-green-400",
  failed: "bg-red-500/20 text-red-400",
  enrolled: "bg-blue-500/20 text-blue-400",
  completed: "bg-green-500/20 text-green-400",
  active: "bg-blue-500/20 text-blue-400",
  at_risk: "bg-red-500/20 text-red-400",
};

function KPICard({ label, value, sub, icon: Icon, color }: { label: string; value: string; sub: string; icon: React.ElementType; color: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm text-muted-foreground">{label}</span>
        <div className={`rounded-lg p-2 ${color}`}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
      <div className="text-2xl font-bold text-foreground">{value}</div>
      <div className="mt-1 text-xs text-muted-foreground">{sub}</div>
    </div>
  );
}

function ProgressBar({ value, color = "bg-primary" }: { value: number; color?: string }) {
  return (
    <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${value}%` }} />
    </div>
  );
}

function isOverdue(due: string) {
  return new Date(due) < new Date("2026-04-16");
}

export default function SecurityTrainingDashboard() {
  const [activeTab, setActiveTab] = useState<"catalog" | "enrollments" | "campaigns" | "categories">("catalog");
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/security-training/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-training/courses?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-training/enrollments?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-training/campaigns?org_id=${ORG_ID}`),
    ]).then(([statsRes, coursesRes, enrollRes, campRes]) => {
      const stats     = statsRes.status     === "fulfilled" ? statsRes.value     : null;
      const courses   = coursesRes.status   === "fulfilled" ? coursesRes.value   : null;
      const enrollments = enrollRes.status  === "fulfilled" ? enrollRes.value    : null;
      const campaigns = campRes.status      === "fulfilled" ? campRes.value      : null;
      if (stats || courses || enrollments || campaigns) {
        setLiveData({ stats, courses, enrollments, campaigns });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Security Training</h1>
        <p className="text-sm text-muted-foreground mt-1">Course management, completion tracking, and campaigns</p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KPICard label="Courses" value={String(liveData?.stats?.total_courses ?? liveData?.courses?.length ?? 24)} sub="8 active this quarter" icon={GraduationCap} color="bg-primary/10 text-primary" />
        <KPICard label="Active Enrollments" value={liveData?.stats?.active_enrollments ? liveData.stats.active_enrollments.toLocaleString() : "3,847"} sub="+214 this week" icon={Users} color="bg-blue-500/10 text-blue-400" />
        <KPICard label="Completion Rate" value={liveData?.stats?.completion_rate ? `${liveData.stats.completion_rate.toFixed(1)}%` : "78.4%"} sub="+3.2% vs last quarter" icon={CheckCircle} color="bg-green-500/10 text-green-400" />
        <KPICard label="Avg Score" value={liveData?.stats?.average_score ? liveData.stats.average_score.toFixed(1) : "82.7"} sub="Passing threshold: 80" icon={Star} color="bg-yellow-500/10 text-yellow-400" />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {(["catalog", "enrollments", "campaigns", "categories"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px ${
              activeTab === tab
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Course Catalog */}
      {activeTab === "catalog" && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {(liveData?.courses ?? COURSES).map((c: any) => (
            <div key={c.id} className="rounded-xl border border-border bg-card p-4 flex flex-col gap-3">
              <div className="flex items-start justify-between gap-2">
                <span className="text-sm font-semibold text-foreground leading-snug">{c.title}</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium capitalize ${categoryColor[c.category]}`}>{c.category.replace("_", " ")}</span>
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${difficultyColor[c.difficulty]}`}>{c.difficulty}</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{c.duration}</span>
                <span className="flex items-center gap-1"><Star className="h-3 w-3" />Pass: {c.passingScore}%</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1"><Users className="h-3 w-3" />{c.enrolled.toLocaleString()} enrolled</span>
              </div>
              <div className="mt-auto space-y-1">
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Completion</span><span className="font-medium text-foreground">{c.completion}%</span>
                </div>
                <ProgressBar value={c.completion} color={c.completion >= 80 ? "bg-green-500" : c.completion >= 60 ? "bg-yellow-500" : "bg-red-500"} />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Enrollment Table */}
      {activeTab === "enrollments" && (
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table role="table" className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">User</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Course</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Enrolled</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Due Date</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Progress</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Score</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {(liveData?.enrollments ?? ENROLLMENTS).map((e: any, i: number) => (
                <tr key={i} className="hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{e.user}</td>
                  <td className="px-4 py-3 text-xs text-foreground max-w-[180px] truncate">{e.course}</td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{e.enrolled}</td>
                  <td className={`px-4 py-3 text-xs font-medium ${isOverdue(e.due) && e.status === "enrolled" ? "text-red-400" : "text-muted-foreground"}`}>
                    {e.due}{isOverdue(e.due) && e.status === "enrolled" && <span className="ml-1 text-[10px] text-red-400">OVERDUE</span>}
                  </td>
                  <td className="px-4 py-3 w-28">
                    <div className="flex items-center gap-2">
                      <ProgressBar value={e.progress} color={e.progress === 100 ? "bg-green-500" : "bg-primary"} />
                      <span className="text-[11px] text-muted-foreground w-8 shrink-0">{e.progress}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-foreground">{e.score !== null ? e.score : "="}</td>
                  <td className="px-4 py-3">
                    <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium capitalize ${statusColor[e.status]}`}>{e.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Training Campaigns */}
      {activeTab === "campaigns" && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {(liveData?.campaigns ?? CAMPAIGNS).map((c: any, i: number) => (
            <div key={i} className="rounded-xl border border-border bg-card p-5 space-y-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold text-foreground">{c.name}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{c.group}</div>
                </div>
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium capitalize ${statusColor[c.status]}`}>{c.status.replace("_", " ")}</span>
              </div>
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1"><GraduationCap className="h-3 w-3" />{c.courses} courses</span>
                <span className="flex items-center gap-1"><Clock className="h-3 w-3" />Due {c.due}</span>
              </div>
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Completion</span>
                  <span className="font-semibold text-foreground">{c.completion}%</span>
                </div>
                <ProgressBar value={c.completion} color={c.completion === 100 ? "bg-green-500" : c.status === "at_risk" ? "bg-red-500" : "bg-primary"} />
              </div>
              <button className="flex items-center gap-1 text-xs text-primary hover:underline">
                View details <ChevronRight className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Category Completion */}
      {activeTab === "categories" && (
        <div className="rounded-xl border border-border bg-card p-6 space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold text-foreground">Completion by Category</span>
          </div>
          {CATEGORIES.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            CATEGORIES.map((cat) => (
            <div key={cat.name} className="space-y-1.5">
              <div className="flex justify-between text-sm">
                <span className="text-foreground">{cat.name}</span>
                <span className="font-semibold text-foreground">{cat.completion}%</span>
              </div>
              <ProgressBar
                value={cat.completion}
                color={cat.completion >= 80 ? "bg-green-500" : cat.completion >= 60 ? "bg-yellow-500" : "bg-red-500"}
              />
            </div>
          )))}
        </div>
      )}
    </div>
  );
}
