/**
 * Awareness Program Dashboard
 *
 * Security awareness program management with enrollment, completion, and compliance tracking.
 *   1. KPIs: programs / enrolled / completed / avg pass rate
 *   2. Program list with progress bars
 *   3. Enrollment table
 *   4. Department compliance table
 *   5. Overdue enrollments panel
 *   6. Awareness events log
 *
 * Route: /awareness-program
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { GraduationCap, Users, AlertTriangle, CheckCircle, XCircle, Calendar, Bell } from "lucide-react";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_PROGRAMS = [
  { id: "prg-001", program_name: "Annual Security Awareness",     type: "mandatory",  frequency: "annual",    enrolled: 820, completed: 781, pass_rate: 94, status: "active" },
  { id: "prg-002", program_name: "Phishing Simulation Training",  type: "simulation", frequency: "monthly",   enrolled: 820, completed: 652, pass_rate: 87, status: "active" },
  { id: "prg-003", program_name: "GDPR Data Handling Basics",     type: "compliance", frequency: "annual",    enrolled: 420, completed: 398, pass_rate: 91, status: "active" },
  { id: "prg-004", program_name: "Privileged Access Training",    type: "role-based", frequency: "quarterly", enrolled:  62, completed:  55, pass_rate: 96, status: "active" },
  { id: "prg-005", program_name: "Secure Coding Fundamentals",    type: "role-based", frequency: "biannual",  enrolled: 134, completed:  89, pass_rate: 78, status: "active" },
  { id: "prg-006", program_name: "Incident Reporting Procedures", type: "mandatory",  frequency: "annual",    enrolled: 820, completed: 501, pass_rate: 82, status: "draft"  },
];

const MOCK_ENROLLMENTS = [
  { id: "enr-001", user_name: "Alice Johnson",  department: "Engineering",  enrolled_at: "2026-03-01", score: 95, passed: true,  attempts: 1 },
  { id: "enr-002", user_name: "Bob Martinez",   department: "Finance",      enrolled_at: "2026-03-01", score: 88, passed: true,  attempts: 1 },
  { id: "enr-003", user_name: "Carol Davis",    department: "HR",           enrolled_at: "2026-03-01", score: 72, passed: false, attempts: 2 },
  { id: "enr-004", user_name: "Dave Wilson",    department: "IT",           enrolled_at: "2026-03-01", score: 99, passed: true,  attempts: 1 },
  { id: "enr-005", user_name: "Eva Chen",       department: "Legal",        enrolled_at: "2026-03-15", score:  0, passed: false, attempts: 0 },
  { id: "enr-006", user_name: "Frank Okonkwo",  department: "Engineering",  enrolled_at: "2026-03-15", score: 81, passed: true,  attempts: 1 },
  { id: "enr-007", user_name: "Grace Kim",      department: "Marketing",    enrolled_at: "2026-03-20", score:  0, passed: false, attempts: 0 },
  { id: "enr-008", user_name: "Hiro Tanaka",    department: "IT",           enrolled_at: "2026-03-10", score: 91, passed: true,  attempts: 1 },
  { id: "enr-009", user_name: "Isla Brown",     department: "Finance",      enrolled_at: "2026-03-01", score: 55, passed: false, attempts: 3 },
  { id: "enr-010", user_name: "Jack O'Brien",   department: "Legal",        enrolled_at: "2026-02-20", score: 78, passed: true,  attempts: 2 },
];

const MOCK_DEPARTMENTS = [
  { department: "Engineering",  enrolled: 134, completed: 128, pass_count: 122, compliance_rate: 91 },
  { department: "Finance",      enrolled:  88, completed:  82, pass_count:  79, compliance_rate: 90 },
  { department: "HR",           enrolled:  45, completed:  40, pass_count:  33, compliance_rate: 73 },
  { department: "IT",           enrolled:  62, completed:  61, pass_count:  60, compliance_rate: 97 },
  { department: "Legal",        enrolled:  28, completed:  22, pass_count:  21, compliance_rate: 75 },
  { department: "Marketing",    enrolled:  71, completed:  55, pass_count:  48, compliance_rate: 68 },
  { department: "Operations",   enrolled: 112, completed: 101, pass_count:  95, compliance_rate: 85 },
  { department: "Sales",        enrolled:  98, completed:  78, pass_count:  71, compliance_rate: 72 },
];

const MOCK_OVERDUE = [
  { user_name: "Eva Chen",    department: "Legal",   enrolled_at: "2026-03-15", days_elapsed: 32 },
  { user_name: "Grace Kim",   department: "Marketing",enrolled_at: "2026-03-20",days_elapsed: 27 },
  { user_name: "Isla Brown",  department: "Finance", enrolled_at: "2026-03-01", days_elapsed: 46 },
  { user_name: "Leo Park",    department: "Sales",   enrolled_at: "2026-03-05", days_elapsed: 42 },
  { user_name: "Mia Torres",  department: "HR",      enrolled_at: "2026-03-10", days_elapsed: 37 },
];

const MOCK_EVENTS = [
  { id: "evt-001", event_type: "completion",       description: "Alice Johnson completed Annual Security Awareness",         affected_users:   1, department: "Engineering", event_date: "2026-04-16T09:45:00Z" },
  { id: "evt-002", event_type: "phishing_click",   description: "3 users clicked simulated phishing link in Marketing",     affected_users:   3, department: "Marketing",   event_date: "2026-04-16T09:30:00Z" },
  { id: "evt-003", event_type: "enrollment",       description: "New cohort enrolled in GDPR Data Handling Basics",         affected_users:  42, department: "All",         event_date: "2026-04-16T09:00:00Z" },
  { id: "evt-004", event_type: "failure",          description: "Isla Brown failed Annual Security Awareness (attempt 3)",  affected_users:   1, department: "Finance",     event_date: "2026-04-15T14:22:00Z" },
  { id: "evt-005", event_type: "reminder_sent",    description: "Overdue reminder sent to 5 users across 4 departments",   affected_users:   5, department: "Multiple",    event_date: "2026-04-15T10:00:00Z" },
  { id: "evt-006", event_type: "completion",       description: "IT Dept achieved 97% compliance rate",                    affected_users:  62, department: "IT",           event_date: "2026-04-14T16:00:00Z" },
];

// ── Helpers ────────────────────────────────────────────────────

function fmt(iso: string) {
  return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function TypeBadge({ t }: { t: string }) {
  const cls: Record<string, string> = {
    mandatory:  "bg-red-500/20 text-red-400",
    simulation: "bg-purple-500/20 text-purple-400",
    compliance: "bg-blue-500/20 text-blue-400",
    "role-based": "bg-orange-500/20 text-orange-400",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium capitalize", cls[t] ?? "bg-gray-700 text-gray-300")}>{t}</span>;
}

function FreqBadge({ f }: { f: string }) {
  return <span className="text-[10px] px-2 py-0.5 rounded bg-teal-500/20 text-teal-400 font-medium capitalize">{f}</span>;
}

function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    active: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
    draft:  "bg-gray-500/20 text-gray-400 border border-gray-500/30",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium capitalize", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}

function DeptBadge({ d }: { d: string }) {
  const colors = ["bg-blue-500/20 text-blue-400", "bg-purple-500/20 text-purple-400", "bg-teal-500/20 text-teal-400", "bg-pink-500/20 text-pink-400", "bg-indigo-500/20 text-indigo-400"];
  const idx = d.length % colors.length;
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", colors[idx])}>{d}</span>;
}

function EventTypeBadge({ t }: { t: string }) {
  const cls: Record<string, string> = {
    completion:     "bg-emerald-500/20 text-emerald-400",
    phishing_click: "bg-red-500/20 text-red-400",
    enrollment:     "bg-blue-500/20 text-blue-400",
    failure:        "bg-orange-500/20 text-orange-400",
    reminder_sent:  "bg-yellow-500/20 text-yellow-400",
  };
  const label = t.replace(/_/g, " ");
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium capitalize", cls[t] ?? "bg-gray-700 text-gray-300")}>{label}</span>;
}

function complianceColor(rate: number) {
  if (rate >= 90) return "text-emerald-400";
  if (rate >= 75) return "text-yellow-400";
  return "text-red-400";
}

function KpiCard({ icon: Icon, label, value, sub, color }: { icon: React.ElementType; label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className="bg-gray-800 rounded-lg p-6 flex items-start gap-4">
      <div className={cn("p-3 rounded-lg", color)}><Icon className="w-5 h-5" /></div>
      <div>
        <p className="text-gray-400 text-sm">{label}</p>
        <p className="text-2xl font-bold text-white mt-0.5">{value}</p>
        {sub && <p className="text-gray-500 text-xs mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function AwarenessProgramDashboard() {
  const [selectedProgram, setSelectedProgram] = useState(MOCK_PROGRAMS[0]);

  const totalEnrolled   = MOCK_PROGRAMS.reduce((s, p) => s + p.enrolled, 0);
  const totalCompleted  = MOCK_PROGRAMS.reduce((s, p) => s + p.completed, 0);
  const avgPassRate     = Math.round(MOCK_PROGRAMS.reduce((s, p) => s + p.pass_rate, 0) / MOCK_PROGRAMS.length);

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><GraduationCap className="w-6 h-6 text-blue-400" /> Awareness Programs</h1>
          <p className="text-gray-400 text-sm mt-1">Security awareness training enrollment, completion, and compliance by department</p>
        </div>
      </div>

      {/* Overdue Banner */}
      {MOCK_OVERDUE.length > 0 && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
          className="bg-orange-500/10 border border-orange-500/30 text-orange-300 px-4 py-3 rounded-lg flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm font-medium">{MOCK_OVERDUE.length} users enrolled over 30 days without completing training</span>
          <span className="ml-auto text-xs text-orange-400">{MOCK_OVERDUE.map(u => u.user_name.split(" ")[0]).join(", ")}</span>
        </motion.div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard icon={GraduationCap} label="Programs"          value={MOCK_PROGRAMS.length} color="bg-blue-500/20 text-blue-400" />
        <KpiCard icon={Users}         label="Total Enrolled"    value={totalEnrolled.toLocaleString()} sub="unique users" color="bg-purple-500/20 text-purple-400" />
        <KpiCard icon={CheckCircle}   label="Completed"         value={totalCompleted.toLocaleString()} color="bg-emerald-500/20 text-emerald-400" />
        <KpiCard icon={GraduationCap} label="Avg Pass Rate"     value={`${avgPassRate}%`}    color="bg-teal-500/20 text-teal-400" />
      </div>

      {/* Program List */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Programs</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {MOCK_PROGRAMS.map(p => (
            <button key={p.id} onClick={() => setSelectedProgram(p)}
              className={cn("bg-gray-900 rounded-lg p-4 text-left hover:bg-gray-700/50 transition-all border",
                selectedProgram.id === p.id ? "border-blue-500/60" : "border-transparent")}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-white text-sm font-semibold truncate">{p.program_name}</p>
                <StatusBadge s={p.status} />
              </div>
              <div className="flex gap-2 mb-3">
                <TypeBadge t={p.type} />
                <FreqBadge f={p.frequency} />
              </div>
              <div className="space-y-1">
                <div className="flex justify-between text-[10px] text-gray-500">
                  <span>Enrolled: {p.enrolled}</span>
                  <span>Completed: {p.completed}</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-1.5">
                  <div className="h-1.5 bg-blue-500 rounded-full" style={{ width: `${(p.completed / p.enrolled) * 100}%` }} />
                </div>
                <div className="flex justify-between text-[10px]">
                  <span className="text-gray-500">{Math.round((p.completed / p.enrolled) * 100)}% complete</span>
                  <span className={cn("font-semibold", p.pass_rate >= 90 ? "text-emerald-400" : p.pass_rate >= 75 ? "text-yellow-400" : "text-red-400")}>
                    {p.pass_rate}% pass rate
                  </span>
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Enrollment Table */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
            Enrollments — <span className="text-blue-400">{selectedProgram.program_name}</span>
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                  <th className="text-left pb-2 pr-4">User</th>
                  <th className="text-left pb-2 pr-4">Department</th>
                  <th className="text-left pb-2 pr-4">Enrolled</th>
                  <th className="text-left pb-2 pr-4 w-28">Score</th>
                  <th className="text-left pb-2 pr-4">Status</th>
                  <th className="text-left pb-2">Attempts</th>
                </tr>
              </thead>
              <tbody>
                {MOCK_ENROLLMENTS.map(e => (
                  <tr key={e.id} className="border-b border-gray-700/50 hover:bg-gray-700/20">
                    <td className="py-2.5 pr-4 text-white text-xs font-medium">{e.user_name}</td>
                    <td className="py-2.5 pr-4"><DeptBadge d={e.department} /></td>
                    <td className="py-2.5 pr-4 text-gray-400 text-xs">{e.enrolled_at}</td>
                    <td className="py-2.5 pr-4">
                      {e.score > 0 ? (
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                            <div className={cn("h-1.5 rounded-full", e.score >= 80 ? "bg-emerald-500" : "bg-red-500")}
                              style={{ width: `${e.score}%` }} />
                          </div>
                          <span className="text-xs text-gray-300 w-7">{e.score}</span>
                        </div>
                      ) : <span className="text-gray-600 text-xs">N/A</span>}
                    </td>
                    <td className="py-2.5 pr-4">
                      {e.attempts === 0
                        ? <span className="text-gray-500 text-xs">Not started</span>
                        : e.passed
                          ? <span className="text-emerald-400 text-xs font-semibold flex items-center gap-1"><CheckCircle className="w-3.5 h-3.5" /> Passed</span>
                          : <span className="text-red-400 text-xs font-semibold flex items-center gap-1"><XCircle className="w-3.5 h-3.5" /> Failed</span>}
                    </td>
                    <td className="py-2.5 text-gray-400 text-xs">{e.attempts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="space-y-6">
          {/* Overdue Panel */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" /> Overdue Enrollments
            </h2>
            <div className="space-y-2">
              {MOCK_OVERDUE.map((u, i) => (
                <div key={i} className="bg-orange-500/10 border border-orange-500/20 rounded-lg px-3 py-2.5">
                  <div className="flex items-center justify-between">
                    <p className="text-white text-xs font-semibold">{u.user_name}</p>
                    <span className="text-orange-400 text-xs font-bold">{u.days_elapsed}d overdue</span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <DeptBadge d={u.department} />
                    <span className="text-gray-500 text-[10px]">enrolled {u.enrolled_at}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Dept Compliance */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">Department Compliance</h2>
            <div className="space-y-2">
              {MOCK_DEPARTMENTS.sort((a, b) => b.compliance_rate - a.compliance_rate).map(d => (
                <div key={d.department} className="flex items-center gap-3">
                  <span className="text-xs text-gray-300 w-24 truncate">{d.department}</span>
                  <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                    <div className={cn("h-1.5 rounded-full",
                      d.compliance_rate >= 90 ? "bg-emerald-500" :
                      d.compliance_rate >= 75 ? "bg-yellow-500" : "bg-red-500")}
                      style={{ width: `${d.compliance_rate}%` }} />
                  </div>
                  <span className={cn("text-xs font-bold w-10 text-right", complianceColor(d.compliance_rate))}>
                    {d.compliance_rate}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Awareness Events Log */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
          <Bell className="w-4 h-4 text-yellow-400" /> Awareness Events
        </h2>
        <div className="space-y-2">
          {MOCK_EVENTS.map(ev => (
            <div key={ev.id} className="bg-gray-900 rounded-lg px-4 py-3 flex items-center gap-4">
              <EventTypeBadge t={ev.event_type} />
              <p className="text-xs text-gray-300 flex-1">{ev.description}</p>
              <DeptBadge d={ev.department} />
              <span className="text-[10px] text-gray-500 flex items-center gap-1 flex-shrink-0">
                <Calendar className="w-3 h-3" /> {fmt(ev.event_date)}
              </span>
              <span className="text-[10px] text-gray-500 w-16 text-right">{ev.affected_users} user{ev.affected_users > 1 ? "s" : ""}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
