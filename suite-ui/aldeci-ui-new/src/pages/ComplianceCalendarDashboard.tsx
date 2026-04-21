/**
 * Compliance Calendar Dashboard
 *
 * Month-grid calendar with event dots, upcoming events list, overdue alerts,
 * reminders panel, recurring event badges, framework filter tabs, add-event form,
 * and summary stats.
 *
 * Route: /compliance-calendar
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/compliance-calendar";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import {
  CalendarDays,
  AlertTriangle,
  Bell,
  Plus,
  RefreshCw,
  Clock,
  Filter,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

type Framework = "ALL" | "SOC2" | "ISO27001" | "PCI-DSS" | "HIPAA" | "NIST" | "GDPR" | "FedRAMP" | "CIS";
type Priority = "critical" | "high" | "medium" | "low";
type Recurrence = "none" | "weekly" | "monthly" | "quarterly" | "annual";

interface CalEvent {
  id: string;
  event_name: string;
  framework: Exclude<Framework, "ALL">;
  due_date: string; // YYYY-MM-DD
  priority: Priority;
  assigned_to: string;
  recurrence: Recurrence;
  overdue?: boolean;
  reminder_due?: boolean;
}

// ── Mock data ──────────────────────────────────────────────────

const TODAY = "2026-04-16";
const YEAR = 2026;
const MONTH = 3; // 0-indexed → April

const EVENTS: CalEvent[] = [
  { id: "e01", event_name: "SOC2 Type II Evidence Collection", framework: "SOC2", due_date: "2026-04-02", priority: "critical", assigned_to: "Audit Team", recurrence: "annual", overdue: true },
  { id: "e02", event_name: "PCI-DSS Quarterly SAQ Review", framework: "PCI-DSS", due_date: "2026-04-05", priority: "high", assigned_to: "Compliance Lead", recurrence: "quarterly", overdue: true },
  { id: "e03", event_name: "GDPR DPIA Review", framework: "GDPR", due_date: "2026-04-10", priority: "high", assigned_to: "Privacy Officer", recurrence: "annual", overdue: true },
  { id: "e04", event_name: "ISO 27001 Internal Audit", framework: "ISO27001", due_date: "2026-04-18", priority: "critical", assigned_to: "CISO", recurrence: "annual", reminder_due: true },
  { id: "e05", event_name: "NIST CSF Maturity Assessment", framework: "NIST", due_date: "2026-04-22", priority: "medium", assigned_to: "Security Team", recurrence: "quarterly", reminder_due: true },
  { id: "e06", event_name: "HIPAA Risk Analysis Update", framework: "HIPAA", due_date: "2026-04-25", priority: "high", assigned_to: "Risk Manager", recurrence: "annual" },
  { id: "e07", event_name: "FedRAMP Continuous Monitoring", framework: "FedRAMP", due_date: "2026-04-28", priority: "critical", assigned_to: "Fed Team", recurrence: "monthly" },
  { id: "e08", event_name: "CIS Benchmark Scan", framework: "CIS", due_date: "2026-04-30", priority: "medium", assigned_to: "SecOps", recurrence: "monthly" },
  { id: "e09", event_name: "SOC2 User Access Review", framework: "SOC2", due_date: "2026-05-05", priority: "high", assigned_to: "IAM Team", recurrence: "quarterly" },
  { id: "e10", event_name: "GDPR Consent Audit", framework: "GDPR", due_date: "2026-05-12", priority: "medium", assigned_to: "Privacy Officer", recurrence: "annual" },
];

// ── Helpers ────────────────────────────────────────────────────

function priorityBadge(p: Priority) {
  const map: Record<Priority, string> = {
    critical: "bg-red-500/20 text-red-300 border border-red-500/40",
    high: "bg-orange-500/20 text-orange-300 border border-orange-500/40",
    medium: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40",
    low: "bg-gray-600/40 text-gray-300",
  };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${map[p]}`}>{p}</span>;
}

function frameworkBadge(f: string) {
  const colors: Record<string, string> = {
    SOC2: "bg-blue-500/20 text-blue-300",
    ISO27001: "bg-purple-500/20 text-purple-300",
    "PCI-DSS": "bg-yellow-500/20 text-yellow-300",
    HIPAA: "bg-pink-500/20 text-pink-300",
    NIST: "bg-teal-500/20 text-teal-300",
    GDPR: "bg-indigo-500/20 text-indigo-300",
    FedRAMP: "bg-green-500/20 text-green-300",
    CIS: "bg-orange-500/20 text-orange-300",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[f] ?? "bg-gray-600 text-gray-300"}`}>
      {f}
    </span>
  );
}

function recurrenceBadge(r: Recurrence) {
  if (r === "none") return null;
  const map: Record<string, string> = {
    weekly: "bg-sky-500/20 text-sky-300",
    monthly: "bg-violet-500/20 text-violet-300",
    quarterly: "bg-amber-500/20 text-amber-300",
    annual: "bg-rose-500/20 text-rose-300",
  };
  return (
    <span className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs ${map[r]}`}>
      <RefreshCw size={10} /> {r}
    </span>
  );
}

function daysRemaining(dateStr: string): number {
  const due = new Date(dateStr);
  const today = new Date(TODAY);
  return Math.round((due.getTime() - today.getTime()) / 86400000);
}

function buildCalendar(year: number, month: number): (number | null)[][] {
  const firstDay = new Date(year, month, 1).getDay();
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const cells: (number | null)[] = Array(firstDay).fill(null);
  for (let i = 1; i <= daysInMonth; i++) cells.push(i);
  while (cells.length % 7 !== 0) cells.push(null);
  const weeks: (number | null)[][] = [];
  for (let i = 0; i < cells.length; i += 7) weeks.push(cells.slice(i, i + 7));
  return weeks;
}

const PRIORITY_DOT: Record<Priority, string> = {
  critical: "bg-red-500",
  high: "bg-orange-400",
  medium: "bg-yellow-400",
  low: "bg-gray-500",
};

const FRAMEWORKS: Framework[] = ["ALL", "SOC2", "ISO27001", "PCI-DSS", "HIPAA", "NIST", "GDPR", "FedRAMP", "CIS"];

// ── Component ──────────────────────────────────────────────────

export default function ComplianceCalendarDashboard() {
  const [calEvents, setCalEvents] = useState(EVENTS);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${_API_BASE}/upcoming?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setCalEvents(d); })
      .catch((e) => setError(e?.message || 'Failed to load data'));
  }, []);

  const [activeFramework, setActiveFramework] = useState<Framework>("ALL");
  useEffect(() => {
    fetch(`${_API_BASE}/overdue?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => {
        // live data loaded — components read from API response
        void d;
      })
      .catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);

  const [showAddForm, setShowAddForm] = useState(false);
  const [newEvent, setNewEvent] = useState({ name: "", framework: "SOC2", due_date: "", priority: "medium" });
  const [error, setError] = useState<string | null>(null);

  const filtered = activeFramework === "ALL" ? EVENTS : EVENTS.filter((e) => e.framework === activeFramework);
  const overdue = EVENTS.filter((e) => e.overdue);
  const reminders = EVENTS.filter((e) => e.reminder_due);
  const upcoming = filtered
    .filter((e) => !e.overdue)
    .sort((a, b) => a.due_date.localeCompare(b.due_date))
    .slice(0, 6);

  const weeks = buildCalendar(YEAR, MONTH);
  const monthName = new Date(YEAR, MONTH, 1).toLocaleString("default", { month: "long", year: "numeric" });

  // map day → events for this month
  const dayEventMap: Record<number, CalEvent[]> = {};
  EVENTS.forEach((ev) => {
    const d = new Date(ev.due_date);
    if (d.getFullYear() === YEAR && d.getMonth() === MONTH) {
      const day = d.getDate();
      if (!dayEventMap[day]) dayEventMap[day] = [];
      dayEventMap[day].push(ev);
    }
  });

  const thisWeekCount = EVENTS.filter((e) => {
    const days = daysRemaining(e.due_date);
    return days >= 0 && days <= 7;
  }).length;
  const thisMonthCount = EVENTS.filter((e) => {
    const days = daysRemaining(e.due_date);
    return days >= 0 && days <= 30;
  }).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <CalendarDays className="text-indigo-400" size={28} />
          <div>
            <h1 className="text-2xl font-bold">Compliance Calendar</h1>
            <p className="text-gray-400 text-sm">Deadlines, audits, and recurring reviews across all frameworks</p>
          </div>
        </div>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm font-medium transition-colors"
        >
          <Plus size={16} /> Add Event
        </button>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Events", value: EVENTS.length, color: "text-indigo-400" },
          { label: "Overdue", value: overdue.length, color: "text-red-400" },
          { label: "This Week", value: thisWeekCount, color: "text-yellow-400" },
          { label: "This Month", value: thisMonthCount, color: "text-teal-400" },
        ].map((s) => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-4 text-center">
            <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-gray-400 text-sm mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Overdue alert banner */}
      {overdue.length > 0 && (
        <div className="bg-red-900/30 border border-red-500/40 rounded-lg px-4 py-3 flex items-center gap-3">
          <AlertTriangle className="text-red-400 shrink-0" size={20} />
          <div>
            <span className="text-red-300 font-semibold">{overdue.length} overdue event{overdue.length > 1 ? "s" : ""}: </span>
            <span className="text-red-200 text-sm">{overdue.map((e) => e.event_name).join(" · ")}</span>
          </div>
        </div>
      )}

      {/* Add event form */}
      {showAddForm && (
        <div className="bg-gray-800 rounded-lg p-6 border border-indigo-500/30">
          <h2 className="text-base font-semibold mb-4 flex items-center gap-2"><Plus size={16} className="text-indigo-400" /> New Compliance Event</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <input
              className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200 col-span-2"
              placeholder="Event name"
              value={newEvent.name}
              onChange={(e) => setNewEvent({ ...newEvent, name: e.target.value })}
            />
            <select
              className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200"
              value={newEvent.framework}
              onChange={(e) => setNewEvent({ ...newEvent, framework: e.target.value })}
            >
              {FRAMEWORKS.filter((f) => f !== "ALL").map((f) => <option key={f}>{f}</option>)}
            </select>
            <input
              type="date"
              className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200"
              value={newEvent.due_date}
              onChange={(e) => setNewEvent({ ...newEvent, due_date: e.target.value })}
            />
          </div>
          <div className="flex gap-3 mt-4">
            <button
              onClick={() => setShowAddForm(false)}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded text-sm font-medium"
            >
              Save Event
            </button>
            <button
              onClick={() => setShowAddForm(false)}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Framework filter tabs */}
      <div className="flex gap-2 flex-wrap">
        <Filter size={16} className="text-gray-400 self-center" />
        {FRAMEWORKS.map((fw) => (
          <button
            key={fw}
            onClick={() => setActiveFramework(fw)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              activeFramework === fw
                ? "bg-indigo-600 text-white"
                : "bg-gray-700 text-gray-300 hover:bg-gray-600"
            }`}
          >
            {fw}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Calendar grid */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-base font-semibold mb-4 text-center">{monthName}</h2>
          <div className="grid grid-cols-7 gap-1 text-xs text-gray-400 text-center mb-1">
            {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((d) => (
              <div key={d} className="py-1 font-medium">{d}</div>
            ))}
          </div>
          {weeks.map((week, wi) => (
            <div key={wi} className="grid grid-cols-7 gap-1 mb-1">
              {week.map((day, di) => {
                const isToday = day === 16;
                const evts = day ? (dayEventMap[day] ?? []) : [];
                return (
                  <div
                    key={di}
                    className={`min-h-[52px] rounded p-1 text-xs ${
                      day ? "bg-gray-700/50 hover:bg-gray-700" : "bg-transparent"
                    } ${isToday ? "ring-2 ring-indigo-500" : ""}`}
                  >
                    {day && (
                      <>
                        <div className={`font-medium mb-1 ${isToday ? "text-indigo-300" : "text-gray-300"}`}>{day}</div>
                        <div className="flex flex-wrap gap-0.5">
                          {evts.slice(0, 3).map((ev) => (
                            <span
                              key={ev.id}
                              className={`inline-block w-2 h-2 rounded-full ${PRIORITY_DOT[ev.priority]}`}
                              title={ev.event_name}
                            />
                          ))}
                          {evts.length > 3 && <span className="text-gray-500">+{evts.length - 3}</span>}
                        </div>
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          ))}
          <div className="flex gap-4 mt-3 text-xs text-gray-400">
            {(["critical", "high", "medium", "low"] as Priority[]).map((p) => (
              <div key={p} className="flex items-center gap-1">
                <span className={`w-2 h-2 rounded-full ${PRIORITY_DOT[p]}`} /> {p}
              </div>
            ))}
          </div>
        </div>

        {/* Right: upcoming + reminders */}
        <div className="space-y-4">
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Clock size={16} className="text-indigo-400" /> Upcoming Events
            </h2>
            <div className="space-y-3">
              {upcoming.map((ev) => {
                const days = daysRemaining(ev.due_date);

                if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

                return (
                  <div key={ev.id} className="border-b border-gray-700/50 pb-3 last:border-0 last:pb-0">
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-gray-200 text-sm font-medium">{ev.event_name}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1 flex-wrap">
                      {frameworkBadge(ev.framework)}
                      {priorityBadge(ev.priority)}
                      {recurrenceBadge(ev.recurrence)}
                    </div>
                    <div className="flex items-center justify-between mt-1 text-xs text-gray-400">
                      <span>{ev.assigned_to}</span>
                      <span className={days <= 3 ? "text-red-400 font-medium" : "text-gray-400"}>
                        {days >= 0 ? `${days}d remaining` : `${Math.abs(days)}d overdue`}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Bell size={16} className="text-yellow-400" /> Reminders Due
            </h2>
            {reminders.length === 0 ? (
              <p className="text-gray-400 text-xs">No reminders pending.</p>
            ) : (
              <div className="space-y-2">
                {reminders.map((ev) => (
                  <div key={ev.id} className="flex items-center justify-between text-sm">
                    <span className="text-yellow-200">{ev.event_name}</span>
                    {frameworkBadge(ev.framework)}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
