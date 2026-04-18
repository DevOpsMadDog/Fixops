/**
 * Gap Analysis Dashboard
 *
 * Framework coverage grid, control gaps, and remediation planning.
 *   1. KPIs: total gaps / open / critical open
 *   2. Framework coverage grid (10 frameworks)
 *   3. Assessment table with coverage progress
 *   4. Control gaps list with overdue highlighting
 *   5. Remediation plans panel
 *   6. Overdue alert banner
 *
 * Route: /gap-analysis
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { BarChart2, AlertTriangle, CheckCircle, Clock, Shield, FileSearch } from "lucide-react";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_FRAMEWORKS = [
  { id: "fw-01", name: "SOC 2",        coverage_pct: 87, risk_level: "low",      controls: { implemented: 112, partial: 15, not_implemented: 3 } },
  { id: "fw-02", name: "ISO 27001",    coverage_pct: 79, risk_level: "medium",   controls: { implemented:  93, partial: 22, not_implemented: 9 } },
  { id: "fw-03", name: "PCI-DSS",      coverage_pct: 91, risk_level: "low",      controls: { implemented: 255, partial:  8, not_implemented: 3 } },
  { id: "fw-04", name: "HIPAA",        coverage_pct: 68, risk_level: "high",     controls: { implemented:  81, partial: 28, not_implemented: 17 } },
  { id: "fw-05", name: "NIST CSF",     coverage_pct: 74, risk_level: "medium",   controls: { implemented:  89, partial: 21, not_implemented: 10 } },
  { id: "fw-06", name: "NIST 800-53",  coverage_pct: 55, risk_level: "critical", controls: { implemented: 312, partial: 88, not_implemented: 166 } },
  { id: "fw-07", name: "CIS",          coverage_pct: 82, risk_level: "medium",   controls: { implemented: 148, partial: 16, not_implemented: 16 } },
  { id: "fw-08", name: "FedRAMP",      coverage_pct: 42, risk_level: "critical", controls: { implemented:  88, partial: 55, not_implemented: 66 } },
  { id: "fw-09", name: "GDPR",         coverage_pct: 93, risk_level: "low",      controls: { implemented:  53, partial:  3, not_implemented: 1 } },
  { id: "fw-10", name: "SOX",          coverage_pct: 78, risk_level: "medium",   controls: { implemented: 112, partial: 21, not_implemented: 11 } },
];

const MOCK_ASSESSMENTS = [
  { id: "asmnt-001", assessment_name: "Q1 2026 Full Compliance Audit", framework: "SOC 2",       coverage_pct: 87, implemented: 112, partial: 15, not_implemented: 3,  risk_level: "low" },
  { id: "asmnt-002", assessment_name: "Annual ISO Review",              framework: "ISO 27001",   coverage_pct: 79, implemented:  93, partial: 22, not_implemented: 9,  risk_level: "medium" },
  { id: "asmnt-003", assessment_name: "NIST 800-53 Gap Assessment",    framework: "NIST 800-53", coverage_pct: 55, implemented: 312, partial: 88, not_implemented: 166, risk_level: "critical" },
  { id: "asmnt-004", assessment_name: "FedRAMP Readiness Review",      framework: "FedRAMP",     coverage_pct: 42, implemented:  88, partial: 55, not_implemented: 66,  risk_level: "critical" },
  { id: "asmnt-005", assessment_name: "PCI-DSS SAQ-D",                  framework: "PCI-DSS",    coverage_pct: 91, implemented: 255, partial:  8, not_implemented: 3,   risk_level: "low" },
];

const MOCK_GAPS = [
  { id: "gap-001", control_id: "NIST-AC-17",  domain: "Access Control",    priority: "critical", status: "open",        due_date: "2026-03-15", owner: "alice@aldeci.io" },
  { id: "gap-002", control_id: "FED-IA-5",    domain: "IAM",               priority: "critical", status: "in_progress", due_date: "2026-04-01", owner: "bob@aldeci.io" },
  { id: "gap-003", control_id: "HIPAA-164.3",  domain: "Data Security",     priority: "high",     status: "open",        due_date: "2026-04-20", owner: "carol@aldeci.io" },
  { id: "gap-004", control_id: "ISO-A.12.3",  domain: "Backup",            priority: "high",     status: "open",        due_date: "2026-04-30", owner: "dave@aldeci.io" },
  { id: "gap-005", control_id: "NIST-CM-6",   domain: "Config Mgmt",       priority: "medium",   status: "in_progress", due_date: "2026-05-15", owner: "alice@aldeci.io" },
  { id: "gap-006", control_id: "CIS-7.1",     domain: "Vulnerability Mgmt",priority: "medium",   status: "implemented", due_date: "2026-03-01", owner: "bob@aldeci.io" },
  { id: "gap-007", control_id: "SOX-IT-GC",   domain: "IT General Controls",priority: "high",     status: "open",        due_date: "2026-04-10", owner: "carol@aldeci.io" },
  { id: "gap-008", control_id: "NIST-IR-4",   domain: "Incident Response", priority: "critical", status: "open",        due_date: "2026-02-28", owner: "dave@aldeci.io" },
  { id: "gap-009", control_id: "PCI-REQ-6",   domain: "Secure Dev",        priority: "low",      status: "accepted",    due_date: "2026-06-01", owner: "alice@aldeci.io" },
];

const MOCK_REMEDIATION = [
  { id: "rem-001", control_id: "NIST-AC-17", plan: "Implement MFA for all remote access VPN sessions using Duo Security.", owner: "alice@aldeci.io", target: "2026-04-25", progress: 65 },
  { id: "rem-002", control_id: "FED-IA-5",   plan: "Deploy CyberArk PAM for privileged account rotation on all production systems.", owner: "bob@aldeci.io", target: "2026-04-30", progress: 40 },
  { id: "rem-003", control_id: "HIPAA-164.3", plan: "Enable S3 bucket encryption at rest with KMS CMK for all PHI data stores.", owner: "carol@aldeci.io", target: "2026-05-10", progress: 20 },
];

// ── Helpers ────────────────────────────────────────────────────

function RiskBadge({ r }: { r: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    low:      "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium capitalize", cls[r] ?? "bg-gray-700 text-gray-300")}>{r}</span>;
}

function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    open:           "bg-red-500/20 text-red-400",
    in_progress:    "bg-blue-500/20 text-blue-400",
    implemented:    "bg-emerald-500/20 text-emerald-400",
    accepted:       "bg-gray-500/20 text-gray-400",
  };
  const label = s.replace(/_/g, " ");
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium capitalize", cls[s] ?? "bg-gray-700 text-gray-300")}>{label}</span>;
}

function DomainBadge({ d }: { d: string }) {
  return <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 font-medium">{d}</span>;
}

function PriorityBadge({ p }: { p: string }) {
  const cls: Record<string, string> = {
    critical: "text-red-400 font-bold",
    high:     "text-orange-400 font-semibold",
    medium:   "text-yellow-400",
    low:      "text-gray-400",
  };
  return <span className={cn("text-xs capitalize", cls[p] ?? "text-gray-400")}>{p}</span>;
}

function KpiCard({ icon: Icon, label, value, color }: { icon: React.ElementType; label: string; value: string | number; color: string }) {
  return (
    <div className="bg-gray-800 rounded-lg p-6 flex items-start gap-4">
      <div className={cn("p-3 rounded-lg", color)}><Icon className="w-5 h-5" /></div>
      <div>
        <p className="text-gray-400 text-sm">{label}</p>
        <p className="text-2xl font-bold text-white mt-0.5">{value}</p>
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function GapAnalysisDashboard() {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);

  const [fetchError, setFetchError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setFetchError(null);
    apiFetch(`/api/v1/gap-analysis/assessments?org_id=${ORG_ID}`).catch((err) => {
      setFetchError(err instanceof Error ? err.message : "Failed to load gap analysis data");
    });
  };

  useEffect(() => {
    loadData();
  
    setLoading(false);}, []);

  const today = new Date("2026-04-16");
  const overdueGaps = MOCK_GAPS.filter(g => g.status === "open" && new Date(g.due_date) < today);
  const openGaps    = MOCK_GAPS.filter(g => g.status === "open");
  const critOpen    = MOCK_GAPS.filter(g => g.status === "open" && g.priority === "critical");

  const displayedGaps = selectedFramework
    ? MOCK_GAPS.filter(g => g.control_id.startsWith(selectedFramework.split(" ")[0].toUpperCase()))
    : MOCK_GAPS;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */
    setLoading(false);}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><FileSearch className="w-6 h-6 text-purple-400" /> Gap Analysis</h1>
          <p className="text-gray-400 text-sm mt-1">Framework coverage gaps, control status, and remediation tracking</p>
        </div>
      </div>

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors">Retry</button>
        </div>
      )}

      {/* Overdue Banner */}
      {overdueGaps.length > 0 && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
          className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm font-medium">{overdueGaps.length} control gap{overdueGaps.length > 1 ? "s are" : " is"} overdue — immediate remediation required</span>
          <span className="ml-auto text-xs text-red-400">{overdueGaps.map(g => g.control_id).join(", ")}</span>
        </motion.div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <KpiCard icon={BarChart2}    label="Total Gaps"        value={MOCK_GAPS.length} color="bg-purple-500/20 text-purple-400" />
        <KpiCard icon={AlertTriangle} label="Open Gaps"        value={openGaps.length}  color="bg-orange-500/20 text-orange-400" />
        <KpiCard icon={Shield}       label="Critical Open"     value={critOpen.length}  color="bg-red-500/20 text-red-400" />
      </div>

      {/* Framework Coverage Grid */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Framework Coverage</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {MOCK_FRAMEWORKS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            MOCK_FRAMEWORKS.map(fw => (
            <button key={fw.id} onClick={() => setSelectedFramework(selectedFramework === fw.name ? null : fw.name)}
              className={cn("bg-gray-900 rounded-lg p-4 text-left hover:bg-gray-700/50 transition-all border",
                selectedFramework === fw.name ? "border-purple-500/60" : "border-transparent")}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-white text-xs font-semibold">{fw.name}</p>
                <RiskBadge r={fw.risk_level} />
              </div>
              <p className="text-2xl font-bold text-white">{fw.coverage_pct}%</p>
              <div className="w-full bg-gray-700 rounded-full h-1.5 mt-2">
                <div className={cn("h-1.5 rounded-full", fw.coverage_pct >= 80 ? "bg-emerald-500" : fw.coverage_pct >= 60 ? "bg-yellow-500" : "bg-red-500")}
                  style={{ width: `${fw.coverage_pct}%` }} />
              </div>
              <div className="flex gap-2 mt-2 text-[10px]">
                <span className="text-emerald-400">{fw.controls.implemented}✓</span>
                <span className="text-yellow-400">{fw.controls.partial}~</span>
                <span className="text-red-400">{fw.controls.not_implemented}✗</span>
              </div>
            </button>
          ))}
          )}
        </div>
      </div>

      {/* Assessment Table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Assessments</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-4">Assessment</th>
                <th className="text-left pb-2 pr-4">Framework</th>
                <th className="text-left pb-2 pr-4 w-40">Coverage</th>
                <th className="text-left pb-2 pr-4">Implemented</th>
                <th className="text-left pb-2 pr-4">Partial</th>
                <th className="text-left pb-2 pr-4">Not Impl.</th>
                <th className="text-left pb-2">Risk</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_ASSESSMENTS.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                MOCK_ASSESSMENTS.map(a => (
                <tr key={a.id} className="border-b border-gray-700/50 hover:bg-gray-700/20">
                  <td className="py-2.5 pr-4 text-white text-xs">{a.assessment_name}</td>
                  <td className="py-2.5 pr-4"><span className="text-[10px] bg-purple-500/20 text-purple-400 px-2 py-0.5 rounded">{a.framework}</span></td>
                  <td className="py-2.5 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                        <div className={cn("h-1.5 rounded-full", a.coverage_pct >= 80 ? "bg-emerald-500" : a.coverage_pct >= 60 ? "bg-yellow-500" : "bg-red-500")}
                          style={{ width: `${a.coverage_pct}%` }} />
                      </div>
                      <span className="text-xs text-gray-300 w-10 text-right">{a.coverage_pct}%</span>
                    </div>
                  </td>
                  <td className="py-2.5 pr-4 text-emerald-400 font-semibold">{a.implemented}</td>
                  <td className="py-2.5 pr-4 text-yellow-400">{a.partial}</td>
                  <td className="py-2.5 pr-4 text-red-400 font-semibold">{a.not_implemented}</td>
                  <td className="py-2.5"><RiskBadge r={a.risk_level} /></td>
                </tr>
              ))}
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Control Gaps */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Control Gaps</h2>
          <div className="space-y-2">
            {displayedGaps.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              displayedGaps.map(g => {
              const overdue = g.status === "open" && new Date(g.due_date) < today;
              return (
                <div key={g.id} className={cn("bg-gray-900 rounded-lg px-4 py-3 flex items-center gap-3", overdue && "border border-red-500/30")}>
                  <code className="text-xs text-cyan-300 font-mono w-28 flex-shrink-0">{g.control_id}</code>
                  <DomainBadge d={g.domain} />
                  <PriorityBadge p={g.priority} />
                  <StatusBadge s={g.status} />
                  <span className={cn("ml-auto text-xs", overdue ? "text-red-400 font-bold" : "text-gray-500")}>
                    {overdue ? "OVERDUE " : ""}Due {g.due_date}
                  </span>
                  <span className="text-xs text-gray-500 truncate max-w-[120px]">{g.owner}</span>
                </div>
              );
            })}
            )}
          </div>
        </div>

        {/* Remediation Plans */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Remediation Plans</h2>
          <div className="space-y-4">
            {MOCK_REMEDIATION.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              MOCK_REMEDIATION.map(r => (
              <div key={r.id} className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <code className="text-xs text-cyan-300 font-mono">{r.control_id}</code>
                  <span className="text-xs text-gray-500">{r.target}</span>
                </div>
                <p className="text-xs text-gray-300 mb-3">{r.plan}</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                    <div className="h-1.5 bg-blue-500 rounded-full" style={{ width: `${r.progress}%` }} />
                  </div>
                  <span className="text-xs text-blue-400 font-semibold w-8 text-right">{r.progress}%</span>
                </div>
                <p className="text-[10px] text-gray-500 mt-2">{r.owner}</p>
              </div>
            ))}
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
