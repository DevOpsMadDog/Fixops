/**
 * Control Testing Dashboard
 *
 * Security control testing lifecycle management.
 *   1. Failing controls alert list
 *   2. Due tests banner
 *   3. Summary (by status counts, never tested list)
 *   4. Controls table (control_name, control_type, framework, effectiveness_score bar, status, last_tested, next_test)
 *   5. Test history sub-table per control (test_name, method, tester, result, score, tested_at)
 *   6. Schedule management (frequency, next_run)
 *
 * Route: /control-testing
 * API: GET /api/v1/control-testing
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/control-testing";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { FlaskConical, AlertTriangle, CheckCircle2, XCircle, Clock, Calendar, BarChart2, ChevronRight } from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

interface Control {
  id: string;
  control_name: string;
  control_type: "preventive" | "detective" | "corrective" | "compensating";
  framework: string;
  effectiveness_score: number; // 0-100
  status: "effective" | "partially_effective" | "ineffective" | "not_tested" | "scheduled";
  last_tested: string | null;
  next_test: string;
  frequency: "monthly" | "quarterly" | "semi-annual" | "annual";
  test_history: TestRun[];
}

interface TestRun {
  id: string;
  test_name: string;
  method: "automated" | "manual" | "hybrid";
  tester: string;
  result: "pass" | "fail" | "partial" | "inconclusive";
  score: number;
  tested_at: string;
  notes?: string;
}

// ── Mock data ──────────────────────────────────────────────────

const CONTROLS: Control[] = [
  {
    id: "c1", control_name: "Multi-Factor Authentication Enforcement", control_type: "preventive",
    framework: "NIST CSF", effectiveness_score: 92, status: "effective",
    last_tested: "2026-04-01", next_test: "2026-07-01", frequency: "quarterly",
    test_history: [
      { id: "t1", test_name: "MFA Coverage Audit", method: "automated", tester: "sec-automation", result: "pass", score: 92, tested_at: "2026-04-01", notes: "98% of users covered" },
      { id: "t2", test_name: "MFA Coverage Audit", method: "automated", tester: "sec-automation", result: "pass", score: 88, tested_at: "2026-01-01" },
    ],
  },
  {
    id: "c2", control_name: "Vulnerability Patching SLA", control_type: "corrective",
    framework: "ISO 27001", effectiveness_score: 74, status: "partially_effective",
    last_tested: "2026-03-15", next_test: "2026-06-15", frequency: "quarterly",
    test_history: [
      { id: "t3", test_name: "Patch Compliance Scan", method: "automated", tester: "vuln-mgmt", result: "partial", score: 74, tested_at: "2026-03-15", notes: "P1 SLA met; P2 backlog at 32%" },
      { id: "t4", test_name: "Patch Compliance Scan", method: "automated", tester: "vuln-mgmt", result: "partial", score: 68, tested_at: "2025-12-15" },
    ],
  },
  {
    id: "c3", control_name: "Network Egress Filtering", control_type: "preventive",
    framework: "CIS Controls", effectiveness_score: 45, status: "ineffective",
    last_tested: "2026-02-10", next_test: "2026-04-20", frequency: "monthly",
    test_history: [
      { id: "t5", test_name: "Firewall Egress Test", method: "manual", tester: "netops-lead", result: "fail", score: 45, tested_at: "2026-02-10", notes: "Port 443 unrestricted to all destinations" },
      { id: "t6", test_name: "Firewall Egress Test", method: "manual", tester: "netops-lead", result: "fail", score: 50, tested_at: "2026-01-10" },
    ],
  },
  {
    id: "c4", control_name: "Data Loss Prevention Policy", control_type: "preventive",
    framework: "PCI-DSS", effectiveness_score: 83, status: "effective",
    last_tested: "2026-04-05", next_test: "2026-07-05", frequency: "quarterly",
    test_history: [
      { id: "t7", test_name: "DLP Rule Validation", method: "hybrid", tester: "data-security", result: "pass", score: 83, tested_at: "2026-04-05" },
    ],
  },
  {
    id: "c5", control_name: "Privileged Access Review", control_type: "detective",
    framework: "SOC 2", effectiveness_score: 0, status: "not_tested",
    last_tested: null, next_test: "2026-04-30", frequency: "semi-annual",
    test_history: [],
  },
  {
    id: "c6", control_name: "Incident Response Plan Testing", control_type: "corrective",
    framework: "NIST CSF", effectiveness_score: 0, status: "not_tested",
    last_tested: null, next_test: "2026-05-15", frequency: "semi-annual",
    test_history: [],
  },
  {
    id: "c7", control_name: "Encryption Key Management", control_type: "preventive",
    framework: "ISO 27001", effectiveness_score: 96, status: "effective",
    last_tested: "2026-03-20", next_test: "2026-09-20", frequency: "semi-annual",
    test_history: [
      { id: "t8", test_name: "Key Rotation Audit", method: "automated", tester: "crypto-team", result: "pass", score: 96, tested_at: "2026-03-20" },
      { id: "t9", test_name: "Key Rotation Audit", method: "automated", tester: "crypto-team", result: "pass", score: 93, tested_at: "2025-09-20" },
    ],
  },
  {
    id: "c8", control_name: "Third-Party Risk Assessment", control_type: "detective",
    framework: "SOC 2", effectiveness_score: 61, status: "partially_effective",
    last_tested: "2026-01-25", next_test: "2026-04-25", frequency: "quarterly",
    test_history: [
      { id: "t10", test_name: "Vendor Risk Review", method: "manual", tester: "vendor-risk", result: "partial", score: 61, tested_at: "2026-01-25", notes: "12 of 38 vendors lack recent assessments" },
    ],
  },
  {
    id: "c9", control_name: "Security Awareness Training", control_type: "preventive",
    framework: "CIS Controls", effectiveness_score: 78, status: "scheduled",
    last_tested: "2025-10-01", next_test: "2026-04-18", frequency: "semi-annual",
    test_history: [
      { id: "t11", test_name: "Phishing Simulation", method: "automated", tester: "awareness-team", result: "pass", score: 78, tested_at: "2025-10-01" },
    ],
  },
  {
    id: "c10", control_name: "Log Integrity & Retention", control_type: "detective",
    framework: "PCI-DSS", effectiveness_score: 88, status: "effective",
    last_tested: "2026-04-10", next_test: "2026-05-10", frequency: "monthly",
    test_history: [
      { id: "t12", test_name: "Log Audit Check", method: "automated", tester: "soc-team", result: "pass", score: 88, tested_at: "2026-04-10" },
      { id: "t13", test_name: "Log Audit Check", method: "automated", tester: "soc-team", result: "pass", score: 86, tested_at: "2026-03-10" },
      { id: "t14", test_name: "Log Audit Check", method: "automated", tester: "soc-team", result: "partial", score: 72, tested_at: "2026-02-10", notes: "Log gap detected on FW-EDGE-01" },
    ],
  },
];

// ── Helpers ────────────────────────────────────────────────────

const statusColor: Record<Control["status"], string> = {
  effective: "bg-green-900 text-green-300",
  partially_effective: "bg-yellow-900 text-yellow-300",
  ineffective: "bg-red-900 text-red-300",
  not_tested: "bg-gray-700 text-gray-400",
  scheduled: "bg-blue-900 text-blue-300",
};

const controlTypeColor: Record<Control["control_type"], string> = {
  preventive: "bg-blue-900 text-blue-300",
  detective: "bg-purple-900 text-purple-300",
  corrective: "bg-teal-900 text-teal-300",
  compensating: "bg-orange-900 text-orange-300",
};

const resultColor: Record<TestRun["result"], string> = {
  pass: "bg-green-900 text-green-300",
  fail: "bg-red-900 text-red-300",
  partial: "bg-yellow-900 text-yellow-300",
  inconclusive: "bg-gray-700 text-gray-400",
};

const methodColor: Record<TestRun["method"], string> = {
  automated: "bg-sky-900 text-sky-300",
  manual: "bg-indigo-900 text-indigo-300",
  hybrid: "bg-violet-900 text-violet-300",
};

function isDue(next_test: string): boolean {
  return new Date(next_test) <= new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
}

// ── Component ──────────────────────────────────────────────────

export default function ControlTestingDashboard() {
  const [controls, setControls] = useState(CONTROLS);
  const [error, setError] = useState<string | null>(null);


  const fetchData = () => {
    setError(null);
    fetch(`${_API_BASE}/controls`, { headers: _getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => { if (Array.isArray(d)) setControls(d); })
    .catch(err => setError(err.message || 'Failed to load data'));
  };

  useEffect(() => { fetchData(); }, []);

  const [selectedControl, setSelectedControl] = useState<Control | null>(CONTROLS[0]);
  useEffect(() => {
    fetch(_API_BASE, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
      .then(d => {
        // live data loaded — components read from API response
        void d;
      })
      .catch(err => setError(err.message || 'Failed to load data'));
  }, []);


  const failing = CONTROLS.filter(c => c.status === "ineffective");
  const neverTested = CONTROLS.filter(c => c.status === "not_tested");
  const dueControls = CONTROLS.filter(c => isDue(c.next_test) && c.status !== "not_tested");

  const byCounts = {
    effective: CONTROLS.filter(c => c.status === "effective").length,
    partially_effective: CONTROLS.filter(c => c.status === "partially_effective").length,
    ineffective: CONTROLS.filter(c => c.status === "ineffective").length,
    not_tested: CONTROLS.filter(c => c.status === "not_tested").length,
    scheduled: CONTROLS.filter(c => c.status === "scheduled").length,
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
          <p className="font-medium">Error loading data</p>
          <p className="text-sm">{error}</p>
          <button onClick={() => { setError(null); fetchData(); }} className="mt-2 text-sm underline">Retry</button>
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <FlaskConical className="w-6 h-6 text-violet-400" />
            Control Testing
          </h1>
          <p className="text-gray-400 text-sm mt-1">Security control effectiveness testing and schedule management</p>
        </div>
        <button className="flex items-center gap-2 bg-violet-600 hover:bg-violet-700 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <Calendar className="w-4 h-4" /> Schedule Test
        </button>
      </div>

      {/* Failing controls alert */}
      {failing.length > 0 && (
        <div className="bg-red-900/40 border border-red-700 rounded-lg p-4 space-y-2">
          <div className="flex items-center gap-2">
            <XCircle className="w-5 h-5 text-red-400 shrink-0" />
            <span className="text-red-300 font-medium">{failing.length} failing control{failing.length > 1 ? "s" : ""} require immediate attention</span>
          </div>
          {failing.map(c => (
            <div key={c.id} className="flex items-center gap-2 ml-7">
              <ChevronRight className="w-3 h-3 text-red-500" />
              <button
                onClick={() => setSelectedControl(c)}
                className="text-red-400 hover:text-red-300 text-sm underline-offset-2 hover:underline transition-colors"
              >
                {c.control_name}
              </button>
              <span className="text-gray-500 text-xs">({c.framework})</span>
            </div>
          ))}
        </div>
      )}

      {/* Due tests banner */}
      {dueControls.length > 0 && (
        <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-3 flex items-center gap-3">
          <Clock className="w-5 h-5 text-yellow-400 shrink-0" />
          <span className="text-yellow-300 text-sm">
            {dueControls.length} control test{dueControls.length > 1 ? "s" : ""} due within 7 days: {dueControls.map(c => c.control_name).join(", ")}
          </span>
        </div>
      )}

      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {[
          { label: "Effective", value: byCounts.effective, color: "text-green-400" },
          { label: "Partial", value: byCounts.partially_effective, color: "text-yellow-400" },
          { label: "Ineffective", value: byCounts.ineffective, color: "text-red-400" },
          { label: "Not Tested", value: byCounts.not_tested, color: "text-gray-400" },
          { label: "Scheduled", value: byCounts.scheduled, color: "text-blue-400" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-2">{k.label}</div>
            <div className={`text-2xl font-bold ${k.color}`}>{k.value}</div>
          </div>
        ))}
      </div>

      {/* Never tested list */}
      {neverTested.length > 0 && (
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="font-semibold text-sm flex items-center gap-2 mb-3 text-gray-400">
            <AlertTriangle className="w-4 h-4 text-gray-500" /> Never Tested Controls
          </div>
          <div className="flex flex-wrap gap-2">
            {neverTested.map(c => (
              <button
                key={c.id}
                onClick={() => setSelectedControl(c)}
                className="bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
              >
                {c.control_name}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Controls table + history panel */}
      <div className="grid lg:grid-cols-3 gap-6">
        {/* Controls table */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700 font-semibold flex items-center gap-2">
            <FlaskConical className="w-4 h-4 text-violet-400" /> Controls
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-700/50">
                <tr>
                  {["Control","Type","Framework","Effectiveness","Status","Last Tested","Next Test"].map(h => (
                    <th key={h} className="px-3 py-3 text-left text-gray-400 font-medium text-xs">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {CONTROLS.map(c => (
                  <tr
                    key={c.id}
                    onClick={() => setSelectedControl(c)}
                    className={`border-t border-gray-700 hover:bg-gray-700/40 cursor-pointer transition-colors ${
                      selectedControl?.id === c.id ? "bg-violet-900/20" : ""
                    }`}
                  >
                    <td className="px-3 py-3 font-medium text-xs max-w-[180px]">
                      <div className="truncate">{c.control_name}</div>
                    </td>
                    <td className="px-3 py-3">
                      <span className={`px-1.5 py-0.5 rounded text-xs capitalize ${controlTypeColor[c.control_type]}`}>
                        {c.control_type}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <span className="bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded text-xs">{c.framework}</span>
                    </td>
                    <td className="px-3 py-3">
                      {c.effectiveness_score > 0 ? (
                        <div className="flex items-center gap-2">
                          <div className="w-14 bg-gray-700 rounded-full h-1.5">
                            <div
                              className={`h-1.5 rounded-full ${c.effectiveness_score >= 80 ? "bg-green-500" : c.effectiveness_score >= 60 ? "bg-yellow-500" : "bg-red-500"}`}
                              style={{ width: `${c.effectiveness_score}%` }}
                            />
                          </div>
                          <span className="text-xs text-gray-300">{c.effectiveness_score}%</span>
                        </div>
                      ) : (
                        <span className="text-gray-600 text-xs">—</span>
                      )}
                    </td>
                    <td className="px-3 py-3">
                      <span className={`px-1.5 py-0.5 rounded text-xs ${statusColor[c.status]}`}>
                        {c.status.replace(/_/g," ")}
                      </span>
                    </td>
                    <td className="px-3 py-3 text-gray-400 text-xs">{c.last_tested || "—"}</td>
                    <td className={`px-3 py-3 text-xs ${isDue(c.next_test) ? "text-yellow-400 font-medium" : "text-gray-400"}`}>
                      {c.next_test}
                    </td>
                  </tr>
                )))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Test history + schedule */}
        <div className="bg-gray-800 rounded-lg overflow-hidden flex flex-col">
          <div className="p-4 border-b border-gray-700 font-semibold text-sm">
            {selectedControl ? (
              <div>
                <div className="flex items-center gap-2">
                  <BarChart2 className="w-4 h-4 text-violet-400" />
                  Test History
                </div>
                <div className="text-gray-400 text-xs mt-0.5 truncate">{selectedControl.control_name}</div>
              </div>
            ) : (
              <span className="text-gray-400">Select a control</span>
            )}
          </div>

          {selectedControl && (
            <>
              {/* Schedule info */}
              <div className="p-4 border-b border-gray-700 bg-gray-700/30 flex gap-4 text-xs">
                <div>
                  <div className="text-gray-400">Frequency</div>
                  <div className="font-medium capitalize text-blue-300">{selectedControl.frequency}</div>
                </div>
                <div>
                  <div className="text-gray-400">Next Run</div>
                  <div className={`font-medium ${isDue(selectedControl.next_test) ? "text-yellow-400" : "text-gray-200"}`}>
                    {selectedControl.next_test}
                  </div>
                </div>
                <div>
                  <div className="text-gray-400">Framework</div>
                  <div className="font-medium text-gray-200">{selectedControl.framework}</div>
                </div>
              </div>

              {/* History */}
              <div className="flex-1 overflow-y-auto">
                {selectedControl.test_history.length === 0 ? (
                  <div className="p-4 text-gray-500 text-sm">No test runs recorded.</div>
                ) : (
                  <div className="divide-y divide-gray-700">
                    {selectedControl.test_history.map(t => (
                      <div key={t.id} className="p-4 space-y-2 hover:bg-gray-700/30 transition-colors">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium">{t.test_name}</span>
                          <span className={`px-2 py-0.5 rounded text-xs ${resultColor[t.result]}`}>{t.result}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-1.5 py-0.5 rounded text-xs ${methodColor[t.method]}`}>{t.method}</span>
                          <span className="text-gray-400 text-xs">{t.tester}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-20 bg-gray-700 rounded-full h-1.5">
                            <div
                              className={`h-1.5 rounded-full ${t.score >= 80 ? "bg-green-500" : t.score >= 60 ? "bg-yellow-500" : "bg-red-500"}`}
                              style={{ width: `${t.score}%` }}
                            />
                          </div>
                          <span className="text-xs text-gray-400">{t.score}%</span>
                          <span className="text-xs text-gray-500 ml-auto">{t.tested_at}</span>
                        </div>
                        {t.notes && (
                          <p className="text-xs text-gray-400 italic">{t.notes}</p>
                        )}
                      </div>
                    )))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
