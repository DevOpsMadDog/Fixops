/**
 * Security Investment Dashboard
 *
 * Portfolio summary cards, investment table, budget utilization per category,
 * ROI outcomes panel, top-5 ROI investments ranking, and budget allocation form.
 *
 * Route: /security-investment
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/security-investment";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { DollarSign, TrendingUp, CheckCircle2, Clock, Plus, Trophy } from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

type InvestStatus = "active" | "completed" | "planned" | "on_hold";
type Category = "detection" | "prevention" | "response" | "governance" | "training" | "infrastructure" | "tooling";
type OutcomeType = "cost_avoided" | "incidents_prevented" | "compliance_fine_avoided" | "productivity_gain" | "insurance_reduction";

interface Investment {
  id: string;
  investment_name: string;
  category: Category;
  vendor: string;
  amount: number;
  status: InvestStatus;
  roi_score: number; // 0-200 (>100 = positive ROI)
  start_date: string;
  end_date?: string;
}

interface BudgetLine {
  category: Category;
  allocated: number;
  spent: number;
}

interface Outcome {
  id: string;
  investment_name: string;
  outcome_type: OutcomeType;
  quantified_value: number;
  verified: boolean;
}

// ── Mock data ──────────────────────────────────────────────────

const INVESTMENTS: Investment[] = [
  { id: "inv01", investment_name: "Crowdstrike EDR Enterprise", category: "detection", vendor: "CrowdStrike", amount: 180000, status: "active", roi_score: 167, start_date: "2025-01-01" },
  { id: "inv02", investment_name: "Zscaler ZTNA Platform", category: "prevention", vendor: "Zscaler", amount: 220000, status: "active", roi_score: 143, start_date: "2025-03-01" },
  { id: "inv03", investment_name: "SOC Analyst Headcount (3 FTEs)", category: "response", vendor: "Internal", amount: 390000, status: "active", roi_score: 118, start_date: "2025-01-01" },
  { id: "inv04", investment_name: "Security Awareness Training", category: "training", vendor: "KnowBe4", amount: 45000, status: "completed", roi_score: 204, start_date: "2025-02-01", end_date: "2025-12-31" },
  { id: "inv05", investment_name: "GRC Platform (Vanta)", category: "governance", vendor: "Vanta", amount: 60000, status: "active", roi_score: 135, start_date: "2025-04-01" },
  { id: "inv06", investment_name: "WAF & DDoS Protection", category: "infrastructure", vendor: "Cloudflare", amount: 36000, status: "active", roi_score: 89, start_date: "2025-06-01" },
  { id: "inv07", investment_name: "SIEM Log Management", category: "tooling", vendor: "Elastic", amount: 95000, status: "active", roi_score: 72, start_date: "2025-08-01" },
  { id: "inv08", investment_name: "Pen Testing Annual Contract", category: "detection", vendor: "Synack", amount: 75000, status: "completed", roi_score: 155, start_date: "2025-03-01", end_date: "2025-09-30" },
];

const BUDGET: BudgetLine[] = [
  { category: "detection", allocated: 280000, spent: 255000 },
  { category: "prevention", allocated: 240000, spent: 220000 },
  { category: "response", allocated: 420000, spent: 390000 },
  { category: "governance", allocated: 80000, spent: 60000 },
  { category: "training", allocated: 50000, spent: 45000 },
  { category: "infrastructure", allocated: 30000, spent: 36000 },
  { category: "tooling", allocated: 90000, spent: 95000 },
];

const OUTCOMES: Outcome[] = [
  { id: "o01", investment_name: "Security Awareness Training", outcome_type: "incidents_prevented", quantified_value: 12, verified: true },
  { id: "o02", investment_name: "Crowdstrike EDR Enterprise", outcome_type: "cost_avoided", quantified_value: 300000, verified: true },
  { id: "o03", investment_name: "GRC Platform (Vanta)", outcome_type: "compliance_fine_avoided", quantified_value: 500000, verified: false },
  { id: "o04", investment_name: "Zscaler ZTNA Platform", outcome_type: "productivity_gain", quantified_value: 85000, verified: true },
  { id: "o05", investment_name: "Cyber Insurance Renegotiation", outcome_type: "insurance_reduction", quantified_value: 42000, verified: false },
];

// ── Helpers ────────────────────────────────────────────────────

function fmt(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n}`;
}

const CAT_COLOR: Record<Category, string> = {
  detection: "bg-blue-500/20 text-blue-300",
  prevention: "bg-purple-500/20 text-purple-300",
  response: "bg-red-500/20 text-red-300",
  governance: "bg-teal-500/20 text-teal-300",
  training: "bg-green-500/20 text-green-300",
  infrastructure: "bg-orange-500/20 text-orange-300",
  tooling: "bg-yellow-500/20 text-yellow-300",
};

const STATUS_COLOR: Record<InvestStatus, string> = {
  active: "bg-green-500/20 text-green-300",
  completed: "bg-gray-600/40 text-gray-400",
  planned: "bg-sky-500/20 text-sky-300",
  on_hold: "bg-yellow-500/20 text-yellow-300",
};

const OUTCOME_LABELS: Record<OutcomeType, string> = {
  cost_avoided: "Cost Avoided",
  incidents_prevented: "Incidents Prevented",
  compliance_fine_avoided: "Fine Avoided",
  productivity_gain: "Productivity Gain",
  insurance_reduction: "Insurance Savings",
};

const OUTCOME_COLOR: Record<OutcomeType, string> = {
  cost_avoided: "bg-green-500/20 text-green-300",
  incidents_prevented: "bg-blue-500/20 text-blue-300",
  compliance_fine_avoided: "bg-purple-500/20 text-purple-300",
  productivity_gain: "bg-teal-500/20 text-teal-300",
  insurance_reduction: "bg-yellow-500/20 text-yellow-300",
};

// ── Component ──────────────────────────────────────────────────

export default function SecurityInvestmentDashboard() {
  const [investments, setInvestments] = useState(INVESTMENTS);

  useEffect(() => {
    fetch(`${_API_BASE}/investments`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setInvestments(d); })
      .catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const [showForm, setShowForm] = useState(false);
  useEffect(() => {
    fetch(`${_API_BASE}/investments`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setInvestments(d); })
      .catch(() => { setError('Failed to load data'); });
  }, []);
  const [newAlloc, setNewAlloc] = useState({ category: "detection", amount: "" });
  const [loading, setLoading] = useState(true);

  const totalInvested = INVESTMENTS.reduce((s, i) => s + i.amount, 0);
  const avgROI = Math.round(INVESTMENTS.reduce((s, i) => s + i.roi_score, 0) / INVESTMENTS.length);
  const activeCount = INVESTMENTS.filter((i) => i.status === "active").length;
  const completedCount = INVESTMENTS.filter((i) => i.status === "completed").length;

  const top5 = [...INVESTMENTS].sort((a, b) => b.roi_score - a.roi_score).slice(0, 5);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

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
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <DollarSign className="text-emerald-400" size={28} />
          <div>
            <h1 className="text-2xl font-bold">Security Investment Dashboard</h1>
            <p className="text-gray-400 text-sm">ROI tracking, budget utilization, and investment portfolio analysis</p>
          </div>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-700 hover:bg-emerald-600 rounded-lg text-sm font-medium transition-colors"
        >
          <Plus size={16} /> Budget Allocation
        </button>
      </div>

      {/* Budget allocation form */}
      {showForm && (
        <div className="bg-gray-800 rounded-lg p-6 border border-emerald-500/30">
          <h2 className="text-base font-semibold mb-4 flex items-center gap-2"><Plus size={16} className="text-emerald-400" /> Add Budget Allocation</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <select
              className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200"
              value={newAlloc.category}
              onChange={(e) => setNewAlloc({ ...newAlloc, category: e.target.value })}
            >
              {Object.keys(CAT_COLOR).map((c) => <option key={c}>{c}</option>)}
            </select>
            <input
              className="bg-gray-700 rounded px-3 py-2 text-sm text-gray-200"
              placeholder="Amount (USD)"
              value={newAlloc.amount}
              onChange={(e) => setNewAlloc({ ...newAlloc, amount: e.target.value })}
            />
            <div className="flex gap-2">
              <button onClick={() => setShowForm(false)} className="px-4 py-2 bg-emerald-700 hover:bg-emerald-600 rounded text-sm flex-1">Save</button>
              <button onClick={() => setShowForm(false)} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <div className="text-3xl font-bold text-emerald-400">{fmt(totalInvested)}</div>
          <div className="text-gray-400 text-sm mt-1">Total Invested</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <div className="text-3xl font-bold text-teal-400">{avgROI}%</div>
          <div className="text-gray-400 text-sm mt-1">Avg ROI Score</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <div className="text-3xl font-bold text-blue-400">{activeCount}</div>
          <div className="text-gray-400 text-sm mt-1">Active Investments</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <div className="text-3xl font-bold text-gray-400">{completedCount}</div>
          <div className="text-gray-400 text-sm mt-1">Completed</div>
        </div>
      </div>

      {/* Investment table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <TrendingUp size={18} className="text-emerald-400" /> Investment Portfolio
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 border-b border-gray-700">
                <th className="text-left py-2">Investment</th>
                <th className="text-left py-2">Category</th>
                <th className="text-left py-2">Vendor</th>
                <th className="text-right py-2">Amount</th>
                <th className="text-left py-2 pl-4">Status</th>
                <th className="text-left py-2">ROI Score</th>
              </tr>
            </thead>
            <tbody>
              {INVESTMENTS.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                INVESTMENTS.map((inv) => (
                <tr key={inv.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-2 font-medium text-gray-200">{inv.investment_name}</td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${CAT_COLOR[inv.category]}`}>{inv.category}</span>
                  </td>
                  <td className="py-2 text-gray-400">{inv.vendor}</td>
                  <td className="py-2 text-right text-gray-300 font-mono">{fmt(inv.amount)}</td>
                  <td className="py-2 pl-4">
                    <span className={`px-2 py-0.5 rounded text-xs ${STATUS_COLOR[inv.status]}`}>{inv.status}</span>
                  </td>
                  <td className="py-2">
                    <div className="flex items-center gap-2 w-32">
                      <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${inv.roi_score >= 100 ? "bg-green-500" : "bg-orange-500"}`}
                          style={{ width: `${Math.min(100, inv.roi_score / 2)}%` }}
                        />
                      </div>
                      <span className={`text-xs font-bold ${inv.roi_score >= 100 ? "text-green-400" : "text-orange-400"}`}>
                        {inv.roi_score}%
                      </span>
                    </div>
                  </td>
                </tr>
              ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Budget utilization */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Budget Utilization by Category</h2>
          <div className="space-y-4">
            {BUDGET.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              BUDGET.map((b) => {
              const pct = Math.round((b.spent / b.allocated) * 100);
              const over = b.spent > b.allocated;
              return (
                <div key={b.category}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className={`font-medium ${over ? "text-red-400" : "text-gray-300"}`}>{b.category}</span>
                    <span className={over ? "text-red-400 font-medium" : "text-gray-400"}>
                      {fmt(b.spent)} / {fmt(b.allocated)} {over ? "⚠ OVER" : ""}
                    </span>
                  </div>
                  <div className="bg-gray-700 rounded-full h-3 flex overflow-hidden">
                    <div
                      className={`h-3 rounded-l-full ${over ? "bg-red-500" : "bg-emerald-500"}`}
                      style={{ width: `${Math.min(100, pct)}%` }}
                    />
                    {over && <div className="bg-red-700 h-3 rounded-r-full" style={{ width: `${pct - 100}%` }} />}
                  </div>
                  <div className="text-right text-xs text-gray-500 mt-0.5">{pct}% utilized</div>
                </div>
              );
            })
            )}
          </div>
        </div>

        <div className="space-y-4">
          {/* ROI outcomes */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <CheckCircle2 size={18} className="text-emerald-400" /> ROI Outcomes
            </h2>
            <div className="space-y-3">
              {OUTCOMES.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                OUTCOMES.map((o) => (
                <div key={o.id} className="flex items-center justify-between gap-2 text-sm border-b border-gray-700/50 pb-2 last:border-0">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`px-2 py-0.5 rounded text-xs shrink-0 ${OUTCOME_COLOR[o.outcome_type]}`}>
                      {OUTCOME_LABELS[o.outcome_type]}
                    </span>
                    <span className="text-gray-300 truncate">{o.investment_name}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-emerald-400 font-mono font-medium">
                      {o.outcome_type === "incidents_prevented" ? `${o.quantified_value} inc.` : fmt(o.quantified_value)}
                    </span>
                    {o.verified ? (
                      <span title="Verified"><CheckCircle2 size={14} className="text-green-400" /></span>
                    ) : (
                      <span title="Pending verification"><Clock size={14} className="text-gray-500" /></span>
                    )}
                  </div>
                </div>
              ))
              )}
            </div>
          </div>

          {/* Top-5 ROI */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Trophy size={18} className="text-yellow-400" /> Top-5 by ROI
            </h2>
            <div className="space-y-2">
              {top5.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                top5.map((inv, i) => (
                <div key={inv.id} className="flex items-center gap-3 text-sm">
                  <span className="text-gray-500 w-4">{i + 1}.</span>
                  <span className="flex-1 text-gray-200 truncate">{inv.investment_name}</span>
                  <span className="text-green-400 font-bold font-mono">{inv.roi_score}%</span>
                </div>
              ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
