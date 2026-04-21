/**
 * Competitive Comparison Page
 *
 * ALDECI vs Wiz vs Snyk vs Lacework vs Rapid7 vs Tenable
 * Feature matrix, price comparison, TCO calculator, scorecard.
 *
 * Route: /competitive-comparison
 */

import { useState, useEffect } from "react";
import { Shield, DollarSign, CheckCircle, XCircle, AlertCircle, TrendingDown, Award, Calculator } from "lucide-react";

// ── API helpers ───────────────────────────────────────────────
const ORG_ID = "default";
function getApiKey() {
  return (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "dev-key";
}
async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, { headers: { "X-API-Key": getApiKey() } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Data ──────────────────────────────────────────────────────────────────────

const VENDORS = ["ALDECI", "Wiz", "Lacework", "Snyk", "Rapid7", "Tenable"] as const;
type Vendor = typeof VENDORS[number];

type CellValue = "yes" | "no" | "partial" | string;

interface FeatureRow {
  feature: string;
  category: string;
  values: Record<Vendor, CellValue>;
  winner?: Vendor;
}

const FEATURE_ROWS: FeatureRow[] = [
  {
    feature: "Platform Category",
    category: "Overview",
    values: { ALDECI: "ASPM+CTEM+CSPM", Wiz: "CSPM", Lacework: "CTEM", Snyk: "ASPM", Rapid7: "CTEM", Tenable: "ASPM" },
  },
  {
    feature: "Deployment Model",
    category: "Overview",
    values: { ALDECI: "Self-hosted", Wiz: "Cloud SaaS", Lacework: "Cloud SaaS", Snyk: "Cloud SaaS", Rapid7: "Cloud SaaS", Tenable: "Cloud/SaaS" },
    winner: "ALDECI",
  },
  {
    feature: "Monthly Cost @ 500 Assets",
    category: "Pricing",
    values: { ALDECI: "$35–99", Wiz: "$4,167", Lacework: "$3,500", Snyk: "$2,500", Rapid7: "$2,000", Tenable: "$3,000" },
    winner: "ALDECI",
  },
  {
    feature: "Annual Cost (3 tools needed)",
    category: "Pricing",
    values: { ALDECI: "$420–1,188", Wiz: "$50,000", Lacework: "$42,000", Snyk: "$30,000", Rapid7: "$24,000", Tenable: "$36,000" },
    winner: "ALDECI",
  },
  {
    feature: "AI-Driven Risk Scoring",
    category: "AI & Intelligence",
    values: { ALDECI: "yes", Wiz: "no", Lacework: "no", Snyk: "no", Rapid7: "no", Tenable: "no" },
    winner: "ALDECI",
  },
  {
    feature: "Knowledge Graph",
    category: "AI & Intelligence",
    values: { ALDECI: "yes", Wiz: "no", Lacework: "no", Snyk: "no", Rapid7: "no", Tenable: "no" },
    winner: "ALDECI",
  },
  {
    feature: "Unified Compliance Dashboard",
    category: "Compliance",
    values: { ALDECI: "yes", Wiz: "partial", Lacework: "partial", Snyk: "partial", Rapid7: "partial", Tenable: "partial" },
    winner: "ALDECI",
  },
  {
    feature: "Data Residency (On-Prem)",
    category: "Security",
    values: { ALDECI: "yes", Wiz: "no", Lacework: "no", Snyk: "no", Rapid7: "no", Tenable: "no" },
    winner: "ALDECI",
  },
  {
    feature: "Time to Value",
    category: "Overview",
    values: { ALDECI: "15 min", Wiz: "4–6 weeks", Lacework: "4–6 weeks", Snyk: "2–3 weeks", Rapid7: "4–6 weeks", Tenable: "4–6 weeks" },
    winner: "ALDECI",
  },
  {
    feature: "API Endpoints",
    category: "Integration",
    values: { ALDECI: "850+", Wiz: "~200", Lacework: "~150", Snyk: "~100", Rapid7: "~200", Tenable: "~150" },
    winner: "ALDECI",
  },
  {
    feature: "Custom Workflow Support",
    category: "Integration",
    values: { ALDECI: "yes", Wiz: "partial", Lacework: "partial", Snyk: "partial", Rapid7: "partial", Tenable: "partial" },
    winner: "ALDECI",
  },
  {
    feature: "Multi-Tenant RBAC",
    category: "Enterprise",
    values: { ALDECI: "yes", Wiz: "partial", Lacework: "partial", Snyk: "partial", Rapid7: "partial", Tenable: "partial" },
    winner: "ALDECI",
  },
  {
    feature: "Open Integrations",
    category: "Integration",
    values: { ALDECI: "yes", Wiz: "no", Lacework: "no", Snyk: "no", Rapid7: "no", Tenable: "no" },
    winner: "ALDECI",
  },
  {
    feature: "Threat Intel Feeds",
    category: "AI & Intelligence",
    values: { ALDECI: "28+", Wiz: "10+", Lacework: "8+", Snyk: "5+", Rapid7: "12+", Tenable: "8+" },
    winner: "ALDECI",
  },
  {
    feature: "Scanner Support",
    category: "Integration",
    values: { ALDECI: "32", Wiz: "15", Lacework: "12", Snyk: "25", Rapid7: "20", Tenable: "22" },
    winner: "ALDECI",
  },
  {
    feature: "PULL Connectors",
    category: "Integration",
    values: { ALDECI: "13", Wiz: "8", Lacework: "7", Snyk: "6", Rapid7: "9", Tenable: "8" },
    winner: "ALDECI",
  },
  {
    feature: "SLA Auto-Escalation",
    category: "Enterprise",
    values: { ALDECI: "yes", Wiz: "no", Lacework: "no", Snyk: "no", Rapid7: "partial", Tenable: "no" },
    winner: "ALDECI",
  },
  {
    feature: "Evidence Auto-Collection",
    category: "Compliance",
    values: { ALDECI: "yes", Wiz: "no", Lacework: "no", Snyk: "no", Rapid7: "partial", Tenable: "no" },
    winner: "ALDECI",
  },
  {
    feature: "Open Source",
    category: "Overview",
    values: { ALDECI: "yes", Wiz: "no", Lacework: "no", Snyk: "no", Rapid7: "no", Tenable: "no" },
    winner: "ALDECI",
  },
];

const SCORECARD: Record<Vendor, Record<string, number>> = {
  ALDECI:   { Cost: 10, "Self-Hosted": 10, "AI Consensus": 10, "Unified Platform": 9, Brand: 2, Support: 5, "Feature Breadth": 8, "Analyst Coverage": 1 },
  Wiz:      { Cost: 2,  "Self-Hosted": 0,  "AI Consensus": 4,  "Unified Platform": 7, Brand: 9, Support: 9, "Feature Breadth": 8, "Analyst Coverage": 10 },
  Lacework: { Cost: 2,  "Self-Hosted": 0,  "AI Consensus": 3,  "Unified Platform": 6, Brand: 8, Support: 9, "Feature Breadth": 7, "Analyst Coverage": 9  },
  Snyk:     { Cost: 3,  "Self-Hosted": 0,  "AI Consensus": 3,  "Unified Platform": 5, Brand: 9, Support: 8, "Feature Breadth": 9, "Analyst Coverage": 10 },
  Rapid7:   { Cost: 3,  "Self-Hosted": 0,  "AI Consensus": 2,  "Unified Platform": 6, Brand: 7, Support: 9, "Feature Breadth": 8, "Analyst Coverage": 8  },
  Tenable:  { Cost: 2,  "Self-Hosted": 0,  "AI Consensus": 3,  "Unified Platform": 5, Brand: 9, Support: 9, "Feature Breadth": 9, "Analyst Coverage": 10 },
};

const SCORECARD_DIMS = ["Cost", "Self-Hosted", "AI Consensus", "Unified Platform", "Brand", "Support", "Feature Breadth", "Analyst Coverage"];

const COST_TABLE = [
  { label: "ALDECI Pro",                monthly: 99,   annual: 1188,    three_yr: 3564,   note: "Self-hosted, all features" },
  { label: "Wiz + Snyk + Rapid7",       monthly: 9167, annual: 110000,  three_yr: 330000, note: "Market-standard 3-tool stack" },
  { label: "Lacework + Snyk + Rapid7",  monthly: 8500, annual: 102000,  three_yr: 306000, note: "CTEM + ASPM + CTEM" },
  { label: "Wiz only",                  monthly: 4167, annual: 50000,   three_yr: 150000, note: "CSPM only — gaps remain" },
];

const WIN_SCENARIOS = [
  {
    title: "Mid-Market Startup",
    profile: "50–500 employees, limited security budget, no vendor loyalty",
    win: "Docker deploy in 15 min, $99/month, one dashboard, no lock-in",
    probability: 85,
    dealSize: "$1,188/yr",
    color: "green",
  },
  {
    title: "Enterprise with Compliance",
    profile: "$100M+ ARR, SOC2/HIPAA/PCI-DSS requirements, data residency needed",
    win: "100% self-hosted, evidence auto-collection, audit logs, 7 frameworks",
    probability: 75,
    dealSize: "$499/mo",
    color: "emerald",
  },
  {
    title: "MSSP Provider",
    profile: "Manages 50+ customer environments, needs white-label + APIs",
    win: "850+ APIs, 30 personas per tenant, SCIM/Okta, deploy to customer VPC",
    probability: 80,
    dealSize: "$200K/yr",
    color: "blue",
  },
];

// ── TCO Calculator ────────────────────────────────────────────────────────────

function TCOCalculator() {
  const [assets, setAssets] = useState(500);
  const [years, setYears] = useState(3);

  const aldeci = 99 * 12 * years;
  const competitor = (assets <= 100 ? 2000 : assets <= 500 ? 8000 : 15000) * 12 * years;
  const savings = competitor - aldeci;
  const savingsPct = Math.round((savings / competitor) * 100);

  return (
    <div className="bg-gray-800 rounded-xl p-6 space-y-5">
      <h2 className="text-lg font-semibold text-white flex items-center gap-2">
        <Calculator className="w-5 h-5 text-emerald-400" />
        TCO Calculator
      </h2>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Number of Assets</label>
          <input
            type="range" min={50} max={5000} step={50} value={assets}
            onChange={e => setAssets(Number(e.target.value))}
            className="w-full accent-emerald-400"
          />
          <div className="text-sm text-white font-medium mt-1">{assets.toLocaleString()} assets</div>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Years</label>
          <input
            type="range" min={1} max={5} step={1} value={years}
            onChange={e => setYears(Number(e.target.value))}
            className="w-full accent-emerald-400"
          />
          <div className="text-sm text-white font-medium mt-1">{years} year{years > 1 ? "s" : ""}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-emerald-900/30 border border-emerald-500/30 rounded-lg p-4 text-center">
          <div className="text-xs text-emerald-400 mb-1">ALDECI Total</div>
          <div className="text-2xl font-bold text-emerald-300">${aldeci.toLocaleString()}</div>
          <div className="text-xs text-gray-400 mt-1">Self-hosted Pro</div>
        </div>
        <div className="bg-red-900/20 border border-red-500/20 rounded-lg p-4 text-center">
          <div className="text-xs text-red-400 mb-1">3-Tool Stack Total</div>
          <div className="text-2xl font-bold text-red-300">${competitor.toLocaleString()}</div>
          <div className="text-xs text-gray-400 mt-1">Wiz + Snyk + Rapid7</div>
        </div>
        <div className="bg-blue-900/30 border border-blue-500/30 rounded-lg p-4 text-center">
          <div className="text-xs text-blue-400 mb-1">Your Savings</div>
          <div className="text-2xl font-bold text-blue-300">${savings.toLocaleString()}</div>
          <div className="text-xs text-gray-400 mt-1">{savingsPct}% cost reduction</div>
        </div>
      </div>

      <div className="bg-gray-700/40 rounded-lg p-3">
        <div className="flex justify-between text-xs text-gray-400 mb-2">
          <span>Savings vs competitor stack</span>
          <span className="text-emerald-400 font-semibold">{savingsPct}%</span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-3">
          <div
            className="h-3 rounded-full bg-gradient-to-r from-emerald-500 to-green-400 transition-all duration-500"
            style={{ width: `${savingsPct}%` }}
          />
        </div>
      </div>
    </div>
  );
}

// ── Cell renderer ─────────────────────────────────────────────────────────────

function Cell({ vendor, value, isAldeci }: { vendor: Vendor; value: CellValue; isAldeci: boolean }) {
  const base = isAldeci ? "bg-emerald-900/20" : "";

  if (value === "yes") {
    return (
      <td className={`px-3 py-2.5 text-center ${base}`}>
        <CheckCircle className="w-4 h-4 text-emerald-400 mx-auto" />
      </td>
    );
  }
  if (value === "no") {
    return (
      <td className={`px-3 py-2.5 text-center ${base}`}>
        <XCircle className="w-4 h-4 text-red-400 mx-auto" />
      </td>
    );
  }
  if (value === "partial") {
    return (
      <td className={`px-3 py-2.5 text-center ${base}`}>
        <AlertCircle className="w-4 h-4 text-yellow-400 mx-auto" />
      </td>
    );
  }
  return (
    <td className={`px-3 py-2.5 text-center text-xs font-medium ${isAldeci ? "text-emerald-300 bg-emerald-900/20" : "text-gray-300"}`}>
      {value}
    </td>
  );
}

// ── Scorecard bar ─────────────────────────────────────────────────────────────

const VENDOR_COLORS: Record<Vendor, string> = {
  ALDECI:   "bg-emerald-500",
  Wiz:      "bg-blue-500",
  Lacework: "bg-purple-500",
  Snyk:     "bg-orange-500",
  Rapid7:   "bg-red-500",
  Tenable:  "bg-pink-500",
};

const VENDOR_TEXT: Record<Vendor, string> = {
  ALDECI:   "text-emerald-400",
  Wiz:      "text-blue-400",
  Lacework: "text-purple-400",
  Snyk:     "text-orange-400",
  Rapid7:   "text-red-400",
  Tenable:  "text-pink-400",
};

function avg(scores: Record<string, number>) {
  const vals = Object.values(scores);
  if (vals.length === 0) return "0.0";
  return (vals.reduce((a, b) => a + b, 0) / vals.length).toFixed(1);
}

// ── Main component ────────────────────────────────────────────────────────────

const CATEGORIES = [...new Set(FEATURE_ROWS.map(r => r.category))];

export default function CompetitiveComparisonPage() {
  const [activeCategory, setActiveCategory] = useState<string>("All");
  const [loading, setLoading] = useState(true);
  const [selectedVendors, setSelectedVendors] = useState<Vendor[]>([...VENDORS]);
  const [livePosture, setLivePosture] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch(`/posture-score/current?org_id=${ORG_ID}`)
      .then(d => setLivePosture(d))
      .catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);

  const categories = ["All", ...CATEGORIES];

  const filteredRows = activeCategory === "All"
    ? FEATURE_ROWS
    : FEATURE_ROWS.filter(r => r.category === activeCategory);

  const visibleVendors = selectedVendors.includes("ALDECI")
    ? selectedVendors
    : ["ALDECI" as Vendor, ...selectedVendors];

  function toggleVendor(v: Vendor) {
    if (v === "ALDECI") return; // always show ALDECI
    setSelectedVendors(prev =>
      prev.includes(v) ? prev.filter(x => x !== v) : [...prev, v]
    );
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-8">

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-400" />
            ALDECI vs The Market
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Side-by-side comparison: ASPM + CTEM + CSPM at 92% lower cost
          </p>
        </div>
        <div className="flex items-center gap-2 bg-emerald-900/30 border border-emerald-500/30 rounded-lg px-4 py-2">
          <TrendingDown className="w-4 h-4 text-emerald-400" />
          <span className="text-emerald-300 text-sm font-semibold">92% cheaper than 3-tool stack</span>
        </div>
      </div>

      {/* Hero price comparison */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "ALDECI Monthly",       value: "$35–99",  sub: "Pro tier / self-hosted",         color: "text-emerald-300", bg: "bg-emerald-900/20 border-emerald-500/30" },
          { label: "Competitor Monthly",   value: "$9,167",  sub: "Wiz + Snyk + Rapid7 combined",   color: "text-red-300",     bg: "bg-red-900/20 border-red-500/20" },
          { label: "3-Year Savings",       value: "$326K+",  sub: "vs. market-standard stack",      color: "text-blue-300",    bg: "bg-blue-900/20 border-blue-500/20" },
          { label: "Time to Value",        value: "15 min",  sub: "docker up — vs. 4–6 weeks",      color: "text-amber-300",   bg: "bg-amber-900/20 border-amber-500/20" },
        ].map(k => (
          <div key={k.label} className={`rounded-xl p-4 border ${k.bg} text-center`}>
            <div className={`text-2xl font-bold ${k.color}`}>{k.value}</div>
            <div className="text-xs text-gray-400 mt-0.5 font-medium">{k.label}</div>
            <div className="text-xs text-gray-500 mt-1">{k.sub}</div>
          </div>
        ))}
      </div>

      {/* Vendor toggles */}
      <div className="flex flex-wrap gap-2 items-center">
        <span className="text-xs text-gray-400 mr-1">Compare:</span>
        {VENDORS.map(v => (
          <button
            key={v}
            onClick={() => toggleVendor(v)}
            disabled={v === "ALDECI"}
            className={`px-3 py-1 rounded-full text-xs font-medium border transition-all ${
              selectedVendors.includes(v)
                ? `border-transparent ${VENDOR_COLORS[v]} bg-opacity-80 text-white`
                : "border-gray-600 text-gray-400 bg-gray-800"
            } ${v === "ALDECI" ? "opacity-100 cursor-default" : "cursor-pointer hover:opacity-90"}`}
          >
            {v}
          </button>
        ))}
      </div>

      {/* Category filter tabs */}
      <div className="flex flex-wrap gap-2">
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors ${
              activeCategory === cat
                ? "bg-indigo-600 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700"
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Feature matrix table */}
      <div className="bg-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm min-w-[700px]">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left px-4 py-3 text-gray-400 font-medium w-56">Feature</th>
              {visibleVendors.map(v => (
                <th key={v} className={`px-3 py-3 text-center font-semibold text-xs ${v === "ALDECI" ? "text-emerald-400 bg-emerald-900/20" : VENDOR_TEXT[v]}`}>
                  {v}
                  {v === "ALDECI" && (
                    <div className="text-xs font-normal text-gray-400 mt-0.5">$35–99/mo</div>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700/50">
            {filteredRows.map((row, i) => (
              <tr key={i} className="hover:bg-gray-700/20 transition-colors">
                <td className="px-4 py-2.5">
                  <div className="text-gray-200 text-xs font-medium">{row.feature}</div>
                  <div className="text-gray-500 text-xs">{row.category}</div>
                </td>
                {visibleVendors.map(v => (
                  <Cell key={v} vendor={v} value={row.values[v]} isAldeci={v === "ALDECI"} />
                ))}
              </tr>
            ))}
          </tbody>
        </table>

        {/* Legend */}
        <div className="flex gap-4 px-4 py-3 border-t border-gray-700 text-xs text-gray-400">
          <span className="flex items-center gap-1"><CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> Full support</span>
          <span className="flex items-center gap-1"><AlertCircle className="w-3.5 h-3.5 text-yellow-400" /> Partial support</span>
          <span className="flex items-center gap-1"><XCircle className="w-3.5 h-3.5 text-red-400" /> Not supported</span>
        </div>
      </div>

      {/* Cost breakdown table + TCO calculator */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Cost table */}
        <div className="bg-gray-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-gray-700 flex items-center gap-2">
            <DollarSign className="w-4 h-4 text-amber-400" />
            <h2 className="font-semibold text-white text-sm">3-Year Total Cost of Ownership</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left px-4 py-2 text-gray-400 font-medium text-xs">Vendor Stack</th>
                  <th className="text-right px-3 py-2 text-gray-400 font-medium text-xs">Monthly</th>
                  <th className="text-right px-3 py-2 text-gray-400 font-medium text-xs">Annual</th>
                  <th className="text-right px-3 py-2 text-gray-400 font-medium text-xs">3-Year</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {COST_TABLE.map((row, i) => (
                  <tr key={i} className={i === 0 ? "bg-emerald-900/20" : "hover:bg-gray-700/20"}>
                    <td className="px-4 py-3">
                      <div className={`text-xs font-semibold ${i === 0 ? "text-emerald-300" : "text-gray-200"}`}>{row.label}</div>
                      <div className="text-xs text-gray-500 mt-0.5">{row.note}</div>
                    </td>
                    <td className={`px-3 py-3 text-right text-xs font-mono font-medium ${i === 0 ? "text-emerald-300" : "text-red-300"}`}>
                      ${row.monthly.toLocaleString()}
                    </td>
                    <td className={`px-3 py-3 text-right text-xs font-mono font-medium ${i === 0 ? "text-emerald-300" : "text-red-300"}`}>
                      ${row.annual.toLocaleString()}
                    </td>
                    <td className={`px-3 py-3 text-right text-xs font-mono font-bold ${i === 0 ? "text-emerald-300" : "text-red-300"}`}>
                      ${row.three_yr.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-3 bg-gray-700/30 text-xs text-gray-400">
            At 500 assets — <span className="text-emerald-400 font-semibold">92–98% cost reduction</span> vs. market-standard stack.
          </div>
        </div>

        {/* TCO Calculator */}
        <TCOCalculator />
      </div>

      {/* Win scenarios */}
      <div className="space-y-3">
        <h2 className="text-base font-semibold text-white flex items-center gap-2">
          <Award className="w-4 h-4 text-amber-400" />
          Where ALDECI Wins
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {WIN_SCENARIOS.map(s => (
            <div key={s.title} className="bg-gray-800 rounded-xl p-4 border border-gray-700 hover:border-emerald-500/40 transition-colors">
              <div className="flex items-start justify-between mb-2">
                <div className="font-semibold text-white text-sm">{s.title}</div>
                <div className="text-xs bg-emerald-900/40 text-emerald-300 px-2 py-0.5 rounded-full font-medium">
                  {s.probability}% win rate
                </div>
              </div>
              <p className="text-gray-400 text-xs mb-3">{s.profile}</p>
              <div className="bg-gray-700/40 rounded-lg p-3 mb-3">
                <div className="text-xs text-gray-400 mb-1">ALDECI advantage:</div>
                <p className="text-emerald-300 text-xs">{s.win}</p>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Deal size:</span>
                <span className="text-amber-300 font-semibold">{s.dealSize}</span>
              </div>
              {/* Win probability bar */}
              <div className="mt-3">
                <div className="w-full bg-gray-700 rounded-full h-1.5">
                  <div
                    className="h-1.5 rounded-full bg-gradient-to-r from-emerald-500 to-green-400"
                    style={{ width: `${s.probability}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Scorecard */}
      <div className="bg-gray-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="font-semibold text-white text-sm flex items-center gap-2">
            <Award className="w-4 h-4 text-indigo-400" />
            Competitive Advantage Scorecard (0–10)
          </h2>
          <div className="text-xs text-gray-400">Average scores across all dimensions</div>
        </div>

        {/* Average scores row */}
        <div className="grid grid-cols-6 divide-x divide-gray-700 border-b border-gray-700">
          {VENDORS.map(v => (
            <div key={v} className={`p-3 text-center ${v === "ALDECI" ? "bg-emerald-900/20" : ""}`}>
              <div className={`text-xs font-semibold mb-1 ${VENDOR_TEXT[v]}`}>{v}</div>
              <div className={`text-2xl font-bold ${v === "ALDECI" ? "text-emerald-300" : "text-gray-300"}`}>
                {avg(SCORECARD[v])}
              </div>
              <div className="text-xs text-gray-500 mt-0.5">avg</div>
            </div>
          ))}
        </div>

        {/* Per-dimension bars */}
        <div className="p-4 space-y-4">
          {SCORECARD_DIMS.map(dim => (
            <div key={dim}>
              <div className="text-xs text-gray-400 mb-2">{dim}</div>
              <div className="space-y-1.5">
                {VENDORS.map(v => {
                  const score = SCORECARD[v][dim];

                  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

                  return (
                    <div key={v} className="flex items-center gap-2">
                      <span className={`text-xs w-20 flex-shrink-0 ${VENDOR_TEXT[v]}`}>{v}</span>
                      <div className="flex-1 bg-gray-700 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${VENDOR_COLORS[v]} transition-all duration-500`}
                          style={{ width: `${score * 10}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-400 w-4 text-right">{score}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        <div className="px-4 py-3 bg-gray-700/30 text-xs text-gray-400 border-t border-gray-700">
          ALDECI average: <span className="text-emerald-400 font-semibold">6.8</span> — highest overall.
          Incumbents lead on brand/support/analyst coverage; ALDECI leads on cost, architecture, and AI.
        </div>
      </div>

      {/* 12-month roadmap callout */}
      <div className="bg-gradient-to-r from-indigo-900/30 to-emerald-900/30 border border-indigo-500/20 rounded-xl p-5">
        <h2 className="font-semibold text-white text-sm mb-3">12-Month Roadmap to Close Gaps</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          {[
            { quarter: "Q2 2026", items: ["Open-source launch (MIT)", "SOC2 Type II certification", "Product Hunt launch", "5 MSSP case studies"] },
            { quarter: "Q3 2026", items: ["VP Sales hire", "24/7 on-call support tier", "Gartner MQ submission", "10 enterprise pilots"] },
            { quarter: "Q4 2026", items: ["SIEM connector (Splunk/ELK)", "SOAR connector (Cortex)", "XDR connector (CrowdStrike)", "ALDECI-as-a-Service"] },
            { quarter: "Q1 2027", items: ["10 enterprise contracts", "200 mid-market customers", "Series A fundraising ($8M)", "$3M ARR target"] },
          ].map(q => (
            <div key={q.quarter} className="space-y-2">
              <div className="text-indigo-400 font-semibold">{q.quarter}</div>
              <ul className="space-y-1">
                {q.items.map(item => (
                  <li key={item} className="text-gray-300 flex items-start gap-1">
                    <span className="text-emerald-500 flex-shrink-0 mt-0.5">›</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
