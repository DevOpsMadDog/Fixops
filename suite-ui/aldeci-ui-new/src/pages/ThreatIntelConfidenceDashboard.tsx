/**
 * Threat Intel Confidence Dashboard
 *
 * IOC table with confidence score bars, source reliability ranking,
 * high-confidence IOCs panel, search bar, summary cards by type donut,
 * expire stale button.
 *
 * Route: /ti-confidence
 */

import { useState, useEffect, type ReactNode } from "react";
import { Eye, Search, Zap, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// ── Mock data ──────────────────────────────────────────────────────────────────

const MOCK_IOCS = [
  { id: "ioc-001", ioc_value: "185.220.101.47",               ioc_type: "ip",     confidence_score: 0.94, threat_level: "critical", source_count: 5, corroboration_count: 8, expires_at: "2026-05-01", status: "active"  },
  { id: "ioc-002", ioc_value: "malware-cdn.attacker.ru",       ioc_type: "domain", confidence_score: 0.87, threat_level: "high",     source_count: 4, corroboration_count: 6, expires_at: "2026-04-28", status: "active"  },
  { id: "ioc-003", ioc_value: "https://evil.xyz/payload.exe",  ioc_type: "url",    confidence_score: 0.82, threat_level: "high",     source_count: 3, corroboration_count: 5, expires_at: "2026-04-25", status: "active"  },
  { id: "ioc-004", ioc_value: "a3f1c2d9e0b4567890abcdef123456", ioc_type: "hash",   confidence_score: 0.76, threat_level: "high",     source_count: 3, corroboration_count: 4, expires_at: "2026-05-10", status: "active"  },
  { id: "ioc-005", ioc_value: "phish@secure-bank-verify.com",  ioc_type: "email",  confidence_score: 0.63, threat_level: "medium",   source_count: 2, corroboration_count: 2, expires_at: "2026-04-20", status: "active"  },
  { id: "ioc-006", ioc_value: "192.168.44.200",                ioc_type: "ip",     confidence_score: 0.41, threat_level: "medium",   source_count: 1, corroboration_count: 1, expires_at: "2026-04-18", status: "active"  },
  { id: "ioc-007", ioc_value: "suspicious-update.net",         ioc_type: "domain", confidence_score: 0.28, threat_level: "low",      source_count: 1, corroboration_count: 0, expires_at: "2026-04-17", status: "active"  },
  { id: "ioc-008", ioc_value: "bad-actor-2023@proton.me",      ioc_type: "email",  confidence_score: 0.91, threat_level: "critical", source_count: 4, corroboration_count: 7, expires_at: "2026-05-05", status: "active"  },
  { id: "ioc-009", ioc_value: "c0ffeebabe1234567890deadbeef00", ioc_type: "hash",   confidence_score: 0.55, threat_level: "medium",   source_count: 2, corroboration_count: 2, expires_at: "2026-04-15", status: "expired" },
  { id: "ioc-010", ioc_value: "203.0.113.42",                  ioc_type: "ip",     confidence_score: 0.18, threat_level: "low",      source_count: 1, corroboration_count: 0, expires_at: "2026-04-10", status: "false_positive" },
];

const MOCK_SOURCES = [
  { source_name: "AlienVault OTX",    reliability_score: 0.91, total_iocs: 1842, confirmed: 1621, false_positives: 38 },
  { source_name: "VirusTotal",        reliability_score: 0.88, total_iocs: 3204, confirmed: 2814, false_positives: 71 },
  { source_name: "Shodan",            reliability_score: 0.79, total_iocs: 924,  confirmed: 758,  false_positives: 44 },
  { source_name: "AbuseIPDB",         reliability_score: 0.85, total_iocs: 2157, confirmed: 1894, false_positives: 55 },
  { source_name: "MISP Community",    reliability_score: 0.72, total_iocs: 601,  confirmed: 463,  false_positives: 89 },
  { source_name: "Internal Sensors",  reliability_score: 0.96, total_iocs: 441,  confirmed: 428,  false_positives: 7  },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

function confidenceColor(score: number): string {
  if (score >= 0.8) return "#ef4444";
  if (score >= 0.6) return "#f97316";
  if (score >= 0.4) return "#eab308";
  return "#6b7280";
}

function ConfidenceBar({ score }: { score: number }) {
  const color = confidenceColor(score);
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 bg-gray-700 rounded-full h-2">
        <div className="h-2 rounded-full transition-all" style={{ width: `${score * 100}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-mono w-10 text-right" style={{ color }}>{(score * 100).toFixed(0)}%</span>
    </div>
  );
}

function ThreatBadge({ t }: { t: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    low:      "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[t] ?? "bg-gray-700 text-gray-300")}>{t}</span>;
}

function TypeBadge({ t }: { t: string }) {
  const cls: Record<string, string> = {
    ip:     "bg-blue-500/20 text-blue-300",
    domain: "bg-purple-500/20 text-purple-300",
    url:    "bg-teal-500/20 text-teal-300",
    hash:   "bg-yellow-500/20 text-yellow-300",
    email:  "bg-pink-500/20 text-pink-300",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[t] ?? "bg-gray-700 text-gray-300")}>{t}</span>;
}

function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    active:         "bg-green-500/20 text-green-400",
    expired:        "bg-gray-700 text-gray-400",
    false_positive: "bg-red-500/20 text-red-400",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s.replace("_", " ")}</span>;
}

function truncate(s: string, n = 32) {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

// ── Donut chart (SVG) ─────────────────────────────────────────────────────────

function TypeDonut({ iocs }: { iocs: typeof MOCK_IOCS }) {
  const types = ["ip", "domain", "url", "hash", "email"];
  const colors = ["#3b82f6","#a855f7","#14b8a6","#eab308","#ec4899"];
  const counts = types.map(t => iocs.filter(i => i.ioc_type === t && i.status === "active").length);
  const total = counts.reduce((a, b) => a + b, 0) || 1;
  const r = 40, cx = 60, cy = 60, gap = 2;
  let angle = -Math.PI / 2;
  const slices: ReactNode[] = [];
  counts.forEach((count, i) => {
    const sweep = (count / total) * (2 * Math.PI);
    const x1 = cx + r * Math.cos(angle);
    const y1 = cy + r * Math.sin(angle);
    const x2 = cx + r * Math.cos(angle + sweep - gap / r);
    const y2 = cy + r * Math.sin(angle + sweep - gap / r);
    const large = sweep > Math.PI ? 1 : 0;
    if (count > 0) {
      slices.push(
        <path key={i} d={`M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`}
          fill={colors[i]} opacity="0.8" />
      );
    }
    angle += sweep;
  });

  return (
    <div className="flex items-center gap-4">
      <svg viewBox="0 0 120 120" className="w-28 h-28">
        <circle cx={cx} cy={cy} r={r} fill="#1e293b" />
        {slices}
        <circle cx={cx} cy={cy} r={r * 0.55} fill="#1f2937" />
        <text x={cx} y={cy + 4} textAnchor="middle" fill="white" fontSize="11" fontWeight="bold">{total}</text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="#94a3b8" fontSize="7">active</text>
      </svg>
      <div className="space-y-1">
        {types.map((t, i) => (
          <div key={t} className="flex items-center gap-2 text-xs">
            <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: colors[i] }} />
            <span className="text-gray-300 capitalize">{t}</span>
            <span className="text-gray-500 ml-auto pl-2">{counts[i]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function ThreatIntelConfidenceDashboard() {
  const [iocs, setIocs] = useState(MOCK_IOCS);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [expiring, setExpiring] = useState(false);

  useEffect(() => {
    apiFetch(`/api/v1/ti-confidence/iocs?org_id=${ORG_ID}`).then((d) => {
      if (Array.isArray(d?.iocs)) setIocs(d.iocs);
      else if (Array.isArray(d)) setIocs(d);
    }).catch(() => { setError('Failed to load data'); });
  }, []);

  const filtered = search
    ? iocs.filter(i => i.ioc_value.toLowerCase().includes(search.toLowerCase()) || i.ioc_type.includes(search.toLowerCase()))
    : iocs;

  const highConf = iocs.filter(i => i.confidence_score >= 0.7 && i.status === "active");
  const activeCount = iocs.filter(i => i.status === "active").length;
  const expiredCount = iocs.filter(i => i.status === "expired").length;
  const fpCount = iocs.filter(i => i.status === "false_positive").length;

  function expireStale() {
    setExpiring(true);
    setTimeout(() => {
      setIocs(prev => prev.map(i => {
        const exp = new Date(i.expires_at) < new Date("2026-04-16");
        return exp && i.status === "active" ? { ...i, status: "expired" } : i;
      }));
      setExpiring(false);
    }, 1000);
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-500/10 rounded-lg">
            <Eye className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Threat Intel Confidence</h1>
            <p className="text-sm text-gray-400">IOC confidence scoring, source reliability, and expiry management</p>
          </div>
        </div>
        <button
          onClick={expireStale}
          disabled={expiring}
          className="flex items-center gap-2 px-4 py-2 bg-red-600/80 hover:bg-red-600 rounded-lg text-sm font-medium transition-all disabled:opacity-60"
        >
          <XCircle className="w-4 h-4" />
          {expiring ? "Expiring..." : "Expire Stale IOCs"}
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total IOCs",   value: iocs.length,  color: "text-white",      icon: <Eye className="w-5 h-5 text-gray-400" /> },
          { label: "Active",       value: activeCount,   color: "text-green-400",  icon: <CheckCircle className="w-5 h-5 text-green-400" /> },
          { label: "Expired",      value: expiredCount,  color: "text-gray-400",   icon: <XCircle className="w-5 h-5 text-gray-500" /> },
          { label: "False Positives",value: fpCount,     color: "text-red-400",    icon: <AlertTriangle className="w-5 h-5 text-red-400" /> },
        ].map(c => (
          <div key={c.label} className="bg-gray-800 rounded-lg p-4 flex items-center gap-3">
            {c.icon}
            <div>
              <p className="text-xs text-gray-400">{c.label}</p>
              <p className={cn("text-2xl font-bold", c.color)}>{c.value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Type donut + search */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">IOC Types</h2>
          <TypeDonut iocs={iocs} />
        </div>

        {/* High-confidence panel */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-5 h-5 text-yellow-400" />
            <h2 className="text-lg font-semibold text-white">High-Confidence IOCs (≥70%)</h2>
          </div>
          <div className="space-y-2">
            {highConf.map(i => (
              <div key={i.id} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
                <div className="flex items-center gap-2">
                  <TypeBadge t={i.ioc_type} />
                  <span className="text-sm font-mono text-gray-200">{truncate(i.ioc_value, 38)}</span>
                </div>
                <div className="flex items-center gap-3">
                  <ThreatBadge t={i.threat_level} />
                  <ConfidenceBar score={i.confidence_score} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* IOC table with search */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">All IOCs</h2>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search IOC value or type…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-9 pr-4 py-1.5 bg-gray-700 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-400 focus:outline-none focus:border-purple-500 w-64"
            />
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                {["IOC Value", "Type", "Confidence", "Threat Level", "Sources", "Corroborations", "Expires", "Status"].map(h => (
                  <th key={h} className="text-left text-gray-400 font-medium py-2 pr-4 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(i => (
                <tr key={i.id} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4 font-mono text-xs text-gray-200">{truncate(i.ioc_value, 30)}</td>
                  <td className="py-2.5 pr-4"><TypeBadge t={i.ioc_type} /></td>
                  <td className="py-2.5 pr-4"><ConfidenceBar score={i.confidence_score} /></td>
                  <td className="py-2.5 pr-4"><ThreatBadge t={i.threat_level} /></td>
                  <td className="py-2.5 pr-4 text-center text-gray-300">{i.source_count}</td>
                  <td className="py-2.5 pr-4 text-center text-gray-300">{i.corroboration_count}</td>
                  <td className="py-2.5 pr-4 text-xs text-gray-400">{i.expires_at}</td>
                  <td className="py-2.5"><StatusBadge s={i.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <p className="text-center text-gray-500 py-8">No IOCs matching "{search}"</p>
          )}
        </div>
      </div>

      {/* Source reliability */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Source Reliability Ranking</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Source</th>
                <th className="text-left text-gray-400 font-medium py-2 pr-4 w-48">Reliability</th>
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Total IOCs</th>
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Confirmed</th>
                <th className="text-left text-gray-400 font-medium py-2">False Positives</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_SOURCES.sort((a, b) => b.reliability_score - a.reliability_score).map(s => (
                <tr key={s.source_name} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4 font-medium text-white">{s.source_name}</td>
                  <td className="py-2.5 pr-4">
                    <ConfidenceBar score={s.reliability_score} />
                  </td>
                  <td className="py-2.5 pr-4 text-gray-300">{s.total_iocs.toLocaleString()}</td>
                  <td className="py-2.5 pr-4 text-green-400">{s.confirmed.toLocaleString()}</td>
                  <td className="py-2.5 text-red-400">{s.false_positives}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
