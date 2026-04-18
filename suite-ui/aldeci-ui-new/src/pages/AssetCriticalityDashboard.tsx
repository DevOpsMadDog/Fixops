/**
 * Asset Criticality Dashboard
 *
 * Tier distribution donut, assets table with criticality bars, criticality
 * factors panel for selected asset, critical path visualizer (BFS chain),
 * and top-10 most critical assets ranking.
 *
 * Route: /asset-criticality
 */

import { useState, useEffect } from "react";
import { Server, AlertTriangle, GitBranch, Trophy } from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

type Tier = "tier-1-critical" | "tier-2-high" | "tier-3-medium" | "tier-4-low";

interface Asset {
  id: string;
  asset_name: string;
  asset_type: "server" | "database" | "api" | "network" | "endpoint" | "cloud" | "iot";
  criticality_score: number;
  tier: Tier;
  business_owner: string;
  environment: "production" | "staging" | "dev";
  depends_on?: string; // id
  factors: Factor[];
}

interface Factor {
  factor_name: string;
  weight: number;
  value: number; // out of 10
}

// ── Mock data ──────────────────────────────────────────────────

const ASSETS: Asset[] = [
  {
    id: "a01", asset_name: "prod-db-primary", asset_type: "database",
    criticality_score: 98, tier: "tier-1-critical",
    business_owner: "Platform Team", environment: "production",
    depends_on: undefined,
    factors: [
      { factor_name: "Data Sensitivity", weight: 30, value: 10 },
      { factor_name: "Revenue Impact", weight: 25, value: 10 },
      { factor_name: "Regulatory Scope", weight: 20, value: 9 },
      { factor_name: "Single Point of Failure", weight: 15, value: 10 },
      { factor_name: "Exposure Level", weight: 10, value: 8 },
    ],
  },
  {
    id: "a02", asset_name: "auth-service-api", asset_type: "api",
    criticality_score: 95, tier: "tier-1-critical",
    business_owner: "Security Team", environment: "production",
    depends_on: "a01",
    factors: [
      { factor_name: "Data Sensitivity", weight: 30, value: 9 },
      { factor_name: "Revenue Impact", weight: 25, value: 10 },
      { factor_name: "Regulatory Scope", weight: 20, value: 10 },
      { factor_name: "Single Point of Failure", weight: 15, value: 9 },
      { factor_name: "Exposure Level", weight: 10, value: 9 },
    ],
  },
  {
    id: "a03", asset_name: "payment-gateway", asset_type: "api",
    criticality_score: 91, tier: "tier-1-critical",
    business_owner: "Finance Team", environment: "production",
    depends_on: "a02",
    factors: [
      { factor_name: "Data Sensitivity", weight: 30, value: 10 },
      { factor_name: "Revenue Impact", weight: 25, value: 10 },
      { factor_name: "Regulatory Scope", weight: 20, value: 10 },
      { factor_name: "Single Point of Failure", weight: 15, value: 7 },
      { factor_name: "Exposure Level", weight: 10, value: 8 },
    ],
  },
  {
    id: "a04", asset_name: "k8s-control-plane", asset_type: "server",
    criticality_score: 87, tier: "tier-2-high",
    business_owner: "DevOps", environment: "production",
    depends_on: "a01",
    factors: [
      { factor_name: "Data Sensitivity", weight: 30, value: 7 },
      { factor_name: "Revenue Impact", weight: 25, value: 9 },
      { factor_name: "Regulatory Scope", weight: 20, value: 6 },
      { factor_name: "Single Point of Failure", weight: 15, value: 10 },
      { factor_name: "Exposure Level", weight: 10, value: 6 },
    ],
  },
  {
    id: "a05", asset_name: "vpn-gateway-01", asset_type: "network",
    criticality_score: 82, tier: "tier-2-high",
    business_owner: "Network Team", environment: "production",
    depends_on: "a04",
    factors: [
      { factor_name: "Data Sensitivity", weight: 30, value: 6 },
      { factor_name: "Revenue Impact", weight: 25, value: 8 },
      { factor_name: "Regulatory Scope", weight: 20, value: 7 },
      { factor_name: "Single Point of Failure", weight: 15, value: 9 },
      { factor_name: "Exposure Level", weight: 10, value: 9 },
    ],
  },
  {
    id: "a06", asset_name: "analytics-db", asset_type: "database",
    criticality_score: 65, tier: "tier-3-medium",
    business_owner: "Analytics Team", environment: "production",
    depends_on: "a05",
    factors: [
      { factor_name: "Data Sensitivity", weight: 30, value: 6 },
      { factor_name: "Revenue Impact", weight: 25, value: 5 },
      { factor_name: "Regulatory Scope", weight: 20, value: 5 },
      { factor_name: "Single Point of Failure", weight: 15, value: 6 },
      { factor_name: "Exposure Level", weight: 10, value: 5 },
    ],
  },
  {
    id: "a07", asset_name: "dev-build-server", asset_type: "server",
    criticality_score: 38, tier: "tier-4-low",
    business_owner: "Engineering", environment: "dev",
    depends_on: undefined,
    factors: [
      { factor_name: "Data Sensitivity", weight: 30, value: 2 },
      { factor_name: "Revenue Impact", weight: 25, value: 3 },
      { factor_name: "Regulatory Scope", weight: 20, value: 1 },
      { factor_name: "Single Point of Failure", weight: 15, value: 4 },
      { factor_name: "Exposure Level", weight: 10, value: 3 },
    ],
  },
];

// ── Helpers ────────────────────────────────────────────────────

const TIER_CONFIG: Record<Tier, { label: string; color: string; ring: string; text: string; bar: string }> = {
  "tier-1-critical": { label: "Tier 1 Critical", color: "#ef4444", ring: "ring-red-500", text: "text-red-400", bar: "bg-red-500" },
  "tier-2-high": { label: "Tier 2 High", color: "#f97316", ring: "ring-orange-500", text: "text-orange-400", bar: "bg-orange-500" },
  "tier-3-medium": { label: "Tier 3 Medium", color: "#eab308", ring: "ring-yellow-500", text: "text-yellow-400", bar: "bg-yellow-500" },
  "tier-4-low": { label: "Tier 4 Low", color: "#6b7280", ring: "ring-gray-500", text: "text-gray-400", bar: "bg-gray-500" },
};

const ENV_COLOR: Record<string, string> = {
  production: "bg-red-500/20 text-red-300",
  staging: "bg-yellow-500/20 text-yellow-300",
  dev: "bg-gray-600/40 text-gray-400",
};

const TYPE_COLOR: Record<string, string> = {
  server: "bg-blue-500/20 text-blue-300",
  database: "bg-purple-500/20 text-purple-300",
  api: "bg-teal-500/20 text-teal-300",
  network: "bg-cyan-500/20 text-cyan-300",
  endpoint: "bg-pink-500/20 text-pink-300",
  cloud: "bg-sky-500/20 text-sky-300",
  iot: "bg-orange-500/20 text-orange-300",
};

// ── Donut ──────────────────────────────────────────────────────

const TIERS: Tier[] = ["tier-1-critical", "tier-2-high", "tier-3-medium", "tier-4-low"];

function TierDonut({ assets }: { assets: Asset[] }) {
  const counts = TIERS.map((t) => assets.filter((a) => a.tier === t).length);
  const total = counts.reduce((s, c) => s + c, 0);
  if (total === 0) return null;

  const r = 55, cx = 80, cy = 80;
  const circ = 2 * Math.PI * r;
  let offset = 0;
  const segments = counts.map((c, i) => {
    const pct = c / total;
    const len = pct * circ;
    const seg = { offset, len, color: TIER_CONFIG[TIERS[i]].color, count: c, pct };
    offset += len;
    return seg;
  });

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 160 160" className="w-40 h-40">
        {segments.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Data will appear here once available</p>
          </div>
        ) : (
          segments.map((seg, i) => (
          <circle
            key={i}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={seg.color}
            strokeWidth="22"
            strokeDasharray={`${seg.len} ${circ - seg.len}`}
            strokeDashoffset={-seg.offset + circ / 4}
            strokeLinecap="butt"
          />
        ))}
        <text x={cx} y={cy + 6} textAnchor="middle" fontSize="22" fontWeight="bold" fill="white">{total}</text>
        <text x={cx} y={cy + 18} textAnchor="middle" fontSize="8" fill="#94a3b8">assets</text>
      </svg>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 mt-2 text-xs">
        {TIERS.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Data will appear here once available</p>
          </div>
        ) : (
          TIERS.map((t, i) => (
          <div key={t} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: TIER_CONFIG[t].color }} />
            <span className="text-gray-300">{TIER_CONFIG[t].label.replace("Tier ", "T")}</span>
            <span className="text-gray-500">({counts[i]})</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Critical Path ──────────────────────────────────────────────

function CriticalPath({ assets, rootId }: { assets: Asset[]; rootId: string }) {
  const assetMap = Object.fromEntries(assets.map((a) => [a.id, a]));
  const chain: Asset[] = [];
  let current: Asset | undefined = assetMap[rootId];
  while (current && chain.length < 4) {
    chain.push(current);
    current = current.depends_on ? assetMap[current.depends_on] : undefined;
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {chain.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
          <p className="text-lg font-medium">No data available</p>
          <p className="text-sm">Data will appear here once available</p>
        </div>
      ) : (
        chain.map((a, i) => (
        <div key={a.id} className="flex items-center gap-2">
          <div className={`px-3 py-1.5 rounded-lg border text-xs font-medium ${TIER_CONFIG[a.tier].text} border-current/30`}
            style={{ borderColor: TIER_CONFIG[a.tier].color + "40", background: TIER_CONFIG[a.tier].color + "15" }}>
            {a.asset_name}
          </div>
          {i < chain.length - 1 && <span className="text-gray-500">→</span>}
        </div>
      ))}
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function AssetCriticalityDashboard() {
  const [selectedId, setSelectedId] = useState<string>(ASSETS[0].id);
  const [loading, setLoading] = useState(true);
  const sorted = [...ASSETS].sort((a, b) => b.criticality_score - a.criticality_score);
  const selected = ASSETS.find((a) => a.id === selectedId)!;
  const top10 = sorted.slice(0, 10);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Server className="text-orange-400" size={28} />
        <div>
          <h1 className="text-2xl font-bold">Asset Criticality Dashboard</h1>
          <p className="text-gray-400 text-sm">Tier-based criticality scoring, dependency chains, and business impact analysis</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Donut */}
        <div className="bg-gray-800 rounded-lg p-6 flex flex-col items-center justify-center">
          <h2 className="text-sm font-semibold mb-3 text-gray-300">Tier Distribution</h2>
          <TierDonut assets={ASSETS} />
        </div>

        {/* Assets table */}
        <div className="lg:col-span-3 bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Asset Inventory</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-400 border-b border-gray-700">
                  <th className="text-left py-2">Asset</th>
                  <th className="text-left py-2">Type</th>
                  <th className="text-left py-2 w-32">Score</th>
                  <th className="text-left py-2">Tier</th>
                  <th className="text-left py-2">Owner</th>
                  <th className="text-left py-2">Env</th>
                </tr>
              </thead>
              <tbody>
                {sorted.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  sorted.map((a) => {
                  const tc = TIER_CONFIG[a.tier];
                  return (
                    <tr
                      key={a.id}
                      onClick={() => setSelectedId(a.id)}
                      className={`border-b border-gray-700/50 cursor-pointer transition-colors ${
                        selectedId === a.id ? "bg-gray-700/60" : "hover:bg-gray-700/30"
                      }`}
                    >
                      <td className="py-2 font-medium text-gray-200">{a.asset_name}</td>
                      <td className="py-2">
                        <span className={`px-2 py-0.5 rounded text-xs ${TYPE_COLOR[a.asset_type]}`}>{a.asset_type}</span>
                      </td>
                      <td className="py-2">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                            <div className={`h-1.5 rounded-full ${tc.bar}`} style={{ width: `${a.criticality_score}%` }} />
                          </div>
                          <span className={`text-xs font-bold ${tc.text}`}>{a.criticality_score}</span>
                        </div>
                      </td>
                      <td className="py-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${tc.text}`}
                          style={{ background: TIER_CONFIG[a.tier].color + "20" }}>
                          {tc.label}
                        </span>
                      </td>
                      <td className="py-2 text-gray-400">{a.business_owner}</td>
                      <td className="py-2">
                        <span className={`px-2 py-0.5 rounded text-xs ${ENV_COLOR[a.environment]}`}>{a.environment}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Criticality factors for selected asset */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-1 flex items-center gap-2">
            <AlertTriangle size={18} className="text-orange-400" /> Criticality Factors
          </h2>
          <p className="text-gray-400 text-xs mb-4">Selected: <span className="text-orange-300 font-medium">{selected.asset_name}</span></p>
          <div className="space-y-3">
            {selected.factors.map((f) => {
              const contribution = (f.weight / 100) * f.value * 10;
              return (
                <div key={f.factor_name}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-300">{f.factor_name}</span>
                    <span className="text-gray-400">wt {f.weight}% · val {f.value}/10 · contrib {contribution.toFixed(0)}</span>
                  </div>
                  <div className="flex gap-2">
                    <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                      <div className="bg-orange-500 h-1.5 rounded-full" style={{ width: `${f.weight}%` }} />
                    </div>
                    <div className="flex-1 bg-gray-700 rounded-full h-1.5">
                      <div className="bg-sky-500 h-1.5 rounded-full" style={{ width: `${f.value * 10}%` }} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="mt-4 text-xs text-gray-500">Click a row in the table to inspect a different asset.</div>
        </div>

        {/* Critical path + top-10 */}
        <div className="space-y-4">
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <GitBranch size={18} className="text-orange-400" /> Critical Path
            </h2>
            <p className="text-xs text-gray-400 mb-3">Dependency chain (max 3 hops) from selected asset:</p>
            <CriticalPath assets={ASSETS} rootId={selectedId} />
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Trophy size={18} className="text-orange-400" /> Top-10 Most Critical
            </h2>
            <div className="space-y-2">
              {top10.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                top10.map((a, i) => {
                const tc = TIER_CONFIG[a.tier];
                return (
                  <div key={a.id} className="flex items-center gap-3 text-sm">
                    <span className="text-gray-500 w-5 text-right">{i + 1}.</span>
                    <span className="flex-1 text-gray-200 truncate">{a.asset_name}</span>
                    <span className={`text-xs font-bold ${tc.text}`}>{a.criticality_score}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
