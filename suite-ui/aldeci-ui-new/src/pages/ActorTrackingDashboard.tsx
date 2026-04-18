/**
 * Actor Tracking Dashboard
 *
 * Track threat actors: cards with threat level, attribution confidence,
 * activity feed, intelligence panel, and TTP frequency bars.
 *
 * Route: /actor-tracking
 */

import { useState, useEffect } from "react";
import { Users, Activity, Eye, AlertTriangle, CheckCircle, RefreshCw, Shield, Globe } from "lucide-react";

const API_BASE = "/api/v1/actor-tracking";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

// ── Types ─────────────────────────────────────────────────────────────────────

type ActorType = "nation-state" | "cybercriminal" | "hacktivism" | "insider" | "apt";
type ThreatLevel = "critical" | "high" | "medium" | "low";
type IntelType = "technical-ioc" | "strategic" | "operational" | "tactical";

interface TrackedActor {
  id: string;
  actor_name: string;
  alias: string[];
  actor_type: ActorType;
  nation_state: string | null;
  threat_level: ThreatLevel;
  targeting_our_sector: boolean;
  last_activity: string; // ISO date
  attribution_confidence: number; // 0-100
  ttps: string[];
  active_campaigns: number;
  intel_count: number;
}

interface ActivityEntry {
  id: string;
  actor_id: string;
  actor_name: string;
  activity_type: string;
  description: string;
  affected_sectors: string[];
  verified: boolean;
  timestamp: string;
}

interface IntelEntry {
  id: string;
  actor_id: string;
  intel_type: IntelType;
  summary: string;
  confidence: number;
  valid_until: string;
  source: string;
}

// ── Mock data ─────────────────────────────────────────────────────────────────

const MOCK_ACTORS: TrackedActor[] = [
  { id: "act-001", actor_name: "Lazarus Group",    alias: ["Hidden Cobra", "ZINC"],         actor_type: "nation-state",  nation_state: "North Korea", threat_level: "critical", targeting_our_sector: true,  last_activity: "2026-04-14", attribution_confidence: 91, ttps: ["spear-phishing", "supply-chain", "watering-hole", "ransomware", "cryptojacking"], active_campaigns: 3, intel_count: 48 },
  { id: "act-002", actor_name: "APT29",            alias: ["Cozy Bear", "Midnight Blizzard"], actor_type: "apt",         nation_state: "Russia",       threat_level: "critical", targeting_our_sector: true,  last_activity: "2026-04-12", attribution_confidence: 87, ttps: ["credential-stuffing", "oauth-abuse", "lateral-movement", "persistence"], active_campaigns: 2, intel_count: 62 },
  { id: "act-003", actor_name: "FIN7",             alias: ["Carbanak", "Navigator"],         actor_type: "cybercriminal", nation_state: null,           threat_level: "high",     targeting_our_sector: true,  last_activity: "2026-04-10", attribution_confidence: 78, ttps: ["spear-phishing", "pos-malware", "social-engineering", "cobalt-strike"], active_campaigns: 1, intel_count: 34 },
  { id: "act-004", actor_name: "Scattered Spider", alias: ["0ktapus", "Starfraud"],          actor_type: "cybercriminal", nation_state: null,           threat_level: "high",     targeting_our_sector: false, last_activity: "2026-04-05", attribution_confidence: 72, ttps: ["sim-swapping", "social-engineering", "mfa-bypass", "cloud-compromise"], active_campaigns: 1, intel_count: 21 },
  { id: "act-005", actor_name: "Volt Typhoon",     alias: ["Bronze Silhouette"],             actor_type: "nation-state",  nation_state: "China",        threat_level: "critical", targeting_our_sector: true,  last_activity: "2026-04-13", attribution_confidence: 83, ttps: ["living-off-the-land", "oci-abuse", "vpn-exploitation", "steganography"], active_campaigns: 2, intel_count: 39 },
  { id: "act-006", actor_name: "Cl0p",             alias: ["TA505"],                         actor_type: "cybercriminal", nation_state: null,           threat_level: "medium",   targeting_our_sector: false, last_activity: "2026-03-28", attribution_confidence: 65, ttps: ["zero-day-exploitation", "data-exfiltration", "extortion", "ransomware"], active_campaigns: 0, intel_count: 17 },
];

const MOCK_ACTIVITY: ActivityEntry[] = [
  { id: "aev-001", actor_id: "act-001", actor_name: "Lazarus Group",    activity_type: "Spear-phishing Campaign",  description: "Targeted finance employees with fake SWIFT transaction alerts",        affected_sectors: ["Financial", "Banking"],           verified: true,  timestamp: "2026-04-14T09:22:00Z" },
  { id: "aev-002", actor_id: "act-002", actor_name: "APT29",            activity_type: "OAuth Token Abuse",        description: "Abused OAuth tokens to access cloud email without credentials",        affected_sectors: ["Government", "Tech"],             verified: true,  timestamp: "2026-04-12T14:05:00Z" },
  { id: "aev-003", actor_id: "act-005", actor_name: "Volt Typhoon",     activity_type: "Infrastructure Recon",    description: "Living-off-the-land recon detected on critical infra networks",          affected_sectors: ["Energy", "Utilities", "Defense"], verified: true,  timestamp: "2026-04-13T22:10:00Z" },
  { id: "aev-004", actor_id: "act-003", actor_name: "FIN7",             activity_type: "Cobalt Strike Beacon",    description: "CS beacon deployed via macro-enabled Word doc targeting POS systems",   affected_sectors: ["Retail", "Hospitality"],          verified: false, timestamp: "2026-04-10T11:30:00Z" },
  { id: "aev-005", actor_id: "act-004", actor_name: "Scattered Spider", activity_type: "SIM Swap Attack",         description: "Telecom provider targeted to bypass MFA on executive accounts",          affected_sectors: ["Technology", "Telecom"],          verified: true,  timestamp: "2026-04-05T18:44:00Z" },
  { id: "aev-006", actor_id: "act-001", actor_name: "Lazarus Group",    activity_type: "Supply Chain Compromise", description: "Compromised open-source package with backdoor — 3 versions affected",   affected_sectors: ["Technology", "Financial"],        verified: true,  timestamp: "2026-04-11T06:55:00Z" },
];

const MOCK_INTEL: Record<string, IntelEntry[]> = {
  "act-001": [
    { id: "int-001", actor_id: "act-001", intel_type: "technical-ioc", summary: "C2 infrastructure using FastFlux DNS on AS15169 subnets", confidence: 88, valid_until: "2026-05-01", source: "CISA Advisory" },
    { id: "int-002", actor_id: "act-001", intel_type: "tactical",       summary: "Spear-phishing lures mimicking HR policy updates — Q2 2026", confidence: 92, valid_until: "2026-04-30", source: "Internal CTI" },
  ],
  "act-002": [
    { id: "int-003", actor_id: "act-002", intel_type: "strategic",      summary: "Targeting cloud identity providers ahead of elections",     confidence: 79, valid_until: "2026-06-01", source: "MSTIC" },
    { id: "int-004", actor_id: "act-002", intel_type: "operational",    summary: "Using residential proxies to blend into normal traffic",    confidence: 84, valid_until: "2026-05-15", source: "Mandiant" },
  ],
  "act-005": [
    { id: "int-005", actor_id: "act-005", intel_type: "tactical",       summary: "Exploiting CVE-2025-3109 in Cisco IOS XE for initial access", confidence: 91, valid_until: "2026-04-25", source: "NSA/CISA Joint Advisory" },
  ],
};

const TOP_TTPS = [
  { ttp: "spear-phishing",       count: 18 },
  { ttp: "lateral-movement",     count: 14 },
  { ttp: "ransomware",           count: 12 },
  { ttp: "credential-stuffing",  count: 11 },
  { ttp: "social-engineering",   count: 10 },
  { ttp: "supply-chain",         count: 9 },
  { ttp: "zero-day-exploitation", count: 8 },
  { ttp: "cobalt-strike",        count: 7 },
  { ttp: "data-exfiltration",    count: 7 },
  { ttp: "mfa-bypass",           count: 5 },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const days = Math.floor(diff / 86400000);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  return `${days}d ago`;
}

function threatBorderColor(t: ThreatLevel): string {
  return t === "critical" ? "border-red-500" : t === "high" ? "border-orange-400" : t === "medium" ? "border-yellow-400" : "border-gray-500";
}

function threatTextColor(t: ThreatLevel): string {
  return t === "critical" ? "text-red-400" : t === "high" ? "text-orange-400" : t === "medium" ? "text-yellow-400" : "text-gray-400";
}

function intelBadge(t: IntelType): string {
  const map: Record<IntelType, string> = {
    "technical-ioc": "bg-cyan-500/20 text-cyan-300",
    "strategic":     "bg-purple-500/20 text-purple-300",
    "operational":   "bg-blue-500/20 text-blue-300",
    "tactical":      "bg-orange-500/20 text-orange-300",
  };
  return map[t];
}

function actorTypeBadge(t: ActorType): string {
  const map: Record<ActorType, string> = {
    "nation-state":  "bg-red-500/20 text-red-300",
    "apt":           "bg-purple-500/20 text-purple-300",
    "cybercriminal": "bg-orange-500/20 text-orange-300",
    "hacktivism":    "bg-yellow-500/20 text-yellow-300",
    "insider":       "bg-pink-500/20 text-pink-300",
  };
  return map[t];
}

const MAX_TTP = TOP_TTPS[0].count;

// ── Component ─────────────────────────────────────────────────────────────────

export default function ActorTrackingDashboard() {
  const [selectedId, setSelectedId] = useState<string>("act-001");
  const [error, setError] = useState<string | null>(null);
  const [actors, setActors] = useState(MOCK_ACTORS);
  const [activity, setActivity] = useState(MOCK_ACTIVITY);


  const fetchData = () => {
    setError(null);
    fetch(`${API_BASE}/actors`, { headers: getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => { if (Array.isArray(d)) setActors(d); })
    .catch(err => setError(err.message || 'Failed to load data'));
    fetch(`${API_BASE}/activity`, { headers: getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => { if (Array.isArray(d)) setActivity(d); })
    .catch(err => setError(err.message || 'Failed to load data'));
  };

  useEffect(() => { fetchData(); }, []);

  const selected = actors.find(a => a.id === selectedId) ?? actors[0];
  const actorIntel = MOCK_INTEL[selectedId] ?? [];

  const stats = {
    total:     actors.length,
    critical:  actors.filter(a => a.threat_level === "critical").length,
    targeting: actors.filter(a => a.targeting_our_sector).length,
    campaigns: actors.reduce((s, a) => s + a.active_campaigns, 0),
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
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
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Users className="w-6 h-6 text-red-400" />
            Actor Tracking
          </h1>
          <p className="text-gray-400 text-sm mt-1">Tracked threat actors — intelligence, TTPs, and activity</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Tracked Actors",      value: stats.total,     color: "text-white" },
          { label: "Critical Threat",     value: stats.critical,  color: "text-red-400" },
          { label: "Targeting Our Sector", value: stats.targeting, color: "text-orange-400" },
          { label: "Active Campaigns",    value: stats.campaigns,  color: "text-amber-400" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
            <div className={`text-3xl font-bold ${k.color}`}>{k.value}</div>
            <div className="text-gray-400 text-xs mt-1">{k.label}</div>
          </div>
        ))}
      </div>

      {/* Actor cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {actors.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
            <p className="text-lg font-medium">No data available</p>
            <p className="text-sm">Data will appear here once available</p>
          </div>
        ) : (
          actors.map(actor => (
          <div
            key={actor.id}
            onClick={() => setSelectedId(actor.id)}
            className={`bg-gray-800 rounded-lg p-4 border-l-4 cursor-pointer transition-all hover:bg-gray-700/60 ${threatBorderColor(actor.threat_level)} ${selectedId === actor.id ? "ring-2 ring-indigo-500/50" : ""}`}
          >
            <div className="flex items-start justify-between mb-2">
              <div>
                <div className="font-semibold text-white text-sm">{actor.actor_name}</div>
                <div className="text-gray-400 text-xs mt-0.5">{actor.alias.slice(0, 2).join(" / ")}</div>
              </div>
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${actorTypeBadge(actor.actor_type)}`}>
                {actor.actor_type}
              </span>
            </div>

            {actor.nation_state && (
              <div className="flex items-center gap-1 text-xs text-gray-400 mb-2">
                <Globe className="w-3 h-3" /> {actor.nation_state}
              </div>
            )}

            {actor.targeting_our_sector && (
              <div className="flex items-center gap-1 text-xs text-amber-400 mb-2">
                <AlertTriangle className="w-3 h-3" /> Targeting our sector
              </div>
            )}

            <div className="flex items-center justify-between text-xs mt-2">
              <span className={`font-semibold uppercase ${threatTextColor(actor.threat_level)}`}>{actor.threat_level}</span>
              <span className="text-gray-400">{relativeTime(actor.last_activity)}</span>
            </div>

            {/* Attribution confidence bar */}
            <div className="mt-3">
              <div className="flex justify-between text-xs text-gray-400 mb-1">
                <span>Attribution confidence</span>
                <span>{actor.attribution_confidence}%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-1.5">
                <div
                  className={`h-1.5 rounded-full ${actor.attribution_confidence >= 80 ? "bg-green-500" : actor.attribution_confidence >= 60 ? "bg-yellow-400" : "bg-orange-500"}`}
                  style={{ width: `${actor.attribution_confidence}%` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Bottom: Activity feed + Intel panel + TTP bars */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Activity feed */}
        <div className="xl:col-span-1 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" /> Activity Feed
            </h2>
          </div>
          <div className="divide-y divide-gray-700/50">
            {MOCK_ACTIVITY.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              MOCK_ACTIVITY.map(ev => (
              <div key={ev.id} className="p-4">
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="bg-blue-500/20 text-blue-300 text-xs px-2 py-0.5 rounded-full font-medium">{ev.activity_type}</span>
                  {ev.verified
                    ? <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0 mt-0.5" />
                    : <AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />}
                </div>
                <div className="text-gray-400 text-xs font-medium mb-1">{ev.actor_name}</div>
                <p className="text-gray-300 text-xs leading-relaxed">{ev.description}</p>
                <div className="flex flex-wrap gap-1 mt-2">
                  {ev.affected_sectors.map(s => (
                    <span key={s} className="bg-gray-700 text-gray-400 text-xs px-1.5 py-0.5 rounded">{s}</span>
                  ))
                )}
                </div>
                <div className="text-gray-500 text-xs mt-1">{relativeTime(ev.timestamp)}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Intelligence panel */}
        <div className="xl:col-span-1 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Eye className="w-4 h-4 text-purple-400" /> Intel: {selected.actor_name}
            </h2>
          </div>
          <div className="p-4 space-y-4">
            {/* TTPs */}
            <div>
              <div className="text-xs text-gray-400 mb-2">Known TTPs</div>
              <div className="flex flex-wrap gap-1">
                {selected.ttps.map(t => (
                  <span key={t} className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded-full">{t}</span>
                ))}
              </div>
            </div>
            {/* Intel entries */}
            {actorIntel.length > 0 ? actorIntel.map(intel => (
              <div key={intel.id} className="border border-gray-700 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${intelBadge(intel.intel_type)}`}>{intel.intel_type}</span>
                  <span className="text-gray-400 text-xs">{intel.confidence}% confidence</span>
                </div>
                <p className="text-gray-300 text-xs leading-relaxed">{intel.summary}</p>
                <div className="flex justify-between text-xs text-gray-500 mt-2">
                  <span>{intel.source}</span>
                  <span>Valid until {intel.valid_until}</span>
                </div>
              </div>
            )) : (
              <div className="text-gray-500 text-sm text-center py-4">No intelligence for this actor yet.</div>
            )}
          </div>
        </div>

        {/* TTP frequency bars */}
        <div className="xl:col-span-1 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-orange-400" /> Top 10 TTPs
            </h2>
          </div>
          <div className="p-4 space-y-3">
            {TOP_TTPS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              TOP_TTPS.map(({ ttp, count }) => (
              <div key={ttp}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-300">{ttp}</span>
                  <span className="text-gray-400">{count}</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div
                    className="h-2 rounded-full bg-gradient-to-r from-orange-500 to-red-500"
                    style={{ width: `${(count / MAX_TTP) * 100}%` }}
                  />
                </div>
              </div>
            ))
          )}
          </div>
        </div>
      </div>
    </div>
  );
}
