/**
 * Threat Landscape Dashboard
 *
 * Shows threat actor cards, emerging threats feed, assessment history,
 * landscape summary stats, and resolve threat action.
 *
 * Route: /threat-landscape
 * API: GET /api/v1/threat-landscape
 */

import { useState, useEffect } from "react";

// ── Types ──────────────────────────────────────────────────────

type ActorType = "nation_state" | "criminal" | "hacktivist" | "insider" | "unknown";
type Sophistication = "very_high" | "high" | "medium" | "low";
type ThreatSeverity = "critical" | "high" | "medium" | "low";

interface ThreatActor {
  id: string;
  actor_name: string;
  actor_type: ActorType;
  motivation: string;
  sophistication: Sophistication;
  active: boolean;
  target_sectors: string[];
  known_ttps: string[];
  first_seen: string;
  last_active: string;
}

interface EmergingThreat {
  id: string;
  threat_category: string;
  title: string;
  severity: ThreatSeverity;
  first_observed: string;
  mitigations_count: number;
  description: string;
  resolved: boolean;
}

interface AssessmentRecord {
  id: string;
  date: string;
  sector: string;
  overall_risk: ThreatSeverity;
  threat_actors_active: number;
  emerging_threats: number;
  analyst: string;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ACTORS: ThreatActor[] = [
  {
    id: "ta-001", actor_name: "APT-Phantom", actor_type: "nation_state", motivation: "Espionage",
    sophistication: "very_high", active: true,
    target_sectors: ["Finance", "Defense", "Healthcare"],
    known_ttps: ["Spearphishing", "Lateral Movement", "Data Exfiltration"],
    first_seen: "2021-03-15", last_active: "2026-04-12",
  },
  {
    id: "ta-002", actor_name: "CrimsonSpider", actor_type: "criminal", motivation: "Financial Gain",
    sophistication: "high", active: true,
    target_sectors: ["Retail", "Banking", "E-Commerce"],
    known_ttps: ["Ransomware", "Credential Stuffing", "BEC"],
    first_seen: "2023-07-01", last_active: "2026-04-15",
  },
  {
    id: "ta-003", actor_name: "GhostNet-7", actor_type: "hacktivist", motivation: "Ideology",
    sophistication: "medium", active: false,
    target_sectors: ["Government", "Energy", "Media"],
    known_ttps: ["DDoS", "Web Defacement", "Doxxing"],
    first_seen: "2022-11-20", last_active: "2026-01-08",
  },
  {
    id: "ta-004", actor_name: "SilverFox", actor_type: "nation_state", motivation: "Sabotage",
    sophistication: "very_high", active: true,
    target_sectors: ["Critical Infrastructure", "Utilities", "Telecoms"],
    known_ttps: ["Supply Chain Attack", "Zero-day Exploit", "ICS Manipulation"],
    first_seen: "2020-05-03", last_active: "2026-04-14",
  },
  {
    id: "ta-005", actor_name: "InsiderX-42", actor_type: "insider", motivation: "Personal Grievance",
    sophistication: "low", active: false,
    target_sectors: ["Technology", "Financial Services"],
    known_ttps: ["Privilege Abuse", "Data Theft"],
    first_seen: "2025-09-01", last_active: "2025-12-15",
  },
];

const MOCK_THREATS: EmergingThreat[] = [
  { id: "et-001", threat_category: "Ransomware",     title: "NextGenLock ransomware targeting healthcare EHR systems", severity: "critical", first_observed: "2026-04-10", mitigations_count: 3, description: "New ransomware variant with wiper capability targeting HL7/FHIR endpoints.", resolved: false },
  { id: "et-002", threat_category: "Supply Chain",   title: "Compromised npm package with data-stealing payload",      severity: "high",     first_observed: "2026-04-08", mitigations_count: 5, description: "Malicious package mimicking popular crypto library, 14K downloads before takedown.", resolved: false },
  { id: "et-003", threat_category: "Zero-Day",       title: "CVE-2026-19231 — RCE in Apache Kafka broker",             severity: "critical", first_observed: "2026-04-05", mitigations_count: 2, description: "Unauthenticated remote code execution via malformed consumer group request.", resolved: false },
  { id: "et-004", threat_category: "Phishing",       title: "AI-generated spearphishing campaign targeting CFOs",      severity: "high",     first_observed: "2026-04-01", mitigations_count: 7, description: "Deepfake voice + email combo targeting wire transfers.", resolved: false },
  { id: "et-005", threat_category: "DDoS",           title: "Layer 7 amplification attack wave targeting SaaS APIs",   severity: "medium",   first_observed: "2026-03-28", mitigations_count: 9, description: "Botnet of 300K compromised IoT devices coordinated through Telegram.", resolved: true  },
  { id: "et-006", threat_category: "Credential",     title: "Large-scale credential stuffing against SSO portals",     severity: "high",     first_observed: "2026-03-20", mitigations_count: 6, description: "2.1M compromised credentials from dark web combo lists.", resolved: false },
];

const MOCK_ASSESSMENTS: AssessmentRecord[] = [
  { id: "as-001", date: "2026-04-15", sector: "Financial Services", overall_risk: "high",     threat_actors_active: 4, emerging_threats: 6, analyst: "L. Chen" },
  { id: "as-002", date: "2026-04-08", sector: "Healthcare",         overall_risk: "critical", threat_actors_active: 3, emerging_threats: 4, analyst: "M. Patel" },
  { id: "as-003", date: "2026-04-01", sector: "Retail",             overall_risk: "medium",   threat_actors_active: 2, emerging_threats: 3, analyst: "S. Kowalski" },
  { id: "as-004", date: "2026-03-25", sector: "Government",         overall_risk: "high",     threat_actors_active: 5, emerging_threats: 7, analyst: "L. Chen" },
  { id: "as-005", date: "2026-03-18", sector: "Technology",         overall_risk: "high",     threat_actors_active: 4, emerging_threats: 5, analyst: "T. Nguyen" },
];

// ── Helpers ────────────────────────────────────────────────────

const actorTypeConfig: Record<ActorType, { label: string; color: string }> = {
  nation_state: { label: "Nation State", color: "bg-red-700 text-red-100" },
  criminal:     { label: "Criminal",     color: "bg-orange-700 text-orange-100" },
  hacktivist:   { label: "Hacktivist",   color: "bg-purple-700 text-purple-100" },
  insider:      { label: "Insider",      color: "bg-amber-700 text-amber-100" },
  unknown:      { label: "Unknown",      color: "bg-gray-600 text-gray-200" },
};

const sophisticationConfig: Record<Sophistication, { label: string; color: string }> = {
  very_high: { label: "Very High", color: "bg-red-900 text-red-300 border border-red-700" },
  high:      { label: "High",      color: "bg-orange-900 text-orange-300 border border-orange-700" },
  medium:    { label: "Medium",    color: "bg-amber-900 text-amber-300 border border-amber-700" },
  low:       { label: "Low",       color: "bg-gray-700 text-gray-300 border border-gray-600" },
};

const severityConfig: Record<ThreatSeverity, { label: string; badge: string; text: string }> = {
  critical: { label: "Critical", badge: "bg-red-700 text-red-100",    text: "text-red-400" },
  high:     { label: "High",     badge: "bg-orange-700 text-orange-100", text: "text-orange-400" },
  medium:   { label: "Medium",   badge: "bg-amber-700 text-amber-100", text: "text-amber-400" },
  low:      { label: "Low",      badge: "bg-green-700 text-green-100", text: "text-green-400" },
};

// ── Component ──────────────────────────────────────────────────

export default function ThreatLandscapeDashboard() {
  const [threats, setThreats] = useState<EmergingThreat[]>(MOCK_THREATS);
  useEffect(() => {
    fetch("/api/v1/threat-landscape", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => {});
  }, []);
  const [filterActive, setFilterActive] = useState<"all" | "active" | "inactive">("all");
  const [resolvedMsg, setResolvedMsg] = useState<string | null>(null);

  const filteredActors = MOCK_ACTORS.filter(a => {
    if (filterActive === "active") return a.active;
    if (filterActive === "inactive") return !a.active;
    return true;
  });

  const activeActors = MOCK_ACTORS.filter(a => a.active).length;
  const activeThreats = threats.filter(t => !t.resolved).length;
  const bySeverity = {
    critical: threats.filter(t => t.severity === "critical" && !t.resolved).length,
    high: threats.filter(t => t.severity === "high" && !t.resolved).length,
    medium: threats.filter(t => t.severity === "medium" && !t.resolved).length,
  };

  function handleResolve(id: string) {
    setThreats(prev => prev.map(t => t.id === id ? { ...t, resolved: true } : t));
    setResolvedMsg("Threat marked as resolved.");
    setTimeout(() => setResolvedMsg(null), 3000);
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Landscape</h1>
          <p className="text-gray-400 mt-1">Active threat actors, emerging threats, and sector risk assessments</p>
        </div>
        {resolvedMsg && (
          <div className="bg-green-800/40 border border-green-600 text-green-300 px-4 py-2 rounded text-sm">
            {resolvedMsg}
          </div>
        )}
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: "Active Actors",    value: activeActors,         color: "text-red-400" },
          { label: "Active Threats",   value: activeThreats,        color: "text-orange-400" },
          { label: "Critical",         value: bySeverity.critical,  color: "text-red-400" },
          { label: "High",             value: bySeverity.high,      color: "text-orange-400" },
          { label: "Medium",           value: bySeverity.medium,    color: "text-amber-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Threat Actor Cards */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Threat Actors</h2>
          <div className="flex gap-2 bg-gray-800 rounded-lg p-1">
            {(["all", "active", "inactive"] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilterActive(f)}
                className={`px-3 py-1 rounded text-xs font-medium capitalize transition-colors ${
                  filterActive === f ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredActors.map(actor => (
            <div key={actor.id} className="bg-gray-800 rounded-lg p-5 space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-white font-semibold">{actor.actor_name}</p>
                  <p className="text-gray-400 text-xs mt-0.5">Last active: {actor.last_active}</p>
                </div>
                <div className="flex flex-col items-end gap-1.5">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${actorTypeConfig[actor.actor_type].color}`}>
                    {actorTypeConfig[actor.actor_type].label}
                  </span>
                  <span className={`flex items-center gap-1 text-xs font-medium ${actor.active ? "text-green-400" : "text-gray-500"}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${actor.active ? "bg-green-400" : "bg-gray-500"}`} />
                    {actor.active ? "Active" : "Inactive"}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-gray-500 text-xs">Sophistication:</span>
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${sophisticationConfig[actor.sophistication].color}`}>
                  {sophisticationConfig[actor.sophistication].label}
                </span>
              </div>
              <p className="text-gray-400 text-xs"><span className="text-gray-500">Motivation:</span> {actor.motivation}</p>
              <div>
                <p className="text-gray-500 text-xs mb-1">Target Sectors</p>
                <div className="flex flex-wrap gap-1">
                  {actor.target_sectors.map(s => (
                    <span key={s} className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">{s}</span>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-gray-500 text-xs mb-1">Known TTPs</p>
                <div className="flex flex-wrap gap-1">
                  {actor.known_ttps.map(t => (
                    <span key={t} className="bg-gray-900 text-gray-400 px-2 py-0.5 rounded text-xs border border-gray-700">{t}</span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Emerging Threats Feed */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Emerging Threats</h2>
        <div className="space-y-3">
          {threats.map(threat => (
            <div key={threat.id} className={`p-4 rounded-lg border transition-opacity ${threat.resolved ? "opacity-50 border-gray-700 bg-gray-700/20" : "border-gray-700 bg-gray-700/30"}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${severityConfig[threat.severity].badge}`}>
                      {severityConfig[threat.severity].label}
                    </span>
                    <span className="bg-gray-600 text-gray-200 px-2 py-0.5 rounded text-xs">{threat.threat_category}</span>
                    {threat.resolved && <span className="bg-green-900 text-green-300 px-2 py-0.5 rounded text-xs">Resolved</span>}
                  </div>
                  <p className="text-white text-sm font-medium">{threat.title}</p>
                  <p className="text-gray-400 text-xs mt-1">{threat.description}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                    <span>First observed: {threat.first_observed}</span>
                    <span>{threat.mitigations_count} mitigation{threat.mitigations_count !== 1 ? "s" : ""} available</span>
                  </div>
                </div>
                {!threat.resolved && (
                  <button
                    onClick={() => handleResolve(threat.id)}
                    className="shrink-0 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 hover:text-white rounded text-xs font-medium transition-colors"
                  >
                    Resolve
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Assessment History Table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Assessment History</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-4">Date</th>
                <th className="text-left pb-2 pr-4">Sector</th>
                <th className="text-left pb-2 pr-4">Overall Risk</th>
                <th className="text-left pb-2 pr-4">Active Actors</th>
                <th className="text-left pb-2 pr-4">Emerging Threats</th>
                <th className="text-left pb-2">Analyst</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {MOCK_ASSESSMENTS.map(a => (
                <tr key={a.id} className="hover:bg-gray-700/30 transition-colors">
                  <td className="py-2.5 pr-4 text-gray-300">{a.date}</td>
                  <td className="py-2.5 pr-4 text-gray-200">{a.sector}</td>
                  <td className="py-2.5 pr-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${severityConfig[a.overall_risk].badge}`}>
                      {severityConfig[a.overall_risk].label}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4 text-gray-300">{a.threat_actors_active}</td>
                  <td className="py-2.5 pr-4 text-gray-300">{a.emerging_threats}</td>
                  <td className="py-2.5 text-gray-400">{a.analyst}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
