/**
 * Incident Knowledge Base Dashboard
 *
 * Shows article search, article cards, runbook list with success rate,
 * search analytics, and KB stats.
 *
 * Route: /incident-kb
 * API: GET /api/v1/incident-kb
 */

import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// == Types ======================================================

type ArticleType = "playbook" | "reference" | "post_mortem" | "how_to" | "policy" | "faq";
type IncidentType = "ransomware" | "data_breach" | "ddos" | "phishing" | "insider_threat" | "supply_chain" | "zero_day" | "account_takeover";
type ArticleSeverity = "critical" | "high" | "medium" | "low" | "info";

interface KBArticle {
  id: string;
  title: string;
  article_type: ArticleType;
  incident_type: IncidentType;
  severity: ArticleSeverity;
  view_count: number;
  helpful_count: number;
  author: string;
  updated_at: string;
  content_preview: string;
  tags: string[];
}

interface Runbook {
  id: string;
  runbook_name: string;
  incident_type: IncidentType;
  estimated_minutes: number;
  success_rate: number;
  execution_count: number;
  last_executed: string;
  steps_count: number;
}

// == Mock data ==================================================

const MOCK_ARTICLES: KBArticle[] = [
  {
    id: "art-001", title: "Ransomware Response = Containment & Recovery",
    article_type: "playbook", incident_type: "ransomware", severity: "critical",
    view_count: 842, helpful_count: 134, author: "IR Team", updated_at: "2026-04-01",
    content_preview: "Step-by-step guide for ransomware containment: isolate affected hosts, preserve forensic evidence, initiate backup restoration, notify stakeholders.",
    tags: ["ransomware", "containment", "recovery", "backup"],
  },
  {
    id: "art-002", title: "Data Breach Notification Requirements = GDPR & CCPA",
    article_type: "policy", incident_type: "data_breach", severity: "critical",
    view_count: 631, helpful_count: 98, author: "Legal/GRC", updated_at: "2026-03-15",
    content_preview: "Regulatory timelines: GDPR 72-hour DPA notification, CCPA consumer notice requirements, breach documentation checklist.",
    tags: ["gdpr", "ccpa", "breach", "notification", "compliance"],
  },
  {
    id: "art-003", title: "DDoS Mitigation Runbook = Layer 3/4 and Layer 7",
    article_type: "playbook", incident_type: "ddos", severity: "high",
    view_count: 415, helpful_count: 71, author: "NetSec", updated_at: "2026-02-20",
    content_preview: "Traffic scrubbing activation, rate limiting thresholds, upstream provider escalation contacts, CDN configuration for Layer 7 attacks.",
    tags: ["ddos", "mitigation", "layer7", "cdn", "rate-limiting"],
  },
  {
    id: "art-004", title: "Phishing Investigation Checklist",
    article_type: "how_to", incident_type: "phishing", severity: "high",
    view_count: 1204, helpful_count: 201, author: "SOC Tier 1", updated_at: "2026-04-10",
    content_preview: "Header analysis, link defanging, sandbox detonation, recipient identification, mailbox remediation steps for phishing campaigns.",
    tags: ["phishing", "email", "investigation", "sandbox"],
  },
  {
    id: "art-005", title: "Insider Threat = HR & Legal Escalation Path",
    article_type: "reference", incident_type: "insider_threat", severity: "high",
    view_count: 289, helpful_count: 44, author: "HR Security", updated_at: "2026-01-30",
    content_preview: "When to involve HR, legal hold procedures, user account suspension without tipping off, chain of custody for evidence.",
    tags: ["insider", "hr", "legal", "evidence", "confidentiality"],
  },
  {
    id: "art-006", title: "Supply Chain Attack = Dependency Integrity Verification",
    article_type: "post_mortem", incident_type: "supply_chain", severity: "critical",
    view_count: 374, helpful_count: 62, author: "AppSec", updated_at: "2026-03-28",
    content_preview: "Post-mortem analysis of SolarWinds-style compromise patterns. Hash verification procedures, SBOM comparison, rollback strategy.",
    tags: ["supply-chain", "sbom", "integrity", "post-mortem"],
  },
  {
    id: "art-007", title: "Zero-Day Emergency Patch Protocol",
    article_type: "how_to", incident_type: "zero_day", severity: "critical",
    view_count: 558, helpful_count: 89, author: "Vuln Mgmt", updated_at: "2026-04-05",
    content_preview: "Emergency patch approval bypass for CVSS 9+, compensating controls while patch is unavailable, vendor escalation contacts.",
    tags: ["zero-day", "patch", "emergency", "compensating-controls"],
  },
  {
    id: "art-008", title: "Account Takeover = Session Revocation & User Notification",
    article_type: "faq", incident_type: "account_takeover", severity: "medium",
    view_count: 723, helpful_count: 117, author: "IAM Team", updated_at: "2026-04-12",
    content_preview: "Force-logout all sessions, reset MFA enrollments, notify affected users, review OAuth grants, audit recent activity.",
    tags: ["ato", "session", "mfa", "oauth", "audit"],
  },
];

const MOCK_RUNBOOKS: Runbook[] = [
  { id: "rb-001", runbook_name: "Ransomware Full Response",        incident_type: "ransomware",      estimated_minutes: 120, success_rate: 88, execution_count: 14, last_executed: "2026-04-10", steps_count: 24 },
  { id: "rb-002", runbook_name: "Phishing Campaign Triage",        incident_type: "phishing",        estimated_minutes: 30,  success_rate: 96, execution_count: 67, last_executed: "2026-04-15", steps_count: 12 },
  { id: "rb-003", runbook_name: "DDoS Layer 7 Mitigation",         incident_type: "ddos",            estimated_minutes: 45,  success_rate: 82, execution_count: 8,  last_executed: "2026-03-22", steps_count: 16 },
  { id: "rb-004", runbook_name: "Data Breach Containment",         incident_type: "data_breach",     estimated_minutes: 90,  success_rate: 79, execution_count: 5,  last_executed: "2026-02-14", steps_count: 20 },
  { id: "rb-005", runbook_name: "Account Takeover Response",       incident_type: "account_takeover",estimated_minutes: 20,  success_rate: 94, execution_count: 31, last_executed: "2026-04-14", steps_count: 10 },
  { id: "rb-006", runbook_name: "Supply Chain Compromise Triage",  incident_type: "supply_chain",    estimated_minutes: 180, success_rate: 71, execution_count: 3,  last_executed: "2026-01-08", steps_count: 32 },
];

const SEARCH_ANALYTICS = [
  { term: "ransomware containment", count: 89 },
  { term: "phishing headers",       count: 76 },
  { term: "gdpr notification",      count: 64 },
  { term: "mfa bypass",             count: 58 },
  { term: "zero-day patch",         count: 51 },
];

// == Helpers ====================================================

const articleTypeConfig: Record<ArticleType, { label: string; color: string }> = {
  playbook:    { label: "Playbook",    color: "bg-blue-700 text-blue-100" },
  reference:   { label: "Reference",  color: "bg-gray-600 text-gray-200" },
  post_mortem: { label: "Post-Mortem",color: "bg-purple-700 text-purple-100" },
  how_to:      { label: "How-To",     color: "bg-cyan-700 text-cyan-100" },
  policy:      { label: "Policy",     color: "bg-indigo-700 text-indigo-100" },
  faq:         { label: "FAQ",        color: "bg-green-700 text-green-100" },
};

const severityConfig: Record<ArticleSeverity, { label: string; text: string }> = {
  critical: { label: "Critical", text: "text-red-400" },
  high:     { label: "High",     text: "text-orange-400" },
  medium:   { label: "Medium",   text: "text-amber-400" },
  low:      { label: "Low",      text: "text-green-400" },
  info:     { label: "Info",     text: "text-blue-400" },
};

const incidentTypeLabels: Record<IncidentType, string> = {
  ransomware:      "Ransomware",
  data_breach:     "Data Breach",
  ddos:            "DDoS",
  phishing:        "Phishing",
  insider_threat:  "Insider Threat",
  supply_chain:    "Supply Chain",
  zero_day:        "Zero-Day",
  account_takeover:"Account Takeover",
};

function successRateColor(rate: number) {
  if (rate >= 90) return "bg-green-500";
  if (rate >= 75) return "bg-amber-500";
  return "bg-red-500";
}

function matchesSearch(article: KBArticle, query: string): boolean {
  const q = query.toLowerCase();
  return (
    article.title.toLowerCase().includes(q) ||
    article.content_preview.toLowerCase().includes(q) ||
    article.tags.some(t => t.toLowerCase().includes(q)) ||
    incidentTypeLabels[article.incident_type].toLowerCase().includes(q)
  );
}

// == Component ==================================================

export default function IncidentKBDashboard() {
  const [search, setSearch] = useState("");
  const [helpfulMap, setHelpfulMap] = useState<Record<string, boolean>>({});
  const [executedRunbooks, setExecutedRunbooks] = useState<Record<string, boolean>>({});

  const [fetchError, setFetchError] = useState<string | null>(null);

  const loadData = () => {
    setFetchError(null);
    apiFetch(`/api/v1/incident-kb/articles?org_id=${ORG_ID}`).catch((err) => {
      setFetchError(err instanceof Error ? err.message : "Failed to load knowledge base data");
    });
  };

  useEffect(() => {
    loadData();}, []);
  const [executeMsg, setExecuteMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const filteredArticles = search.trim()
    ? MOCK_ARTICLES.filter(a => matchesSearch(a, search.trim()))
    : MOCK_ARTICLES;

  const totalArticles = MOCK_ARTICLES.length;
  const totalRunbooks = MOCK_RUNBOOKS.length;
  const avgSuccessRate = Math.round(MOCK_RUNBOOKS.reduce((s, r) => s + r.success_rate, 0) / MOCK_RUNBOOKS.length);
  const mostViewed = MOCK_ARTICLES.reduce((best, a) => a.view_count > best.view_count ? a : best, MOCK_ARTICLES[0]);

  function handleHelpful(id: string) {
    setHelpfulMap(prev => ({ ...prev, [id]: !prev[id] }));}

  function handleExecute(rb: Runbook) {
    setExecutedRunbooks(prev => ({ ...prev, [rb.id]: true }));
    setExecuteMsg(`Executing "${rb.runbook_name}"...`);
    setTimeout(() => setExecuteMsg(null), 3000);
  }

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
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Incident Knowledge Base</h1>
          <p className="text-gray-400 mt-1">Playbooks, runbooks, reference articles, and post-mortems</p>
        </div>
        {executeMsg && (
          <div className="bg-blue-800/40 border border-blue-600 text-blue-300 px-4 py-2 rounded text-sm">{executeMsg}</div>
        )}
      </div>

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between" role="status" aria-live="polite">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors" aria-label="Refresh data">Retry</button>
        </div>
      )}

      {/* KB Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Articles",  value: totalArticles,    color: "text-blue-400" },
          { label: "Total Runbooks",  value: totalRunbooks,    color: "text-purple-400" },
          { label: "Avg Success Rate",value: `${avgSuccessRate}%`, color: "text-green-400" },
          { label: "Most Viewed",     value: mostViewed.view_count, color: "text-amber-400" },
        ].map(s => (
          <div key={s.label} className="bg-gray-800 rounded-lg p-5">
            <p className="text-gray-400 text-sm">{s.label}</p>
            <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Search Bar */}
      <div className="relative">
        <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" />
        </svg>
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search articles by title, content, tags, or incident type..."
          className="w-full bg-gray-800 border border-gray-600 rounded-lg pl-10 pr-4 py-3 text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
        />
        {search && (
          <button
            onClick={() => setSearch("")}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 text-lg"
          >
            =
          </button>
        )}
      </div>

      {/* Search results count */}
      {search && (
        <p className="text-gray-400 text-sm">
          {filteredArticles.length} result{filteredArticles.length !== 1 ? "s" : ""} for "{search}"
        </p>
      )}

      {/* Article Cards */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">
          Articles {search ? `(${filteredArticles.length})` : `(${totalArticles})`}
        </h2>
        {filteredArticles.length === 0 ? (
          <div className="bg-gray-800 rounded-lg p-8 text-center">
            <p className="text-gray-500">No articles found matching "{search}"</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredArticles.map(article => {
              const isHelpful = helpfulMap[article.id];
              return (
                <div key={article.id} className="bg-gray-800 rounded-lg p-5 space-y-3 hover:bg-gray-750 transition-colors">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${articleTypeConfig[article.article_type].color}`}>
                        {articleTypeConfig[article.article_type].label}
                      </span>
                      <span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">
                        {incidentTypeLabels[article.incident_type]}
                      </span>
                    </div>
                    <span className={`text-xs font-medium shrink-0 ${severityConfig[article.severity].text}`}>
                      {severityConfig[article.severity].label}
                    </span>
                  </div>
                  <h3 className="text-white font-semibold leading-snug">{article.title}</h3>
                  <p className="text-gray-400 text-xs leading-relaxed line-clamp-2">{article.content_preview}</p>
                  <div className="flex flex-wrap gap-1">
                    {article.tags.map(tag => (
                      <span key={tag} className="bg-gray-700/60 text-gray-400 px-1.5 py-0.5 rounded text-xs">#{tag}</span>
                    )))}
                  </div>
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <div className="flex items-center gap-3">
                      <span>{article.view_count} views</span>
                      <span>by {article.author}</span>
                      <span>updated {article.updated_at}</span>
                    </div>
                    <button
                      onClick={() => handleHelpful(article.id)}
                      className={`flex items-center gap-1 transition-colors ${isHelpful ? "text-red-400" : "text-gray-500 hover:text-red-400"}`}
                    >
                      <span>{isHelpful ? "=" : "="}</span>
                      <span>{article.helpful_count + (isHelpful ? 1 : 0)}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Runbooks */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Runbooks</h2>
          <div className="space-y-4">
            {MOCK_RUNBOOKS.map(rb => {
              const executed = executedRunbooks[rb.id];
              return (
                <div key={rb.id} className="flex items-center gap-4 p-4 bg-gray-700/30 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors">
                  <div className="flex-1 min-w-0 space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-white font-medium">{rb.runbook_name}</p>
                      <span className="bg-gray-600 text-gray-200 px-2 py-0.5 rounded text-xs">
                        {incidentTypeLabels[rb.incident_type]}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-gray-500">
                      <span>~{rb.estimated_minutes} min</span>
                      <span>{rb.steps_count} steps</span>
                      <span>{rb.execution_count} executions</span>
                      <span>Last: {rb.last_executed}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-32 bg-gray-600 rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${successRateColor(rb.success_rate)}`}
                          style={{ width: `${rb.success_rate}%` }}
                        />
                      </div>
                      <span className={`text-xs font-medium ${rb.success_rate >= 90 ? "text-green-400" : rb.success_rate >= 75 ? "text-amber-400" : "text-red-400"}`}>
                        {rb.success_rate}% success
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => handleExecute(rb)}
                    disabled={executed}
                    className={`shrink-0 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                      executed
                        ? "bg-gray-700 text-gray-500 cursor-not-allowed"
                        : "bg-blue-600 hover:bg-blue-700 text-white"
                    }`}
                  >
                    {executed ? "Running=" : "Execute"}
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        {/* Search Analytics */}
        <div className="lg:col-span-1 bg-gray-800 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-white mb-4">Top Searched Terms</h2>
          <div className="space-y-3">
            {SEARCH_ANALYTICS.map((item, idx) => (
              <div key={item.term} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-600 w-4">{idx + 1}</span>
                    <span
                      className="text-gray-300 cursor-pointer hover:text-blue-400 transition-colors"
                      onClick={() => setSearch(item.term)}
                    >
                      {item.term}
                    </span>
                  </div>
                  <span className="text-gray-500 font-medium">{item.count}</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-1">
                  <div
                    className="h-1 rounded-full bg-blue-500"
                    style={{ width: `${(item.count / SEARCH_ANALYTICS[0].count) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
          <p className="text-gray-600 text-xs mt-4">Click a term to search</p>
        </div>
      </div>
    </div>
  );
}
