/**
 * Feed Subscriptions Dashboard
 *
 * Threat intelligence feed subscription management.
 *   1. Subscription cards (feed_name, feed_type badge, status dot, ioc_count, error_count, last_fetched, refresh_interval)
 *   2. Ingestion log table (fetched_at, iocs_fetched, new, updated, status badge)
 *   3. Delivery configs per feed (delivery_type, endpoint, filter_severity, enabled toggle)
 *   4. Due subscriptions alert
 *   5. Stats panel
 *
 * Route: /feed-subscriptions
 * API: GET /api/v1/feed-subscriptions
 */

import { useState, useEffect } from "react";
import { Rss, AlertTriangle, CheckCircle2, XCircle, Clock, BarChart2, RefreshCw, Settings } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// ── Types ──────────────────────────────────────────────────────

interface FeedSubscription {
  id: string;
  feed_name: string;
  feed_type: "osint" | "commercial" | "isac" | "government" | "custom";
  status: "active" | "paused" | "error" | "pending";
  ioc_count: number;
  error_count: number;
  last_fetched: string; // relative
  refresh_interval: string;
  deliveries: DeliveryConfig[];
  logs: IngestionLog[];
}

interface DeliveryConfig {
  id: string;
  delivery_type: "siem" | "webhook" | "email" | "api" | "kafka";
  endpoint: string;
  filter_severity: "all" | "high+" | "critical";
  enabled: boolean;
}

interface IngestionLog {
  id: string;
  fetched_at: string;
  iocs_fetched: number;
  new_iocs: number;
  updated_iocs: number;
  status: "success" | "partial" | "failed";
}

// ── Mock data ──────────────────────────────────────────────────

const FEEDS: FeedSubscription[] = [
  {
    id: "f1", feed_name: "AlienVault OTX", feed_type: "osint", status: "active",
    ioc_count: 142_503, error_count: 2, last_fetched: "3 min ago", refresh_interval: "15 min",
    deliveries: [
      { id: "d1", delivery_type: "siem", endpoint: "splunk.internal:8088", filter_severity: "high+", enabled: true },
      { id: "d2", delivery_type: "webhook", endpoint: "https://hooks.aldeci.io/otx", filter_severity: "all", enabled: true },
    ],
    logs: [
      { id: "l1", fetched_at: "2026-04-16 10:45", iocs_fetched: 1243, new_iocs: 89, updated_iocs: 312, status: "success" },
      { id: "l2", fetched_at: "2026-04-16 10:30", iocs_fetched: 987, new_iocs: 44, updated_iocs: 201, status: "success" },
      { id: "l3", fetched_at: "2026-04-16 10:15", iocs_fetched: 0, new_iocs: 0, updated_iocs: 0, status: "failed" },
    ],
  },
  {
    id: "f2", feed_name: "URLhaus (abuse.ch)", feed_type: "osint", status: "active",
    ioc_count: 78_201, error_count: 0, last_fetched: "8 min ago", refresh_interval: "30 min",
    deliveries: [
      { id: "d3", delivery_type: "api", endpoint: "/api/v1/ioc-enrichment", filter_severity: "all", enabled: true },
    ],
    logs: [
      { id: "l4", fetched_at: "2026-04-16 10:38", iocs_fetched: 3412, new_iocs: 201, updated_iocs: 88, status: "success" },
      { id: "l5", fetched_at: "2026-04-16 10:08", iocs_fetched: 2901, new_iocs: 183, updated_iocs: 74, status: "success" },
    ],
  },
  {
    id: "f3", feed_name: "CISA KEV Feed", feed_type: "government", status: "active",
    ioc_count: 1_243, error_count: 0, last_fetched: "2 hr ago", refresh_interval: "6 hr",
    deliveries: [
      { id: "d4", delivery_type: "email", endpoint: "secops@company.io", filter_severity: "critical", enabled: true },
      { id: "d5", delivery_type: "siem", endpoint: "elastic.internal:9200", filter_severity: "critical", enabled: false },
    ],
    logs: [
      { id: "l6", fetched_at: "2026-04-16 08:00", iocs_fetched: 3, new_iocs: 3, updated_iocs: 0, status: "success" },
    ],
  },
  {
    id: "f4", feed_name: "Recorded Future Intel", feed_type: "commercial", status: "active",
    ioc_count: 984_012, error_count: 5, last_fetched: "12 min ago", refresh_interval: "5 min",
    deliveries: [
      { id: "d6", delivery_type: "kafka", endpoint: "kafka:9092/threat-intel", filter_severity: "high+", enabled: true },
    ],
    logs: [
      { id: "l7", fetched_at: "2026-04-16 10:44", iocs_fetched: 8821, new_iocs: 412, updated_iocs: 1203, status: "success" },
      { id: "l8", fetched_at: "2026-04-16 10:39", iocs_fetched: 9011, new_iocs: 388, updated_iocs: 1144, status: "partial" },
    ],
  },
  {
    id: "f5", feed_name: "FS-ISAC TLP:AMBER", feed_type: "isac", status: "error",
    ioc_count: 22_100, error_count: 14, last_fetched: "48 min ago", refresh_interval: "1 hr",
    deliveries: [
      { id: "d7", delivery_type: "webhook", endpoint: "https://siem.company.io/isac", filter_severity: "all", enabled: false },
    ],
    logs: [
      { id: "l9", fetched_at: "2026-04-16 10:00", iocs_fetched: 0, new_iocs: 0, updated_iocs: 0, status: "failed" },
      { id: "l10", fetched_at: "2026-04-16 09:00", iocs_fetched: 0, new_iocs: 0, updated_iocs: 0, status: "failed" },
    ],
  },
  {
    id: "f6", feed_name: "Shodan Exposure Monitor", feed_type: "custom", status: "paused",
    ioc_count: 5_431, error_count: 1, last_fetched: "3 days ago", refresh_interval: "24 hr",
    deliveries: [],
    logs: [
      { id: "l11", fetched_at: "2026-04-13 08:00", iocs_fetched: 211, new_iocs: 45, updated_iocs: 88, status: "success" },
    ],
  },
];

// ── Helpers ────────────────────────────────────────────────────

const statusDot: Record<FeedSubscription["status"], string> = {
  active: "bg-green-400",
  paused: "bg-gray-400",
  error: "bg-red-400",
  pending: "bg-yellow-400",
};

const statusLabel: Record<FeedSubscription["status"], string> = {
  active: "text-green-400",
  paused: "text-gray-400",
  error: "text-red-400",
  pending: "text-yellow-400",
};

const feedTypeColor: Record<FeedSubscription["feed_type"], string> = {
  osint: "bg-blue-900 text-blue-300",
  commercial: "bg-purple-900 text-purple-300",
  isac: "bg-teal-900 text-teal-300",
  government: "bg-red-900 text-red-300",
  custom: "bg-gray-700 text-gray-300",
};

const logStatusColor: Record<IngestionLog["status"], string> = {
  success: "bg-green-900 text-green-300",
  partial: "bg-yellow-900 text-yellow-300",
  failed: "bg-red-900 text-red-300",
};

function fmtNum(n: number): string {
  return n >= 1_000_000 ? `${(n/1_000_000).toFixed(1)}M`
    : n >= 1_000 ? `${(n/1_000).toFixed(1)}K`
    : String(n);
}

// ── Component ──────────────────────────────────────────────────

export default function FeedSubscriptionsDashboard() {
  const [selectedFeed, setSelectedFeed] = useState<FeedSubscription | null>(FEEDS[0]);
  const [activeTab, setActiveTab] = useState<"logs" | "delivery">("logs");

  useEffect(() => {
    apiFetch(`/api/v1/feed-subscriptions/subscriptions?org_id=${ORG_ID}`).catch(() => {});
  }, []);

  const errorFeeds = FEEDS.filter(f => f.status === "error");
  const totalIOCs = FEEDS.reduce((s, f) => s + f.ioc_count, 0);
  const activeCount = FEEDS.filter(f => f.status === "active").length;
  const totalErrors = FEEDS.reduce((s, f) => s + f.error_count, 0);

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Rss className="w-6 h-6 text-blue-400" />
            Feed Subscriptions
          </h1>
          <p className="text-gray-400 text-sm mt-1">Threat intelligence feed ingestion and delivery management</p>
        </div>
        <button className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh All
        </button>
      </div>

      {/* Error banner */}
      {errorFeeds.length > 0 && (
        <div className="bg-red-900/40 border border-red-700 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <span className="text-red-300 font-medium">
            {errorFeeds.length} feed{errorFeeds.length > 1 ? "s" : ""} in error state: {errorFeeds.map(f => f.feed_name).join(", ")}
          </span>
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Subscriptions", value: FEEDS.length, icon: <Rss className="w-5 h-5 text-blue-400" />, sub: "configured feeds" },
          { label: "Active Feeds", value: activeCount, icon: <CheckCircle2 className="w-5 h-5 text-green-400" />, sub: "currently ingesting" },
          { label: "Total IOCs", value: fmtNum(totalIOCs), icon: <BarChart2 className="w-5 h-5 text-purple-400" />, sub: "across all feeds" },
          { label: "Total Errors", value: totalErrors, icon: <XCircle className="w-5 h-5 text-red-400" />, sub: "fetch failures" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-400 text-xs uppercase tracking-wide">{k.label}</span>
              {k.icon}
            </div>
            <div className="text-3xl font-bold">{k.value}</div>
            <div className="text-gray-500 text-xs mt-1">{k.sub}</div>
          </div>
        ))}
      </div>

      {/* Feed cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {FEEDS.map(feed => (
          <div
            key={feed.id}
            onClick={() => setSelectedFeed(feed)}
            className={`bg-gray-800 rounded-lg p-4 cursor-pointer hover:bg-gray-750 transition-colors border-2 ${
              selectedFeed?.id === feed.id ? "border-blue-600" : "border-transparent"
            }`}
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="font-semibold text-sm">{feed.feed_name}</div>
                <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize mt-1 inline-block ${feedTypeColor[feed.feed_type]}`}>
                  {feed.feed_type}
                </span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className={`w-2 h-2 rounded-full ${statusDot[feed.status]}`} />
                <span className={`text-xs capitalize ${statusLabel[feed.status]}`}>{feed.status}</span>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <div className="text-gray-400">IOC Count</div>
                <div className="font-bold text-lg text-white">{fmtNum(feed.ioc_count)}</div>
              </div>
              <div>
                <div className="text-gray-400">Errors</div>
                <div className={`font-bold text-lg ${feed.error_count > 0 ? "text-red-400" : "text-green-400"}`}>
                  {feed.error_count}
                </div>
              </div>
              <div>
                <div className="text-gray-400">Last Fetched</div>
                <div className="text-gray-300 flex items-center gap-1"><Clock className="w-3 h-3" />{feed.last_fetched}</div>
              </div>
              <div>
                <div className="text-gray-400">Interval</div>
                <div className="text-gray-300">{feed.refresh_interval}</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Detail panel */}
      {selectedFeed && (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700 flex items-center justify-between">
            <div className="font-semibold flex items-center gap-2">
              <Settings className="w-4 h-4 text-gray-400" />
              {selectedFeed.feed_name} — Details
            </div>
            <div className="flex gap-1 bg-gray-700 rounded-lg p-1">
              {(["logs","delivery"] as const).map(tab => (
                <button
                  key={tab}
                  onClick={e => { e.stopPropagation(); setActiveTab(tab); }}
                  className={`px-3 py-1 rounded-md text-xs font-medium capitalize transition-colors ${
                    activeTab === tab ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"
                  }`}
                >
                  {tab === "logs" ? "Ingestion Log" : "Delivery Configs"}
                </button>
              ))}
            </div>
          </div>

          {activeTab === "logs" ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-700/50">
                  <tr>
                    {["Fetched At","IOCs Fetched","New","Updated","Status"].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {selectedFeed.logs.map(log => (
                    <tr key={log.id} className="border-t border-gray-700 hover:bg-gray-700/30 transition-colors">
                      <td className="px-4 py-3 text-gray-400 text-xs font-mono">{log.fetched_at}</td>
                      <td className="px-4 py-3 font-medium">{log.iocs_fetched.toLocaleString()}</td>
                      <td className="px-4 py-3 text-green-400">+{log.new_iocs}</td>
                      <td className="px-4 py-3 text-blue-400">~{log.updated_iocs}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${logStatusColor[log.status]}`}>
                          {log.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-4 space-y-3">
              {selectedFeed.deliveries.length === 0 ? (
                <p className="text-gray-500 text-sm">No delivery configurations for this feed.</p>
              ) : (
                selectedFeed.deliveries.map(d => (
                  <div key={d.id} className="bg-gray-700/50 rounded-lg p-3 flex items-center gap-4">
                    <span className="bg-indigo-900 text-indigo-300 px-2 py-0.5 rounded text-xs uppercase font-medium">{d.delivery_type}</span>
                    <span className="text-gray-300 text-xs font-mono flex-1 truncate">{d.endpoint}</span>
                    <span className="text-xs text-gray-400">Filter: <span className="text-yellow-400">{d.filter_severity}</span></span>
                    <div className={`w-2 h-2 rounded-full ${d.enabled ? "bg-green-400" : "bg-gray-500"}`} title={d.enabled ? "Enabled" : "Disabled"} />
                    <span className={`text-xs ${d.enabled ? "text-green-400" : "text-gray-500"}`}>{d.enabled ? "On" : "Off"}</span>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
