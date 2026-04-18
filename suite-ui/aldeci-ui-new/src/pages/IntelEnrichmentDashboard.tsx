/**
 * Intel Enrichment Dashboard
 *
 * Shows IOC enrichment requests, result details, source success rates,
 * and a bulk enrichment form.
 *
 * Route: /intel-enrichment
 * API: GET /api/v1/intel-enrichment
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/intel-enrichment";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });


// == Types ======================================================

type IOCType = "ip" | "domain" | "url" | "hash" | "email" | "asn";
type EnrichmentStatus = "pending" | "in_progress" | "completed" | "failed";

interface EnrichmentRequest {
  id: string;
  indicator: string;
  ioc_type: IOCType;
  status: EnrichmentStatus;
  sources_queried: number;
  sources_responded: number;
  created_at: string;
  reputation_score: number | null;
  malicious: boolean | null;
  confidence: number | null;
  tags: string[];
}

interface EnrichmentSource {
  id: string;
  name: string;
  ioc_types: IOCType[];
  success_rate: number;
  avg_response_ms: number;
  total_queries: number;
}

// == Mock data ==================================================

const MOCK_REQUESTS: EnrichmentRequest[] = [
  { id: "enr-001", indicator: "185.220.101.45",          ioc_type: "ip",     status: "completed", sources_queried: 8, sources_responded: 8, created_at: "2026-04-16 09:00", reputation_score: 92, malicious: true,  confidence: 95, tags: ["tor-exit-node", "bruteforce"] },
  { id: "enr-002", indicator: "malware-c2.evil.ru",      ioc_type: "domain", status: "completed", sources_queried: 7, sources_responded: 6, created_at: "2026-04-16 08:45", reputation_score: 88, malicious: true,  confidence: 87, tags: ["c2", "malware", "emotet"] },
  { id: "enr-003", indicator: "d41d8cd98f00b204e9800998ecf8427e", ioc_type: "hash", status: "completed", sources_queried: 5, sources_responded: 5, created_at: "2026-04-16 08:30", reputation_score: 0, malicious: false, confidence: 99, tags: ["clean", "empty-file"] },
  { id: "enr-004", indicator: "https://phish.example.com/login", ioc_type: "url",    status: "completed", sources_queried: 6, sources_responded: 5, created_at: "2026-04-16 08:15", reputation_score: 76, malicious: true,  confidence: 82, tags: ["phishing", "credential-harvest"] },
  { id: "enr-005", indicator: "attacker@protonmail.com",  ioc_type: "email",  status: "in_progress", sources_queried: 4, sources_responded: 2, created_at: "2026-04-16 09:10", reputation_score: null, malicious: null, confidence: null, tags: [] },
  { id: "enr-006", indicator: "198.51.100.22",            ioc_type: "ip",     status: "pending",  sources_queried: 0, sources_responded: 0, created_at: "2026-04-16 09:15", reputation_score: null, malicious: null, confidence: null, tags: [] },
  { id: "enr-007", indicator: "AS12345",                  ioc_type: "asn",    status: "failed",   sources_queried: 3, sources_responded: 0, created_at: "2026-04-16 07:00", reputation_score: null, malicious: null, confidence: null, tags: [] },
];

const MOCK_SOURCES: EnrichmentSource[] = [
  { id: "src-001", name: "VirusTotal",      ioc_types: ["ip", "domain", "url", "hash"], success_rate: 99,  avg_response_ms: 450,  total_queries: 12847 },
  { id: "src-002", name: "AbuseIPDB",       ioc_types: ["ip"],                           success_rate: 98,  avg_response_ms: 280,  total_queries: 8921  },
  { id: "src-003", name: "Shodan",          ioc_types: ["ip", "asn"],                    success_rate: 95,  avg_response_ms: 720,  total_queries: 5634  },
  { id: "src-004", name: "URLhaus",         ioc_types: ["url", "domain", "hash"],        success_rate: 92,  avg_response_ms: 190,  total_queries: 7245  },
  { id: "src-005", name: "AlienVault OTX",  ioc_types: ["ip", "domain", "hash", "url"], success_rate: 97,  avg_response_ms: 380,  total_queries: 10112 },
  { id: "src-006", name: "GreyNoise",       ioc_types: ["ip"],                           success_rate: 94,  avg_response_ms: 210,  total_queries: 4389  },
  { id: "src-007", name: "Have I Been Pwned", ioc_types: ["email"],                      success_rate: 99,  avg_response_ms: 160,  total_queries: 2108  },
  { id: "src-008", name: "RiskIQ",          ioc_types: ["domain", "ip", "email"],        success_rate: 88,  avg_response_ms: 940,  total_queries: 3562  },
];

// == Helpers ====================================================

const typeColors: Record<IOCType, string> = {
  ip:     "bg-blue-700 text-blue-100",
  domain: "bg-purple-700 text-purple-100",
  url:    "bg-cyan-700 text-cyan-100",
  hash:   "bg-gray-600 text-gray-200",
  email:  "bg-pink-700 text-pink-100",
  asn:    "bg-indigo-700 text-indigo-100",
};

const statusColors: Record<EnrichmentStatus, string> = {
  pending:     "bg-gray-600 text-gray-200",
  in_progress: "bg-blue-700 text-blue-100",
  completed:   "bg-green-700 text-green-100",
  failed:      "bg-red-700 text-red-100",
};

// == Component ==================================================

export default function IntelEnrichmentDashboard() {
  const [requests, setRequests] = useState(MOCK_REQUESTS);

  const [fetchError, setFetchError] = useState<string | null>(null);

  const loadData = () => {
    setFetchError(null);
    fetch(`${_API_BASE}/requests`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`${r.status}`)))
      .then(d => { if (Array.isArray(d)) setRequests(d); })
      .catch((err) => {
        setFetchError(err instanceof Error ? err.message : "Failed to load enrichment data");
      });
  };

  useEffect(() => {
    loadData();}, []);

  const [selectedRequest, setSelectedRequest] = useState<string>(MOCK_REQUESTS[0].id);
  const [bulkInput, setBulkInput] = useState("");
  const [bulkSubmitted, setBulkSubmitted] = useState(false);
  const [loading, setLoading] = useState(true);

  const selected = MOCK_REQUESTS.find(r => r.id === selectedRequest);

  const totalCompleted = MOCK_REQUESTS.filter(r => r.status === "completed").length;
  const totalPending = MOCK_REQUESTS.filter(r => r.status === "pending" || r.status === "in_progress").length;
  const avgSources = Math.round(
    MOCK_REQUESTS.filter(r => r.status === "completed").reduce((s, r) => s + r.sources_queried, 0) / totalCompleted || 0
  );

  function handleBulkSubmit() {
    if (bulkInput.trim()) {
      setBulkSubmitted(true);
      setTimeout(() => setBulkSubmitted(false), 3000);
      setBulkInput("");
    }}

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
      <div>
        <h1 className="text-2xl font-bold text-white">Intel Enrichment</h1>
        <p className="text-gray-400 mt-1">IOC enrichment requests, source analysis, and reputation scoring</p>
      </div>

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between" role="status" aria-live="polite">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors" aria-label="Refresh data">Retry</button>
        </div>
      )}

      {/* Stats Panel */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Requests", value: MOCK_REQUESTS.length, color: "text-blue-400" },
          { label: "Completed",      value: totalCompleted,       color: "text-green-400" },
          { label: "Pending",        value: totalPending,         color: "text-amber-400" },
          { label: "Avg Sources",    value: avgSources,           color: "text-purple-400" },
        ].map(kpi => (
          <div key={kpi.label} className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">{kpi.label}</p>
            <p className={`text-3xl font-bold mt-1 ${kpi.color}`}>{kpi.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Requests Table */}
        <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Enrichment Requests</h2>
          <div className="overflow-x-auto">
            <table role="table" className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-left">
                  <th className="pb-3 pr-4">Indicator</th>
                  <th className="pb-3 pr-4">Type</th>
                  <th className="pb-3 pr-4">Status</th>
                  <th className="pb-3 pr-4">Sources</th>
                  <th className="pb-3">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {MOCK_REQUESTS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MOCK_REQUESTS.map(req => (
                  <tr
                    key={req.id}
                    onClick={() => setSelectedRequest(req.id)}
                    className={`cursor-pointer transition-colors ${selectedRequest === req.id ? "bg-blue-900/30" : "hover:bg-gray-700/50"}`}
                  >
                    <td className="py-3 pr-4 font-mono text-xs text-white max-w-[180px] truncate">{req.indicator}</td>
                    <td className="py-3 pr-4">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${typeColors[req.ioc_type]}`}>{req.ioc_type}</span>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColors[req.status]}`}>{req.status.replace("_", " ")}</span>
                    </td>
                    <td className="py-3 pr-4 text-gray-400 text-xs">
                      {req.sources_responded}/{req.sources_queried}
                    </td>
                    <td className="py-3 text-gray-500 text-xs">{req.created_at}</td>
                  </tr>
                )))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Result Details */}
        <div className="space-y-4">
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-4">Result Details</h2>
            {selected && selected.status === "completed" ? (
              <div className="space-y-4">
                <div>
                  <p className="text-gray-400 text-xs mb-1">Indicator</p>
                  <p className="text-white text-xs font-mono break-all">{selected.indicator}</p>
                </div>
                {/* Reputation score bar */}
                <div>
                  <div className="flex justify-between mb-1">
                    <p className="text-gray-400 text-xs">Reputation Score</p>
                    <span className={`text-sm font-bold ${(selected.reputation_score ?? 0) >= 70 ? "text-red-400" : (selected.reputation_score ?? 0) >= 40 ? "text-amber-400" : "text-green-400"}`}>
                      {selected.reputation_score ?? "N/A"}
                    </span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${(selected.reputation_score ?? 0) >= 70 ? "bg-red-500" : (selected.reputation_score ?? 0) >= 40 ? "bg-amber-500" : "bg-green-500"}`}
                      style={{ width: `${selected.reputation_score ?? 0}%` }}
                    />
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div>
                    <p className="text-gray-400 text-xs">Verdict</p>
                    <span className={`font-bold text-sm ${selected.malicious ? "text-red-400" : "text-green-400"}`}>
                      {selected.malicious ? "MALICIOUS" : "CLEAN"}
                    </span>
                  </div>
                  <div className="ml-auto">
                    <p className="text-gray-400 text-xs">Confidence</p>
                    <span className="text-white font-semibold">{selected.confidence}%</span>
                  </div>
                </div>
                {selected.tags.length > 0 && (
                  <div>
                    <p className="text-gray-400 text-xs mb-2">Tags</p>
                    <div className="flex flex-wrap gap-1">
                      {selected.tags.map(tag => (
                        <span key={tag} className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">{tag}</span>
                      ))
                    )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-gray-500 text-sm">Select a completed request to view details</p>
            )}
          </div>
        </div>
      </div>

      {/* Sources */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Enrichment Sources</h2>
        <div className="overflow-x-auto">
          <table role="table" className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-left">
                <th className="pb-3 pr-4">Source</th>
                <th className="pb-3 pr-4">Supported Types</th>
                <th className="pb-3 pr-4">Success Rate</th>
                <th className="pb-3 pr-4">Avg Response</th>
                <th className="pb-3">Total Queries</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {MOCK_SOURCES.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                MOCK_SOURCES.map(src => (
                <tr key={src.id} className="hover:bg-gray-700/50">
                  <td className="py-3 pr-4 text-white font-medium">{src.name}</td>
                  <td className="py-3 pr-4">
                    <div className="flex flex-wrap gap-1">
                      {src.ioc_types.map(t => (
                        <span key={t} className={`px-1.5 py-0.5 rounded text-xs font-medium uppercase ${typeColors[t]}`}>{t}</span>
                      ))
                    )}
                    </div>
                  </td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="w-20 bg-gray-700 rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${src.success_rate >= 95 ? "bg-green-500" : src.success_rate >= 85 ? "bg-amber-500" : "bg-red-500"}`}
                          style={{ width: `${src.success_rate}%` }}
                        />
                      </div>
                      <span className={`text-xs font-medium ${src.success_rate >= 95 ? "text-green-400" : src.success_rate >= 85 ? "text-amber-400" : "text-red-400"}`}>
                        {src.success_rate}%
                      </span>
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-gray-400 text-xs">{src.avg_response_ms}ms</td>
                  <td className="py-3 text-gray-400">{src.total_queries.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bulk Enrich Form */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-2">Bulk Enrich IOCs</h2>
        <p className="text-gray-400 text-sm mb-4">Paste one indicator per line (IPs, domains, URLs, hashes, emails)</p>
        {bulkSubmitted && (
          <div className="mb-4 bg-green-900/40 border border-green-700 rounded-lg p-3 text-green-300 text-sm">
            Enrichment requests submitted successfully.
          </div>
        )}
        <textarea
          value={bulkInput}
          onChange={e => setBulkInput(e.target.value)}
          placeholder={"185.220.101.45\nmalware-c2.evil.ru\nd41d8cd98f00b204e9800998ecf8427e"}
          rows={5}
          className="w-full bg-gray-900 border border-gray-600 rounded-lg p-3 text-gray-200 text-sm font-mono focus:outline-none focus:border-blue-500 resize-none"
        />
        <div className="mt-3 flex items-center justify-between">
          <p className="text-gray-500 text-xs">
            {bulkInput.trim() ? bulkInput.trim().split("\n").filter(Boolean).length : 0} IOC{bulkInput.trim().split("\n").filter(Boolean).length !== 1 ? "s" : ""} detected
          </p>
          <button
            onClick={handleBulkSubmit}
            disabled={!bulkInput.trim()}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:text-gray-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            Submit for Enrichment
          </button>
        </div>
      </div>
    </div>
  );
}
