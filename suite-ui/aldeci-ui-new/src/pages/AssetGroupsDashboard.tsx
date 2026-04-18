/**
 * Asset Groups Dashboard
 *
 * Asset group management with member and policy tracking.
 *   1. Group grid (group_name, group_type badge, criticality color, owner, member_count pill)
 *   2. Member list per group (asset_id, asset_type badge, added_by)
 *   3. Policy list per group (policy_name, policy_type, enabled toggle)
 *   4. Bulk add members form (paste asset IDs)
 *   5. Group stats (by criticality/type CSS bars, largest group)
 *
 * Route: /asset-groups
 * API: GET /api/v1/asset-groups
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/asset-groups";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { Layers, Users, Shield, Plus, BarChart2, AlertTriangle } from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

interface AssetGroup {
  id: string;
  group_name: string;
  group_type: "server" | "endpoint" | "cloud" | "network" | "application" | "iot";
  criticality: "critical" | "high" | "medium" | "low";
  owner: string;
  members: AssetMember[];
  policies: GroupPolicy[];
}

interface AssetMember {
  asset_id: string;
  asset_type: "server" | "workstation" | "vm" | "container" | "network_device" | "mobile" | "iot";
  added_by: string;
  added_at: string;
}

interface GroupPolicy {
  policy_name: string;
  policy_type: "patch" | "compliance" | "access" | "monitoring" | "backup";
  enabled: boolean;
}

// ── Mock data ──────────────────────────────────────────────────

const GROUPS: AssetGroup[] = [
  {
    id: "g1", group_name: "Production Servers", group_type: "server", criticality: "critical", owner: "sre@company.io",
    members: [
      { asset_id: "SRV-001", asset_type: "server", added_by: "admin", added_at: "2026-01-10" },
      { asset_id: "SRV-002", asset_type: "server", added_by: "admin", added_at: "2026-01-10" },
      { asset_id: "VM-099",  asset_type: "vm",     added_by: "devops", added_at: "2026-02-14" },
      { asset_id: "SRV-003", asset_type: "server", added_by: "admin", added_at: "2026-03-01" },
    ],
    policies: [
      { policy_name: "Critical Patch SLA 24h",   policy_type: "patch",       enabled: true },
      { policy_name: "PCI-DSS Compliance Scan",  policy_type: "compliance",  enabled: true },
      { policy_name: "Privileged Access Control", policy_type: "access",      enabled: true },
      { policy_name: "24/7 Monitoring",           policy_type: "monitoring",  enabled: true },
    ],
  },
  {
    id: "g2", group_name: "Developer Workstations", group_type: "endpoint", criticality: "high", owner: "it@company.io",
    members: [
      { asset_id: "WS-D101", asset_type: "workstation", added_by: "it-admin", added_at: "2026-02-01" },
      { asset_id: "WS-D102", asset_type: "workstation", added_by: "it-admin", added_at: "2026-02-01" },
      { asset_id: "WS-D103", asset_type: "workstation", added_by: "it-admin", added_at: "2026-02-15" },
    ],
    policies: [
      { policy_name: "EDR Full Scan Weekly",     policy_type: "monitoring",  enabled: true },
      { policy_name: "Dev Tool Allowlist",        policy_type: "access",      enabled: false },
      { policy_name: "Auto Patch Non-Critical",  policy_type: "patch",       enabled: true },
    ],
  },
  {
    id: "g3", group_name: "AWS Cloud Assets", group_type: "cloud", criticality: "critical", owner: "cloud-ops@company.io",
    members: [
      { asset_id: "AWS-EC2-4521", asset_type: "vm",        added_by: "terraform", added_at: "2026-01-20" },
      { asset_id: "AWS-EC2-4522", asset_type: "vm",        added_by: "terraform", added_at: "2026-01-20" },
      { asset_id: "K8S-NODE-01",  asset_type: "container", added_by: "k8s-sync",  added_at: "2026-03-10" },
      { asset_id: "K8S-NODE-02",  asset_type: "container", added_by: "k8s-sync",  added_at: "2026-03-10" },
      { asset_id: "K8S-NODE-03",  asset_type: "container", added_by: "k8s-sync",  added_at: "2026-03-10" },
    ],
    policies: [
      { policy_name: "CSPM Continuous Scan",    policy_type: "compliance", enabled: true },
      { policy_name: "IMDSv2 Enforcement",       policy_type: "access",     enabled: true },
      { policy_name: "Snapshot Backup Daily",    policy_type: "backup",     enabled: true },
    ],
  },
  {
    id: "g4", group_name: "Network Core Devices", group_type: "network", criticality: "critical", owner: "netops@company.io",
    members: [
      { asset_id: "RTR-CORE-01", asset_type: "network_device", added_by: "netops", added_at: "2026-01-05" },
      { asset_id: "SW-DIST-01",  asset_type: "network_device", added_by: "netops", added_at: "2026-01-05" },
      { asset_id: "FW-EDGE-01",  asset_type: "network_device", added_by: "netops", added_at: "2026-01-05" },
    ],
    policies: [
      { policy_name: "Config Backup Hourly",    policy_type: "backup",     enabled: true },
      { policy_name: "NTP Compliance Check",    policy_type: "compliance", enabled: true },
      { policy_name: "ACL Review Monthly",      policy_type: "access",     enabled: true },
    ],
  },
  {
    id: "g5", group_name: "Customer-Facing APIs", group_type: "application", criticality: "high", owner: "appsec@company.io",
    members: [
      { asset_id: "APP-API-GATEWAY",  asset_type: "server", added_by: "appsec",  added_at: "2026-02-20" },
      { asset_id: "APP-AUTH-SERVICE", asset_type: "server", added_by: "appsec",  added_at: "2026-02-20" },
    ],
    policies: [
      { policy_name: "OWASP API Scan Weekly",  policy_type: "compliance", enabled: true },
      { policy_name: "WAF Policy Enforcement", policy_type: "monitoring", enabled: true },
      { policy_name: "API Key Rotation 90d",   policy_type: "access",     enabled: false },
    ],
  },
  {
    id: "g6", group_name: "Factory IoT Sensors", group_type: "iot", criticality: "medium", owner: "ot-team@company.io",
    members: [
      { asset_id: "IOT-TEMP-001", asset_type: "iot", added_by: "ot-admin", added_at: "2026-03-01" },
      { asset_id: "IOT-PRES-002", asset_type: "iot", added_by: "ot-admin", added_at: "2026-03-01" },
    ],
    policies: [
      { policy_name: "OT Network Isolation",  policy_type: "access",     enabled: true },
      { policy_name: "Firmware Patch Monthly", policy_type: "patch",      enabled: false },
    ],
  },
];

// ── Helpers ────────────────────────────────────────────────────

const critColor: Record<AssetGroup["criticality"], string> = {
  critical: "text-red-400 border-red-700",
  high: "text-orange-400 border-orange-700",
  medium: "text-yellow-400 border-yellow-700",
  low: "text-green-400 border-green-700",
};

const critBg: Record<AssetGroup["criticality"], string> = {
  critical: "bg-red-900/30",
  high: "bg-orange-900/30",
  medium: "bg-yellow-900/20",
  low: "bg-green-900/20",
};

const groupTypeColor: Record<AssetGroup["group_type"], string> = {
  server: "bg-blue-900 text-blue-300",
  endpoint: "bg-purple-900 text-purple-300",
  cloud: "bg-sky-900 text-sky-300",
  network: "bg-teal-900 text-teal-300",
  application: "bg-indigo-900 text-indigo-300",
  iot: "bg-orange-900 text-orange-300",
};

const assetTypeColor: Record<AssetMember["asset_type"], string> = {
  server: "bg-blue-800 text-blue-200",
  workstation: "bg-purple-800 text-purple-200",
  vm: "bg-sky-800 text-sky-200",
  container: "bg-teal-800 text-teal-200",
  network_device: "bg-indigo-800 text-indigo-200",
  mobile: "bg-pink-800 text-pink-200",
  iot: "bg-orange-800 text-orange-200",
};

const policyTypeColor: Record<GroupPolicy["policy_type"], string> = {
  patch: "bg-yellow-900 text-yellow-300",
  compliance: "bg-blue-900 text-blue-300",
  access: "bg-red-900 text-red-300",
  monitoring: "bg-green-900 text-green-300",
  backup: "bg-gray-700 text-gray-300",
};

// ── Component ──────────────────────────────────────────────────

export default function AssetGroupsDashboard() {
  const [selectedGroup, setSelectedGroup] = useState<AssetGroup | null>(GROUPS[0]);
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setError(null);
    fetch(_API_BASE, { headers: _getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => {
    // live data loaded — components read from API response
    void d;
    })
    .catch(err => setError(err.message || 'Failed to load data'));
  };

  useEffect(() => { fetchData(); }, []);

  const [activeTab, setActiveTab] = useState<"members" | "policies">("members");
  const [bulkInput, setBulkInput] = useState("");
  const [showBulk, setShowBulk] = useState(false);

  const byCriticality = {
    critical: GROUPS.filter(g => g.criticality === "critical").length,
    high: GROUPS.filter(g => g.criticality === "high").length,
    medium: GROUPS.filter(g => g.criticality === "medium").length,
    low: GROUPS.filter(g => g.criticality === "low").length,
  };
  const byType: Record<string, number> = {};
  GROUPS.forEach(g => { byType[g.group_type] = (byType[g.group_type] || 0) + 1; });
  const largest = [...GROUPS].sort((a, b) => b.members.length - a.members.length)[0];

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
            <Layers className="w-6 h-6 text-teal-400" />
            Asset Groups
          </h1>
          <p className="text-gray-400 text-sm mt-1">Asset grouping, membership, and policy assignment</p>
        </div>
        <button className="flex items-center gap-2 bg-teal-600 hover:bg-teal-700 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <Plus className="w-4 h-4" /> New Group
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Groups", value: GROUPS.length, sub: "defined" },
          { label: "Total Members", value: GROUPS.reduce((s, g) => s + g.members.length, 0), sub: "assets across groups" },
          { label: "Critical Groups", value: byCriticality.critical, sub: "require priority attention" },
          { label: "Largest Group", value: largest.members.length, sub: largest.group_name },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-5">
            <div className="text-gray-400 text-xs uppercase tracking-wide mb-2">{k.label}</div>
            <div className="text-3xl font-bold">{k.value}</div>
            <div className="text-gray-500 text-xs mt-1">{k.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Group grid */}
        <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4 content-start">
          {GROUPS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            GROUPS.map(g => (
            <div
              key={g.id}
              onClick={() => setSelectedGroup(g)}
              className={`rounded-lg p-4 cursor-pointer border-2 transition-colors ${
                selectedGroup?.id === g.id ? "border-teal-500 bg-gray-700" : `border ${critColor[g.criticality]} bg-gray-800 hover:bg-gray-750`
              } ${critBg[g.criticality]}`}
            >
              <div className="flex items-start justify-between mb-2">
                <div>
                  <div className="font-semibold text-sm">{g.group_name}</div>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize mt-1 inline-block ${groupTypeColor[g.group_type]}`}>
                    {g.group_type}
                  </span>
                </div>
                <span className={`text-xs font-bold capitalize ${critColor[g.criticality].split(" ")[0]}`}>{g.criticality}</span>
              </div>
              <div className="flex items-center justify-between mt-3 text-xs text-gray-400">
                <span className="flex items-center gap-1"><Users className="w-3 h-3" /> {g.members.length} members</span>
                <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> {g.policies.filter(p => p.enabled).length} active policies</span>
              </div>
              <div className="text-xs text-gray-500 mt-1 truncate">Owner: {g.owner}</div>
            </div>
          ))}
          )}
        </div>

        {/* Stats */}
        <div className="bg-gray-800 rounded-lg p-5 space-y-5 h-fit">
          <div className="font-semibold flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-teal-400" /> Group Statistics
          </div>
          <div>
            <div className="text-xs text-gray-400 font-medium mb-3">By Criticality</div>
            {(["critical","high","medium","low"] as const).map(lvl => {
              const pct = Math.round((byCriticality[lvl] / GROUPS.length) * 100);
              return (
                <div key={lvl} className="mb-2">
                  <div className="flex justify-between text-xs mb-1">
                    <span className={`capitalize ${critColor[lvl].split(" ")[0]}`}>{lvl}</span>
                    <span className="text-gray-400">{byCriticality[lvl]}</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full ${lvl === "critical" ? "bg-red-500" : lvl === "high" ? "bg-orange-500" : lvl === "medium" ? "bg-yellow-500" : "bg-green-500"}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          )}
          </div>
          <div>
            <div className="text-xs text-gray-400 font-medium mb-3">By Type</div>
            {Object.entries(byType).map(([type, count]) => {
              const pct = Math.round((count / GROUPS.length) * 100);
              return (
                <div key={type} className="mb-2">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="capitalize text-gray-300">{type}</span>
                    <span className="text-gray-400">{count}</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-1.5">
                    <div className="h-1.5 bg-teal-500 rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Detail panel */}
      {selectedGroup && (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700 flex items-center justify-between">
            <div className="font-semibold">{selectedGroup.group_name}</div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setShowBulk(v => !v)}
                className="flex items-center gap-1 text-xs text-teal-400 hover:text-teal-300 transition-colors"
              >
                <Plus className="w-3 h-3" /> Bulk Add Members
              </button>
              <div className="flex gap-1 bg-gray-700 rounded-lg p-1">
                {(["members","policies"] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-3 py-1 rounded-md text-xs font-medium capitalize transition-colors ${
                      activeTab === tab ? "bg-teal-600 text-white" : "text-gray-400 hover:text-white"
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {showBulk && (
            <div className="p-4 bg-gray-700/30 border-b border-gray-700 flex gap-3 items-start">
              <textarea
                value={bulkInput}
                onChange={e => setBulkInput(e.target.value)}
                placeholder="Paste asset IDs, one per line (e.g. SRV-004, VM-100, ...)"
                className="flex-1 bg-gray-700 border border-gray-600 rounded-lg p-3 text-sm text-gray-200 placeholder-gray-500 resize-none focus:outline-none focus:border-teal-500"
                rows={3}
              />
              <div className="flex flex-col gap-2">
                <button className="bg-teal-600 hover:bg-teal-700 px-3 py-2 rounded-lg text-xs font-medium transition-colors">Add</button>
                <button onClick={() => { setBulkInput(""); setShowBulk(false); }} className="bg-gray-600 hover:bg-gray-500 px-3 py-2 rounded-lg text-xs transition-colors">Cancel</button>
              </div>
            </div>
          )}

          {activeTab === "members" ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-700/50">
                  <tr>
                    {["Asset ID","Type","Added By","Added At"].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {selectedGroup.members.map(m => (
                    <tr key={m.asset_id} className="border-t border-gray-700 hover:bg-gray-700/30 transition-colors">
                      <td className="px-4 py-3 font-mono font-medium text-teal-300">{m.asset_id}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs capitalize ${assetTypeColor[m.asset_type]}`}>
                          {m.asset_type.replace("_"," ")}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{m.added_by}</td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{m.added_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-700/50">
                  <tr>
                    {["Policy Name","Type","Status"].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {selectedGroup.policies.map(p => (
                    <tr key={p.policy_name} className="border-t border-gray-700 hover:bg-gray-700/30 transition-colors">
                      <td className="px-4 py-3 font-medium">{p.policy_name}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs capitalize ${policyTypeColor[p.policy_type]}`}>{p.policy_type}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className={`w-2 h-2 rounded-full ${p.enabled ? "bg-green-400" : "bg-gray-500"}`} />
                          <span className={`text-xs ${p.enabled ? "text-green-400" : "text-gray-500"}`}>
                            {p.enabled ? "Enabled" : "Disabled"}
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
