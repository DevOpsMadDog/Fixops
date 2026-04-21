/**
 * SBOM Export Dashboard
 *
 * Software Bill of Materials export with CycloneDX / SPDX support.
 *   1. KPIs: total projects, total components, open vulns, critical vulns
 *   2. Project summary cards
 *   3. Component table with ecosystem / license / vuln count
 *   4. Vuln list per component
 *   5. Export buttons (CycloneDX / SPDX)
 *   6. Export history table
 *
 * Route: /sbom-export
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/sbom-export";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { motion } from "framer-motion";
import { Package, Shield, Download, Search, FileText, AlertTriangle, CheckCircle } from "lucide-react";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_PROJECTS = [
  { id: "proj-001", project_name: "suite-api",      component_count: 142, vuln_count: 23, critical_vulns: 3, latest_export: "2026-04-16T08:00:00Z" },
  { id: "proj-002", project_name: "suite-core",     component_count: 218, vuln_count: 41, critical_vulns: 7, latest_export: "2026-04-16T07:30:00Z" },
  { id: "proj-003", project_name: "suite-ui",       component_count: 334, vuln_count: 12, critical_vulns: 1, latest_export: "2026-04-15T22:00:00Z" },
  { id: "proj-004", project_name: "suite-feeds",    component_count:  67, vuln_count:  8, critical_vulns: 2, latest_export: "2026-04-15T20:00:00Z" },
  { id: "proj-005", project_name: "suite-attack",   component_count:  89, vuln_count: 16, critical_vulns: 4, latest_export: "2026-04-15T18:00:00Z" },
];

const MOCK_COMPONENTS = [
  { id: "cmp-001", component_name: "fastapi",       version: "0.110.0", ecosystem: "PyPI",    license: "MIT",          vuln_count: 0, purl: "pkg:pypi/fastapi@0.110.0" },
  { id: "cmp-002", component_name: "cryptography",  version: "41.0.7",  ecosystem: "PyPI",    license: "Apache-2.0",   vuln_count: 2, purl: "pkg:pypi/cryptography@41.0.7" },
  { id: "cmp-003", component_name: "requests",      version: "2.31.0",  ecosystem: "PyPI",    license: "Apache-2.0",   vuln_count: 1, purl: "pkg:pypi/requests@2.31.0" },
  { id: "cmp-004", component_name: "react",         version: "19.0.0",  ecosystem: "npm",     license: "MIT",          vuln_count: 0, purl: "pkg:npm/react@19.0.0" },
  { id: "cmp-005", component_name: "lodash",        version: "4.17.20", ecosystem: "npm",     license: "MIT",          vuln_count: 3, purl: "pkg:npm/lodash@4.17.20" },
  { id: "cmp-006", component_name: "log4j-core",   version: "2.14.1",  ecosystem: "Maven",   license: "Apache-2.0",   vuln_count: 5, purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },
  { id: "cmp-007", component_name: "openssl",       version: "3.1.4",   ecosystem: "OS",      license: "OpenSSL",      vuln_count: 1, purl: "pkg:generic/openssl@3.1.4" },
  { id: "cmp-008", component_name: "pydantic",      version: "2.6.1",   ecosystem: "PyPI",    license: "MIT",          vuln_count: 0, purl: "pkg:pypi/pydantic@2.6.1" },
];

const MOCK_VULNS: Record<string, { cve_id: string; severity: string; cvss_score: number; fixed_in: string; patched: boolean }[]> = {
  "cmp-002": [
    { cve_id: "CVE-2024-26130", severity: "high",     cvss_score: 7.5, fixed_in: "42.0.0", patched: false },
    { cve_id: "CVE-2023-49083", severity: "medium",   cvss_score: 5.3, fixed_in: "41.0.8", patched: false },
  ],
  "cmp-003": [
    { cve_id: "CVE-2024-35195", severity: "medium",   cvss_score: 5.9, fixed_in: "2.32.0", patched: false },
  ],
  "cmp-005": [
    { cve_id: "CVE-2021-23337", severity: "high",     cvss_score: 7.2, fixed_in: "4.17.21", patched: true },
    { cve_id: "CVE-2020-28500", severity: "medium",   cvss_score: 5.3, fixed_in: "4.17.21", patched: true },
    { cve_id: "CVE-2019-10744", severity: "critical",  cvss_score: 9.1, fixed_in: "4.17.12", patched: true },
  ],
  "cmp-006": [
    { cve_id: "CVE-2021-44228", severity: "critical",  cvss_score: 10.0, fixed_in: "2.15.0", patched: false },
    { cve_id: "CVE-2021-45046", severity: "critical",  cvss_score: 9.0,  fixed_in: "2.16.0", patched: false },
    { cve_id: "CVE-2021-44832", severity: "medium",    cvss_score: 6.6,  fixed_in: "2.17.1", patched: false },
    { cve_id: "CVE-2021-45105", severity: "high",      cvss_score: 7.5,  fixed_in: "2.17.0", patched: false },
    { cve_id: "CVE-2022-23302",  severity: "medium",    cvss_score: 6.5,  fixed_in: "2.17.1", patched: false },
  ],
  "cmp-007": [
    { cve_id: "CVE-2024-0727", severity: "medium",    cvss_score: 5.5, fixed_in: "3.1.5", patched: false },
  ],
};

const MOCK_HISTORY = [
  { id: "exp-001", format: "CycloneDX", version_tag: "v1.4", component_count: 218, generated_at: "2026-04-16T08:00:00Z", exported_by: "alice@aldeci.io" },
  { id: "exp-002", format: "SPDX",      version_tag: "2.3",  component_count: 218, generated_at: "2026-04-16T07:45:00Z", exported_by: "bob@aldeci.io" },
  { id: "exp-003", format: "CycloneDX", version_tag: "v1.4", component_count: 334, generated_at: "2026-04-15T22:00:00Z", exported_by: "carol@aldeci.io" },
  { id: "exp-004", format: "SPDX",      version_tag: "2.3",  component_count: 142, generated_at: "2026-04-15T20:00:00Z", exported_by: "alice@aldeci.io" },
  { id: "exp-005", format: "CycloneDX", version_tag: "v1.6", component_count:  89, generated_at: "2026-04-15T18:00:00Z", exported_by: "david@aldeci.io" },
];

// ── Helpers ────────────────────────────────────────────────────

function fmt(iso: string) {
  return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    low:      "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium capitalize", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}

function EcoBadge({ eco }: { eco: string }) {
  const cls: Record<string, string> = {
    PyPI:  "bg-blue-500/20 text-blue-400",
    npm:   "bg-red-500/20 text-red-400",
    Maven: "bg-orange-500/20 text-orange-400",
    OS:    "bg-purple-500/20 text-purple-400",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", cls[eco] ?? "bg-gray-700 text-gray-300")}>{eco}</span>;
}

function FormatBadge({ fmt: f }: { fmt: string }) {
  const cls = f === "CycloneDX" ? "bg-cyan-500/20 text-cyan-400" : "bg-emerald-500/20 text-emerald-400";
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", cls)}>{f}</span>;
}

function KpiCard({ icon: Icon, label, value, sub, color }: { icon: React.ElementType; label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className="bg-gray-800 rounded-lg p-6 flex items-start gap-4">
      <div className={cn("p-3 rounded-lg", color)}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-gray-400 text-sm">{label}</p>
        <p className="text-2xl font-bold text-white mt-0.5">{value}</p>
        {sub && <p className="text-gray-500 text-xs mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function SBOMExportDashboard() {
  const [search, setSearch] = useState("");
  useEffect(() => {
    fetch(`${_API_BASE}/projects?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setSelectedProject(d); })
      .catch(() => { /* graceful fallback */ });
  }, []);
  const [selectedProject, setSelectedProject] = useState(MOCK_PROJECTS[1]);
  const [expandedComp, setExpandedComp] = useState<string | null>(null);
  const [exportMsg, setExportMsg] = useState("");

  const filteredComponents = MOCK_COMPONENTS.filter(c =>
    c.component_name.toLowerCase().includes(search.toLowerCase()) ||
    c.ecosystem.toLowerCase().includes(search.toLowerCase())
  );

  const totalComponents = MOCK_PROJECTS.reduce((s, p) => s + p.component_count, 0);
  const totalVulns      = MOCK_PROJECTS.reduce((s, p) => s + p.vuln_count, 0);
  const totalCritical   = MOCK_PROJECTS.reduce((s, p) => s + p.critical_vulns, 0);

  function handleExport(format: string) {
    setExportMsg(`Generating ${format} export for "${selectedProject.project_name}"…`);
    setTimeout(() => setExportMsg(`${format} export ready — ${selectedProject.component_count} components`), 1500);
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Package className="w-6 h-6 text-cyan-400" /> SBOM Export</h1>
          <p className="text-gray-400 text-sm mt-1">Software Bill of Materials — CycloneDX / SPDX generation</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => handleExport("CycloneDX")} className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
            <Download className="w-4 h-4" /> Generate CycloneDX
            <span className="bg-cyan-800 text-cyan-200 text-[10px] px-1.5 py-0.5 rounded">v1.6</span>
          </button>
          <button onClick={() => handleExport("SPDX")} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
            <Download className="w-4 h-4" /> Generate SPDX
            <span className="bg-emerald-800 text-emerald-200 text-[10px] px-1.5 py-0.5 rounded">2.3</span>
          </button>
        </div>
      </div>

      {exportMsg && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 px-4 py-3 rounded-lg text-sm flex items-center gap-2">
          <FileText className="w-4 h-4" /> {exportMsg}
        </motion.div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard icon={Package}       title="Total Projects"    value={MOCK_PROJECTS.length} sub="active repositories"        color="bg-cyan-500/20 text-cyan-400" />
        <KpiCard icon={FileText}      title="Total Components"  value={totalComponents.toLocaleString()} sub="unique packages"  color="bg-blue-500/20 text-blue-400" />
        <KpiCard icon={AlertTriangle} title="Open Vulns"        value={totalVulns}            sub="across all projects"        color="bg-orange-500/20 text-orange-400" />
        <KpiCard icon={Shield}        title="Critical Vulns"    value={totalCritical}          sub="require immediate action"   color="bg-red-500/20 text-red-400" />
      </div>

      {/* Project Cards */}
      <div>
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">Projects</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {MOCK_PROJECTS.map(p => (
            <button key={p.id} onClick={() => setSelectedProject(p)}
              className={cn("bg-gray-800 rounded-lg p-4 text-left transition-all border",
                selectedProject.id === p.id ? "border-cyan-500/60" : "border-transparent hover:border-gray-600")}>
              <p className="font-semibold text-white text-sm truncate">{p.project_name}</p>
              <p className="text-gray-400 text-xs mt-1">{p.component_count} components</p>
              <div className="flex gap-3 mt-2">
                <span className="text-orange-400 text-xs">{p.vuln_count} vulns</span>
                {p.critical_vulns > 0 && <span className="text-red-400 text-xs font-bold">{p.critical_vulns} critical</span>}
              </div>
              <p className="text-gray-600 text-[10px] mt-1">Exported {fmt(p.latest_export)}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Component Table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
            Components — <span className="text-cyan-400">{selectedProject.project_name}</span>
          </h2>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Filter components…"
              className="bg-gray-900 border border-gray-700 rounded-lg pl-9 pr-4 py-1.5 text-sm text-white placeholder-gray-500 w-56 focus:outline-none focus:border-cyan-500" />
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-4">Component</th>
                <th className="text-left pb-2 pr-4">Version</th>
                <th className="text-left pb-2 pr-4">Ecosystem</th>
                <th className="text-left pb-2 pr-4">License</th>
                <th className="text-left pb-2 pr-4">Vulns</th>
                <th className="text-left pb-2">PURL</th>
              </tr>
            </thead>
            <tbody>
              {filteredComponents.map(c => (
                <>
                  <tr key={c.id} className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                    onClick={() => setExpandedComp(expandedComp === c.id ? null : c.id)}>
                    <td className="py-2.5 pr-4 font-mono text-white">{c.component_name}</td>
                    <td className="py-2.5 pr-4 text-gray-300">{c.version}</td>
                    <td className="py-2.5 pr-4"><EcoBadge eco={c.ecosystem} /></td>
                    <td className="py-2.5 pr-4 text-gray-400 text-xs">{c.license}</td>
                    <td className="py-2.5 pr-4">
                      {c.vuln_count > 0
                        ? <span className="text-red-400 font-bold">{c.vuln_count}</span>
                        : <CheckCircle className="w-4 h-4 text-emerald-500" />}
                    </td>
                    <td className="py-2.5 text-gray-500 text-xs font-mono truncate max-w-[220px]">{c.purl}</td>
                  </tr>
                  {expandedComp === c.id && MOCK_VULNS[c.id] && (
                    <tr key={`${c.id}-vulns`}>
                      <td colSpan={6} className="bg-gray-900/60 px-6 py-3">
                        <p className="text-xs text-gray-400 font-semibold mb-2">Vulnerabilities in {c.component_name}</p>
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="text-gray-600 uppercase">
                              <th className="text-left pb-1 pr-4">CVE ID</th>
                              <th className="text-left pb-1 pr-4">Severity</th>
                              <th className="text-left pb-1 pr-4">CVSS</th>
                              <th className="text-left pb-1 pr-4">Fixed In</th>
                              <th className="text-left pb-1">Patched</th>
                            </tr>
                          </thead>
                          <tbody>
                            {MOCK_VULNS[c.id].map(v => (
                              <tr key={v.cve_id} className="border-t border-gray-700/30">
                                <td className="py-1 pr-4 font-mono text-cyan-300">{v.cve_id}</td>
                                <td className="py-1 pr-4"><SeverityBadge s={v.severity} /></td>
                                <td className="py-1 pr-4 text-white font-bold">{v.cvss_score.toFixed(1)}</td>
                                <td className="py-1 pr-4 text-gray-400">{v.fixed_in}</td>
                                <td className="py-1">
                                  {v.patched
                                    ? <span className="text-emerald-400 font-semibold">Yes</span>
                                    : <span className="text-red-400 font-semibold">No</span>}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Export History */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Export History</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                <th className="text-left pb-2 pr-4">Format</th>
                <th className="text-left pb-2 pr-4">Version</th>
                <th className="text-left pb-2 pr-4">Components</th>
                <th className="text-left pb-2 pr-4">Generated At</th>
                <th className="text-left pb-2">Exported By</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_HISTORY.map(h => (
                <tr key={h.id} className="border-b border-gray-700/50 hover:bg-gray-700/20">
                  <td className="py-2.5 pr-4"><FormatBadge fmt={h.format} /></td>
                  <td className="py-2.5 pr-4 text-gray-300 font-mono text-xs">{h.version_tag}</td>
                  <td className="py-2.5 pr-4 text-white font-semibold">{h.component_count}</td>
                  <td className="py-2.5 pr-4 text-gray-400 text-xs">{fmt(h.generated_at)}</td>
                  <td className="py-2.5 text-gray-400 text-xs">{h.exported_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
