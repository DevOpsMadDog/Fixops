/**
 * Security Dependency Risk Dashboard
 *
 * Ecosystem tabs (npm/pypi/maven/nuget/cargo/go), risky deps table with risk_score bars,
 * vulnerability list with patch buttons, license conflicts panel,
 * dependency summary cards, transitive graph panel.
 *
 * Route: /dependency-risk
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/dependency-risk";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { Package, AlertTriangle, Shield, CheckCircle, AlertOctagon } from "lucide-react";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────────────────────

type Ecosystem = "npm" | "pypi" | "maven" | "nuget" | "cargo" | "go";

const ECOSYSTEMS: Ecosystem[] = ["npm", "pypi", "maven", "nuget", "cargo", "go"];

const MOCK_DEPS: Array<{
  id: string; package_name: string; version: string; ecosystem: Ecosystem;
  risk_score: number; vuln_count: number; critical_vuln_count: number; license: string;
}> = [
  { id: "d-001", package_name: "log4j-core",         version: "2.14.1", ecosystem: "maven",  risk_score: 9.8, vuln_count: 4, critical_vuln_count: 2, license: "Apache-2.0" },
  { id: "d-002", package_name: "lodash",              version: "4.17.15",ecosystem: "npm",    risk_score: 7.2, vuln_count: 3, critical_vuln_count: 1, license: "MIT"        },
  { id: "d-003", package_name: "flask",               version: "1.1.4",  ecosystem: "pypi",   risk_score: 6.8, vuln_count: 2, critical_vuln_count: 0, license: "BSD-3"      },
  { id: "d-004", package_name: "newtonsoft.json",     version: "12.0.3", ecosystem: "nuget",  risk_score: 5.1, vuln_count: 1, critical_vuln_count: 0, license: "MIT"        },
  { id: "d-005", package_name: "openssl",             version: "1.1.1q", ecosystem: "cargo",  risk_score: 8.4, vuln_count: 3, critical_vuln_count: 2, license: "OpenSSL"    },
  { id: "d-006", package_name: "google.golang.org/grpc",version:"1.53.0",ecosystem: "go",     risk_score: 4.3, vuln_count: 1, critical_vuln_count: 0, license: "Apache-2.0" },
  { id: "d-007", package_name: "express",             version: "4.17.3", ecosystem: "npm",    risk_score: 6.1, vuln_count: 2, critical_vuln_count: 0, license: "MIT"        },
  { id: "d-008", package_name: "cryptography",        version: "38.0.1", ecosystem: "pypi",   risk_score: 7.9, vuln_count: 2, critical_vuln_count: 1, license: "Apache-2.0" },
  { id: "d-009", package_name: "commons-text",        version: "1.9.0",  ecosystem: "maven",  risk_score: 9.1, vuln_count: 3, critical_vuln_count: 2, license: "Apache-2.0" },
  { id: "d-010", package_name: "moment",              version: "2.29.3", ecosystem: "npm",    risk_score: 3.8, vuln_count: 1, critical_vuln_count: 0, license: "MIT"        },
];

const MOCK_VULNS = [
  { id: "v-001", dep_id: "d-001", cve_id: "CVE-2021-44228", severity: "critical", cvss_score: 10.0, fixed_version: "2.17.0", patched: false },
  { id: "v-002", dep_id: "d-001", cve_id: "CVE-2021-45046", severity: "critical", cvss_score: 9.0,  fixed_version: "2.16.0", patched: false },
  { id: "v-003", dep_id: "d-002", cve_id: "CVE-2021-23337", severity: "high",     cvss_score: 7.2,  fixed_version: "4.17.21",patched: true  },
  { id: "v-004", dep_id: "d-005", cve_id: "CVE-2022-0778",  severity: "high",     cvss_score: 7.5,  fixed_version: "1.1.1n", patched: false },
  { id: "v-005", dep_id: "d-009", cve_id: "CVE-2022-42889", severity: "critical", cvss_score: 9.8,  fixed_version: "1.10.0", patched: false },
  { id: "v-006", dep_id: "d-008", cve_id: "CVE-2023-23931", severity: "high",     cvss_score: 7.4,  fixed_version: "39.0.1", patched: true  },
  { id: "v-007", dep_id: "d-003", cve_id: "CVE-2023-30861", severity: "high",     cvss_score: 7.5,  fixed_version: "2.3.2",  patched: false },
];

const MOCK_LICENSE_CONFLICTS = [
  { package_name: "gpl-library",   license_name: "GPL-3.0",  risk_level: "high",     copyleft: true  },
  { package_name: "agpl-service",  license_name: "AGPL-3.0", risk_level: "critical",  copyleft: true  },
  { package_name: "lgpl-util",     license_name: "LGPL-2.1", risk_level: "medium",   copyleft: true  },
  { package_name: "proprietary-sdk",license_name: "Proprietary",risk_level:"high",   copyleft: false },
];

const MOCK_TRANSITIVE = [
  { parent: "log4j-core",   children: ["log4j-api", "disruptor", "jackson-core"] },
  { parent: "lodash",       children: ["lodash-merge", "lodash-get"] },
  { parent: "openssl",      children: ["zlib", "libcrypto"] },
  { parent: "commons-text", children: ["commons-lang3", "commons-io"] },
];

const SUMMARY = { total: 847, direct: 124, transitive: 723, high_risk: 31 };

// ── Helpers ────────────────────────────────────────────────────────────────────

function riskColor(score: number) {
  if (score >= 7) return "#ef4444";
  if (score >= 5) return "#f97316";
  if (score >= 3) return "#eab308";
  return "#22c55e";
}

function RiskBar({ score }: { score: number }) {
  const color = riskColor(score);
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 bg-gray-700 rounded-full h-2">
        <div className="h-2 rounded-full" style={{ width: `${(score / 10) * 100}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-mono w-8 text-right" style={{ color }}>{score.toFixed(1)}</span>
    </div>
  );
}

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    low:      "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}

function EcoBadge({ e }: { e: string }) {
  const cls: Record<string, string> = {
    npm:    "bg-red-500/20 text-red-300",
    pypi:   "bg-blue-500/20 text-blue-300",
    maven:  "bg-orange-500/20 text-orange-300",
    nuget:  "bg-purple-500/20 text-purple-300",
    cargo:  "bg-yellow-500/20 text-yellow-300",
    go:     "bg-teal-500/20 text-teal-300",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[e] ?? "bg-gray-700 text-gray-300")}>{e}</span>;
}

function LicenseRiskBadge({ level }: { level: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[level] ?? "bg-gray-700 text-gray-300")}>{level}</span>;
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function SecurityDependencyRiskDashboard() {
  const [activeEco, setActiveEco] = useState<"All" | Ecosystem>("All");
  const [vulns, setVulns] = useState(MOCK_VULNS);
  useEffect(() => {
    fetch(_API_BASE, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setVulns(d); })
      .catch(() => { setError('Failed to load data'); });
  }, []);

  const filteredDeps = activeEco === "All"
    ? MOCK_DEPS
    : MOCK_DEPS.filter(d => d.ecosystem === activeEco);

  const filteredDepsIds = new Set(filteredDeps.map(d => d.id));
  const filteredVulns = vulns.filter(v => filteredDepsIds.has(v.dep_id));

  function patchVuln(id: string) {
    setVulns(prev => prev.map(v => v.id === id ? { ...v, patched: true } : v));
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-yellow-500/10 rounded-lg">
          <Package className="w-6 h-6 text-yellow-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">Dependency Risk</h1>
          <p className="text-sm text-gray-400">Software composition analysis across all ecosystems</p>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Dependencies", value: SUMMARY.total,       color: "text-white",      icon: <Package className="w-5 h-5 text-gray-400" /> },
          { label: "Direct",             value: SUMMARY.direct,      color: "text-blue-400",   icon: <Shield className="w-5 h-5 text-blue-400" /> },
          { label: "Transitive",         value: SUMMARY.transitive,  color: "text-purple-400", icon: <Package className="w-5 h-5 text-purple-400" /> },
          { label: "High Risk",          value: SUMMARY.high_risk,   color: "text-red-400",    icon: <AlertOctagon className="w-5 h-5 text-red-400" /> },
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

      {/* Ecosystem tabs */}
      <div className="flex gap-2 flex-wrap">
        {(["All", ...ECOSYSTEMS] as Array<"All" | Ecosystem>).map(e => (
          <button
            key={e}
            onClick={() => setActiveEco(e)}
            className={cn(
              "px-3 py-1.5 rounded-lg text-sm font-medium transition-all",
              activeEco === e ? "bg-yellow-600 text-white" : "bg-gray-800 text-gray-400 hover:bg-gray-700"
            )}
          >
            {e}
          </button>
        ))}
      </div>

      {/* Risky dependencies table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Risky Dependencies ({filteredDeps.length})</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                {["Package", "Version", "Ecosystem", "Risk Score", "Vulns", "Critical", "License"].map(h => (
                  <th key={h} className="text-left text-gray-400 font-medium py-2 pr-4 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredDeps.sort((a, b) => b.risk_score - a.risk_score).map(d => (
                <tr key={d.id} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4 font-mono text-sm text-white">{d.package_name}</td>
                  <td className="py-2.5 pr-4 text-xs text-gray-400 font-mono">{d.version}</td>
                  <td className="py-2.5 pr-4"><EcoBadge e={d.ecosystem} /></td>
                  <td className="py-2.5 pr-4 min-w-[130px]"><RiskBar score={d.risk_score} /></td>
                  <td className="py-2.5 pr-4 text-center text-yellow-400">{d.vuln_count}</td>
                  <td className="py-2.5 pr-4 text-center text-red-400 font-bold">{d.critical_vuln_count}</td>
                  <td className="py-2.5 text-xs text-gray-400">{d.license}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Vuln list + License conflicts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability list */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Vulnerabilities ({filteredVulns.length})</h2>
          <div className="space-y-2">
            {filteredVulns.map(v => {
              const dep = MOCK_DEPS.find(d => d.id === v.dep_id);
              return (
                <div key={v.id} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-blue-300">{v.cve_id}</span>
                      <SeverityBadge s={v.severity} />
                      <span className="text-xs text-gray-500 font-mono">CVSS {v.cvss_score.toFixed(1)}</span>
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5">
                      {dep?.package_name} · fix: {v.fixed_version}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 ml-4 flex-shrink-0">
                    {v.patched
                      ? <span className="flex items-center gap-1 px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-medium">
                          <CheckCircle className="w-3 h-3" /> patched
                        </span>
                      : <>
                          <span className="flex items-center gap-1 px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs font-medium">
                            pending
                          </span>
                          <button onClick={() => patchVuln(v.id)} className="px-2 py-0.5 bg-blue-600/40 hover:bg-blue-600/70 text-blue-300 rounded text-xs">
                            Patch
                          </button>
                        </>
                    }
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* License conflicts + transitive graph */}
        <div className="space-y-4">
          {/* License conflicts */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              <h2 className="text-lg font-semibold text-white">License Conflicts</h2>
            </div>
            <div className="space-y-2">
              {MOCK_LICENSE_CONFLICTS.map(l => (
                <div key={l.package_name} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
                  <div>
                    <p className="text-sm font-medium text-white">{l.package_name}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-xs text-gray-400">{l.license_name}</span>
                      {l.copyleft && (
                        <span className="text-xs text-red-400 flex items-center gap-0.5">
                          <AlertOctagon className="w-3 h-3" /> copyleft
                        </span>
                      )}
                    </div>
                  </div>
                  <LicenseRiskBadge level={l.risk_level} />
                </div>
              ))}
            </div>
          </div>

          {/* Transitive graph */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Transitive Dependencies</h2>
            <div className="space-y-3">
              {MOCK_TRANSITIVE.map(t => (
                <div key={t.parent}>
                  <div className="flex items-center gap-2 text-sm mb-1">
                    <Package className="w-3.5 h-3.5 text-yellow-400" />
                    <span className="font-mono text-yellow-300">{t.parent}</span>
                  </div>
                  <div className="ml-5 space-y-1">
                    {t.children.map(c => (
                      <div key={c} className="flex items-center gap-2 text-xs text-gray-400">
                        <span className="text-gray-600">└─</span>
                        <span className="font-mono text-gray-300">{c}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
