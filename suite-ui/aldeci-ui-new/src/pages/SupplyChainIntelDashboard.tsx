/**
 * Supply Chain Intelligence Dashboard
 *
 * Package vulnerability tracking, malicious package detection, and SBOM analysis.
 *   1. KPIs: Tracked Packages, Vulnerable, Malicious Flags, Critical CVEs
 *   2. Malicious package alerts (8 red warning cards)
 *   3. Vulnerable packages table (15 rows)
 *   4. SBOM snapshots (6 projects)
 *   5. Package check widget (search + 5 mock results)
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Package, AlertTriangle, ShieldAlert, RefreshCw, Search, Bug, FileCheck, BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MALICIOUS_PKGS = [
  { name: "colours",           eco: "npm",   malware: "typosquat",         confidence: 98, reported: "2026-04-15", source: "Socket.dev" },
  { name: "requessts",         eco: "pypi",  malware: "typosquat",         confidence: 95, reported: "2026-04-14", source: "Snyk Intel" },
  { name: "event-source-poly", eco: "npm",   malware: "backdoor",          confidence: 99, reported: "2026-04-13", source: "OSV" },
  { name: "pycryptodome2",     eco: "pypi",  malware: "credential_stealer",confidence: 97, reported: "2026-04-12", source: "MalwareBazaar" },
  { name: "loguru-patch",      eco: "pypi",  malware: "cryptominer",       confidence: 93, reported: "2026-04-11", source: "Sonatype" },
  { name: "spring-boot-extra", eco: "maven", malware: "backdoor",          confidence: 96, reported: "2026-04-10", source: "OSV" },
  { name: "lodash.utils",      eco: "npm",   malware: "typosquat",         confidence: 91, reported: "2026-04-09", source: "Socket.dev" },
  { name: "gorilla-mux-plus",  eco: "go",    malware: "credential_stealer",confidence: 88, reported: "2026-04-08", source: "Snyk Intel" },
];

const VULN_PKGS = [
  { name: "log4j-core",          eco: "maven", ver: "2.14.1", sev: "Critical", vulns: 3,  license: "Apache-2.0", risk: "Critical" },
  { name: "requests",            eco: "pypi",  ver: "2.27.0", sev: "High",     vulns: 2,  license: "Apache-2.0", risk: "High" },
  { name: "express",             eco: "npm",   ver: "4.17.1", sev: "High",     vulns: 4,  license: "MIT",        risk: "High" },
  { name: "spring-web",          eco: "maven", ver: "5.3.18", sev: "Critical", vulns: 1,  license: "Apache-2.0", risk: "Critical" },
  { name: "axios",               eco: "npm",   ver: "0.21.1", sev: "High",     vulns: 2,  license: "MIT",        risk: "High" },
  { name: "pillow",              eco: "pypi",  ver: "8.3.1",  sev: "High",     vulns: 3,  license: "HPND",       risk: "High" },
  { name: "lodash",              eco: "npm",   ver: "4.17.20",sev: "Medium",   vulns: 5,  license: "MIT",        risk: "Medium" },
  { name: "jackson-databind",    eco: "maven", ver: "2.12.3", sev: "High",     vulns: 2,  license: "Apache-2.0", risk: "High" },
  { name: "werkzeug",            eco: "pypi",  ver: "2.0.1",  sev: "Medium",   vulns: 1,  license: "BSD-3",      risk: "Medium" },
  { name: "protobuf",            eco: "npm",   ver: "3.19.0", sev: "High",     vulns: 1,  license: "BSD-3",      risk: "High" },
  { name: "cryptography",        eco: "pypi",  ver: "36.0.0", sev: "High",     vulns: 2,  license: "Apache-2.0", risk: "High" },
  { name: "openssl",             eco: "cargo", ver: "0.10.38",sev: "Critical", vulns: 2,  license: "Apache-2.0", risk: "Critical" },
  { name: "moment",              eco: "npm",   ver: "2.29.1", sev: "Medium",   vulns: 3,  license: "MIT",        risk: "Medium" },
  { name: "sinatra",             eco: "ruby",  ver: "2.1.0",  sev: "High",     vulns: 1,  license: "MIT",        risk: "High" },
  { name: "pyyaml",              eco: "pypi",  ver: "5.4.1",  sev: "Critical", vulns: 1,  license: "MIT",        risk: "Critical" },
];

const SBOM_SNAPSHOTS = [
  { project: "aldeci-api",        deps: 214, vuln: 28, critical: 5, licenses: 2, risk: 72, taken: "2026-04-16 06:00" },
  { project: "aldeci-ui",         deps: 847, vuln: 41, critical: 3, licenses: 0, risk: 58, taken: "2026-04-16 06:00" },
  { project: "suite-feeds",       deps: 91,  vuln: 9,  critical: 1, licenses: 1, risk: 44, taken: "2026-04-16 06:00" },
  { project: "suite-attack",      deps: 63,  vuln: 7,  critical: 2, licenses: 0, risk: 61, taken: "2026-04-16 06:00" },
  { project: "trustgraph-mcp",    deps: 38,  vuln: 3,  critical: 0, licenses: 0, risk: 22, taken: "2026-04-15 06:00" },
  { project: "suite-integrations",deps: 128, vuln: 14, critical: 2, licenses: 1, risk: 49, taken: "2026-04-15 06:00" },
];

const PKG_CHECK_RESULTS = [
  { name: "lodash",      eco: "npm",   malicious: false, vulns: 5, risk: "Medium" },
  { name: "lodash.clonedeep", eco: "npm", malicious: false, vulns: 1, risk: "Low" },
  { name: "lodash.merge",eco: "npm",   malicious: false, vulns: 2, risk: "Medium" },
  { name: "lodash-es",  eco: "npm",   malicious: false, vulns: 1, risk: "Low" },
  { name: "lodash.utils",eco: "npm",   malicious: true,  vulns: 0, risk: "Critical" },
];

// ── Helpers ────────────────────────────────────────────────────

function EcoBadge({ eco }: { eco: string }) {
  const map: Record<string, string> = {
    npm:   "border-red-500/30 text-red-400 bg-red-500/10",
    pypi:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    maven: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    go:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    ruby:  "border-pink-500/30 text-pink-400 bg-pink-500/10",
    cargo: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[eco] ?? "border-border text-muted-foreground")}>{eco}</Badge>;
}

function MalwareBadge({ t }: { t: string }) {
  const map: Record<string, string> = {
    typosquat:          "border-amber-500/30 text-amber-400 bg-amber-500/10",
    backdoor:           "border-red-600/40 text-red-300 bg-red-600/15",
    credential_stealer: "border-red-500/30 text-red-400 bg-red-500/10",
    cryptominer:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[t] ?? "")}>{t.replace(/_/g, " ")}</Badge>;
}

function SevBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function RiskBadge({ r }: { r: string }) {
  return <SevBadge sev={r} />;
}

// ── Component ──────────────────────────────────────────────────

export default function SupplyChainIntelDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [query, setQuery] = useState("");
  const [searched, setSearched] = useState(false);

  const handleSearch = () => setSearched(true);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Supply Chain Intelligence"
        description="Package vulnerability tracking, malicious package detection, and SBOM analysis"
        actions={
          <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Tracked Packages" value={847} icon={Package}       trend="up" />
        <KpiCard title="Vulnerable"        value={124} icon={Bug}           trend="up"  className="border-amber-500/20" />
        <KpiCard title="Malicious Flags"   value={8}   icon={ShieldAlert}   trend="up"  className="border-red-500/20" />
        <KpiCard title="Critical CVEs"     value={23}  icon={AlertTriangle} trend="up"  className="border-red-500/20" />
      </div>

      {/* Malicious Package Alerts */}
      <Card className="border-red-500/30">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldAlert className="h-4 w-4" />
              Malicious Package Alerts
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">8 flagged</Badge>
          </div>
          <CardDescription className="text-xs">Packages flagged as malicious by threat intel sources</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {MALICIOUS_PKGS.map((pkg, i) => (
            <div key={i} className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2.5 space-y-1.5">
              <div className="flex items-center gap-2">
                <code className="text-xs font-mono text-red-300 truncate flex-1">{pkg.name}</code>
                <EcoBadge eco={pkg.eco} />
              </div>
              <MalwareBadge t={pkg.malware} />
              <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                <span>Confidence: <span className="text-red-400 font-bold">{pkg.confidence}%</span></span>
              </div>
              <div className="text-[10px] text-muted-foreground truncate">
                {pkg.source} · {pkg.reported}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Vulnerable Packages Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Bug className="h-4 w-4 text-amber-400" />
            Vulnerable Packages
          </CardTitle>
          <CardDescription className="text-xs">Packages with known CVEs sorted by severity</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Package</TableHead>
                  <TableHead className="text-[11px] h-8">Ecosystem</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Vulns</TableHead>
                  <TableHead className="text-[11px] h-8">License</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {VULN_PKGS.map((p, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{p.name}</TableCell>
                    <TableCell className="py-2.5"><EcoBadge eco={p.eco} /></TableCell>
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{p.ver}</TableCell>
                    <TableCell className="py-2.5"><SevBadge sev={p.sev} /></TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 font-bold">{p.vulns}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{p.license}</TableCell>
                    <TableCell className="py-2.5"><RiskBadge r={p.risk} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-green-500/30 text-green-400 hover:bg-green-500/10">
                        Patch
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* SBOM Snapshots + Package Check side by side */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* SBOM Snapshots */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileCheck className="h-4 w-4 text-green-400" />
              SBOM Snapshots
            </CardTitle>
            <CardDescription className="text-xs">Latest dependency snapshots per project</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {SBOM_SNAPSHOTS.map((snap, i) => (
              <div key={i} className="rounded-lg border border-border bg-muted/10 px-3 py-2.5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium font-mono">{snap.project}</span>
                  <span className="text-[10px] text-muted-foreground">{snap.taken}</span>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] text-muted-foreground">{snap.deps} deps</span>
                  <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{snap.vuln} vuln</Badge>
                  {snap.critical > 0 && (
                    <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{snap.critical} critical</Badge>
                  )}
                  {snap.licenses > 0 && (
                    <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">{snap.licenses} license issues</Badge>
                  )}
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] text-muted-foreground">
                    <span>Risk Score</span>
                    <span className={cn("font-bold", snap.risk >= 70 ? "text-red-400" : snap.risk >= 50 ? "text-amber-400" : "text-green-400")}>
                      {snap.risk}
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <div
                      className={cn("h-full rounded-full", snap.risk >= 70 ? "bg-red-500" : snap.risk >= 50 ? "bg-amber-500" : "bg-green-500")}
                      style={{ width: `${snap.risk}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Package Check Widget */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Search className="h-4 w-4 text-blue-400" />
              Package Intel Lookup
            </CardTitle>
            <CardDescription className="text-xs">Check any package for malicious flags and vulnerabilities</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Search package name…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="flex-1 h-8 rounded-md border border-border bg-background px-3 text-xs focus:outline-none focus:ring-1 focus:ring-primary text-foreground placeholder:text-muted-foreground"
              />
              <Button size="sm" className="h-8 px-3 text-xs" onClick={handleSearch}>
                <Search className="h-3.5 w-3.5" />
              </Button>
            </div>

            {/* Mock results — always shown as demo */}
            <div className="space-y-2">
              <p className="text-[10px] text-muted-foreground">Showing results for "lodash"</p>
              {PKG_CHECK_RESULTS.map((r, i) => (
                <div key={i} className={cn(
                  "flex items-center justify-between rounded-lg border px-3 py-2",
                  r.malicious ? "border-red-500/30 bg-red-500/5" : "border-border bg-muted/10"
                )}>
                  <div className="flex items-center gap-2 min-w-0">
                    <code className="text-xs font-mono truncate">{r.name}</code>
                    <EcoBadge eco={r.eco} />
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    {r.malicious && (
                      <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Malicious</Badge>
                    )}
                    {r.vulns > 0 && (
                      <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{r.vulns} CVEs</Badge>
                    )}
                    <RiskBadge r={r.risk} />
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-lg border border-border bg-muted/10 p-3 space-y-1">
              <p className="text-[10px] font-medium text-muted-foreground">Intel Sources</p>
              <div className="flex flex-wrap gap-1">
                {["OSV", "NVD", "Snyk Intel", "Socket.dev", "Sonatype", "MalwareBazaar"].map((s) => (
                  <Badge key={s} className="text-[10px] border border-border text-muted-foreground">{s}</Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
