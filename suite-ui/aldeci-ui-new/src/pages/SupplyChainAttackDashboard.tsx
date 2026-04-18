/**
 * Supply Chain Attack Dashboard
 *
 * Package ecosystem attack detection and malicious dependency tracking.
 *   1. KPI cards: Total Packages, Suspicious Packages, Malicious Packages, Critical Detections
 *   2. Packages table
 *   3. Detections table
 *
 * API: GET /api/v1/supply-chain-attacks/{stats,packages,detections}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Package, RefreshCw, AlertTriangle, ShieldAlert, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Interfaces ─────────────────────────────────────────────────

interface SupplyChainStats {
  total_packages: number;
  suspicious_packages: number;
  malicious_packages: number;
  critical_detections: number;
}

interface SupplyChainPackage {
  package_name: string;
  ecosystem: string;
  version: string;
  attack_type: string;
  status: string;
  risk_score: number;
}

interface SupplyChainDetection {
  detection_type: string;
  severity: string;
  confidence_score: number;
  status: string;
  package_id: string;
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS: SupplyChainStats = {
  total_packages:      4821,
  suspicious_packages: 34,
  malicious_packages:  7,
  critical_detections: 3,
};

const MOCK_PACKAGES: SupplyChainPackage[] = [
  { package_name: "lodash",       ecosystem: "npm",   version: "4.17.21", attack_type: "none",           status: "clean",      risk_score: 5  },
  { package_name: "event-stream", ecosystem: "npm",   version: "3.3.6",   attack_type: "malicious_code", status: "malicious",  risk_score: 98 },
  { package_name: "colors",       ecosystem: "npm",   version: "1.4.44",  attack_type: "protestware",    status: "suspicious", risk_score: 72 },
  { package_name: "PyYAML",       ecosystem: "pypi",  version: "5.3.1",   attack_type: "deserialization",status: "suspicious", risk_score: 55 },
  { package_name: "ua-parser-js", ecosystem: "npm",   version: "0.7.29",  attack_type: "malicious_code", status: "malicious",  risk_score: 95 },
  { package_name: "requests",     ecosystem: "pypi",  version: "2.31.0",  attack_type: "none",           status: "clean",      risk_score: 8  },
  { package_name: "log4j-core",   ecosystem: "maven", version: "2.14.1",  attack_type: "rce",            status: "malicious",  risk_score: 99 },
];

const MOCK_DETECTIONS: SupplyChainDetection[] = [
  { detection_type: "Malicious code injection", severity: "critical", confidence_score: 97, status: "confirmed", package_id: "event-stream@3.3.6"  },
  { detection_type: "Typosquatting",            severity: "high",     confidence_score: 82, status: "open",      package_id: "lod4sh@4.17.21"       },
  { detection_type: "Dependency confusion",     severity: "critical", confidence_score: 91, status: "confirmed", package_id: "internal-utils@1.0.0" },
  { detection_type: "Protestware payload",      severity: "high",     confidence_score: 75, status: "open",      package_id: "colors@1.4.44"        },
  { detection_type: "Obfuscated post-install",  severity: "medium",   confidence_score: 65, status: "reviewing", package_id: "build-helper@2.1.0"   },
  { detection_type: "Log4Shell RCE vector",     severity: "critical", confidence_score: 99, status: "confirmed", package_id: "log4j-core@2.14.1"    },
];

// ── Badge helpers ──────────────────────────────────────────────

function EcosystemBadge({ ecosystem }: { ecosystem: string }) {
  const map: Record<string, string> = {
    npm:   "border-red-500/30 text-red-400 bg-red-500/10",
    pypi:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    maven: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    gems:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    go:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[ecosystem] ?? "border-border text-muted-foreground")}>
      {ecosystem}
    </Badge>
  );
}

function PackageStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    clean:      "border-green-500/30 text-green-400 bg-green-500/10",
    suspicious: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    malicious:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function DetectionStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    confirmed: "border-red-500/30 text-red-400 bg-red-500/10",
    open:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    reviewing: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    dismissed: "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function SupplyChainAttackDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    stats: SupplyChainStats | null;
    packages: SupplyChainPackage[] | null;
    detections: SupplyChainDetection[] | null;
  }>({ stats: null, packages: null, detections: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/supply-chain-attacks/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/supply-chain-attacks/packages?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/supply-chain-attacks/detections?org_id=${ORG_ID}`),
    ]).then(([statsRes, packagesRes, detectionsRes]) => {
      setLiveData({
        stats:      statsRes.status      === "fulfilled" ? statsRes.value      : null,
        packages:   packagesRes.status   === "fulfilled" ? packagesRes.value   : null,
        detections: detectionsRes.status === "fulfilled" ? detectionsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? MOCK_STATS;
  const packages   = liveData.packages   ?? MOCK_PACKAGES;
  const detections = liveData.detections ?? MOCK_DETECTIONS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Supply Chain Attacks"
        description="Package ecosystem attack detection — typosquatting, dependency confusion, malicious code"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Packages"      value={stats.total_packages}      icon={Package}       trend="flat" />
        <KpiCard title="Suspicious"          value={stats.suspicious_packages} icon={AlertTriangle} trend="down" className="border-amber-500/20" />
        <KpiCard title="Malicious"           value={stats.malicious_packages}  icon={XCircle}       trend="down" className="border-red-500/20" />
        <KpiCard title="Critical Detections" value={stats.critical_detections} icon={ShieldAlert}   trend="down" className="border-red-500/20" />
      </div>

      {/* Packages Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Package className="h-4 w-4 text-blue-400" />
              Package Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {packages.length} packages
            </Badge>
          </div>
          <CardDescription className="text-xs">Tracked packages with attack classification and risk scores</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Package Name</TableHead>
                  <TableHead className="text-[11px] h-8">Ecosystem</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8">Attack Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Risk Score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {packages.map((p: SupplyChainPackage, i: number) => (
                  <TableRow key={p.package_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{p.package_name}</TableCell>
                    <TableCell className="py-2"><EcosystemBadge ecosystem={p.ecosystem ?? "npm"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{p.version}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{p.attack_type === "none" ? "—" : p.attack_type.replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><PackageStatusBadge status={p.status ?? "clean"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-right">
                      <span className={p.risk_score >= 80 ? "text-red-400" : p.risk_score >= 50 ? "text-amber-400" : "text-green-400"}>
                        {p.risk_score}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Detections Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldAlert className="h-4 w-4" />
              Attack Detections
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {detections.filter((d: SupplyChainDetection) => d.status === "confirmed").length} confirmed
            </Badge>
          </div>
          <CardDescription className="text-xs">Supply chain attack detections with confidence scoring</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Detection Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Package</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detections.map((d: SupplyChainDetection, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{d.detection_type}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={d.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-right">
                      <span className={d.confidence_score >= 85 ? "text-red-400" : d.confidence_score >= 65 ? "text-amber-400" : "text-green-400"}>
                        {d.confidence_score}%
                      </span>
                    </TableCell>
                    <TableCell className="py-2"><DetectionStatusBadge status={d.status ?? "open"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{d.package_id}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
