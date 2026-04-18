/**
 * Network Topology
 *
 * Asset map, segment isolation, and exposure detection.
 *   1. KPIs: Total Nodes, Network Segments, Exposed Assets, Topology Edges
 *   2. Node inventory table (12 rows)
 *   3. Segment cards (6 segments in 2-col grid)
 *   4. Exposure alerts (7 alert cards)
 *   5. Path finder input with mock result
 *
 * API stubs: GET /api/v1/network/nodes, /api/v1/network/segments, /api/v1/network/exposure
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

async function apiFetch(path: string) {
  const res = await fetch(path, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import {
  Network, Server, Shield, AlertTriangle, RefreshCw,
  Search, ChevronRight, Layers, Globe, Lock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const NODES = [
  { hostname: "web-prod-01",    ip: "10.0.1.10",  type: "server",      os: "Ubuntu 22.04", location: "us-east-1a", criticality: "Critical", segment: "DMZ",       status: "online" },
  { hostname: "web-prod-02",    ip: "10.0.1.11",  type: "server",      os: "Ubuntu 22.04", location: "us-east-1b", criticality: "Critical", segment: "DMZ",       status: "online" },
  { hostname: "api-gateway-01", ip: "10.0.2.5",   type: "server",      os: "Amazon Linux 2", location: "us-east-1a", criticality: "Critical", segment: "Internal", status: "online" },
  { hostname: "db-primary",     ip: "10.0.3.10",  type: "server",      os: "RHEL 9",       location: "us-east-1a", criticality: "Critical", segment: "Restricted", status: "online" },
  { hostname: "db-replica",     ip: "10.0.3.11",  type: "server",      os: "RHEL 9",       location: "us-east-1b", criticality: "High",     segment: "Restricted", status: "online" },
  { hostname: "fw-edge-01",     ip: "192.168.1.1", type: "firewall",   os: "FortiOS 7.4",  location: "us-east-1a", criticality: "Critical", segment: "DMZ",       status: "online" },
  { hostname: "core-switch-01", ip: "10.0.0.1",   type: "router",      os: "IOS-XE 17.6",  location: "DC-1",      criticality: "High",     segment: "Internal",  status: "online" },
  { hostname: "workstation-42", ip: "10.0.4.42",  type: "workstation", os: "Windows 11",   location: "NYC-HQ",    criticality: "Medium",   segment: "Internal",  status: "online" },
  { hostname: "workstation-71", ip: "10.0.4.71",  type: "workstation", os: "macOS 15",     location: "NYC-HQ",    criticality: "Low",      segment: "Internal",  status: "offline" },
  { hostname: "iot-sensor-03",  ip: "10.0.5.3",   type: "IoT",         os: "Embedded 2.1", location: "Warehouse", criticality: "Medium",   segment: "DMZ",       status: "online" },
  { hostname: "jump-host-01",   ip: "10.0.2.20",  type: "server",      os: "Ubuntu 20.04", location: "us-east-1a", criticality: "High",    segment: "Internal",  status: "online" },
  { hostname: "backup-nas-01",  ip: "10.0.3.50",  type: "server",      os: "TrueNAS 24",   location: "DC-1",      criticality: "High",     segment: "Restricted", status: "degraded" },
];

const SEGMENTS = [
  { name: "DMZ",              vlan: "VLAN 10", subnet: "10.0.1.0/24",  zone: "DMZ",        nodes: 47 },
  { name: "Internal Network", vlan: "VLAN 20", subnet: "10.0.2.0/24",  zone: "Internal",   nodes: 312 },
  { name: "Restricted Zone",  vlan: "VLAN 30", subnet: "10.0.3.0/24",  zone: "Restricted", nodes: 28 },
  { name: "IoT Network",      vlan: "VLAN 40", subnet: "10.0.5.0/24",  zone: "DMZ",        nodes: 94 },
  { name: "Management VLAN",  vlan: "VLAN 99", subnet: "10.0.99.0/24", zone: "Restricted", nodes: 15 },
  { name: "Guest Wireless",   vlan: "VLAN 50", subnet: "172.16.0.0/24", zone: "DMZ",       nodes: 351 },
];

const EXPOSURES = [
  { src: "iot-sensor-03 (10.0.5.3)",   dst: "db-primary (10.0.3.10)",    risk: "IoT device has direct route to DB — no firewall rule", proto: "TCP 5432" },
  { src: "web-prod-01 (10.0.1.10)",    dst: "db-replica (10.0.3.11)",    risk: "HTTP server reaches replica DB without WAF interception", proto: "TCP 3306" },
  { src: "workstation-42 (10.0.4.42)", dst: "db-primary (10.0.3.10)",    risk: "Lateral movement: workstation can reach restricted DB", proto: "TCP 5432" },
  { src: "iot-sensor-03 (10.0.5.3)",   dst: "api-gateway-01 (10.0.2.5)", risk: "IoT device bypasses DMZ firewall to internal API", proto: "TCP 443" },
  { src: "guest-device (172.16.0.22)", dst: "core-switch-01 (10.0.0.1)", risk: "Guest VLAN has SNMP access to core router", proto: "UDP 161" },
  { src: "backup-nas-01 (10.0.3.50)",  dst: "db-primary (10.0.3.10)",    risk: "NAS backup traffic unencrypted on shared segment", proto: "TCP 873" },
  { src: "workstation-71 (10.0.4.71)", dst: "jump-host-01 (10.0.2.20)", risk: "Offline workstation has persistent SSH key to jump host", proto: "TCP 22" },
];

const MOCK_PATH = ["fw-edge-01 (192.168.1.1)", "core-switch-01 (10.0.0.1)", "api-gateway-01 (10.0.2.5)", "db-primary (10.0.3.10)"];

// ── Helpers ────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const cls =
    type === "server"      ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "workstation" ? "border-indigo-500/30 text-indigo-400 bg-indigo-500/10" :
    type === "router"      ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    type === "firewall"    ? "border-green-500/30 text-green-400 bg-green-500/10" :
                             "border-orange-500/30 text-orange-400 bg-orange-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{type}</Badge>;
}

function CritBadge({ crit }: { crit: string }) {
  const cls =
    crit === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    crit === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    crit === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                          "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{crit}</Badge>;
}

function ZoneBadge({ zone }: { zone: string }) {
  const cls =
    zone === "DMZ"        ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    zone === "Restricted" ? "border-red-500/30 text-red-400 bg-red-500/10" :
                            "border-blue-500/30 text-blue-400 bg-blue-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{zone}</Badge>;
}

function StatusDot({ status }: { status: string }) {
  const cls =
    status === "online"   ? "bg-green-500" :
    status === "degraded" ? "bg-amber-500" :
                            "bg-muted-foreground";
  return <span className={cn("inline-block w-2 h-2 rounded-full", cls)} title={status} />;
}

// ── Component ──────────────────────────────────────────────────

export default function NetworkTopology() {
  const [loading, setLoading] = useState(true);

  const [refreshing, setRefreshing]   = useState(false);
  const [srcNode, setSrcNode]         = useState("");
  const [dstNode, setDstNode]         = useState("");
  const [pathResult, setPathResult]   = useState<string[] | null>(null);
  const [liveData, setLiveData]       = useState<any>(null);

  const fetchAll = () =>
    Promise.allSettled([
      apiFetch("/api/v1/asm/assets?org_id=default"),
      apiFetch("/api/v1/asm/stats?org_id=default"),
    ]).then(([assetsRes, statsRes]) => {
      const assets = assetsRes.status === "fulfilled" ? assetsRes.value : null;
      const stats  = statsRes.status  === "fulfilled" ? statsRes.value  : null;
      if (assets || stats) setLiveData({ assets, stats });
    });

  useEffect(() => { fetchAll();}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAll().finally(() => setRefreshing(false));
  };

  const handleFindPath = () => {
    if (srcNode.trim() && dstNode.trim()) setPathResult(MOCK_PATH);
  };

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Network Topology"
        description="Asset map, segment isolation, and exposure detection"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Nodes"       value={liveData?.stats?.total_assets ?? liveData?.assets?.length ?? 847}    icon={Server}  />
        <KpiCard title="Network Segments"  value={liveData?.stats?.total_segments ?? 12}     icon={Layers}  />
        <KpiCard title="Exposed Assets"    value={liveData?.stats?.exposed_assets ?? liveData?.stats?.high_risk ?? 7}      icon={Globe}   trend="up" className="border-red-500/20" />
        <KpiCard title="Topology Edges"    value={liveData?.stats?.total_edges ?? "2,341"}  icon={Network} />
      </div>

      {/* Node inventory table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Server className="h-4 w-4 text-blue-400" />
            Node Inventory
          </CardTitle>
          <CardDescription className="text-xs">All network-connected assets with classification and segment assignment</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Hostname</TableHead>
                  <TableHead className="text-[11px] h-8">IP</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">OS</TableHead>
                  <TableHead className="text-[11px] h-8">Location</TableHead>
                  <TableHead className="text-[11px] h-8">Criticality</TableHead>
                  <TableHead className="text-[11px] h-8">Segment</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {NODES.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  NODES.map((n) => (
                  <TableRow key={n.hostname} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{n.hostname}</TableCell>
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{n.ip}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={n.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{n.os}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{n.location}</TableCell>
                    <TableCell className="py-2.5"><CritBadge crit={n.criticality} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{n.segment}</TableCell>
                    <TableCell className="py-2.5"><StatusDot status={n.status} /></TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Segments grid */}
      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Layers className="h-4 w-4 text-purple-400" />
          Network Segments
        </h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {SEGMENTS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            SEGMENTS.map((seg) => (
            <Card key={seg.name} className="hover:border-border/80 transition-colors">
              <CardContent className="p-4 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-sm font-semibold truncate">{seg.name}</span>
                  <ZoneBadge zone={seg.zone} />
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground/60">VLAN</span>
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground/60">Subnet</span>
                  <span className="font-mono">{seg.vlan}</span>
                  <span className="font-mono">{seg.subnet}</span>
                </div>
                <div className="flex items-center justify-between pt-1 border-t border-border/40">
                  <span className="text-xs text-muted-foreground">Nodes</span>
                  <span className="text-sm font-bold tabular-nums">{seg.nodes}</span>
                </div>
              </CardContent>
            </Card>
          )))}
        </div>
      </div>

      {/* Exposure alerts */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Exposure Alerts
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {EXPOSURES.length} exposures
            </Badge>
          </div>
          <CardDescription className="text-xs">Unexpected cross-segment paths connecting exposed assets to internal critical nodes</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {EXPOSURES.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            EXPOSURES.map((e, i) => (
            <div key={i} className="rounded-md border border-red-500/30 bg-red-500/5 p-3 space-y-1.5">
              <div className="flex items-center gap-2 text-xs">
                <Shield className="h-3.5 w-3.5 text-red-400 shrink-0" />
                <span className="font-mono text-red-300">{e.src}</span>
                <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="font-mono text-red-300">{e.dst}</span>
                <Badge className="ml-auto text-[10px] border border-red-500/30 text-red-400 bg-red-500/10 shrink-0">{e.proto}</Badge>
              </div>
              <p className="text-[11px] text-muted-foreground pl-5">{e.risk}</p>
            </div>
          )))}
        </CardContent>
      </Card>

      {/* Path finder */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Search className="h-4 w-4 text-indigo-400" />
            Path Finder
          </CardTitle>
          <CardDescription className="text-xs">Trace the network path between any two nodes</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <Input
              placeholder="Source node (e.g. workstation-42)"
              value={srcNode}
              onChange={(e) => setSrcNode(e.target.value)}
              className="h-8 text-xs flex-1 min-w-[180px]"
            />
            <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
            <Input
              placeholder="Destination node (e.g. db-primary)"
              value={dstNode}
              onChange={(e) => setDstNode(e.target.value)}
              className="h-8 text-xs flex-1 min-w-[180px]"
            />
            <Button size="sm" className="h-8 text-xs" onClick={handleFindPath}>
              Find Path
            </Button>
          </div>

          {pathResult && (
            <motion.div
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-md border border-indigo-500/30 bg-indigo-500/5 p-3"
            >
              <p className="text-[10px] uppercase tracking-wide text-indigo-400 mb-2">Path discovered — {pathResult.length} hops</p>
              <div className="flex items-center gap-1 flex-wrap">
                {pathResult.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  pathResult.map((node, i) => (
                  <span key={i} className="flex items-center gap-1">
                    <span className="rounded bg-muted px-2 py-0.5 text-xs font-mono">{node}</span>
                    {i < pathResult.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                  </span>
                )))}
              </div>
            </motion.div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
