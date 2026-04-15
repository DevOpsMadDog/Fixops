/**
 * Network Traffic Analysis
 *
 * Anomaly detection, top talkers, and threat actor communication monitoring.
 * Route: /network-analysis
 *
 * API: GET /api/v1/network/flows  GET /api/v1/network/anomalies
 * Falls back to mock data on failure.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Activity,
  Shield,
  Globe,
  Network,
  Radio,
  Search,
  Ban,
  Eye,
  CheckCircle,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type ThreatLevel = "critical" | "high" | "medium" | "low";
type FlowAction = "block" | "monitor" | "allow";
type AnomalyType = "port_scan" | "lateral_movement" | "data_exfil" | "beaconing" | "dns_tunneling";

interface TopTalker {
  id: string;
  source_ip: string;
  source_geo: { flag: string; country: string };
  destination: string;
  protocol: string;
  bytes_transferred: string;
  connections_per_min: number;
  threat_score: number;
  action: FlowAction;
}

interface NetworkAnomaly {
  id: string;
  timestamp: string;
  anomaly_type: AnomalyType;
  source_ip: string;
  destination: string;
  severity: ThreatLevel;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_TOP_TALKERS: TopTalker[] = [
  {
    id: "flow-001",
    source_ip: "45.83.64.12",
    source_geo: { flag: "🇨🇳", country: "China" },
    destination: "10.0.1.45:443",
    protocol: "HTTPS",
    bytes_transferred: "2.3 GB",
    connections_per_min: 847,
    threat_score: 94,
    action: "block",
  },
  {
    id: "flow-002",
    source_ip: "185.220.101.33",
    source_geo: { flag: "🇷🇺", country: "Russia" },
    destination: "10.0.2.18:22",
    protocol: "SSH",
    bytes_transferred: "18.4 MB",
    connections_per_min: 312,
    threat_score: 88,
    action: "block",
  },
  {
    id: "flow-003",
    source_ip: "175.45.176.0",
    source_geo: { flag: "🇰🇵", country: "North Korea" },
    destination: "10.0.1.100:8080",
    protocol: "HTTP",
    bytes_transferred: "892 KB",
    connections_per_min: 156,
    threat_score: 96,
    action: "block",
  },
  {
    id: "flow-004",
    source_ip: "52.94.28.1",
    source_geo: { flag: "🇺🇸", country: "United States" },
    destination: "10.0.3.22:443",
    protocol: "HTTPS",
    bytes_transferred: "4.1 GB",
    connections_per_min: 1203,
    threat_score: 2,
    action: "allow",
  },
  {
    id: "flow-005",
    source_ip: "91.108.56.14",
    source_geo: { flag: "🇮🇷", country: "Iran" },
    destination: "10.0.1.77:53",
    protocol: "DNS",
    bytes_transferred: "234 MB",
    connections_per_min: 2840,
    threat_score: 91,
    action: "block",
  },
  {
    id: "flow-006",
    source_ip: "104.26.3.54",
    source_geo: { flag: "🇺🇸", country: "United States" },
    destination: "10.0.2.55:443",
    protocol: "HTTPS",
    bytes_transferred: "1.7 GB",
    connections_per_min: 445,
    threat_score: 5,
    action: "allow",
  },
  {
    id: "flow-007",
    source_ip: "198.51.100.42",
    source_geo: { flag: "🌐", country: "Tor Exit Node" },
    destination: "10.0.1.12:3389",
    protocol: "RDP",
    bytes_transferred: "67.3 MB",
    connections_per_min: 89,
    threat_score: 99,
    action: "block",
  },
  {
    id: "flow-008",
    source_ip: "13.248.148.20",
    source_geo: { flag: "🇩🇪", country: "Germany" },
    destination: "10.0.3.80:443",
    protocol: "HTTPS",
    bytes_transferred: "328 MB",
    connections_per_min: 672,
    threat_score: 8,
    action: "monitor",
  },
];

const MOCK_ANOMALIES: NetworkAnomaly[] = [
  {
    id: "anom-001",
    timestamp: "14:32:18",
    anomaly_type: "port_scan",
    source_ip: "45.83.64.12",
    destination: "10.0.0.0/24",
    severity: "high",
  },
  {
    id: "anom-002",
    timestamp: "14:28:45",
    anomaly_type: "lateral_movement",
    source_ip: "10.0.1.45",
    destination: "10.0.2.0/24",
    severity: "critical",
  },
  {
    id: "anom-003",
    timestamp: "14:21:09",
    anomaly_type: "data_exfil",
    source_ip: "10.0.1.77",
    destination: "91.108.56.14",
    severity: "critical",
  },
  {
    id: "anom-004",
    timestamp: "14:15:33",
    anomaly_type: "beaconing",
    source_ip: "10.0.3.22",
    destination: "185.220.101.33",
    severity: "high",
  },
  {
    id: "anom-005",
    timestamp: "14:08:57",
    anomaly_type: "dns_tunneling",
    source_ip: "10.0.1.100",
    destination: "91.108.56.14:53",
    severity: "high",
  },
];

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

const ANOMALY_CONFIG: Record<AnomalyType, { label: string; color: string; bgColor: string }> = {
  port_scan: { label: "Port Scan", color: "text-yellow-400", bgColor: "bg-yellow-500/10" },
  lateral_movement: { label: "Lateral Movement", color: "text-red-400", bgColor: "bg-red-500/10" },
  data_exfil: { label: "Data Exfiltration", color: "text-red-500", bgColor: "bg-red-500/10" },
  beaconing: { label: "Beaconing", color: "text-orange-400", bgColor: "bg-orange-500/10" },
  dns_tunneling: { label: "DNS Tunneling", color: "text-purple-400", bgColor: "bg-purple-500/10" },
};

const SEVERITY_COLORS: Record<ThreatLevel, { text: string; bg: string }> = {
  critical: { text: "text-red-400", bg: "bg-red-500/20" },
  high: { text: "text-orange-400", bg: "bg-orange-500/20" },
  medium: { text: "text-yellow-400", bg: "bg-yellow-500/20" },
  low: { text: "text-green-400", bg: "bg-green-500/20" },
};

const ACTION_CONFIG: Record<FlowAction, { label: string; color: string; bgColor: string }> = {
  block: { label: "Block", color: "text-red-400", bgColor: "bg-red-500/10" },
  monitor: { label: "Monitor", color: "text-yellow-400", bgColor: "bg-yellow-500/10" },
  allow: { label: "Allow", color: "text-green-400", bgColor: "bg-green-500/10" },
};

const PROTOCOL_DIST = [
  { label: "HTTPS", pct: 67, color: "bg-blue-500" },
  { label: "DNS", pct: 12, color: "bg-purple-500" },
  { label: "HTTP", pct: 8, color: "bg-orange-500" },
  { label: "Other", pct: 7, color: "bg-slate-500" },
  { label: "SSH", pct: 4, color: "bg-yellow-500" },
  { label: "RDP", pct: 2, color: "bg-red-500" },
];

const GEO_REGIONS = [
  { label: "North America", level: "low", color: "bg-green-500/30 border-green-500/50" },
  { label: "Europe", level: "medium", color: "bg-yellow-500/30 border-yellow-500/50" },
  { label: "Russia", level: "high", color: "bg-red-500/40 border-red-500/70" },
  { label: "China", level: "high", color: "bg-red-500/40 border-red-500/70" },
  { label: "SE Asia", level: "medium", color: "bg-yellow-500/30 border-yellow-500/50" },
  { label: "Middle East", level: "medium", color: "bg-yellow-500/30 border-yellow-500/50" },
  { label: "Africa", level: "low", color: "bg-green-500/30 border-green-500/50" },
  { label: "Oceania", level: "low", color: "bg-green-500/30 border-green-500/50" },
];

// 24-hour traffic volume (index = hour 0-23)
const HOURLY_TRAFFIC = [
  12, 8, 6, 5, 7, 10, 18, 34, 52, 61, 68, 74,
  71, 65, 69, 72, 78, 85, 91, 88, 76, 58, 34, 20,
];
// Anomaly windows: hours where spikes occurred
const ANOMALY_HOURS = new Set([9, 14, 15, 18, 19]);

const maxTraffic = Math.max(...HOURLY_TRAFFIC);

// Threat dots for the Live Threat Map
const THREAT_DOTS = [
  // External threat sources (red, pulsing)
  { id: "t1", x: 72, y: 22, type: "threat", flag: "🇨🇳", label: "45.83.64.12" },
  { id: "t2", x: 65, y: 18, type: "threat", flag: "🇷🇺", label: "185.220.101.33" },
  { id: "t3", x: 75, y: 28, type: "threat", flag: "🇰🇵", label: "175.45.176.0" },
  { id: "t4", x: 68, y: 32, type: "threat", flag: "🇮🇷", label: "91.108.56.14" },
  // Internal assets (blue)
  { id: "i1", x: 40, y: 45, type: "internal", label: "10.0.1.45" },
  { id: "i2", x: 35, y: 55, type: "internal", label: "10.0.2.18" },
  { id: "i3", x: 45, y: 60, type: "internal", label: "10.0.1.77" },
  { id: "i4", x: 30, y: 48, type: "internal", label: "10.0.1.100" },
  { id: "i5", x: 50, y: 52, type: "internal", label: "10.0.3.22" },
  // Normal external traffic (blue, dimmer)
  { id: "n1", x: 15, y: 30, type: "normal", label: "52.94.28.1" },
  { id: "n2", x: 20, y: 65, type: "normal", label: "104.26.3.54" },
  { id: "n3", x: 10, y: 50, type: "normal", label: "13.248.148.20" },
  { id: "n4", x: 82, y: 60, type: "normal", label: "CDN Edge" },
  { id: "n5", x: 85, y: 40, type: "normal", label: "AWS CF" },
  { id: "n6", x: 25, y: 75, type: "normal", label: "GCP LB" },
  // Tor exit node (orange)
  { id: "r1", x: 55, y: 20, type: "tor", label: "Tor Exit" },
];

// Threat lines: from threat source to internal target
const THREAT_LINES = [
  { from: "t1", to: "i1" },
  { from: "t2", to: "i2" },
  { from: "t3", to: "i3" },
  { from: "t4", to: "i4" },
];

function getDotById(id: string) {
  return THREAT_DOTS.find((d) => d.id === id);
}

// ═══════════════════════════════════════════════════════════
// Component: Live Threat Map
// ═══════════════════════════════════════════════════════════

function LiveThreatMap() {
  return (
    <Card className="border-slate-700 bg-slate-900/40">
      <CardHeader className="border-b border-slate-700 pb-4">
        <CardTitle className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-blue-400" />
          Live Threat Map
          <span className="ml-auto flex items-center gap-1 text-xs text-green-400 font-normal">
            <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
            LIVE
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-4">
        <div
          className="relative w-full bg-slate-950 rounded-lg border border-slate-700/50 overflow-hidden"
          style={{ height: "260px" }}
        >
          {/* Grid lines for map feel */}
          <div
            className="absolute inset-0 opacity-10"
            style={{
              backgroundImage:
                "linear-gradient(rgba(100,116,139,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(100,116,139,0.5) 1px, transparent 1px)",
              backgroundSize: "40px 40px",
            }}
          />

          {/* SVG threat lines */}
          <svg className="absolute inset-0 w-full h-full" style={{ pointerEvents: "none" }}>
            {THREAT_LINES.map((line) => {
              const from = getDotById(line.from);
              const to = getDotById(line.to);
              if (!from || !to) return null;
              return (
                <line
                  key={`${line.from}-${line.to}`}
                  x1={`${from.x}%`}
                  y1={`${from.y}%`}
                  x2={`${to.x}%`}
                  y2={`${to.y}%`}
                  stroke="rgba(239,68,68,0.6)"
                  strokeWidth="1.5"
                  strokeDasharray="4 3"
                >
                  <animate
                    attributeName="stroke-dashoffset"
                    values="0;-14"
                    dur="1s"
                    repeatCount="indefinite"
                  />
                </line>
              );
            })}
            {/* Tor line — orange */}
            {(() => {
              const tor = getDotById("r1");
              const target = getDotById("i5");
              if (!tor || !target) return null;
              return (
                <line
                  x1={`${tor.x}%`}
                  y1={`${tor.y}%`}
                  x2={`${target.x}%`}
                  y2={`${target.y}%`}
                  stroke="rgba(251,146,60,0.6)"
                  strokeWidth="1.5"
                  strokeDasharray="4 3"
                >
                  <animate
                    attributeName="stroke-dashoffset"
                    values="0;-14"
                    dur="1.2s"
                    repeatCount="indefinite"
                  />
                </line>
              );
            })()}
          </svg>

          {/* Dots */}
          {THREAT_DOTS.map((dot) => (
            <div
              key={dot.id}
              className="absolute group"
              style={{ left: `${dot.x}%`, top: `${dot.y}%`, transform: "translate(-50%, -50%)" }}
            >
              {dot.type === "threat" ? (
                <>
                  {/* Outer pulse ring */}
                  <span className="absolute inset-0 rounded-full bg-red-500/30 animate-ping" style={{ width: 20, height: 20, left: -4, top: -4 }} />
                  <div className="relative w-3 h-3 rounded-full bg-red-500 border border-red-300 shadow-lg shadow-red-500/50 cursor-pointer" />
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:flex items-center gap-1 bg-slate-900 border border-red-500/40 rounded px-2 py-1 text-xs whitespace-nowrap z-10">
                    <span>{dot.flag}</span>
                    <span className="text-red-300">{dot.label}</span>
                  </div>
                </>
              ) : dot.type === "tor" ? (
                <>
                  <span className="absolute inset-0 rounded-full bg-orange-500/30 animate-ping" style={{ width: 18, height: 18, left: -3, top: -3 }} />
                  <div className="relative w-2.5 h-2.5 rounded-full bg-orange-500 border border-orange-300 cursor-pointer" />
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:flex items-center gap-1 bg-slate-900 border border-orange-500/40 rounded px-2 py-1 text-xs whitespace-nowrap z-10">
                    <span className="text-orange-300">{dot.label}</span>
                  </div>
                </>
              ) : dot.type === "internal" ? (
                <>
                  <div className="w-3 h-3 rounded bg-blue-500 border border-blue-300 cursor-pointer" />
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block bg-slate-900 border border-blue-500/40 rounded px-2 py-1 text-xs text-blue-300 whitespace-nowrap z-10">
                    {dot.label}
                  </div>
                </>
              ) : (
                <div className="w-2 h-2 rounded-full bg-blue-400/50 border border-blue-400/30 cursor-pointer" />
              )}
            </div>
          ))}

          {/* Legend */}
          <div className="absolute bottom-3 left-3 flex flex-col gap-1">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
              Threat actor
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-2.5 h-2.5 rounded-full bg-orange-500" />
              Tor exit node
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-2.5 h-2.5 rounded bg-blue-500" />
              Internal asset
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <div className="w-2 h-2 rounded-full bg-blue-400/50" />
              Legitimate traffic
            </div>
          </div>

          {/* Country flags overlay */}
          <div className="absolute top-3 right-3 flex flex-col gap-1">
            {[
              { flag: "🇨🇳", label: "CN — 847 conn/min" },
              { flag: "🇷🇺", label: "RU — 312 conn/min" },
              { flag: "🇰🇵", label: "KP — 156 conn/min" },
              { flag: "🇮🇷", label: "IR — 2,840 conn/min" },
            ].map((item) => (
              <div key={item.flag} className="flex items-center gap-1 text-xs bg-red-500/10 border border-red-500/20 rounded px-2 py-0.5">
                <span>{item.flag}</span>
                <span className="text-red-300">{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Component: Top Talkers Table
// ═══════════════════════════════════════════════════════════

interface TopTalkersProps {
  talkers: TopTalker[];
  isLoading: boolean;
}

function TopTalkersTable({ talkers, isLoading }: TopTalkersProps) {
  const [search, setSearch] = useState("");

  const filtered = talkers.filter(
    (t) =>
      t.source_ip.includes(search) ||
      t.source_geo.country.toLowerCase().includes(search.toLowerCase()) ||
      t.destination.includes(search),
  );

  return (
    <Card className="border-slate-700 bg-slate-900/40">
      <CardHeader className="border-b border-slate-700 pb-4">
        <div className="flex items-center justify-between gap-4">
          <CardTitle className="flex items-center gap-2">
            <Network className="w-5 h-5 text-blue-400" />
            Top Talkers
          </CardTitle>
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-slate-500" />
            <input
              placeholder="Filter by IP, country..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-8 w-48 rounded-md border border-slate-700 bg-slate-800/50 px-3 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-4">
        {isLoading ? (
          <div className="text-slate-400 py-4">Loading...</div>
        ) : (
          <ScrollArea className="w-full">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700/50">
                  <th className="text-left py-3 px-3 font-semibold text-slate-300">Source IP</th>
                  <th className="text-left py-3 px-3 font-semibold text-slate-300">Geo</th>
                  <th className="text-left py-3 px-3 font-semibold text-slate-300">Destination</th>
                  <th className="text-left py-3 px-3 font-semibold text-slate-300">Protocol</th>
                  <th className="text-left py-3 px-3 font-semibold text-slate-300">Bytes</th>
                  <th className="text-left py-3 px-3 font-semibold text-slate-300">Conn/min</th>
                  <th className="text-left py-3 px-3 font-semibold text-slate-300">Threat</th>
                  <th className="text-left py-3 px-3 font-semibold text-slate-300">Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((talker) => (
                  <motion.tr
                    key={talker.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="border-b border-slate-700/30 hover:bg-slate-800/30 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-3 font-mono text-slate-200 text-xs">{talker.source_ip}</td>
                    <td className="py-3 px-3 text-slate-300">
                      <span className="mr-1">{talker.source_geo.flag}</span>
                      {talker.source_geo.country}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400 text-xs">{talker.destination}</td>
                    <td className="py-3 px-3">
                      <Badge variant="outline" className="border-slate-600 text-slate-300 text-xs">
                        {talker.protocol}
                      </Badge>
                    </td>
                    <td className="py-3 px-3 text-slate-300 text-xs">{talker.bytes_transferred}</td>
                    <td className="py-3 px-3 text-slate-300 text-xs">
                      <span
                        className={cn(
                          talker.connections_per_min > 500 ? "text-red-400 font-semibold" : "text-slate-300",
                        )}
                      >
                        {talker.connections_per_min.toLocaleString()}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                          <div
                            className={cn(
                              "h-full rounded-full",
                              talker.threat_score >= 80 ? "bg-red-500" : talker.threat_score >= 40 ? "bg-yellow-500" : "bg-green-500",
                            )}
                            style={{ width: `${talker.threat_score}%` }}
                          />
                        </div>
                        <span
                          className={cn(
                            "text-xs font-semibold",
                            talker.threat_score >= 80 ? "text-red-400" : talker.threat_score >= 40 ? "text-yellow-400" : "text-green-400",
                          )}
                        >
                          {talker.threat_score}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <Badge
                        variant="outline"
                        className={cn(
                          "border-0 text-xs",
                          ACTION_CONFIG[talker.action].bgColor,
                          ACTION_CONFIG[talker.action].color,
                        )}
                      >
                        {talker.action === "block" && <Ban className="w-3 h-3 mr-1" />}
                        {talker.action === "monitor" && <Eye className="w-3 h-3 mr-1" />}
                        {talker.action === "allow" && <CheckCircle className="w-3 h-3 mr-1" />}
                        {ACTION_CONFIG[talker.action].label}
                      </Badge>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Component: Protocol Distribution
// ═══════════════════════════════════════════════════════════

function ProtocolDistribution() {
  return (
    <Card className="border-slate-700 bg-slate-900/40">
      <CardHeader className="border-b border-slate-700 pb-4">
        <CardTitle className="flex items-center gap-2">
          <Radio className="w-5 h-5 text-purple-400" />
          Protocol Distribution
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-6 space-y-3">
        {PROTOCOL_DIST.map((proto, idx) => (
          <div key={proto.label} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-300">{proto.label}</span>
              <span className="text-slate-400 font-semibold">{proto.pct}%</span>
            </div>
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${proto.pct}%` }}
                transition={{ delay: idx * 0.05, duration: 0.5 }}
                className={cn("h-full rounded-full", proto.color)}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Component: Network Anomaly Feed
// ═══════════════════════════════════════════════════════════

interface AnomalyFeedProps {
  anomalies: NetworkAnomaly[];
  isLoading: boolean;
}

function AnomalyFeed({ anomalies, isLoading }: AnomalyFeedProps) {
  return (
    <Card className="border-slate-700 bg-slate-900/40">
      <CardHeader className="border-b border-slate-700 pb-4">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-yellow-400" />
            Network Anomaly Feed
          </CardTitle>
          <span className="flex items-center gap-1 text-xs text-green-400">
            <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
            Real-time
          </span>
        </div>
      </CardHeader>
      <CardContent className="pt-4">
        {isLoading ? (
          <div className="text-slate-400 py-4">Loading...</div>
        ) : (
          <div className="space-y-3">
            {anomalies.map((anom, idx) => {
              const cfg = ANOMALY_CONFIG[anom.anomaly_type];
              const sev = SEVERITY_COLORS[anom.severity];
              return (
                <motion.div
                  key={anom.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.06 }}
                  className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600 transition-colors"
                >
                  <div className={cn("mt-0.5 p-1.5 rounded", cfg.bgColor)}>
                    <AlertTriangle className={cn("w-3.5 h-3.5", cfg.color)} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={cn("text-xs font-semibold", cfg.color)}>{cfg.label}</span>
                      <Badge
                        variant="outline"
                        className={cn("border-0 h-5 text-xs", sev.bg, sev.text)}
                      >
                        {anom.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-1 text-xs text-slate-400">
                      <span className="font-mono">{anom.source_ip}</span>
                      <span className="text-slate-600">→</span>
                      <span className="font-mono truncate">{anom.destination}</span>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-2 flex-shrink-0">
                    <span className="text-xs text-slate-500">{anom.timestamp}</span>
                    <Button size="sm" variant="ghost" className="h-6 px-2 text-xs text-blue-400 hover:text-blue-300 hover:bg-blue-500/10">
                      Investigate
                    </Button>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Component: Geo Threat Heatmap
// ═══════════════════════════════════════════════════════════

function GeoThreatHeatmap() {
  return (
    <Card className="border-slate-700 bg-slate-900/40">
      <CardHeader className="border-b border-slate-700 pb-4">
        <CardTitle className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyan-400" />
          Geo Threat Heatmap
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-4">
        <div className="grid grid-cols-4 gap-2">
          {GEO_REGIONS.map((region, idx) => (
            <motion.div
              key={region.label}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: idx * 0.05 }}
              className={cn(
                "rounded-lg border p-3 text-center cursor-pointer hover:opacity-90 transition-opacity",
                region.color,
              )}
            >
              <p className="text-xs font-semibold text-slate-200 leading-tight mb-1">{region.label}</p>
              <p
                className={cn(
                  "text-xs capitalize font-medium",
                  region.level === "high"
                    ? "text-red-300"
                    : region.level === "medium"
                      ? "text-yellow-300"
                      : "text-green-300",
                )}
              >
                {region.level}
              </p>
            </motion.div>
          ))}
        </div>
        <div className="flex items-center gap-6 mt-4 justify-center">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <div className="w-3 h-3 rounded bg-green-500/30 border border-green-500/50" />
            Low activity
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <div className="w-3 h-3 rounded bg-yellow-500/30 border border-yellow-500/50" />
            Medium activity
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <div className="w-3 h-3 rounded bg-red-500/40 border border-red-500/70" />
            High activity
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Component: Connection Timeline (24-hour)
// ═══════════════════════════════════════════════════════════

function ConnectionTimeline() {
  return (
    <Card className="border-slate-700 bg-slate-900/40">
      <CardHeader className="border-b border-slate-700 pb-4">
        <CardTitle className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-green-400" />
          Connection Timeline (24h)
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-4">
        <div className="flex items-end gap-0.5 h-24">
          {HOURLY_TRAFFIC.map((val, hour) => {
            const isAnomaly = ANOMALY_HOURS.has(hour);
            return (
              <motion.div
                key={hour}
                title={`${String(hour).padStart(2, "0")}:00 — ${val} units${isAnomaly ? " ⚠ Anomaly" : ""}`}
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: `${(val / maxTraffic) * 100}%`, opacity: 1 }}
                transition={{ delay: hour * 0.02, duration: 0.4 }}
                className={cn(
                  "flex-1 rounded-t cursor-pointer hover:opacity-100 transition-opacity",
                  isAnomaly
                    ? "bg-gradient-to-t from-red-600 to-red-400 opacity-90"
                    : "bg-gradient-to-t from-blue-600 to-blue-400 opacity-60",
                )}
              />
            );
          })}
        </div>
        {/* Hour labels — show every 4 hours */}
        <div className="flex justify-between mt-1 px-0.5">
          {[0, 4, 8, 12, 16, 20, 23].map((h) => (
            <span key={h} className="text-xs text-slate-600">
              {String(h).padStart(2, "0")}:00
            </span>
          ))}
        </div>
        <div className="flex items-center gap-4 mt-3">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <div className="w-3 h-3 rounded-sm bg-blue-500/60" />
            Normal traffic
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <div className="w-3 h-3 rounded-sm bg-red-500" />
            Anomaly window
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function NetworkAnalysis() {
  const { data: topTalkers = MOCK_TOP_TALKERS, isLoading: loadingFlows } = useQuery({
    queryKey: ["network-flows"],
    queryFn: async () => {
      try {
        const res = await fetch(`${API}/api/v1/network/flows`);
        if (!res.ok) throw new Error("Failed to fetch");
        return res.json();
      } catch {
        return MOCK_TOP_TALKERS;
      }
    },
  });

  const { data: anomalies = MOCK_ANOMALIES, isLoading: loadingAnomalies } = useQuery({
    queryKey: ["network-anomalies"],
    queryFn: async () => {
      try {
        const res = await fetch(`${API}/api/v1/network/anomalies`);
        if (!res.ok) throw new Error("Failed to fetch");
        return res.json();
      } catch {
        return MOCK_ANOMALIES;
      }
    },
  });

  return (
    <div className="min-h-screen bg-slate-950">
      <PageHeader
        title="Network Traffic Analysis"
        description="Anomaly detection, top talkers, and threat actor communication monitoring"
        actions={
          <Button className="bg-red-600 hover:bg-red-700">
            <Shield className="w-4 h-4 mr-2" />
            Block All Threats
          </Button>
        }
      />

      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* KPI Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            title="Alerts Today"
            value="47"
            trend="up"
            trendLabel="+12 from yesterday"
            icon={AlertTriangle}
          />
          <KpiCard
            title="Suspicious Flows"
            value="12"
            trend="up"
            trendLabel="Active now"
            icon={Activity}
          />
          <KpiCard
            title="Blocked Connections"
            value="234"
            trend="up"
            trendLabel="+18 this hour"
            icon={Ban}
          />
          <KpiCard
            title="Bandwidth Anomalies"
            value="3"
            trend="flat"
            trendLabel="Last 1h"
            icon={Zap}
          />
        </div>

        {/* Live Threat Map — full width */}
        <LiveThreatMap />

        {/* Top Talkers — full width */}
        <TopTalkersTable talkers={topTalkers} isLoading={loadingFlows} />

        {/* Protocol Distribution + Anomaly Feed — 2 col */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <ProtocolDistribution />
          <div className="lg:col-span-2">
            <AnomalyFeed anomalies={anomalies} isLoading={loadingAnomalies} />
          </div>
        </div>

        {/* Geo Heatmap + Connection Timeline — 2 col */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <GeoThreatHeatmap />
          <ConnectionTimeline />
        </div>
      </div>
    </div>
  );
}
