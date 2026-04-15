/**
 * API Abuse Detection Dashboard
 *
 * Anomalous API usage patterns:
 *   1. KPIs: Active Threats, Rate Limit Violations, Suspicious IPs, Blocked Requests Today
 *   2. Active Abuse Patterns Table: IP, pattern type, requests/min, endpoints, action
 *   3. Endpoint Heat Map: bar chart showing most-abused endpoints
 *   4. Blocked IPs: CIDR ranges and count
 *   5. Rate Limit Events: timeline
 *
 * Route: /api-abuse
 * API: GET /api/v1/api-abuse/patterns, /api/v1/api-abuse/endpoints, /api/v1/api-abuse/events (mock fallback)
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  Zap,
  TrendingUp,
  Server,
  Globe,
  Lock,
  AlertCircle,
  Clock,
  Activity,
  Ban,
  BarChart3,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type PatternType = "scraping" | "brute_force" | "data_harvest" | "credential_stuffing";
type Action = "rate_limited" | "blocked" | "monitoring";
type EventType = "rate_limit_exceeded" | "suspicious_pattern" | "ip_blocked";

interface AbusePattern {
  id: string;
  ip_address: string;
  pattern_type: PatternType;
  requests_per_min: number;
  endpoints_targeted: number;
  action: Action;
  first_seen: string;
  threat_score: number;
}

interface EndpointHeat {
  endpoint: string;
  abuse_count: number;
  pattern_types: PatternType[];
}

interface BlockedIP {
  ip_address: string;
  cidr: string;
  reason: string;
  blocked_at: string;
  count: number;
}

interface RateLimitEvent {
  id: string;
  timestamp: string;
  ip_address: string;
  endpoint: string;
  requests: number;
  severity: "critical" | "high" | "medium" | "low";
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_PATTERNS: AbusePattern[] = [
  {
    id: "PAT-001",
    ip_address: "192.168.1.105",
    pattern_type: "credential_stuffing",
    requests_per_min: 847,
    endpoints_targeted: 3,
    action: "blocked",
    first_seen: "2026-04-14 14:15",
    threat_score: 98,
  },
  {
    id: "PAT-002",
    ip_address: "203.0.113.42",
    pattern_type: "scraping",
    requests_per_min: 523,
    endpoints_targeted: 7,
    action: "rate_limited",
    first_seen: "2026-04-14 12:43",
    threat_score: 76,
  },
  {
    id: "PAT-003",
    ip_address: "198.51.100.88",
    pattern_type: "data_harvest",
    requests_per_min: 612,
    endpoints_targeted: 5,
    action: "blocked",
    first_seen: "2026-04-14 10:22",
    threat_score: 94,
  },
  {
    id: "PAT-004",
    ip_address: "192.0.2.156",
    pattern_type: "brute_force",
    requests_per_min: 234,
    endpoints_targeted: 2,
    action: "rate_limited",
    first_seen: "2026-04-14 08:51",
    threat_score: 82,
  },
  {
    id: "PAT-005",
    ip_address: "203.0.113.99",
    pattern_type: "scraping",
    requests_per_min: 445,
    endpoints_targeted: 6,
    action: "monitoring",
    first_seen: "2026-04-14 07:30",
    threat_score: 65,
  },
];

const MOCK_ENDPOINTS: EndpointHeat[] = [
  {
    endpoint: "/api/v1/users/search",
    abuse_count: 24,
    pattern_types: ["scraping", "data_harvest"],
  },
  {
    endpoint: "/api/v1/auth/login",
    abuse_count: 19,
    pattern_types: ["credential_stuffing", "brute_force"],
  },
  {
    endpoint: "/api/v1/reports/export",
    abuse_count: 17,
    pattern_types: ["scraping", "data_harvest"],
  },
  {
    endpoint: "/api/v1/assets/list",
    abuse_count: 12,
    pattern_types: ["scraping"],
  },
  {
    endpoint: "/api/v1/findings/query",
    abuse_count: 8,
    pattern_types: ["data_harvest"],
  },
];

const MOCK_BLOCKED_IPS: BlockedIP[] = [
  {
    ip_address: "192.168.1.105",
    cidr: "192.168.1.0/24",
    reason: "Credential stuffing attack",
    blocked_at: "2026-04-14 14:16",
    count: 847,
  },
  {
    ip_address: "198.51.100.88",
    cidr: "198.51.100.0/24",
    reason: "Suspicious data harvesting",
    blocked_at: "2026-04-14 10:23",
    count: 612,
  },
  {
    ip_address: "203.0.113.42",
    cidr: "203.0.113.0/24",
    reason: "Rate limit violations (active scraping)",
    blocked_at: "2026-04-14 12:44",
    count: 523,
  },
];

const MOCK_EVENTS: RateLimitEvent[] = [
  {
    id: "EVT-001",
    timestamp: "2026-04-14 15:02",
    ip_address: "192.168.1.105",
    endpoint: "/api/v1/auth/login",
    requests: 156,
    severity: "critical",
  },
  {
    id: "EVT-002",
    timestamp: "2026-04-14 14:58",
    ip_address: "203.0.113.42",
    endpoint: "/api/v1/users/search",
    requests: 89,
    severity: "high",
  },
  {
    id: "EVT-003",
    timestamp: "2026-04-14 14:45",
    ip_address: "198.51.100.88",
    endpoint: "/api/v1/reports/export",
    requests: 73,
    severity: "high",
  },
  {
    id: "EVT-004",
    timestamp: "2026-04-14 14:32",
    ip_address: "192.0.2.156",
    endpoint: "/api/v1/findings/query",
    requests: 42,
    severity: "medium",
  },
  {
    id: "EVT-005",
    timestamp: "2026-04-14 14:15",
    ip_address: "203.0.113.99",
    endpoint: "/api/v1/assets/list",
    requests: 38,
    severity: "medium",
  },
];

// ══════════════════════════════════════════════════════════════
// Styling
// ══════════════════════════════════════════════════════════════

const PATTERN_COLORS: Record<PatternType, string> = {
  scraping: "bg-blue-500/10 text-blue-700 border-blue-200",
  brute_force: "bg-red-500/10 text-red-700 border-red-200",
  data_harvest: "bg-orange-500/10 text-orange-700 border-orange-200",
  credential_stuffing: "bg-purple-500/10 text-purple-700 border-purple-200",
};

const ACTION_ICONS: Record<Action, typeof Shield> = {
  rate_limited: AlertCircle,
  blocked: Ban,
  monitoring: Activity,
};

const ACTION_COLORS: Record<Action, string> = {
  rate_limited: "text-yellow-400",
  blocked: "text-red-400",
  monitoring: "text-blue-400",
};

// ══════════════════════════════════════════════════════════════
// Heat Map Bar Component
// ══════════════════════════════════════════════════════════════

function HeatMapBar({ item, max }: { item: EndpointHeat; max: number }) {
  const percentage = (item.abuse_count / max) * 100;
  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      className="space-y-2"
    >
      <div className="flex items-center justify-between">
        <span className="text-sm font-mono text-slate-300">{item.endpoint}</span>
        <span className="text-xs text-slate-500">{item.abuse_count} incidents</span>
      </div>
      <div className="w-full bg-slate-700 rounded-full h-3 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={{ duration: 0.6, delay: 0.3 }}
          className="h-3 rounded-full bg-gradient-to-r from-orange-400 to-red-500"
        />
      </div>
      <div className="flex flex-wrap gap-1 mt-1">
        {item.pattern_types.map((pt) => (
          <Badge key={pt} variant="secondary" className="text-[10px] capitalize">
            {pt.replace("_", " ")}
          </Badge>
        ))}
      </div>
    </motion.div>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function APIAbuseDashboard() {
  const [selectedIP, setSelectedIP] = useState<string | null>(null);

  const activeThreatCount = MOCK_PATTERNS.filter((p) => p.action === "blocked").length;
  const rateLimitViolations = MOCK_EVENTS.filter((e) => e.severity === "critical" || e.severity === "high").length;
  const suspiciousIPs = MOCK_PATTERNS.length;
  const blockedToday = MOCK_EVENTS.length;
  const maxEndpointCount = Math.max(...MOCK_ENDPOINTS.map((e) => e.abuse_count));

  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      {/* Header */}
      <PageHeader
        title="API Abuse Detection"
        description="Anomalous API usage patterns and threat detection"
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Active Threats"
          value={activeThreatCount}
          icon={AlertTriangle}
          change={3}
          changeLabel="new today"
        />
        <KpiCard
          title="Rate Limit Violations"
          value={rateLimitViolations}
          icon={Zap}
        />
        <KpiCard
          title="Suspicious IPs"
          value={suspiciousIPs}
          icon={Globe}
        />
        <KpiCard
          title="Blocked Requests Today"
          value={blockedToday}
          icon={Ban}
        />
      </div>

      {/* Active Abuse Patterns Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              Active Abuse Patterns
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">IP Address</TableHead>
                    <TableHead className="text-slate-300">Pattern Type</TableHead>
                    <TableHead className="text-slate-300">Requests/Min</TableHead>
                    <TableHead className="text-slate-300">Endpoints Targeted</TableHead>
                    <TableHead className="text-slate-300">Threat Score</TableHead>
                    <TableHead className="text-slate-300">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {MOCK_PATTERNS.map((pattern, idx) => {
                    const ActionIcon = ACTION_ICONS[pattern.action];
                    return (
                      <motion.tr
                        key={pattern.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                        className={cn(
                          "border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors cursor-pointer",
                          selectedIP === pattern.ip_address && "bg-slate-800/50"
                        )}
                        onClick={() => setSelectedIP(selectedIP === pattern.ip_address ? null : pattern.ip_address)}
                      >
                        <TableCell className="text-slate-300 font-mono">
                          <Globe className="w-4 h-4 inline mr-2 text-slate-500" />
                          {pattern.ip_address}
                        </TableCell>
                        <TableCell>
                          <Badge className={cn("text-xs font-semibold capitalize", PATTERN_COLORS[pattern.pattern_type])}>
                            {pattern.pattern_type.replace("_", " ")}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-slate-300 font-semibold">
                          <TrendingUp className="w-4 h-4 inline mr-2 text-slate-500" />
                          {pattern.requests_per_min}
                        </TableCell>
                        <TableCell className="text-slate-300">{pattern.endpoints_targeted}</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <div className="w-12 h-2 bg-slate-700 rounded-full overflow-hidden">
                              <div
                                className={cn(
                                  "h-2 rounded-full",
                                  pattern.threat_score >= 90
                                    ? "bg-red-500"
                                    : pattern.threat_score >= 75
                                      ? "bg-orange-500"
                                      : "bg-yellow-500"
                                )}
                                style={{ width: `${pattern.threat_score}%` }}
                              />
                            </div>
                            <span className="text-xs text-slate-400 w-6 text-right">{pattern.threat_score}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <ActionIcon className={cn("w-4 h-4", ACTION_COLORS[pattern.action])} />
                            <Badge
                              variant={pattern.action === "blocked" ? "destructive" : "secondary"}
                              className="text-xs capitalize"
                            >
                              {pattern.action.replace("_", " ")}
                            </Badge>
                          </div>
                        </TableCell>
                      </motion.tr>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Endpoint Heat Map + Blocked IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Endpoint Heat Map */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-2"
        >
          <Card className="border-slate-700">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-orange-400" />
                Endpoint Heat Map
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6 space-y-6">
              {MOCK_ENDPOINTS.map((endpoint, idx) => (
                <HeatMapBar key={endpoint.endpoint} item={endpoint} max={maxEndpointCount} />
              ))}
            </CardContent>
          </Card>
        </motion.div>

        {/* Blocked IPs */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="border-slate-700 h-full">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2 text-base">
                <Ban className="w-5 h-5 text-red-400" />
                Blocked IPs
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              {MOCK_BLOCKED_IPS.map((blocked, idx) => (
                <motion.div
                  key={blocked.ip_address}
                  initial={{ opacity: 0, x: -4 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.3 + idx * 0.05 }}
                  className="p-3 rounded-lg bg-red-500/5 border border-red-500/20 space-y-2"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="font-mono text-sm text-red-300">{blocked.ip_address}</p>
                      <p className="text-xs text-slate-500 mt-1">CIDR: {blocked.cidr}</p>
                    </div>
                    <Badge variant="destructive" className="text-xs">
                      {blocked.count}
                    </Badge>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{blocked.reason}</p>
                  <p className="text-[11px] text-slate-600">{blocked.blocked_at}</p>
                </motion.div>
              ))}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Rate Limit Events Timeline */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-cyan-400" />
              Rate Limit Events Timeline
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-4">
            {MOCK_EVENTS.map((event, idx) => (
              <motion.div
                key={event.id}
                initial={{ opacity: 0, x: -4 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.4 + idx * 0.05 }}
                className={cn(
                  "p-4 rounded-lg border-l-4 transition-all",
                  event.severity === "critical"
                    ? "border-l-red-500 bg-red-500/5"
                    : event.severity === "high"
                      ? "border-l-orange-500 bg-orange-500/5"
                      : event.severity === "medium"
                        ? "border-l-yellow-500 bg-yellow-500/5"
                        : "border-l-blue-500 bg-blue-500/5"
                )}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-sm text-slate-300">{event.endpoint}</span>
                      <Badge variant={event.severity as any} className="text-xs">
                        {event.severity}
                      </Badge>
                    </div>
                    <p className="text-sm text-slate-400">
                      <Globe className="w-4 h-4 inline mr-2" />
                      {event.ip_address}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="font-semibold text-slate-200">{event.requests}</p>
                    <p className="text-xs text-slate-500">requests</p>
                  </div>
                </div>
                <p className="text-xs text-slate-500 mt-2 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {event.timestamp}
                </p>
              </motion.div>
            ))}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
