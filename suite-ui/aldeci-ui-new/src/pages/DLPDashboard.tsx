/**
 * Data Loss Prevention Dashboard
 *
 * Sensitive data monitoring and control:
 *   1. KPIs: Violations Today, High Severity, Data Volume Monitored, Policies Active
 *   2. DLP Violations Table: timestamp, user, data_type, action_taken, channel, severity
 *   3. Policy Status Grid: toggle cards for each DLP policy
 *   4. Sensitive Data Map: text-based categorization
 *   5. Recent Incidents Feed
 *
 * Route: /dlp
 * API: GET /api/v1/dlp/violations, /api/v1/dlp/policies, /api/v1/dlp/incidents (mock fallback)
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  Lock,
  FileText,
  Database,
  Mail,
  HardDrive,
  Cloud,
  Printer,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Clock,
  User,
  Zap,
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

type DataType = "PII" | "PCI" | "PHI" | "IP";
type ActionTaken = "blocked" | "warned" | "logged";
type Channel = "email" | "usb" | "cloud" | "print" | "api";
type Severity = "critical" | "high" | "medium" | "low";

interface DLPViolation {
  id: string;
  timestamp: string;
  user: string;
  data_type: DataType;
  action_taken: ActionTaken;
  channel: Channel;
  severity: Severity;
  details: string;
}

interface DLPPolicy {
  id: string;
  name: string;
  enabled: boolean;
  channels: Channel[];
  description: string;
}

interface DLPIncident {
  id: string;
  timestamp: string;
  title: string;
  severity: Severity;
  status: "open" | "resolved";
  user: string;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_VIOLATIONS: DLPViolation[] = [
  {
    id: "DLP-001",
    timestamp: "2026-04-14 14:32",
    user: "john.smith@company.com",
    data_type: "PII",
    action_taken: "blocked",
    channel: "email",
    severity: "high",
    details: "SSN patterns detected in email attachment",
  },
  {
    id: "DLP-002",
    timestamp: "2026-04-14 13:15",
    user: "sarah.johnson@company.com",
    data_type: "PCI",
    action_taken: "warned",
    channel: "cloud",
    severity: "critical",
    details: "Credit card data attempted upload to personal Google Drive",
  },
  {
    id: "DLP-003",
    timestamp: "2026-04-14 11:48",
    user: "mike.davis@company.com",
    data_type: "PHI",
    action_taken: "logged",
    channel: "usb",
    severity: "high",
    details: "Patient records copied to USB device",
  },
  {
    id: "DLP-004",
    timestamp: "2026-04-14 10:22",
    user: "emma.wilson@company.com",
    data_type: "IP",
    action_taken: "blocked",
    channel: "email",
    severity: "medium",
    details: "Proprietary source code in email to external recipient",
  },
  {
    id: "DLP-005",
    timestamp: "2026-04-14 09:51",
    user: "robert.brown@company.com",
    data_type: "PII",
    action_taken: "warned",
    channel: "print",
    severity: "medium",
    details: "Employee directory attempted printing to public printer",
  },
  {
    id: "DLP-006",
    timestamp: "2026-04-14 08:34",
    user: "lisa.chen@company.com",
    data_type: "PCI",
    action_taken: "blocked",
    channel: "api",
    severity: "critical",
    details: "API request included payment card numbers",
  },
];

const MOCK_POLICIES: DLPPolicy[] = [
  {
    id: "POL-001",
    name: "Email DLP",
    enabled: true,
    channels: ["email"],
    description: "Monitor and block sensitive data in email communications",
  },
  {
    id: "POL-002",
    name: "Cloud Upload",
    enabled: true,
    channels: ["cloud"],
    description: "Prevent uploads of classified data to cloud services",
  },
  {
    id: "POL-003",
    name: "USB Transfer",
    enabled: true,
    channels: ["usb"],
    description: "Block sensitive data transfers to USB devices",
  },
  {
    id: "POL-004",
    name: "API Data Exposure",
    enabled: false,
    channels: ["api"],
    description: "Scan API payloads for embedded sensitive data",
  },
  {
    id: "POL-005",
    name: "Print Control",
    enabled: true,
    channels: ["print"],
    description: "Monitor and restrict printing of confidential documents",
  },
];

const MOCK_INCIDENTS: DLPIncident[] = [
  {
    id: "INC-001",
    timestamp: "2026-04-14 14:32",
    title: "PII breach attempt via email",
    severity: "high",
    status: "open",
    user: "john.smith@company.com",
  },
  {
    id: "INC-002",
    timestamp: "2026-04-14 13:15",
    title: "Critical: Credit card data exposure",
    severity: "critical",
    status: "open",
    user: "sarah.johnson@company.com",
  },
  {
    id: "INC-003",
    timestamp: "2026-04-13 16:45",
    title: "Resolved: USB data transfer incident",
    severity: "high",
    status: "resolved",
    user: "mike.davis@company.com",
  },
];

// ══════════════════════════════════════════════════════════════
// Severity & Channel Styling
// ══════════════════════════════════════════════════════════════

const SEV_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/10 text-red-700 border-red-200",
  high: "bg-orange-500/10 text-orange-700 border-orange-200",
  medium: "bg-yellow-500/10 text-yellow-700 border-yellow-200",
  low: "bg-blue-500/10 text-blue-700 border-blue-200",
};

const ACTION_ICONS: Record<ActionTaken, typeof Shield> = {
  blocked: XCircle,
  warned: AlertTriangle,
  logged: FileText,
};

const CHANNEL_ICONS: Record<Channel, typeof Mail> = {
  email: Mail,
  usb: HardDrive,
  cloud: Cloud,
  print: Printer,
  api: Database,
};

const DATA_TYPE_COLORS: Record<DataType, string> = {
  PII: "bg-purple-500/10 text-purple-700",
  PCI: "bg-red-500/10 text-red-700",
  PHI: "bg-blue-500/10 text-blue-700",
  IP: "bg-amber-500/10 text-amber-700",
};

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function DLPDashboard() {
  const [policies, setPolicies] = useState<DLPPolicy[]>(MOCK_POLICIES);

  const criticalCount = MOCK_VIOLATIONS.filter((v) => v.severity === "critical").length;
  const totalDataVolume = "2.4TB"; // Mock
  const enabledPolicies = policies.filter((p) => p.enabled).length;

  const togglePolicy = (policyId: string) => {
    setPolicies((prev) =>
      prev.map((p) => (p.id === policyId ? { ...p, enabled: !p.enabled } : p))
    );
  };

  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      {/* Header */}
      <PageHeader
        title="Data Loss Prevention"
        description="Sensitive data monitoring and control"
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Violations Today"
          value={MOCK_VIOLATIONS.length}
          icon={AlertTriangle}
          change={12}
          changeLabel="vs yesterday"
        />
        <KpiCard
          title="High Severity"
          value={criticalCount}
          icon={AlertCircle}
        />
        <KpiCard
          title="Data Volume Monitored"
          value={totalDataVolume}
          icon={Database}
        />
        <KpiCard
          title="Policies Active"
          value={`${enabledPolicies}/${policies.length}`}
          icon={Shield}
        />
      </div>

      {/* DLP Violations Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-400" />
              DLP Violations
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Timestamp</TableHead>
                    <TableHead className="text-slate-300">User</TableHead>
                    <TableHead className="text-slate-300">Data Type</TableHead>
                    <TableHead className="text-slate-300">Channel</TableHead>
                    <TableHead className="text-slate-300">Action Taken</TableHead>
                    <TableHead className="text-slate-300 text-right">Severity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {MOCK_VIOLATIONS.map((violation, idx) => {
                    const ActionIcon = ACTION_ICONS[violation.action_taken];
                    const ChannelIcon = CHANNEL_ICONS[violation.channel];
                    return (
                      <motion.tr
                        key={violation.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                        className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                      >
                        <TableCell className="text-slate-300 font-mono text-sm">
                          <Clock className="w-4 h-4 inline mr-2 text-slate-500" />
                          {violation.timestamp}
                        </TableCell>
                        <TableCell className="text-slate-300">
                          <User className="w-4 h-4 inline mr-2 text-slate-500" />
                          {violation.user}
                        </TableCell>
                        <TableCell>
                          <Badge className={cn("text-xs font-semibold", DATA_TYPE_COLORS[violation.data_type])}>
                            {violation.data_type}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <ChannelIcon className="w-4 h-4 text-slate-400" />
                            <span className="text-slate-300 capitalize">{violation.channel}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <ActionIcon className="w-4 h-4 text-slate-400" />
                            <span className="text-slate-300 capitalize">{violation.action_taken}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <Badge variant={violation.severity as any} className="text-xs">
                            {violation.severity}
                          </Badge>
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

      {/* Policy Status + Sensitive Data Map */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Policy Status Grid */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-2"
        >
          <Card className="border-slate-700">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-400" />
                Policy Status
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {policies.map((policy) => (
                  <motion.div
                    key={policy.id}
                    layout
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className={cn(
                      "p-4 rounded-lg border-2 transition-all cursor-pointer",
                      policy.enabled
                        ? "border-green-500/30 bg-green-500/5"
                        : "border-slate-600 bg-slate-800/30"
                    )}
                    onClick={() => togglePolicy(policy.id)}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-semibold text-slate-200">{policy.name}</h4>
                      {policy.enabled ? (
                        <CheckCircle2 className="w-5 h-5 text-green-400" />
                      ) : (
                        <XCircle className="w-5 h-5 text-slate-500" />
                      )}
                    </div>
                    <p className="text-sm text-slate-400 mb-3">{policy.description}</p>
                    <div className="flex flex-wrap gap-1">
                      {policy.channels.map((ch) => (
                        <Badge key={ch} variant="secondary" className="text-xs capitalize">
                          {ch}
                        </Badge>
                      ))}
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Sensitive Data Map */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="border-slate-700 h-full">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2 text-base">
                <Database className="w-5 h-5 text-cyan-400" />
                Data Classification
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              {Object.entries(DATA_TYPE_COLORS).map(([type, color]) => {
                const count = MOCK_VIOLATIONS.filter((v) => v.data_type === type).length;
                return (
                  <div key={type}>
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-sm font-semibold text-slate-300">{type}</span>
                      <span className="text-xs text-slate-500">{count} violations</span>
                    </div>
                    <div className="w-full bg-slate-700 rounded-full h-2">
                      <div
                        className={cn("h-2 rounded-full transition-all", color)}
                        style={{
                          width: `${(count / MOCK_VIOLATIONS.length) * 100}%`,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Recent Incidents Feed */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-yellow-400" />
              Recent Incidents
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-4">
            {MOCK_INCIDENTS.map((incident, idx) => (
              <motion.div
                key={incident.id}
                initial={{ opacity: 0, x: -4 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.4 + idx * 0.05 }}
                className={cn(
                  "p-4 rounded-lg border-l-4 transition-all",
                  incident.severity === "critical"
                    ? "border-l-red-500 bg-red-500/5"
                    : incident.severity === "high"
                      ? "border-l-orange-500 bg-orange-500/5"
                      : "border-l-yellow-500 bg-yellow-500/5"
                )}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-semibold text-slate-200">{incident.title}</h4>
                      <Badge variant={incident.severity as any} className="text-xs">
                        {incident.severity}
                      </Badge>
                    </div>
                    <p className="text-xs text-slate-400 mb-2">{incident.user}</p>
                    <p className="text-xs text-slate-500">{incident.timestamp}</p>
                  </div>
                  <Badge
                    variant={incident.status === "open" ? "destructive" : "secondary"}
                    className="text-xs capitalize"
                  >
                    {incident.status}
                  </Badge>
                </div>
              </motion.div>
            ))}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
