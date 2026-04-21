/**
 * Zero Trust Policy Dashboard
 *
 * Policy management and decision tracking with:
 *   1. Zero Trust Score gauge (0-100) with maturity levels
 *   2. 5 Pillars status cards (Identity, Device, Network, Application, Data)
 *   3. Active Policies table with enforcement actions
 *   4. Policy Decision Log with allow/deny decisions
 *   5. Micro-Segmentation Map (text-based network zones)
 *
 * API: GET /api/v1/zero-trust/policies, /api/v1/zero-trust/score
 * Fallback: mock data when API is unavailable
 */

import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Shield, ShieldAlert, ShieldCheck, Lock, Zap, RefreshCw,
  AlertCircle, CheckCircle, Clock, MapPin, Users, Database,
  Smartphone, Wifi, Code2, BarChart3,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";
import { usePageTitle } from "@/hooks/use-page-title";

const API_BASE = import.meta.env.VITE_API_URL || "";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type Action = "Allow" | "Deny" | "Quarantine" | "Step-Up Auth";
type MaturityLevel = "Traditional" | "Basic" | "Intermediate" | "Advanced" | "Optimal";

interface PillarStatus {
  name: string;
  maturity: number;
  status: "Good" | "Warning" | "Critical";
  findings: string[];
  icon: React.ReactNode;
}

interface Policy {
  id: string;
  policy_name: string;
  action: Action;
  conditions: string;
  entities_matched: number;
  last_triggered: string;
}

interface Decision {
  id: string;
  timestamp: string;
  user: string;
  resource: string;
  policy_matched: string;
  action_taken: "Allow" | "Deny" | "Quarantine" | "Step-Up Auth";
}

interface ZeroTrustData {
  score: number;
  maturity_level: MaturityLevel;
  pillars: PillarStatus[];
  policies: Policy[];
  decisions: Decision[];
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_ZERO_TRUST_DATA: ZeroTrustData = {
  score: 72,
  maturity_level: "Intermediate",
  pillars: [
    {
      name: "Identity",
      maturity: 85,
      status: "Good",
      findings: ["MFA enabled for 92% of users", "Privileged access review completed"],
      icon: <Users className="w-5 h-5" />,
    },
    {
      name: "Device",
      maturity: 68,
      status: "Warning",
      findings: ["95% devices enrolled in MDM", "Device compliance scoring needed"],
      icon: <Smartphone className="w-5 h-5" />,
    },
    {
      name: "Network",
      maturity: 72,
      status: "Warning",
      findings: ["Micro-segmentation: 6 zones active", "3 legacy unmanaged subnets detected"],
      icon: <Wifi className="w-5 h-5" />,
    },
    {
      name: "Application",
      maturity: 71,
      status: "Warning",
      findings: ["74% apps have least-privilege policies", "Legacy app access requires review"],
      icon: <Code2 className="w-5 h-5" />,
    },
    {
      name: "Data",
      maturity: 65,
      status: "Critical",
      findings: ["Encryption in transit: 89% compliant", "Classification coverage: 42% — needs expansion"],
      icon: <Database className="w-5 h-5" />,
    },
  ],
  policies: [
    {
      id: "p1",
      policy_name: "MFA required for admin access",
      action: "Step-Up Auth",
      conditions: "role == admin AND mfa_disabled",
      entities_matched: 12,
      last_triggered: "2026-04-14 09:32:15",
    },
    {
      id: "p2",
      policy_name: "Block Tor exit nodes",
      action: "Deny",
      conditions: "ip_origin == tor_exit_node",
      entities_matched: 47,
      last_triggered: "2026-04-14 08:47:22",
    },
    {
      id: "p3",
      policy_name: "Quarantine unmanaged devices",
      action: "Quarantine",
      conditions: "device_status == unmanaged AND network_access_attempt",
      entities_matched: 8,
      last_triggered: "2026-04-13 16:21:09",
    },
    {
      id: "p4",
      policy_name: "Deny access from sanctioned countries",
      action: "Deny",
      conditions: "geo_location IN [sanctioned_list]",
      entities_matched: 23,
      last_triggered: "2026-04-14 10:15:44",
    },
    {
      id: "p5",
      policy_name: "Step-up auth for sensitive data",
      action: "Step-Up Auth",
      conditions: "resource_classification == sensitive AND access_type == export",
      entities_matched: 156,
      last_triggered: "2026-04-14 13:28:30",
    },
    {
      id: "p6",
      policy_name: "Allow trusted networks",
      action: "Allow",
      conditions: "ip_range IN corporate_vpn OR office_networks",
      entities_matched: 1842,
      last_triggered: "2026-04-14 14:05:12",
    },
  ],
  decisions: [
    {
      id: "d1",
      timestamp: "2026-04-14 14:32:10",
      user: "alice@company.com",
      resource: "Finance_Database",
      policy_matched: "Step-up auth for sensitive data",
      action_taken: "Allow",
    },
    {
      id: "d2",
      timestamp: "2026-04-14 14:28:55",
      user: "bob@company.com",
      resource: "Export Reports",
      policy_matched: "Step-up auth for sensitive data",
      action_taken: "Step-Up Auth",
    },
    {
      id: "d3",
      timestamp: "2026-04-14 14:15:22",
      user: "192.168.1.105",
      resource: "VPN_Gateway",
      policy_matched: "Block Tor exit nodes",
      action_taken: "Deny",
    },
    {
      id: "d4",
      timestamp: "2026-04-14 14:02:08",
      user: "device_xyz",
      resource: "Network_Segment_A",
      policy_matched: "Quarantine unmanaged devices",
      action_taken: "Quarantine",
    },
    {
      id: "d5",
      timestamp: "2026-04-14 13:58:33",
      user: "charlie@company.com",
      resource: "Admin_Panel",
      policy_matched: "MFA required for admin access",
      action_taken: "Allow",
    },
    {
      id: "d6",
      timestamp: "2026-04-14 13:45:12",
      user: "192.45.120.200",
      resource: "API_Gateway",
      policy_matched: "Deny access from sanctioned countries",
      action_taken: "Deny",
    },
  ],
};

// ══════════════════════════════════════════════════════════════
// SVG Components
// ══════════════════════════════════════════════════════════════

/**
 * Zero Trust Score Gauge (SVG circular progress)
 */
const ZeroTrustGauge = ({ score, maturityLevel }: { score: number; maturityLevel: MaturityLevel }) => {
  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getColor = () => {
    if (score >= 80) return "#10b981"; // emerald
    if (score >= 60) return "#f59e0b"; // amber
    return "#ef4444"; // red
  };

  const getMobilityDescription = (level: MaturityLevel) => {
    const descriptions: Record<MaturityLevel, string> = {
      Traditional: "Legacy trust model",
      Basic: "Foundational controls",
      Intermediate: "Balanced approach",
      Advanced: "Strong posture",
      Optimal: "Industry leading",
    };
    return descriptions[level];
  };

  return (
    <div className="flex flex-col items-center justify-center gap-4">
      <div className="relative w-52 h-52">
        <svg width="200" height="200" className="transform -rotate-90 absolute inset-0">
          <circle cx="100" cy="100" r="45" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="8" />
          <circle
            cx="100"
            cy="100"
            r="45"
            fill="none"
            stroke={getColor()}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{ transition: "all 0.3s ease-in-out" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-4xl font-bold text-white">{score}</div>
          <div className="text-xs text-gray-400">/ 100</div>
        </div>
      </div>
      <div className="text-center">
        <Badge className={cn(
          "font-semibold px-3 py-1",
          score >= 80 ? "bg-emerald-600 hover:bg-emerald-700" :
          score >= 60 ? "bg-amber-600 hover:bg-amber-700" :
          "bg-red-600 hover:bg-red-700"
        )}>
          {maturityLevel}
        </Badge>
        <p className="text-xs text-gray-400 mt-2">{getMobilityDescription(maturityLevel)}</p>
      </div>
    </div>
  );
};

/**
 * Micro-Segmentation Map (text-based network diagram)
 */
const MicroSegmentationMap = () => {
  return (
    <div className="bg-slate-900/30 rounded-lg p-6 border border-slate-700 font-mono text-xs space-y-3">
      <div className="text-gray-300 mb-4">Network Micro-Segmentation Zones</div>

      <div className="flex gap-2 flex-wrap">
        {/* Zone boxes */}
        <div className="border border-emerald-500/50 bg-emerald-500/10 px-3 py-2 rounded">
          <div className="text-emerald-400 font-semibold">Zone 1: DMZ</div>
          <div className="text-gray-400 text-xs">Public-facing apps</div>
        </div>

        <div className="border border-blue-500/50 bg-blue-500/10 px-3 py-2 rounded">
          <div className="text-blue-400 font-semibold">Zone 2: Corp</div>
          <div className="text-gray-400 text-xs">Internal services</div>
        </div>

        <div className="border border-purple-500/50 bg-purple-500/10 px-3 py-2 rounded">
          <div className="text-purple-400 font-semibold">Zone 3: Data</div>
          <div className="text-gray-400 text-xs">Database tier</div>
        </div>

        <div className="border border-yellow-500/50 bg-yellow-500/10 px-3 py-2 rounded">
          <div className="text-yellow-400 font-semibold">Zone 4: Admin</div>
          <div className="text-gray-400 text-xs">Privileged access</div>
        </div>

        <div className="border border-red-500/50 bg-red-500/10 px-3 py-2 rounded">
          <div className="text-red-400 font-semibold">Zone 5: Isolated</div>
          <div className="text-gray-400 text-xs">High-risk systems</div>
        </div>

        <div className="border border-gray-500/50 bg-gray-500/10 px-3 py-2 rounded">
          <div className="text-gray-400 font-semibold">Zone 6: Guest</div>
          <div className="text-gray-500 text-xs">Visitor network</div>
        </div>
      </div>

      <Separator className="my-2 bg-slate-700" />

      <div className="text-gray-400 text-xs space-y-1">
        <div>Zone Connections:</div>
        <div className="ml-2">DMZ ↔ Corp (strict rules) | Corp ↔ Data (auth required)</div>
        <div className="ml-2">Admin → All (with approval) | Guest (isolated)</div>
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function ZeroTrustDashboard() {
  usePageTitle("Zero Trust");
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null);

  // Fetch Zero Trust data
  const { data, isLoading, refetch } = useQuery<ZeroTrustData>({
    queryKey: ["zero-trust-policies"],
    queryFn: async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/zero-trust/policies?org_id=default`);
        if (!response.ok) throw new Error("Failed to fetch");
        return response.json();
      } catch {
        return MOCK_ZERO_TRUST_DATA;
      }
    },
    staleTime: 60000,
  });

  if (isLoading) return <PageSkeleton />;

  const zeroTrustData = data || MOCK_ZERO_TRUST_DATA;

  return (
    <div className="space-y-6 pb-8">
      {/* Page Header */}
      <PageHeader
        title="Zero Trust Policy Engine"
        description="Never trust, always verify"
        action={
          <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-2">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
        }
      />

      {/* Zero Trust Score Card */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Card className="bg-slate-800/40 border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-400" />
              Zero Trust Maturity Score
            </CardTitle>
          </CardHeader>
          <CardContent className="flex justify-center py-8">
            <ZeroTrustGauge score={zeroTrustData.score} maturityLevel={zeroTrustData.maturity_level} />
          </CardContent>
        </Card>
      </motion.div>

      {/* 5 Pillars Status Cards */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {zeroTrustData.pillars.map((pillar, idx) => {
            const statusColor = pillar.status === "Good" ? "emerald" : pillar.status === "Warning" ? "amber" : "red";
            const bgColor = statusColor === "emerald" ? "bg-emerald-500/10 border-emerald-500/50" :
                           statusColor === "amber" ? "bg-amber-500/10 border-amber-500/50" :
                           "bg-red-500/10 border-red-500/50";
            const textColor = statusColor === "emerald" ? "text-emerald-400" :
                             statusColor === "amber" ? "text-amber-400" :
                             "text-red-400";

            return (
              <motion.div
                key={pillar.name}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.15 + idx * 0.05 }}
              >
                <Card className={`border ${bgColor}`}>
                  <CardContent className="pt-6">
                    <div className="flex items-start justify-between mb-3">
                      <div className={textColor}>{pillar.icon}</div>
                      <Badge variant="outline" className={cn("text-xs", textColor)}>
                        {pillar.status}
                      </Badge>
                    </div>
                    <div className="font-semibold text-white mb-1">{pillar.name}</div>
                    <div className="mb-3">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs text-gray-400">Maturity</span>
                        <span className={`text-sm font-bold ${textColor}`}>{pillar.maturity}%</span>
                      </div>
                      <div className="w-full bg-slate-700 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full transition-all ${statusColor === "emerald" ? "bg-emerald-500" : statusColor === "amber" ? "bg-amber-500" : "bg-red-500"}`}
                          style={{ width: `${pillar.maturity}%` }}
                        />
                      </div>
                    </div>
                    <div className="space-y-1">
                      {pillar.findings.map((finding, idx) => (
                        <div key={idx} className="text-xs text-gray-400 flex gap-2">
                          <span className="text-gray-600 flex-shrink-0">•</span>
                          <span>{finding}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </div>
      </motion.div>

      {/* Active Policies Table */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
        <Card className="bg-slate-800/40 border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-amber-400" />
              Active Policies ({zeroTrustData.policies.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700 hover:bg-transparent">
                    <TableHead className="text-gray-400">Policy Name</TableHead>
                    <TableHead className="text-gray-400">Action</TableHead>
                    <TableHead className="text-gray-400">Conditions</TableHead>
                    <TableHead className="text-gray-400 text-right">Entities Matched</TableHead>
                    <TableHead className="text-gray-400">Last Triggered</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {zeroTrustData.policies.map((policy) => {
                    const actionColor = policy.action === "Allow" ? "emerald" :
                                       policy.action === "Deny" ? "red" :
                                       policy.action === "Quarantine" ? "amber" :
                                       "blue";
                    return (
                      <TableRow key={policy.id} className="border-slate-700 hover:bg-slate-800/40">
                        <TableCell className="font-medium text-white">{policy.policy_name}</TableCell>
                        <TableCell>
                          <Badge className={cn(
                            "font-semibold",
                            actionColor === "emerald" ? "bg-emerald-600 hover:bg-emerald-700" :
                            actionColor === "red" ? "bg-red-600 hover:bg-red-700" :
                            actionColor === "amber" ? "bg-amber-600 hover:bg-amber-700" :
                            "bg-blue-600 hover:bg-blue-700"
                          )}>
                            {policy.action}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-gray-400 text-sm max-w-xs truncate">{policy.conditions}</TableCell>
                        <TableCell className="text-right text-gray-400">{policy.entities_matched}</TableCell>
                        <TableCell className="text-gray-400 text-sm">{policy.last_triggered}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Policy Decision Log */}
        <motion.div
          className="lg:col-span-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="bg-slate-800/40 border-slate-700 h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-purple-400" />
                Policy Decision Log
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {zeroTrustData.decisions.map((decision) => {
                  const isAllow = decision.action_taken === "Allow";
                  const isDeny = decision.action_taken === "Deny";
                  const isQuarantine = decision.action_taken === "Quarantine";
                  const isStepUp = decision.action_taken === "Step-Up Auth";

                  return (
                    <div
                      key={decision.id}
                      className="border border-slate-700 rounded-lg p-3 bg-slate-900/20 hover:bg-slate-900/40 transition-colors"
                    >
                      <div className="flex items-start justify-between gap-3 mb-2">
                        <div className="flex items-center gap-2 flex-1">
                          {isAllow && <CheckCircle className="w-4 h-4 text-emerald-500 flex-shrink-0" />}
                          {isDeny && <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0" />}
                          {isQuarantine && <AlertCircle className="w-4 h-4 text-amber-500 flex-shrink-0" />}
                          {isStepUp && <Lock className="w-4 h-4 text-blue-500 flex-shrink-0" />}
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-white truncate">{decision.user}</div>
                            <div className="text-xs text-gray-400">{decision.timestamp}</div>
                          </div>
                        </div>
                        <Badge className={cn(
                          "text-xs font-semibold flex-shrink-0",
                          isAllow ? "bg-emerald-600 hover:bg-emerald-700" :
                          isDeny ? "bg-red-600 hover:bg-red-700" :
                          isQuarantine ? "bg-amber-600 hover:bg-amber-700" :
                          "bg-blue-600 hover:bg-blue-700"
                        )}>
                          {decision.action_taken}
                        </Badge>
                      </div>
                      <div className="text-xs space-y-1">
                        <div className="text-gray-400">
                          <span className="text-gray-500">Resource:</span> {decision.resource}
                        </div>
                        <div className="text-gray-400">
                          <span className="text-gray-500">Policy:</span> {decision.policy_matched}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Micro-Segmentation Map */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <Card className="bg-slate-800/40 border-slate-700 h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MapPin className="w-5 h-5 text-cyan-400" />
                Segmentation Map
              </CardTitle>
            </CardHeader>
            <CardContent>
              <MicroSegmentationMap />
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
