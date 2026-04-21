/**
 * Change Management Dashboard
 *
 * IT change management with risk assessment and approval lifecycle tracking.
 *   1. KPIs: Total Changes, Pending Review, Approved, Emergency Changes
 *   2. Changes table (title, change_type, priority, risk_level, status, requested_by)
 *
 * Route: /change-management
 * API: GET /api/v1/change-management
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { GitMerge, RefreshCw, Clock, CheckCircle, Zap, List } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_CHANGES = [
  { id: "chg-001", title: "Firewall rule update — DMZ egress",     change_type: "standard",  priority: "high",   risk_level: "high",   status: "pending_review", requested_by: "ops-team"    },
  { id: "chg-002", title: "Patch CVE-2026-1234 on prod servers",   change_type: "emergency", priority: "urgent", risk_level: "high",   status: "approved",       requested_by: "security"    },
  { id: "chg-003", title: "MFA rollout — finance department",      change_type: "normal",    priority: "medium", risk_level: "medium", status: "approved",       requested_by: "it-admin"    },
  { id: "chg-004", title: "VPN gateway migration",                 change_type: "major",     priority: "high",   risk_level: "high",   status: "pending_review", requested_by: "network-eng" },
  { id: "chg-005", title: "TLS 1.0 deprecation",                  change_type: "standard",  priority: "medium", risk_level: "low",    status: "completed",      requested_by: "sec-arch"    },
  { id: "chg-006", title: "SIEM rule tuning — false positive fix", change_type: "normal",    priority: "low",    risk_level: "low",    status: "approved",       requested_by: "soc-analyst" },
  { id: "chg-007", title: "Certificate renewal — wildcard cert",   change_type: "standard",  priority: "urgent", risk_level: "medium", status: "emergency",      requested_by: "devops"      },
  { id: "chg-008", title: "IDS signature update",                  change_type: "normal",    priority: "low",    risk_level: "low",    status: "completed",      requested_by: "noc-team"    },
  { id: "chg-009", title: "Zero-day patch — kernel vulnerability", change_type: "emergency", priority: "urgent", risk_level: "high",   status: "emergency",      requested_by: "security"    },
  { id: "chg-010", title: "Backup configuration change",           change_type: "standard",  priority: "low",    risk_level: "low",    status: "pending_review", requested_by: "it-admin"    },
];

const MOCK_STATS = { total_changes: 83, pending_review: 12, approved: 31, emergency_changes: 4 };

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending_review: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    approved:       "border-green-500/30 text-green-400 bg-green-500/10",
    completed:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    emergency:      "border-red-500/30 text-red-400 bg-red-500/10",
    rejected:       "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  const label: Record<string, string> = {
    pending_review: "Pending Review",
    approved:       "Approved",
    completed:      "Completed",
    emergency:      "Emergency",
    rejected:       "Rejected",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    high:   "border-red-500/30 text-red-400 bg-red-500/10",
    medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const map: Record<string, string> = {
    urgent: "border-red-500/30 text-red-400 bg-red-500/10",
    high:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[priority] ?? "border-border")}>
      {priority}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function ChangeManagementDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveChanges, setLiveChanges] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/change-management/changes?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/change-management/stats?org_id=${ORG_ID}`),
    ]).then(([changesRes, statsRes]) => {
      if (changesRes.status === "fulfilled") setLiveChanges(changesRes.value?.changes ?? changesRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
    setLoading(false);
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const changes = liveChanges ?? MOCK_CHANGES;
  const stats   = liveStats   ?? MOCK_STATS;


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Change Management"
        description="IT change request lifecycle, risk assessment, and approval workflow tracking for security-aware change control"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Changes"     value={stats.total_changes}     icon={List}        trend="flat" className="border-purple-500/20" />
        <KpiCard title="Pending Review"    value={stats.pending_review}    icon={Clock}       trend="flat" className="border-yellow-500/20" />
        <KpiCard title="Approved"          value={stats.approved}          icon={CheckCircle} trend="up"   className="border-violet-500/20" />
        <KpiCard title="Emergency Changes" value={stats.emergency_changes} icon={Zap}         trend="down" className="border-red-500/20" />
      </div>

      {/* Changes Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <GitMerge className="h-4 w-4" />
              Change Requests
            </CardTitle>
            <Badge className="text-[10px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10">
              {changes.filter((c: any) => c.status === "pending_review").length} pending
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Change requests with type, priority, risk level, and approval status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Requested By</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {changes.map((chg: any, i: number) => (
                  <TableRow key={chg.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-purple-300 max-w-[220px] truncate">
                      {chg.title ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {chg.change_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <PriorityBadge priority={chg.priority ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskBadge level={chg.risk_level ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-violet-300">
                      {chg.requested_by ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <StatusBadge status={chg.status ?? "pending_review"} />
                    </TableCell>
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
