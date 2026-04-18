/**
 * Access Request Management Dashboard
 *
 * Access request lifecycle tracking with approval workflow and expiry monitoring.
 *   1. KPIs: Total Requests, Pending, Approved, Avg Approval Time (hrs)
 *   2. Requests table (resource, access_type, requester_id, status, request_date, expires_at)
 *
 * Route: /access-requests
 * API: GET /api/v1/access-requests
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { KeyRound, RefreshCw, Clock, CheckCircle2, HourglassIcon, BarChart2 } from "lucide-react";

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
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_REQUESTS = [
  { id: "req-001", resource: "prod-db-primary",       access_type: "read",       requester_id: "alice@corp.io",   status: "approved", request_date: "2026-04-14T09:10:00Z", expires_at: "2026-05-14T09:10:00Z" },
  { id: "req-002", resource: "s3-financial-reports",  access_type: "write",      requester_id: "bob@corp.io",     status: "pending",  request_date: "2026-04-16T07:45:00Z", expires_at: null },
  { id: "req-003", resource: "k8s-prod-namespace",    access_type: "admin",      requester_id: "carol@corp.io",   status: "rejected", request_date: "2026-04-15T14:22:00Z", expires_at: null },
  { id: "req-004", resource: "vpn-tier2",             access_type: "ssh",        requester_id: "dave@corp.io",    status: "approved", request_date: "2026-04-13T11:00:00Z", expires_at: "2026-04-30T11:00:00Z" },
  { id: "req-005", resource: "github-secrets",        access_type: "read",       requester_id: "eve@corp.io",     status: "revoked",  request_date: "2026-04-10T08:30:00Z", expires_at: "2026-04-15T08:30:00Z" },
  { id: "req-006", resource: "azure-subscription",    access_type: "contributor",requester_id: "frank@corp.io",   status: "pending",  request_date: "2026-04-16T09:01:00Z", expires_at: null },
  { id: "req-007", resource: "elk-cluster",           access_type: "read",       requester_id: "grace@corp.io",   status: "approved", request_date: "2026-04-12T16:55:00Z", expires_at: "2026-05-12T16:55:00Z" },
  { id: "req-008", resource: "vault-secrets-engine",  access_type: "write",      requester_id: "henry@corp.io",   status: "pending",  request_date: "2026-04-16T06:20:00Z", expires_at: null },
  { id: "req-009", resource: "splunk-admin-panel",    access_type: "admin",      requester_id: "irene@corp.io",   status: "approved", request_date: "2026-04-11T10:00:00Z", expires_at: "2026-07-11T10:00:00Z" },
  { id: "req-010", resource: "gcp-bigquery",          access_type: "read",       requester_id: "james@corp.io",   status: "rejected", request_date: "2026-04-15T13:40:00Z", expires_at: null },
];

const MOCK_STATS = { total_requests: 284, pending: 41, approved: 198, avg_approval_time_hrs: 3.7 };

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    approved: "border-green-500/30 text-green-400 bg-green-500/10",
    rejected: "border-red-500/30 text-red-400 bg-red-500/10",
    revoked:  "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function formatTs(ts: string | null) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function exportCsv(rows: any[]) {
  const headers = ["resource", "access_type", "requester_id", "status", "request_date", "expires_at"];
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => `"${r[h] ?? ""}"`).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "access_requests.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function AccessRequestManagementDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveRequests, setLiveRequests] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/access-requests/requests?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/access-requests/stats?org_id=${ORG_ID}`),
    ]).then(([reqRes, statsRes]) => {
      if (reqRes.status === "fulfilled") setLiveRequests(reqRes.value?.requests ?? reqRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const requests = liveRequests ?? MOCK_REQUESTS;
  const stats    = liveStats    ?? MOCK_STATS;

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
      <PageHeader
        title="Access Request Management"
        description="Access provisioning lifecycle — track pending approvals, granted access, and expiry enforcement"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Requests"       value={stats.total_requests}                          icon={KeyRound}       trend="flat" className="border-blue-500/20" />
        <KpiCard title="Pending"              value={stats.pending}                                 icon={HourglassIcon}  trend="flat" className="border-cyan-500/20" />
        <KpiCard title="Approved"             value={stats.approved}                                icon={CheckCircle2}   trend="up"   className="border-blue-500/20" />
        <KpiCard title="Avg Approval (hrs)"   value={`${stats.avg_approval_time_hrs}h`}             icon={Clock}          trend="down" className="border-cyan-500/20" />
      </div>

      {/* Requests Table */}
      <Card className="border-blue-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-blue-400">
              <BarChart2 className="h-4 w-4" />
              Access Request Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10">
                {requests.filter((r: any) => r.status === "pending").length} pending
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(requests)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            Resource access requests with type, requester, approval status, and expiry
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Resource</TableHead>
                  <TableHead className="text-[11px] h-8">Access Type</TableHead>
                  <TableHead className="text-[11px] h-8">Requester</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Request Date</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Expires At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {requests.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  requests.map((req: any, i: number) => (
                  <TableRow key={req.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-blue-300 max-w-[180px] truncate">
                      {req.resource ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-cyan-300">
                      {req.access_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {req.requester_id ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={req.status ?? "pending"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {formatTs(req.request_date)}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                      {formatTs(req.expires_at)}
                    </TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
