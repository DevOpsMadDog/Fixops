import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Shield, Users, Activity, Calendar, Search, RefreshCw,
  Download, CheckCircle, XCircle, AlertTriangle, Link2, FileJson, Files
} from "lucide-react";
import { useAuditLog } from "@/hooks/use-api";
import { cn, getInitials } from "@/lib/utils";

const ACTION_COLORS: Record<string, string> = {
  create: "bg-green-900/40 text-green-400 border-green-700",
  update: "bg-blue-900/40 text-blue-400 border-blue-700",
  delete: "bg-red-900/40 text-red-400 border-red-700",
  login: "bg-violet-900/40 text-violet-400 border-violet-700",
  logout: "bg-gray-900/40 text-gray-400 border-gray-700",
  approve: "bg-teal-900/40 text-teal-400 border-teal-700",
  reject: "bg-orange-900/40 text-orange-400 border-orange-700",
  view: "bg-slate-900/40 text-slate-400 border-slate-600",
  export: "bg-yellow-900/40 text-yellow-400 border-yellow-700",
};

function getActionColor(action: string) {
  const lower = action.toLowerCase();
  for (const [key, cls] of Object.entries(ACTION_COLORS)) {
    if (lower.includes(key)) return cls;
  }
  return "bg-muted text-muted-foreground";
}

function HashBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <Badge className="gap-1 text-xs bg-green-900/40 text-green-400 border-green-700">
      <CheckCircle className="h-2.5 w-2.5" />
      Hash Verified
    </Badge>
  ) : (
    <Badge variant="destructive" className="gap-1 text-xs">
      <XCircle className="h-2.5 w-2.5" />
      Tampered
    </Badge>
  );
}

export default function AuditTrail() {
  const auditQuery = useAuditLog();
  const refetch = useCallback(() => auditQuery.refetch(), [auditQuery]);

  const [search, setSearch] = useState("");
  const [actorFilter, setActorFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [dateRange, setDateRange] = useState("all");

  if (auditQuery.isLoading) return <PageSkeleton />;
  if (auditQuery.isError) return <ErrorState message="Failed to load audit logs" onRetry={refetch} />;

  const logs: any[] = auditQuery.data?.data ?? auditQuery.data ?? [];

  const totalEvents = logs.length;
  const today = new Date().toDateString();
  const todayCount = logs.filter((l: any) => {
    if (!l.timestamp && !l.created_at) return false;
    return new Date(l.timestamp ?? l.created_at).toDateString() === today;
  }).length;
  const thisWeek = logs.filter((l: any) => {
    if (!l.timestamp && !l.created_at) return false;
    const d = new Date(l.timestamp ?? l.created_at);
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    return d > weekAgo;
  }).length;
  const actors = Array.from(new Set(logs.map((l: any) => l.actor ?? l.user ?? l.actor_name).filter(Boolean)));
  const actions = Array.from(new Set(logs.map((l: any) => l.action ?? l.event_type).filter(Boolean)));
  const uniqueActors = actors.length;

  // Tamper detection — if any log has hash_valid = false
  const tamperDetected = logs.some((l: any) => l.hash_valid === false || l.tampered === true);

  const filtered = logs.filter((l: any) => {
    const q = search.toLowerCase();
    const actor = l.actor ?? l.user ?? l.actor_name ?? "";
    const action = l.action ?? l.event_type ?? "";
    const resource = l.resource ?? l.target ?? "";
    const msg = l.message ?? "";
    const matchesSearch = !search ||
      actor.toLowerCase().includes(q) ||
      action.toLowerCase().includes(q) ||
      resource.toLowerCase().includes(q) ||
      msg.toLowerCase().includes(q);
    const matchesActor = actorFilter === "all" || actor === actorFilter;
    const matchesAction = actionFilter === "all" || action.toLowerCase().includes(actionFilter.toLowerCase());
    const matchesStatus = statusFilter === "all" ||
      (statusFilter === "success" && (l.status ?? "success") === "success") ||
      (statusFilter === "failed" && l.status === "failed");
    return matchesSearch && matchesActor && matchesAction && matchesStatus;
  });

  const handleExportCSV = () => {
    const headers = ["Timestamp", "Actor", "Action", "Resource", "IP", "Status"];
    const rows = filtered.map((l: any) => [
      l.timestamp ?? l.created_at ?? "",
      l.actor ?? l.user ?? "",
      l.action ?? l.event_type ?? "",
      l.resource ?? l.target ?? "",
      l.ip_address ?? l.ip ?? "",
      l.status ?? "success",
    ]);
    const csv = [headers, ...rows].map((row) => row.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit-trail.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportJSON = () => {
    const json = JSON.stringify(filtered, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit-trail.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Audit Trail"
        description="Complete tamper-evident audit log with hash-chain verification"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Button variant="outline" size="sm" onClick={handleExportCSV} className="gap-2">
          <Download className="h-4 w-4" />
          CSV
        </Button>
        <Button variant="outline" size="sm" onClick={handleExportJSON} className="gap-2">
          <FileJson className="h-4 w-4" />
          JSON
        </Button>
          </div>
        }
      />

      {/* Tamper detection alert */}
      {tamperDetected && (
        <Alert variant="destructive" className="border-red-800 bg-red-950/40">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription className="font-medium">
            Tamper detected — one or more audit log entries have an invalid hash chain. Immediate investigation required.
          </AlertDescription>
        </Alert>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Events" value={totalEvents} icon={Activity} />
        <KpiCard title="Today" value={todayCount} icon={Calendar} />
        <KpiCard title="This Week" value={thisWeek} icon={Shield} />
        <KpiCard title="Unique Actors" value={uniqueActors} icon={Users} />
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-48">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search actor, action, resource…"
                className="pl-9"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Select value={actorFilter} onValueChange={setActorFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Actor" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Actors</SelectItem>
                {actors.slice(0, 20).map((a) => (
                  <SelectItem key={a} value={a}>{a}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={actionFilter} onValueChange={setActionFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Action" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Actions</SelectItem>
                {actions.slice(0, 20).map((a) => (
                  <SelectItem key={a} value={a}>{a}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="success">Success</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Audit Log Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Link2 className="h-4 w-4 text-primary" />
              Audit Events
            </span>
            <div className="flex items-center gap-2">
              <HashBadge verified={!tamperDetected} />
              <span className="text-sm font-normal text-muted-foreground">{filtered.length} events</span>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Timestamp</TableHead>
                <TableHead className="text-xs">Actor</TableHead>
                <TableHead className="text-xs">Action</TableHead>
                <TableHead className="text-xs">Resource</TableHead>
                <TableHead className="text-xs">IP Address</TableHead>
                <TableHead className="text-xs">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                    No audit events match your filters
                  </TableCell>
                </TableRow>
              ) : (
                filtered.slice(0, 100).map((log: any, i: number) => {
                  const actor = log.actor ?? log.user ?? log.actor_name ?? "system";
                  const action = log.action ?? log.event_type ?? "unknown";
                  const resource = log.resource ?? log.target ?? "—";
                  const ip = log.ip_address ?? log.ip ?? "—";
                  const status = log.status ?? "success";
                  return (
                    <TableRow key={log.id ?? i} className={cn("hover:bg-muted/30", log.hash_valid === false && "bg-red-950/20")}>
                      <TableCell className="font-mono text-xs text-muted-foreground whitespace-nowrap">
                        {log.timestamp ?? log.created_at ?? "—"}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Avatar className="h-6 w-6">
                            <AvatarFallback className="text-xs bg-muted">
                              {getInitials(actor)}
                            </AvatarFallback>
                          </Avatar>
                          <span className="text-xs font-medium">{actor}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={cn("text-xs capitalize", getActionColor(action))}>
                          {action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-48 truncate">{resource}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{ip}</TableCell>
                      <TableCell>
                        {status === "success" ? (
                          <span className="flex items-center gap-1 text-green-500 text-xs">
                            <CheckCircle className="h-3 w-3" /> Success
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-red-500 text-xs">
                            <XCircle className="h-3 w-3" /> Failed
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </motion.div>
  );
}
