import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Shield, Users, Activity, Calendar, Search, RefreshCw,
  Download, CheckCircle, XCircle, AlertTriangle, Link2, FileJson, Files,
  Eye, Hash, Lock, ShieldAlert, Tag
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

// Compliance control labels for linkage badges
const CONTROL_MAP: Record<string, string[]> = {
  login: ["SOC2 CC6.1", "NIST AC-2"],
  logout: ["SOC2 CC6.1"],
  create: ["SOC2 CC7.2", "ISO27001 A.9"],
  update: ["SOC2 CC7.2", "PCI-DSS Req 10"],
  delete: ["SOC2 CC7.3", "HIPAA §164.312"],
  export: ["SOC2 CC6.7", "PCI-DSS Req 12"],
  approve: ["SOC2 CC4.2", "NIST AU-9"],
};

function getControlBadges(action: string) {
  const lower = action.toLowerCase();
  for (const [key, controls] of Object.entries(CONTROL_MAP)) {
    if (lower.includes(key)) return controls;
  }
  return [];
}

function AuditDetailDrawer({ log }: { log: any }) {
  const [open, setOpen] = useState(false);
  const actor = log.actor ?? log.user ?? log.actor_name ?? "system";
  const action = log.action ?? log.event_type ?? "unknown";
  const resource = log.resource ?? log.target ?? "—";
  const controlBadges = getControlBadges(action);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7">
          <Eye className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-mono text-sm">
            <Hash className="h-4 w-4 text-primary" />
            Audit Entry Detail
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          {/* Metadata grid */}
          <div className="grid grid-cols-2 gap-3 rounded-lg bg-muted/30 p-4 border border-border/40">
            {[
              ["Actor", actor],
              ["Action", action],
              ["Resource", resource],
              ["IP Address", log.ip_address ?? log.ip ?? "—"],
              ["Timestamp", log.timestamp ?? log.created_at ?? "—"],
              ["Status", log.status ?? "success"],
              ["Session ID", log.session_id ?? "—"],
              ["User Agent", log.user_agent ?? "—"],
            ].map(([label, value]) => (
              <div key={label}>
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className="text-sm font-medium mt-0.5 font-mono truncate">{value}</p>
              </div>
            ))
          }
          </div>

          {/* Hash chain verification */}
          <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
              <Lock className="h-3.5 w-3.5" />
              Hash Chain Verification
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground text-xs">Entry Hash</span>
                <code className="text-xs font-mono text-violet-400 truncate ml-4 max-w-72">
                  {log.hash ?? "—"}
                </code>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground text-xs">Previous Hash</span>
                <code className="text-xs font-mono text-blue-400 truncate ml-4 max-w-72">
                  {log.prev_hash ?? "—"}
                </code>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-muted-foreground text-xs">Chain Integrity</span>
                <HashBadge verified={log.hash_valid !== false && log.tampered !== true} />
              </div>
            </div>
          </div>

          {/* Compliance control linkage */}
          {controlBadges.length > 0 && (
            <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
                <Tag className="h-3.5 w-3.5" />
                Compliance Control Linkage
              </h4>
              <div className="flex flex-wrap gap-2">
                {controlBadges.map((ctrl) => (
                  <Badge key={ctrl} variant="outline" className="text-xs gap-1">
                    <Link2 className="h-2.5 w-2.5" />
                    {ctrl}
                  </Badge>
                ))
              )}
              </div>
            </div>
          )}

          {/* Raw payload */}
          {log.payload && (
            <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
                Event Payload
              </h4>
              <ScrollArea className="h-32">
                <code className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                  {JSON.stringify(log.payload, null, 2)}
                </code>
              </ScrollArea>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function AuditTrail() {
  const auditQuery = useAuditLog();
  const refetch = useCallback(() => auditQuery.refetch(), [auditQuery]);

  const [search, setSearch] = useState("");
  const [actorFilter, setActorFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  if (auditQuery.isLoading) return <PageSkeleton />;
  if (auditQuery.isError) return <ErrorState message="Failed to load audit logs" onRetry={refetch} />;

  const logs: any[] = toArray(auditQuery.data);

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

  // Tamper detection
  const tamperDetected = logs.some((l: any) => l.hash_valid === false || l.tampered === true);
  const tamperCount = logs.filter((l: any) => l.hash_valid === false || l.tampered === true).length;

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
    const ts = l.timestamp ?? l.created_at;
    const matchesDateFrom = !dateFrom || !ts || new Date(ts) >= new Date(dateFrom);
    const matchesDateTo = !dateTo || !ts || new Date(ts) <= new Date(dateTo + "T23:59:59");
    return matchesSearch && matchesActor && matchesAction && matchesStatus && matchesDateFrom && matchesDateTo;
  });

  const handleExportCSV = () => {
    const headers = ["Timestamp", "Actor", "Action", "Resource", "IP", "Status", "Hash"];
    const rows = filtered.map((l: any) => [
      l.timestamp ?? l.created_at ?? "",
      l.actor ?? l.user ?? "",
      l.action ?? l.event_type ?? "",
      l.resource ?? l.target ?? "",
      l.ip_address ?? l.ip ?? "",
      l.status ?? "success",
      l.hash ?? "",
    ]);
    const csv = [headers, ...rows].map((row) => row.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-trail-${dateFrom || "all"}-${dateTo || "all"}.csv`;
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
            Tamper detected — {tamperCount} audit log {tamperCount === 1 ? "entry has" : "entries have"} an invalid hash chain. Immediate investigation required.
          </AlertDescription>
        </Alert>
      )}

      {/* Hash Chain Integrity Panel */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
      >
        <Card className={tamperDetected ? "border-red-800/50" : "border-green-800/30"}>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Lock className="h-4 w-4 text-primary" />
              Hash Chain Integrity
              <Badge
                className={`ml-auto gap-1 text-xs ${tamperDetected ? "bg-red-900/40 text-red-400 border-red-700" : "bg-green-900/40 text-green-400 border-green-700"}`}
              >
                {tamperDetected ? <XCircle className="h-2.5 w-2.5" /> : <CheckCircle className="h-2.5 w-2.5" />}
                {tamperDetected ? `${tamperCount} tampered` : "All entries verified"}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: "Chain Status", value: tamperDetected ? "COMPROMISED" : "INTACT", color: tamperDetected ? "text-red-400" : "text-green-400" },
                { label: "Algorithm", value: "SHA-256 HMAC", color: "text-blue-400" },
                { label: "Entries Verified", value: `${logs.length - tamperCount}/${logs.length}`, color: "text-foreground" },
                { label: "Last Verification", value: new Date().toLocaleTimeString(), color: "text-muted-foreground" },
              ].map(({ label, value, color }) => (
                <div key={label} className="p-3 rounded-lg bg-muted/30 border border-border/40">
                  <p className="text-xs text-muted-foreground mb-1">{label}</p>
                  <p className={`text-sm font-mono font-semibold ${color}`}>{value}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Events" value={totalEvents} icon={Activity} />
        <KpiCard title="Today" value={todayCount} icon={Calendar} />
        <KpiCard title="This Week" value={thisWeek} icon={Shield} />
        <KpiCard title="Unique Actors" value={uniqueActors} icon={Users} />
      </div>

      {/* Filters with date range */}
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
          {/* Date range row */}
          <div className="flex flex-wrap gap-3 mt-3 pt-3 border-t border-border/40">
            <div className="flex items-center gap-2">
              <Label className="text-xs text-muted-foreground whitespace-nowrap">Date From</Label>
              <Input
                type="date"
                className="w-40 h-8 text-xs"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <Label className="text-xs text-muted-foreground whitespace-nowrap">Date To</Label>
              <Input
                type="date"
                className="w-40 h-8 text-xs"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
              />
            </div>
            {(dateFrom || dateTo) && (
              <Button
                variant="ghost"
                size="sm"
                className="h-8 text-xs"
                onClick={() => { setDateFrom(""); setDateTo(""); }}
              >
                Clear dates
              </Button>
            )}
            <span className="text-xs text-muted-foreground self-center ml-auto">
              {filtered.length} of {totalEvents} events
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Tamper Detection Alerts Section */}
      {tamperDetected && (
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card className="border-red-800/50">
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2 text-red-400">
                <ShieldAlert className="h-4 w-4" />
                Tamper Detection Alerts ({tamperCount})
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {logs.filter((l: any) => l.hash_valid === false || l.tampered === true).map((l: any, i: number) => (
                <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-red-950/30 border border-red-800/40">
                  <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-red-300">
                      Entry tampered: {l.action ?? l.event_type ?? "unknown"} by {l.actor ?? l.user ?? "system"}
                    </p>
                    <p className="text-xs text-muted-foreground mt-0.5 font-mono truncate">
                      {l.timestamp ?? l.created_at ?? "—"} · {l.resource ?? l.target ?? "—"}
                    </p>
                  </div>
                  <Badge variant="destructive" className="text-xs shrink-0">Tampered</Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        </motion.div>
      )}

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
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Timestamp</TableHead>
                <TableHead className="text-xs">Actor</TableHead>
                <TableHead className="text-xs">Action</TableHead>
                <TableHead className="text-xs">Resource</TableHead>
                <TableHead className="text-xs">IP Address</TableHead>
                <TableHead className="text-xs">Controls</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs text-right">Detail</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-12 text-muted-foreground">
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
                  const controlBadges = getControlBadges(action);
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
                        <div className="flex flex-wrap gap-1">
                          {controlBadges.slice(0, 1).map((ctrl) => (
                            <Badge key={ctrl} variant="outline" className="text-xs py-0 h-4 font-mono">
                              {ctrl}
                            </Badge>
                          ))
                        }
                          {controlBadges.length > 1 && (
                            <Badge variant="outline" className="text-xs py-0 h-4 text-muted-foreground">
                              +{controlBadges.length - 1}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
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
                      <TableCell className="text-right">
                        <AuditDetailDrawer log={log} />
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
