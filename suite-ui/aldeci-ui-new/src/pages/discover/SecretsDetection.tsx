import { useState, useCallback, useMemo } from "react";
import { motion } from "framer-motion";
import {
  Key, Eye, EyeOff, RefreshCw, RotateCcw, ShieldOff, ShieldCheck,
  AlertTriangle, Clock, Filter, Download, Search, MoreHorizontal,
  Lock, Unlock, History,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Checkbox } from "@/components/ui/checkbox";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { secretsApi } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";
import { cn } from "@/lib/utils";

interface SecretFinding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  scanner?: string;
  type?: string;
  secret_type?: string;
  file?: string;
  line?: number;
  repository?: string;
  repo?: string;
  value?: string;
  masked_value?: string;
  found_date?: string;
  created_at?: string;
  rotation_history?: RotationEntry[];
  description?: string;
}

interface RotationEntry {
  date: string;
  action: string;
  by?: string;
}

function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || "").toLowerCase();
  const map: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return <Badge className={cn("border text-xs font-semibold uppercase", map[s] || "bg-slate-500/15 text-slate-400 border-slate-500/20")}>{severity || "Unknown"}</Badge>;
}

function SecretStatusBadge({ status }: { status?: string }) {
  const s = (status || "").toLowerCase();
  const map: Record<string, string> = {
    active: "bg-red-500/10 text-red-400 border-red-500/20",
    rotated: "bg-green-500/10 text-green-400 border-green-500/20",
    revoked: "bg-slate-500/10 text-slate-400 border-slate-500/20",
    pending: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  };
  return <Badge className={cn("border text-xs", map[s] || "bg-slate-500/10 text-slate-400 border-slate-500/20")}>{status || "Unknown"}</Badge>;
}

function SecretTypeBadge({ type }: { type?: string }) {
  const typeLabels: Record<string, string> = {
    api_key: "API Key",
    token: "Token",
    password: "Password",
    certificate: "Certificate",
    private_key: "Private Key",
    oauth_token: "OAuth Token",
    aws_key: "AWS Key",
    github_token: "GitHub Token",
  };
  const t = (type || "").toLowerCase().replace(/\s+/g, "_");
  return (
    <Badge variant="outline" className="text-xs font-mono">
      <Key className="h-2.5 w-2.5 mr-1" />
      {typeLabels[t] || type || "Unknown"}
    </Badge>
  );
}

function maskSecret(val?: string): string {
  if (!val) return "••••••••••••••••";
  const visible = Math.min(4, Math.floor(val.length / 5));
  return val.slice(0, visible) + "•".repeat(Math.max(12, val.length - visible * 2)) + val.slice(-visible);
}

function formatDate(dateStr?: string): string {
  if (!dateStr) return "—";
  try { return new Date(dateStr).toLocaleDateString(); } catch { return "—"; }
}

export default function SecretsDetection() {
  const [typeFilter, setTypeFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [repoFilter, setRepoFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedRows, setSelectedRows] = useState<Set<string>>(new Set());
  const [detailSecret, setDetailSecret] = useState<SecretFinding | null>(null);
  const [revealedValues, setRevealedValues] = useState<Set<string>>(new Set());

  const query = useQuery({
    queryKey: ["secrets", statusFilter],
    queryFn: async () => {
      const params: Record<string, unknown> = { limit: 200 };
      if (statusFilter !== "all") params.status = statusFilter;
      const { data } = await secretsApi.list(params);
      return data;
    },
  });
  const refetch = useCallback(() => query.refetch(), [query]);

  const allSecrets: SecretFinding[] = useMemo(() => {
    const d = query.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray((d as Record<string,unknown>)?.items)) return (d as Record<string,unknown>).items as SecretFinding[];
    if (Array.isArray((d as Record<string,unknown>)?.secrets)) return (d as Record<string,unknown>).secrets as SecretFinding[];
    return [];
  }, [query.data]);

  const stats = useMemo(() => ({
    total: allSecrets.length,
    active: allSecrets.filter((s) => s.status?.toLowerCase() === "active").length,
    rotated: allSecrets.filter((s) => s.status?.toLowerCase() === "rotated").length,
    revoked: allSecrets.filter((s) => s.status?.toLowerCase() === "revoked").length,
  }), [allSecrets]);

  const repositories = useMemo(() =>
    Array.from(new Set(allSecrets.map((s) => s.repository || s.repo).filter(Boolean))),
    [allSecrets]
  );

  const secretTypes = useMemo(() =>
    Array.from(new Set(allSecrets.map((s) => s.type || s.secret_type).filter(Boolean))),
    [allSecrets]
  );

  const filtered = useMemo(() => {
    let list = allSecrets;
    if (typeFilter !== "all") list = list.filter((s) => (s.type || s.secret_type) === typeFilter);
    if (repoFilter !== "all") list = list.filter((s) => (s.repository || s.repo) === repoFilter);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((s) => s.title?.toLowerCase().includes(q) || s.file?.toLowerCase().includes(q) || (s.repository || s.repo || "").toLowerCase().includes(q));
    }
    return list;
  }, [allSecrets, typeFilter, statusFilter, repoFilter, searchQuery]);

  function toggleRow(id: string) {
    setSelectedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (selectedRows.size === filtered.length) setSelectedRows(new Set());
    else setSelectedRows(new Set(filtered.map((s) => s.id || s.finding_id || "")));
  }

  function toggleReveal(id: string) {
    setRevealedValues((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  if (query.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (query.isError) {
    return <ErrorState message="Failed to load secrets detection results." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="Secrets Detection" description="Leaked credentials and sensitive data across all repositories">
        <Button variant="outline" size="sm" onClick={() => query.refetch()} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
        {selectedRows.size > 0 && (
          <Button size="sm" className="gap-2 bg-orange-500 hover:bg-orange-600 text-white">
            <RotateCcw className="h-4 w-4" /> Bulk Rotate ({selectedRows.size})
          </Button>
        )}
        <Button variant="outline" size="sm" className="gap-2">
          <Download className="h-4 w-4" /> Export
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Secrets Found" value={stats.total} icon={Key} />
        <KpiCard
          title="Active (Exposed)"
          value={stats.active}
          icon={ShieldOff}
          className="border-red-500/20"
        />
        <KpiCard
          title="Rotated"
          value={stats.rotated}
          icon={RotateCcw}
          className="border-yellow-500/20"
        />
        <KpiCard
          title="Revoked"
          value={stats.revoked}
          icon={ShieldCheck}
          className="border-green-500/20"
        />
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-4 pb-4">
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search secrets, file path, repository..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="api_key">API Key</SelectItem>
                <SelectItem value="token">Token</SelectItem>
                <SelectItem value="password">Password</SelectItem>
                <SelectItem value="certificate">Certificate</SelectItem>
                <SelectItem value="private_key">Private Key</SelectItem>
                {secretTypes.map((t) => (
                  <SelectItem key={t} value={t!}>{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="rotated">Rotated</SelectItem>
                <SelectItem value="revoked">Revoked</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
              </SelectContent>
            </Select>
            {repositories.length > 0 && (
              <Select value={repoFilter} onValueChange={setRepoFilter}>
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="Repository" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Repositories</SelectItem>
                  {repositories.map((r) => (
                    <SelectItem key={r} value={r!}>{r}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Secrets Table */}
      <Card>
        <CardHeader className="pb-2 flex flex-row items-center justify-between">
          <CardTitle className="text-sm text-muted-foreground">{filtered.length} secrets found</CardTitle>
          {selectedRows.size > 0 && (
            <span className="text-sm text-primary font-medium">{selectedRows.size} selected</span>
          )}
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-10">
                  <Checkbox
                    checked={selectedRows.size === filtered.length && filtered.length > 0}
                    onCheckedChange={toggleAll}
                  />
                </TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Title / Description</TableHead>
                <TableHead>Location</TableHead>
                <TableHead>Repository</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Found</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-12 text-muted-foreground">
                    <div className="flex flex-col items-center gap-2">
                      <Lock className="h-8 w-8 opacity-30 text-green-400" />
                      <p>No secrets found matching current filters</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((secret, idx) => {
                  const id = secret.id || secret.finding_id || String(idx);
                  return (
                    <TableRow
                      key={id}
                      className="cursor-pointer hover:bg-muted/40"
                      onClick={() => setDetailSecret(secret)}
                    >
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Checkbox checked={selectedRows.has(id)} onCheckedChange={() => toggleRow(id)} />
                      </TableCell>
                      <TableCell>
                        <SecretTypeBadge type={secret.type || secret.secret_type} />
                      </TableCell>
                      <TableCell className="max-w-[200px]">
                        <span className="truncate block text-sm font-medium">{secret.title || "Unnamed Secret"}</span>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-blue-400 max-w-[200px]">
                        <span className="truncate block">
                          {secret.file ? `${secret.file}${secret.line ? `:${secret.line}` : ""}` : "—"}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-[150px]">
                        <span className="truncate block">{secret.repository || secret.repo || "—"}</span>
                      </TableCell>
                      <TableCell>
                        <SecretStatusBadge status={secret.status} />
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={secret.severity} />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatDate(secret.found_date || secret.created_at)}
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-7 w-7">
                              <MoreHorizontal className="h-3.5 w-3.5" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => setDetailSecret(secret)}>
                              <Eye className="h-3.5 w-3.5 mr-2" /> View Detail
                            </DropdownMenuItem>
                            <DropdownMenuItem>
                              <RotateCcw className="h-3.5 w-3.5 mr-2" /> Rotate Secret
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem>
                              <Unlock className="h-3.5 w-3.5 mr-2" /> Mark Revoked
                            </DropdownMenuItem>
                            <DropdownMenuItem>
                              <AlertTriangle className="h-3.5 w-3.5 mr-2" /> Escalate
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
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

      {/* Detail Dialog */}
      <Dialog open={!!detailSecret} onOpenChange={(open) => { if (!open) setDetailSecret(null); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3">
              <Key className="h-5 w-5 text-orange-400" />
              {detailSecret?.title || "Secret Detail"}
            </DialogTitle>
            <DialogDescription>
              {detailSecret?.finding_id || detailSecret?.id}
            </DialogDescription>
          </DialogHeader>
          {detailSecret && (
            <ScrollArea className="max-h-[70vh]">
              <div className="space-y-4 pr-4">
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { label: "Type", value: <SecretTypeBadge type={detailSecret.type || detailSecret.secret_type} /> },
                    { label: "Status", value: <SecretStatusBadge status={detailSecret.status} /> },
                    { label: "Severity", value: <SeverityBadge severity={detailSecret.severity} /> },
                    { label: "Scanner", value: detailSecret.scanner || "—" },
                    { label: "Repository", value: detailSecret.repository || detailSecret.repo || "—" },
                    { label: "Found", value: formatDate(detailSecret.found_date || detailSecret.created_at) },
                  ].map(({ label, value }) => (
                    <div key={label}>
                      <p className="text-xs text-muted-foreground mb-1">{label}</p>
                      <div className="text-sm font-medium">{value}</div>
                    </div>
                  ))}
                </div>

                {/* Location */}
                {detailSecret.file && (
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Location</p>
                    <code className="text-xs font-mono text-blue-400 bg-muted/50 px-2 py-1 rounded block">
                      {detailSecret.file}{detailSecret.line ? `:${detailSecret.line}` : ""}
                    </code>
                  </div>
                )}

                {/* Masked Secret Value */}
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-2">
                    Secret Value
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-5 px-1 text-xs gap-1"
                      onClick={() => toggleReveal(detailSecret.id || "")}
                    >
                      {revealedValues.has(detailSecret.id || "")
                        ? <><EyeOff className="h-3 w-3" /> Hide</>
                        : <><Eye className="h-3 w-3" /> Reveal</>}
                    </Button>
                  </p>
                  <div className="bg-black/60 border border-white/10 rounded-md p-3 font-mono text-sm">
                    {revealedValues.has(detailSecret.id || "")
                      ? (detailSecret.value || detailSecret.masked_value || "Value not available")
                      : maskSecret(detailSecret.value || detailSecret.masked_value)}
                  </div>
                </div>

                {/* Rotation History */}
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1">
                    <History className="h-3 w-3" /> Rotation History
                  </p>
                  {detailSecret.rotation_history && detailSecret.rotation_history.length > 0 ? (
                    <div className="space-y-2">
                      {detailSecret.rotation_history.map((entry, i) => (
                        <div key={i} className="flex items-center gap-3 text-xs bg-muted/30 rounded p-2">
                          <Clock className="h-3 w-3 text-muted-foreground" />
                          <span className="text-muted-foreground">{formatDate(entry.date)}</span>
                          <span className="font-medium">{entry.action}</span>
                          {entry.by && <span className="text-muted-foreground">by {entry.by}</span>}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-muted-foreground bg-muted/20 rounded-md p-3">
                      No rotation history available
                    </div>
                  )}
                </div>

                <Separator />

                <div className="flex gap-2">
                  <Button size="sm" className="gap-1 bg-orange-500 hover:bg-orange-600">
                    <RotateCcw className="h-3 w-3" /> Rotate Now
                  </Button>
                  <Button size="sm" variant="outline" className="gap-1">
                    <Unlock className="h-3 w-3" /> Mark Revoked
                  </Button>
                  <Button size="sm" variant="outline" className="gap-1">
                    <AlertTriangle className="h-3 w-3" /> Escalate
                  </Button>
                </div>
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
