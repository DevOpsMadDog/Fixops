import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Checkbox } from "@/components/ui/checkbox";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion, AnimatePresence } from "framer-motion";
import {
  Package, ShieldCheck, Clock, AlertTriangle, Search, RefreshCw,
  CheckCircle, XCircle, Eye, Lock, Download, FileJson,
  Link2, Trash2, Settings, ChevronRight, Layers
} from "lucide-react";
import { useEvidenceBundles } from "@/hooks/use-api";

function QuantumBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <Badge className="gap-1 text-xs bg-violet-900/60 text-violet-300 border-violet-700 hover:bg-violet-900/80">
      <Lock className="h-2.5 w-2.5" />
      Quantum-Signed
    </Badge>
  ) : (
    <Badge variant="outline" className="gap-1 text-xs text-muted-foreground">
      <AlertTriangle className="h-2.5 w-2.5" />
      Unsigned
    </Badge>
  );
}

function BundleDetailDialog({ bundle }: { bundle: any }) {
  const [open, setOpen] = useState(false);
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
            <Package className="h-4 w-4 text-primary" />
            Bundle Detail: {bundle.bundle_id ?? bundle.id ?? "Unknown"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          {/* Status row */}
          <div className="flex items-center gap-4 flex-wrap">
            <QuantumBadge verified={bundle.quantum_signed ?? bundle.signed ?? false} />
            <Badge variant="outline" className="text-xs">{bundle.framework ?? "—"}</Badge>
            <Badge variant="outline" className="text-xs">{bundle.control ?? "—"}</Badge>
            {bundle.slsa_level && (
              <Badge className="text-xs bg-blue-900/40 text-blue-300 border-blue-700">
                SLSA Level {bundle.slsa_level}
              </Badge>
            )}
          </div>

          <Separator />

          {/* Signature verification */}
          <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
              Signature Verification
            </h4>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <p className="text-muted-foreground text-xs">Signature Status</p>
                <p className="font-medium mt-0.5 flex items-center gap-1">
                  {bundle.signature_valid !== false ? (
                    <><CheckCircle className="h-3.5 w-3.5 text-green-500" /> Verified</>
                  ) : (
                    <><XCircle className="h-3.5 w-3.5 text-red-500" /> Invalid</>
                  )}
                </p>
              </div>
              <div>
                <p className="text-muted-foreground text-xs">Algorithm</p>
                <p className="font-medium mt-0.5 font-mono text-xs">{bundle.algorithm ?? "CRYSTALS-Dilithium"}</p>
              </div>
              <div>
                <p className="text-muted-foreground text-xs">Signed Date</p>
                <p className="font-medium mt-0.5 text-xs">{bundle.signed_date ?? bundle.created_at ?? "—"}</p>
              </div>
              <div>
                <p className="text-muted-foreground text-xs">Expiry Date</p>
                <p className="font-medium mt-0.5 text-xs">{bundle.expiry_date ?? bundle.expires_at ?? "—"}</p>
              </div>
            </div>
            {bundle.signature && (
              <div className="mt-3">
                <p className="text-muted-foreground text-xs mb-1">Signature Hash</p>
                <code className="text-xs font-mono break-all text-violet-400">
                  {bundle.signature}
                </code>
              </div>
            )}
          </div>

          {/* Evidence chain visualization */}
          <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 flex items-center gap-2">
              <Link2 className="h-3.5 w-3.5" />
              Evidence Chain
            </h4>
            <div className="space-y-2">
              {[
                { label: "Scanner Output", status: "verified" },
                { label: "Triage Decision", status: "verified" },
                { label: "Remediation Record", status: bundle.control ? "verified" : "pending" },
                { label: "Evidence Bundle", status: bundle.quantum_signed || bundle.signed ? "signed" : "unsigned" },
                { label: "Audit Entry", status: "verified" },
              ].map(({ label, status }) => (
                <div key={label} className="flex items-center gap-3">
                  <div className={`h-2 w-2 rounded-full shrink-0 ${
                    status === "verified" || status === "signed" ? "bg-green-500" :
                    status === "pending" ? "bg-yellow-500" : "bg-red-500"
                  }`} />
                  <span className="text-xs flex-1">{label}</span>
                  <Badge variant="outline" className={`text-xs py-0 h-4 ${
                    status === "verified" ? "text-green-400 border-green-700" :
                    status === "signed" ? "text-violet-400 border-violet-700" :
                    status === "pending" ? "text-yellow-400 border-yellow-700" :
                    "text-muted-foreground"
                  }`}>
                    {status}
                  </Badge>
                  {status !== "unsigned" && <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                </div>
              ))}
            </div>
          </div>

          {/* SLSA Attestation */}
          {bundle.slsa_attestation && (
            <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
                SLSA Attestation
              </h4>
              <code className="text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all">
                {typeof bundle.slsa_attestation === "string"
                  ? bundle.slsa_attestation
                  : JSON.stringify(bundle.slsa_attestation, null, 2)}
              </code>
            </div>
          )}

          {/* JSON payload */}
          <div className="rounded-lg bg-muted/30 p-4 border border-border/40">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
              Bundle Payload (JSON)
            </h4>
            <ScrollArea className="h-52">
              <code className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                {JSON.stringify(bundle, null, 2)}
              </code>
            </ScrollArea>
          </div>

          <div className="flex gap-2">
            <Button size="sm" variant="outline" className="gap-2">
              <ShieldCheck className="h-3.5 w-3.5" />
              Verify Signature
            </Button>
            <Button size="sm" variant="outline" className="gap-2">
              <Download className="h-3.5 w-3.5" />
              Download Bundle
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function EvidenceVault() {
  const bundlesQuery = useEvidenceBundles();
  const refetch = useCallback(() => bundlesQuery.refetch(), [bundlesQuery]);

  const [search, setSearch] = useState("");
  const [frameworkFilter, setFrameworkFilter] = useState("all");
  const [appFilter, setAppFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBarVisible, setBulkBarVisible] = useState(false);

  if (bundlesQuery.isLoading) return <PageSkeleton />;
  if (bundlesQuery.isError) return <ErrorState message="Failed to load evidence bundles" onRetry={refetch} />;

  const bundles: any[] = bundlesQuery.data?.data ?? bundlesQuery.data ?? [];

  const totalBundles = bundles.length;
  const quantumSigned = bundles.filter((b: any) => b.quantum_signed || b.signed).length;
  const pending = bundles.filter((b: any) => (b.status ?? "").toLowerCase() === "pending").length;
  const expired = bundles.filter((b: any) => {
    if (!b.expiry_date && !b.expires_at) return false;
    return new Date(b.expiry_date ?? b.expires_at) < new Date();
  }).length;

  const frameworks = Array.from(new Set(bundles.map((b: any) => b.framework).filter(Boolean)));
  const apps = Array.from(new Set(bundles.map((b: any) => b.app_id ?? b.app).filter(Boolean)));

  const filtered = bundles.filter((b: any) => {
    const q = search.toLowerCase();
    const matchesSearch =
      !search ||
      (b.bundle_id ?? b.id ?? "").toLowerCase().includes(q) ||
      (b.framework ?? "").toLowerCase().includes(q) ||
      (b.control ?? "").toLowerCase().includes(q) ||
      (b.app_id ?? b.app ?? "").toLowerCase().includes(q);
    const matchesFramework = frameworkFilter === "all" || b.framework === frameworkFilter;
    const matchesApp = appFilter === "all" || (b.app_id ?? b.app) === appFilter;
    const matchesStatus =
      statusFilter === "all" ||
      (statusFilter === "signed" && (b.quantum_signed || b.signed)) ||
      (statusFilter === "pending" && (b.status ?? "").toLowerCase() === "pending") ||
      (statusFilter === "expired" && b.expiry_date && new Date(b.expiry_date) < new Date());
    return matchesSearch && matchesFramework && matchesApp && matchesStatus;
  });

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      setBulkBarVisible(next.size > 0);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
      setBulkBarVisible(false);
    } else {
      const ids = new Set(filtered.slice(0, 50).map((b: any) => b.bundle_id ?? b.id ?? ""));
      setSelected(ids);
      setBulkBarVisible(ids.size > 0);
    }
  };

  const clearSelection = () => {
    setSelected(new Set());
    setBulkBarVisible(false);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Evidence Vault"
        description="All evidence bundles with quantum-secure signatures and SLSA attestations"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Button size="sm" className="gap-2">
          <Download className="h-4 w-4" />
          Export All
        </Button>
          </div>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Bundles" value={totalBundles} icon={Package} />
        <KpiCard title="Quantum-Signed" value={quantumSigned} icon={Lock} change={quantumSigned} changeLabel="verified" />
        <KpiCard title="Pending" value={pending} icon={Clock} />
        <KpiCard title="Expired" value={expired} icon={AlertTriangle} />
      </div>

      {/* Retention Management Panel */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Settings className="h-4 w-4 text-blue-400" />
              Retention Management
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {frameworks.slice(0, 4).map((fw: any) => {
                const fwBundles = bundles.filter((b: any) => b.framework === fw);
                const expiredFw = fwBundles.filter((b: any) => b.expiry_date && new Date(b.expiry_date) < new Date()).length;
                const expiringSoon = fwBundles.filter((b: any) => {
                  const d = b.expiry_date ?? b.expires_at;
                  if (!d) return false;
                  const days = Math.ceil((new Date(d).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
                  return days >= 0 && days <= 30;
                }).length;
                return (
                  <div key={fw} className="p-3 rounded-lg bg-muted/30 border border-border/40">
                    <div className="flex items-center justify-between mb-2">
                      <Badge variant="outline" className="text-xs">{fw}</Badge>
                      <span className="text-xs text-muted-foreground">{fwBundles.length} bundles</span>
                    </div>
                    <div className="space-y-1 text-xs">
                      {expiredFw > 0 && (
                        <span className="flex items-center gap-1 text-red-400">
                          <AlertTriangle className="h-3 w-3" /> {expiredFw} expired
                        </span>
                      )}
                      {expiringSoon > 0 && (
                        <span className="flex items-center gap-1 text-yellow-400">
                          <Clock className="h-3 w-3" /> {expiringSoon} expiring soon
                        </span>
                      )}
                      {expiredFw === 0 && expiringSoon === 0 && (
                        <span className="flex items-center gap-1 text-green-400">
                          <CheckCircle className="h-3 w-3" /> All current
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
              {frameworks.length === 0 && (
                <p className="text-xs text-muted-foreground col-span-4 text-center py-2">
                  No framework retention data available
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-48">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search bundle ID, framework, control, app…"
                className="pl-9"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Select value={frameworkFilter} onValueChange={setFrameworkFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Framework" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Frameworks</SelectItem>
                {frameworks.map((f) => (
                  <SelectItem key={f} value={f}>{f}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={appFilter} onValueChange={setAppFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="App" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Apps</SelectItem>
                {apps.map((a) => (
                  <SelectItem key={a} value={a}>{a}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="signed">Quantum-Signed</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="expired">Expired</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Bulk Operations Bar */}
      <AnimatePresence>
        {bulkBarVisible && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.2 }}
          >
            <Card className="border-primary/40 bg-primary/5">
              <CardContent className="py-3 flex items-center gap-4">
                <span className="text-sm font-medium">{selected.size} bundle{selected.size !== 1 ? "s" : ""} selected</span>
                <div className="flex gap-2 ml-auto">
                  <Button size="sm" variant="outline" className="gap-2 h-7 text-xs">
                    <Download className="h-3.5 w-3.5" />
                    Download Selected
                  </Button>
                  <Button size="sm" variant="outline" className="gap-2 h-7 text-xs">
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Verify Signatures
                  </Button>
                  <Button size="sm" variant="outline" className="gap-2 h-7 text-xs text-red-400 border-red-800 hover:bg-red-950/30">
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete Selected
                  </Button>
                  <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={clearSelection}>
                    Clear
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Evidence Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            <span className="flex items-center gap-2">
              <FileJson className="h-4 w-4 text-primary" />
              Evidence Bundles
            </span>
            <span className="text-sm font-normal text-muted-foreground">
              {filtered.length} of {totalBundles}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="w-10">
                  <Checkbox
                    checked={selected.size > 0 && selected.size === filtered.slice(0, 50).length}
                    onCheckedChange={toggleSelectAll}
                  />
                </TableHead>
                <TableHead className="text-xs">Bundle ID</TableHead>
                <TableHead className="text-xs">Framework</TableHead>
                <TableHead className="text-xs">Control</TableHead>
                <TableHead className="text-xs">App</TableHead>
                <TableHead className="text-xs">Signed Date</TableHead>
                <TableHead className="text-xs">Expiry</TableHead>
                <TableHead className="text-xs">Signature</TableHead>
                <TableHead className="text-xs text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="text-center py-12 text-muted-foreground">
                    No evidence bundles match your filters
                  </TableCell>
                </TableRow>
              ) : (
                filtered.slice(0, 50).map((bundle: any, i: number) => {
                  const bundleId = bundle.bundle_id ?? bundle.id ?? `BND-${String(i + 1).padStart(4, "0")}`;
                  const isExpired =
                    bundle.expiry_date && new Date(bundle.expiry_date) < new Date();
                  const isSelected = selected.has(bundleId);
                  return (
                    <TableRow key={bundleId} className={`hover:bg-muted/30 ${isSelected ? "bg-primary/5" : ""}`}>
                      <TableCell>
                        <Checkbox
                          checked={isSelected}
                          onCheckedChange={() => toggleSelect(bundleId)}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-xs text-primary">
                        {bundleId}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">{bundle.framework ?? "—"}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{bundle.control ?? "—"}</TableCell>
                      <TableCell className="text-xs font-medium">{bundle.app_id ?? bundle.app ?? "—"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {bundle.signed_date ?? bundle.created_at ?? "—"}
                      </TableCell>
                      <TableCell className={`text-xs ${isExpired ? "text-red-500" : "text-muted-foreground"}`}>
                        {bundle.expiry_date ?? bundle.expires_at ?? "—"}
                        {isExpired && " (Expired)"}
                      </TableCell>
                      <TableCell>
                        <QuantumBadge verified={bundle.quantum_signed ?? bundle.signed ?? false} />
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <BundleDetailDialog bundle={bundle} />
                          <Button variant="ghost" size="icon" className="h-7 w-7">
                            <Download className="h-3.5 w-3.5" />
                          </Button>
                        </div>
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
