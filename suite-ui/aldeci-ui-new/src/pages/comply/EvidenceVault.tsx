import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Lock,
  Search,
  Filter,
  X,
  ShieldCheck,
  Hash,
  Calendar,
  Download,
  ExternalLink,
  FileArchive,
  Clock,
  CheckCircle2,
  AlertCircle,
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
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { evidenceApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock Data ───────────────────────────────────────────────────────────────

interface EvidenceBundle {
  id: string;
  bundleId: string;
  appId: string;
  appName: string;
  framework: string;
  control: string;
  generatedAt: string;
  expiresAt: string;
  hash: string;
  quantumSigned: boolean;
  status: "verified" | "pending" | "tampered";
  sizeKb: number;
  retentionDays: number;
  artifacts: number;
}

const MOCK_BUNDLES: EvidenceBundle[] = [
  {
    id: "evb-001",
    bundleId: "EVB-2025-001",
    appId: "app-checkout",
    appName: "Checkout Service",
    framework: "SOC 2",
    control: "CC6.1",
    generatedAt: "2025-01-10T08:30:00Z",
    expiresAt: "2026-01-10T08:30:00Z",
    hash: "sha256:a8f3c2e1d4b7...9f2e",
    quantumSigned: true,
    status: "verified",
    sizeKb: 2840,
    retentionDays: 365,
    artifacts: 14,
  },
  {
    id: "evb-002",
    bundleId: "EVB-2025-002",
    appId: "app-auth",
    appName: "Auth Service",
    framework: "PCI-DSS",
    control: "Req 8.2",
    generatedAt: "2025-01-09T14:15:00Z",
    expiresAt: "2026-01-09T14:15:00Z",
    hash: "sha256:b9e4d5f2a3c8...1d7a",
    quantumSigned: true,
    status: "verified",
    sizeKb: 1560,
    retentionDays: 365,
    artifacts: 8,
  },
  {
    id: "evb-003",
    bundleId: "EVB-2025-003",
    appId: "app-payments",
    appName: "Payments Gateway",
    framework: "PCI-DSS",
    control: "Req 3.4",
    generatedAt: "2025-01-08T11:00:00Z",
    expiresAt: "2026-01-08T11:00:00Z",
    hash: "sha256:c1f2a3b4e5d6...2e8b",
    quantumSigned: false,
    status: "pending",
    sizeKb: 3200,
    retentionDays: 730,
    artifacts: 22,
  },
  {
    id: "evb-004",
    bundleId: "EVB-2025-004",
    appId: "app-iam",
    appName: "IAM Platform",
    framework: "ISO 27001",
    control: "A.9.2.3",
    generatedAt: "2025-01-07T09:45:00Z",
    expiresAt: "2026-01-07T09:45:00Z",
    hash: "sha256:d2e3f4a5b6c7...3f9c",
    quantumSigned: true,
    status: "verified",
    sizeKb: 980,
    retentionDays: 365,
    artifacts: 6,
  },
  {
    id: "evb-005",
    bundleId: "EVB-2025-005",
    appId: "app-data-pipeline",
    appName: "Data Pipeline",
    framework: "HIPAA",
    control: "164.312(a)(1)",
    generatedAt: "2025-01-06T16:20:00Z",
    expiresAt: "2026-01-06T16:20:00Z",
    hash: "sha256:e3f4a5b6c7d8...4a0d",
    quantumSigned: false,
    status: "tampered",
    sizeKb: 4200,
    retentionDays: 2190,
    artifacts: 31,
  },
  {
    id: "evb-006",
    bundleId: "EVB-2025-006",
    appId: "app-api-gw",
    appName: "API Gateway",
    framework: "NIST 800-53",
    control: "AC-2",
    generatedAt: "2025-01-05T10:10:00Z",
    expiresAt: "2026-01-05T10:10:00Z",
    hash: "sha256:f4a5b6c7d8e9...5b1e",
    quantumSigned: true,
    status: "verified",
    sizeKb: 1780,
    retentionDays: 365,
    artifacts: 12,
  },
];

// ─── Sub-components ──────────────────────────────────────────────────────────

function QuantumSignedIcon({ signed }: { signed: boolean }) {
  return signed ? (
    <div className="flex items-center gap-1.5">
      <div className="relative">
        <Lock className="h-3.5 w-3.5 text-green-400" />
        <span className="absolute -top-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-green-400" />
      </div>
      <span className="text-xs text-green-400 font-medium">Quantum-Signed</span>
    </div>
  ) : (
    <div className="flex items-center gap-1.5">
      <Lock className="h-3.5 w-3.5 text-muted-foreground" />
      <span className="text-xs text-muted-foreground">Standard</span>
    </div>
  );
}

function StatusBadge({ status }: { status: EvidenceBundle["status"] }) {
  switch (status) {
    case "verified":
      return <Badge variant="success">Verified</Badge>;
    case "pending":
      return <Badge variant="warning">Pending</Badge>;
    case "tampered":
      return <Badge variant="destructive">Tampered</Badge>;
  }
}

function BundleSlideOver({
  bundle,
  onClose,
}: {
  bundle: EvidenceBundle;
  onClose: () => void;
}) {
  const { data: verifyData, isLoading } = useQuery({
    queryKey: ["evidence-verify", bundle.id],
    queryFn: () => evidenceApi.verify(bundle.id),
    enabled: !!bundle.id,
  });

  const verified = (verifyData as { data?: { verified?: boolean } })?.data?.verified ?? bundle.status === "verified";

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex justify-end"
    >
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <motion.div
        initial={{ x: "100%" }}
        animate={{ x: 0 }}
        exit={{ x: "100%" }}
        transition={{ type: "spring", damping: 30, stiffness: 300 }}
        className="relative w-full max-w-lg bg-card border-l border-border/50 shadow-2xl overflow-y-auto"
      >
        {/* Header */}
        <div className="sticky top-0 bg-card border-b border-border/50 p-5 flex items-start justify-between z-10">
          <div>
            <h2 className="text-lg font-bold">{bundle.bundleId}</h2>
            <p className="text-sm text-muted-foreground mt-0.5">{bundle.appName}</p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="p-5 space-y-5">
          {/* Status */}
          <Card className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium">Verification Status</span>
                {isLoading ? (
                  <Badge variant="secondary">Checking...</Badge>
                ) : verified ? (
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                    <span className="text-sm text-green-400 font-medium">Verified</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-red-400" />
                    <span className="text-sm text-red-400 font-medium">Integrity Fail</span>
                  </div>
                )}
              </div>
              <QuantumSignedIcon signed={bundle.quantumSigned} />
            </CardContent>
          </Card>

          {/* Hash Verification */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-medium">
              <Hash className="h-4 w-4 text-primary" />
              Hash Verification
            </div>
            <div className="bg-muted/30 rounded-lg p-3 font-mono text-xs text-muted-foreground break-all border border-border/50">
              {bundle.hash}0a1b2c3d4e5f6789abcdef0123456789
            </div>
          </div>

          {/* Metadata */}
          <div className="space-y-3">
            {[
              { label: "Framework", value: bundle.framework },
              { label: "Control", value: bundle.control },
              { label: "App ID", value: bundle.appId },
              { label: "Generated", value: new Date(bundle.generatedAt).toLocaleString() },
              { label: "Expires", value: new Date(bundle.expiresAt).toLocaleString() },
              { label: "Artifacts", value: `${bundle.artifacts} files` },
              { label: "Bundle Size", value: `${(bundle.sizeKb / 1024).toFixed(2)} MB` },
              { label: "Retention", value: `${bundle.retentionDays} days` },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between text-sm">
                <span className="text-muted-foreground">{label}</span>
                <span className="font-medium">{value}</span>
              </div>
            ))}
          </div>

          {/* Actions */}
          <div className="flex gap-3 pt-2">
            <Button
              className="flex-1"
              onClick={() => {
                toast.success(`Downloading ${bundle.bundleId}...`);
                onClose();
              }}
            >
              <Download className="mr-2 h-4 w-4" />
              Download Bundle
            </Button>
            <Button
              variant="outline"
              onClick={() => toast.info("Opening auditor portal...")}
            >
              <ExternalLink className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function EvidenceVault() {
  const [search, setSearch] = useState("");
  const [frameworkFilter, setFrameworkFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedBundle, setSelectedBundle] = useState<EvidenceBundle | null>(null);

  const { data } = useQuery({
    queryKey: ["evidence-list"],
    queryFn: () => evidenceApi.list(),
  });

  const bundles: EvidenceBundle[] =
    (data as { data?: EvidenceBundle[] })?.data ?? MOCK_BUNDLES;

  const filtered = useMemo(() => {
    return bundles.filter((b) => {
      const matchSearch =
        !search ||
        b.bundleId.toLowerCase().includes(search.toLowerCase()) ||
        b.appName.toLowerCase().includes(search.toLowerCase()) ||
        b.control.toLowerCase().includes(search.toLowerCase());
      const matchFramework =
        frameworkFilter === "all" || b.framework === frameworkFilter;
      const matchStatus =
        statusFilter === "all" || b.status === statusFilter;
      return matchSearch && matchFramework && matchStatus;
    });
  }, [bundles, search, frameworkFilter, statusFilter]);

  const quantumSignedCount = bundles.filter((b) => b.quantumSigned).length;
  const verifiedCount = bundles.filter((b) => b.status === "verified").length;
  const tamperedCount = bundles.filter((b) => b.status === "tampered").length;

  const columns = [
    {
      key: "bundleId",
      header: "Bundle ID",
      render: (row: EvidenceBundle) => (
        <span className="font-mono text-xs font-medium text-primary">{row.bundleId}</span>
      ),
    },
    {
      key: "appName",
      header: "Application",
      render: (row: EvidenceBundle) => (
        <div>
          <p className="text-sm font-medium">{row.appName}</p>
          <p className="text-xs text-muted-foreground">{row.appId}</p>
        </div>
      ),
    },
    {
      key: "framework",
      header: "Framework / Control",
      render: (row: EvidenceBundle) => (
        <div>
          <p className="text-sm">{row.framework}</p>
          <p className="text-xs text-muted-foreground font-mono">{row.control}</p>
        </div>
      ),
    },
    {
      key: "quantumSigned",
      header: "Signature",
      render: (row: EvidenceBundle) => <QuantumSignedIcon signed={row.quantumSigned} />,
    },
    {
      key: "status",
      header: "Status",
      render: (row: EvidenceBundle) => <StatusBadge status={row.status} />,
    },
    {
      key: "generatedAt",
      header: "Generated",
      render: (row: EvidenceBundle) => (
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Calendar className="h-3.5 w-3.5" />
          {new Date(row.generatedAt).toLocaleDateString()}
        </div>
      ),
    },
    {
      key: "retention",
      header: "Retention",
      render: (row: EvidenceBundle) => (
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Clock className="h-3.5 w-3.5" />
          {row.retentionDays}d
        </div>
      ),
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Evidence Vault"
        description="Immutable evidence bundles with quantum-signed integrity verification for all compliance frameworks"
        badge="Quantum-Secured"
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => toast.success("Bulk export initiated...")}
          >
            <Download className="mr-2 h-4 w-4" />
            Bulk Export
          </Button>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Bundles"
          value={bundles.length}
          change={8}
          changeLabel="this month"
          icon={FileArchive}
          trend="up"
        />
        <KpiCard
          title="Quantum-Signed"
          value={`${quantumSignedCount}/${bundles.length}`}
          change={12}
          changeLabel="vs last month"
          icon={Lock}
          trend="up"
        />
        <KpiCard
          title="Verified Bundles"
          value={verifiedCount}
          change={5}
          changeLabel="vs last month"
          icon={ShieldCheck}
          trend="up"
        />
        <KpiCard
          title="Tamper Alerts"
          value={tamperedCount}
          change={-2}
          changeLabel="vs last month"
          icon={AlertCircle}
          trend={tamperedCount > 0 ? "down" : "flat"}
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search bundles, apps, controls..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Select value={frameworkFilter} onValueChange={setFrameworkFilter}>
            <SelectTrigger className="w-36">
              <SelectValue placeholder="Framework" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Frameworks</SelectItem>
              <SelectItem value="SOC 2">SOC 2</SelectItem>
              <SelectItem value="PCI-DSS">PCI-DSS</SelectItem>
              <SelectItem value="ISO 27001">ISO 27001</SelectItem>
              <SelectItem value="HIPAA">HIPAA</SelectItem>
              <SelectItem value="NIST 800-53">NIST 800-53</SelectItem>
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-32">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="verified">Verified</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="tampered">Tampered</SelectItem>
            </SelectContent>
          </Select>
        </div>
        {(search || frameworkFilter !== "all" || statusFilter !== "all") && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearch("");
              setFrameworkFilter("all");
              setStatusFilter("all");
            }}
          >
            <X className="mr-1 h-3.5 w-3.5" />
            Clear
          </Button>
        )}
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} of {bundles.length} bundles
        </span>
      </div>

      {/* Table */}
      <DataTable
        columns={columns}
        data={filtered as unknown as Record<string, unknown>[]}
        onRowClick={(row) => setSelectedBundle(row as unknown as EvidenceBundle)}
        emptyMessage="No evidence bundles match your filters"
      />

      {/* Slide-over */}
      <AnimatePresence>
        {selectedBundle && (
          <BundleSlideOver
            bundle={selectedBundle}
            onClose={() => setSelectedBundle(null)}
          />
        )}
      </AnimatePresence>
    </motion.div>
  );
}
