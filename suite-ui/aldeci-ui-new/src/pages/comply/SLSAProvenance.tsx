import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  GitBranch,
  Shield,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ChevronRight,
  Link2,
  Terminal,
  Box,
  Clock,
  Search,
  Filter,
  ArrowRight,
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

interface ProvenanceRecord {
  id: string;
  buildId: string;
  artifact: string;
  version: string;
  appId: string;
  appName: string;
  slsaLevel: 1 | 2 | 3;
  builderType: string;
  builderVersion: string;
  sourceRepo: string;
  sourceCommit: string;
  sourceBranch: string;
  buildStartedOn: string;
  buildFinishedOn: string;
  attestationStatus: "verified" | "failed" | "pending" | "missing";
  pipelineIntegrity: "passed" | "failed" | "warning";
  builderTrusted: boolean;
  isolatedBuild: boolean;
  reproducible: boolean;
  attestationHash: string;
}

const MOCK_PROVENANCE: ProvenanceRecord[] = [
  {
    id: "prov-001",
    buildId: "BUILD-20250110-001",
    artifact: "checkout-service",
    version: "v2.14.3",
    appId: "app-checkout",
    appName: "Checkout Service",
    slsaLevel: 3,
    builderType: "github-actions",
    builderVersion: "v4.1.0",
    sourceRepo: "github.com/aldeci/checkout-service",
    sourceCommit: "a3f8c2e1d4b7f9e0",
    sourceBranch: "main",
    buildStartedOn: "2025-01-10T07:00:00Z",
    buildFinishedOn: "2025-01-10T07:08:44Z",
    attestationStatus: "verified",
    pipelineIntegrity: "passed",
    builderTrusted: true,
    isolatedBuild: true,
    reproducible: true,
    attestationHash: "sha256:e3b0c44298fc1c14...9a4e",
  },
  {
    id: "prov-002",
    buildId: "BUILD-20250110-002",
    artifact: "auth-service",
    version: "v1.9.1",
    appId: "app-auth",
    appName: "Auth Service",
    slsaLevel: 3,
    builderType: "github-actions",
    builderVersion: "v4.1.0",
    sourceRepo: "github.com/aldeci/auth-service",
    sourceCommit: "b4e9d3f2c5a8e1b2",
    sourceBranch: "main",
    buildStartedOn: "2025-01-10T09:00:00Z",
    buildFinishedOn: "2025-01-10T09:05:22Z",
    attestationStatus: "verified",
    pipelineIntegrity: "passed",
    builderTrusted: true,
    isolatedBuild: true,
    reproducible: true,
    attestationHash: "sha256:f4c1d55309fc2d25...8b5f",
  },
  {
    id: "prov-003",
    buildId: "BUILD-20250109-001",
    artifact: "payments-gateway",
    version: "v3.2.0",
    appId: "app-payments",
    appName: "Payments Gateway",
    slsaLevel: 2,
    builderType: "jenkins",
    builderVersion: "2.440.3",
    sourceRepo: "github.com/aldeci/payments",
    sourceCommit: "c5f0e4a3b6c9d2e3",
    sourceBranch: "release/3.2",
    buildStartedOn: "2025-01-09T13:30:00Z",
    buildFinishedOn: "2025-01-09T13:41:55Z",
    attestationStatus: "verified",
    pipelineIntegrity: "warning",
    builderTrusted: true,
    isolatedBuild: false,
    reproducible: false,
    attestationHash: "sha256:a2b3c4d5e6f7a8b9...3c0d",
  },
  {
    id: "prov-004",
    buildId: "BUILD-20250109-002",
    artifact: "data-pipeline",
    version: "v0.8.5",
    appId: "app-data-pipeline",
    appName: "Data Pipeline",
    slsaLevel: 1,
    builderType: "github-actions",
    builderVersion: "v4.0.3",
    sourceRepo: "github.com/aldeci/data-pipeline",
    sourceCommit: "d6a1f5b4c7e8f9d0",
    sourceBranch: "develop",
    buildStartedOn: "2025-01-09T10:00:00Z",
    buildFinishedOn: "2025-01-09T10:22:13Z",
    attestationStatus: "failed",
    pipelineIntegrity: "failed",
    builderTrusted: false,
    isolatedBuild: false,
    reproducible: false,
    attestationHash: "",
  },
  {
    id: "prov-005",
    buildId: "BUILD-20250108-001",
    artifact: "api-gateway",
    version: "v4.1.2",
    appId: "app-api-gw",
    appName: "API Gateway",
    slsaLevel: 3,
    builderType: "github-actions",
    builderVersion: "v4.1.0",
    sourceRepo: "github.com/aldeci/api-gateway",
    sourceCommit: "e7b2f6c5d8e9f0a1",
    sourceBranch: "main",
    buildStartedOn: "2025-01-08T06:00:00Z",
    buildFinishedOn: "2025-01-08T06:09:47Z",
    attestationStatus: "verified",
    pipelineIntegrity: "passed",
    builderTrusted: true,
    isolatedBuild: true,
    reproducible: true,
    attestationHash: "sha256:b3c4d5e6f7a8b9c0...4d1e",
  },
  {
    id: "prov-006",
    buildId: "BUILD-20250108-002",
    artifact: "iam-platform",
    version: "v2.0.1",
    appId: "app-iam",
    appName: "IAM Platform",
    slsaLevel: 3,
    builderType: "github-actions",
    builderVersion: "v4.1.0",
    sourceRepo: "github.com/aldeci/iam",
    sourceCommit: "f8c3a7d6e9f0b2c3",
    sourceBranch: "main",
    buildStartedOn: "2025-01-08T08:00:00Z",
    buildFinishedOn: "2025-01-08T08:06:32Z",
    attestationStatus: "pending",
    pipelineIntegrity: "passed",
    builderTrusted: true,
    isolatedBuild: true,
    reproducible: true,
    attestationHash: "",
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function SLSALevelBadge({ level }: { level: 1 | 2 | 3 }) {
  const colors: Record<number, string> = {
    1: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    2: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    3: "text-green-400 bg-green-500/10 border-green-500/30",
  };
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${colors[level]}`}
    >
      <Shield className="h-3 w-3" />
      SLSA L{level}
    </span>
  );
}

function AttestationBadge({ status }: { status: ProvenanceRecord["attestationStatus"] }) {
  switch (status) {
    case "verified":
      return <Badge variant="success">Verified</Badge>;
    case "failed":
      return <Badge variant="destructive">Failed</Badge>;
    case "pending":
      return <Badge variant="warning">Pending</Badge>;
    case "missing":
      return <Badge variant="outline">Missing</Badge>;
  }
}

function IntegrityBadge({ status }: { status: ProvenanceRecord["pipelineIntegrity"] }) {
  switch (status) {
    case "passed":
      return (
        <div className="flex items-center gap-1 text-green-400">
          <CheckCircle2 className="h-3.5 w-3.5" />
          <span className="text-xs">Passed</span>
        </div>
      );
    case "failed":
      return (
        <div className="flex items-center gap-1 text-red-400">
          <XCircle className="h-3.5 w-3.5" />
          <span className="text-xs">Failed</span>
        </div>
      );
    case "warning":
      return (
        <div className="flex items-center gap-1 text-yellow-400">
          <AlertCircle className="h-3.5 w-3.5" />
          <span className="text-xs">Warning</span>
        </div>
      );
  }
}

// ─── Provenance Chain Visualization ──────────────────────────────────────────

function ProvenanceChain({ record }: { record: ProvenanceRecord }) {
  const steps = [
    {
      label: "Source",
      detail: record.sourceBranch,
      icon: GitBranch,
      ok: true,
    },
    {
      label: "Commit",
      detail: record.sourceCommit.slice(0, 8),
      icon: Link2,
      ok: true,
    },
    {
      label: "Build",
      detail: record.builderType,
      icon: Terminal,
      ok: record.builderTrusted,
    },
    {
      label: "Isolate",
      detail: record.isolatedBuild ? "Hermetic" : "Non-hermetic",
      icon: Box,
      ok: record.isolatedBuild,
    },
    {
      label: "Attest",
      detail: record.attestationStatus,
      icon: Shield,
      ok: record.attestationStatus === "verified",
    },
  ];

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {steps.map((step, i) => {
        const Icon = step.icon;
        return (
          <div key={step.label} className="flex items-center gap-2">
            <div
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs ${
                step.ok
                  ? "border-green-500/30 bg-green-500/10 text-green-400"
                  : "border-red-500/30 bg-red-500/10 text-red-400"
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span className="font-medium">{step.label}</span>
              <span className="text-xs opacity-70 font-mono">{step.detail}</span>
            </div>
            {i < steps.length - 1 && (
              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function SLSAProvenance() {
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState("all");
  const [selectedRecord, setSelectedRecord] = useState<ProvenanceRecord | null>(null);

  const { data } = useQuery({
    queryKey: ["slsa-provenance"],
    queryFn: () => evidenceApi.list({ type: "slsa" }),
  });

  const records: ProvenanceRecord[] =
    (data as { data?: ProvenanceRecord[] })?.data ?? MOCK_PROVENANCE;

  const filtered = records.filter((r) => {
    const matchSearch =
      !search ||
      r.buildId.toLowerCase().includes(search.toLowerCase()) ||
      r.appName.toLowerCase().includes(search.toLowerCase()) ||
      r.artifact.toLowerCase().includes(search.toLowerCase());
    const matchLevel =
      levelFilter === "all" || r.slsaLevel.toString() === levelFilter;
    return matchSearch && matchLevel;
  });

  const verifiedCount = records.filter((r) => r.attestationStatus === "verified").length;
  const failedCount = records.filter((r) => r.attestationStatus === "failed").length;
  const level3Count = records.filter((r) => r.slsaLevel === 3).length;
  const integrityFailed = records.filter((r) => r.pipelineIntegrity === "failed").length;

  const columns = [
    {
      key: "buildId",
      header: "Build ID",
      render: (row: ProvenanceRecord) => (
        <div>
          <p className="text-xs font-mono text-primary">{row.buildId}</p>
          <p className="text-xs text-muted-foreground">{row.artifact} {row.version}</p>
        </div>
      ),
    },
    {
      key: "appName",
      header: "Application",
      render: (row: ProvenanceRecord) => (
        <div>
          <p className="text-sm font-medium">{row.appName}</p>
          <p className="text-xs text-muted-foreground font-mono">{row.sourceCommit.slice(0, 12)}</p>
        </div>
      ),
    },
    {
      key: "slsaLevel",
      header: "SLSA Level",
      render: (row: ProvenanceRecord) => <SLSALevelBadge level={row.slsaLevel} />,
    },
    {
      key: "attestation",
      header: "Attestation",
      render: (row: ProvenanceRecord) => <AttestationBadge status={row.attestationStatus} />,
    },
    {
      key: "pipelineIntegrity",
      header: "Pipeline",
      render: (row: ProvenanceRecord) => <IntegrityBadge status={row.pipelineIntegrity} />,
    },
    {
      key: "checks",
      header: "Checks",
      render: (row: ProvenanceRecord) => (
        <div className="flex items-center gap-2 text-xs">
          <span className={row.builderTrusted ? "text-green-400" : "text-red-400"}>
            {row.builderTrusted ? "✓" : "✗"} Trusted Builder
          </span>
          <span className={row.isolatedBuild ? "text-green-400" : "text-yellow-400"}>
            {row.isolatedBuild ? "✓" : "!"} Isolated
          </span>
        </div>
      ),
    },
    {
      key: "buildStartedOn",
      header: "Built",
      render: (row: ProvenanceRecord) => (
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Clock className="h-3.5 w-3.5" />
          {new Date(row.buildStartedOn).toLocaleDateString()}
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
        title="SLSA Provenance"
        description="Build provenance tracking, SLSA v1 attestation verification, and pipeline integrity monitoring"
        badge="SLSA v1"
        actions={
          <Button size="sm" onClick={() => toast.info("Running attestation verification across all builds...")}>
            <Shield className="mr-2 h-4 w-4" />
            Verify All
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Verified Attestations"
          value={`${verifiedCount}/${records.length}`}
          change={5}
          changeLabel="this week"
          icon={Shield}
          trend="up"
        />
        <KpiCard
          title="SLSA Level 3"
          value={level3Count}
          change={2}
          changeLabel="vs last build"
          icon={CheckCircle2}
          trend="up"
        />
        <KpiCard
          title="Attestation Failures"
          value={failedCount}
          icon={XCircle}
          trend={failedCount > 0 ? "down" : "flat"}
        />
        <KpiCard
          title="Pipeline Failures"
          value={integrityFailed}
          icon={AlertCircle}
          trend={integrityFailed > 0 ? "down" : "flat"}
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search build ID, artifact, app..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Select value={levelFilter} onValueChange={setLevelFilter}>
            <SelectTrigger className="w-36">
              <SelectValue placeholder="SLSA Level" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Levels</SelectItem>
              <SelectItem value="1">SLSA Level 1</SelectItem>
              <SelectItem value="2">SLSA Level 2</SelectItem>
              <SelectItem value="3">SLSA Level 3</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} builds
        </span>
      </div>

      {/* Provenance Chain Visualization for selected */}
      <AnimatePresence>
        {selectedRecord && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
          >
            <Card className="border-primary/30 bg-primary/5">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ChevronRight className="h-4 w-4 text-primary" />
                    Provenance Chain — {selectedRecord.buildId}
                  </CardTitle>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => setSelectedRecord(null)}
                  >
                    Close
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <ProvenanceChain record={selectedRecord} />
                {selectedRecord.attestationHash && (
                  <div className="bg-muted/30 rounded-lg p-3 font-mono text-xs text-muted-foreground border border-border/50">
                    Attestation: {selectedRecord.attestationHash}abcdef1234567890
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Pipeline Integrity Alerts */}
      {(failedCount > 0 || records.some((r) => r.pipelineIntegrity === "warning")) && (
        <div className="space-y-2">
          {records
            .filter((r) => r.pipelineIntegrity !== "passed")
            .map((r) => (
              <div
                key={r.id}
                className={`flex items-center justify-between p-3 rounded-lg border ${
                  r.pipelineIntegrity === "failed"
                    ? "border-red-500/30 bg-red-500/10"
                    : "border-yellow-500/30 bg-yellow-500/10"
                }`}
              >
                <div className="flex items-center gap-2.5">
                  {r.pipelineIntegrity === "failed" ? (
                    <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                  ) : (
                    <AlertCircle className="h-4 w-4 text-yellow-400 shrink-0" />
                  )}
                  <div>
                    <p className="text-sm font-medium">
                      {r.pipelineIntegrity === "failed"
                        ? "Pipeline integrity failure"
                        : "Pipeline integrity warning"}{" "}
                      — {r.buildId}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {r.appName} · {r.artifact} {r.version}
                      {!r.isolatedBuild && " · Non-isolated build environment"}
                      {!r.builderTrusted && " · Untrusted builder"}
                    </p>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-xs"
                  onClick={() => toast.info(`Investigating ${r.buildId}...`)}
                >
                  Investigate
                </Button>
              </div>
            ))}
        </div>
      )}

      {/* Table */}
      <DataTable
        columns={columns}
        data={filtered as unknown as Record<string, unknown>[]}
        onRowClick={(row) => setSelectedRecord(row as unknown as ProvenanceRecord)}
        emptyMessage="No provenance records match your filters"
      />
    </motion.div>
  );
}
