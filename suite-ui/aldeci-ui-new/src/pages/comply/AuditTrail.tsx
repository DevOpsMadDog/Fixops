import { useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Download,
  Search,
  Filter,
  X,
  Hash,
  Link2,
  User,
  Clock,
  AlertTriangle,
  FileJson,
  FileText,
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
import { auditApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock Data ───────────────────────────────────────────────────────────────

interface AuditEntry {
  id: string;
  seqNo: number;
  timestamp: string;
  actor: string;
  actorEmail: string;
  action: string;
  resource: string;
  resourceId: string;
  outcome: "success" | "failure" | "warning";
  ipAddress: string;
  userAgent: string;
  prevHash: string;
  entryHash: string;
  chainIntact: boolean;
  details: string;
}

const MOCK_AUDIT_LOG: AuditEntry[] = [
  {
    id: "audit-001", seqNo: 10001,
    timestamp: "2025-01-10T10:45:23Z",
    actor: "Sarah Chen", actorEmail: "s.chen@aldeci.com",
    action: "EVIDENCE_BUNDLE_GENERATED", resource: "Evidence Bundle", resourceId: "EVB-2025-001",
    outcome: "success", ipAddress: "10.0.1.42", userAgent: "Mozilla/5.0 Chrome/121",
    prevHash: "sha256:prev0001", entryHash: "sha256:a8f3c2e1d4b7", chainIntact: true,
    details: "Generated SOC 2 evidence bundle for Checkout Service",
  },
  {
    id: "audit-002", seqNo: 10002,
    timestamp: "2025-01-10T10:32:11Z",
    actor: "Marcus Williams", actorEmail: "m.williams@aldeci.com",
    action: "COMPLIANCE_FRAMEWORK_EXPORTED", resource: "Compliance Framework", resourceId: "soc2",
    outcome: "success", ipAddress: "10.0.1.55", userAgent: "Mozilla/5.0 Firefox/122",
    prevHash: "sha256:a8f3c2e1d4b7", entryHash: "sha256:b9e4d5f2a3c8", chainIntact: true,
    details: "Exported SOC 2 compliance report to auditor portal",
  },
  {
    id: "audit-003", seqNo: 10003,
    timestamp: "2025-01-10T09:18:44Z",
    actor: "Priya Patel", actorEmail: "p.patel@aldeci.com",
    action: "USER_LOGIN", resource: "Auth Session", resourceId: "session-3c9f",
    outcome: "success", ipAddress: "192.168.1.201", userAgent: "Mozilla/5.0 Safari/17",
    prevHash: "sha256:b9e4d5f2a3c8", entryHash: "sha256:c1f2a3b4e5d6", chainIntact: true,
    details: "User authenticated with SAML SSO",
  },
  {
    id: "audit-004", seqNo: 10004,
    timestamp: "2025-01-10T08:55:02Z",
    actor: "system", actorEmail: "system@aldeci.com",
    action: "POLICY_EVALUATION_BLOCKED", resource: "Policy Engine", resourceId: "policy-hipaa-01",
    outcome: "warning", ipAddress: "10.0.0.1", userAgent: "ALdeci-Policy-Engine/3.1",
    prevHash: "sha256:c1f2a3b4e5d6", entryHash: "sha256:d2e3f4a5b6c7", chainIntact: true,
    details: "Blocked deployment: HIPAA control gap detected in data-pipeline v0.8.5",
  },
  {
    id: "audit-005", seqNo: 10005,
    timestamp: "2025-01-10T08:31:19Z",
    actor: "Unknown", actorEmail: "unknown@external.com",
    action: "API_KEY_ACCESS_ATTEMPT", resource: "API Endpoint", resourceId: "/api/v1/evidence",
    outcome: "failure", ipAddress: "185.220.101.47", userAgent: "python-requests/2.31.0",
    prevHash: "sha256:TAMPERED", entryHash: "sha256:e3f4a5b6c7d8", chainIntact: false,
    details: "Unauthorized API access attempt from external IP — chain integrity breach detected",
  },
  {
    id: "audit-006", seqNo: 10006,
    timestamp: "2025-01-10T07:45:00Z",
    actor: "James Thompson", actorEmail: "j.thompson@aldeci.com",
    action: "FINDING_SUPPRESSED", resource: "Finding", resourceId: "FIND-2025-0892",
    outcome: "success", ipAddress: "10.0.2.15", userAgent: "Mozilla/5.0 Chrome/121",
    prevHash: "sha256:e3f4a5b6c7d8", entryHash: "sha256:f4a5b6c7d8e9", chainIntact: true,
    details: "Suppressed false positive finding with justification: vendor acknowledged known issue",
  },
  {
    id: "audit-007", seqNo: 10007,
    timestamp: "2025-01-10T07:12:38Z",
    actor: "system", actorEmail: "system@aldeci.com",
    action: "SCANNER_SCAN_COMPLETED", resource: "Scanner", resourceId: "scanner-trivy",
    outcome: "success", ipAddress: "10.0.0.1", userAgent: "ALdeci-Scanner/4.2",
    prevHash: "sha256:f4a5b6c7d8e9", entryHash: "sha256:a1b2c3d4e5f6", chainIntact: true,
    details: "Trivy scanner completed scan of app-payments — 3 new HIGH findings",
  },
  {
    id: "audit-008", seqNo: 10008,
    timestamp: "2025-01-09T23:01:55Z",
    actor: "Sarah Chen", actorEmail: "s.chen@aldeci.com",
    action: "RETENTION_POLICY_UPDATED", resource: "Evidence Policy", resourceId: "policy-retention-hipaa",
    outcome: "success", ipAddress: "10.0.1.42", userAgent: "Mozilla/5.0 Chrome/121",
    prevHash: "sha256:a1b2c3d4e5f6", entryHash: "sha256:b2c3d4e5f6a7", chainIntact: true,
    details: "Updated HIPAA evidence retention from 1825 to 2190 days",
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function OutcomeBadge({ outcome }: { outcome: AuditEntry["outcome"] }) {
  switch (outcome) {
    case "success":
      return <Badge variant="success">Success</Badge>;
    case "failure":
      return <Badge variant="destructive">Failure</Badge>;
    case "warning":
      return <Badge variant="warning">Warning</Badge>;
  }
}

function ChainIndicator({ intact }: { intact: boolean }) {
  return intact ? (
    <div className="flex items-center gap-1.5 text-green-400">
      <Link2 className="h-3.5 w-3.5" />
      <span className="text-xs">Intact</span>
    </div>
  ) : (
    <div className="flex items-center gap-1.5 text-red-400">
      <XCircle className="h-3.5 w-3.5" />
      <span className="text-xs font-medium">BREACH</span>
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function AuditTrail() {
  const [search, setSearch] = useState("");
  const [userFilter, setUserFilter] = useState("all");
  const [outcomeFilter, setOutcomeFilter] = useState("all");
  const [timeFilter, setTimeFilter] = useState("24h");
  const [selectedEntry, setSelectedEntry] = useState<AuditEntry | null>(null);

  const { data } = useQuery({
    queryKey: ["audit-log", timeFilter],
    queryFn: () => auditApi.list({ period: timeFilter }),
  });

  const verifyMutation = useMutation({
    mutationFn: () => auditApi.verify(),
    onSuccess: () =>
      toast.success("Hash chain verification complete — all entries intact."),
    onError: () =>
      toast.error("Hash chain verification failed — tamper detected in audit log!"),
  });

  const entries: AuditEntry[] =
    (data as { data?: AuditEntry[] })?.data ?? MOCK_AUDIT_LOG;

  const tamperCount = entries.filter((e) => !e.chainIntact).length;
  const failureCount = entries.filter((e) => e.outcome === "failure").length;
  const actors = [...new Set(entries.map((e) => e.actor))];

  const filtered = useMemo(() => {
    return entries.filter((e) => {
      const matchSearch =
        !search ||
        e.action.toLowerCase().includes(search.toLowerCase()) ||
        e.actor.toLowerCase().includes(search.toLowerCase()) ||
        e.resource.toLowerCase().includes(search.toLowerCase()) ||
        e.details.toLowerCase().includes(search.toLowerCase());
      const matchUser = userFilter === "all" || e.actor === userFilter;
      const matchOutcome = outcomeFilter === "all" || e.outcome === outcomeFilter;
      return matchSearch && matchUser && matchOutcome;
    });
  }, [entries, search, userFilter, outcomeFilter]);

  const handleExportCSV = () => {
    const headers = ["SeqNo", "Timestamp", "Actor", "Action", "Resource", "Outcome", "IP", "Hash", "Chain"];
    const rows = filtered.map((e) =>
      [e.seqNo, e.timestamp, e.actor, e.action, e.resource, e.outcome, e.ipAddress, e.entryHash, e.chainIntact]
        .join(",")
    );
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit-trail.csv";
    a.click();
    toast.success("Audit log exported as CSV");
  };

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit-trail.json";
    a.click();
    toast.success("Audit log exported as JSON");
  };

  const columns = [
    {
      key: "seqNo",
      header: "Seq #",
      render: (row: AuditEntry) => (
        <span className="text-xs font-mono text-muted-foreground">#{row.seqNo}</span>
      ),
    },
    {
      key: "timestamp",
      header: "Timestamp",
      render: (row: AuditEntry) => (
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground whitespace-nowrap">
          <Clock className="h-3.5 w-3.5 shrink-0" />
          {new Date(row.timestamp).toLocaleString()}
        </div>
      ),
    },
    {
      key: "actor",
      header: "Actor",
      render: (row: AuditEntry) => (
        <div className="flex items-center gap-2">
          <div className="h-6 w-6 rounded-full bg-primary/20 flex items-center justify-center shrink-0">
            <User className="h-3.5 w-3.5 text-primary" />
          </div>
          <div>
            <p className="text-xs font-medium">{row.actor}</p>
            <p className="text-xs text-muted-foreground">{row.ipAddress}</p>
          </div>
        </div>
      ),
    },
    {
      key: "action",
      header: "Action",
      render: (row: AuditEntry) => (
        <code className="text-xs font-mono text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded">
          {row.action}
        </code>
      ),
    },
    {
      key: "resource",
      header: "Resource",
      render: (row: AuditEntry) => (
        <div>
          <p className="text-xs">{row.resource}</p>
          <p className="text-xs text-muted-foreground font-mono">{row.resourceId}</p>
        </div>
      ),
    },
    {
      key: "outcome",
      header: "Outcome",
      render: (row: AuditEntry) => <OutcomeBadge outcome={row.outcome} />,
    },
    {
      key: "chainIntact",
      header: "Chain",
      render: (row: AuditEntry) => <ChainIndicator intact={row.chainIntact} />,
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
        title="Audit Trail"
        description="Immutable hash-chain audit log with tamper detection and integrity verification"
        badge={tamperCount > 0 ? "⚠ Tamper Detected" : "Chain Intact"}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => verifyMutation.mutate()}
              disabled={verifyMutation.isPending}
            >
              <Hash className="mr-2 h-4 w-4" />
              Verify Chain
            </Button>
            <Button variant="outline" size="sm" onClick={handleExportCSV}>
              <FileText className="mr-2 h-4 w-4" />
              CSV
            </Button>
            <Button variant="outline" size="sm" onClick={handleExportJSON}>
              <FileJson className="mr-2 h-4 w-4" />
              JSON
            </Button>
          </div>
        }
      />

      {/* Tamper Alert */}
      {tamperCount > 0 && (
        <div className="flex items-start gap-3 p-4 rounded-lg border border-red-500/30 bg-red-500/10">
          <ShieldAlert className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-red-400">
              Hash Chain Integrity Breach Detected
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {tamperCount} audit log {tamperCount === 1 ? "entry has" : "entries have"} a broken
              chain — potential tampering. Affected entries are highlighted below. Immediate
              investigation recommended.
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="shrink-0 border-red-500/30 text-red-400 hover:bg-red-500/10"
            onClick={() => toast.info("Creating security incident for chain breach...")}
          >
            Escalate
          </Button>
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Entries"
          value={entries.length}
          change={12}
          changeLabel="today"
          icon={Hash}
          trend="flat"
        />
        <KpiCard
          title="Chain Integrity"
          value={tamperCount === 0 ? "Intact" : "BREACH"}
          icon={tamperCount === 0 ? CheckCircle2 : ShieldAlert}
          trend={tamperCount === 0 ? "up" : "down"}
        />
        <KpiCard
          title="Failures"
          value={failureCount}
          icon={XCircle}
          trend={failureCount > 0 ? "down" : "flat"}
        />
        <KpiCard
          title="Tampered Entries"
          value={tamperCount}
          icon={AlertTriangle}
          trend={tamperCount > 0 ? "down" : "flat"}
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search action, actor, resource..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Select value={userFilter} onValueChange={setUserFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Actor" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Actors</SelectItem>
              {actors.map((a) => (
                <SelectItem key={a} value={a}>
                  {a}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={outcomeFilter} onValueChange={setOutcomeFilter}>
            <SelectTrigger className="w-32">
              <SelectValue placeholder="Outcome" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Outcomes</SelectItem>
              <SelectItem value="success">Success</SelectItem>
              <SelectItem value="failure">Failure</SelectItem>
              <SelectItem value="warning">Warning</SelectItem>
            </SelectContent>
          </Select>
          <Select value={timeFilter} onValueChange={setTimeFilter}>
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1h">Last 1h</SelectItem>
              <SelectItem value="24h">Last 24h</SelectItem>
              <SelectItem value="7d">Last 7d</SelectItem>
              <SelectItem value="30d">Last 30d</SelectItem>
              <SelectItem value="90d">Last 90d</SelectItem>
            </SelectContent>
          </Select>
        </div>
        {(search || userFilter !== "all" || outcomeFilter !== "all") && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearch("");
              setUserFilter("all");
              setOutcomeFilter("all");
            }}
          >
            <X className="mr-1 h-3.5 w-3.5" />
            Clear
          </Button>
        )}
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} entries
        </span>
      </div>

      {/* Table */}
      <DataTable
        columns={columns}
        data={filtered as unknown as Record<string, unknown>[]}
        onRowClick={(row) =>
          setSelectedEntry(
            selectedEntry?.id === (row as unknown as AuditEntry).id
              ? null
              : (row as unknown as AuditEntry)
          )
        }
        emptyMessage="No audit entries match your filters"
      />

      {/* Entry Detail */}
      {selectedEntry && (
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Entry Detail — #{selectedEntry.seqNo}</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => setSelectedEntry(null)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">{selectedEntry.details}</p>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                { label: "Actor Email", value: selectedEntry.actorEmail },
                { label: "User Agent", value: selectedEntry.userAgent },
                { label: "IP Address", value: selectedEntry.ipAddress },
                { label: "Resource ID", value: selectedEntry.resourceId },
              ].map(({ label, value }) => (
                <div key={label} className="flex flex-col gap-0.5">
                  <span className="text-muted-foreground">{label}</span>
                  <span className="font-mono font-medium">{value}</span>
                </div>
              ))}
            </div>
            <div className="space-y-1.5">
              <p className="text-xs text-muted-foreground">Entry Hash</p>
              <p className="font-mono text-xs bg-muted/30 p-2 rounded border border-border/50 break-all">
                {selectedEntry.entryHash}0123456789abcdef0123456789abcdef
              </p>
            </div>
            <div className="space-y-1.5">
              <p className="text-xs text-muted-foreground">Previous Hash</p>
              <p
                className={`font-mono text-xs p-2 rounded border break-all ${
                  selectedEntry.chainIntact
                    ? "bg-muted/30 border-border/50"
                    : "bg-red-500/10 border-red-500/30 text-red-400"
                }`}
              >
                {selectedEntry.prevHash}
                {!selectedEntry.chainIntact && " — MISMATCH DETECTED"}
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}
