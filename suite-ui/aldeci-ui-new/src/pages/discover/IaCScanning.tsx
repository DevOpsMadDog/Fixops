import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Server, AlertTriangle, GitMerge, CheckCircle2, RefreshCw,
  Cloud, Layers, ChevronDown, ChevronUp, FileCode2, TrendingDown
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { findingsApi } from "@/lib/api";
import { toast } from "sonner";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend
} from "recharts";

// ── Mock Data ──────────────────────────────────────────────────────────────────
const MOCK_IAC_FINDINGS = [
  { id: "IAC-8821", title: "S3 bucket allows public read access", resource: "aws_s3_bucket.data-lake", framework: "Terraform", type: "AWS::S3", severity: "critical", drift: "detected", file: "infra/storage.tf:45", status: "open" },
  { id: "IAC-8814", title: "Security group allows inbound 0.0.0.0/0 on port 22", resource: "aws_security_group.bastion", framework: "Terraform", type: "AWS::EC2", severity: "critical", drift: "none", file: "infra/networking.tf:112", status: "open" },
  { id: "IAC-8807", title: "RDS instance not encrypted at rest", resource: "aws_db_instance.primary", framework: "Terraform", type: "AWS::RDS", severity: "high", drift: "detected", file: "infra/database.tf:23", status: "in-progress" },
  { id: "IAC-8800", title: "Lambda function has overly permissive IAM role", resource: "aws_iam_role.lambda-exec", framework: "Terraform", type: "AWS::IAM", severity: "high", drift: "none", file: "infra/lambda.tf:78", status: "open" },
  { id: "IAC-8793", title: "CloudFormation stack lacks deletion policy", resource: "DBStack", framework: "CloudFormation", type: "AWS::CloudFormation", severity: "medium", drift: "none", file: "stacks/database.yml:8", status: "open" },
  { id: "IAC-8786", title: "Kubernetes pod running with privileged: true", resource: "deployment/api-server", framework: "Kubernetes", type: "K8s::Pod", severity: "critical", drift: "detected", file: "k8s/api-deployment.yaml:89", status: "open" },
  { id: "IAC-8779", title: "Kubernetes network policy missing (all traffic allowed)", resource: "namespace/production", framework: "Kubernetes", type: "K8s::NetworkPolicy", severity: "high", drift: "none", file: "k8s/namespaces.yaml:34", status: "open" },
  { id: "IAC-8772", title: "Terraform provider credentials in plaintext state file", resource: "terraform.tfstate", framework: "Terraform", type: "Terraform::State", severity: "critical", drift: "none", file: "terraform.tfstate:1", status: "open" },
  { id: "IAC-8765", title: "Azure storage account allows HTTP access", resource: "azurerm_storage_account.logs", framework: "Terraform", type: "Azure::Storage", severity: "medium", drift: "detected", file: "azure/storage.tf:29", status: "in-progress" },
  { id: "IAC-8758", title: "EKS node group not using IMDSv2", resource: "aws_eks_node_group.workers", framework: "Terraform", type: "AWS::EKS", severity: "medium", drift: "none", file: "infra/eks.tf:156", status: "open" },
];

const RESOURCE_BREAKDOWN = [
  { name: "AWS S3", value: 14, color: "#f97316" },
  { name: "AWS EC2/SG", value: 22, color: "#ef4444" },
  { name: "AWS IAM", value: 18, color: "#a855f7" },
  { name: "AWS RDS", value: 9, color: "#3b82f6" },
  { name: "Kubernetes", value: 27, color: "#06b6d4" },
  { name: "Azure", value: 11, color: "#10b981" },
  { name: "GCP", value: 7, color: "#f59e0b" },
];

const CODE_DIFF_EXAMPLES = {
  "IAC-8821": {
    before: `resource "aws_s3_bucket_acl" "data-lake" {
  bucket = aws_s3_bucket.data-lake.id
  acl    = "public-read"  # INSECURE
}`,
    after: `resource "aws_s3_bucket_acl" "data-lake" {
  bucket = aws_s3_bucket.data-lake.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data-lake" {
  bucket                  = aws_s3_bucket.data-lake.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
  },
};

export default function IaCScanning() {
  const [expandedDiff, setExpandedDiff] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ["findings", "iac"],
    queryFn: () => findingsApi.list({ type: "iac", limit: 50 }),
  });

  const findings = data?.data ?? MOCK_IAC_FINDINGS;
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const driftCount = findings.filter((f) => f.drift === "detected").length;

  const severityColor = (s: string) => ({
    critical: "text-red-400 bg-red-500/10 border-red-500/20",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  }[s] ?? "text-muted-foreground");

  const frameworkColors: Record<string, string> = {
    Terraform: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    CloudFormation: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    Kubernetes: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  };

  const columns = [
    { key: "id", header: "ID", render: (row: typeof MOCK_IAC_FINDINGS[0]) => <span className="font-mono text-xs text-muted-foreground">{row.id}</span> },
    { key: "title", header: "Misconfiguration", render: (row: typeof MOCK_IAC_FINDINGS[0]) => (
      <div>
        <p className="text-sm font-medium">{row.title}</p>
        <code className="text-xs text-muted-foreground font-mono mt-0.5 block">{row.resource}</code>
      </div>
    )},
    { key: "framework", header: "IaC Tool", render: (row: typeof MOCK_IAC_FINDINGS[0]) => (
      <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium border ${frameworkColors[row.framework] ?? ""}`}>{row.framework}</span>
    )},
    { key: "type", header: "Resource Type", render: (row: typeof MOCK_IAC_FINDINGS[0]) => (
      <span className="text-xs font-mono text-muted-foreground">{row.type}</span>
    )},
    { key: "severity", header: "Severity", render: (row: typeof MOCK_IAC_FINDINGS[0]) => (
      <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold border ${severityColor(row.severity)}`}>{row.severity}</span>
    )},
    { key: "drift", header: "Drift", render: (row: typeof MOCK_IAC_FINDINGS[0]) => (
      row.drift === "detected"
        ? <Badge variant="warning">Drift Detected</Badge>
        : <Badge variant="secondary">None</Badge>
    )},
    { key: "file", header: "File", render: (row: typeof MOCK_IAC_FINDINGS[0]) => (
      <code className="text-xs font-mono text-muted-foreground">{row.file}</code>
    )},
    { key: "actions", header: "", render: (row: typeof MOCK_IAC_FINDINGS[0]) => (
      <Button size="sm" variant="ghost" onClick={() => setExpandedDiff(expandedDiff === row.id ? null : row.id)}>
        {expandedDiff === row.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
      </Button>
    )},
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="IaC Scanning"
        description="Infrastructure-as-code misconfiguration detection across Terraform, CloudFormation, and Kubernetes manifests"
        badge="CSPM"
        actions={
          <>
            <Button variant="outline" size="sm"><GitMerge className="h-4 w-4 mr-1.5" />PR Scan</Button>
            <Button size="sm" onClick={() => toast.success("IaC scan queued for all repos")}>
              <RefreshCw className="h-4 w-4 mr-1.5" />Scan All
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Misconfigs" value={findings.length} change={-15} trend="down" icon={Server} />
        <KpiCard title="Critical Issues" value={criticalCount} change={2} trend="up" icon={AlertTriangle} />
        <KpiCard title="Drift Detected" value={driftCount} change={-1} trend="down" icon={GitMerge} />
        <KpiCard title="Templates Scanned" value={128} change={7} trend="up" icon={FileCode2} />
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="resources">Resource Breakdown</TabsTrigger>
          <TabsTrigger value="drift">Drift Detection</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-4 mt-4">
          <DataTable columns={columns} data={findings} emptyMessage="No IaC misconfigurations found" />

          {/* Expanded diff panel */}
          {expandedDiff && CODE_DIFF_EXAMPLES[expandedDiff as keyof typeof CODE_DIFF_EXAMPLES] && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}>
              <Card className="border-primary/30">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base flex items-center gap-2">
                      <FileCode2 className="h-4 w-4 text-primary" />
                      Fix Suggestion — {expandedDiff}
                    </CardTitle>
                    <Badge variant="success">Auto-fixable</Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-red-400 mb-2">— Before (Insecure)</p>
                      <pre className="rounded-md bg-red-500/5 border border-red-500/20 p-3 text-xs font-mono text-red-300 overflow-x-auto whitespace-pre-wrap">
                        {CODE_DIFF_EXAMPLES[expandedDiff as keyof typeof CODE_DIFF_EXAMPLES].before}
                      </pre>
                    </div>
                    <div>
                      <p className="text-xs text-green-400 mb-2">+ After (Secure)</p>
                      <pre className="rounded-md bg-green-500/5 border border-green-500/20 p-3 text-xs font-mono text-green-300 overflow-x-auto whitespace-pre-wrap">
                        {CODE_DIFF_EXAMPLES[expandedDiff as keyof typeof CODE_DIFF_EXAMPLES].after}
                      </pre>
                    </div>
                  </div>
                  <div className="flex gap-2 mt-4">
                    <Button size="sm" onClick={() => toast.success("Fix PR created in GitHub")}>Create Fix PR</Button>
                    <Button size="sm" variant="outline" onClick={() => toast.info("Copied to clipboard")}>Copy Diff</Button>
                    <Button size="sm" variant="ghost" onClick={() => toast.info("Exception added")}>Add Exception</Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </TabsContent>

        <TabsContent value="resources" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Resource Type Distribution</CardTitle>
                <CardDescription>Findings by infrastructure resource category</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie data={RESOURCE_BREAKDOWN} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={60} outerRadius={100} paddingAngle={3}>
                      {RESOURCE_BREAKDOWN.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                    <Legend iconType="circle" iconSize={8} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Top Misconfigured Resources</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {RESOURCE_BREAKDOWN.sort((a, b) => b.value - a.value).map((item) => (
                  <div key={item.name} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-medium">{item.name}</span>
                      <span style={{ color: item.color }} className="font-semibold">{item.value}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${(item.value / 27) * 100}%`, background: item.color }}
                      />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="drift" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {findings.filter((f) => f.drift === "detected").map((finding) => (
              <Card key={finding.id} className="border-yellow-500/20">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <CardTitle className="text-sm font-semibold">{finding.resource}</CardTitle>
                      <CardDescription className="text-xs mt-0.5">{finding.title}</CardDescription>
                    </div>
                    <Badge variant="warning">Drift</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Cloud className="h-3.5 w-3.5" />
                    <span>Actual state differs from declared state in {finding.file}</span>
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" variant="outline" onClick={() => toast.success("State reconciled")}>
                      <Layers className="h-3.5 w-3.5 mr-1" />Reconcile
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => toast.info("Drift accepted")}>Accept</Button>
                  </div>
                </CardContent>
              </Card>
            ))}
            <Card className="border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-10 text-center">
                <TrendingDown className="h-8 w-8 text-green-400 mb-3" />
                <p className="text-sm font-medium">Drift under control</p>
                <p className="text-xs text-muted-foreground mt-1">Only {driftCount} resources with drift detected</p>
                <Button size="sm" className="mt-3" variant="outline" onClick={() => toast.success("Full drift scan started")}>
                  <CheckCircle2 className="h-3.5 w-3.5 mr-1.5" />Run Full Drift Scan
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
