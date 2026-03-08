import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Cloud, ShieldCheck, AlertTriangle, Server, CheckCircle2,
  XCircle, RefreshCw, Download, Globe, Database, Lock
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { findingsApi } from "@/lib/api";
import { toast } from "sonner";
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer, Tooltip
} from "recharts";

// ── Mock Data ──────────────────────────────────────────────────────────────────
const MOCK_CSPM_FINDINGS = {
  aws: [
    { id: "CSPM-9001", service: "S3", title: "Bucket with public read enabled", region: "us-east-1", severity: "critical", status: "open", resourceId: "s3://prod-data-lake", compliance: ["CIS 2.1.5", "SOC2 CC6"] },
    { id: "CSPM-9002", service: "IAM", title: "Root account without MFA", region: "global", severity: "critical", status: "open", resourceId: "arn:aws:iam::123456789:root", compliance: ["CIS 1.5", "PCI 8.3"] },
    { id: "CSPM-9003", service: "EC2", title: "Security group allows all inbound traffic", region: "us-west-2", severity: "high", status: "in-progress", resourceId: "sg-0a1b2c3d4e5f", compliance: ["CIS 5.2", "NIST AC-4"] },
    { id: "CSPM-9004", service: "RDS", title: "Database instance publicly accessible", region: "eu-west-1", severity: "high", status: "open", resourceId: "db.prod-mysql-01", compliance: ["CIS 2.3.1"] },
    { id: "CSPM-9005", service: "CloudTrail", title: "CloudTrail logging disabled in region", region: "ap-southeast-1", severity: "medium", status: "open", resourceId: "trail/prod-trail", compliance: ["CIS 3.1", "SOC2 CC7"] },
    { id: "CSPM-9006", service: "KMS", title: "KMS key rotation not enabled", region: "us-east-1", severity: "medium", status: "resolved", resourceId: "key/1234-abcd", compliance: ["CIS 3.7"] },
  ],
  azure: [
    { id: "CSPM-9101", service: "Storage", title: "Azure blob container allows anonymous access", region: "East US", severity: "critical", status: "open", resourceId: "/subscriptions/.../containers/public", compliance: ["CIS Azure 3.7"] },
    { id: "CSPM-9102", service: "SQL", title: "Azure SQL server without TDE enabled", region: "West Europe", severity: "high", status: "open", resourceId: "/servers/prod-sql-server", compliance: ["CIS Azure 4.1"] },
    { id: "CSPM-9103", service: "Key Vault", title: "Key Vault soft delete not enabled", region: "East US", severity: "medium", status: "open", resourceId: "/vaults/prod-keyvault", compliance: ["CIS Azure 8.4"] },
    { id: "CSPM-9104", service: "Monitor", title: "Activity log alert missing for policy change", region: "global", severity: "medium", status: "open", resourceId: "activitylog/policy", compliance: ["CIS Azure 5.2.2"] },
  ],
  gcp: [
    { id: "CSPM-9201", service: "GCS", title: "Cloud Storage bucket publicly accessible", region: "us-central1", severity: "critical", status: "open", resourceId: "gs://prod-backups", compliance: ["CIS GCP 5.1"] },
    { id: "CSPM-9202", service: "Compute", title: "VM instance with public IP and no firewall", region: "us-east1", severity: "high", status: "in-progress", resourceId: "instances/prod-vm-01", compliance: ["CIS GCP 4.3"] },
    { id: "CSPM-9203", service: "BigQuery", title: "BigQuery dataset publicly accessible", region: "US", severity: "high", status: "open", resourceId: "datasets/analytics_prod", compliance: ["CIS GCP 7.1"] },
    { id: "CSPM-9204", service: "IAM", title: "Service account with editor role", region: "global", severity: "medium", status: "open", resourceId: "serviceaccounts/sa@project.iam.gserviceaccount.com", compliance: ["CIS GCP 1.5"] },
  ],
};

const COMPLIANCE_POSTURE = [
  { framework: "CIS Benchmarks", aws: 72, azure: 68, gcp: 81 },
  { framework: "SOC 2", aws: 84, azure: 79, gcp: 87 },
  { framework: "PCI DSS", aws: 91, azure: 83, gcp: 78 },
  { framework: "NIST CSF", aws: 76, azure: 71, gcp: 82 },
  { framework: "ISO 27001", aws: 88, azure: 86, gcp: 90 },
];

const RADAR_DATA = [
  { subject: "IAM", aws: 65, azure: 72, gcp: 81 },
  { subject: "Network", aws: 78, azure: 69, gcp: 75 },
  { subject: "Storage", aws: 52, azure: 61, gcp: 58 },
  { subject: "Logging", aws: 88, azure: 84, gcp: 91 },
  { subject: "Encryption", aws: 82, azure: 79, gcp: 86 },
  { subject: "Compliance", aws: 74, azure: 68, gcp: 77 },
];

const RESOURCE_INVENTORY = {
  aws:   { vms: 247, storage: 89, databases: 34, network: 156, iam: 1402, functions: 78 },
  azure: { vms: 118, storage: 43, databases: 22, network: 89,  iam: 567,  functions: 31 },
  gcp:   { vms: 84,  storage: 31, databases: 18, network: 62,  iam: 312,  functions: 44 },
};

type CloudProvider = "aws" | "azure" | "gcp";

export default function CloudPosture() {
  const [activeCloud, setActiveCloud] = useState<CloudProvider>("aws");

  const { data } = useQuery({
    queryKey: ["findings", "cspm", activeCloud],
    queryFn: () => findingsApi.list({ type: "cspm", cloud: activeCloud, limit: 50 }),
  });

  const findings = data?.data ?? MOCK_CSPM_FINDINGS[activeCloud];
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const openCount = findings.filter((f) => f.status === "open").length;
  const inventory = RESOURCE_INVENTORY[activeCloud];
  const totalResources = Object.values(inventory).reduce((a, b) => a + b, 0);

  const severityColor = (s: string) => ({
    critical: "text-red-400 bg-red-500/10 border-red-500/20",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  }[s] ?? "text-muted-foreground");

  const cloudColors: Record<CloudProvider, string> = {
    aws: "text-orange-400",
    azure: "text-blue-400",
    gcp: "text-green-400",
  };

  const columns = [
    { key: "id", header: "ID", render: (row: typeof MOCK_CSPM_FINDINGS.aws[0]) => <span className="font-mono text-xs text-muted-foreground">{row.id}</span> },
    { key: "service", header: "Service", render: (row: typeof MOCK_CSPM_FINDINGS.aws[0]) => (
      <span className="text-xs bg-muted/50 px-2 py-0.5 rounded font-mono">{row.service}</span>
    )},
    { key: "title", header: "Finding", render: (row: typeof MOCK_CSPM_FINDINGS.aws[0]) => (
      <div>
        <p className="text-sm font-medium">{row.title}</p>
        <code className="text-xs text-muted-foreground font-mono">{row.resourceId}</code>
      </div>
    )},
    { key: "region", header: "Region", render: (row: typeof MOCK_CSPM_FINDINGS.aws[0]) => (
      <div className="flex items-center gap-1.5">
        <Globe className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-sm">{row.region}</span>
      </div>
    )},
    { key: "severity", header: "Severity", render: (row: typeof MOCK_CSPM_FINDINGS.aws[0]) => (
      <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold border ${severityColor(row.severity)}`}>{row.severity}</span>
    )},
    { key: "compliance", header: "Frameworks", render: (row: typeof MOCK_CSPM_FINDINGS.aws[0]) => (
      <div className="flex flex-wrap gap-1">
        {row.compliance.map((c) => <span key={c} className="text-xs bg-primary/10 text-primary px-1.5 py-0.5 rounded">{c}</span>)}
      </div>
    )},
    { key: "status", header: "Status", render: (row: typeof MOCK_CSPM_FINDINGS.aws[0]) => (
      <Badge variant={row.status === "open" ? "destructive" : row.status === "in-progress" ? "warning" : "success"}>
        {row.status}
      </Badge>
    )},
    { key: "actions", header: "", render: (row: typeof MOCK_CSPM_FINDINGS.aws[0]) => (
      <Button size="sm" variant="ghost" onClick={() => toast.success(`Remediation initiated for ${row.id}`)}>
        Fix
      </Button>
    )},
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Cloud Security Posture"
        description="CSPM findings and compliance status across AWS, Azure, and GCP environments"
        badge="CSPM"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => toast.success("Report generated")}><Download className="h-4 w-4 mr-1.5" />Export</Button>
            <Button size="sm" onClick={() => toast.success("Cloud posture scan initiated")}><RefreshCw className="h-4 w-4 mr-1.5" />Sync Now</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total CSPM Findings" value={findings.length} change={-6} trend="down" icon={Cloud} />
        <KpiCard title="Critical Issues" value={criticalCount} change={1} trend="up" icon={AlertTriangle} />
        <KpiCard title="Open Findings" value={openCount} trend="flat" icon={ShieldCheck} />
        <KpiCard title="Resources Monitored" value={totalResources} trend="flat" icon={Server} />
      </div>

      {/* Multi-cloud tabs */}
      <Tabs value={activeCloud} onValueChange={(v) => setActiveCloud(v as CloudProvider)}>
        <TabsList>
          <TabsTrigger value="aws" className="gap-2">
            <span className="font-bold text-orange-400">⬡</span>AWS
            <Badge variant="secondary" className="ml-1">{MOCK_CSPM_FINDINGS.aws.length}</Badge>
          </TabsTrigger>
          <TabsTrigger value="azure" className="gap-2">
            <span className="font-bold text-blue-400">◆</span>Azure
            <Badge variant="secondary" className="ml-1">{MOCK_CSPM_FINDINGS.azure.length}</Badge>
          </TabsTrigger>
          <TabsTrigger value="gcp" className="gap-2">
            <span className="font-bold text-green-400">●</span>GCP
            <Badge variant="secondary" className="ml-1">{MOCK_CSPM_FINDINGS.gcp.length}</Badge>
          </TabsTrigger>
        </TabsList>

        {(["aws", "azure", "gcp"] as CloudProvider[]).map((cloud) => (
          <TabsContent key={cloud} value={cloud} className="space-y-4 mt-4">
            {/* Resource inventory row */}
            <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
              {Object.entries(RESOURCE_INVENTORY[cloud]).map(([key, count]) => (
                <Card key={key} className="text-center">
                  <CardContent className="p-3">
                    <p className={`text-xl font-bold ${cloudColors[cloud]}`}>{count}</p>
                    <p className="text-xs text-muted-foreground capitalize">{key}</p>
                  </CardContent>
                </Card>
              ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* CSPM findings table */}
              <div className="lg:col-span-2">
                <DataTable columns={columns} data={MOCK_CSPM_FINDINGS[cloud]} emptyMessage="No CSPM findings" />
              </div>

              {/* Compliance sidebar */}
              <div className="space-y-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm">Security Posture Radar</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={200}>
                      <RadarChart data={RADAR_DATA}>
                        <PolarGrid stroke="hsl(var(--border))" />
                        <PolarAngleAxis dataKey="subject" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
                        <Radar dataKey={cloud} stroke={cloud === "aws" ? "#f97316" : cloud === "azure" ? "#3b82f6" : "#10b981"} fill={cloud === "aws" ? "#f97316" : cloud === "azure" ? "#3b82f6" : "#10b981"} fillOpacity={0.2} />
                        <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                      </RadarChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Compliance by Framework</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {COMPLIANCE_POSTURE.map((item) => {
                      const score = item[cloud as keyof typeof item] as number;
                      return (
                        <div key={item.framework}>
                          <div className="flex justify-between text-xs mb-1">
                            <span className="font-medium">{item.framework}</span>
                            <span className={score >= 85 ? "text-green-400" : score >= 70 ? "text-yellow-400" : "text-red-400"}>
                              {score}%
                            </span>
                          </div>
                          <Progress value={score} className="h-1.5" />
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>

                <div className="grid grid-cols-2 gap-2">
                  <Card className="border-green-500/20">
                    <CardContent className="p-3 flex items-center gap-2">
                      <CheckCircle2 className="h-5 w-5 text-green-400 shrink-0" />
                      <div>
                        <p className="text-lg font-bold text-green-400">{findings.filter((f) => f.status === "resolved").length}</p>
                        <p className="text-xs text-muted-foreground">Resolved</p>
                      </div>
                    </CardContent>
                  </Card>
                  <Card className="border-red-500/20">
                    <CardContent className="p-3 flex items-center gap-2">
                      <XCircle className="h-5 w-5 text-red-400 shrink-0" />
                      <div>
                        <p className="text-lg font-bold text-red-400">{criticalCount}</p>
                        <p className="text-xs text-muted-foreground">Critical</p>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </div>
          </TabsContent>
        ))}
      </Tabs>

      {/* Quick actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { icon: Lock, title: "Enable Encryption", desc: "Auto-encrypt unencrypted resources", action: "Apply to 14 resources" },
          { icon: Database, title: "Fix Public Access", desc: "Remove public access from storage", action: "Apply to 6 buckets" },
          { icon: ShieldCheck, title: "Enable MFA", desc: "Enforce MFA for all IAM users", action: "Apply to 23 accounts" },
        ].map((item) => (
          <Card key={item.title} className="hover:border-primary/30 transition-colors cursor-pointer">
            <CardContent className="p-4 flex items-start gap-3">
              <div className="rounded-lg bg-primary/10 p-2 shrink-0">
                <item.icon className="h-5 w-5 text-primary" />
              </div>
              <div className="flex-1">
                <p className="font-semibold text-sm">{item.title}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{item.desc}</p>
                <Button size="sm" variant="link" className="p-0 h-auto mt-1.5 text-xs text-primary" onClick={() => toast.success(`${item.title} action initiated`)}>
                  {item.action} →
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </motion.div>
  );
}
