import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Code2, FileCode, GitBranch, ShieldAlert, Zap, RefreshCw,
  ChevronRight, CheckCircle2, AlertTriangle, Info, FolderOpen, FileWarning
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { findingsApi, scannerApi } from "@/lib/api";
import { toast } from "sonner";

// ── Mock Data ──────────────────────────────────────────────────────────────────
const MOCK_SAST_RESULTS = [
  { id: "SAST-1041", file: "src/api/auth/tokens.ts", line: 87, rule: "hardcoded-secret", title: "Hardcoded JWT secret key", severity: "critical", scanner: "Semgrep", status: "open", snippet: 'const JWT_SECRET = "super-secret-key-12345";' },
  { id: "SAST-1039", file: "src/controllers/user.ts", line: 142, rule: "sql-injection", title: "Unsanitized SQL query construction", severity: "critical", scanner: "CodeQL", status: "open", snippet: 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)' },
  { id: "SAST-1036", file: "src/utils/exec.ts", line: 23, rule: "command-injection", title: "Shell command injection via user input", severity: "critical", scanner: "Semgrep", status: "open", snippet: 'exec(`ls -la ${userPath}`, callback);' },
  { id: "SAST-1030", file: "src/pages/report.tsx", line: 56, rule: "xss-dangerously-set", title: "Unsanitized HTML rendered via dangerouslySetInnerHTML", severity: "high", scanner: "Semgrep", status: "in-progress", snippet: '<div dangerouslySetInnerHTML={{ __html: userContent }} />' },
  { id: "SAST-1025", file: "src/api/files.ts", line: 198, rule: "path-traversal", title: "Path traversal in file download handler", severity: "high", scanner: "CodeQL", status: "open", snippet: 'const filePath = path.join(uploadDir, req.params.filename);' },
  { id: "SAST-1020", file: "src/auth/oauth.ts", line: 67, rule: "open-redirect", title: "Unvalidated redirect destination", severity: "medium", scanner: "Semgrep", status: "open", snippet: 'res.redirect(req.query.next as string);' },
  { id: "SAST-1015", file: "src/api/payments.ts", line: 312, rule: "sensitive-data-log", title: "Credit card PAN logged in plaintext", severity: "high", scanner: "CodeQL", status: "open", snippet: 'logger.info(`Processing payment for card: ${card.number}`);' },
  { id: "SAST-1010", file: "src/config/db.ts", line: 14, rule: "tls-disabled", title: "TLS verification disabled for DB connection", severity: "medium", scanner: "Semgrep", status: "resolved", snippet: "ssl: { rejectUnauthorized: false }" },
];

const MOCK_SCANNERS = [
  { name: "Semgrep", version: "1.62.0", findings: 847, critical: 12, high: 89, lastScan: "4m ago", status: "healthy", coverage: 94 },
  { name: "CodeQL", version: "2.16.1", findings: 312, critical: 8, high: 43, lastScan: "12m ago", status: "healthy", coverage: 88 },
  { name: "OWASP Dep-Check", version: "9.0.9", findings: 156, critical: 22, high: 67, lastScan: "1h ago", status: "healthy", coverage: 100 },
  { name: "Trivy", version: "0.49.1", findings: 203, critical: 5, high: 31, lastScan: "23m ago", status: "warning", coverage: 76 },
];

const FILE_TREE = [
  { name: "src/", type: "folder", findings: 24 },
  { name: "  api/", type: "folder", findings: 12 },
  { name: "    auth/tokens.ts", type: "file", findings: 3, severity: "critical" },
  { name: "    payments.ts", type: "file", findings: 2, severity: "high" },
  { name: "    files.ts", type: "file", findings: 1, severity: "high" },
  { name: "  controllers/", type: "folder", findings: 8 },
  { name: "    user.ts", type: "file", findings: 4, severity: "critical" },
  { name: "  utils/", type: "folder", findings: 4 },
  { name: "    exec.ts", type: "file", findings: 1, severity: "critical" },
  { name: "  config/", type: "folder", findings: 2 },
  { name: "    db.ts", type: "file", findings: 1, severity: "medium" },
];

const FIX_SUGGESTIONS = [
  {
    id: "SAST-1041",
    title: "Replace hardcoded JWT secret",
    before: 'const JWT_SECRET = "super-secret-key-12345";',
    after: 'const JWT_SECRET = process.env.JWT_SECRET;\nif (!JWT_SECRET) throw new Error("JWT_SECRET not set");',
    effort: "15 min",
    autofix: true,
  },
];

export default function CodeScanning() {
  const [selectedResult, setSelectedResult] = useState<typeof MOCK_SAST_RESULTS[0] | null>(null);
  const [activeTab, setActiveTab] = useState("results");

  const { data: findings } = useQuery({
    queryKey: ["findings", "sast"],
    queryFn: () => findingsApi.list({ type: "sast", limit: 50 }),
  });

  const { data: scanners } = useQuery({
    queryKey: ["scanners", "list"],
    queryFn: () => scannerApi.list(),
  });

  const results = findings?.data ?? MOCK_SAST_RESULTS;
  const scannerList = scanners?.data ?? MOCK_SCANNERS;

  const criticalCount = results.filter((r) => r.severity === "critical").length;
  const totalFindings = scannerList.reduce((a: number, s: typeof MOCK_SCANNERS[0]) => a + s.findings, 0);

  const severityColor = (s: string) => ({
    critical: "text-red-400 bg-red-500/10 border-red-500/20",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  }[s] ?? "text-muted-foreground");

  const columns = [
    { key: "id", header: "ID", render: (row: typeof MOCK_SAST_RESULTS[0]) => <span className="font-mono text-xs text-muted-foreground">{row.id}</span> },
    { key: "file", header: "File", render: (row: typeof MOCK_SAST_RESULTS[0]) => (
      <div>
        <p className="font-mono text-xs">{row.file}</p>
        <p className="text-xs text-muted-foreground">Line {row.line}</p>
      </div>
    )},
    { key: "title", header: "Finding", render: (row: typeof MOCK_SAST_RESULTS[0]) => (
      <div>
        <p className="text-sm font-medium">{row.title}</p>
        <code className="text-xs text-muted-foreground font-mono">{row.rule}</code>
      </div>
    )},
    { key: "severity", header: "Severity", render: (row: typeof MOCK_SAST_RESULTS[0]) => (
      <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold border ${severityColor(row.severity)}`}>
        {row.severity}
      </span>
    )},
    { key: "scanner", header: "Scanner", render: (row: typeof MOCK_SAST_RESULTS[0]) => (
      <span className="text-xs bg-muted/50 px-2 py-0.5 rounded font-mono">{row.scanner}</span>
    )},
    { key: "snippet", header: "Code", render: (row: typeof MOCK_SAST_RESULTS[0]) => (
      <code className="text-xs text-muted-foreground font-mono bg-muted/30 px-2 py-0.5 rounded max-w-[200px] truncate block">
        {row.snippet}
      </code>
    )},
    { key: "actions", header: "", render: (row: typeof MOCK_SAST_RESULTS[0]) => (
      <Button size="sm" variant="ghost" onClick={() => setSelectedResult(row)}>
        <ChevronRight className="h-4 w-4" />
      </Button>
    )},
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Code Scanning"
        description="Static application security testing (SAST) results across all repositories and languages"
        badge="SAST"
        actions={
          <>
            <Button variant="outline" size="sm"><GitBranch className="h-4 w-4 mr-1.5" />main</Button>
            <Button size="sm" onClick={() => toast.success("Scan initiated across all repos")}>
              <RefreshCw className="h-4 w-4 mr-1.5" />Run Scan
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total SAST Findings" value={totalFindings} change={-8} trend="down" icon={Code2} />
        <KpiCard title="Critical Findings" value={criticalCount} change={5} trend="up" icon={ShieldAlert} />
        <KpiCard title="Active Scanners" value={scannerList.length} trend="flat" icon={Zap} />
        <KpiCard title="Repos Scanned" value={47} change={3} trend="up" icon={GitBranch} />
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="results">SAST Results</TabsTrigger>
          <TabsTrigger value="scanners">Scanner Comparison</TabsTrigger>
          <TabsTrigger value="filetree">File Explorer</TabsTrigger>
          <TabsTrigger value="fixes">Fix Suggestions</TabsTrigger>
        </TabsList>

        <TabsContent value="results" className="space-y-4 mt-4">
          {selectedResult ? (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="text-base">{selectedResult.title}</CardTitle>
                    <CardDescription className="mt-1 font-mono text-xs">{selectedResult.file}:{selectedResult.line}</CardDescription>
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => setSelectedResult(null)}><AlertTriangle className="h-4 w-4" /> Back</Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Vulnerable Code</p>
                  <pre className="rounded-md bg-red-500/5 border border-red-500/20 p-4 text-xs font-mono text-red-300 overflow-x-auto">
{`// Line ${selectedResult.line}
${selectedResult.snippet}`}
                  </pre>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Suggested Fix</p>
                  <pre className="rounded-md bg-green-500/5 border border-green-500/20 p-4 text-xs font-mono text-green-300 overflow-x-auto">
{`// Fixed: ${selectedResult.rule}
// Use environment variable instead
const secret = process.env.SECRET_KEY;`}
                  </pre>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => toast.success("Auto-fix PR created")}>Create Fix PR</Button>
                  <Button size="sm" variant="outline" onClick={() => toast.info("Suppression applied")}>Suppress Rule</Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <DataTable columns={columns} data={results} onRowClick={(row) => setSelectedResult(row as typeof MOCK_SAST_RESULTS[0])} />
          )}
        </TabsContent>

        <TabsContent value="scanners" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {MOCK_SCANNERS.map((scanner) => (
              <Card key={scanner.name}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Code2 className="h-4 w-4 text-primary" />
                      {scanner.name}
                    </CardTitle>
                    <Badge variant={scanner.status === "healthy" ? "success" : "warning"}>
                      {scanner.status}
                    </Badge>
                  </div>
                  <CardDescription>v{scanner.version} · Last scan {scanner.lastScan}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-3 gap-3 text-center">
                    <div className="rounded-md bg-red-500/10 p-2">
                      <p className="text-lg font-bold text-red-400">{scanner.critical}</p>
                      <p className="text-xs text-muted-foreground">Critical</p>
                    </div>
                    <div className="rounded-md bg-orange-500/10 p-2">
                      <p className="text-lg font-bold text-orange-400">{scanner.high}</p>
                      <p className="text-xs text-muted-foreground">High</p>
                    </div>
                    <div className="rounded-md bg-muted/30 p-2">
                      <p className="text-lg font-bold">{scanner.findings}</p>
                      <p className="text-xs text-muted-foreground">Total</p>
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-muted-foreground">Repo Coverage</span>
                      <span className="font-medium">{scanner.coverage}%</span>
                    </div>
                    <Progress value={scanner.coverage} className="h-1.5" />
                  </div>
                  <Button size="sm" variant="outline" className="w-full" onClick={() => toast.success(`${scanner.name} rescan initiated`)}>
                    <RefreshCw className="h-3.5 w-3.5 mr-1.5" />Rescan
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="filetree" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <FolderOpen className="h-4 w-4 text-primary" />File Tree with Finding Markers
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1 font-mono text-sm">
                {FILE_TREE.map((item, i) => (
                  <div key={i} className={`flex items-center justify-between px-3 py-1.5 rounded-md ${item.type === "file" ? "hover:bg-muted/30 cursor-pointer" : ""}`}>
                    <div className="flex items-center gap-2">
                      {item.type === "folder"
                        ? <FolderOpen className="h-4 w-4 text-blue-400" />
                        : <FileCode className="h-4 w-4 text-muted-foreground" />
                      }
                      <span className={item.type === "folder" ? "text-muted-foreground" : ""}>{item.name}</span>
                    </div>
                    {item.findings > 0 && (
                      <div className="flex items-center gap-1.5">
                        {item.severity && (
                          <FileWarning className={`h-3.5 w-3.5 ${"critical" === item.severity ? "text-red-400" : "text-orange-400"}`} />
                        )}
                        <span className={`text-xs font-medium ${
                          item.severity === "critical" ? "text-red-400" :
                          item.severity === "high" ? "text-orange-400" :
                          "text-muted-foreground"
                        }`}>{item.findings} finding{item.findings !== 1 ? "s" : ""}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="fixes" className="mt-4 space-y-4">
          {FIX_SUGGESTIONS.map((fix) => (
            <Card key={fix.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                    {fix.title}
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    {fix.autofix && <Badge variant="success">Auto-fixable</Badge>}
                    <span className="text-xs text-muted-foreground">{fix.effort} to fix</span>
                  </div>
                </div>
                <CardDescription className="font-mono text-xs">{fix.id}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-xs text-red-400 mb-1.5 flex items-center gap-1"><Info className="h-3 w-3" />Before</p>
                    <pre className="rounded-md bg-red-500/5 border border-red-500/20 p-3 text-xs font-mono text-red-300 overflow-x-auto whitespace-pre-wrap">{fix.before}</pre>
                  </div>
                  <div>
                    <p className="text-xs text-green-400 mb-1.5 flex items-center gap-1"><CheckCircle2 className="h-3 w-3" />After</p>
                    <pre className="rounded-md bg-green-500/5 border border-green-500/20 p-3 text-xs font-mono text-green-300 overflow-x-auto whitespace-pre-wrap">{fix.after}</pre>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => toast.success("Auto-fix PR opened in GitHub")}>Apply Auto-Fix</Button>
                  <Button size="sm" variant="outline" onClick={() => toast.info("Fix copied to clipboard")}>Copy Diff</Button>
                </div>
              </CardContent>
            </Card>
          ))}
          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center justify-center py-10 text-center">
              <CheckCircle2 className="h-8 w-8 text-muted-foreground mb-3" />
              <p className="text-sm text-muted-foreground">47 more findings eligible for auto-fix</p>
              <Button size="sm" className="mt-3" onClick={() => toast.success("Bulk fix review opened")}>Review All</Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
