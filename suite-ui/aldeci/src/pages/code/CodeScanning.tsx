import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Code,
  Search,
  Loader2,
  FileCode,
  Bug,
  ShieldAlert,
  Shield,
  Cloud,
  Key,
  Activity,
  Zap,
  Upload,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/tabs';
import { Textarea } from '../../components/ui/textarea';
import { Input } from '../../components/ui/input';
import {
  sastApi,
  dastApi,
  secretsApi,
  containerScanApi,
  cspmScanApi,
  scannerIngestApi,
  sandboxApi,
  dedupApi,
} from '../../lib/api';
import { toast } from 'sonner';

// ── Types ─────────────────────────────────────────────────────────────────

interface SastFinding {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: string;
  cwe_id: string;
  language: string;
  file_path: string;
  line_number: number;
  column: number;
  snippet: string;
  message: string;
  fix_suggestion: string;
  confidence: number;
  timestamp: string;
}

interface ScanResult {
  scan_id: string;
  files_scanned: number;
  total_findings: number;
  findings: SastFinding[];
  by_severity: Record<string, number>;
  by_cwe: Record<string, number>;
  duration_ms: number;
  timestamp: string;
}

interface ScannerStatus {
  status: string;
  engine: string;
  rules_count?: number;
  languages?: string[];
  capabilities?: string[];
}

// ── Component ─────────────────────────────────────────────────────────────

export default function CodeScanning() {
  const [codeInput, setCodeInput] = useState('');
  const [filename, setFilename] = useState('input.py');
  const [activeTab, setActiveTab] = useState('sast');
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [verifyingFinding, setVerifyingFinding] = useState<string | null>(null);
  const [sandboxResults, setSandboxResults] = useState<Record<string, any>>({});
  const queryClient = useQueryClient();

  // ── Scanner Status Queries (parallel) ───────────────────────────────
  const { data: sastStatus } = useQuery<ScannerStatus>({
    queryKey: ['scanner-status', 'sast'],
    queryFn: () => sastApi.getStatus(),
    retry: false,
    staleTime: 30_000,
  });

  const { data: dastStatus } = useQuery<ScannerStatus>({
    queryKey: ['scanner-status', 'dast'],
    queryFn: () => dastApi.getStatus(),
    retry: false,
    staleTime: 30_000,
  });

  const { data: secretsStatus } = useQuery({
    queryKey: ['scanner-status', 'secrets'],
    queryFn: () => secretsApi.getStatus(),
    retry: false,
    staleTime: 30_000,
  });

  const { data: containerStatus } = useQuery<ScannerStatus>({
    queryKey: ['scanner-status', 'container'],
    queryFn: () => containerScanApi.getStatus(),
    retry: false,
    staleTime: 30_000,
  });

  const { data: cspmStatus } = useQuery<ScannerStatus>({
    queryKey: ['scanner-status', 'cspm'],
    queryFn: () => cspmScanApi.getStatus(),
    retry: false,
    staleTime: 30_000,
  });

  // ── SAST Rules ──────────────────────────────────────────────────────
  const { data: sastRules } = useQuery({
    queryKey: ['sast-rules'],
    queryFn: () => sastApi.getRules(),
    retry: false,
    staleTime: 60_000,
  });

  // ── Secrets Findings ────────────────────────────────────────────────
  useQuery({
    queryKey: ['secrets-findings'],
    queryFn: () => secretsApi.list(),
    retry: false,
  });

  // ── Dedup Stats ─────────────────────────────────────────────────────
  const { data: dedupStats } = useQuery({
    queryKey: ['dedup-stats'],
    queryFn: () => dedupApi.getStats(),
    retry: false,
  });

  // ── Supported 3rd-party Scanners ────────────────────────────────────
  const { data: supportedScanners } = useQuery({
    queryKey: ['supported-scanners'],
    queryFn: () => scannerIngestApi.supported(),
    retry: false,
  });

  // ── Sandbox Health (Docker PoC Verifier — cherry-picked from DeepAudit) ──
  const { data: sandboxHealth } = useQuery({
    queryKey: ['sandbox-health'],
    queryFn: () => sandboxApi.health(),
    retry: false,
    staleTime: 30_000,
  });

  // ── SAST Scan Mutation ──────────────────────────────────────────────
  const scanMutation = useMutation({
    mutationFn: async ({ code, file }: { code: string; file: string }) => {
      return sastApi.scanCode(code, file);
    },
    onSuccess: (data: ScanResult) => {
      setScanResults(data);
      const count = data.total_findings;
      if (count > 0) {
        toast.warning(`Found ${count} vulnerabilit${count === 1 ? 'y' : 'ies'} in ${data.duration_ms.toFixed(1)}ms`);
      } else {
        toast.success(`No vulnerabilities found (${data.duration_ms.toFixed(1)}ms)`);
      }
      queryClient.invalidateQueries({ queryKey: ['dedup-stats'] });
    },
    onError: (error: Error) => {
      toast.error(`Scan failed: ${error.message}`);
    },
  });

  // ── Sandbox Verify Mutation (DeepAudit-inspired) ────────────────────
  const verifyMutation = useMutation({
    mutationFn: async (finding: SastFinding) => {
      return sandboxApi.verifyFinding({
        finding: {
          finding_id: finding.finding_id,
          cve_id: finding.cwe_id,
          title: finding.title,
          severity: finding.severity,
          snippet: finding.snippet,
          file_path: finding.file_path,
          language: finding.language,
        },
      });
    },
    onSuccess: (data: any, finding: SastFinding) => {
      setSandboxResults((prev) => ({ ...prev, [finding.finding_id]: data }));
      setVerifyingFinding(null);
      const status = data?.status || 'unknown';
      if (status === 'verified_exploitable') {
        toast.error(`EXPLOITABLE: ${finding.title} verified in Docker sandbox`);
      } else if (status === 'not_exploitable') {
        toast.success(`Not exploitable: ${finding.title}`);
      } else {
        toast.info(`Sandbox result: ${status}`);
      }
    },
    onError: (error: Error) => {
      setVerifyingFinding(null);
      toast.error(`Sandbox verification failed: ${error.message}`);
    },
  });

  const handleVerifyFinding = (finding: SastFinding) => {
    setVerifyingFinding(finding.finding_id);
    verifyMutation.mutate(finding);
  };

  // ── 3rd-party Upload Mutation ───────────────────────────────────────
  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      return scannerIngestApi.upload(file);
    },
    onSuccess: (data: any) => {
      toast.success(`Ingested ${data?.findings_count || 0} findings from ${data?.scanner_type || 'scanner'}`);
      queryClient.invalidateQueries({ queryKey: ['dedup-stats'] });
    },
    onError: (error: Error) => {
      toast.error(`Upload failed: ${error.message}`);
    },
  });

  const handleScan = () => {
    if (!codeInput.trim()) {
      toast.error('Paste some code to scan');
      return;
    }
    scanMutation.mutate({ code: codeInput, file: filename });
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) uploadMutation.mutate(file);
  };

  // ── Scanner health cards ────────────────────────────────────────────
  const scanners = [
    {
      id: 'sast',
      name: 'SAST',
      description: 'Static Analysis',
      icon: Code,
      status: sastStatus,
      color: 'blue',
      rules: (sastRules as unknown[])?.length || (sastStatus as ScannerStatus)?.rules_count || 0,
    },
    {
      id: 'dast',
      name: 'DAST',
      description: 'Dynamic Analysis',
      icon: Zap,
      status: dastStatus,
      color: 'purple',
    },
    {
      id: 'secrets',
      name: 'Secrets',
      description: 'Secret Detection',
      icon: Key,
      status: secretsStatus ? { status: (secretsStatus as Record<string, unknown>).status as string, engine: 'Secrets Scanner' } : undefined,
      color: 'amber',
      findings: (secretsStatus as Record<string, unknown>)?.total_findings,
    },
    {
      id: 'container',
      name: 'Container',
      description: 'Container Security',
      icon: ShieldAlert,
      status: containerStatus,
      color: 'cyan',
    },
    {
      id: 'cspm',
      name: 'CSPM/IaC',
      description: 'Cloud & IaC',
      icon: Cloud,
      status: cspmStatus,
      color: 'emerald',
    },
  ];

  const isSandboxAvailable = (sandboxHealth as Record<string, unknown>)?.docker_available === true;

  // Flatten supported scanners response: { scanners: { sast: [...], dast: [...] }, total_new: [...] } → flat string[]
  const scannerList: string[] = (() => {
    if (!supportedScanners) return [];
    const data = supportedScanners as Record<string, unknown>;
    // Prefer total_new (flat list of all scanner names)
    if (Array.isArray(data.total_new)) return data.total_new as string[];
    // Fallback: flatten scanners object categories
    if (data.scanners && typeof data.scanners === 'object') {
      return [...new Set(Object.values(data.scanners as Record<string, string[]>).flat())];
    }
    // If it's already an array (shouldn't happen, but safe)
    if (Array.isArray(data)) return data as string[];
    return [];
  })();

  const findings = scanResults?.findings || [];
  const bySeverity = scanResults?.by_severity || {};

  const getSeverityBadge = (severity: string) => {
    const styles: Record<string, string> = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    };
    return styles[severity] || styles.info;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            Code Scanning
          </h1>
          <p className="text-muted-foreground mt-1">
            8 native scanners + 25 third-party normalizers — air-gapped CTEM scanning
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label htmlFor="scanner-upload">
            <Button variant="outline" className="gap-2" asChild>
              <span>
                <Upload className="w-4 h-4" />
                Import 3rd-party
              </span>
            </Button>
          </label>
          <input
            id="scanner-upload"
            type="file"
            accept=".json,.xml,.sarif,.csv"
            className="hidden"
            onChange={handleFileUpload}
          />
        </div>
      </div>

      {/* Scanner Status Grid + Sandbox */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {/* Sandbox Docker PoC Verifier — cherry-picked from DeepAudit */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <Card className="glass-card hover:border-primary/30 transition-colors cursor-pointer border-purple-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <Shield className="w-5 h-5 text-purple-400" />
                <div className={`w-2 h-2 rounded-full ${isSandboxAvailable ? 'bg-green-400' : 'bg-gray-500'}`} />
              </div>
              <p className="font-semibold text-sm">Sandbox PoC</p>
              <p className="text-xs text-muted-foreground">Docker Isolation</p>
              <p className="text-xs text-muted-foreground mt-1">
                {isSandboxAvailable ? 'Docker ready' : 'Docker N/A'}
              </p>
            </CardContent>
          </Card>
        </motion.div>
        {scanners.map((scanner, i) => {
          const Icon = scanner.icon;
          const isHealthy = ['healthy', 'operational', 'ready'].includes(
            scanner.status?.status?.toLowerCase() || ''
          );
          return (
            <motion.div
              key={scanner.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
            >
              <Card className="glass-card hover:border-primary/30 transition-colors cursor-pointer">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <Icon className="w-5 h-5 text-muted-foreground" />
                    <div className={`w-2 h-2 rounded-full ${isHealthy ? 'bg-green-400' : 'bg-gray-500'}`} />
                  </div>
                  <p className="font-semibold text-sm">{scanner.name}</p>
                  <p className="text-xs text-muted-foreground">{scanner.description}</p>
                  {(scanner as any).rules ? (
                    <p className="text-xs text-muted-foreground mt-1">{(scanner as any).rules} rules</p>
                  ) : null}
                  {(scanner as any).findings !== undefined && (
                    <p className="text-xs text-muted-foreground mt-1">{(scanner as any).findings} findings</p>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </div>

      {/* Scan Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="sast" className="gap-2">
            <Code className="w-4 h-4" />
            SAST Scan
          </TabsTrigger>
          <TabsTrigger value="results" className="gap-2">
            <Bug className="w-4 h-4" />
            Findings {findings.length > 0 && `(${findings.length})`}
          </TabsTrigger>
          <TabsTrigger value="ingest" className="gap-2">
            <Upload className="w-4 h-4" />
            3rd-Party Ingest
          </TabsTrigger>
        </TabsList>

        {/* SAST Scan Tab */}
        <TabsContent value="sast" className="space-y-4">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Code className="w-5 h-5" />
                Static Application Security Testing
              </CardTitle>
              <CardDescription>
                Paste code to scan with ALdeci&apos;s native SAST engine ({(sastRules as unknown[])?.length || 16} rules, {(sastStatus as ScannerStatus)?.languages?.length || 7} languages)
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-3 items-end">
                <div className="flex-1">
                  <label className="text-xs text-muted-foreground mb-1 block">Filename (for language detection)</label>
                  <Input
                    placeholder="input.py"
                    value={filename}
                    onChange={(e) => setFilename(e.target.value)}
                    className="max-w-xs"
                  />
                </div>
                <Button
                  onClick={handleScan}
                  disabled={scanMutation.isPending}
                  className="gap-2"
                  size="lg"
                >
                  {scanMutation.isPending ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4" />
                      Scan Code
                    </>
                  )}
                </Button>
              </div>
              <Textarea
                placeholder={`# Paste your code here for SAST analysis\nimport os\nos.system(user_input)  # This will be flagged\neval(request.data)       # And this too`}
                value={codeInput}
                onChange={(e) => setCodeInput(e.target.value)}
                className="font-mono text-sm min-h-[200px]"
              />
              {(sastStatus as ScannerStatus)?.languages && (
                <div className="flex flex-wrap gap-1.5">
                  <span className="text-xs text-muted-foreground">Supported:</span>
                  {(sastStatus as ScannerStatus).languages!.map((lang: string) => (
                    <Badge key={lang} variant="outline" className="text-[10px]">{lang}</Badge>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Scan Results Summary */}
          {scanResults && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <Card className="glass-card border-red-500/20">
                  <CardContent className="p-4 text-center">
                    <p className="text-2xl font-bold text-red-400">{bySeverity.critical || 0}</p>
                    <p className="text-xs text-muted-foreground">Critical</p>
                  </CardContent>
                </Card>
                <Card className="glass-card border-orange-500/20">
                  <CardContent className="p-4 text-center">
                    <p className="text-2xl font-bold text-orange-400">{bySeverity.high || 0}</p>
                    <p className="text-xs text-muted-foreground">High</p>
                  </CardContent>
                </Card>
                <Card className="glass-card border-yellow-500/20">
                  <CardContent className="p-4 text-center">
                    <p className="text-2xl font-bold text-yellow-400">{bySeverity.medium || 0}</p>
                    <p className="text-xs text-muted-foreground">Medium</p>
                  </CardContent>
                </Card>
                <Card className="glass-card border-blue-500/20">
                  <CardContent className="p-4 text-center">
                    <p className="text-2xl font-bold text-blue-400">{bySeverity.low || 0}</p>
                    <p className="text-xs text-muted-foreground">Low</p>
                  </CardContent>
                </Card>
                <Card className="glass-card border-green-500/20">
                  <CardContent className="p-4 text-center">
                    <p className="text-2xl font-bold text-green-400">{scanResults.files_scanned}</p>
                    <p className="text-xs text-muted-foreground">Files Scanned</p>
                  </CardContent>
                </Card>
              </div>
            </motion.div>
          )}
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="results">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileCode className="w-5 h-5" />
                Scan Findings
              </CardTitle>
              <CardDescription>
                {findings.length === 0
                  ? 'Run a scan to see findings here'
                  : `${findings.length} finding${findings.length !== 1 ? 's' : ''} — Scan ID: ${scanResults?.scan_id}`
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Code className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No findings yet</p>
                  <p className="text-sm mt-1">Use the SAST Scan tab to analyze code</p>
                </div>
              ) : (
                <div className="space-y-3">
                  <AnimatePresence>
                    {findings.map((finding: SastFinding, index: number) => (
                      <motion.div
                        key={finding.finding_id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.04 }}
                        className="p-4 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors border border-border/50"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1 flex-wrap">
                              <Badge className={getSeverityBadge(finding.severity)}>
                                {finding.severity.toUpperCase()}
                              </Badge>
                              <Badge variant="outline" className="text-[10px]">
                                {finding.cwe_id}
                              </Badge>
                              <Badge variant="outline" className="text-[10px]">
                                {finding.rule_id}
                              </Badge>
                              <span className="text-xs text-muted-foreground ml-auto">
                                {Math.round(finding.confidence * 100)}% confidence
                              </span>
                            </div>
                            <p className="font-medium">{finding.title}</p>
                            <p className="text-sm text-muted-foreground mt-1">{finding.message}</p>
                            <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                              <span className="font-mono">{finding.file_path}:{finding.line_number}</span>
                              <span className="capitalize">{finding.language}</span>
                            </div>
                            {finding.snippet && (
                              <pre className="mt-2 p-2 bg-muted/50 rounded text-xs font-mono overflow-x-auto">
                                {finding.snippet}
                              </pre>
                            )}
                            {finding.fix_suggestion && (
                              <div className="mt-2 p-2 bg-green-500/10 border border-green-500/20 rounded text-xs">
                                <span className="text-green-400 font-medium">Fix: </span>
                                {finding.fix_suggestion}
                              </div>
                            )}
                            {/* Sandbox PoC Verification — cherry-picked from DeepAudit */}
                            <div className="mt-3 flex items-center gap-2">
                              <Button
                                size="sm"
                                variant="outline"
                                className="gap-1.5 text-xs h-7"
                                disabled={verifyingFinding === finding.finding_id || !isSandboxAvailable}
                                onClick={() => handleVerifyFinding(finding)}
                              >
                                {verifyingFinding === finding.finding_id ? (
                                  <><Loader2 className="w-3 h-3 animate-spin" /> Verifying...</>
                                ) : (
                                  <><Shield className="w-3 h-3" /> Verify in Sandbox</>
                                )}
                              </Button>
                              {!isSandboxAvailable && (
                                <span className="text-[10px] text-muted-foreground">Docker required</span>
                              )}
                              {sandboxResults[finding.finding_id] && (
                                <Badge className={
                                  sandboxResults[finding.finding_id].status === 'verified_exploitable'
                                    ? 'bg-red-500/20 text-red-400 border-red-500/30'
                                    : sandboxResults[finding.finding_id].status === 'not_exploitable'
                                    ? 'bg-green-500/20 text-green-400 border-green-500/30'
                                    : 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                                }>
                                  {sandboxResults[finding.finding_id].status?.replace(/_/g, ' ')}
                                </Badge>
                              )}
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 3rd-Party Ingest Tab */}
        <TabsContent value="ingest">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="w-5 h-5" />
                Import Third-Party Scanner Results
              </CardTitle>
              <CardDescription>
                Upload output from any of {scannerList.length || 25}+ supported scanners.
                ALdeci auto-detects the format and normalizes findings.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="border-2 border-dashed border-border rounded-lg p-8 text-center">
                <Upload className="w-10 h-10 mx-auto mb-3 text-muted-foreground" />
                <p className="font-medium">Drop scanner output here</p>
                <p className="text-sm text-muted-foreground mt-1">
                  JSON, XML, SARIF, or CSV from supported scanners
                </p>
                <label htmlFor="ingest-upload">
                  <Button variant="outline" className="mt-4 gap-2" asChild>
                    <span>
                      <Upload className="w-4 h-4" />
                      Choose File
                    </span>
                  </Button>
                </label>
                <input
                  id="ingest-upload"
                  type="file"
                  accept=".json,.xml,.sarif,.csv"
                  className="hidden"
                  onChange={handleFileUpload}
                />
                {uploadMutation.isPending && (
                  <div className="flex items-center justify-center gap-2 mt-4 text-sm text-muted-foreground">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Processing...
                  </div>
                )}
              </div>

              {/* Supported scanners list */}
              {scannerList.length > 0 && (
                <div>
                  <p className="text-sm font-medium mb-2">Supported Scanners</p>
                  <div className="flex flex-wrap gap-1.5">
                    {scannerList.map((scanner: string) => (
                      <Badge key={scanner} variant="outline" className="text-[10px] capitalize">
                        {scanner.replace(/_/g, ' ')}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Dedup Stats Footer */}
      {dedupStats && (
        <Card className="glass-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Activity className="w-5 h-5 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium">Brain Pipeline Deduplication</p>
                  <p className="text-xs text-muted-foreground">
                    Noise reduction: {String((dedupStats as Record<string, unknown>).dedup_rate || 0)}%
                  </p>
                </div>
              </div>
              <Badge variant="outline">
                {String((dedupStats as Record<string, unknown>).unique_clusters || 0)} unique clusters
              </Badge>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
