import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Swords,
  Play,
  Square,
  Terminal,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  Loader2,
  RefreshCw,
  Code,
  Zap,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { ScrollArea } from '../components/ui/scroll-area';
import { pentestApi } from '../lib/api';
import { toast } from 'sonner';

interface TestResult {
  id: string;
  cve?: string;
  target: string;
  status: 'running' | 'completed' | 'failed' | 'pending';
  exploitable: boolean | null;
  duration?: number;
  output?: string;
  timestamp: Date;
}

export default function AttackLab() {
  const [target, setTarget] = useState('');
  const [cveId, setCveId] = useState('');
  const [testResults, setTestResults] = useState<TestResult[]>([]);

  // Fetch available tests
  const { data: _testsData, isLoading: testsLoading, refetch } = useQuery({
    queryKey: ['pentest-tests'],
    queryFn: pentestApi.getTests,
    retry: false,
  });

  // Run micro pentest mutation
  const runTestMutation = useMutation({
    mutationFn: async ({ target, cve }: { target: string; cve?: string }) => {
      return pentestApi.runMicroPentest({
        target,
        cve_id: cve,
        safe_mode: true,
      });
    },
    onMutate: ({ target, cve }) => {
      const newResult: TestResult = {
        id: crypto.randomUUID(),
        cve: cve,
        target,
        status: 'running',
        exploitable: null,
        timestamp: new Date(),
      };
      setTestResults((prev) => [newResult, ...prev]);
      return { id: newResult.id };
    },
    onSuccess: (data, _variables, context) => {
      setTestResults((prev) =>
        prev.map((r) =>
          r.id === context?.id
            ? {
                ...r,
                status: 'completed',
                exploitable: data.exploitable || false,
                output: data.output || data.result,
                duration: data.duration,
              }
            : r
        )
      );
      toast.success('Test completed', {
        description: data.exploitable ? 'Vulnerability confirmed!' : 'Not exploitable',
      });
    },
    onError: (error: any, _variables, context) => {
      setTestResults((prev) =>
        prev.map((r) =>
          r.id === context?.id
            ? {
                ...r,
                status: 'failed',
                output: error.response?.data?.detail || error.message,
              }
            : r
        )
      );
      toast.error('Test failed', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  // Validate exploit mutation
  const validateMutation = useMutation({
    mutationFn: async (cve: string) => {
      return pentestApi.validateExploit(cve);
    },
    onSuccess: (data) => {
      toast.success('Validation complete', {
        description: `CVE ${data.cve}: ${data.exploitable ? 'Exploitable' : 'Not exploitable'}`,
      });
    },
    onError: (error: any) => {
      toast.error('Validation failed', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  const handleRunTest = () => {
    if (!target.trim()) {
      toast.error('Please enter a target');
      return;
    }
    runTestMutation.mutate({ target: target.trim(), cve: cveId.trim() || undefined });
  };

  const getStatusIcon = (status: TestResult['status']) => {
    switch (status) {
      case 'running':
        return <Loader2 className="w-4 h-4 animate-spin text-blue-500" />;
      case 'completed':
        return <CheckCircle2 className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-500" />;
      default:
        return <Clock className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const predefinedTests = [
    { id: 'sql-injection', name: 'SQL Injection', description: 'Test for SQL injection vulnerabilities' },
    { id: 'xss', name: 'XSS', description: 'Cross-site scripting tests' },
    { id: 'ssrf', name: 'SSRF', description: 'Server-side request forgery' },
    { id: 'path-traversal', name: 'Path Traversal', description: 'Directory traversal attacks' },
    { id: 'command-injection', name: 'Command Injection', description: 'OS command injection tests' },
    { id: 'auth-bypass', name: 'Auth Bypass', description: 'Authentication bypass attempts' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Swords className="w-8 h-8 text-primary" />
            Attack Lab
          </h1>
          <p className="text-muted-foreground mt-1">
            Micro-penetration testing and exploit validation
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()} className="gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      {/* Warning Banner */}
      <Card className="border-yellow-500/30 bg-yellow-500/5">
        <CardContent className="py-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-yellow-500" />
            <div>
              <p className="font-medium">Safe Mode Enabled</p>
              <p className="text-sm text-muted-foreground">
                All tests run in isolated sandboxes. No actual exploitation of production systems.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="test" className="space-y-6">
        <TabsList>
          <TabsTrigger value="test">Run Tests</TabsTrigger>
          <TabsTrigger value="validate">Validate CVE</TabsTrigger>
          <TabsTrigger value="results">Results</TabsTrigger>
          <TabsTrigger value="catalog">Test Catalog</TabsTrigger>
        </TabsList>

        {/* Run Tests Tab */}
        <TabsContent value="test" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-primary" />
                Micro-Pentest Executor
              </CardTitle>
              <CardDescription>
                Run targeted security tests against specified targets
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Target URL/Host</label>
                  <Input
                    placeholder="https://example.com or 192.168.1.1"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">CVE ID (Optional)</label>
                  <Input
                    placeholder="CVE-2024-XXXX"
                    value={cveId}
                    onChange={(e) => setCveId(e.target.value)}
                  />
                </div>
              </div>

              <div className="flex gap-2">
                <Button
                  onClick={handleRunTest}
                  disabled={runTestMutation.isPending}
                  className="gap-2"
                >
                  {runTestMutation.isPending ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )}
                  Run Test
                </Button>
                <Button variant="outline" className="gap-2">
                  <Square className="w-4 h-4" />
                  Stop All
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Quick Tests */}
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Quick Tests</CardTitle>
              <CardDescription>Common security test scenarios</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                {predefinedTests.map((test) => (
                  <motion.div
                    key={test.id}
                    whileHover={{ scale: 1.02 }}
                    className="p-4 rounded-lg border border-border bg-muted/30 text-center cursor-pointer hover:border-primary/50 transition-colors"
                    onClick={() => {
                      if (target) {
                        runTestMutation.mutate({ target, cve: test.id });
                      } else {
                        toast.error('Enter a target first');
                      }
                    }}
                  >
                    <Zap className="w-6 h-6 mx-auto text-primary mb-2" />
                    <p className="font-medium text-sm">{test.name}</p>
                    <p className="text-xs text-muted-foreground">{test.description}</p>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Validate CVE Tab */}
        <TabsContent value="validate" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                CVE Exploit Validation
              </CardTitle>
              <CardDescription>
                Validate if a specific CVE is exploitable in your environment
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">CVE ID</label>
                <div className="flex gap-2">
                  <Input
                    placeholder="CVE-2024-3400"
                    value={cveId}
                    onChange={(e) => setCveId(e.target.value)}
                    className="flex-1"
                  />
                  <Button
                    onClick={() => cveId && validateMutation.mutate(cveId)}
                    disabled={validateMutation.isPending || !cveId}
                    className="gap-2"
                  >
                    {validateMutation.isPending ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Shield className="w-4 h-4" />
                    )}
                    Validate
                  </Button>
                </div>
              </div>

              {/* Common CVEs */}
              <div className="pt-4">
                <p className="text-sm text-muted-foreground mb-3">Recently exploited CVEs:</p>
                <div className="flex flex-wrap gap-2">
                  {['CVE-2024-3400', 'CVE-2024-21887', 'CVE-2023-46805', 'CVE-2024-1709'].map((cve) => (
                    <Badge
                      key={cve}
                      variant="outline"
                      className="cursor-pointer hover:bg-primary/10"
                      onClick={() => setCveId(cve)}
                    >
                      {cve}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Results Tab */}
        <TabsContent value="results" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Test Results</CardTitle>
              <CardDescription>
                History of executed security tests
              </CardDescription>
            </CardHeader>
            <CardContent>
              {testResults.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Swords className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No tests executed yet</p>
                  <p className="text-sm">Run a test to see results here</p>
                </div>
              ) : (
                <ScrollArea className="h-[400px]">
                  <div className="space-y-3">
                    {testResults.map((result, index) => (
                      <motion.div
                        key={result.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.05 }}
                        className="p-4 rounded-lg border border-border bg-muted/30"
                      >
                        <div className="flex items-start justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              {getStatusIcon(result.status)}
                              <span className="font-medium">{result.target}</span>
                              {result.cve && (
                                <Badge variant="outline">{result.cve}</Badge>
                              )}
                            </div>
                            <p className="text-sm text-muted-foreground">
                              {result.timestamp.toLocaleString()}
                            </p>
                          </div>
                          <div className="text-right">
                            {result.status === 'completed' && (
                              <Badge variant={result.exploitable ? 'critical' : 'default'}>
                                {result.exploitable ? 'Exploitable' : 'Safe'}
                              </Badge>
                            )}
                            {result.duration && (
                              <p className="text-xs text-muted-foreground mt-1">
                                {result.duration}ms
                              </p>
                            )}
                          </div>
                        </div>
                        
                        {result.output && (
                          <div className="mt-3 p-3 rounded bg-background/50 font-mono text-xs">
                            <pre className="whitespace-pre-wrap">{result.output}</pre>
                          </div>
                        )}
                      </motion.div>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Test Catalog Tab */}
        <TabsContent value="catalog" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Test Catalog</CardTitle>
              <CardDescription>
                Available security test modules
              </CardDescription>
            </CardHeader>
            <CardContent>
              {testsLoading ? (
                <div className="space-y-4">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="h-20 skeleton rounded-lg" />
                  ))}
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {predefinedTests.map((test, index) => (
                    <motion.div
                      key={test.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                    >
                      <Card className="glass-card hover:border-primary/30 transition-colors cursor-pointer">
                        <CardContent className="pt-6">
                          <div className="flex items-start gap-4">
                            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                              <Code className="w-5 h-5 text-primary" />
                            </div>
                            <div className="flex-1">
                              <h4 className="font-semibold">{test.name}</h4>
                              <p className="text-sm text-muted-foreground">{test.description}</p>
                              <div className="flex gap-2 mt-2">
                                <Badge variant="outline">Automated</Badge>
                                <Badge variant="outline">Safe Mode</Badge>
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </motion.div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
